//! Инициализация NSS и глобального верификатора сертификатов.
//!
//! Схема повторяет Firefox:
//!  * NSS инициализируется в режиме NoDB (`NSS_NoDB_Init` + domestic policy)
//!    через `nss_rs::init()` — никаких записей на диск;
//!  * корневые центры сертификации НЕ берутся из NSS (в NoDB их нет) —
//!    они загружаются в верификатор rustls-webpki либо из PEM, переданного
//!    приложением (Android: доверенное хранилище ОС отдаёт Kotlin-слой),
//!    либо из системного хранилища (desktop Linux/Windows);
//!  * проверка цепочек (path building, сроков, SAN, EKU) делает
//!    `WebPkiServerVerifier` — на параметры TLS это не влияет.
//!
//! `shutdown()` — настоящий (в отличие от более ранних версий):
//! сбрасывает верификатор и, если NSS подняли мы (а не хост-приложение),
//! вызывает `NSS_Shutdown`. После успешного `bn_shutdown` библиотеку
//! можно инициализировать снова (`bn_init`) и .so можно выгружать
//! (dlclose). Все дескрипторы должны быть закрыты ДО `bn_shutdown`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;

use crate::error::{Error, ErrorCode, Result};
use crate::nssx;

use nssx::_SECStatus_SECSuccess as SECSuccess;

pub struct GlobalContext {
    pub verifier: Arc<WebPkiServerVerifier>,
}

static GLOBAL: Mutex<Option<GlobalContext>> = Mutex::new(None);

/// NSS подняли мы, а не хост-приложение — только тогда `shutdown()`
/// имеет право вызвать `NSS_Shutdown`.
static NSS_OWNED: AtomicBool = AtomicBool::new(false);

fn lock_global() -> MutexGuard<'static, Option<GlobalContext>> {
    // Отравление после перехваченной паники не должно навсегда
    // блокировать библиотеку: состояние верификатора атомарно
    // заменяется целиком, частичных изменений в нём не бывает.
    GLOBAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Инициализировать библиотеку.
///
/// `pem_roots`:
///  * `Some(bytes)` — PEM-блоки `-----BEGIN CERTIFICATE-----` с корневыми
///    (и, при необходимости, промежуточными) сертификатами;
///  * `None` — загрузить корни из хранилища ОС (только desktop).
///
/// Повторный вызов после успешного `init` — no-op; после `shutdown` —
/// полноценная повторная инициализация.
pub fn init(pem_roots: Option<&[u8]>) -> Result<()> {
    let mut g = lock_global();
    if g.is_some() {
        return Ok(());
    }
    match init_inner(pem_roots) {
        Ok(ctx) => {
            *g = Some(ctx);
            Ok(())
        }
        Err(e) => {
            // Откат: не оставлять поднятый NSS после неудачного bn_init
            // (ошибка в PEM/системных корнях). После ошибки вызывающий
            // bn_shutdown не зовёт — без отката NSS висел бы в памяти
            // процесса до выхода, а NSS_OWNED навсегда говорил «наше».
            if NSS_OWNED.load(Ordering::Acquire)
                && unsafe { nssx::NSS_Shutdown() } == SECSuccess
            {
                NSS_OWNED.store(false, Ordering::Release);
            }
            Err(e)
        }
    }
}

/// Доступ к верификатору (после успешного `init`).
pub fn global() -> Result<Arc<WebPkiServerVerifier>> {
    lock_global()
        .as_ref()
        .map(|c| c.verifier.clone())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::NotInitialized,
                "bn_init не был вызван или уже был bn_shutdown",
            )
        })
}

/// Выключить библиотеку: сбросить верификатор и NSS (если наше).
///
/// Возвращает ошибку, если `NSS_Shutdown` не удался — NSS держат
/// незакрытые ресурсы (сокеты/соединения): закройте все дескрипторы
/// и повторите. В этом случае выгружать .so (dlclose) нельзя.
///
/// Операции, начавшиеся параллельно с `bn_shutdown`, не защищены:
/// такое соединение получит ошибку NSS/NSPR (не UB); при живых
/// дескрипторах `NSS_Shutdown` просто не удастся.
pub fn shutdown() -> Result<()> {
    // NSS_Shutdown под тем же замком, что и init: иначе в окно между
    // `*g = None` и NSS_Shutdown параллельный bn_init успевал увидеть
    // поднятый NSS, не стать владельцем (NSS_OWNED не выставлялся) и
    // записать GLOBAL=Some — и NSS выключался у «инициализированной»
    // библиотеки. Под замком bn_init дождётся конца выключения и
    // поднимет NSS заново.
    let mut g = lock_global();
    *g = None; // дроп верификатора
    if NSS_OWNED.load(Ordering::Acquire) {
        if unsafe { nssx::NSS_Shutdown() } == SECSuccess {
            NSS_OWNED.store(false, Ordering::Release);
        } else {
            let err = unsafe { nssx::PR_GetError() };
            return Err(Error::new(
                ErrorCode::Generic,
                format!(
                    "NSS_Shutdown: остались незакрытые ресурсы — закройте все \
                     дескрипторы и повторите (NSPR/{err})"
                ),
            ));
        }
    }
    Ok(())
}

fn init_inner(pem_roots: Option<&[u8]>) -> Result<GlobalContext> {
    // 1. Корневые сертификаты — ДО подъёма NSS: разбор PEM и системного
    //    хранилища NSS не требует, и ошибка здесь не должна оставлять
    //    после себя поднятый NSS (страховка — откат в init()).
    let mut roots = RootCertStore::empty();
    let mut loaded = 0usize;
    if let Some(pem) = pem_roots {
        for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(pem)) {
            let cert = cert.map_err(|e| {
                Error::new(ErrorCode::InvalidArgument, format!("PEM parse: {e}"))
            })?;
            roots
                .add(cert)
                .map_err(|e| Error::new(ErrorCode::InvalidArgument, format!("root CA: {e}")))?;
            loaded += 1;
        }
    } else {
        let native = rustls_native_certs::load_native_certs();
        if let Some(err) = native.errors.first() {
            return Err(Error::new(
                ErrorCode::Generic,
                format!("system roots: {err}"),
            ));
        }
        for cert in native.certs {
            if roots.add(cert).is_ok() {
                loaded += 1;
            }
        }
    }
    if loaded == 0 {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "не загружено ни одного корневого сертификата",
        ));
    }

    // 2. Верификатор цепочек (алгоритмы подписей из ring-провайдера rustls).
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .map_err(|e| Error::new(ErrorCode::Generic, format!("verifier: {e}")))?;

    // 3. NSS — последним (NSS_NoDB_Init + NSS_SetDomesticPolicy + проверка
    //    версии): всё, что может упасть без NSS, уже сделано.
    ensure_nss()?;

    Ok(GlobalContext { verifier })
}

/// Поднять NSS, если он ещё не поднят; зафиксировать владение.
///
/// Обычный путь — `nss::init()` (nss-rs): проверка версии, time::init,
/// freebl, `NSS_NoDB_Init`, domestic policy; выполняется один раз за
/// процесс (OnceLock внутри nss-rs). Если NSS уже поднят хост-приложением,
/// nss-rs возвращает `External` и мы НЕ становимся владельцем.
///
/// Особый случай — повторный `bn_init` после нашего `bn_shutdown`:
/// OnceLock nss-rs уже «сыт» и NSS повторно не поднимает, хотя
/// `NSS_Shutdown` его выключил. Тогда поднимаем NSS напрямую
/// (те же вызовы, что делает nss-rs), не полагаясь на его состояние.
fn ensure_nss() -> Result<()> {
    let was_up = unsafe { nssx::NSS_IsInitialized() } != 0;
    nss::init().map_err(|e| Error::new(ErrorCode::Generic, format!("NSS init: {e:?}")))?;
    if !was_up && unsafe { nssx::NSS_IsInitialized() } == 0 {
        // Re-init после bn_shutdown: NSS выключен, а nss-rs не знает.
        if unsafe { nssx::NSS_VersionCheck(c"3.130".as_ptr()) } == 0 {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "требуется NSS >= 3.130 (см. docs/BUILDING.md)",
            ));
        }
        if unsafe { nssx::NSS_NoDB_Init(std::ptr::null()) } != SECSuccess {
            return Err(Error::new(
                ErrorCode::Generic,
                "NSS_NoDB_Init (re-init после bn_shutdown)",
            ));
        }
        if unsafe { nssx::NSS_SetDomesticPolicy() } != SECSuccess {
            return Err(Error::new(
                ErrorCode::Generic,
                "NSS_SetDomesticPolicy (re-init после bn_shutdown)",
            ));
        }
    }
    if !was_up {
        // Мы подняли NSS (сейчас или nss-rs-ом по нашей просьбе) —
        // bn_shutdown имеет право его выключить.
        NSS_OWNED.store(true, Ordering::Release);
    }
    Ok(())
}
