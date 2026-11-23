//! TLS-соединения на NSPR/NSS сокетах.
//!
//! Жизненный цикл (то же, что у nsSSLIOLayer в Firefox):
//!  1. резолв всех адресов + Happy Eyeballs (RFC 8305, задержка старта 300 мс
//!     — как network.http.fast-fallback-to-IPv4);
//!  2. на каждого кандидата: `PR_NewTCPSocket` → `SSL_ImportFD` →
//!     профиль Firefox (`profile::configure_socket`);
//!  3. non-blocking + `PR_Connect`, ожидание через `PR_Poll` по всем
//!     активным; побеждает первый установившийся TCP;
//!  4. `SSL_ResetHandshake(client)` + `SSL_SetURL`;
//!  5. `SSL_ForceHandshake` в цикле — ГЛАВНАЯ ЛОВУШКА NSS:
//!     `PR_Connect` НЕ запускает TLS-handshake, без ForceHandshake
//!     первый PR_Write просто уедет в сеть открытым текстом (см.
//!     docs/PITFALLS.md);
//!  6. при TLS version-intolerance (набор ошибок PSM) — прозрачный
//!     повтор с максимумом TLS 1.2 + downgrade-check;
//!  7. read/write через PR_Read/PR_Write с PR_Poll на WOULD_BLOCK.

use std::cell::RefCell;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::raw::{c_int, c_short, c_uint, c_void};
use std::time::{Duration, Instant};

use crate::error::{Error, ErrorCode, Result};
use crate::profile::{self, Profile, TlsOptions};
use crate::nssx;
use crate::verify;

// Статусы/константы из биндингов (constified-имена).
use nssx::PRStatus_PR_SUCCESS as PR_SUCCESS;
use nssx::SSLNextProtoState_SSL_NEXT_PROTO_NEGOTIATED as NEXT_PROTO_NEGOTIATED;
use nssx::SSLNextProtoState_SSL_NEXT_PROTO_SELECTED as NEXT_PROTO_SELECTED;
use nssx::_SECStatus_SECFailure as SECFailure;
use nssx::_SECStatus_SECSuccess as SECSuccess;

/// Параметры подключения.
pub struct ConnectParams<'a> {
    /// Имя хоста: SNI + проверка сертификата.
    pub host: &'a str,
    /// Адрес; `None` → резолвим `host:port` через getaddrinfo.
    pub addr: Option<SocketAddr>,
    pub port: u16,
    /// Список ALPN (например ["h2", "http/1.1"]); `None` — не предлагать.
    pub alpn: Option<&'a [&'a str]>,
    /// ECHConfigList (байты ech= из DNS HTTPS-записи).
    pub ech_config_list: Option<&'a [u8]>,
    pub profile: Profile,
    pub timeout: Duration,
}

impl<'a> ConnectParams<'a> {
    /// Все адреса хоста (или один, если задан явно). Порядок —
    /// RFC 6724 от getaddrinfo; дальше работает Happy Eyeballs.
    fn resolve_all(&self) -> Result<Vec<SocketAddr>> {
        if let Some(a) = self.addr {
            return Ok(vec![a]);
        }
        let host = self.host.trim_start_matches('[').trim_end_matches(']');
        match (host, self.port).to_socket_addrs() {
            Ok(addrs) => {
                let v: Vec<SocketAddr> = addrs.take(MAX_ADDRS).collect();
                if v.is_empty() {
                    Err(Error::new(ErrorCode::DnsFailure, "адрес не разрешён"))
                } else {
                    Ok(v)
                }
            }
            Err(e) => Err(Error::new(
                ErrorCode::DnsFailure,
                format!("DNS {host}: {e}"),
            )),
        }
    }
}

struct AuthContext {
    host: String,
    /// Ошибка из колбэка верификации (проявится после ForceHandshake).
    cert_error: RefCell<Option<Error>>,
}

pub struct TlsStream {
    fd: *mut nssx::PRFileDesc,
    host: String,
    /// Порт (для authority/Host в HTTP/1.1; нормализован 0 → 443 в FFI).
    port: u16,
    /// Контекст auth-колбэка. Владение здесь, а не в стеке connect():
    /// NSS может вызвать колбэк и ПОСЛЕ handshake (ренеготиация
    /// TLS 1.2), поэтому контекст живёт столько же, сколько fd, и
    /// освобождается только после PR_Close. Устраняет UAF, который
    /// был при владении в try_connect.
    auth_ctx: *mut AuthContext,
    closed: bool,
}

impl TlsStream {
    /// Установить TLS-соединение с профилем Firefox.
    ///
    /// Адреса пробуются с гонкой (Happy Eyeballs, RFC 8305): следующий
    /// адрес стартует через 300 мс, побеждает первый установившийся TCP.
    /// При TLS version-intolerance (набор ошибок как в PSM) handshake
    /// прозрачно повторяется с максимумом TLS 1.2.
    pub fn connect(p: &ConnectParams<'_>) -> Result<TlsStream> {
        let _ = crate::init::global()?;
        let addrs = p.resolve_all()?;
        unsafe {
            match try_connect(p, &addrs, Instant::now() + p.timeout, None) {
                Err(e) if is_version_intolerance(&e) => {
                    // Как PSM в adjustForTLSIntolerance: повтор с пониженным
                    // максимумом (SCSV Firefox при 1.2 не шлёт — только
                    // downgrade-check; см. profile::set_version_range).
                    try_connect(
                        p,
                        &addrs,
                        Instant::now() + p.timeout,
                        Some(nssx::SSL_LIBRARY_VERSION_TLS_1_2 as u16),
                    )
                }
                r => r,
            }
        }
    }

    /// Прочитать до `buf.len()` байт; 0 = EOF (чистое закрытие).
    pub fn read(&mut self, buf: &mut [u8], timeout: Duration) -> Result<usize> {
        self.check_alive()?;
        let deadline = Instant::now() + timeout;
        unsafe {
            loop {
                let n = nssx::PR_Read(self.fd, buf.as_mut_ptr().cast(), buf.len() as c_int);
                if n > 0 {
                    return Ok(n as usize);
                }
                if n == 0 {
                    self.closed = true;
                    return Ok(0);
                }
                let err = nssx::PR_GetError();
                if err == nssx::PR_WOULD_BLOCK_ERROR {
                    poll_status(self.fd, PR_POLL_READ, deadline)?;
                    continue;
                }
                self.closed = true;
                return Err(pr_error(ErrorCode::Generic, err, "PR_Read"));
            }
        }
    }

    /// Записать весь буфер (частичная запись — продолжаем в цикле).
    pub fn write_all(&mut self, buf: &[u8], timeout: Duration) -> Result<()> {
        self.check_alive()?;
        let deadline = Instant::now() + timeout;
        let mut off = 0usize;
        unsafe {
            while off < buf.len() {
                let n = nssx::PR_Write(
                    self.fd,
                    buf[off..].as_ptr().cast(),
                    (buf.len() - off) as c_int,
                );
                if n >= 0 {
                    off += n as usize;
                    continue;
                }
                let err = nssx::PR_GetError();
                if err == nssx::PR_WOULD_BLOCK_ERROR {
                    poll_status(self.fd, PR_POLL_WRITE, deadline)?;
                    continue;
                }
                self.closed = true;
                return Err(pr_error(ErrorCode::Generic, err, "PR_Write"));
            }
        }
        Ok(())
    }

    /// Согласованный ALPN, если был.
    pub fn negotiated_alpn(&self) -> Result<Option<String>> {
        self.check_alive()?;
        unsafe {
            let mut state: nssx::SSLNextProtoState = std::mem::zeroed();
            let mut out = [0u8; 255];
            let mut out_len: c_uint = 0;
            let rv = nssx::SSL_GetNextProto(
                self.fd,
                &mut state,
                out.as_mut_ptr(),
                &mut out_len,
                out.len() as c_uint,
            );
            if rv != SECSuccess {
                return Ok(None);
            }
            match state {
                NEXT_PROTO_NEGOTIATED | NEXT_PROTO_SELECTED => {
                    let s = String::from_utf8_lossy(&out[..out_len as usize]).into_owned();
                    Ok(Some(s))
                }
                _ => Ok(None),
            }
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    /// Порт подключения (нужен для authority/Host в HTTP/1.1).
    pub fn port(&self) -> u16 {
        self.port
    }

    fn check_alive(&self) -> Result<()> {
        if self.closed {
            return Err(Error::new(ErrorCode::Closed, "соединение закрыто"));
        }
        Ok(())
    }

    /// Аккуратное закрытие: close_notify + free. Порядок важен:
    /// PR_Close (который может реентерабельно звать NSS-колбэки)
    /// выполняется ДО освобождения AuthContext.
    pub fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            unsafe {
                // PR_Close на SSL-дескрипторе отправляет close_notify.
                nssx::PR_Close(self.fd);
                if !self.auth_ctx.is_null() {
                    drop(Box::from_raw(self.auth_ctx));
                    self.auth_ctx = std::ptr::null_mut();
                }
            }
        }
    }
}

impl Drop for TlsStream {
    fn drop(&mut self) {
        self.close();
    }
}

// --- Подключение: гонка адресов + fallback --------------------------------------

/// RAII-обёртка над PRFileDesc: закрывает дескриптор в drop, если
/// владение не снято `release()`. Гарантирует отсутствие утечек TCP/SSL
/// дескрипторов на ЛЮБОМ пути выхода (включая панику между созданием
/// сокета и успехом).
struct FdGuard(*mut nssx::PRFileDesc);

impl FdGuard {
    fn raw(&self) -> *mut nssx::PRFileDesc {
        self.0
    }

    /// Отдать владение (для TlsStream); дескриптор больше не закроется в drop.
    fn release(mut self) -> *mut nssx::PRFileDesc {
        std::mem::replace(&mut self.0, std::ptr::null_mut())
    }
}

impl Drop for FdGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { nssx::PR_Close(self.0) };
        }
    }
}

/// Стаггер между запусками адресов (RFC 8305). Firefox:
/// network.http.fast-fallback-to-IPv4 = 300 мс.
const HE_FALLBACK: Duration = Duration::from_millis(300);

/// Максимум адресов на одно подключение.
const MAX_ADDRS: usize = 8;

/// Одна попытка подключения: гонка адресов (`he_connect`) + handshake
/// с профилем Firefox. `version_max` — пониженный максимум версии
/// (fallback-повтор), `None` — обычный (1.2–1.3).
unsafe fn try_connect(
    p: &ConnectParams<'_>,
    addrs: &[SocketAddr],
    deadline: Instant,
    version_max: Option<u16>,
) -> Result<TlsStream> {
    // 1. TCP с гонкой адресов (Happy Eyeballs). FdGuard закрывает
    //    дескриптор на любой ошибке ниже — вручную PR_Close не нужно.
    let fd = he_connect(p, addrs, deadline, version_max)?;

    // 2. Клиентский handshake.
    if nssx::SSL_ResetHandshake(fd.raw(), 0) != SECSuccess {
        let err = nssx::PR_GetError();
        return Err(pr_error(ErrorCode::HandshakeFailed, err, "SSL_ResetHandshake"));
    }
    let chost = std::ffi::CString::new(p.host)
        .map_err(|_| Error::invalid_arg("host содержит NUL"))?;
    if nssx::SSL_SetURL(fd.raw(), chost.as_ptr()) != SECSuccess {
        let err = nssx::PR_GetError();
        return Err(pr_error(ErrorCode::HandshakeFailed, err, "SSL_SetURL"));
    }

    // 3. ALPN (SSL_SetNextProtoNego — это и есть ALPN-API NSS).
    if let Some(list) = p.alpn {
        let wire = alpn_wire(list);
        if nssx::SSL_SetNextProtoNego(fd.raw(), wire.as_ptr(), wire.len() as c_uint)
            != SECSuccess
        {
            let err = nssx::PR_GetError();
            return Err(pr_error(
                ErrorCode::HandshakeFailed,
                err,
                "SSL_SetNextProtoNego",
            ));
        }
    }

    // 4. False start: NSS без колбэка никогда не false-start'ит (даже с
    //    включённой опцией); критерии — рекомендованные NSS, как у PSM.
    if nssx::SSL_SetCanFalseStartCallback(
        fd.raw(),
        Some(can_false_start_cb),
        std::ptr::null_mut(),
    ) != SECSuccess
    {
        return Err(Error::generic("SSL_SetCanFalseStartCallback"));
    }

    // 5. Колбэк верификации сертификата (как PSM в Firefox). Контекст
    //    передаётся NSS сырым указателем; до конца handshake он должен
    //    оставаться живым при ЛЮБОМ исходе — освобождение строго после
    //    PR_Close (см. ниже), иначе реентерабельный вызов колбэка из
    //    PR_Close читал бы освобождённую память (UAF).
    let auth_ctx = Box::into_raw(Box::new(AuthContext {
        host: p.host.to_string(),
        cert_error: RefCell::new(None),
    }));
    if nssx::SSL_AuthCertificateHook(fd.raw(), Some(auth_certificate_cb), auth_ctx.cast())
        != SECSuccess
    {
        drop(fd); // PR_Close — до освобождения контекста
        drop(Box::from_raw(auth_ctx));
        return Err(Error::generic("SSL_AuthCertificateHook"));
    }

    // 6. ForceHandshake — см. docs/PITFALLS.md.
    let handshake: std::result::Result<(), Error> = loop {
        if Instant::now() >= deadline {
            break Err(Error::timeout("handshake: таймаут"));
        }
        let rv = nssx::SSL_ForceHandshake(fd.raw());
        if rv == SECSuccess {
            break Ok(());
        }
        let err = nssx::PR_GetError();
        if err == nssx::PR_WOULD_BLOCK_ERROR {
            // SSL хочет читать ИЛИ писать — опрашиваем оба.
            if let Err(e) = poll_status(fd.raw(), PR_POLL_READ | PR_POLL_WRITE, deadline) {
                break Err(e);
            }
            continue;
        }
        break Err(pr_error(ErrorCode::HandshakeFailed, err, "SSL_ForceHandshake"));
    };

    // Единая точка выхода: сначала PR_Close (fd), потом контекст.
    match handshake {
        Ok(()) => {
            // Успех: контекст переходит в TlsStream (колбэк останется
            // зарегистрированным на fd и после handshake).
            if let Some(cert_err) = (*auth_ctx).cert_error.borrow_mut().take() {
                drop(fd);
                drop(Box::from_raw(auth_ctx));
                return Err(cert_err);
            }
            Ok(TlsStream {
                fd: fd.release(),
                host: p.host.to_string(),
                port: p.port,
                auth_ctx,
                closed: false,
            })
        }
        Err(e) => {
            drop(fd); // PR_Close — до освобождения контекста
            let ctx = Box::from_raw(auth_ctx);
            // Ошибка верификации важнее транспортной.
            if let Some(cert_err) = ctx.cert_error.borrow_mut().take() {
                return Err(cert_err);
            }
            if e.pr_code == nssx::SSLErrorCodes_SSL_ERROR_ECH_RETRY_WITH_ECH as i32 {
                return Err(Error::new(
                    ErrorCode::EchRetryWithEch,
                    "сервер отклонил ECH: обновите ECHConfigList (DNS HTTPS-запись) и повторите подключение",
                ));
            }
            Err(e)
        }
    }
}

/// Happy Eyeballs (RFC 8305): адреса пробуются по порядку (порядок
/// getaddrinfo = RFC 6724), следующий стартует через `HE_FALLBACK`,
/// незавершённые конкурируют; побеждает первый установившийся TCP,
/// остальные закрываются (FdGuard — автоматически, включая выходы по
/// таймауту/ошибке).
unsafe fn he_connect(
    p: &ConnectParams<'_>,
    addrs: &[SocketAddr],
    deadline: Instant,
    version_max: Option<u16>,
) -> Result<FdGuard> {
    let mut active: Vec<FdGuard> = Vec::new();
    let mut next_addr = 0usize;
    let mut next_start = Instant::now(); // первая попытка — немедленно
    let mut last_err: Option<Error> = None;

    loop {
        if Instant::now() >= deadline {
            return Err(Error::timeout("connect: таймаут")); // active → drop → close
        }

        // Стартуем новую попытку, если пришло время.
        if next_addr < addrs.len() && Instant::now() >= next_start {
            match start_attempt(p, addrs[next_addr], version_max) {
                Ok(fd) => active.push(fd),
                Err(e) => last_err = Some(e),
            }
            next_addr += 1;
            next_start = Instant::now() + HE_FALLBACK;
            continue;
        }

        if active.is_empty() {
            if next_addr >= addrs.len() {
                return Err(last_err.unwrap_or_else(|| {
                    Error::new(ErrorCode::ConnectFailed, "соединение не установлено")
                }));
            }
            // Ждём старта следующей попытки (или дедлайна).
            let until = next_start.min(deadline);
            std::thread::sleep(until.saturating_duration_since(Instant::now()));
            continue;
        }

        // Опрашиваем активные сокеты до ближайшего события: старт
        // следующего адреса или общий дедлайн.
        let mut pfds: Vec<nssx::PRPollDesc> = active
            .iter()
            .map(|fd| nssx::PRPollDesc {
                fd: fd.raw(),
                in_flags: PR_POLL_WRITE | PR_POLL_EXCEPT,
                out_flags: 0,
            })
            .collect();
        let until = if next_addr < addrs.len() {
            next_start.min(deadline)
        } else {
            deadline
        };
        let now = Instant::now();
        let ms = ((until - now).as_millis() as u64).clamp(1, 60_000) as u32;
        let n = nssx::PR_Poll(
            pfds.as_mut_ptr(),
            pfds.len() as _,
            nssx::PR_MillisecondsToInterval(ms),
        );
        if n < 0 {
            let err = nssx::PR_GetError();
            if err == nssx::PR_PENDING_INTERRUPT_ERROR {
                continue;
            }
            return Err(pr_error(ErrorCode::Generic, err, "PR_Poll")); // active → drop
        }
        if n == 0 {
            continue; // интервал истёк — пересчитаем условия цикла
        }

        // Готовые сокеты: проверяем завершение connect.
        let mut i = 0usize;
        while i < active.len() {
            if pfds[i].out_flags == 0 {
                i += 1;
                continue;
            }
            let fd = active[i].raw();
            let rv = nssx::PR_ConnectContinue(fd, PR_POLL_WRITE as c_short);
            let connected =
                rv == PR_SUCCESS || nssx::PR_GetError() == nssx::PR_IS_CONNECTED_ERROR;
            if !connected {
                // Попытка не удалась — закрываем (drop FdGuard), пробуем дальше.
                last_err = Some(pr_error(
                    ErrorCode::ConnectFailed,
                    nssx::PR_GetError(),
                    "PR_ConnectContinue",
                ));
                drop(active.remove(i));
                continue;
            }
            // Победитель: остальных закрывает drop всего active.
            let winner = active.swap_remove(i);
            return Ok(winner);
        }
    }
}

/// Создать и сконфигурировать сокет-попытку для одного адреса:
/// TCP → SSL-слой → профиль Firefox → non-blocking → PR_Connect.
/// Каждая ошибка закрывает сокет (FdGuard / явный drop).
unsafe fn start_attempt(
    p: &ConnectParams<'_>,
    addr: SocketAddr,
    version_max: Option<u16>,
) -> Result<FdGuard> {
    let tcp = nssx::PR_NewTCPSocket();
    if tcp.is_null() {
        return Err(Error::new(ErrorCode::Generic, "PR_NewTCPSocket"));
    }
    let imported = nssx::SSL_ImportFD(std::ptr::null_mut(), tcp);
    if imported.is_null() {
        nssx::PR_Close(tcp); // SSL-слой не создан — закрываем TCP сам
        return Err(Error::new(ErrorCode::Generic, "SSL_ImportFD"));
    }
    let fd = FdGuard(imported);
    let tls_opts = TlsOptions {
        ech_config_list: p.ech_config_list,
        version_max,
    };
    if let Err(e) = profile::configure_socket(fd.raw(), p.profile, &tls_opts) {
        return Err(e); // drop(fd) → PR_Close
    }
    if let Err(e) = set_nonblocking(fd.raw(), true) {
        return Err(e);
    }
    let netaddr = netaddr_from(&addr);
    let rv = nssx::PR_Connect(fd.raw(), &netaddr, nssx::PR_INTERVAL_NO_TIMEOUT);
    if rv != PR_SUCCESS {
        let err = nssx::PR_GetError();
        if err != nssx::PR_IN_PROGRESS_ERROR {
            return Err(pr_error(ErrorCode::ConnectFailed, err, "PR_Connect"));
        }
    }
    Ok(fd)
}

/// False start: NSS вызывает колбэк, чтобы решить, можно ли отправлять
/// данные до завершения handshake. Используем рекомендованные NSS
/// критерии (SSL_RecommendedCanFalseStart) — так же, как PSM в Firefox.
unsafe extern "C" fn can_false_start_cb(
    fd: *mut nssx::PRFileDesc,
    _arg: *mut c_void,
    can_false_start: *mut nssx::PRBool,
) -> c_int {
    if nssx::SSL_RecommendedCanFalseStart(fd, can_false_start) == SECSuccess {
        SECSuccess
    } else {
        SECFailure
    }
}

/// Ошибки, по которым PSM считает сервер TLS-неинтолерантным
/// (tlsIntoleranceTelemetryBucket, nsNSSIOLayer.cpp): Firefox
/// повторяет такое подключение с пониженной максимальной версией.
fn is_version_intolerance(e: &Error) -> bool {
    use nssx::*;
    let codes: [i32; 13] = [
        SSLErrorCodes_SSL_ERROR_BAD_MAC_ALERT as i32,
        SSLErrorCodes_SSL_ERROR_BAD_MAC_READ as i32,
        SSLErrorCodes_SSL_ERROR_HANDSHAKE_FAILURE_ALERT as i32,
        SSLErrorCodes_SSL_ERROR_HANDSHAKE_UNEXPECTED_ALERT as i32,
        SSLErrorCodes_SSL_ERROR_ILLEGAL_PARAMETER_ALERT as i32,
        SSLErrorCodes_SSL_ERROR_NO_CYPHER_OVERLAP as i32,
        SSLErrorCodes_SSL_ERROR_UNSUPPORTED_VERSION as i32,
        SSLErrorCodes_SSL_ERROR_PROTOCOL_VERSION_ALERT as i32,
        SSLErrorCodes_SSL_ERROR_BAD_HANDSHAKE_HASH_VALUE as i32,
        SSLErrorCodes_SSL_ERROR_DECODE_ERROR_ALERT as i32,
        SSLErrorCodes_SSL_ERROR_INTERNAL_ERROR_ALERT as i32,
        PR_CONNECT_RESET_ERROR,
        PR_END_OF_FILE_ERROR,
    ];
    codes.contains(&e.pr_code)
}

// --- Вспомогательное ------------------------------------------------------------

const PR_POLL_READ: i16 = 0x1;
const PR_POLL_WRITE: i16 = 0x4;
const PR_POLL_EXCEPT: i16 = 0x2;

unsafe fn set_nonblocking(fd: *mut nssx::PRFileDesc, on: bool) -> Result<()> {
    let mut opt: nssx::PRSocketOptionData = std::mem::zeroed();
    opt.option = nssx::PRSockOption_PR_SockOpt_Nonblocking;
    // Именованное поле union `value`, ветка `non_blocking` (PRBool).
    opt.value.non_blocking = on as i32;
    if nssx::PR_SetSocketOption(fd, &opt) == PR_SUCCESS {
        Ok(())
    } else {
        Err(pr_error(ErrorCode::Generic, nssx::PR_GetError(), "PR_SetSocketOption"))
    }
}

/// Ждать готовности (флаги PR_POLL_*) до дедлайна.
unsafe fn poll_status(
    fd: *mut nssx::PRFileDesc,
    flags: i16,
    deadline: Instant,
) -> Result<()> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(Error::timeout("операция: таймаут"));
        }
        let ms = ((deadline - now).as_millis().min(u32::MAX as u128 - 1) as u32 + 1)
            .min(60_000);
        let mut pfd = nssx::PRPollDesc {
            fd,
            in_flags: flags,
            out_flags: 0,
        };
        let n = nssx::PR_Poll(&mut pfd, 1, nssx::PR_MillisecondsToInterval(ms));
        if n > 0 {
            return Ok(());
        }
        if n == 0 {
            continue; // истёк наш под-таймаут — проверяем дедлайн
        }
        let err = nssx::PR_GetError();
        if err == nssx::PR_PENDING_INTERRUPT_ERROR {
            continue;
        }
        return Err(pr_error(ErrorCode::Generic, err, "PR_Poll"));
    }
}

/// PRNetAddr из SocketAddr. Раскладка PRNetAddr стабильна десятилетиями:
/// [0..2) family (u16, host order), [2..4) port (u16, network order),
/// v4: [4..8) ip; v6: [4..8) flowinfo, [8..24) addr, [24..28) scope_id.
fn netaddr_from(addr: &SocketAddr) -> nssx::PRNetAddr {
    let mut buf = [0u8; 28];
    match addr {
        SocketAddr::V4(a) => {
            buf[0..2].copy_from_slice(&(nssx::PR_AF_INET as u16).to_le_bytes());
            buf[2..4].copy_from_slice(&a.port().to_be_bytes());
            buf[4..8].copy_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            buf[0..2].copy_from_slice(&(nssx::PR_AF_INET6 as u16).to_le_bytes());
            buf[2..4].copy_from_slice(&a.port().to_be_bytes());
            buf[4..8].copy_from_slice(&0u32.to_le_bytes()); // flowinfo
            buf[8..24].copy_from_slice(&a.ip().octets());
            buf[24..28].copy_from_slice(&a.scope_id().to_le_bytes());
        }
    }
    unsafe { std::ptr::read(buf.as_ptr() as *const nssx::PRNetAddr) }
}

/// ALPN-список в wire-формате: длина-байт + протокол.
fn alpn_wire(list: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in list {
        let b = p.as_bytes();
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out
}

/// Колбэк верификации для NSS (аналог AuthCertificate в PSM).
unsafe extern "C" fn auth_certificate_cb(
    arg: *mut c_void,
    fd: *mut nssx::PRFileDesc,
    _checksig: c_int,
    _is_server: c_int,
) -> c_int {
    let ctx = &*(arg as *const AuthContext);
    match peer_chain(fd) {
        Ok(chain) => match verify::verify_server_chain(&chain, &ctx.host) {
            Ok(()) => SECSuccess,
            Err(e) => {
                *ctx.cert_error.borrow_mut() = Some(e);
                nssx::PR_SetError(nssx::SSLErrorCodes_SSL_ERROR_BAD_CERTIFICATE as i32, 0);
                SECFailure
            }
        },
        Err(e) => {
            *ctx.cert_error.borrow_mut() = Some(e);
            nssx::PR_SetError(nssx::SSLErrorCodes_SSL_ERROR_BAD_CERTIFICATE as i32, 0);
            SECFailure
        }
    }
}

/// Снять цепочку сертификатов собеседника (DER-список).
/// SSL_PeerCertificateChainDER — экспериментальный API (макрос).
unsafe fn peer_chain(fd: *mut nssx::PRFileDesc) -> Result<Vec<Vec<u8>>> {
    let get_chain: Option<
        unsafe extern "C" fn(*mut nssx::PRFileDesc, *mut *mut nssx::SECItemArray) -> c_int,
    > = resolve_experimental(c"SSL_PeerCertificateChainDER");
    let get_chain = get_chain.ok_or_else(|| {
        Error::new(ErrorCode::Unsupported, "NSS без SSL_PeerCertificateChainDER")
    })?;
    let mut arr: *mut nssx::SECItemArray = std::ptr::null_mut();
    if get_chain(fd, &mut arr) != SECSuccess {
        return Err(pr_error(
            ErrorCode::HandshakeFailed,
            nssx::PR_GetError(),
            "SSL_PeerCertificateChainDER",
        ));
    }
    if arr.is_null() {
        return Err(Error::new(
            ErrorCode::HandshakeFailed,
            "сервер не предоставил цепочку сертификатов",
        ));
    }
    let items = std::slice::from_raw_parts((*arr).items, (*arr).len as usize);
    let mut chain = Vec::with_capacity(items.len());
    for it in items {
        if !it.data.is_null() {
            chain.push(std::slice::from_raw_parts(it.data, it.len as usize).to_vec());
        }
    }
    nssx::SECITEM_FreeArray(arr, 1);
    Ok(chain)
}

/// Ошибка NSPR → Error (с исходным кодом для retry-логики).
unsafe fn pr_error(code: ErrorCode, pr: i32, what: &str) -> Error {
    let p = nssx::PR_ErrorToString(pr, nssx::PR_LANGUAGE_I_DEFAULT);
    let msg = if p.is_null() {
        format!("{what}: NSPR/{pr}")
    } else {
        format!(
            "{what}: {} (NSPR/{pr})",
            std::ffi::CStr::from_ptr(p).to_string_lossy()
        )
    };
    Error::new(code, msg).with_pr_code(pr)
}

/// Разрешение экспериментального API NSS по имени.
unsafe fn resolve_experimental<F: Copy>(name: &std::ffi::CStr) -> Option<F> {
    let p = nssx::SSL_GetExperimentalAPI(name.as_ptr());
    if p.is_null() {
        return None;
    }
    let raw: unsafe extern "C" fn() = std::mem::transmute(p);
    Some(unsafe { std::mem::transmute_copy::<_, F>(&raw) })
}
