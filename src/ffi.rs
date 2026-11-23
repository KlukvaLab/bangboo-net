//! C ABI (см. ffi/bangboo_net.h).
//!
//! Правила:
//!  * дескрипторы — указатели на Box<T>; NULL недопустим;
//!  * отрицательный возврат — код ошибки из `ErrorCode`;
//!    детали — bn_last_error_message();
//!  * строки — UTF-8 с завершающим NUL, валидны до следующего вызова
//!    библиотеки в этом потоке;
//!  * буферы «на выход»: при нехватке места возвращается -13
//!    (BufferTooSmall), нужный размер — в out-параметре `needed`.
//!
//! Устойчивость (см. docs/SECURITY.md):
//!  * каждый экспорт обёрнут в catch_unwind: паника Rust не пересекает
//!    границу C ABI (это UB и ломает стек ART/C++), вместо этого
//!    возвращается -14 (Panic);
//!  * состояние каждого дескриптора под Mutex: одновременные вызовы из
//!    разных потоков сериализуются, гонок данных нет;
//!  * жизненный цикл — через «билет» (RwLock в Arc): операции держат
//!    read-lock, close/free — write-lock и только под ним освобождают
//!    Box. Операция, начавшаяся до close, использует корректную память;
//!  * close/free принимают адрес указателя (BnTls ** и т.п.) и
//!    обнуляют его — повторный вызов безопасен (no-op), двойного
//!    освобождения не будет;
//!  * после bn_h3_close дескрипторы его запросов осиротевают:
//!    bn_h3_req_* возвращают -9 (Closed), а не падают на висячем
//!    указателе.

use std::cell::RefCell;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use neqo_transport::StreamId;

use crate::error::{set_last_error, set_last_error_str, Error, ErrorCode};
use crate::limits;
use crate::profile::Profile;
use crate::http1;
use crate::quic::{H3ConnectParams, H3Connection};
use crate::tls::{ConnectParams as TlsConnectParams, TlsStream};
use crate::ws::{Opcode, WsStream};

// --- дескрипторы ---------------------------------------------------------------

/// Билет жизни дескриптора. Операции держат read-lock, close/free —
/// write-lock; Box освобождается только под write-lock, поэтому ни одна
/// начавшаяся операция не может коснуться освобождённой памяти.
struct Ticket {
    use_lock: RwLock<()>,
}

type TicketRef = Arc<Ticket>;

fn new_ticket() -> TicketRef {
    Arc::new(Ticket {
        use_lock: RwLock::new(()),
    })
}

fn rd(t: &Ticket) -> RwLockReadGuard<'_, ()> {
    // Отравление после перехваченной паники не должно блокировать
    // библиотеку навсегда.
    t.use_lock.read().unwrap_or_else(|e| e.into_inner())
}

fn wr(t: &Ticket) -> RwLockWriteGuard<'_, ()> {
    t.use_lock.write().unwrap_or_else(|e| e.into_inner())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Opaque-типы для заголовка.
pub struct BnTls {
    inner: Mutex<TlsStream>,
    ticket: TicketRef,
}
pub struct BnWs {
    inner: Mutex<WsStream>,
    ticket: TicketRef,
}
pub struct BnH3 {
    inner: Mutex<H3Connection>,
    /// Дескрипторы живых запросов (для осиротивания при close).
    requests: Mutex<Vec<*mut BnH3Request>>,
    ticket: TicketRef,
}
pub struct BnH3Request {
    /// Соединение; NULL после bn_h3_close (осиротевший запрос).
    conn: AtomicPtr<BnH3>,
    stream_id: u64,
    /// Клон билета соединения: пока запрос жив, ticket жив, а значит
    /// bn_h3_close дождётся окончания операций и только потом освободит
    /// Box<BnH3>.
    ticket: TicketRef,
}
pub struct BnHttpResponse {
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    ticket: TicketRef,
}

/// Параметры подключения (общие для TLS/H3/WSS).
#[repr(C)]
pub struct BnConnectOptions {
    /// Имя хоста (SNI, проверка сертификата). UTF-8.
    pub host: *const c_char,
    /// Предварительно разрешённый IP (Kotlin делает DNS); NULL → резолвим.
    pub ip: *const c_char,
    pub port: u16,
    /// ALPN для TLS-ветки, wire-строка вида "h2,http/1.1"; NULL → нет ALPN.
    pub alpn: *const c_char,
    /// ECHConfigList (сырые байты из DNS HTTPS-записи); NULL → без ECH.
    pub ech_config_list: *const u8,
    pub ech_config_list_len: u32,
    /// Токен resumption QUIC (bn_h3_take_resumption_token).
    pub resumption_token: *const u8,
    pub resumption_token_len: u32,
    /// Таймаут connect+handshake, мс.
    pub timeout_ms: u32,
    /// 0 = firefox-desktop, 1 = firefox-android.
    pub profile: u8,
    /// Зарезервировано.
    pub reserved: [u8; 7],
}

#[repr(C)]
pub struct BnHeader {
    pub name: *const c_char,
    pub value: *const u8,
    pub value_len: u32,
}

// --- инфраструктура ------------------------------------------------------------

/// Обёртка всех экспортов: паника НЕ пересекает границу C ABI
/// (unwind через extern "C" — UB: ломает стек C++/ART). Вместо этого
/// вызывающий получает fallback (обычно -14) и сообщение через
/// bn_last_error_message.
///
/// На входе КАЖДОЙ операции слот последней ошибки очищается: слот
/// всегда отражает только последний вызов в этом потоке (свежесть
/// для многопоточных/JNA-сценариев; чтение — bn_last_error_code /
/// bn_last_error_message, оба не разрушающие).
fn bn_guard<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    crate::error::clear_last_error();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(payload) => {
            let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "паника без сообщения".to_string()
            };
            crate::error::set_panic_error(&format!(
                "перехвачена паника Rust: {msg}; состояние дескриптора могло \
                 быть нарушено — закройте его и не используйте дальше"
            ));
            fallback
        }
    }
}

fn err_code(e: &Error) -> c_int {
    set_last_error(e);
    -(e.code as c_int)
}

fn check_ptr<T>(p: *const T) -> Result<(), Error> {
    if p.is_null() {
        Err(Error::invalid_arg("нулевой указатель"))
    } else {
        Ok(())
    }
}

unsafe fn cstr<'a>(p: *const c_char) -> Result<&'a str, Error> {
    if p.is_null() {
        return Err(Error::invalid_arg("нулевая строка"));
    }
    CStr::from_ptr(p).to_str().map_err(|_| Error::invalid_arg("не UTF-8"))
}

unsafe fn blob<'a>(p: *const u8, len: u32) -> Option<&'a [u8]> {
    if p.is_null() || len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(p, len as usize))
    }
}

/// Дефолтный таймаут операций, мс (контракт заголовка: timeout_ms=0 → 30000).
const DEFAULT_TIMEOUT_MS: u32 = 30_000;
/// Потолок таймаута (24 ч): PR_MillisecondsToInterval принимает PRUint32 и
/// на значениях порядка u32::MAX (~49.7 суток) переполняется, а
/// Instant + Duration на таких величинах может паниковать.
const MAX_TIMEOUT_MS: u32 = 86_400_000;

fn dur(ms: u32) -> Duration {
    let ms = if ms == 0 {
        DEFAULT_TIMEOUT_MS
    } else {
        ms.min(MAX_TIMEOUT_MS)
    };
    Duration::from_millis(ms as u64)
}

/// Записать нужный размер в out-параметр `needed` (если передан).
unsafe fn set_needed(needed: *mut u32, n: usize) {
    if !needed.is_null() {
        *needed = n.min(u32::MAX as usize) as u32;
    }
}

/// Слишком мал: -13 + нужный размер в *needed.
unsafe fn too_small(needed: *mut u32, need: usize) -> c_int {
    set_needed(needed, need);
    set_last_error(&Error::new(
        ErrorCode::BufferTooSmall,
        format!("буфер вызывающего мал: нужно {need} байт"),
    ));
    -(ErrorCode::BufferTooSmall as c_int)
}

/// Скопировать `data` в `out` (вместимостью `cap`).
/// `nul = true` — дописать завершающий NUL (строковые буферы).
/// `Ok(len)` — записано len байт (без NUL); `Err(need)` — буфер
/// мал или NULL, требуется `need` байт.
unsafe fn copy_out(
    out: *mut u8,
    cap: u32,
    data: &[u8],
    nul: bool,
) -> std::result::Result<usize, usize> {
    let need = data.len() + usize::from(nul);
    if need == 0 {
        return Ok(0);
    }
    if out.is_null() || need > cap as usize {
        return Err(need);
    }
    if !data.is_empty() {
        ptr::copy_nonoverlapping(data.as_ptr(), out, data.len());
    }
    if nul {
        *out.add(data.len()) = 0;
    }
    Ok(data.len())
}

/// Копировать пару (имя, значение) заголовка с NUL-терминацией обоих.
/// Проверяет ОБА буфера до записи: при нехватке возвращает -13 и
/// записывает оба нужных размера (с NUL).
#[allow(clippy::too_many_arguments)]
unsafe fn copy_header_pair(
    name: &[u8],
    name_buf: *mut c_char,
    name_cap: u32,
    value: &[u8],
    value_buf: *mut u8,
    value_cap: u32,
    needed_name: *mut u32,
    needed_value: *mut u32,
) -> c_int {
    let need_name = name.len() + 1;
    let need_value = value.len() + 1;
    if need_name > name_cap as usize
        || need_value > value_cap as usize
        || name_buf.is_null()
        || value_buf.is_null()
    {
        set_needed(needed_name, need_name);
        set_needed(needed_value, need_value);
        set_last_error(&Error::new(
            ErrorCode::BufferTooSmall,
            format!(
                "буферы заголовка малы: имя {need_name} байт, значение {need_value} байт"
            ),
        ));
        return -(ErrorCode::BufferTooSmall as c_int);
    }
    ptr::copy_nonoverlapping(name.as_ptr(), name_buf as *mut u8, name.len());
    *name_buf.add(name.len()) = 0;
    ptr::copy_nonoverlapping(value.as_ptr(), value_buf, value.len());
    *value_buf.add(value.len()) = 0; // NUL для удобства printf/strcmp
    value.len() as c_int
}

// --- init / версии ---------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn bn_init(pem_roots: *const u8, pem_roots_len: u32) -> c_int {
    bn_guard(-1, || {
        let roots = blob(pem_roots, pem_roots_len);
        match crate::init::init(roots) {
            Ok(()) => 0,
            Err(e) => err_code(&e),
        }
    })
}

/// Выключить библиотеку: сбросить верификатор и NSS (если подняли мы).
/// Все дескрипторы должны быть закрыты заранее; иначе ошибка (в этом
/// случае dlclose .so нельзя). После успеха возможен повторный bn_init.
#[no_mangle]
pub unsafe extern "C" fn bn_shutdown() -> c_int {
    bn_guard(-1, || match crate::init::shutdown() {
        Ok(()) => 0,
        Err(e) => err_code(&e),
    })
}

#[no_mangle]
pub unsafe extern "C" fn bn_last_error_message() -> *const c_char {
    bn_last_error_message_impl()
}

/// Код последней ошибки в этом потоке: 1..=15 (ErrorCode) или 0, если
/// ошибки не было. Для функций, возвращающих указатель (NULL при ошибке):
/// вызывайте ДО bn_last_error_message — тот очищает слот.
#[no_mangle]
pub unsafe extern "C" fn bn_last_error_code() -> c_int {
    crate::error::last_error_code()
}

/// Лимиты размеров (анти-DoS): тело HTTP/1.1-ответа, сообщение WS,
/// ответ HTTP/3. 0 = без лимита. По умолчанию 64 МиБ.
#[no_mangle]
pub unsafe extern "C" fn bn_set_limits(
    max_http1_body: u32,
    max_ws_message: u32,
    max_h3_response: u32,
) -> c_int {
    bn_guard(-1, || {
        limits::set(
            max_http1_body as usize,
            max_ws_message as usize,
            max_h3_response as usize,
        );
        0
    })
}

#[no_mangle]
pub unsafe extern "C" fn bn_version() -> *const c_char {
    bn_guard(ptr::null(), || {
        let v = crate::version_string();
        VERSION_BUF.with(|buf| {
            let mut b = buf.borrow_mut();
            let bytes = v.as_bytes();
            let mut take = bytes.len().min(b.len() - 1);
            while take > 0 && !v.is_char_boundary(take) {
                take -= 1;
            }
            b[..take].copy_from_slice(&bytes[..take]);
            b[take] = 0;
            b.as_ptr() as *const c_char
        })
    })
}

// --- TLS ------------------------------------------------------------------------

unsafe fn connect_options_parse(
    o: *const BnConnectOptions,
) -> Result<(String, Option<std::net::SocketAddr>, Option<Vec<String>>, Option<Vec<u8>>, Option<Vec<u8>>, u32, u16, Profile), Error> {
    check_ptr(o)?;
    let o = &*o;
    let host = cstr(o.host)?.to_string();
    // Дефолты контракта (заголовок): port=0 => 443; timeout_ms=0 => 30000
    // (нормализуется в dur()).
    let port = if o.port == 0 { 443 } else { o.port };
    // ip — голый адрес ("127.0.0.1"/"::1"); порт берём из o.port (с дефолтом).
    let ip = if o.ip.is_null() {
        None
    } else {
        let s = cstr(o.ip)?;
        let addr: std::net::IpAddr = s
            .parse()
            .map_err(|_| Error::invalid_arg("не удалось разобрать ip"))?;
        Some(std::net::SocketAddr::new(addr, port))
    };
    let alpn = if o.alpn.is_null() {
        None
    } else {
        let s = cstr(o.alpn)?;
        Some(
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>(),
        )
    };
    let ech = blob(o.ech_config_list, o.ech_config_list_len).map(<[u8]>::to_vec);
    let token = blob(o.resumption_token, o.resumption_token_len).map(<[u8]>::to_vec);
    Ok((
        host,
        ip,
        alpn,
        ech,
        token,
        o.timeout_ms,
        port,
        Profile::from_u8(o.profile),
    ))
}

#[no_mangle]
pub unsafe extern "C" fn bn_tls_connect(
    opts: *const BnConnectOptions,
) -> *mut BnTls {
    bn_guard(ptr::null_mut(), || {
        let parsed = match connect_options_parse(opts) {
            Ok(v) => v,
            Err(e) => {
                set_last_error(&e);
                return ptr::null_mut();
            }
        };
        let (host, ip, alpn, ech, _token, timeout_ms, port, profile) = parsed;
        let alpn_refs: Option<Vec<&str>> =
            alpn.as_ref().map(|v| v.iter().map(String::as_str).collect());
        let p = TlsConnectParams {
            host: &host,
            addr: ip,
            port,
            alpn: alpn_refs.as_deref(),
            ech_config_list: ech.as_deref(),
            profile,
            timeout: dur(timeout_ms),
        };
        match TlsStream::connect(&p) {
            Ok(s) => Box::into_raw(Box::new(BnTls {
                inner: Mutex::new(s),
                ticket: new_ticket(),
            })),
            Err(e) => {
                set_last_error(&e);
                ptr::null_mut()
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn bn_tls_read(
    s: *mut BnTls,
    buf: *mut u8,
    len: u32,
    timeout_ms: u32,
) -> c_int {
    bn_guard(-(ErrorCode::Panic as c_int), || {
        let s = match s.as_ref() {
            Some(s) => s,
            None => {
                set_last_error_str("bn_tls_read: NULL");
                return -(ErrorCode::InvalidArgument as c_int);
            }
        };
        let _rd = rd(&s.ticket);
        if len == 0 {
            return 0; // nothing to read — не трогаем NULL-буфер
        }
        if buf.is_null() {
            return -(ErrorCode::InvalidArgument as c_int);
        }
        let out = std::slice::from_raw_parts_mut(buf, len as usize);
        match lock(&s.inner).read(out, dur(timeout_ms)) {
            Ok(n) => n as c_int,
            Err(e) => err_code(&e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn bn_tls_write(
    s: *mut BnTls,
    buf: *const u8,
    len: u32,
    timeout_ms: u32,
) -> c_int {
    bn_guard(-(ErrorCode::Panic as c_int), || {
        let s = match s.as_ref() {
            Some(s) => s,
            None => {
                set_last_error_str("bn_tls_write: NULL");
                return -(ErrorCode::InvalidArgument as c_int);
            }
        };
        let _rd = rd(&s.ticket);
        let data = match blob(buf, len) {
            Some(d) => d,
            None => {
                // NULL-буфер при len > 0 — ошибка вызова, а не «успешно
                // отправлено 0 байт» (молчаливая потеря данных).
                if len > 0 {
                    set_last_error_str("bn_tls_write: NULL-буфер при len > 0");
                    return -(ErrorCode::InvalidArgument as c_int);
                }
                &[]
            }
        };
        match lock(&s.inner).write_all(data, dur(timeout_ms)) {
            Ok(()) => data.len() as c_int,
            Err(e) => err_code(&e),
        }
    })
}

/// Согласованный ALPN. Возвращает длину (без NUL) или 0, если ALPN не
/// было. Буфер мал → -13, нужный размер (с NUL) — в *needed.
#[no_mangle]
pub unsafe extern "C" fn bn_tls_alpn(
    s: *mut BnTls,
    out: *mut c_char,
    out_cap: u32,
    needed: *mut u32,
) -> c_int {
    bn_guard(-(ErrorCode::Panic as c_int), || {
        let s = match s.as_ref() {
            Some(s) => s,
            None => {
                set_last_error_str("bn_tls_alpn: NULL");
                return -(ErrorCode::InvalidArgument as c_int);
            }
        };
        let _rd = rd(&s.ticket);
        match lock(&s.inner).negotiated_alpn() {
            Ok(Some(proto)) => match copy_out(out as *mut u8, out_cap, proto.as_bytes(), true) {
                Ok(n) => n as c_int,
                Err(need) => too_small(needed, need),
            },
            Ok(None) => 0,
            Err(e) => err_code(&e),
        }
    })
}

/// Закрыть дескриптор TLS и обнулить указатель. Повторный вызов
/// (в т.ч. с NULL) — безопасный no-op.
#[no_mangle]
pub unsafe extern "C" fn bn_tls_close(s: *mut *mut BnTls) {
    bn_guard((), || {
        if s.is_null() {
            return;
        }
        let p = *s;
        if p.is_null() {
            return;
        }
        let href = &*p;
        // Клонируем Arc билета ДО взятия замка: локальные переменные
        // дропаются в обратном порядке, поэтому write-замок снимется,
        // пока клон ещё держит билет живым. Без клона unlock писал бы
        // в слово состояния RwLock уже освобождённого билета (UAF).
        let ticket = Arc::clone(&href.ticket);
        let _wr = wr(&ticket); // ждём активные операции
        lock(&href.inner).close();
        drop(Box::from_raw(p));
        *s = ptr::null_mut();
    })
}

// --- HTTP/1.1 поверх TLS -----------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn bn_http1_fetch(
    s: *mut BnTls,
    method: *const c_char,
    target: *const c_char,
    headers: *const BnHeader,
    nheaders: u32,
    body: *const u8,
    body_len: u32,
    timeout_ms: u32,
) -> *mut BnHttpResponse {
    bn_guard(ptr::null_mut(), || {
        let s = match s.as_ref() {
            Some(s) => s,
            None => {
                set_last_error_str("bn_http1_fetch: NULL");
                return ptr::null_mut();
            }
        };
        let _rd = rd(&s.ticket);
        let run = || -> Result<BnHttpResponse, Error> {
            let method = cstr(method)?;
            let target = cstr(target)?;
            let mut hdrs: Vec<(String, String)> = Vec::new();
            if !headers.is_null() {
                for i in 0..nheaders as usize {
                    let h = &*headers.add(i);
                    let name = cstr(h.name)?;
                    let value = blob(h.value, h.value_len)
                        .map(|b| String::from_utf8_lossy(b).into_owned())
                        .unwrap_or_default();
                    hdrs.push((name.to_string(), value));
                }
            }
            // Authority = host[:port] — из реального порта подключения
            // (раньше был захардкожен 443, порт :8443 давал неверный Host).
            let (host, port) = {
                let g = lock(&s.inner);
                (g.host().to_string(), g.port())
            };
            let authority = http_authority(&host, port);
            let req = http1::Request {
                method,
                target,
                authority: &authority,
                headers: &hdrs,
                body: blob(body, body_len),
                // Keep-alive: несколько fetch по одному дескриптору
                // (как Firefox); WSS использует Upgrade.
                connection: http1::ConnectionHeader::KeepAlive,
            };
            let timeout = dur(timeout_ms);
            let mut g = lock(&s.inner);
            let mut resp = http1::send_request_and_read_head(&mut g, &req, timeout)?;
            http1::read_body(&mut g, &mut resp, timeout)?;
            drop(g);
            Ok(BnHttpResponse {
                status: resp.status,
                headers: resp
                    .headers
                    .into_iter()
                    .map(|(n, v)| (n, v.into_bytes()))
                    .collect(),
                body: resp.body,
                ticket: new_ticket(),
            })
        };
        match run() {
            Ok(r) => Box::into_raw(Box::new(r)),
            Err(e) => {
                set_last_error(&e);
                ptr::null_mut()
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn bn_http1_response_status(r: *const BnHttpResponse) -> c_int {
    bn_guard(-(ErrorCode::InvalidArgument as c_int), || {
        match r.as_ref() {
            Some(r) => {
                let _rd = rd(&r.ticket);
                r.status as c_int
            }
            None => -(ErrorCode::InvalidArgument as c_int),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn bn_http1_response_header_count(r: *const BnHttpResponse) -> c_int {
    bn_guard(-(ErrorCode::InvalidArgument as c_int), || {
        match r.as_ref() {
            Some(r) => {
                let _rd = rd(&r.ticket);
                r.headers.len() as c_int
            }
            None => -(ErrorCode::InvalidArgument as c_int),
        }
    })
}

/// Копирует i-й заголовок: name (NUL-terminated) и value (NUL-terminated
/// для удобства printf/strcmp). Возвращает длину value (без NUL).
/// Буферы малы/NULL → -13; нужные размеры (с NUL) — в *needed_name и
/// *needed_value (оба записываются при ошибке).
#[no_mangle]
pub unsafe extern "C" fn bn_http1_response_header(
    r: *const BnHttpResponse,
    index: c_int,
    name_buf: *mut c_char,
    name_cap: u32,
    value_buf: *mut u8,
    value_cap: u32,
    needed_name: *mut u32,
    needed_value: *mut u32,
) -> c_int {
    bn_guard(-(ErrorCode::Panic as c_int), || {
        let r = match r.as_ref() {
            Some(r) => r,
            None => {
                set_last_error_str("bn_http1_response_header: NULL");
                return -(ErrorCode::InvalidArgument as c_int);
            }
        };
        let _rd = rd(&r.ticket);
        if index < 0 || index as usize >= r.headers.len() {
            return -(ErrorCode::InvalidArgument as c_int);
        }
        let (name, value) = &r.headers[index as usize];
        copy_header_pair(
            name.as_bytes(),
            name_buf,
            name_cap,
            value,
            value_buf,
            value_cap,
            needed_name,
            needed_value,
        )
    })
}

#[no_mangle]
pub unsafe extern "C" fn bn_http1_response_body(
    r: *const BnHttpResponse,
    out: *mut u8,
    out_cap: u32,
    needed: *mut u32,
) -> c_int {
    bn_guard(-(ErrorCode::Panic as c_int), || {
        let r = match r.as_ref() {
            Some(r) => r,
            None => {
                set_last_error_str("bn_http1_response_body: NULL");
                return -(ErrorCode::InvalidArgument as c_int);
            }
        };
        let _rd = rd(&r.ticket);
        match copy_out(out, out_cap, &r.body, false) {
            Ok(n) => n as c_int,
            Err(need) => too_small(needed, need),
        }
    })
}

/// Освободить ответ и обнулить указатель. Повторный вызов — no-op.
#[no_mangle]
pub unsafe extern "C" fn bn_http1_response_free(r: *mut *mut BnHttpResponse) {
    bn_guard((), || {
        if r.is_null() {
            return;
        }
        let p = *r;
        if p.is_null() {
            return;
        }
        let href = &*p;
        // Клон Arc билета — защита от UAF при unlock (см. bn_tls_close).
        let ticket = Arc::clone(&href.ticket);
        let _wr = wr(&ticket);
        drop(Box::from_raw(p));
        *r = ptr::null_mut();
    })
}

// --- WSS ------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn bn_ws_connect(
    opts: *const BnConnectOptions,
    path: *const c_char,
    headers: *const BnHeader,
    nheaders: u32,
) -> *mut BnWs {
    bn_guard(ptr::null_mut(), || {
        let parsed = match connect_options_parse(opts) {
            Ok(v) => v,
            Err(e) => {
                set_last_error(&e);
                return ptr::null_mut();
            }
        };
        let (host, ip, alpn, ech, _token, timeout_ms, port, profile) = parsed;
        let path = match cstr(path) {
            Ok(p) => p,
            Err(e) => {
                set_last_error(&e);
                return ptr::null_mut();
            }
        };
        let mut hdrs: Vec<(String, Vec<u8>)> = Vec::new();
        if !headers.is_null() {
            for i in 0..nheaders as usize {
                let h = &*headers.add(i);
                match cstr(h.name) {
                    Ok(n) => hdrs.push((
                        n.to_string(),
                        blob(h.value, h.value_len).map(<[u8]>::to_vec).unwrap_or_default(),
                    )),
                    Err(e) => {
                        set_last_error(&e);
                        return ptr::null_mut();
                    }
                }
            }
        }
        let hdrs_str: Vec<(String, String)> = hdrs
            .into_iter()
            .map(|(n, v)| (n, String::from_utf8_lossy(&v).into_owned()))
            .collect();
        let alpn_refs: Option<Vec<&str>> =
            alpn.as_ref().map(|v| v.iter().map(String::as_str).collect());
        let p = TlsConnectParams {
            host: &host,
            addr: ip,
            port,
            // По умолчанию WSS предлагает [h2, http/1.1] (как Firefox), но
            // пользовательский список из BnConnectOptions.alpn имеет приоритет
            // (например "http/1.1" для гарантии WSS на h2-серверах).
            alpn: alpn_refs.as_deref(),
            ech_config_list: ech.as_deref(),
            profile,
            timeout: dur(timeout_ms),
        };
        match WsStream::connect(&p, path, &hdrs_str, dur(timeout_ms)) {
            Ok(w) => Box::into_raw(Box::new(BnWs {
                inner: Mutex::new(w),
                ticket: new_ticket(),
            })),
            Err(e) => {
                set_last_error(&e);
                ptr::null_mut()
            }
        }
    })
}

/// opcode: 1=text, 2=binary, 9=ping.
#[no_mangle]
pub unsafe extern "C" fn bn_ws_send(
    w: *mut BnWs,
    opcode: u8,
    data: *const u8,
    len: u32,
    timeout_ms: u32,
) -> c_int {
    bn_guard(-(ErrorCode::Panic as c_int), || {
        let w = match w.as_ref() {
            Some(w) => w,
            None => {
                set_last_error_str("bn_ws_send: NULL");
                return -(ErrorCode::InvalidArgument as c_int);
            }
        };
        let _rd = rd(&w.ticket);
        let op = match opcode {
            1 => Opcode::Text,
            2 => Opcode::Binary,
            9 => Opcode::Ping,
            _ => {
                set_last_error_str("bn_ws_send: opcode должен быть 1, 2 или 9");
                return -(ErrorCode::InvalidArgument as c_int);
            }
        };
        let payload = match blob(data, len) {
            Some(d) => d,
            None => {
                // NULL-буфер при len > 0 — ошибка вызова (см. bn_tls_write).
                if len > 0 {
                    set_last_error_str("bn_ws_send: NULL-буфер при len > 0");
                    return -(ErrorCode::InvalidArgument as c_int);
                }
                &[]
            }
        };
        match lock(&w.inner).send(op, payload, dur(timeout_ms)) {
            Ok(()) => payload.len() as c_int,
            Err(e) => err_code(&e),
        }
    })
}

/// Ждёт сообщение. Возвращает длину payload (≥0) или код ошибки (<0).
/// opcode_out: 1=text, 2=binary, 8=close, 10=pong. Буфер мал → -13,
/// нужный размер — в *needed (сообщение при этом НЕ теряется: оно
/// вернётся при следующем вызове).
#[no_mangle]
pub unsafe extern "C" fn bn_ws_recv(
    w: *mut BnWs,
    opcode_out: *mut u8,
    buf: *mut u8,
    buf_cap: u32,
    timeout_ms: u32,
    needed: *mut u32,
) -> c_int {
    bn_guard(-(ErrorCode::Panic as c_int), || {
        let w = match w.as_ref() {
            Some(w) => w,
            None => {
                set_last_error_str("bn_ws_recv: NULL");
                return -(ErrorCode::InvalidArgument as c_int);
            }
        };
        let _rd = rd(&w.ticket);
        let mut g = lock(&w.inner);
        match g.recv(dur(timeout_ms)) {
            Ok(msg) => {
                if msg.payload.len() > buf_cap as usize {
                    // Слишком мал: вернуть в очередь, сообщить нужный размер.
                    let need = msg.payload.len();
                    g.stash(msg);
                    return too_small(needed, need);
                }
                if !msg.payload.is_empty() && buf.is_null() {
                    return -(ErrorCode::InvalidArgument as c_int);
                }
                if !opcode_out.is_null() {
                    *opcode_out = msg.opcode as u8;
                }
                if !msg.payload.is_empty() {
                    ptr::copy_nonoverlapping(msg.payload.as_ptr(), buf, msg.payload.len());
                }
                msg.payload.len() as c_int
            }
            Err(e) => err_code(&e),
        }
    })
}

/// Отправляет close-кадр, закрывает TLS, освобождает дескриптор и
/// обнуляет указатель. Повторный вызов — no-op.
#[no_mangle]
pub unsafe extern "C" fn bn_ws_close(
    w: *mut *mut BnWs,
    code: u16,
    reason: *const c_char,
    timeout_ms: u32,
) -> c_int {
    bn_guard(-(ErrorCode::Panic as c_int), || {
        if w.is_null() {
            return 0;
        }
        let p = *w;
        if p.is_null() {
            return 0;
        }
        let wref = &*p;
        // Клон Arc билета — защита от UAF при unlock (см. bn_tls_close).
        let ticket = Arc::clone(&wref.ticket);
        let _wr = wr(&ticket); // ждём активные операции
        let reason = if reason.is_null() {
            String::new()
        } else {
            CStr::from_ptr(reason).to_string_lossy().into_owned()
        };
        let rv = lock(&wref.inner).close(code, &reason, dur(timeout_ms));
        drop(Box::from_raw(p));
        *w = ptr::null_mut();
        match rv {
            Ok(()) => 0,
            Err(e) => err_code(&e),
        }
    })
}

// --- HTTP/3 ----------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn bn_h3_connect(opts: *const BnConnectOptions) -> *mut BnH3 {
    bn_guard(ptr::null_mut(), || {
        let parsed = match connect_options_parse(opts) {
            Ok(v) => v,
            Err(e) => {
                set_last_error(&e);
                return ptr::null_mut();
            }
        };
        let (host, ip, _alpn, ech, token, timeout_ms, port, _profile) = parsed;
        let p = H3ConnectParams {
            host: &host,
            addr: ip,
            port,
            ech_config_list: ech.as_deref(),
            resumption_token: token.as_deref(),
            timeout: dur(timeout_ms),
        };
        match H3Connection::connect(&p) {
            Ok(c) => Box::into_raw(Box::new(BnH3 {
                inner: Mutex::new(c),
                requests: Mutex::new(Vec::new()),
                ticket: new_ticket(),
            })),
            Err(e) => {
                set_last_error(&e);
                ptr::null_mut()
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn bn_h3_fetch(
    h: *mut BnH3,
    method: *const c_char,
    target: *const c_char,
    headers: *const BnHeader,
    nheaders: u32,
    body: *const u8,
    body_len: u32,
    timeout_ms: u32,
) -> *mut BnH3Request {
    bn_guard(ptr::null_mut(), || {
        let h = match h.as_ref() {
            Some(h) => h,
            None => {
                set_last_error_str("bn_h3_fetch: NULL");
                return ptr::null_mut();
            }
        };
        let _rd = rd(&h.ticket);
        let run = || -> Result<*mut BnH3Request, Error> {
            let method = cstr(method)?;
            let target = cstr(target)?;
            let mut hdrs: Vec<(String, Vec<u8>)> = Vec::new();
            if !headers.is_null() {
                for i in 0..nheaders as usize {
                    let hd = &*headers.add(i);
                    hdrs.push((
                        cstr(hd.name)?.to_string(),
                        blob(hd.value, hd.value_len).map(<[u8]>::to_vec).unwrap_or_default(),
                    ));
                }
            }
            let stream_id = {
                let mut inner = lock(&h.inner);
                inner.fetch(
                    method,
                    target,
                    &hdrs,
                    blob(body, body_len),
                    dur(timeout_ms),
                )?
            };
            let req = Box::into_raw(Box::new(BnH3Request {
                conn: AtomicPtr::new(h as *const BnH3 as *mut BnH3),
                stream_id: stream_id.as_u64(),
                ticket: h.ticket.clone(),
            }));
            lock(&h.requests).push(req);
            Ok(req)
        };
        match run() {
            Ok(p) => p,
            Err(e) => {
                set_last_error(&e);
                ptr::null_mut()
            }
        }
    })
}

/// Доступ к соединению из дескриптора запроса под read-lock тикета:
/// Box<BnH3> гарантированно жив на время замыкания (bn_h3_close
/// освобождает его только под write-lock).
fn with_conn<T>(
    r: &BnH3Request,
    f: impl FnOnce(&BnH3) -> crate::error::Result<T>,
) -> crate::error::Result<T> {
    let _rd = rd(&r.ticket);
    let conn = r.conn.load(Ordering::Acquire);
    if conn.is_null() {
        return Err(Error::new(
            ErrorCode::Closed,
            "соединение HTTP/3 уже закрыто (bn_h3_close)",
        ));
    }
    f(unsafe { &*conn })
}

#[no_mangle]
pub unsafe extern "C" fn bn_h3_req_status(r: *const BnH3Request) -> c_int {
    bn_guard(-(ErrorCode::Panic as c_int), || {
        let r = match r.as_ref() {
            Some(r) => r,
            None => return -(ErrorCode::InvalidArgument as c_int),
        };
        match with_conn(r, |h| {
            let inner = lock(&h.inner);
            inner
                .request(StreamId::from(r.stream_id))
                .map(|st| st.status.map(i32::from).unwrap_or(-1))
                .ok_or_else(|| Error::invalid_arg("неизвестный stream_id"))
        }) {
            Ok(v) => v,
            Err(e) => err_code(&e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn bn_h3_req_header_count(r: *const BnH3Request) -> c_int {
    bn_guard(-(ErrorCode::Panic as c_int), || {
        let r = match r.as_ref() {
            Some(r) => r,
            None => return -(ErrorCode::InvalidArgument as c_int),
        };
        match with_conn(r, |h| {
            let inner = lock(&h.inner);
            inner
                .request(StreamId::from(r.stream_id))
                .map(|st| st.headers.len() as c_int)
                .ok_or_else(|| Error::invalid_arg("неизвестный stream_id"))
        }) {
            Ok(v) => v,
            Err(e) => err_code(&e),
        }
    })
}

/// Копирует i-й заголовок ответа (name и value NUL-terminated).
/// Буферы малы/NULL → -13; нужные размеры (с NUL) — в *needed_name и
/// *needed_value (оба записываются при ошибке).
#[no_mangle]
pub unsafe extern "C" fn bn_h3_req_header(
    r: *const BnH3Request,
    index: c_int,
    name_buf: *mut c_char,
    name_cap: u32,
    value_buf: *mut u8,
    value_cap: u32,
    needed_name: *mut u32,
    needed_value: *mut u32,
) -> c_int {
    bn_guard(-(ErrorCode::Panic as c_int), || {
        let r = match r.as_ref() {
            Some(r) => r,
            None => {
                set_last_error_str("bn_h3_req_header: NULL");
                return -(ErrorCode::InvalidArgument as c_int);
            }
        };
        let res = with_conn(r, |h| {
            let inner = lock(&h.inner);
            let st = inner
                .request(StreamId::from(r.stream_id))
                .ok_or_else(|| Error::invalid_arg("неизвестный stream_id"))?;
            if index < 0 || index as usize >= st.headers.len() {
                return Err(Error::invalid_arg("индекс за пределами"));
            }
            let (name, value) = &st.headers[index as usize];
            // copy_header_pair безопасна только под read-lock тикета,
            // который with_conn держит.
            Ok(unsafe {
                copy_header_pair(
                    name.as_bytes(),
                    name_buf,
                    name_cap,
                    value,
                    value_buf,
                    value_cap,
                    needed_name,
                    needed_value,
                )
            })
        });
        match res {
            Ok(v) => v,
            Err(e) => err_code(&e),
        }
    })
}

/// >=0 прочитано; 0 = тело закончено (fin); <0 ошибка.
#[no_mangle]
pub unsafe extern "C" fn bn_h3_req_read(
    r: *mut BnH3Request,
    buf: *mut u8,
    buf_cap: u32,
    timeout_ms: u32,
) -> c_int {
    bn_guard(-(ErrorCode::Panic as c_int), || {
        let r = match r.as_ref() {
            Some(r) => r,
            None => {
                set_last_error_str("bn_h3_req_read: NULL");
                return -(ErrorCode::InvalidArgument as c_int);
            }
        };
        let res = with_conn(r, |h| {
            let mut inner = lock(&h.inner);
            if buf_cap == 0 {
                // «Драйв»-вызов: пустой буфер допустим (в т.ч. NULL).
                let mut empty: [u8; 0] = [];
                inner.read_body(StreamId::from(r.stream_id), &mut empty, dur(timeout_ms))
            } else {
                if buf.is_null() {
                    return Err(Error::invalid_arg("нулевой буфер"));
                }
                let mut out = std::slice::from_raw_parts_mut(buf, buf_cap as usize);
                inner.read_body(StreamId::from(r.stream_id), &mut out, dur(timeout_ms))
            }
        });
        match res {
            Ok(n) => n as c_int,
            Err(e) => err_code(&e),
        }
    })
}

/// Освободить дескриптор запроса и обнулить указатель. Безопасен и
/// после bn_h3_close (осиротевший запрос), и повторно.
#[no_mangle]
pub unsafe extern "C" fn bn_h3_req_free(r: *mut *mut BnH3Request) {
    bn_guard((), || {
        if r.is_null() {
            return;
        }
        let p = *r;
        if p.is_null() {
            return;
        }
        let rref = &*p;
        // Клон Arc билета — защита от UAF при unlock (см. bn_tls_close).
        let ticket = Arc::clone(&rref.ticket);
        let _rd = rd(&ticket);
        let conn = rref.conn.load(Ordering::Acquire);
        if !conn.is_null() {
            let href = unsafe { &*conn };
            lock(&href.requests).retain(|x| *x != p);
        }
        drop(Box::from_raw(p));
        *r = ptr::null_mut();
    })
}

/// Токен resumption (0-RTT): >0 длина; 0 нет; мал буфер → -13 + *needed.
#[no_mangle]
pub unsafe extern "C" fn bn_h3_take_resumption_token(
    h: *mut BnH3,
    out: *mut u8,
    out_cap: u32,
    needed: *mut u32,
) -> c_int {
    bn_guard(-(ErrorCode::Panic as c_int), || {
        let h = match h.as_ref() {
            Some(h) => h,
            None => {
                set_last_error_str("bn_h3_take_resumption_token: NULL");
                return -(ErrorCode::InvalidArgument as c_int);
            }
        };
        let _rd = rd(&h.ticket);
        match lock(&h.inner).take_resumption_token() {
            Some(t) => match copy_out(out, out_cap, &t, false) {
                Ok(n) => n as c_int,
                Err(need) => too_small(needed, need),
            },
            None => 0,
        }
    })
}

/// Закрыть соединение HTTP/3, осиротить его запросы (их дескрипторы
/// далее возвращают -9), освободить Box и обнулить указатель.
#[no_mangle]
pub unsafe extern "C" fn bn_h3_close(h: *mut *mut BnH3) {
    bn_guard((), || {
        if h.is_null() {
            return;
        }
        let p = *h;
        if p.is_null() {
            return;
        }
        let href = &*p;
        // Клон Arc билета — защита от UAF при unlock (см. bn_tls_close).
        let ticket = Arc::clone(&href.ticket);
        let _wr = wr(&ticket); // ждём все операции по соединению
        {
            // Осиротить запросы: conn = NULL → bn_h3_req_* вернут Closed.
            let mut reqs = lock(&href.requests);
            for r in reqs.iter() {
                (**r).conn.store(ptr::null_mut(), Ordering::Release);
            }
            reqs.clear();
        }
        lock(&href.inner).close();
        drop(Box::from_raw(p));
        *h = ptr::null_mut();
    })
}

fn http_authority(host: &str, port: u16) -> String {
    let default = matches!(port, 80 | 443);
    if host.contains(':') && !host.starts_with('[') {
        if default {
            format!("[{host}]")
        } else {
            format!("[{host}]:{port}")
        }
    } else if default {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

// --- буферы для возвращаемых строк ----------------------------------------------
//
// Copy-типы с const-инициализацией: TLS-деструкторы не регистрируются,
// выгрузка .so (dlclose) безопасна на всех версиях bionic.

thread_local! {
    static MSG: RefCell<[u8; 256]> = const { RefCell::new([0; 256]) };
    static VERSION_BUF: RefCell<[u8; 128]> = const { RefCell::new([0; 128]) };
}

/// Записать сообщение последней ошибки (для bn_last_error_message).
/// Чтение НЕ разрушающее: слот очищается только следующей операцией
/// bn_* (см. bn_guard), поэтому code и message можно читать в любом
/// порядке и сколько угодно раз.
pub fn bn_last_error_message_impl() -> *const c_char {
    let msg = crate::error::last_error_message();
    MSG.with(|m| {
        let mut b = m.borrow_mut();
        let bytes = msg.as_bytes();
        // last_error_message уже обрезает по 255 с границей UTF-8; на
        // всякий случай повторяем защиту здесь.
        let mut take = bytes.len().min(b.len() - 1);
        while take > 0 && !msg.is_char_boundary(take) {
            take -= 1;
        }
        b[..take].copy_from_slice(&bytes[..take]);
        b[take] = 0;
        b.as_ptr() as *const c_char
    })
}
