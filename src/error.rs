//! Коды ошибок библиотеки (стабильные значения для C ABI)
//! и внутренний тип ошибки с сообщением.
//!
//! Слот последней ошибки — thread-local с фиксированным буфером.
//! Тип слота `Copy`, поэтому TLS-деструктор НЕ регистрируется:
//! выгрузка .so (dlclose) на Android безопасна даже на старых
//! версиях bionic, которые вызывают деструкторы выгруженных
//! библиотек (исправлено в bionic только с API 28).

use std::{cell::RefCell, fmt};

/// Коды ошибок, возвращаемые через C ABI. Значения фиксированы —
/// менять нумерацию между версиями нельзя.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ErrorCode {
    Ok = 0,
    /// Внутренняя ошибка (см. bn_last_error_message)
    Generic = 1,
    InvalidArgument = 2,
    NotInitialized = 3,
    /// Разрешение имени не удалось / некорректный адрес
    DnsFailure = 4,
    /// TCP-соединение не установлено
    ConnectFailed = 5,
    /// TLS/QUIC handshake не завершён (в т.ч. fatal alert)
    HandshakeFailed = 6,
    /// Цепочка сертификатов не прошла проверку
    CertificateInvalid = 7,
    /// Истёк таймаут операции
    Timeout = 8,
    /// Соединение закрыто (EOF)
    Closed = 9,
    /// Нарушение протокола (HTTP/WS/H3 framing)
    ProtocolError = 10,
    /// Функция не поддерживается в этой сборке
    Unsupported = 11,
    /// Сервер отклонил ECH и вернул новую ECHConfigList — приложение
    /// должно заново получить конфиг из DNS HTTPS-записи и повторить
    /// подключение.
    EchRetryWithEch = 12,
    /// Буфер вызывающего слишком мал. Нужный размер записан в
    /// out-параметр `needed` функции (если передан); это значение
    /// всегда записывается ДО возврата -13.
    BufferTooSmall = 13,
    /// Внутренняя паника Rust перехвачена на границе FFI
    /// (catch_unwind): стек C++/ART не повреждён, дескриптор
    /// остаётся валидным, но его состояние могло быть нарушено.
    Panic = 14,
    /// Сообщение/тело превысило лимит размера (bn_set_limits).
    MessageTooLarge = 15,
}

impl ErrorCode {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Ok,
            2 => Self::InvalidArgument,
            3 => Self::NotInitialized,
            4 => Self::DnsFailure,
            5 => Self::ConnectFailed,
            6 => Self::HandshakeFailed,
            7 => Self::CertificateInvalid,
            8 => Self::Timeout,
            9 => Self::Closed,
            10 => Self::ProtocolError,
            11 => Self::Unsupported,
            12 => Self::EchRetryWithEch,
            13 => Self::BufferTooSmall,
            14 => Self::Panic,
            15 => Self::MessageTooLarge,
            _ => Self::Generic,
        }
    }
}

/// Полная ошибка: код + человекочитаемое сообщение.
#[derive(Debug, Clone)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
    /// Исходный код ошибки NSPR/SSL (0 — не NSPR-ошибка).
    /// Используется внутренней retry-логикой (TLS version-intolerance),
    /// наружу через C ABI не экспортируется.
    pub pr_code: i32,
}

impl Error {
    pub fn new(code: ErrorCode, msg: impl Into<String>) -> Self {
        Self {
            code,
            message: msg.into(),
            pr_code: 0,
        }
    }

    /// Присоединить исходный код NSPR/SSL.
    pub fn with_pr_code(mut self, pr: i32) -> Self {
        self.pr_code = pr;
        self
    }

    pub fn generic(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Generic, msg)
    }

    pub fn invalid_arg(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, msg)
    }

    pub fn timeout(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Timeout, msg)
    }

    /// Превышен лимит размера сообщения (bn_set_limits).
    pub fn too_large(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::MessageTooLarge, msg)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        let code = match e.kind() {
            std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut => ErrorCode::Timeout,
            std::io::ErrorKind::UnexpectedEof => ErrorCode::Closed,
            _ => ErrorCode::Generic,
        };
        Self::new(code, format!("io: {e}"))
    }
}

// --- Последняя ошибка для FFI ----------------------------------------------
//
// Слот хранит сообщение в фиксированном буфере (обрезка по границе
// UTF-8, максимум 255 байт + NUL). Copy-тип — деструктор не
// регистрируется, см. комментарий модуля.

const MSG_CAP: usize = 256;
const MSG_MAX: usize = MSG_CAP - 1;

#[derive(Clone, Copy)]
struct ErrSlot {
    code: i32,
    len: usize,
    buf: [u8; MSG_CAP],
}

impl ErrSlot {
    const EMPTY: Self = Self {
        code: 0,
        len: 0,
        buf: [0; MSG_CAP],
    };

    fn set(&mut self, code: i32, msg: &str) {
        let bytes = msg.as_bytes();
        let mut take = bytes.len().min(MSG_MAX);
        // Не рвём посреди UTF-8-последовательности.
        while take > 0 && !msg.is_char_boundary(take) {
            take -= 1;
        }
        // NUL внутри сообщения обрезал бы его для C — тоже отрезаем.
        if let Some(nul) = bytes[..take].iter().position(|&b| b == 0) {
            take = nul;
        }
        self.code = code;
        self.len = take;
        self.buf[..take].copy_from_slice(&bytes[..take]);
        self.buf[take] = 0;
    }

    fn message(&self) -> &str {
        // Обрезка в `set` всегда по границе символа — UTF-8 валиден.
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

thread_local! {
    static LAST_ERROR: RefCell<ErrSlot> = const { RefCell::new(ErrSlot::EMPTY) };
}

/// Записать код и сообщение последней ошибки (для bn_last_error_code /
/// bn_last_error_message).
pub fn set_last_error(err: &Error) {
    LAST_ERROR.with(|slot| slot.borrow_mut().set(err.code as i32, &format!("{err}")));
}

/// Записать произвольное сообщение с кодом InvalidArgument
/// (для ошибок, обнаруженных в FFI-обёртке).
pub fn set_last_error_str(msg: impl Into<String>) {
    LAST_ERROR.with(|slot| {
        slot.borrow_mut()
            .set(ErrorCode::InvalidArgument as i32, &msg.into())
    });
}

/// Записать ошибку перехваченной паники (код Panic).
pub fn set_panic_error(msg: &str) {
    LAST_ERROR.with(|slot| slot.borrow_mut().set(ErrorCode::Panic as i32, msg));
}

/// Очистить слот последней ошибки. Вызывается на входе КАЖДОЙ операции
/// bn_* (в bn_guard): слот всегда отражает только последний вызов в
/// потоке — «свежесть» ошибки для многопоточных/JNA-сценариев.
pub fn clear_last_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = ErrSlot::EMPTY);
}

/// Последнее сообщение об ошибке в этом потоке (не разрушающее чтение;
/// очищается при следующем вызове bn_*).
pub fn last_error_message() -> String {
    LAST_ERROR.with(|slot| slot.borrow().message().to_string())
}

/// Код последней ошибки в этом потоке (без очистки; 0 = ошибки не было).
/// Слот очищается при следующем вызове bn_* (свежесть ошибки).
pub fn last_error_code() -> i32 {
    LAST_ERROR.with(|slot| slot.borrow().code)
}
