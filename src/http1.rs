//! Минимальный HTTP/1.1-клиент поверх TLS-стрима.
//!
//! Нужен для трёх вещей: «HTTPS over TLS» (GET/POST с чтением ответа),
//! keep-alive (несколько запросов по одному соединению, как Firefox) и
//! WSS-handshake (rfc6455 начинается с HTTP/1.1 Upgrade). Поддерживается
//! ровно необходимое: запрос, статус, заголовки, тело по Content-Length
//! или chunked. Тело читается ТОЧНО по объявленному размеру — соединение
//! остаётся переиспользуемым; серверный «Connection: close» или ответ
//! без длины (чтение до EOF) делают соединение одноразовым (следующий
//! запрос получит -9 Closed).

use std::time::{Duration, Instant};

use crate::error::{Error, ErrorCode, Result};
use crate::tls::TlsStream;

pub const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Заголовок (name, value).
pub type HeaderPair = (String, String);

pub struct Request<'a> {
    pub method: &'a str,
    /// Путь с query, например "/api?v=1".
    pub target: &'a str,
    /// Хост для заголовка Host (обычно host[:port]).
    pub authority: &'a str,
    pub headers: &'a [HeaderPair],
    pub body: Option<&'a [u8]>,
    /// Значение заголовка Connection: Close, KeepAlive или Upgrade (WSS).
    pub connection: ConnectionHeader,
}

/// Заголовок Connection запроса.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionHeader {
    /// Одноразовый запрос: сервер закроет соединение после ответа.
    Close,
    /// Переиспользуемое соединение (как Firefox): тело читается ровно
    /// по Content-Length/chunked, соединение готово к следующему запросу.
    KeepAlive,
    /// WSS-handshake (RFC 6455 §4.1).
    Upgrade,
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<HeaderPair>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Отправить запрос и ДОЧИТАТЬ заголовки ответа (тело не трогаем —
/// его читает `read_body`; для 101 Upgrade тело отсутствует).
pub fn send_request_and_read_head(
    stream: &mut TlsStream,
    req: &Request<'_>,
    timeout: Duration,
) -> Result<Response> {
    let deadline = Instant::now() + timeout;

    // Проверка до сборки запроса: без неё method/target/authority и
    // заголовки от C-вызывающего конкатенировались в запрос как есть,
    // и `\r\n` в них инъектировал произвольные заголовки, открывая
    // HTTP Request Smuggling на keep-alive-соединении.
    validate_request(req)?;

    // --- Запрос ------------------------------------------------------------
    let mut head = String::with_capacity(256);
    head.push_str(req.method);
    head.push(' ');
    head.push_str(req.target);
    head.push_str(" HTTP/1.1\r\nHost: ");
    head.push_str(req.authority);
    head.push_str("\r\n");
    // Connection управляем сами: close/keep-alive/Upgrade (WSS).
    match req.connection {
        ConnectionHeader::Close => head.push_str("Connection: close\r\n"),
        ConnectionHeader::KeepAlive => head.push_str("Connection: keep-alive\r\n"),
        ConnectionHeader::Upgrade => head.push_str("Connection: Upgrade\r\n"),
    }
    let mut has_ua = false;
    for (n, v) in req.headers {
        if n.eq_ignore_ascii_case("connection") {
            continue; // Connection управляем сами
        }
        if n.eq_ignore_ascii_case("host") {
            continue;
        }
        if n.eq_ignore_ascii_case("user-agent") {
            has_ua = true;
        }
        head.push_str(n);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }
    let _ = has_ua; // User-Agent при желании передаёт вызывающая сторона.
    match req.body {
        Some(b) => {
            head.push_str(&format!("Content-Length: {}\r\n\r\n", b.len()));
            stream.write_all(head.as_bytes(), remaining(deadline)?)?;
            stream.write_all(b, remaining(deadline)?)?;
        }
        None => {
            head.push_str("\r\n");
            stream.write_all(head.as_bytes(), remaining(deadline)?)?;
        }
    }

    // --- Статус-строка + заголовки ------------------------------------------
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let head_end = loop {
        if let Some(pos) = find_double_crlf(&buf) {
            break pos;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(Error::new(ErrorCode::ProtocolError, "заголовки ответа слишком большие"));
        }
        read_more(stream, &mut buf, deadline)?;
    };

    let head_str = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| Error::new(ErrorCode::ProtocolError, "пустой ответ"))?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(Error::new(
            ErrorCode::ProtocolError,
            format!("неожиданная версия: {version:?}"),
        ));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::new(ErrorCode::ProtocolError, "некорректный статус"))?;
    let reason = parts.next().unwrap_or("").to_string();

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((n, v)) = line.split_once(':') {
            headers.push((n.trim().to_string(), v.trim().to_string()));
        }
    }

    // Хвост после заголовков — начало тела (не теряем!).
    let rest = buf[head_end + 4..].to_vec();

    let mut resp = Response {
        status,
        reason,
        headers,
        body: Vec::new(),
    };
    if !rest.is_empty() {
        resp.body = rest;
    }
    Ok(resp)
}

/// Проверить запрос до отправки (RFC 9110): метод и имена заголовков —
/// токены, в target/authority нет ни управляющих символов, ни пробелов,
/// в значениях заголовков — CR/LF/NUL. Content-Length и
/// Transfer-Encoding от вызывающего отклоняются: фреймингом управляет
/// библиотека (при body она дописывает свой Content-Length — чужой дал
/// бы задвоение заголовка).
fn validate_request(req: &Request<'_>) -> Result<()> {
    if req.method.is_empty() || !req.method.bytes().all(is_tchar) {
        return Err(Error::invalid_arg(format!(
            "метод {:?} не токен RFC 9110",
            req.method
        )));
    }
    // ≤ 0x20 отсекает и управляющие символы, и пробел, ломающий
    // request-line; 0x7F — DEL.
    for (what, s) in [("target", req.target), ("authority", req.authority)] {
        if s.is_empty() || s.bytes().any(|b| b <= 0x20 || b == 0x7F) {
            return Err(Error::invalid_arg(format!(
                "{what} пуст или содержит управляющие символы/пробел"
            )));
        }
    }
    for (n, v) in req.headers {
        if n.is_empty() || !n.bytes().all(is_tchar) {
            return Err(Error::invalid_arg(format!(
                "имя заголовка {n:?} не токен RFC 9110"
            )));
        }
        if v.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
            return Err(Error::invalid_arg(format!(
                "значение заголовка {n:?} содержит CR/LF/NUL"
            )));
        }
        if n.eq_ignore_ascii_case("content-length")
            || n.eq_ignore_ascii_case("transfer-encoding")
        {
            return Err(Error::invalid_arg(
                "Content-Length/Transfer-Encoding задаёт библиотека, не вызывающий",
            ));
        }
    }
    Ok(())
}

/// Токен RFC 9110 (tchar): буквы, цифры и спецсимволы "!#$%&'*+-.^_`|~".
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Дочитать тело ответа (по Content-Length, chunked или до EOF).
/// Размер ограничен `bn_set_limits` (по умолчанию 64 МиБ): сервер,
/// объявляющий сколь угодно большое тело, не может занять всю память
/// процесса — превышение даёт ошибку MessageTooLarge.
pub fn read_body(stream: &mut TlsStream, resp: &mut Response, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let max = crate::limits::http1_body();

    if resp.status == 101 {
        return Ok(()); // Upgrade — тела нет, дальше говорит WebSocket.
    }

    let chunked = resp
        .header("Transfer-Encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);

    if chunked {
        let mut raw = std::mem::take(&mut resp.body);
        let mut out = Vec::new();
        loop {
            // Ищем конец текущего chunk-заголовка.
            let (size, after_size) = loop {
                if let Some(pos) = find_crlf(&raw) {
                    let line = String::from_utf8_lossy(&raw[..pos]).into_owned();
                    let size_str = line.split(';').next().unwrap_or("").trim();
                    let size = usize::from_str_radix(size_str, 16).map_err(|_| {
                        Error::new(ErrorCode::ProtocolError, "chunked: плохой размер")
                    })?;
                    break (size, pos + 2);
                }
                read_more(stream, &mut raw, deadline)?;
            };
            if size == 0 {
                // Последний chunk. За ним идут трейлеры (RFC 9112 §7.1:
                // строки до пустой, минимум финальный CRLF) — обязаны
                // быть потреблены, иначе переиспользуемое (keep-alive)
                // соединение рассинхронизируется на следующем ответе.
                loop {
                    let pos = match find_crlf(&raw) {
                        Some(p) => p,
                        None => {
                            read_more(stream, &mut raw, deadline)?;
                            continue;
                        }
                    };
                    let line_empty = pos == 0;
                    raw.drain(..pos + 2);
                    if line_empty {
                        break;
                    }
                }
                break;
            }
            // Лимит: сам chunk и накопленное тело. Сравнение через
            // saturating_sub: `out.len() + size` при size из
            // chunk-заголовка вида ffffffffffffffff переполнилось бы —
            // в release молча (обход лимита), в debug паникой.
            if size > max.saturating_sub(out.len()) {
                return Err(Error::too_large(format!(
                    "chunked-тело превышает лимит {max} байт (bn_set_limits)"
                )));
            }
            // Дочитываем data + CRLF. Конец чанка — только через
            // checked-математику: размер приходит от сервера.
            let end = after_size
                .checked_add(size)
                .and_then(|v| v.checked_add(2))
                .ok_or_else(|| {
                    Error::new(ErrorCode::ProtocolError, "chunked: переполнение размера")
                })?;
            while raw.len() < end {
                read_more(stream, &mut raw, deadline)?;
            }
            out.extend_from_slice(&raw[after_size..end - 2]);
            raw.drain(..end);
        }
        resp.body = out;
        return Ok(());
    }

    if let Some(cl) = resp.header("Content-Length") {
        let want: usize = cl
            .trim()
            .parse()
            .map_err(|_| Error::new(ErrorCode::ProtocolError, "плохой Content-Length"))?;
        if want > max {
            return Err(Error::too_large(format!(
                "Content-Length {want} превышает лимит {max} байт (bn_set_limits)"
            )));
        }
        while resp.body.len() < want {
            let need = want - resp.body.len();
            read_into(stream, &mut resp.body, need, deadline)?;
        }
        resp.body.truncate(want);
        return Ok(());
    }

    // До EOF.
    loop {
        if resp.body.len() >= max {
            return Err(Error::too_large(format!(
                "тело ответа (без Content-Length) превышает лимит {max} байт (bn_set_limits)"
            )));
        }
        let room = (max - resp.body.len()).min(16 * 1024);
        match read_into(stream, &mut resp.body, room, deadline) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(e) if e.code == ErrorCode::Closed => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// --- низкоуровневое ---------------------------------------------------------

fn remaining(deadline: Instant) -> Result<Duration> {
    let now = Instant::now();
    if now >= deadline {
        return Err(Error::timeout("http1: таймаут"));
    }
    Ok(deadline - now)
}

fn read_more(stream: &mut TlsStream, buf: &mut Vec<u8>, deadline: Instant) -> Result<()> {
    let mut chunk = [0u8; 8192];
    let n = stream.read(&mut chunk, remaining(deadline)?)?;
    if n == 0 {
        // EOF до завершения ответа: сервер закрыл соединение (в т.ч.
        // «второй запрос после Connection: close»). Это Closed, а не
        // нарушение протокола.
        return Err(Error::new(
            ErrorCode::Closed,
            "соединение закрыто в середине ответа",
        ));
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(())
}

fn read_into(
    stream: &mut TlsStream,
    buf: &mut Vec<u8>,
    max: usize,
    deadline: Instant,
) -> Result<usize> {
    // Читаем кусок ≤16 КиБ и дописываем в конец. Прежний
    // `buf.resize(start + max, 0)` выделял И заполнял нулями весь max
    // заранее: при снятом лимите (0) Content-Length от сервера
    // превращался в мгновенную аллокацию непроверенного размера (OOM).
    const CHUNK: usize = 16 * 1024;
    let mut chunk = [0u8; CHUNK];
    let want = max.min(CHUNK);
    let n = stream.read(&mut chunk[..want], remaining(deadline)?)?;
    buf.extend_from_slice(&chunk[..n]);
    Ok(n)
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(
        method: &'a str,
        target: &'a str,
        authority: &'a str,
        headers: &'a [HeaderPair],
    ) -> Request<'a> {
        Request {
            method,
            target,
            authority,
            headers,
            body: None,
            connection: ConnectionHeader::KeepAlive,
        }
    }

    #[test]
    fn validate_accepts_normal_request() {
        let hs = vec![("Accept".to_string(), "*/*".to_string())];
        assert!(validate_request(&req("GET", "/a?b=c", "example.com", &hs)).is_ok());
        assert!(validate_request(&req("POST", "/upload", "example.com:8443", &[])).is_ok());
    }

    #[test]
    fn validate_rejects_injection() {
        // CRLF в значении заголовка.
        let hs = vec![("X-Evil".to_string(), "1\r\nHost: evil".to_string())];
        assert!(validate_request(&req("GET", "/", "example.com", &hs)).is_err());
        // NUL в значении заголовка.
        let nul = vec![("X-Null".to_string(), "a\0b".to_string())];
        assert!(validate_request(&req("GET", "/", "example.com", &nul)).is_err());
        // Пробел в методе ломает request-line.
        assert!(validate_request(&req("GET /x", "/", "example.com", &[])).is_err());
        // CRLF в target и в authority.
        assert!(validate_request(&req("GET", "/a\r\nX: y", "example.com", &[])).is_err());
        assert!(validate_request(&req("GET", "/", "exa\r\nmple", &[])).is_err());
        // Фрейминг-заголовки задаёт библиотека, не вызывающий.
        let cl = vec![("Content-Length".to_string(), "5".to_string())];
        assert!(validate_request(&req("POST", "/", "example.com", &cl)).is_err());
        let te = vec![("Transfer-Encoding".to_string(), "chunked".to_string())];
        assert!(validate_request(&req("POST", "/", "example.com", &te)).is_err());
    }
}
