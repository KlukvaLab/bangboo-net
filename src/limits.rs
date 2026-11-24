//! Лимиты размеров сообщений — защита от неограниченного роста
//! памяти при чтении ответов (DoS со стороны сервера).
//!
//! Лимиты глобальные на процесс, меняются через `bn_set_limits` до
//! или во время работы (действуют на все последующие операции).
//! `0` — лимит снят (не рекомендуется). По умолчанию 64 МиБ на
//! каждую категорию.
//!
//! Применяются к:
//!  * телу HTTP/1.1-ответа (Content-Length, chunked, чтение до EOF);
//!  * сообщению WebSocket (кадр и сумма фрагментов, оба направления);
//!  * телу HTTP/3-ответа (на один запрос).

use std::sync::atomic::{AtomicUsize, Ordering};

const DEFAULT: usize = 64 * 1024 * 1024;

static MAX_HTTP1_BODY: AtomicUsize = AtomicUsize::new(DEFAULT);
static MAX_WS_MESSAGE: AtomicUsize = AtomicUsize::new(DEFAULT);
static MAX_H3_RESPONSE: AtomicUsize = AtomicUsize::new(DEFAULT);

/// Установить лимиты: тело HTTP/1.1, сообщение WS, ответ HTTP/3
/// (байты; 0 = без лимита).
pub fn set(http1_body: usize, ws_message: usize, h3_response: usize) {
    MAX_HTTP1_BODY.store(http1_body, Ordering::Relaxed);
    MAX_WS_MESSAGE.store(ws_message, Ordering::Relaxed);
    MAX_H3_RESPONSE.store(h3_response, Ordering::Relaxed);
}

fn load(v: &AtomicUsize) -> usize {
    let n = v.load(Ordering::Relaxed);
    if n == 0 {
        usize::MAX
    } else {
        n
    }
}

/// Лимит тела HTTP/1.1-ответа (usize::MAX = без лимита).
pub fn http1_body() -> usize {
    load(&MAX_HTTP1_BODY)
}

/// Лимит сообщения WebSocket (usize::MAX = без лимита).
pub fn ws_message() -> usize {
    load(&MAX_WS_MESSAGE)
}

/// Лимит тела HTTP/3-ответа (usize::MAX = без лимита).
pub fn h3_response() -> usize {
    load(&MAX_H3_RESPONSE)
}
