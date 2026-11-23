//! Тест TLS-resumption: два соединения подряд к одному и тому же адресу.
//! Второе должно возобновить TLS-сессию из клиентского кеша NSS
//! (in-memory, ключ — адрес сервера + порт).
//!
//! Требует сети — запускайте явно:
//! ```text
//! cargo test --test resume -- --ignored --nocapture
//! ```

use std::net::ToSocketAddrs;
use std::time::Duration;

use bangboo_net::nssx;
use bangboo_net::profile::Profile;
use bangboo_net::tls::{ConnectParams, TlsStream};

const HOST: &str = "example.com";

/// Одно соединение: handshake + минимальный HTTP/1.1-обмен (чтобы
/// NewSessionTicket сервера успел прийти и попасть в кеш NSS).
fn one_round(addr: std::net::SocketAddr) {
    let mut tls = TlsStream::connect(&ConnectParams {
        host: HOST,
        addr: Some(addr),
        port: 443,
        alpn: None,
        ech_config_list: None,
        profile: Profile::FirefoxDesktop,
        timeout: Duration::from_secs(15),
    })
    .expect("TlsStream::connect");

    let req = format!("GET / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes(), Duration::from_secs(10))
        .expect("write_all");
    let mut buf = vec![0u8; 8192];
    let _ = tls.read(&mut buf, Duration::from_secs(10));
    tls.close();
}

#[test]
#[ignore = "network"]
fn tls_resumption_via_nss_client_cache() {
    // Инициализация (аналог bn_init(NULL,0)): корни из хранилища ОС.
    bangboo_net::init::init(None).expect("init");

    // Фиксируем адрес: кеш NSS ключуется адресом+портом, а DNS
    // round-robin на второй резолв может вернуть другой IP.
    let addr = (HOST, 443)
        .to_socket_addrs()
        .expect("resolve")
        .next()
        .expect("адрес разрешён");

    let before = unsafe { (*nssx::SSL_GetStatistics()).hsh_sid_cache_hits };
    one_round(addr);
    let mid = unsafe { (*nssx::SSL_GetStatistics()).hsh_sid_cache_hits };
    assert_eq!(mid, before, "первое соединение не должно резюмиться");

    // Небольшая пауза: NewSessionTicket может прийти чуть позже ответа.
    std::thread::sleep(Duration::from_millis(300));
    one_round(addr);

    let after = unsafe { (*nssx::SSL_GetStatistics()).hsh_sid_cache_hits };
    assert!(
        after > mid,
        "второе соединение не возобновило сессию: hsh_sid_cache_hits {mid} -> {after}"
    );
}
