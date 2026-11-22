# neqo-backend

Прокладка для использования сетевого стека **Firefox** (NSS + neqo):
Rust-библиотека с C ABI — TLS, HTTP/1.1, HTTP/3 и WebSocket-клиент для
приложений на C и Kotlin (Android + Desktop).

## Что это

Библиотека построена на тех же компонентах, что и браузер Firefox —
NSS и neqo, — и даёт три транспортных пути:

| Путь | Стек | Конфигурация TLS |
|---|---|---|
| **HTTPS over TLS** | NSS (тот же, что в Firefox) | задаётся `profile.rs` по исходникам Gecko |
| **HTTPS over QUIC (HTTP/3)** | neqo 0.34.0 — QUIC-стек Firefox | применяется самой neqo |
| **WSS (WebSocket over TLS)** | NSS + RFC 6455-фрейминг | TLS — как выше; фрейминг как WebSocketChannel |

Все соединения **принудительно проверяются**: цепочка сертификатов
сервера (построение пути, подписи, сроки, SAN, EKU) обязана пройти
проверку — небезопасный режим отсутствует в API.

## Состав стека

1. **Тот же код**: NSS и neqo — это библиотеки, которыми пользуется сам
   Firefox; QUIC-соединения формируются кодом браузера.
2. **Та же конфигурация**: TLS-сокеты настраиваются по данным, снятым с
   `nsNSSIOLayer.cpp` / `nsNSSComponent.cpp` / `StaticPrefList.yaml`
   Gecko — наборы шифров, группы (включая X25519MLKEM768), GREASE,
   пермутация расширений, сигнатурные схемы, сжатие сертификатов.
   Подробности: [docs/PROFILE.md](docs/PROFILE.md).
3. **Пиннинг версий**: `neqo 0.34.0`, `nss-rs 0.16.3`, `NSS 3.134` —
   см. [docs/BUILDING.md](docs/BUILDING.md).

## Структура

```
ffi/neqo_backend.h   — заголовок C ABI (для JNA и C)
src/
  ffi.rs             — extern "C" слой (изолирует ABI от ядра)
  profile.rs         — TLS-профиль Firefox (все константы с источниками)
  tls.rs             — TLS-сокеты NSPR/NSS
  http1.rs           — минимальный HTTP/1.1 (нужен для WSS)
  ws.rs, sha1.rs     — RFC 6455 клиент
  quic.rs            — HTTP/3 клиент (neqo) с синхронным драйвером
  init.rs, verify.rs — NSS init, корни, верификация цепочек
  error.rs           — коды ошибок C ABI
  limits.rs          — лимиты размеров сообщений (анти-DoS)
scripts/             — сборка под все целевые платформы
docs/                — документация (RU)
```

## Быстрый старт (C)

```c
#include "neqo_backend.h"

nb_init(NULL, 0);                       // корни из ОС; на Android — PEM

NbConnectOptions opts = {0};
opts.host = "example.org";
opts.port = 443;
opts.timeout_ms = 15000;
opts.profile = 0;                       // 0 = firefox-desktop

/* 1) сырой TLS (байтовый поток) */
NbTls *tls = nb_tls_connect(&opts);
nb_tls_write(tls, req, req_len, 5000);
int n = nb_tls_read(tls, buf, sizeof(buf), 5000);
nb_tls_close(&tls);                     /* tls = NULL */

/* 2) HTTP/3 */
NbH3 *h3 = nb_h3_connect(&opts);
NbH3Request *r = nb_h3_fetch(h3, "GET", "/", NULL, 0, NULL, 0, 15000);
int status = nb_h3_req_status(r);       /* ждём != -1 через poll статуса */
int body = nb_h3_req_read(r, buf, sizeof(buf), 5000);
nb_h3_req_free(&r); nb_h3_close(&h3);   /* запрос можно освободить и после close */

/* 3) WSS */
NbWs *ws = nb_ws_connect(&opts, "/ws", NULL, 0);
nb_ws_send(ws, 1 /*text*/, "hello", 5, 5000);
int len = nb_ws_recv(ws, &opcode, buf, sizeof(buf), 5000, NULL);
nb_ws_close(&ws, 1000, "bye", 5000);    /* ws = NULL */
```

Список функций, коды ошибок, ECH, 0-RTT-токены и использование из
Kotlin/JNA: [docs/USAGE.md](docs/USAGE.md).

## Сборка

Требуется pinned-набор (скрипты делают всё сами):

```bash
scripts/fetch_nss.sh          # NSS 3.134 + NSPR 4.41, проверка sha256
scripts/build_linux.sh x86_64 # и/или: i686, aarch64
scripts/build_android.sh arm64 # и/или: arm32
```

Полное описание (зависимости, NDK, Windows, кросс-компиляция):
[docs/BUILDING.md](docs/BUILDING.md).

## Документация

* [docs/BUILDING.md](docs/BUILDING.md) — сборка, таргеты, пиннинг
* [docs/PROFILE.md](docs/PROFILE.md) — TLS-профиль Firefox: параметры и источники
* [docs/PITFALLS.md](docs/PITFALLS.md) — ловушки NSS/neqo (обязательно к прочтению)
* [docs/USAGE.md](docs/USAGE.md) — C ABI, Kotlin/JNA, сценарии
* [docs/SECURITY.md](docs/SECURITY.md) — устойчивость ABI: паники, потоки,
  владение, лимиты, dlclose

## Статус v1

* TLS 1.2/1.3 (профили desktop/android), HTTP/1.1 (keep-alive:
  несколько запросов по одному соединению), HTTP/3, WSS — готово.
* Поведение подключения — как у Firefox: false start, TLS-resumption
  (клиентский кеш NSS, в рамках процесса), Happy Eyeballs для TCP
  (RFC 8305, стаггер 300 мс), повтор при version-intolerance с
  downgrade-check.
* Устойчивый C ABI: паники перехвачены (catch_unwind, -14), дескрипторы
  потокобезопасны, close/free обнуляют указатель, лимиты размеров
  (`nb_set_limits`, -15), `nb_shutdown` чистит NSS для dlclose —
  см. [docs/SECURITY.md](docs/SECURITY.md).
* ECH (реальный + GREASE) — передаётся аргументами методов; Kotlin-слой
  приложения сам получает ECHConfigList из DNS и подставляет.
* Не входит в v1: HTTP/2, OCSP-checking (stapling запрашивается как в
  Firefox, но статус не проверяется).

## Проверено (Linux x86_64, машина сборки)

Е2Е-тест `tests/smoke.c` (компилируется с `ffi/neqo_backend.h`, линкуется
с собранной `libneqo_backend.so`):

| Проверка | Результат |
|---|---|
| `cargo test` | 2 passed (SHA-1 векторы, RFC 6455 accept) |
| TLS + HTTP/1.1 GET example.com | **200**, тело прочитано (в т.ч. chunked) |
| HTTP/3 GET example.com (QUIC handshake + верификация цепочки) | **200**, 321 байт |
| HTTP/3 с resumption-токеном (`tests/h3_resume.c`) | два соединения подряд, **200/200** |
| TLS-resumption (`tests/resume.rs`: два соединения, один адрес) | второе возобновлено (кеш NSS) |
| WSS (text/binary/ping/close, echo) | **эхо text+binary**, close-кадр 1000 |
| ECH (конфиг из DoH, crypto.cloudflare.com) | handshake с ECH — успешен |
| Устойчивость ABI (`tests/misuse.c`: NULL-аргументы, двойной close, too-small буферы, use-after-close, лимиты, shutdown/re-init) | **OK** (-2/-13/-9/-15/-3 как задумано) |
| Рантайм без LD_LIBRARY_PATH | rpath=$ORIGIN на всех .so, NSS 3.134 из бандла |
