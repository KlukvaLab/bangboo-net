# Использование bangboo-net

## Модель API

Библиотека — набор C-функций с непрозрачными дескрипторами. Всё
блокирующее, с таймаутами в миллисекундах: никаких колбэков из
библиотеки в приложение (кроме возвратов), никаких потоков внутри
(кроме тех, что создаёт сам NSS внутренне). Это делает интеграцию
с Kotlin/JNA тривиальной.

```
bn_init ──► bn_tls_connect ──► bn_tls_read/write ──► bn_tls_close
              │
              ├─► bn_http1_fetch (запрос+ответ целиком)
              ├─► bn_ws_connect ──► bn_ws_send/recv ──► bn_ws_close
              └─► bn_h3_connect ──► bn_h3_fetch ──► bn_h3_req_read ──► bn_h3_close
```

## Коды возврата

`>= 0` — успех (байты/длина/статус), `< 0` — ошибка:

| Код | Имя | Значение |
|---|---|---|
| -1 | Generic | внутренняя ошибка, детали в `bn_last_error_message()` |
| -2 | InvalidArgument | NULL-указатель, кривая строка |
| -3 | NotInitialized | `bn_init` не вызван/не удался (или был `bn_shutdown`) |
| -4 | DnsFailure | имя не разрешилось |
| -5 | ConnectFailed | TCP не соединился |
| -6 | HandshakeFailed | TLS/QUIC handshake, alert |
| -7 | CertificateInvalid | цепочка не прошла проверку |
| -8 | Timeout | истёк таймаут операции |
| -9 | Closed | соединение закрыто (EOF или дескриптор уже закрыт) |
| -10 | ProtocolError | HTTP/WS/H3 framing |
| -11 | Unsupported | не поддерживается сборкой |
| -12 | EchRetryWithEch | сервер отклонил ECH → обновить `ech=` по DNS HTTPS-записи и повторить connect |
| -13 | BufferTooSmall | буфер вызывающего мал; нужный размер — в out-параметре `needed` |
| -14 | Panic | внутренняя паника Rust перехвачена на границе FFI; дескриптор рекомендуется закрыть |
| -15 | MessageTooLarge | сообщение/тело превысило лимит (`bn_set_limits`) |

Буферы «на выход» (`bn_tls_alpn`, `bn_http1_response_*`,
`bn_h3_take_resumption_token`, `bn_ws_recv`, ...): при нехватке места
возвращается `-13`, а нужный размер записывается в out-параметр
`needed` (может быть NULL — тогда только код ошибки). Для строковых
буферов `needed` включает завершающий NUL; заголовки: имя и значение
пишутся с NUL-терминатором.

Для функций, возвращающих указатель (`bn_tls_connect`, `bn_ws_connect`,
`bn_h3_connect`, `bn_http1_fetch`, `bn_h3_fetch`; NULL при ошибке), код
ошибки недоступен в возврате — берите его из `bn_last_error_code()`.

**Свежесть ошибки (важно для JNA/многопоточности):** обе функции
`bn_last_error_code()` / `bn_last_error_message()` — неразрушающие;
слот очищается на входе КАЖДОЙ операции `bn_*`. Слот всегда отражает
именно последний вызов в этом потоке: после успешной операции
`bn_last_error_code() == 0`. `code` и `message` можно читать в любом
порядке и сколько угодно раз.

**Таймауты:** все параметры `timeout_ms`: `0` → 30000 мс; значения
выше 24 часов урезаются до 24 часов (защита от переполнения
PRIntervalTime в NSPR). **Порты:** `NbConnectOptions.port = 0` → 443.

## bn_init: корневые сертификаты

* **Desktop (Linux/Windows):** `bn_init(NULL, 0)` — корни берутся из
  хранилища ОС (`rustls-native-certs`).
* **Android:** системного PEM-пути нет — Kotlin-слой читает хранилище
  доверенных ЦС (или бандлит Mozilla CA bundle) и передаёт байты PEM:

```kotlin
val pem = readAsset("mozilla-ca-bundle.pem") // или из системы
nbInit(pem.toByteArray(), pem.size)
```

Повторный вызов `bn_init` — no-op; после `bn_shutdown` — полноценная
повторная инициализация (например, для тестов).

## Лимиты размеров (анти-DoS)

`bn_set_limits(max_http1_body, max_ws_message, max_h3_response)`
ограничивает тело HTTP/1.1-ответа, сообщение WebSocket (кадр и сумма
фрагментов, оба направления) и тело HTTP/3-ответа. По умолчанию
64 МиБ; `0` — без лимита. Превышение → `-15 MessageTooLarge`
(H3-поток при этом гасится STOP_SENDING, WS-сообщение не теряется
при too-small буфере — вернётся следующим `bn_ws_recv`).

## ECH и параметры — кто их подставляет

По договорённости, **Kotlin-слой приложения сам** автоматически
подставляет параметры:

* `NbConnectOptions.ech_config_list` — байты `ech=` из DNS HTTPS-записи
  (resolver приложения). Нет записи → NULL (библиотека всё равно шлёт
  GREASE ECH, как Firefox);
* `NbConnectOptions.ip` — предрезолвленный адрес (если приложение хочет
  свой DNS/кеш). NULL → библиотека резолвит `host`;
* `NbConnectOptions.profile` — 0 (desktop) / 1 (android) — выбирается
  по платформе;
* `resumption_token` — 0-RTT токен из прошлого соединения
  (`bn_h3_take_resumption_token`), если приложение хочет ускорить.

## Поведение подключения (TCP/TLS-путь)

* **Happy Eyeballs (RFC 8305)**: резолвятся все адреса (порядок
  RFC 6724), следующий стартует через 300 мс (как
  network.http.fast-fallback-to-IPv4); побеждает первый установившийся
  TCP, остальные закрываются. Для QUIC-пути берётся первый адрес.
* **TLS version-intolerance**: при ошибках из списка PSM handshake
  прозрачно повторяется с максимумом TLS 1.2 + downgrade-check
  (sentinel в ServerHello.random). Приложение видит только результат.
* **False start** включён (pref security.ssl.enable_false_start;
  критерии — рекомендованные NSS, как у PSM).
* **TLS-resumption**: клиентский кеш NSS, в рамках процесса; ключ —
  адрес сервера + порт (другой IP после ре-резолва → полное
  рукопожатие). Между запусками приложения сессии не живут.

## C: сырой TLS-туннель (байтовый поток)

```c
NbConnectOptions o = {0};
o.host = "target.example";
o.port = 443;
o.timeout_ms = 15000;
o.profile = 0;

NbTls *t = bn_tls_connect(&o);
if (!t) die(bn_last_error_message());

/* дальше — произвольный байтовый протокол поверх TLS */
bn_tls_write(t, payload, len, 5000);
int n = bn_tls_read(t, buf, sizeof buf, 5000); /* 0=EOF, <0=ошибка */
bn_tls_close(&t);                               /* t = NULL */
```

ALPN при необходимости: `o.alpn = "h2,http/1.1"` (wire-формат: через
запятую). Согласованный протокол — `bn_tls_alpn`.

## C: HTTP/1.1 (полный запрос-ответ)

```c
NbHeader hs[] = {
    { "User-Agent", ua, strlen(ua) },
    { "Accept", "*/*", 3 },
};
NbHttpResponse *r = bn_http1_fetch(t, "POST", "/api/v1/x",
                                   hs, 2, body, body_len, 15000);
int status = bn_http1_response_status(r);          /* 200 */
int n = bn_http1_response_header_count(r);
/* ... bn_http1_response_header(r, i, name, val, NULL, NULL) ... */
uint8_t body[65536];
int len = bn_http1_response_body(r, body, sizeof body, NULL);
bn_http1_response_free(&r);                        /* r = NULL */
```

Тело ответа буферизуется целиком (v1); для стриминга используйте
сырой TLS + свой HTTP, или HTTP/3-путь (он стриминговый).

**KEEP-ALIVE:** несколько `bn_http1_fetch` по одному дескриптору `NbTls`
работают без переподключения (запрос идёт с `Connection: keep-alive`,
тело читается ровно по Content-Length/chunked, включая трейлеры).
Соединение становится одноразовым, если сервер ответил
`Connection: close` или прислал тело без длины (чтение до EOF) —
следующий fetch вернёт `-9 Closed`; откройте новый дескриптор.

## C: HTTP/3 (стриминговое тело)

```c
NbH3 *h = bn_h3_connect(&o);
NbH3Request *r = bn_h3_fetch(h, "GET", "/big.bin", NULL, 0, NULL, 0, 15000);

int status = bn_h3_req_status(r);            /* -1, пока заголовки не пришли */
uint8_t chunk[16384];
for (;;) {
    int n = bn_h3_req_read(r, chunk, sizeof chunk, 5000);
    if (n == 0) break;                        /* fin */
    if (n < 0) die(bn_last_error_message());
    fwrite(chunk, 1, n, out);
}

uint8_t tok[512];
int tl = bn_h3_take_resumption_token(h, tok, sizeof tok, NULL); /* 0-RTT */
bn_h3_req_free(&r);
bn_h3_close(&h);
```

`bn_h3_req_read` блокирует до появления данных или таймаута — цикл
событий QUIC крутится внутри. Одно соединение → много последовательных
запросов (новый `bn_h3_fetch` без реконнекта).

## C: WebSocket (WSS)

```c
NbHeader hs[] = {
    { "User-Agent", ua, strlen(ua) },
    { "Sec-WebSocket-Protocol", "chat", 4 },
};
NbWs *w = bn_ws_connect(&o, "/ws", hs, 2);

bn_ws_send(w, 1 /* text */, "hello", 5, 5000);

uint8_t op;
uint8_t buf[16384];
int n = bn_ws_recv(w, &op, buf, sizeof buf, 5000, NULL);
/* op: 1=text, 2=binary, 8=close(первые 2 байта payload = код), 10=pong */
/* ping сервера библиотека отрабатывает авто-pong сама, как Firefox */

bn_ws_send(w, 9 /* ping */, NULL, 0, 5000);
bn_ws_close(&w, 1000, "bye", 5000);                 /* w = NULL */
```

Фрейминг RFC 6455: клиентская маскировка, фрагментация входящих
собирается в сообщения (лимит — `bn_set_limits`, по умолчанию 64 МиБ),
auto-pong на ping.

ALPN: по умолчанию WSS предлагает `[h2, http/1.1]` (как Firefox); если
сервер согласовал h2 — ошибка Unsupported (WebSocket v1 идёт по http/1.1).
На h2-агрессивных серверах принудите: `o.alpn = "http/1.1"`.

## Kotlin (JNA)

Библиотека — обычный C ABI, поэтому на JVM/Desktop достаточно
[JNA](https://github.com/java-native-access/jna): функции из
`ffi/bangboo_net.h` объявляются в интерфейсе `Library`, структуры
`NbConnectOptions`/`NbHeader` — классами `Structure` с
`@Structure.FieldOrder` в точном порядке полей C (совпадение layout
проверено: 72/24 байта на x86_64).

Поверх сырого биндинга удобно сделать идиоматичную обёртку с
исключениями и `AutoCloseable`; типичный вид:

```kotlin
// desktop: корни из ОС; Android: передать PEM системных корней
Bangboo.init()

// HTTPS (HTTP/1.1) — целиком запрос-ответ
Bangboo.tls(ConnectOptions(host = "example.org")).use { tls ->
    val resp = tls.fetch("GET", "/", headers = mapOf("User-Agent" to UA))
    println("HTTP ${resp.status}, тело ${resp.body.size} байт")
}

// HTTP/3 — стриминговое тело + resumption-токен для 0-RTT
Bangboo.h3(ConnectOptions(host = "cloudflare-quic.com")).use { h3 ->
    h3.fetch("GET", "/").use { req ->
        val status = req.awaitHeaders()
        val body = req.readAll()
    }
    val token = h3.takeResumptionToken()
}

// WSS
Bangboo.ws(ConnectOptions(host = "echo.example"), path = "/ws").use { ws ->
    ws.sendText("привет")
    when (val m = ws.receive()) { is WsMessage.Text -> println(m.text) ... }
    ws.close(1000, "bye")
}

// ECH: конфиг берём из DNS HTTPS-записи (приложение отвечает за это само)
val ech = dohFetchEch("crypto.cloudflare.com")   // байты ech= из JSON DoH
Bangboo.tls(ConnectOptions(host = "crypto.cloudflare.com", echConfigList = ech)).use { ... }
// при EchRetryWithEch — исключение EchRetryException: обновите конфиг
// по DNS и повторите подключение
```

## Потоки и время жизни

* Дескрипторы потокобезопасны: одновременные вызовы из разных потоков
  сериализуются внутри (Mutex на состояние дескриптора). Вызов
  `close/free` concurrently с операцией по тому же дескриптору
  безопасен: операция завершится, затем дескриптор освободится.
* `bn_*_close/free` принимают адрес указателя и ОБНУЛЯЮТ его —
  повторный вызов (и с NULL) безопасный no-op:
  `bn_tls_close(&t); bn_tls_close(&t);` — без double-free.
* `bn_h3_close` осиротивает дескрипторы запросов: `bn_h3_req_*` после
  этого возвращают `-9 Closed` (не падают), `bn_h3_req_free` работает.
  Запросы можно освобождать и до, и после закрытия соединения.
* `bn_shutdown` освобождает верификатор и выключает NSS (если её
  подняла библиотека). Закройте все дескрипторы ДО вызова, иначе
  ошибка -1 (и dlclose .so тогда нельзя). После успеха возможен
  повторный `bn_init`. На Android вызывайте `bn_shutdown` до
  `dlclose` (детали — docs/SECURITY.md).
* Строки из `bn_last_error_message()`/`bn_version()` валидны до
  следующего вызова библиотеки в том же потоке.

## Ограничения v1

* HTTP/1.1-ответ буферизуется целиком (стриминг — TLS/H3-пути).
* TLS-resumption — в рамках процесса (кеш NSS); 0-RTT есть только в
  QUIC-пути (токен `bn_h3_take_resumption_token`).
* WSS-over-HTTP/3 (WebTransport CONNECT) — не реализован (v2).
* Happy Eyeballs: TCP/TLS — гонка адресов RFC 8305; QUIC — первый
  адрес (RFC 6724), гонка QUIC↔TCP остаётся приложению.
