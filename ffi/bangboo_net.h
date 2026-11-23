/*
 * bangboo_net.h — C ABI библиотеки bangboo-net.
 *
 * TLS / HTTP/1.1 / HTTP/3 (QUIC) / WSS на сетевом стеке Firefox (NSS+neqo).
 * Для Kotlin подключается через JNA/JNI-обёртку; для C — напрямую.
 *
 * Правила:
 *  - дескрипторы (NbTls*, NbWs*, NbH3*, NbH3Request*, NbHttpResponse*)
 *    создаются *_connect / *_fetch и освобождаются *_close / *_free;
 *  - close/free принимают АДРЕС указателя и обнуляют его:
 *      bn_tls_close(&tls);   // tls == NULL, повторный вызов — no-op
 *    Это исключает double-free при повторном вызове;
 *  - возвращаемые int: >= 0 — успех/размер, < 0 — код ошибки
 *    (bn_errno из комментария ниже); текст — bn_last_error_message();
 *  - буферы «на выход»: если места не хватило, возвращается -13
 *    (BufferTooSmall), а нужный размер записывается в out-параметр
 *    `needed` (может быть NULL). Для строковых буферов needed включает
 *    завершающий NUL;
 *  - строки — UTF-8 NUL-terminated; валидны до следующего вызова
 *    библиотеки в этом потоке;
 *  - ТАЙМАУТЫ (все параметры timeout_ms): 0 => 30000 мс; значения
 *    больше 24 часов урезаются до 24 часов;
 *  - ПОТОКОБЕЗОПАСНОСТЬ: дескрипторы можно использовать из нескольких
 *    потоков одновременно — вызовы сериализуются внутри. Вызов
 *    close/free concurrently с операцией по тому же дескриптору
 *    безопасен (операция завершится, затем дескриптор освободится).
 *    После возврата close/free указатель недействителен (NULL).
 */

#ifndef NEQO_BACKEND_H
#define NEQO_BACKEND_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Коды ошибок (отрицательные возвраты) ----
 *  0  OK
 * -1  Generic — внутренняя ошибка (см. bn_last_error_message)
 * -2  InvalidArgument
 * -3  NotInitialized (bn_init не вызван/не удался)
 * -4  DnsFailure
 * -5  ConnectFailed
 * -6  HandshakeFailed (TLS/QUIC handshake, alert)
 * -7  CertificateInvalid (цепочка не прошла проверку)
 * -8  Timeout
 * -9  Closed (EOF или дескриптор уже закрыт)
 * -10 ProtocolError (HTTP/WS/H3 framing)
 * -11 Unsupported
 * -12 EchRetryWithEch — сервер отклонил ECH: обновите ECHConfigList
 *      (DNS HTTPS-запись) и повторите bn_tls_connect
 * -13 BufferTooSmall — буфер вызывающего мал; нужный размер записан
 *      в out-параметр needed (если передан)
 * -14 Panic — внутренняя паника Rust перехвачена на границе FFI;
 *      стек не повреждён, но дескриптор рекомендуется закрыть
 * -15 MessageTooLarge — сообщение/тело превысило лимит (bn_set_limits)
 */

typedef struct NbTls NbTls;
typedef struct NbWs NbWs;
typedef struct NbH3 NbH3;
typedef struct NbH3Request NbH3Request;
typedef struct NbHttpResponse NbHttpResponse;

typedef struct NbHeader {
    const char *name;    /* UTF-8 */
    const uint8_t *value;
    uint32_t value_len;
} NbHeader;

typedef struct NbConnectOptions {
    const char *host;             /* имя хоста: SNI + проверка сертификата */
    const char *ip;               /* предрезолвленный IP (NULL => резолв lib) */
    uint16_t port;                /* 0 => 443 */
    const char *alpn;             /* wire-список для TLS: "h2,http/1.1"; NULL => нет.
                                    * Для WSS имеет приоритет над дефолтом
                                    * [h2,http/1.1]: ставьте "http/1.1",
                                    * если сервер любит h2 (v1 WS идёт по 1.1) */
    const uint8_t *ech_config_list; /* ECHConfigList из DNS HTTPS-записи; NULL => нет */
    uint32_t ech_config_list_len;
    const uint8_t *resumption_token; /* QUIC 0-RTT токен; NULL => нет */
    uint32_t resumption_token_len;
    uint32_t timeout_ms;          /* connect+handshake; 0 => 30000 */
    uint8_t profile;              /* 0 = firefox-desktop, 1 = firefox-android */
    uint8_t reserved[7];
} NbConnectOptions;

/* ---- init / версии -------------------------------------------------- */

/* Инициализация. pem_roots: PEM-корни (Android: отдаёт Kotlin-слой из
 * системного хранилища); NULL — корни из хранилища ОС (desktop).
 * Повторный вызов — no-op. */
int32_t bn_init(const uint8_t *pem_roots, uint32_t pem_roots_len);

/* Выключение: верификатор сбрасывается, NSS (если поднята библиотекой)
 * выключается через NSS_Shutdown. ЗАКРОЙТЕ все дескрипторы ДО вызова —
 * иначе ошибка -1 и dlclose .so в этом случае нельзя. После успеха
 * возможен повторный bn_init. Вызывайте до dlclose на Android. */
int32_t bn_shutdown(void);

const char *bn_last_error_message(void); /* до следующего вызова в потоке */
/* Код последней ошибки (1..15, см. выше; 0 = ошибки не было).
 * Оба аксессора НЕразрушающие: слот отражает последнюю операцию bn_*
 * в этом потоке и очищается при следующем вызове bn_* — code и
 * message можно читать в любом порядке и сколько угодно раз. */
int32_t bn_last_error_code(void);
const char *bn_version(void);            /* до следующего вызова в потоке */

/* Лимиты размеров (анти-DoS), байты: тело HTTP/1.1-ответа, сообщение
 * WebSocket, тело HTTP/3-ответа. 0 = без лимита. По умолчанию 64 МиБ.
 * Превышение → -15 MessageTooLarge. Глобально на процесс. */
int32_t bn_set_limits(uint32_t max_http1_body,
                      uint32_t max_ws_message,
                      uint32_t max_h3_response);

/* ---- HTTPS over TLS -------------------------------------------------- */

NbTls *bn_tls_connect(const NbConnectOptions *opts);
/* >=0 прочитано байт; 0 = EOF; <0 ошибка (len==0 → 0) */
int32_t bn_tls_read(NbTls *s, uint8_t *buf, uint32_t len, uint32_t timeout_ms);
/* >=0 записано; <0 ошибка (пишем всё) */
int32_t bn_tls_write(NbTls *s, const uint8_t *buf, uint32_t len, uint32_t timeout_ms);
/* Согласованный ALPN: >0 длина (без NUL), 0 нет; мал буфер => -13,
 * нужный размер (с NUL) — в *needed. */
int32_t bn_tls_alpn(NbTls *s, char *buf, uint32_t buf_cap, uint32_t *needed);
/* Закрывает и ОБНУЛЯЕТ *s. Повторный вызов (и NULL) — no-op. */
void bn_tls_close(NbTls **s);

/* Полный HTTP/1.1-запрос по TLS-стриму (response буферизуется целиком,
 * с учётом лимита bn_set_limits). KEEP-ALIVE: несколько fetch по одному
 * дескриптору NbTls работают без переподключения (Connection:
 * keep-alive, тело читается ровно по Content-Length/chunked). Если
 * сервер ответил «Connection: close» или тело без длины (EOF),
 * следующий fetch вернёт -9 Closed — откройте новый дескриптор. */
NbHttpResponse *bn_http1_fetch(NbTls *s,
                               const char *method,
                               const char *target, /* "/path?query" */
                               const NbHeader *headers, uint32_t nheaders,
                               const uint8_t *body, uint32_t body_len,
                               uint32_t timeout_ms);
int32_t bn_http1_response_status(const NbHttpResponse *r);
int32_t bn_http1_response_header_count(const NbHttpResponse *r);
/* Копирует i-й заголовок; name и value NUL-terminated. Возвращает длину
 * value (без NUL). Мал один из буферов => -13, нужные размеры (с NUL)
 * — в *needed_name и *needed_value. */
int32_t bn_http1_response_header(const NbHttpResponse *r, int32_t index,
                                 char *name_buf, uint32_t name_cap,
                                 uint8_t *value_buf, uint32_t value_cap,
                                 uint32_t *needed_name, uint32_t *needed_value);
/* Тело ответа. Мал буфер => -13, нужный размер — в *needed. */
int32_t bn_http1_response_body(const NbHttpResponse *r,
                               uint8_t *buf, uint32_t buf_cap, uint32_t *needed);
/* Освобождает и ОБНУЛЯЕТ *r. Повторный вызов — no-op. */
void bn_http1_response_free(NbHttpResponse **r);

/* ---- WSS (WebSocket over TLS, RFC 6455) ------------------------------- */

/* path: "/ws"; headers: User-Agent, Sec-WebSocket-Protocol, Cookie, ... */
NbWs *bn_ws_connect(const NbConnectOptions *opts,
                    const char *path,
                    const NbHeader *headers, uint32_t nheaders);
/* opcode: 1=text, 2=binary, 9=ping; payload ограничен bn_set_limits */
int32_t bn_ws_send(NbWs *w, uint8_t opcode,
                   const uint8_t *data, uint32_t len, uint32_t timeout_ms);
/* Ждёт сообщение; opcode_out: 1,2,8(close),10(pong).
 * Возвращает длину payload (>=0) или <0. Мал буфер => -13 + *needed:
 * сообщение НЕ теряется, вернётся следующим вызовом. */
int32_t bn_ws_recv(NbWs *w, uint8_t *opcode_out,
                   uint8_t *buf, uint32_t buf_cap, uint32_t timeout_ms,
                   uint32_t *needed);
/* Отправляет close-кадр, закрывает TLS, освобождает дескриптор и
 * ОБНУЛЯЕТ *w. Повторный вызов — no-op (0). */
int32_t bn_ws_close(NbWs **w, uint16_t code, const char *reason,
                    uint32_t timeout_ms);

/* ---- HTTPS over QUIC (HTTP/3) ----------------------------------------- */

NbH3 *bn_h3_connect(const NbConnectOptions *opts);
NbH3Request *bn_h3_fetch(NbH3 *h,
                         const char *method,
                         const char *target,
                         const NbHeader *headers, uint32_t nheaders,
                         const uint8_t *body, uint32_t body_len,
                         uint32_t timeout_ms);
/* -1 = заголовков ещё нет; -9 = соединение закрыто (bn_h3_close);
 * после close дескрипторы запросов остаются валидными для free. */
int32_t bn_h3_req_status(const NbH3Request *r);
int32_t bn_h3_req_header_count(const NbH3Request *r);
/* Как bn_http1_response_header (NUL-terminated, -13 + needed при
 * нехватке места). */
int32_t bn_h3_req_header(const NbH3Request *r, int32_t index,
                         char *name_buf, uint32_t name_cap,
                         uint8_t *value_buf, uint32_t value_cap,
                         uint32_t *needed_name, uint32_t *needed_value);
/* >=0 прочитано; 0 = тело закончено (fin); buf_cap==0 — «драйв»-вызов
 * (ждёт данные, не читая); <0 ошибка (-9 после bn_h3_close). */
int32_t bn_h3_req_read(NbH3Request *r, uint8_t *buf, uint32_t buf_cap,
                       uint32_t timeout_ms);
/* Освобождает и ОБНУЛЯЕТ *r; работает и после bn_h3_close. */
void bn_h3_req_free(NbH3Request **r);
/* Токен resumption (0-RTT): >0 длина; 0 нет; мал буфер => -13 + *needed */
int32_t bn_h3_take_resumption_token(NbH3 *h, uint8_t *buf, uint32_t buf_cap,
                                    uint32_t *needed);
/* Закрывает соединение, осиротивает запросы (bn_h3_req_* далее дают -9),
 * освобождает дескриптор и ОБНУЛЯЕТ *h. Повторный вызов — no-op. */
void bn_h3_close(NbH3 **h);

#ifdef __cplusplus
}
#endif

#endif /* NEQO_BACKEND_H */
