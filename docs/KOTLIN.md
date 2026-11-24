# Kotlin: подключение Bangboo Net через JNA

Справка для KMP-клиента: как все 30 функций `ffi/bangboo_net.h` ложатся на
Kotlin через JNA. Сценарии использования (TLS-туннель, HTTP/1.1, HTTP/3,
WSS, ECH, 0-RTT) — в [USAGE.md](USAGE.md); здесь только маппинг типов,
жизненный цикл дескрипторов и типовые приёмы.

## 1. Подключение библиотеки

Зависимость: `net.java.dev.jna:jna:5.14.0` (аннотация `@Structure.FieldOrder`
появилась в 5.8). Для гарантированной UTF-8 в строках задайте до загрузки:

```kotlin
System.setProperty("jna.encoding", "UTF-8")
```

Где искать `libbangboo_net.so` / `bangboo_net.dll`: передайте каталог через
`-Djna.library.path=...` (или положите рядом с исполняемым файлом). NSS-библиотеки
кладите в тот же каталог — скрипты сборки ставят всем .so `rpath=$ORIGIN`,
так что `libbangboo_net.so` сам найдёт свой NSS из комплекта.

```kotlin
import com.sun.jna.Native
import com.sun.jna.Library

val bn: BangbooNet = Native.load("bangboo_net", BangbooNet::class.java)
// Linux:  dist/linux-x86_64/libbangboo_net.so (+ 10 .so NSS рядом)
// Windows: dist/win-x86_64/bangboo_net.dll (+ NSS DLL рядом)
// Android: все .so из выхода scripts/build_android.sh — в jniLibs/<abi>;
//          JNA подключается зависимостью net.java.dev.jna:jna@aar.
```

На Android у ОС нет пути к системным корневым сертификатам в PEM — корни
читает Kotlin-слой и передаёт в `bn_init` (см. §4).

## 2. Маппинг типов C → JNA/Kotlin

| C (из bangboo_net.h) | JNA/Kotlin | Примечание |
|---|---|---|
| `int32_t` (возврат/код) | `Int` | ≥0 успех, <0 код ошибки (§5) |
| `uint32_t` (длины) | `Int` | разумные размеры < 2³¹ помещаются |
| `uint16_t` | `Short` | `port`, `code` в ws_close |
| `uint8_t` | `Byte` | `opcode`, `profile` |
| `BnTls*`, `BnWs*`, `BnH3*`, `BnH3Request*`, `BnHttpResponse*` | `Pointer?` | непрозрачные дескрипторы |
| `BnTls**` и пр. (close/free) | `PointerByReference` | библиотека ОБНУЛЯЕТ: после вызова `ref.value == null` |
| `const char *` (вход) | `String?` | null → NULL; кодировка — jna.encoding |
| `const char *` (возврат) | `String?` | валидна до следующего вызова bn_* в этом потоке |
| `const uint8_t *` + `uint32_t len` (вход) | `ByteArray?` + `Int` | null + 0 = «нет» |
| `uint8_t *` + `uint32_t` (выходной буфер) | `ByteArray` + `Int` | JNA копирует результат в массив после вызова |
| `uint8_t *opcode_out` | `ByteArray(1)` | читайте `[0]` после вызова |
| `uint32_t *needed` | `IntByReference?` | null допустим; при -13 там нужный размер |
| `BnHeader[]` + `nheaders` | `Array<BnHeader>?` + `Int` | null при nheaders=0 |

Правила структур: порядок и типы полей должны совпадать с заголовком
байт-в-байт; JNA синхронизирует Structure автоматически при передаче в
нативный вызов. Нулевая строка/массив передаются как настоящий NULL.

## 3. Структуры

```kotlin
import com.sun.jna.Structure
import com.sun.jna.Pointer

@Structure.FieldOrder("host", "ip", "port", "alpn", "ech_config_list",
    "ech_config_list_len", "resumption_token", "resumption_token_len",
    "timeout_ms", "profile", "reserved")
open class BnConnectOptions : Structure() {
    @JvmField var host: String = ""              // SNI + проверка сертификата
    @JvmField var ip: String? = null             // null → резолв в библиотеке
    @JvmField var port: Short = 0                // 0 → 443
    @JvmField var alpn: String? = null           // напр. "http/1.1"; null → дефолт
    @JvmField var ech_config_list: ByteArray? = null
    @JvmField var ech_config_list_len: Int = 0
    @JvmField var resumption_token: ByteArray? = null
    @JvmField var resumption_token_len: Int = 0
    @JvmField var timeout_ms: Int = 0            // 0 → 30000; >24 ч урежется
    @JvmField var profile: Byte = 0              // 0 = desktop, 1 = android
    @JvmField var reserved: ByteArray = ByteArray(7)
}

@Structure.FieldOrder("name", "value", "value_len")
class BnHeader : Structure() {
    @JvmField var name: String = ""              // без NUL: "Cookie"
    @JvmField var value: ByteArray? = null       // байты значения
    @JvmField var value_len: Int = 0             // = value!!.size
}
```

## 4. Интерфейс: все 30 функций

### 4.1 Жизненный цикл и общие (6)

```kotlin
/** Корни доверия в PEM. null → хранилище ОС (Linux/Windows desktop).
 *  Android: соберите PEM из системного хранилища и передайте байты. */
fun bn_init(pem_roots: ByteArray?, pem_roots_len: Int): Int
/** Верификатор сбрасывается, NSS гасится. ЗАКРОЙТЕ дескрипторы ДО вызова;
 *  иначе -1 и dlclose делать нельзя. После успеха возможен bn_init снова. */
fun bn_shutdown(): Int
/** Текст последней ошибки (thread-local). Не разрушает слот. */
fun bn_last_error_message(): String?
/** Код последней ошибки: 1..15 (без знака минус), 0 = не было. */
fun bn_last_error_code(): Int
/** Строка «bangboo-net x.y (neqo …, nss-rs …)». */
fun bn_version(): String?
/** Лимиты размеров, байты (0 = без лимита; дефолт 64 МиБ; на процесс). */
fun bn_set_limits(max_http1_body: Int, max_ws_message: Int, max_h3_response: Int): Int
```

### 4.2 TLS-туннель (5)

```kotlin
fun bn_tls_connect(opts: BnConnectOptions): Pointer?
fun bn_tls_read(s: Pointer, buf: ByteArray?, len: Int, timeout_ms: Int): Int
fun bn_tls_write(s: Pointer, buf: ByteArray?, len: Int, timeout_ms: Int): Int
fun bn_tls_alpn(s: Pointer, buf: ByteArray, buf_cap: Int, needed: IntByReference?): Int
fun bn_tls_close(s: PointerByReference)
```

`bn_tls_read`: 0 = EOF; `len == buf.size`. `bn_tls_write` отправляет всё
(частичная запись внутри); NULL-буфер при len>0 → -2. `bn_tls_alpn`:
>0 длина без NUL (читайте `String(buf, 0, rc, UTF_8)`), 0 = ALPN не было.

### 4.3 HTTP/1.1 (6)

```kotlin
fun bn_http1_fetch(s: Pointer, method: String?, target: String?,
                   headers: Array<BnHeader>?, nheaders: Int,
                   body: ByteArray?, body_len: Int, timeout_ms: Int): Pointer?
fun bn_http1_response_status(r: Pointer): Int
fun bn_http1_response_header_count(r: Pointer): Int
fun bn_http1_response_header(r: Pointer, index: Int,
                             name_buf: ByteArray, name_cap: Int,
                             value_buf: ByteArray, value_cap: Int,
                             needed_name: IntByReference?, needed_value: IntByReference?): Int
fun bn_http1_response_body(r: Pointer, buf: ByteArray, buf_cap: Int,
                           needed: IntByReference?): Int
fun bn_http1_response_free(r: PointerByReference)
```

`fetch` буферизует ответ целиком (лимит `bn_set_limits`); keep-alive —
несколько `fetch` по одному `s`; после `Connection: close` следующий
`fetch` вернёт -9. Возвраты `header`: длина value без NUL; имя в
`name_buf` с NUL (длина имени = `needed_name.value - 1`).

### 4.4 WSS (4)

```kotlin
fun bn_ws_connect(opts: BnConnectOptions, path: String?,
                  headers: Array<BnHeader>?, nheaders: Int): Pointer?
fun bn_ws_send(w: Pointer, opcode: Byte, data: ByteArray?, len: Int,
               timeout_ms: Int): Int
fun bn_ws_recv(w: Pointer, opcode_out: ByteArray,
               buf: ByteArray?, buf_cap: Int, timeout_ms: Int,
               needed: IntByReference?): Int
fun bn_ws_close(w: PointerByReference, code: Short, reason: String?,
                timeout_ms: Int): Int
```

`opcode` отправки: 1=text, 2=binary, 9=ping. В `recv` `opcode_out[0]`:
1/2/8=close/10=pong. При -13 сообщение НЕ потеряно — придёт следующим
`recv` (возьмите `needed.value` и повторите).

### 4.5 HTTP/3 (9)

```kotlin
fun bn_h3_connect(opts: BnConnectOptions): Pointer?
fun bn_h3_fetch(h: Pointer, method: String?, target: String?,
                headers: Array<BnHeader>?, nheaders: Int,
                body: ByteArray?, body_len: Int, timeout_ms: Int): Pointer?
fun bn_h3_req_status(r: Pointer): Int            // -1 ещё нет, код как в :status
fun bn_h3_req_header_count(r: Pointer): Int
fun bn_h3_req_header(r: Pointer, index: Int,
                     name_buf: ByteArray, name_cap: Int,
                     value_buf: ByteArray, value_cap: Int,
                     needed_name: IntByReference?, needed_value: IntByReference?): Int
fun bn_h3_req_read(r: Pointer, buf: ByteArray?, buf_cap: Int,
                   timeout_ms: Int): Int
fun bn_h3_req_free(r: PointerByReference)        // работает и после bn_h3_close
fun bn_h3_take_resumption_token(h: Pointer, buf: ByteArray, buf_cap: Int,
                                needed: IntByReference?): Int
fun bn_h3_close(h: PointerByReference)
```

«Разгон» тела: `bn_h3_req_read(r, null, 0, timeout)` ждёт данные, не читая;
>0 — размер накопленного тела (теперь читайте обычным вызовом), 0 — только
настоящий fin. Токен из `take_resumption_token` кладите в
`BnConnectOptions.resumption_token` следующего соединения (0-RTT).

## 5. Коды ошибок (возврат < 0)

| Код | Имя | Что делать |
|---|---|---|
| -1 | Generic | читать `bn_last_error_message()` |
| -2 | InvalidArgument | проверить NULL/строки/буферы вызова |
| -3 | NotInitialized | вызвать `bn_init` |
| -4 | DnsFailure | хост/IP |
| -5 | ConnectFailed | сеть/порт |
| -6 | HandshakeFailed | TLS/QUIC handshake, alert сервера |
| -7 | CertificateInvalid | цепочка не прошла проверку (отключить нельзя) |
| -8 | Timeout | увеличить `timeout_ms` |
| -9 | Closed | EOF или дескриптор уже закрыт — создать новый |
| -10 | ProtocolError | HTTP/WS/H3 framing |
| -11 | Unsupported | не входит в v1 |
| -12 | EchRetryWithEch | обновить ECHConfigList из DNS и повторить connect |
| -13 | BufferTooSmall | взять `needed` и повторить вызов |
| -14 | Panic | паника перехвачена; дескриптор лучше закрыть |
| -15 | MessageTooLarge | увеличить лимит в `bn_set_limits` или уменьшить сообщение |

Текст: `bn.lastErrorMessage()`; код без минуса: `bn.lastErrorCode()`.
Слот на поток: читайте сразу после неудачного вызова в том же потоке.

## 6. Типовые приёмы

```kotlin
import com.sun.jna.IntByReference
import com.sun.jna.Pointer
import com.sun.jna.PointerByReference

class BnException(val code: Int, text: String?) :
    RuntimeException(text ?: "bangboo-net: код $code")

/** Обёртка: отрицательный возврат → исключение с текстом из библиотеки. */
fun BangbooNet.checked(rc: Int): Int {
    if (rc < 0) throw BnException(rc, bn_last_error_message())
    return rc
}

/** Вызов с out-буфером, который может потребоваться больше: при -13
 *  повторяем с размером из needed. Возвращает данные нужной длины. */
fun BangbooNet.bufferFor(out: (buf: ByteArray, cap: Int, needed: IntByReference?) -> Int): ByteArray {
    var cap = 256
    val needed = IntByReference()
    while (true) {
        val buf = ByteArray(cap)
        val rc = out(buf, cap, needed)
        if (rc >= 0) return buf.copyOf(minOf(rc, cap))
        if (rc != -13) throw BnException(rc, bn_last_error_message())
        cap = needed.value            // нужный размер (с NUL для строк)
    }
}
```

Жизненный цикл дескриптора (close принимает адрес и обнуляет):

```kotlin
val ref = PointerByReference()
ref.value = bn.bn_tls_connect(opts) ?: throw BnException(-5, bn.bn_last_error_message())
try {
    // bn_tls_read / bn_tls_write / bn_http1_fetch(ref.value, ...)
} finally {
    bn.bn_tls_close(ref)              // повторный вызов безопасен
}
```

Потоки: один дескриптор можно звать из нескольких потоков — вызовы
сериализуются внутри; close/free догонит операцию, которая уже держит
дескриптор. Окно «дескриптор ещё не взят под замок, а close уже начался»
не защищено — такие гонки разруливайте у себя (см. docs/SECURITY.md §3).

## 7. Минимальный рабочий пример

```kotlin
fun main() {
    System.setProperty("jna.encoding", "UTF-8")
    val bn = Native.load("bangboo_net", BangbooNet::class.java)
    bn.checked(bn.bn_init(null, 0))

    val opts = BnConnectOptions().apply {
        host = "example.org"; port = 443; timeout_ms = 15000; profile = 0
    }
    val tls = PointerByReference()
    tls.value = bn.bn_tls_connect(opts) ?: throw BnException(-1, bn.bn_last_error_message())
    try {
        val resp = PointerByReference()
        resp.value = bn.bn_http1_fetch(tls.value, "GET", "/",
            null, 0, null, 0, 15000)
            ?: throw BnException(-1, bn.bn_last_error_message())
        try {
            println("HTTP ${bn.bn_http1_response_status(resp.value)}")
            val body = bn.bufferFor { buf, cap, needed ->
                bn.bn_http1_response_body(resp.value, buf, cap, needed)
            }
            println(String(body, Charsets.UTF_8).take(120))
        } finally { bn.bn_http1_response_free(resp) }
    } finally { bn.bn_tls_close(tls) }

    bn.checked(bn.bn_shutdown())      // после закрытия всех дескрипторов
}
```

Замечание про альтернативу: если захочется идиоматичный Kotlin без ручных
дескрипторов (ресурсные классы, перечисления вместо кодов), следующий шаг —
генерация обёртки UniFFI поверх тех же bn_*-функций; JNA-слой выше остаётся
эталоном контракта.
