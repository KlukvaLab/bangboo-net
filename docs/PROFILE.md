# TLS-профиль Firefox

Какие параметры TLS библиотека применяет к соединениям и откуда они
берутся. Все значения сняты с исходников Gecko (nsNSSIOLayer.cpp,
nsNSSComponent.cpp, StaticPrefList.yaml); номера строк — для
актуального mozilla-central, с которого снимались значения.

## Два пути — два механизма

### QUIC / HTTP-3: стек браузера

neqo — это QUIC/HTTP3-стек Firefox. `Http3Client` из `neqo-http3`
формирует QUIC ClientHello тем же кодом, что и браузер: порядок
расширений, параметры транспорта, кодирование фреймов.
Настройки в `quic.rs`:

* ALPN `"h3"` (как necko в Http3Session);
* TLS-шифры `TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256,
  TLS_AES_256_GCM_SHA384` — те же три набора, что Firefox разрешает
  для QUIC (`neqo-transport::Connection::set_ciphers`);
* случайные 8-байтовые Connection ID (RandomConnectionIdGenerator(8));
* `ConnectionParameters::default()` — дефолты neqo совпадают с тем,
  что использует gecko (versions v1+v2 compatible negotiation, pacing,
  pmtud, congestion control new-reno по умолчанию).

### TLS over TCP: профиль profile.rs

NSS по умолчанию настроен минимально — браузер конфигурирует сокеты
сам (nsNSSIOLayer.cpp). `profile::configure_socket()` применяет те же
настройки, элемент за элементом:

| Элемент | Значение | Источник |
|---|---|---|
| Версии TLS | 1.2–1.3 | StaticPrefList: security.tls.version.min=3, max=4 |
| Шифры | см. ниже | nsNSSComponent.cpp `sCipherPrefs` + `InitializeCipherSuite()` |
| Сигнатурные схемы | 14 схем (ML-DSA-44/65/87, ..., ecdsa_sha1, rsa_pkcs1_sha1) | security/manager/ssl/EnabledSignatureSchemes.h |
| Named groups | mlkem768x25519, x25519, p256, p384, p521 (FFDHE выкл: префы DHE = false) | nsNSSIOLayer.cpp |
| Key shares | mlkem768x25519 + x25519 + p256 (3 share) | `SSL_SendAdditionalKeyShares(2)` |
| False start | вкл (опция + критерии NSS) | pref security.ssl.enable_false_start |
| GREASE | вкл (`SSL_ENABLE_GREASE`) | включён в современном NSS, Firefox не отключает |
| Пермутация расширений | вкл (`SSL_ENABLE_CH_EXTENSION_PERMUTATION`) | Firefox 124+, дефолт NSS |
| TLS 1.3 compat mode | вкл | nsNSSIOLayer.cpp — всегда PR_TRUE |
| ECH GREASE | вкл, probability 100%, размер 100 | prefs security.tls.ech.grease_* |
| Сжатие сертификатов | zlib(1), brotli(2), zstd(3) | prefs security.tls.enable_certificate_compression_* (abridged выкл) |
| OCSP stapling | запрашивается (`SSL_ENABLE_OCSP_STAPLING`) | pref security.ssl.enable_ocsp_stapling |
| SCT | запрашивается | CT-режим Firefox |
| ALPN | вкл; список задаёт приложение | pref security.ssl.enable_alpn |
| Session tickets | вкл | ConfigureTLSSessionIdentifiers |
| Клиентский кеш сессий | вкл (`SSL_NO_CACHE=0`) | PSM: disableSessionIdentifiers = false |
| 0-RTT | разрешён | pref security.tls.enable_0rtt_data |
| Delegated credentials | разрешены | pref security.tls.enable_delegated_credentials |
| EMS / downgrade check | вкл | nsNSSComponent.cpp CommonInit |

### Наборы шифров (wire-порядок задаёт NSS, не список!)

Firefox в `InitializeCipherSuite()` сначала выключает ВСЕ шифры NSS,
затем включает разрешённые префами. Мы повторяем буквально это.
Порядок в ClientHello определяется порядком компиляции NSS
(`ssl3con.c`) — ещё одна причина пиннить версию NSS.

Включены (release-канал):

```
TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384
TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA
```

Выключены (префы false / удалены из NSS): все DHE-наборы, 3DES, RC4,
NULL, EXPORT. Ошибки «cipher not implemented» при включении отдельных
наборов сознательно игнорируются — так переживаются минорные различия
версий NSS.

### Профили

`NbConnectOptions.profile`:
* `0` = **firefox-desktop**, `1` = **firefox-android**.

Конфигурации совпадают: mlkem768x25519 включён и на Android —
Nimbus-флаг postQuantumKeyExchangeEnabled больше не отключает
security.tls.enable_kyber (fenix/app/nimbus.fml.yaml, default=null,
см. bug 1958676). Параметр оставлен для ABI-совместимости и будущих
расхождений профилей.

## Отличия от браузера (v1)

Реализовано и совпадает с Firefox:

* **False start** — вкл (опция + критерии
  SSL_RecommendedCanFalseStart, как у PSM).
* **TLS-resumption** — клиентский кеш NSS (in-memory, в рамках
  процесса; ключ — адрес+порт).
* **Downgrade-check** — при fallback-повторе NSS проверяет sentinel
  в ServerHello.random (как PSM при adjustForTLSIntolerance).
* **EMS, GREASE, пермутация расширений, сжатие сертификатов** —
  совпадают (таблица выше).
* **Record size limit** — не отправляем; Firefox для TLS тоже не
  отправляет (только для WebRTC).

Остаются различия:

* **Intolerance-память** — PSM запоминает per-host версию, «которую
  сервер терпит», на всю сессию браузера и сразу подключается с
  пониженным максимумом; мы делаем один stateless-ретрай на
  соединение (1.3 → 1.2). Wire при самом ретрае совпадает с Firefox.
* **Happy Eyeballs** — TCP/TLS-путь: гонка адресов RFC 8305 (стаггер
  300 мс, как network.http.fast-fallback-to-IPv4). QUIC-путь:
  первый адрес (порядок RFC 6724); гонка QUIC↔TCP — это уровень
  necko (приложения), не транспортной библиотеки.
* **SCSV** — TLS_FALLBACK_SCSV Firefox отправляет только при
  даунгрейде ниже TLS 1.2; наш минимум — 1.2, поэтому SCSV не
  нужен никогда (для 1.2-fallback действует downgrade-check).
* **DNS** — блокирующий getaddrinfo вместо асинхронного resolver'а
  Firefox; порядок адресов (RFC 6724) тот же.

## Проверка профиля (после обновления зависимостей)

1. Снимите собственный ClientHello: `tcpdump`/Wireshark, либо
   tshark-фильтр `tls.handshake.type == 1`.
2. Сверьте списки шифров, групп и расширений с таблицами этого
   документа.

## Обновление под новый Firefox

1. Посмотрите версию NSS в Firefox: about:buildconfig
   («NSS» в списке библиотек).
2. Обновите тарбол в `scripts/fetch_nss.sh` (URL + sha256).
3. Обновите git-теги neqo/nss-rs в `Cargo.toml` (они двигаются вместе:
   см. зависимость `nss` в neqo-репозитории нужного тега).
4. Сверьте diff `nsNSSIOLayer.cpp`/`nsNSSComponent.cpp` на предмет
   новых опций/шифров/групп → поправьте `profile.rs`.
5. Прогоните проверку профиля (раздел выше).
