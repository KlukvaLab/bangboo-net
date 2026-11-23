/* Дымовой тест bangboo-net: TLS + HTTP/1.1 GET, затем HTTP/3.
 * Проверяет и новый контракт безопасности: too-small буферы (-13 + needed),
 * обнуляющие close, двойной close, NULL-аргументы.
 * Сборка: gcc tests/smoke.c -I ffi -o smoke -L target/release -lbangboo_net
 * Запуск: LD_LIBRARY_PATH=...:/target/release ./smoke [host]
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "bangboo_net.h"

static int failures = 0;

#define CHECK(cond, ...) do { \
    if (!(cond)) { \
        printf("FAIL: "); \
        printf(__VA_ARGS__); \
        printf("\n"); \
        failures++; \
    } \
} while (0)

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "example.com";
    printf("version: %s\n", bn_version());

    if (bn_init(NULL, 0) != 0) {
        printf("bn_init FAILED: %s\n", bn_last_error_message());
        return 1;
    }
    printf("bn_init OK (system roots)\n");

    /* NULL-устойчивость */
    CHECK(bn_tls_read(NULL, NULL, 0, 1) == -2, "bn_tls_read(NULL) == -2");
    CHECK(bn_tls_connect(NULL) == NULL, "bn_tls_connect(NULL) == NULL");
    CHECK(bn_last_error_code() == 2, "last_error_code == 2");

    BnConnectOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.host = host;
    opts.port = 443;
    opts.timeout_ms = 15000;
    opts.profile = 0; /* firefox-desktop */

    BnTls *tls = bn_tls_connect(&opts);
    if (!tls) {
        printf("bn_tls_connect FAILED: %s\n", bn_last_error_message());
        return 2;
    }
    printf("bn_tls_connect OK\n");

    /* too-small буфер: -13 + needed */
    char tiny[2];
    uint32_t needed = 0;
    int al = bn_tls_alpn(tls, tiny, sizeof(tiny), &needed);
    if (al == -13) {
        printf("alpn too-small OK: needed=%u\n", needed);
    } else {
        printf("alpn: %d (%s)\n", al, al > 0 ? tiny : "-");
    }

    char alpn[64] = {0};
    al = bn_tls_alpn(tls, alpn, sizeof(alpn), NULL);
    printf("alpn: %d (%s)\n", al, al > 0 ? alpn : "-");

    const char *ua = "bangboo-net-smoke/0.1";
    BnHeader headers[1] = {
        { "User-Agent", (const uint8_t *)ua, (uint32_t)strlen(ua) },
    };
    BnHttpResponse *resp = bn_http1_fetch(
        tls, "GET", "/", headers, 1, NULL, 0, 15000);
    if (!resp) {
        printf("bn_http1_fetch FAILED: %s\n", bn_last_error_message());
        bn_tls_close(&tls);
        return 3;
    }
    printf("HTTP status: %d\n", bn_http1_response_status(resp));
    printf("headers: %d\n", bn_http1_response_header_count(resp));

    /* заголовок с too-small значением: -13 + оба needed */
    {
        char nbuf[128];
        uint32_t nn = 0, nv = 0;
        int rc = bn_http1_response_header(resp, 0, nbuf, sizeof(nbuf),
                                          (uint8_t *)"", 1, &nn, &nv);
        if (rc == -13) {
            printf("header too-small OK: needed name=%u value=%u\n", nn, nv);
            CHECK(nn > 0 && nv > 1, "needed sizes sane");
            /* повтор с достаточным буфером */
            char vb[1024];
            rc = bn_http1_response_header(resp, 0, nbuf, sizeof(nbuf),
                                          (uint8_t *)vb, sizeof(vb), NULL, NULL);
            CHECK(rc >= 0, "header retry OK");
        } else {
            printf("header[0]: %d\n", rc);
        }
    }

    char name[128], val[512];
    int hn = bn_http1_response_header_count(resp);
    for (int i = 0; i < hn; i++) {
        bn_http1_response_header(resp, i, name, sizeof(name),
                                  (uint8_t *)val, sizeof(val), NULL, NULL);
        printf("  %s: %s\n", name, val);
    }

    /* тело с too-small буфером: -13 + needed */
    {
        uint8_t small[4];
        uint32_t need = 0;
        int rc = bn_http1_response_body(resp, small, sizeof(small), &need);
        if (rc == -13) {
            printf("body too-small OK: needed=%u\n", need);
            CHECK(need > sizeof(small), "needed > cap");
        }
    }
    uint8_t *body = malloc(256 * 1024);
    int bl = bn_http1_response_body(resp, body, 256 * 1024 - 1, NULL);
    if (bl > 0) {
        body[bl < 256 * 1024 - 1 ? bl : 256 * 1024 - 1] = 0;
    }
    printf("body(%d bytes): %.*s\n", bl, bl > 0 ? bl : 0, (char *)body);
    free(body);

    /* keep-alive: второй запрос по ТОМУ ЖЕ дескриптору, без переподключения */
    {
        BnHttpResponse *r2 = bn_http1_fetch(tls, "GET", "/", NULL, 0, NULL, 0, 15000);
        CHECK(r2 != NULL, "второй fetch по keep-alive (не NULL)");
        if (r2) {
            CHECK(bn_http1_response_status(r2) == 200,
                  "второй fetch: статус 200, получен %d",
                  bn_http1_response_status(r2));
            uint8_t b2[4096];
            int l2 = bn_http1_response_body(r2, b2, sizeof(b2), NULL);
            printf("keep-alive #2: статус %d, тело %d байт\n",
                   bn_http1_response_status(r2), l2);
            bn_http1_response_free(&r2);
        }
    }

    bn_http1_response_free(&resp);
    CHECK(resp == NULL, "response_free nullified");
    bn_http1_response_free(&resp); /* повторный — no-op */
    bn_tls_close(&tls);
    CHECK(tls == NULL, "tls_close nullified");
    bn_tls_close(&tls); /* повторный — no-op */
    printf("SMOKE TEST TLS OK\n");

    /* HTTP/3 */
    BnH3 *h3 = bn_h3_connect(&opts);
    if (!h3) {
        printf("bn_h3_connect FAILED: %s\n", bn_last_error_message());
        return 4;
    }
    printf("bn_h3_connect OK (QUIC handshake)\n");
    BnH3Request *req = bn_h3_fetch(h3, "GET", "/", NULL, 0, NULL, 0, 15000);
    if (!req) {
        printf("bn_h3_fetch FAILED: %s\n", bn_last_error_message());
        bn_h3_close(&h3);
        return 5;
    }
    int st = -1;
    for (int i = 0; i < 100 && st < 0; i++) {
        uint8_t b[256];
        int n = bn_h3_req_read(req, b, sizeof(b), 300);
        (void)n;
        st = bn_h3_req_status(req);
    }
    printf("H3 status: %d\n", st);
    uint8_t b3[4096];
    int total = 0;
    for (;;) {
        int n = bn_h3_req_read(req, b3, sizeof(b3), 5000);
        if (n <= 0) break;
        total += n;
    }
    printf("H3 body: %d bytes\n", total);
    /* close соединения при живом запросе → осиротевание */
    bn_h3_close(&h3);
    CHECK(h3 == NULL, "h3_close nullified");
    /* use-after-close: осиротевший запрос должен дать -9, не упасть */
    CHECK(bn_h3_req_status(req) == -9, "req_status after close == -9");
    bn_h3_req_free(&req); /* освобождение осиротевшего запроса */
    CHECK(req == NULL, "req_free nullified");
    bn_h3_close(&h3); /* повторный — no-op */
    printf("SMOKE TEST H3 OK\n");

    if (failures) {
        printf("SMOKE: %d FAILURES\n", failures);
        return 10;
    }
    return 0;
}
