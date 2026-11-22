/* Дымовой тест neqo-backend: TLS + HTTP/1.1 GET, затем HTTP/3.
 * Проверяет и новый контракт безопасности: too-small буферы (-13 + needed),
 * обнуляющие close, двойной close, NULL-аргументы.
 * Сборка: gcc tests/smoke.c -I ffi -o smoke -L target/release -lneqo_backend
 * Запуск: LD_LIBRARY_PATH=...:/target/release ./smoke [host]
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "neqo_backend.h"

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
    printf("version: %s\n", nb_version());

    if (nb_init(NULL, 0) != 0) {
        printf("nb_init FAILED: %s\n", nb_last_error_message());
        return 1;
    }
    printf("nb_init OK (system roots)\n");

    /* NULL-устойчивость */
    CHECK(nb_tls_read(NULL, NULL, 0, 1) == -2, "nb_tls_read(NULL) == -2");
    CHECK(nb_tls_connect(NULL) == NULL, "nb_tls_connect(NULL) == NULL");
    CHECK(nb_last_error_code() == 2, "last_error_code == 2");

    NbConnectOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.host = host;
    opts.port = 443;
    opts.timeout_ms = 15000;
    opts.profile = 0; /* firefox-desktop */

    NbTls *tls = nb_tls_connect(&opts);
    if (!tls) {
        printf("nb_tls_connect FAILED: %s\n", nb_last_error_message());
        return 2;
    }
    printf("nb_tls_connect OK\n");

    /* too-small буфер: -13 + needed */
    char tiny[2];
    uint32_t needed = 0;
    int al = nb_tls_alpn(tls, tiny, sizeof(tiny), &needed);
    if (al == -13) {
        printf("alpn too-small OK: needed=%u\n", needed);
    } else {
        printf("alpn: %d (%s)\n", al, al > 0 ? tiny : "-");
    }

    char alpn[64] = {0};
    al = nb_tls_alpn(tls, alpn, sizeof(alpn), NULL);
    printf("alpn: %d (%s)\n", al, al > 0 ? alpn : "-");

    const char *ua = "neqo-backend-smoke/0.1";
    NbHeader headers[1] = {
        { "User-Agent", (const uint8_t *)ua, (uint32_t)strlen(ua) },
    };
    NbHttpResponse *resp = nb_http1_fetch(
        tls, "GET", "/", headers, 1, NULL, 0, 15000);
    if (!resp) {
        printf("nb_http1_fetch FAILED: %s\n", nb_last_error_message());
        nb_tls_close(&tls);
        return 3;
    }
    printf("HTTP status: %d\n", nb_http1_response_status(resp));
    printf("headers: %d\n", nb_http1_response_header_count(resp));

    /* заголовок с too-small значением: -13 + оба needed */
    {
        char nbuf[128];
        uint32_t nn = 0, nv = 0;
        int rc = nb_http1_response_header(resp, 0, nbuf, sizeof(nbuf),
                                          (uint8_t *)"", 1, &nn, &nv);
        if (rc == -13) {
            printf("header too-small OK: needed name=%u value=%u\n", nn, nv);
            CHECK(nn > 0 && nv > 1, "needed sizes sane");
            /* повтор с достаточным буфером */
            char vb[1024];
            rc = nb_http1_response_header(resp, 0, nbuf, sizeof(nbuf),
                                          (uint8_t *)vb, sizeof(vb), NULL, NULL);
            CHECK(rc >= 0, "header retry OK");
        } else {
            printf("header[0]: %d\n", rc);
        }
    }

    char name[128], val[512];
    int hn = nb_http1_response_header_count(resp);
    for (int i = 0; i < hn; i++) {
        nb_http1_response_header(resp, i, name, sizeof(name),
                                  (uint8_t *)val, sizeof(val), NULL, NULL);
        printf("  %s: %s\n", name, val);
    }

    /* тело с too-small буфером: -13 + needed */
    {
        uint8_t small[4];
        uint32_t need = 0;
        int rc = nb_http1_response_body(resp, small, sizeof(small), &need);
        if (rc == -13) {
            printf("body too-small OK: needed=%u\n", need);
            CHECK(need > sizeof(small), "needed > cap");
        }
    }
    uint8_t *body = malloc(256 * 1024);
    int bl = nb_http1_response_body(resp, body, 256 * 1024 - 1, NULL);
    if (bl > 0) {
        body[bl < 256 * 1024 - 1 ? bl : 256 * 1024 - 1] = 0;
    }
    printf("body(%d bytes): %.*s\n", bl, bl > 0 ? bl : 0, (char *)body);
    free(body);

    /* keep-alive: второй запрос по ТОМУ ЖЕ дескриптору, без переподключения */
    {
        NbHttpResponse *r2 = nb_http1_fetch(tls, "GET", "/", NULL, 0, NULL, 0, 15000);
        CHECK(r2 != NULL, "второй fetch по keep-alive (не NULL)");
        if (r2) {
            CHECK(nb_http1_response_status(r2) == 200,
                  "второй fetch: статус 200, получен %d",
                  nb_http1_response_status(r2));
            uint8_t b2[4096];
            int l2 = nb_http1_response_body(r2, b2, sizeof(b2), NULL);
            printf("keep-alive #2: статус %d, тело %d байт\n",
                   nb_http1_response_status(r2), l2);
            nb_http1_response_free(&r2);
        }
    }

    nb_http1_response_free(&resp);
    CHECK(resp == NULL, "response_free nullified");
    nb_http1_response_free(&resp); /* повторный — no-op */
    nb_tls_close(&tls);
    CHECK(tls == NULL, "tls_close nullified");
    nb_tls_close(&tls); /* повторный — no-op */
    printf("SMOKE TEST TLS OK\n");

    /* HTTP/3 */
    NbH3 *h3 = nb_h3_connect(&opts);
    if (!h3) {
        printf("nb_h3_connect FAILED: %s\n", nb_last_error_message());
        return 4;
    }
    printf("nb_h3_connect OK (QUIC handshake)\n");
    NbH3Request *req = nb_h3_fetch(h3, "GET", "/", NULL, 0, NULL, 0, 15000);
    if (!req) {
        printf("nb_h3_fetch FAILED: %s\n", nb_last_error_message());
        nb_h3_close(&h3);
        return 5;
    }
    int st = -1;
    for (int i = 0; i < 100 && st < 0; i++) {
        uint8_t b[256];
        int n = nb_h3_req_read(req, b, sizeof(b), 300);
        (void)n;
        st = nb_h3_req_status(req);
    }
    printf("H3 status: %d\n", st);
    uint8_t b3[4096];
    int total = 0;
    for (;;) {
        int n = nb_h3_req_read(req, b3, sizeof(b3), 5000);
        if (n <= 0) break;
        total += n;
    }
    printf("H3 body: %d bytes\n", total);
    /* close соединения при живом запросе → осиротевание */
    nb_h3_close(&h3);
    CHECK(h3 == NULL, "h3_close nullified");
    /* use-after-close: осиротевший запрос должен дать -9, не упасть */
    CHECK(nb_h3_req_status(req) == -9, "req_status after close == -9");
    nb_h3_req_free(&req); /* освобождение осиротевшего запроса */
    CHECK(req == NULL, "req_free nullified");
    nb_h3_close(&h3); /* повторный — no-op */
    printf("SMOKE TEST H3 OK\n");

    if (failures) {
        printf("SMOKE: %d FAILURES\n", failures);
        return 10;
    }
    return 0;
}
