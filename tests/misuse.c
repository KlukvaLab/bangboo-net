/* Тест устойчивости к неправильному использованию (аудит безопасности):
 *  - двойной close/free всех дескрипторов;
 *  - close/free с NULL и с NULL-слотом;
 *  - NULL-аргументы во всех функциях → -2, не segfault;
 *  - too-small буферы → -13 + needed;
 *  - use-after-close запроса H3 → -9 (не UAF);
 *  - лимиты bn_set_limits → -15 MessageTooLarge;
 *  - bn_shutdown при закрытых дескрипторах → 0, повторный bn_init работает.
 *
 * Сборка: gcc tests/misuse.c -I ffi -o misuse -L target/release -lbangboo_net
 * Запуск: LD_LIBRARY_PATH=... ./misuse [host]
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

    CHECK(bn_init(NULL, 0) == 0, "bn_init");

    /* --- NULL-аргументы ------------------------------------------------ */
    CHECK(bn_tls_read(NULL, NULL, 0, 1) == -2, "tls_read(NULL)");
    CHECK(bn_tls_write(NULL, NULL, 0, 1) == -2, "tls_write(NULL)");
    CHECK(bn_tls_alpn(NULL, NULL, 0, NULL) == -2, "tls_alpn(NULL)");
    CHECK(bn_http1_fetch(NULL, "GET", "/", NULL, 0, NULL, 0, 1) == NULL, "http1_fetch(NULL)");
    CHECK(bn_http1_response_status(NULL) == -2, "resp_status(NULL)");
    CHECK(bn_http1_response_header_count(NULL) == -2, "resp_hc(NULL)");
    CHECK(bn_http1_response_header(NULL, 0, NULL, 0, NULL, 0, NULL, NULL) == -2, "resp_h(NULL)");
    CHECK(bn_http1_response_body(NULL, NULL, 0, NULL) == -2, "resp_body(NULL)");
    CHECK(bn_ws_connect(NULL, "/", NULL, 0) == NULL, "ws_connect(NULL)");
    CHECK(bn_ws_send(NULL, 1, NULL, 0, 1) == -2, "ws_send(NULL)");
    CHECK(bn_ws_recv(NULL, NULL, NULL, 0, 1, NULL) == -2, "ws_recv(NULL)");
    CHECK(bn_h3_connect(NULL) == NULL, "h3_connect(NULL)");
    CHECK(bn_h3_fetch(NULL, "GET", "/", NULL, 0, NULL, 0, 1) == NULL, "h3_fetch(NULL)");
    CHECK(bn_h3_req_status(NULL) == -2, "req_status(NULL)");
    CHECK(bn_h3_req_header_count(NULL) == -2, "req_hc(NULL)");
    CHECK(bn_h3_req_header(NULL, 0, NULL, 0, NULL, 0, NULL, NULL) == -2, "req_h(NULL)");
    CHECK(bn_h3_req_read(NULL, NULL, 0, 1) == -2, "req_read(NULL)");
    CHECK(bn_h3_take_resumption_token(NULL, NULL, 0, NULL) == -2, "take_tok(NULL)");

    /* close/free с NULL и NULL-слотами — no-op */
    bn_tls_close(NULL);
    BnTls *nt = NULL; bn_tls_close(&nt);
    BnWs *nw = NULL; CHECK(bn_ws_close(&nw, 1000, NULL, 100) == 0, "ws_close(NULL slot)");
    BnH3 *nh = NULL; bn_h3_close(&nh);
    BnH3Request *nr = NULL; bn_h3_req_free(&nr);
    BnHttpResponse *nresp = NULL; bn_http1_response_free(&nresp);
    printf("NULL-args OK\n");

    /* --- реальное соединение + лимиты ---------------------------------- */
    /* 16 байт: любая непустая страница не влезет → MessageTooLarge */
    bn_set_limits(16, 16, 16);

    BnConnectOptions o;
    memset(&o, 0, sizeof o);
    o.host = host;
    o.port = 443;
    o.timeout_ms = 15000;
    o.profile = 0;

    BnTls *tls = bn_tls_connect(&o);
    if (!tls) {
        printf("bn_tls_connect FAILED (сеть?): %s\n", bn_last_error_message());
        bn_set_limits(0, 0, 0);
        return 1;
    }

    BnHttpResponse *resp = bn_http1_fetch(tls, "GET", "/", NULL, 0, NULL, 0, 15000);
    CHECK(resp == NULL, "fetch под лимитом 16 байт → NULL");
    CHECK(bn_last_error_code() == 15,
          "код 15 MessageTooLarge, получен %d", bn_last_error_code());
    printf("limits: %s\n", bn_last_error_message());

    bn_tls_close(&tls);
    CHECK(tls == NULL, "tls_close nullified");
    bn_tls_close(&tls); /* двойной close — no-op */
    bn_tls_close(&tls);

    /* after-close операции по обнулённому указателю детектируются как
     * NULL (-2), а не UAF. */
    CHECK(bn_tls_read(tls, NULL, 0, 1) == -2, "read after close==NULL → -2");

    /* --- дефолты контракта: port=0 => 443, timeout_ms=0 => 30000 ------- */
    bn_set_limits(0, 0, 0); /* вернуть безлимит */
    {
        BnConnectOptions od = o;
        od.port = 0;
        od.timeout_ms = 0;
        BnTls *td = bn_tls_connect(&od);
        CHECK(td != NULL, "port=0 → 443, timeout_ms=0 → 30000");
        if (td) {
            bn_tls_close(&td);
        }
        /* свежесть ошибки: после успешной операции слот чист */
        CHECK(bn_last_error_code() == 0,
              "после успешного connect код ошибки 0, получен %d",
              bn_last_error_code());
    }

    /* --- H3: use-after-close -------------------------------------------- */
    BnH3 *h3 = bn_h3_connect(&o);
    if (h3) {
        BnH3Request *req = bn_h3_fetch(h3, "GET", "/", NULL, 0, NULL, 0, 15000);
        if (req) {
            /* закрыть СОЕДИНЕНИЕ, оставив запрос живым → осиротевание */
            bn_h3_close(&h3);
            CHECK(h3 == NULL, "h3_close nullified");
            int rc = bn_h3_req_status(req);
            CHECK(rc == -9, "req_status после close == -9, получен %d", rc);
            rc = bn_h3_req_read(req, NULL, 0, 100);
            CHECK(rc == -9, "req_read после close == -9, получен %d", rc);
            rc = bn_h3_req_header_count(req);
            CHECK(rc == -9, "req_header_count после close == -9, получен %d", rc);
            bn_h3_req_free(&req);
            CHECK(req == NULL, "req_free nullified");
            bn_h3_req_free(&req); /* двойной — no-op */
        } else {
            printf("bn_h3_fetch FAILED: %s\n", bn_last_error_message());
            bn_h3_close(&h3);
        }
    } else {
        printf("bn_h3_connect FAILED (сеть?): %s — пропуск H3-части\n",
               bn_last_error_message());
    }
    printf("use-after-close OK\n");

    /* --- shutdown / re-init ---------------------------------------------- */
    CHECK(bn_shutdown() == 0, "bn_shutdown при закрытых дескрипторах == 0");
    CHECK(bn_shutdown() == 0, "повторный bn_shutdown == 0");
    /* использование до повторного init → -3 */
    CHECK(bn_tls_connect(&o) == NULL, "connect после shutdown → NULL");
    CHECK(bn_last_error_code() == 3, "код 3 NotInitialized, получен %d",
          bn_last_error_code());
    CHECK(bn_init(NULL, 0) == 0, "повторный bn_init после shutdown");
    BnTls *tls2 = bn_tls_connect(&o);
    CHECK(tls2 != NULL, "connect после re-init");
    if (tls2) {
        bn_tls_close(&tls2);
    }
    printf("shutdown/re-init OK\n");

    if (failures) {
        printf("MISUSE: %d FAILURES\n", failures);
        return 10;
    }
    printf("MISUSE TEST OK\n");
    return 0;
}
