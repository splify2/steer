/* Разбор и освобождение частичных ответов, включая ошибки выделения памяти. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ctlcall.h"

void *__real_malloc(size_t);
void *__real_realloc(void *, size_t);
char *__real_strndup(const char *, size_t);
static long fail_at = -1, calls;
static int fail(void) { return fail_at >= 0 && calls++ == fail_at; }
void *__wrap_malloc(size_t n) { return fail() ? NULL : __real_malloc(n); }
void *__wrap_realloc(void *p, size_t n) { return fail() ? NULL : __real_realloc(p, n); }
char *__wrap_strndup(const char *p, size_t n) { return fail() ? NULL : __real_strndup(p, n); }

static void check(const char *s, int ok, int code) {
    struct ctlcall_resp r;
    int rc = ctlcall_parse(s, &r);
    if ((rc == 0) != ok || (ok && code >= 0 && (!r.has_code || r.code != code))) {
        fprintf(stderr, "unexpected parse result: %s\n", s); exit(1);
    }
    ctlcall_resp_free(&r);
}
int main(void) {
    const char *fields[] = {"stdout", "stderr", "error", "message", "spec_path", "state_dir", "ecode"};
    char input[256];
    for (size_t i = 0; i < sizeof(fields)/sizeof(fields[0]); i++) {
        snprintf(input, sizeof(input), "{\"%s\":\"first\",\"%s\":\"broken\\u12\"}", fields[i], fields[i]);
        check(input, 0, -1);
    }
    check("{\"stdout\":\"ok\",\"args\":{},\"args\":{", 0, -1);
    check("{\"code\":4294967296}", 0, -1);
    check("{\"code\":999999999999999999999999999999}", 0, -1);
    check("{\"code\":256}", 0, -1);
    check("{\"code\":-1}", 0, -1);
    check("{\"code\":0.5}", 0, -1);
    check("{\"code\":1e2}", 0, -1);
    check("{\"code\":0,\"code\":\"ctl.busy\"}", 0, -1);
    check("{\"code\":00}", 0, -1);
    check("{\"code\":0}", 1, 0);
    check("{\"code\":255}", 1, 255);
    check("{\"error\":\"busy\",\"code\":\"ctl.busy\"}", 1, -1);
    const char *valid = "{\"stdout\":\"first\",\"stdout\":\"second string longer than sixty-four bytes so the buffer will need to grow during parsing\","
                        "\"args\":{},\"args\":{\"x\":1},\"code\":0}";
    for (long n = 0; n < 40; n++) {
        struct ctlcall_resp r;
        calls = 0; fail_at = n;
        int rc = ctlcall_parse(valid, &r);
        fail_at = -1;
        if (rc == 0 && n < calls) { fprintf(stderr, "allocation failure ignored at %ld\n", n); return 1; }
        ctlcall_resp_free(&r);
    }
    puts("ctlcall parse cleanup: OK");
    return 0;
}
