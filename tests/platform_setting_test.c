/* Регрессия многократного чтения снимка platform.env в одном процессе. */
#include "platform.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void expect(const char *name, const char *value) {
    const char *s = plat_setting(name);
    assert(s && !strcmp(s, value));
}
int main(int argc, char **argv) {
    assert(argc == 3);
    assert(!setenv("STEER_PLUGIN_ETC", argv[1], 1));
    const char *names[] = {"STEER_MARK_FIELD", "STEER_RULE_PREF", "STEER_ROUTER_SELF",
                           "STEER_MARK_RESTORE", "PLAT_EMPTY", "PLAT_DUP", "PLAT_LAST"};
    const char *values[] = {"0x000000ff", "100", "1", "1", "", "first", "tail"};
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) assert(!unsetenv(names[i]));
    const char *saved = plat_setting(argv[2][0] == 'r' ? "PLAT_LAST" : "STEER_MARK_FIELD");
    assert(saved);
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        size_t j = argv[2][0] == 'r' ? sizeof names / sizeof names[0] - i - 1 : i;
        expect(names[j], values[j]);
    }
    assert(!plat_setting("MISSING") && !plat_setting("PLAT"));
    assert(!strcmp(saved, argv[2][0] == 'r' ? "tail" : "0x000000ff"));
    assert(saved == plat_setting(argv[2][0] == 'r' ? "PLAT_LAST" : "STEER_MARK_FIELD"));
    assert(!setenv("STEER_RULE_PREF", "", 1)); expect("STEER_RULE_PREF", "");
    assert(!setenv("STEER_RULE_PREF", "777", 1)); expect("STEER_RULE_PREF", "777");
    assert(!unsetenv("STEER_RULE_PREF")); expect("STEER_RULE_PREF", "100");
    char path[1024];snprintf(path, sizeof path, "%s/platform.env", argv[1]);
    FILE *f = fopen(path, "w");assert(f);assert(fputs("PLAT_LAST=changed\n", f) >= 0);assert(!fclose(f));
    expect("PLAT_LAST", "tail");expect("STEER_RULE_PREF", "100");
    assert(!strcmp(saved, argv[2][0] == 'r' ? "tail" : "0x000000ff"));
    assert(!plat_select("openwrt"));
    const struct platform_ops *p = plat();
    assert(p->mark_base == 1 && p->mark_bits == 8 && p->mark_mask == 0xff);
    assert(p->rule_pref == 100 && p->local_channels == 1 && p->local_dns == 0 && p->self_mark == 0xff);
    puts("platform settings: PASS");
    return 0;
}
