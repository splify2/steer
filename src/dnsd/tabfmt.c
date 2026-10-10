/* Формат таблицы доменных каналов — см. шапку tabfmt.h.
 *
 * Файл НЕ включает proxy.c и ничего из него не зовёт: демону, которому нужна только сборка
 * таблицы (steerd, docs/architecture.md, раздел 4а), незачем линковать epoll резолвера, сеть
 * и fake-IP ради двух функций ниже — table.c (dch_build) и этот файл собираются отдельно от
 * DNSD_SRC переменной DNSD_TABLE_SRC (build/sources.mk). */
#include "dnsd_int.h"
#include "tabfmt.h"
#include <errno.h>

/* ---- сборка: демон и `steer dnsd-table --spec` ------------------------------------------- */

static void join_list(FILE *out, const char (*v)[46], size_t n) {
    if (!n) { fputc('-', out); return; }
    for (size_t i = 0; i < n; i++) fprintf(out, "%s%s", i ? "," : "", v[i]);
}

void tabfmt_build(const struct spec *sp, FILE *out) {
    dch_build(sp);
    /* Без апстримов и кэша таблица остаётся такой, какой была до 1.11, — байт в байт: заголовок
     * «N», без строк апстримов. Иначе заголовок «N U кэш min max neg» и U строк после каналов. */
    int ext = g_dup_cfg_n || g_dcache_cfg.entries;
    if (!ext)
        fprintf(out, "%zu\n", g_dch_n);
    else
        fprintf(out, "%zu %zu %ld %ld %ld %ld", g_dch_n, g_dup_cfg_n, g_dcache_cfg.entries,
                g_dcache_cfg.ttl_min, g_dcache_cfg.ttl_max, g_dcache_cfg.ttl_neg);
    /* Сервер имён вне правил (`dns.other`) — седьмым числом, только когда он задан: без него
     * заголовок прежний до байта. */
    if (ext && g_dup_other) fprintf(out, " %u", g_dup_other);
    if (ext) fputc('\n', out);
    for (size_t i = 0; i < g_dch_n; i++) {
        const struct dchan *c = &g_dch[i];
        /* family — по факту (1.9, IPv6): «46», когда у доменной группы есть половина IPv6
         * (dom6_ok — парный набор «<set>6» и v6-двойник у компилятора) и спека не v1, иначе
         * «4» (решает dch_fam, table.c). */
        fprintf(out, "%s|%s|%d|%s|%s", c->set, c->out, c->realip ? 1 : 0,
                (c->fam & DCH_V6) ? ((c->fam & DCH_V4) ? "46" : "6") : "4", c->chan);
        for (size_t k = 0; k < c->rules_n; k++)
            fprintf(out, "|%s", c->rules_path[k]);
        if (c->up) fprintf(out, "|dns:%d", c->up);
        fputc('\n', out);
    }
    /* Апстрим: имя|адрес|выход|метка|адреса сервера|серверы bootstrap[|frag]. «-» — пусто;
     * frag — `fragment: true` (ClientHello двумя записями TLS), поля нет — выключено. */
    for (size_t i = 0; i < g_dup_cfg_n; i++) {
        const struct dup_cfg *u = &g_dup_cfg[i];
        if (u->grp) {
            /* Группа: «имя|group:race|-|0|члены|-» — члены номерами строк апстримов с единицы. */
            fprintf(out, "%s|group:%s|-|0|", u->u.name, u->grp == DNSG_RACE ? "race" : "failover");
            for (size_t k = 0; k < u->gm_n; k++) fprintf(out, "%s%u", k ? "," : "", u->gm[k] + 1);
            fputs("|-\n", out);
            continue;
        }
        fprintf(out, "%s|%s|%s|%u|", u->u.name, u->u.url, u->via[0] ? u->via : "-", u->mark);
        join_list(out, u->u.ips, u->u.ips_n);
        fputc('|', out);
        join_list(out, u->u.boot, u->u.boot_n);
        if (u->u.frag) fputs("|frag", out);        /* седьмое поле — только когда оно есть */
        fputc('\n', out);
    }
}

/* ---- разбор: резолвер (--table-fd) --------------------------------------------------------- */

/* Освободить всё, чем СЕЙЧАС владеет g_dch: набор правил (загружает reload_rules, proxy.c,
 * не эта функция) и пути его файлов, которые в режиме --table-fd всегда strdup'нуты прежним
 * вызовом tabfmt_parse (первым — нечего освобождать, g_dch тогда ещё в нулях BSS, free(NULL)
 * от этого не портится). */
static void tabfmt_release_current(void) {
    for (size_t i = 0; i < g_dch_n; i++) {
        ruleset_free(&g_dch[i].rules);
        dch_parts_free(g_dch[i].parts, g_dch[i].parts_n);
        for (size_t k = 0; k < g_dch[i].rules_n; k++)
            free((char *)g_dch[i].rules_path[k]);
        free(g_dch[i].rules_path);
    }
    if (g_dch) memset(g_dch, 0, g_dch_n * sizeof(*g_dch));
    g_dch_n = 0;
}

/* Индекс первого '\n' в buf[from, len), или len — «не нашли» (len сам никогда не индекс
 * настоящего байта таблицы, поэтому сравнение результата с len у вызывающих однозначно). */
static size_t find_nl(const char *buf, size_t len, size_t from) {
    for (size_t i = from; i < len; i++)
        if (buf[i] == '\n') return i;
    return len;
}

/* Скопировать поле дли ины flen в dst[dcap] с усечением — то же truncate-по-построению, что и
 * dch_build (snprintf "%.31s" и соседи, table.c): поле от испорченной строки длиннее буфера
 * усекается, а не переполняет его. */
static void field_copy(char *dst, size_t dcap, const char *src, size_t flen) {
    if (flen >= dcap) flen = dcap - 1;
    memcpy(dst, src, flen);
    dst[flen] = '\0';
}

/* Разобрать одну строку канала buf[from, line_end) (без завершающего '\n') в *c и в family
 * (family_cap байт, включая '\0'). Возвращает 0 при успехе, -1 — меньше пяти полей
 * (set|out|realip|family|chan обязательны, путей может не быть вовсе). */
static int parse_chan_line(const char *buf, size_t from, size_t line_end, struct dchan *c,
                            char *family, size_t family_cap) {
    memset(c, 0, sizeof(*c));
    if (family_cap) family[0] = '\0';
    size_t pos = from;
    int field = 0;
    while (pos <= line_end) {
        size_t fend = pos;
        while (fend < line_end && buf[fend] != '|') fend++;
        size_t flen = fend - pos;
        switch (field) {
            case 0: field_copy(c->set, sizeof(c->set), buf + pos, flen); break;
            case 1: field_copy(c->out, sizeof(c->out), buf + pos, flen); break;
            case 2: {
                char digit[8];
                field_copy(digit, sizeof(digit), buf + pos, flen);
                c->realip = atoi(digit) != 0;
                break;
            }
            case 3: field_copy(family, family_cap, buf + pos, flen); break;
            case 4: field_copy(c->chan, sizeof(c->chan), buf + pos, flen); break;
            default:
                /* Поле «dns:N» — апстрим канала (1.11); остальное — пути списков. */
                if (flen > 4 && !memcmp(buf + pos, "dns:", 4)) {
                    char num[8];
                    field_copy(num, sizeof(num), buf + pos + 4, flen - 4);
                    c->up = atoi(num);
                    break;
                }
                {
                    /* Путей у канала — сколько прислал демон (раньше — не больше 64, остальные
                     * молча отбрасывались). */
                    char *p = malloc(flen + 1);
                    if (!p) return -1;
                    memcpy(p, buf + pos, flen);
                    p[flen] = '\0';
                    if (c->rules_n == c->rules_cap) {
                        size_t nc = c->rules_cap ? c->rules_cap * 2 : 8;
                        const char **np = realloc(c->rules_path, nc * sizeof(*np));
                        if (!np) { free(p); return -1; }
                        c->rules_path = np;
                        c->rules_cap = nc;
                    }
                    c->rules_path[c->rules_n++] = p;
                }
                break;
        }
        field++;
        if (fend >= line_end) break;
        pos = fend + 1;
    }
    return field >= 5 ? 0 : -1;
}

/* Первая строка: «N» (до 1.11) или «N U кэш min max neg [other]». */
static int parse_header(const char *buf, size_t nl, long *want, long *upn, struct dcache_cfg *cc,
                        long *other) {
    char h[96];
    field_copy(h, sizeof(h), buf, nl);
    char *end = NULL;
    long n = strtol(h, &end, 10);
    *upn = 0;
    *other = 0;
    memset(cc, 0, sizeof(*cc));
    if (end == h || n < 0) return -1;       /* число каналов ничем, кроме памяти, не ограничено */
    *want = n;
    if (*end == '\0') return 0;
    if (*end != ' ') return -1;
    long u, e, mn, mx, ng, ot = 0;
    int used = 0, used2 = 0;
    if (sscanf(end + 1, "%ld %ld %ld %ld %ld%n", &u, &e, &mn, &mx, &ng, &used) != 5) return -1;
    if (end[1 + used] == ' ') {
        if (sscanf(end + 1 + used, " %ld%n", &ot, &used2) != 1 || end[1 + used + used2] != '\0' ||
            ot < 0 || ot > u)
            return -1;
    } else if (end[1 + used] != '\0') {
        return -1;
    }
    if (u < 0 || e < 0 || e > 1000000 || mn < 0 || mx < 0 || ng < 0) return -1;
    *upn = u;
    *other = ot;
    cc->entries = e; cc->ttl_min = mn; cc->ttl_max = mx; cc->ttl_neg = ng;
    return 0;
}

/* Разбить строку по '|' на поля (до max); возвращает их число. */
static size_t split_fields(const char *buf, size_t from, size_t end, size_t (*f)[2], size_t max) {
    size_t n = 0, pos = from;
    while (n < max) {
        size_t e = pos;
        while (e < end && buf[e] != '|') e++;
        f[n][0] = pos; f[n][1] = e - pos;
        n++;
        if (e >= end) break;
        pos = e + 1;
    }
    return n;
}

/* Список адресов через запятую — в кучу по числу записей (раньше — не больше четырёх). */
static int list_into(const char *s, size_t n, char (**dst)[46], size_t *cnt) {
    *cnt = 0;
    *dst = NULL;
    if (n == 1 && s[0] == '-') return 0;
    size_t items = 1;
    for (size_t i = 0; i < n; i++) items += s[i] == ',';
    char (*a)[46] = calloc(items, sizeof(*a));
    if (!a) return -1;
    size_t pos = 0;
    while (pos <= n) {
        size_t e = pos;
        while (e < n && s[e] != ',') e++;
        if (e > pos && *cnt < items) {
            field_copy(a[*cnt], 46, s + pos, e - pos);
            (*cnt)++;
        }
        pos = e + 1;
    }
    if (*cnt) *dst = a; else free(a);
    return 0;
}

/* Строка апстрима «имя|адрес|выход|метка|адреса|bootstrap». Адрес, который не разбирается (таблицу
 * прислал демон другой версии), не роняет резолвер: апстрим остаётся с proto == DNSP_NONE и не
 * используется, а каналы на него отвечают прежним путём наверх. */
static int parse_up_line(const char *buf, size_t from, size_t end, struct dup_cfg *c) {
    size_t f[7][2];
    size_t nf = split_fields(buf, from, end, f, 7);
    if (nf != 6 && nf != 7) return -1;
    memset(c, 0, sizeof(*c));
    field_copy(c->u.name, sizeof(c->u.name), buf + f[0][0], f[0][1]);
    field_copy(c->u.url, sizeof(c->u.url), buf + f[1][0], f[1][1]);
    c->own = 1;
    if (!strncmp(c->u.url, "group:", 6)) {
        /* Группа: члены — номера строк апстримов с единицы через запятую; проверяются, когда
         * разобраны все строки (tabfmt_parse). Режим, которого этот резолвер не знает, — группа
         * без членов: каналы на неё получают отказ, а не чужой ответ. */
        const char *m = buf + f[4][0];
        size_t mlen = f[4][1], items = 1;
        for (size_t i = 0; i < mlen; i++) items += m[i] == ',';
        c->grp = !strcmp(c->u.url + 6, "race") ? DNSG_RACE
               : !strcmp(c->u.url + 6, "failover") ? DNSG_FAILOVER : 0;
        if (!c->grp) { c->u.url[0] = '\0'; return 0; }
        c->gm = calloc(items, sizeof(*c->gm));
        if (!c->gm) return -1;
        for (size_t pos = 0; pos < mlen;) {
            size_t e = pos;
            while (e < mlen && m[e] != ',') e++;
            char num[16];
            field_copy(num, sizeof(num), m + pos, e - pos);
            long v = strtol(num, NULL, 10);
            if (v > 0) c->gm[c->gm_n++] = (unsigned)(v - 1);
            pos = e + 1;
        }
        return 0;
    }
    if (!(f[2][1] == 1 && buf[f[2][0]] == '-')) {
        field_copy(c->via, sizeof(c->via), buf + f[2][0], f[2][1]);
        c->need_mark = 1;
    }
    char num[16];
    field_copy(num, sizeof(num), buf + f[3][0], f[3][1]);
    c->mark = (unsigned)strtoul(num, NULL, 10);
    c->u.frag = nf == 7 && f[6][1] == 4 && !strncmp(buf + f[6][0], "frag", 4);
    /* own = 1 (выше): массивы адресов ниже — куча этой записи (dup_cfg_list_reset) */
    if (list_into(buf + f[4][0], f[4][1], &c->u.ips, &c->u.ips_n) != 0 ||
        list_into(buf + f[5][0], f[5][1], &c->u.boot, &c->u.boot_n) != 0) {
        free(c->u.ips);
        free(c->u.boot);
        c->u.ips = c->u.boot = NULL;
        c->u.ips_n = c->u.boot_n = 0;
        return -1;
    }
    char why[96];
    struct spec_dns_up p;
    memset(&p, 0, sizeof(p));
    if (dnsurl_parse(c->u.url, &p, why, sizeof(why)) == 0) {
        c->u.proto = p.proto;
        c->u.port = p.port;
        snprintf(c->u.host, sizeof(c->u.host), "%s", p.host);
        snprintf(c->u.path, sizeof(c->u.path), "%s", p.path);
    }
    return 0;
}

int tabfmt_parse(const char *buf, size_t len) {
    size_t nl = find_nl(buf, len, 0);
    if (nl >= len) return -1; /* нет даже строки-счётчика */
    long want, upn, other;
    struct dcache_cfg cc;
    if (parse_header(buf, nl, &want, &upn, &cc, &other) != 0) return -1;

    tabfmt_release_current();
    dup_cfg_list_reset();
    g_dcache_cfg = cc;

    size_t out_n = 0;
    size_t pos = nl + 1;
    for (long i = 0; i < want; i++) {
        size_t line_end = find_nl(buf, len, pos);
        if (line_end >= len) return -1; /* обещали want строк, а текст кончился раньше */
        struct dchan tmp;
        char family[8];
        if (parse_chan_line(buf, pos, line_end, &tmp, family, sizeof(family)) != 0) return -1;
        /* family — «4», «6» или «46» (1.9, IPv6): DCH_V6 — у канала есть парный набор «<set>6»,
         * и на AAAA его имён резолвер отвечает адресом (fake-IP v6 или настоящим) вместо
         * пустого ответа. Канал «6» (без IPv4) принимается так же: A его имён он не забирает
         * (proxy.c, match_for). */
        int has4 = !strcmp(family, "4") || !strcmp(family, "46");
        int has6 = !strcmp(family, "6") || !strcmp(family, "46");
        if (!has4 && !has6) return -1; /* не «4», не «6», не «46» — испорченный текст */
        tmp.fam = (has4 ? DCH_V4 : 0) | (has6 ? DCH_V6 : 0);
        struct dchan *nd = dch_new();
        if (!nd) return -1;
        *nd = tmp;
        g_dch_n = ++out_n;
        pos = line_end + 1;
    }
    g_dch_n = out_n;
    for (long i = 0; i < upn; i++) {
        size_t line_end = find_nl(buf, len, pos);
        if (line_end >= len) return -1;
        if (g_dup_cfg_n == g_dup_cfg_cap) {
            size_t nc = g_dup_cfg_cap ? g_dup_cfg_cap * 2 : 8;
            struct dup_cfg *np = realloc(g_dup_cfg, nc * sizeof(*np));
            if (!np) return -1;
            g_dup_cfg = np;
            g_dup_cfg_cap = nc;
        }
        if (parse_up_line(buf, pos, line_end, &g_dup_cfg[g_dup_cfg_n]) != 0) return -1;
        g_dup_cfg_n++;
        pos = line_end + 1;
    }
    /* Канал, чей апстрим в таблице не назван, спрашивает прежним путём. */
    for (size_t i = 0; i < g_dch_n; i++)
        if (g_dch[i].up < 0 || (size_t)g_dch[i].up > g_dup_cfg_n) g_dch[i].up = 0;
    /* Член группы — сервер этой же таблицы, не группа: иначе он из группы выпадает. */
    for (size_t i = 0; i < g_dup_cfg_n; i++) {
        struct dup_cfg *c = &g_dup_cfg[i];
        size_t k = 0;
        for (size_t j = 0; j < c->gm_n; j++)
            if (c->gm[j] < g_dup_cfg_n && c->gm[j] != i && !g_dup_cfg[c->gm[j]].grp) c->gm[k++] = c->gm[j];
        c->gm_n = k;
    }
    g_dup_other = (unsigned)other;
    return 0;
}

/* ---- приёмник из трубы: буферизация между вызовами epoll ---------------------------------- */

int tabfmt_feed(struct tabfmt_feed *st, const char *data, size_t n) {
    if (n) {
        if (st->len + n > TABFMT_FEED_MAX) return -1;
        if (st->len + n > st->cap) {
            size_t nc = st->cap ? st->cap : 16384;
            while (nc < st->len + n) nc *= 2;
            char *nb = realloc(st->buf, nc);
            if (!nb) return -1;
            st->buf = nb;
            st->cap = nc;
        }
        memcpy(st->buf + st->len, data, n);
        st->len += n;
    }

    size_t nl = find_nl(st->buf, st->len, 0);
    if (nl >= st->len) return 0; /* строка-счётчик ещё не дописана */
    long want, upn, other;
    struct dcache_cfg cc;
    if (parse_header(st->buf, nl, &want, &upn, &cc, &other) != 0) return -1;
    want += upn;                 /* строки каналов и строки апстримов идут подряд */

    size_t pos = nl + 1;
    for (long i = 0; i < want; i++) {
        size_t line_end = find_nl(st->buf, st->len, pos);
        if (line_end >= st->len) return 0; /* строк пока меньше, чем обещал счётчик */
        pos = line_end + 1;
    }
    /* pos — конец РОВНО ОДНОЙ таблицы: столько и передаётся в tabfmt_parse, остаток (начало
     * следующей, если демон прислал две таблицы одной записью в трубу) остаётся в буфере. */
    if (tabfmt_parse(st->buf, pos) != 0) return -1;
    memmove(st->buf, st->buf + pos, st->len - pos);
    st->len -= pos;
    return 1;
}

int tabfmt_read_first(int fd, struct tabfmt_feed *st) {
    /* st — буфер вызывающего (в run_proxy это то же состояние, которым потом кормит труба через
     * epoll): переполнение первой блокирующей записи демона второй таблицей — редкость, но
     * оставлять её хвост здесь и не отдать вызывающему значило бы потерять байты, уже прочитанные
     * с fd. Поэтому состояние ровно одно на весь процесс, а не своё у каждого вызова. */
    for (;;) {
        char chunk[4096];
        ssize_t r = read(fd, chunk, sizeof(chunk));
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1; /* труба закрылась раньше первой таблицы — демон умер */
        int rc = tabfmt_feed(st, chunk, (size_t)r);
        if (rc < 0) return -1;
        if (rc > 0) return 0; /* первая таблица разобрана; хвост (если демон прислал вторую
                                * следом же записью) остался в st — его доберёт та же tabfmt_feed
                                * из цикла epoll, без потери байт */
    }
}
