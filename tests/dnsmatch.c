/* Подбор доменного правила: проверка семантики, а не скорости.
 *
 * Зачем отдельным тестом. Подбор переписан с перебора на индекс по суффиксам имени, и это
 * ровно тот случай, когда ошибка не видна снаружи: канал просто перестаёт совпадать, трафик
 * идёт открытым путём, и в логе ничего нет. «Работает» и «правильно» здесь расходятся молча,
 * поэтому проверяются граничные случаи, а не пара примеров:
 *
 *   - доменное правило совпадает с самим именем и с поддоменами, но НЕ с чужим именем,
 *     которое лишь заканчивается теми же буквами (notyoutube.com против youtube.com);
 *   - точное правило совпадает только с самим именем;
 *   - совпадение на границе точки, а не по символам: «ube.com» не совпадает с «youtube.com»;
 *   - шаблоны и регулярные выражения работают по-прежнему — они по суффиксу не находятся и
 *     идут отдельным перебором;
 *   - одно и то же имя, заданное и точным, и доменным правилом, работает как доменное: в
 *     индексе это один ключ с двумя метками, и потеря метки была бы невидима.
 *
 * Резолвер (DNSD_SRC) линкуется отдельным объектом (Makefile, docs/architecture.md, раздел
 * 4): подбор — публичная функция резолвера (ruleset_match, dnsd_int.h), а таблица ожиданий
 * (struct pending и соседи, проверяемая ниже отдельно) — единственный кусок, у которого
 * "static" снят ради этого стенда, тоже в dnsd_int.h. */
#include "dnsd_int.h"
#include "nftnl.h"
#include "tabfmt.h"
#include "srsplan.h"
#include <sys/stat.h>

static int fails;

/* Подмена strdup: ruleset_add обязан пережить отказ выделения (раньше str_lower(NULL) валил резолвер).
 * Тест линкуется с кодом резолвера одним объектом, так что наш strdup перекрывает libc. */
static int g_strdup_fail;
char *strdup(const char *s) {
    if (g_strdup_fail) return NULL;
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static void check(const char *what, int want, int got) {
    printf("%-58s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want != got) fails++;
}

/* Таблица каналов стенда — на n мест, обнулённая (g_dch теперь куча, а не массив на 64). */
static void dch_zero(size_t n) {
    if (g_dch_cap < n) {
        struct dchan *p = realloc(g_dch, n * sizeof(*p));
        if (!p) { perror("realloc"); exit(2); }
        g_dch = p;
        g_dch_cap = n;
    }
    memset(g_dch, 0, g_dch_cap * sizeof(*g_dch));
    g_dch_n = 0;
}

/* Набор каналов из двух номеров (chm_t — номер записи в таблице наборов, а не битовая маска). */
static chm_t chm2(size_t a, size_t b) { return chm_or(chm_one(a), chm_one(b)); }

static void check_str(const char *what, const char *want, const char *got) {
    int ok = strcmp(want, got) == 0;
    printf("%-58s %s\n", what, ok ? "ok" : "ПРОВАЛ");
    if (!ok) { fails++; printf("     хочу: %s\n     есть: %s\n", want, got); }
}

/* Набор из строк списка — в том же виде, в каком их читает load_rules_into. */
static void build(struct ruleset *rs, const char *const *lines) {
    memset(rs, 0, sizeof(*rs));
    for (size_t i = 0; lines[i]; i++) {
        char buf[512];
        snprintf(buf, sizeof(buf), "%s", lines[i]);
        ruleset_add(rs, buf);
    }
}

/* Живые соединения для стенда пула fake-IP: адреса из списка (n < 0 — «узнать нельзя»). */
static uint32_t *g_pool_live_addr;
static int g_pool_live_n;
static int pool_live_stub(uint8_t *bits) {
    if (g_pool_live_n < 0) return -1;
    for (int i = 0; i < g_pool_live_n; i++) {
        uint32_t ix = g_pool_live_addr[i] - FAKEIP_POOL_BASE;
        bits[ix >> 3] |= (uint8_t)(1u << (ix & 7));
    }
    return 0;
}

int main(void) {
    {
        struct ruleset rs;
        memset(&rs, 0, sizeof(rs));
        static const char *const raw[] = { "example.com", "=exact.example", "*.wild.example", "re:^a$" };
        g_strdup_fail = 1;
        for (size_t i = 0; i < sizeof(raw) / sizeof(*raw); i++)
            check(raw[i], -1, ruleset_add(&rs, raw[i]));
        g_strdup_fail = 0;
        check("ruleset_add при отказе strdup: набор пуст", 0, (int)rs.n);
        ruleset_free(&rs);
    }
    /* Ответы проб ядра заданы явно, без `nft -c`: стенд не должен зависеть от машины. */
    setenv("STEER_NFT_INGRESS", "1", 1);
    setenv("STEER_NFT_CONCAT", "1", 1);
    {
        static const char *const lines[] = { "youtube.com", "=exact.example", NULL };
        struct ruleset rs;
        build(&rs, lines);

        check("доменное: само имя", 1, ruleset_match(&rs, "youtube.com"));
        check("доменное: поддомен", 1, ruleset_match(&rs, "www.youtube.com"));
        check("доменное: глубокий поддомен", 1, ruleset_match(&rs, "a.b.c.youtube.com"));
        check("доменное: РЕГИСТР не важен", 1, ruleset_match(&rs, "WWW.YouTube.COM"));
        check("доменное: чужое имя с тем же хвостом", 0, ruleset_match(&rs, "notyoutube.com"));
        check("доменное: совпадение только по границе точки", 0, ruleset_match(&rs, "ube.com"));
        check("доменное: другой домен", 0, ruleset_match(&rs, "example.org"));
        check("доменное: имя короче шаблона", 0, ruleset_match(&rs, "com"));

        check("точное: само имя", 1, ruleset_match(&rs, "exact.example"));
        check("точное: поддомен НЕ совпадает", 0, ruleset_match(&rs, "www.exact.example"));

        ruleset_free(&rs);
    }
    {
        /* Правило в записи FQDN, с завершающей точкой. Имя вопроса из пакета собирается без
         * неё, и `foo.org.` не совпадало ни с чем — правило молча не действовало. */
        static const char *const lines[] = { "fqdn.example.", "=exactdot.example.",
                                             "*.wilddot.example.", ".", "*.", NULL };
        struct ruleset rs;
        build(&rs, lines);
        check("завершающая точка: доменное, само имя", 1, ruleset_match(&rs, "fqdn.example"));
        check("завершающая точка: доменное, поддомен", 1, ruleset_match(&rs, "www.fqdn.example"));
        check("завершающая точка: точное", 1, ruleset_match(&rs, "exactdot.example"));
        check("завершающая точка: шаблон", 1, ruleset_match(&rs, "a.wilddot.example"));
        check("`.` и `*.` — не правило «всё»", 0, ruleset_match(&rs, "other.test"));
        check("`.` и `*.` правилами не становятся", 3, (int)rs.n);
        ruleset_free(&rs);
    }
    {
        /* Одно имя двумя правилами: в индексе это один ключ, и метки обязаны сложиться. */
        static const char *const lines[] = { "=both.test", "both.test", NULL };
        struct ruleset rs;
        build(&rs, lines);
        check("точное и доменное на одном имени: само имя", 1, ruleset_match(&rs, "both.test"));
        check("точное и доменное на одном имени: поддомен", 1, ruleset_match(&rs, "x.both.test"));
        ruleset_free(&rs);
    }
    {
        static const char *const lines[] = { "*.cdn.example", "re:^ads[0-9]+\\.", NULL };
        struct ruleset rs;
        build(&rs, lines);
        check("шаблон: совпадает", 1, ruleset_match(&rs, "img.cdn.example"));
        check("шаблон: не совпадает", 0, ruleset_match(&rs, "cdn.example.org"));
        check("регулярное: совпадает", 1, ruleset_match(&rs, "ads12.example.com"));
        check("регулярное: не совпадает", 0, ruleset_match(&rs, "adsx.example.com"));
        ruleset_free(&rs);
    }
    {
        /* Много правил: проверяем, что индекс находит и первое, и последнее, и не находит
         * того, чего нет. Перерастание таблицы (256 слотов по умолчанию) здесь тоже
         * происходит — на нём ломается неверный перехэш. */
        struct ruleset rs;
        memset(&rs, 0, sizeof(rs));
        char buf[64];
        for (int i = 0; i < 5000; i++) {
            snprintf(buf, sizeof(buf), "d%d.example", i);
            ruleset_add(&rs, buf);
        }
        check("много правил: первое", 1, ruleset_match(&rs, "d0.example"));
        check("много правил: последнее", 1, ruleset_match(&rs, "d4999.example"));
        check("много правил: поддомен последнего", 1, ruleset_match(&rs, "w.d4999.example"));
        check("много правил: отсутствующее", 0, ruleset_match(&rs, "d5000.example"));
        ruleset_free(&rs);
    }
    {
        /* Таблица fake-IP на том же индексе: адрес обязан быть постоянным для домена и
         * разным для разных доменов. Совпадение адресов означало бы, что один домен уводит
         * трафик на сайт другого. */
        uint32_t a = 0, b = 0, again = 0;
        check("fake-IP: выдан", 0, fakeip_lookup_or_alloc("one.test", &a));
        check("fake-IP: другому домену другой", 0, fakeip_lookup_or_alloc("two.test", &b));
        check("fake-IP: адреса не совпадают", 1, a != b);
        check("fake-IP: повторный запрос — тот же адрес", 0,
              fakeip_lookup_or_alloc("one.test", &again));
        check("fake-IP: адрес постоянен", 1, again == a);
        fakeip_entry_set_real("one.test", 0x01020304u);
        check("fake-IP: реальный адрес запомнен", 1,
              fakeip_entry_get_real("one.test") == 0x01020304u);
        check("fake-IP: у другого домена своего нет", 1, fakeip_entry_get_real("two.test") == 0);
    }
    {
        /* Привязка поддельного адреса к настоящему (fakeip_real_pick). Сети доставки ротируют
         * ответы: два ответа подряд с непересекающимися адресами — обычное дело, и прежний адрес при
         * этом рабочий. Замена под именем, которым пользуются, уводила живые сеансы QUIC на другой
         * сервер. Пока имя спрашивают, привязка стоит; меняется она после долгого простоя имени
         * или когда прежний адрес давно не встречался в ответах. */
        uint32_t fa = 0;
        const uint32_t A = 0x9df000aeu, B = 0x3990f422u, C = 0x3990f423u;   /* 157.240.0.174, 57.144.244.34/35 */
        struct answer_ip ab[2] = { { htonl(B), 60 }, { htonl(A), 60 } };
        struct answer_ip ob[1] = { { htonl(B), 60 } }, oc[1] = { { htonl(C), 60 } };
        fakeip_lookup_or_alloc("bind.test", &fa);
        time_t t0 = time(NULL);
        check("привязка: первый ответ — первый адрес ответа", 1,
              fakeip_real_pick("bind.test", ob, 1, t0) == B);
        fakeip_entry_set_real("bind.test", A);
        struct fakeip_entry *e = &g_fakeip.entries[fakeip_find("bind.test")];
        check("привязка: прежний адрес среди ответов (не первым) — остаётся", 1,
              fakeip_real_pick("bind.test", ab, 2, t0 + 10) == A);
        fakeip_touch(e, t0 + 70);
        check("привязка: имя спрашивают, в ответе только другие адреса — остаётся прежний", 1,
              fakeip_real_pick("bind.test", ob, 1, t0 + 70) == A);
        fakeip_touch(e, t0 + 130);
        check("  и на следующий ответ с третьим адресом — тоже", 1,
              fakeip_real_pick("bind.test", oc, 1, t0 + 130) == A);
        int held = 1;
        for (time_t t = t0 + 190; t < t0 + 10 + FAKEIP_REAL_ABSENT_DEFAULT; t += 60) {
            fakeip_touch(e, t);
            if (fakeip_real_pick("bind.test", ob, 1, t) != A) held = 0;
        }
        check("  полчаса непрерывных вопросов без прежнего адреса в ответах — привязка стоит", 1, held);
        fakeip_touch(e, t0 + 10 + FAKEIP_REAL_ABSENT_DEFAULT);
        check("привязка: прежнего адреса нет в ответах полчаса — заменяется", 1,
              fakeip_real_pick("bind.test", ob, 1, t0 + 10 + FAKEIP_REAL_ABSENT_DEFAULT) == B);
        /* Замена состоялась (ядро приняло): отсчёт начинается заново с новым адресом. */
        fakeip_entry_set_real("bind.test", B);
        e->real_seen = t0 + 2000;
        fakeip_touch(e, t0 + 2000);
        fakeip_touch(e, t0 + 2000 + FAKEIP_REAL_IDLE_DEFAULT);       /* ровно срок — ещё не простой */
        check("привязка: вопрос через десять минут ровно — именем ещё пользуются", 1,
              fakeip_real_pick("bind.test", oc, 1, t0 + 2000 + FAKEIP_REAL_IDLE_DEFAULT) == B);
        time_t t1 = t0 + 2000 + 2 * FAKEIP_REAL_IDLE_DEFAULT + 1;    /* простой дольше срока */
        fakeip_touch(e, t1);
        check("привязка: имя спросили после долгого простоя — адрес берётся из ответа", 1,
              fakeip_real_pick("bind.test", oc, 1, t1) == C);
        fakeip_entry_set_real("bind.test", C);
        e->real_seen = t1;
        fakeip_touch(e, t1 + 5);
        check("  а следующий ответ с другим адресом привязку уже не трогает", 1,
              fakeip_real_pick("bind.test", ob, 1, t1 + 5) == C);
        check("привязка: время последнего вопроса отмечено", 1, e->last_used == t1 + 5);

        /* Половина IPv6 — то же правило, свои сроки и своя отметка «после простоя». */
        struct answer_ip6 a6[1], b6[1];
        memset(a6, 0, sizeof(a6)); memset(b6, 0, sizeof(b6));
        a6[0].addr[0] = 0x2a; a6[0].addr[15] = 1;
        b6[0].addr[0] = 0x2a; b6[0].addr[15] = 2;
        uint8_t got[16];
        fakeip_entry_set_real6("bind.test", a6[0].addr);
        e->real6_seen = t1;
        e->idle6 = 0;
        fakeip_touch(e, t1 + 10);
        fakeip_real_pick6("bind.test", b6, 1, t1 + 10, got);
        check("привязка v6: имя спрашивают — прежний адрес остаётся", 0, memcmp(got, a6[0].addr, 16));
        fakeip_touch(e, t1 + 10 + FAKEIP_REAL_IDLE_DEFAULT + 1);
        fakeip_real_pick("bind.test", ob, 1, t1 + 10 + FAKEIP_REAL_IDLE_DEFAULT + 1);   /* ответ A отметку v6 не снимает */
        fakeip_real_pick6("bind.test", b6, 1, t1 + 10 + FAKEIP_REAL_IDLE_DEFAULT + 1, got);
        check("привязка v6: после долгого простоя — адрес из ответа", 0, memcmp(got, b6[0].addr, 16));
    }
    {
        /* Пустой адрес в ответе апстрима (0.0.0.0, :: — так блокирует имя фильтрующий сервер) — не
         * адрес для подмены. Прежде имени выдавался поддельный адрес с подменой на 0.0.0.0, и клиент
         * висел на соединении «в никуда» вместо отказа сразу. */
        struct answer_ip z4[3] = { { 0, 60 }, { htonl(0x01020304u), 60 }, { 0, 60 } };
        check("пустой адрес: из ответа A убраны 0.0.0.0, настоящий остался", 1,
              answer_drop_empty4(z4, 3) == 1 && z4[0].addr == htonl(0x01020304u));
        struct answer_ip z0[2] = { { 0, 60 }, { 0, 10 } };
        check("пустой адрес: ответ из одних 0.0.0.0 — подменять нечего", 0, answer_drop_empty4(z0, 2));
        struct answer_ip6 z6[2];
        memset(z6, 0, sizeof(z6));
        z6[1].addr[15] = 1;
        check("пустой адрес: из ответа AAAA убран ::", 1, answer_drop_empty6(z6, 2) == 1 && z6[0].addr[15] == 1);
        memset(z6, 0, sizeof(z6));
        check("пустой адрес: ответ из одного :: — подменять нечего", 0, answer_drop_empty6(z6, 1));

        /* Запись прежней версии: поддельный адрес выдан, настоящего нет (0.0.0.0 в памяти — «не
         * знаем»). Первый же пустой ответ снимает её; соседние записи находятся по-прежнему. */
        uint32_t fa = 0, fb = 0, fc = 0, again = 0;
        fakeip_lookup_or_alloc("old-blocked.test", &fa);
        fakeip_lookup_or_alloc("neighbour.test", &fb);
        fakeip_entry_set_real("neighbour.test", 0x05060708u);
        size_t before = g_fakeip.n;
        fakeip_entry_blocked("old-blocked.test", 0);
        check("блок апстрима: запись без настоящего адреса снята", 1, fakeip_find("old-blocked.test") < 0);
        check("  в таблице на одну запись меньше", (long)before - 1, (long)g_fakeip.n);
        check("  сосед находится, адрес и подмена прежние", 1,
              fakeip_lookup_or_alloc("neighbour.test", &again) == 0 && again == fb &&
              fakeip_entry_get_real("neighbour.test") == 0x05060708u);
        check("  ранее выданные имена находятся", 1, fakeip_find("one.test") >= 0 && fakeip_find("bind.test") >= 0);
        fakeip_entry_blocked("never-seen.test", 0);
        check("блок апстрима: имя без записи — ничего не меняется", (long)before - 1, (long)g_fakeip.n);

        /* Имя с обеими половинами: пустой A снимает только половину IPv4 (на AAAA имя по-прежнему
         * отвечает подменой), пустой AAAA следом — запись целиком. */
        uint8_t r6[16] = { 0x2a, 0 };
        r6[15] = 9;
        fakeip_lookup_or_alloc("half.test", &fc);
        fakeip_entry_set_real("half.test", 0x0a0b0c0du);
        fakeip_entry_set_real6("half.test", r6);
        g_fakeip_dirty = 0;
        fakeip_entry_blocked("half.test", 0);
        check("блок апстрима: пустой A — настоящий IPv4 забыт", 0, (long)fakeip_entry_known_real("half.test"));
        check("  запись осталась: половина IPv6 жива", 1,
              fakeip_find("half.test") >= 0 && fakeip_entry_known_real6("half.test") != NULL);
        check("  файл состояния будет переписан", 1, g_fakeip_dirty);
        fakeip_entry_blocked("half.test", 1);
        check("блок апстрима: пустой AAAA следом — запись снята целиком", 1, fakeip_find("half.test") < 0);
    }
    {
        /* Подавление HTTPS (65) и SVCB (64) на совпавшем домене. Проверяется не
         * константа, а форма ответа: клиент должен получить NODATA — тот же вопрос,
         * ноль записей — и ни одной подсказки ipv4hint из настоящего ответа. Иначе
         * браузер идёт по реальному адресу мимо туннеля и ждёт таймаута, что и
         * выглядит как задержка на первом открытии сайта.
         *
         * Ответ собирается руками: заголовок, вопрос «www.test HTTPS IN», затем
         * запись с ipv4hint. build_rewritten_response обязан обрезать всё после
         * вопроса. */
        uint8_t resp[64];
        size_t n = 0;
        resp[n++] = 0x12; resp[n++] = 0x34;          /* id */
        resp[n++] = 0x81; resp[n++] = 0x80;          /* QR + RD + RA */
        resp[n++] = 0x00; resp[n++] = 0x01;          /* qdcount = 1 */
        resp[n++] = 0x00; resp[n++] = 0x01;          /* ancount = 1 */
        resp[n++] = 0x00; resp[n++] = 0x00;          /* nscount */
        resp[n++] = 0x00; resp[n++] = 0x00;          /* arcount */
        resp[n++] = 3; memcpy(resp + n, "www", 3);  n += 3;
        resp[n++] = 4; memcpy(resp + n, "test", 4); n += 4;
        resp[n++] = 0;                               /* конец имени */
        resp[n++] = 0x00; resp[n++] = DNS_TYPE_HTTPS;
        resp[n++] = 0x00; resp[n++] = 0x01;          /* class IN */
        size_t qend = n;
        resp[n++] = 0xC0; resp[n++] = 0x0C;          /* ответ: указатель на вопрос */
        resp[n++] = 0x00; resp[n++] = DNS_TYPE_HTTPS;
        resp[n++] = 0x00; resp[n++] = 0x01;
        resp[n++] = 0x00; resp[n++] = 0x00; resp[n++] = 0x00; resp[n++] = 0x3C;
        resp[n++] = 0x00; resp[n++] = 0x0B;          /* rdlength */
        resp[n++] = 0x00; resp[n++] = 0x01;          /* priority 1 */
        resp[n++] = 0x00;                            /* target = . */
        resp[n++] = 0x00; resp[n++] = 0x04;          /* key 4 = ipv4hint */
        resp[n++] = 0x00; resp[n++] = 0x04;
        resp[n++] = 1; resp[n++] = 2; resp[n++] = 3; resp[n++] = 4;

        uint8_t out[512];
        size_t len = build_rewritten_response(resp, qend, out, sizeof(out), 0, 0);
        check("HTTPS: ответ обрезан по конец вопроса", (int)qend, (int)len);
        check("HTTPS: ancount обнулён", 0, out[7]);
        check("HTTPS: вопрос сохранён (qdcount)", 1, out[5]);
        check("HTTPS: тип вопроса не подменён", DNS_TYPE_HTTPS, out[qend - 3]);
        check("HTTPS: id ответа тот же", 0x1234, (out[0] << 8) | out[1]);
        check("HTTPS: ipv4hint 1.2.3.4 клиенту не ушёл", 0,
              memcmp(out + qend - 4, "\x01\x02\x03\x04", 4) == 0);
        check("SVCB разбирается тем же путём, что HTTPS", 1,
              DNS_TYPE_SVCB == 64 && DNS_TYPE_HTTPS == 65);
    }

    {
        /* Быстрый путь: разбор ЗАПРОСА и ответ, собранный из него.
         *
         * Задержка fake-ip держалась на том, что каждый запрос ждал круга до
         * upstream — даже когда ответ от него не зависел. Здесь проверяются оба
         * условия, на которых быстрый путь стоит: parse_query читает вопрос и
         * отвергает не-вопросы, а ответ из запроса несёт правильные флаги —
         * QR (иначе клиент выбросит пакет как чужой запрос) и RA, без AA/TC. */
        uint8_t q[64];
        size_t n = 0;
        q[n++] = 0xAB; q[n++] = 0xCD;               /* id */
        q[n++] = 0x01; q[n++] = 0x00;               /* RD, это запрос */
        q[n++] = 0x00; q[n++] = 0x01;               /* qdcount = 1 */
        q[n++] = 0x00; q[n++] = 0x00;
        q[n++] = 0x00; q[n++] = 0x00;
        q[n++] = 0x00; q[n++] = 0x00;
        q[n++] = 3; memcpy(q + n, "www", 3);  n += 3;
        q[n++] = 4; memcpy(q + n, "test", 4); n += 4;
        q[n++] = 0;
        q[n++] = 0x00; q[n++] = 0x01;               /* тип A */
        q[n++] = 0x00; q[n++] = 0x01;               /* class IN */

        char name[MAX_HOSTNAME];
        uint16_t qtype = 0;
        size_t qend = 0;
        check("запрос: разобран", 0, parse_query(q, n, name, sizeof(name), &qtype, &qend));
        check("запрос: имя", 0, strcmp(name, "www.test"));
        check("запрос: тип A", DNS_TYPE_A, qtype);
        check("запрос: конец вопроса", (int)n, (int)qend);

        /* Ответ (QR=1) быстрый путь обязан отвергнуть: он для запросов. */
        uint8_t r[64];
        memcpy(r, q, n);
        r[2] |= 0x80;
        check("ответ вместо запроса: отвергнут", -1,
              parse_query(r, n, name, sizeof(name), &qtype, &qend));

        /* NODATA из запроса: та же форма, что из ответа, плюс флаги ответа. */
        uint8_t out[512];
        size_t len = build_rewritten_response(q, qend, out, sizeof(out), 0, 0);
        make_response_flags(out);
        check("ответ из запроса: длина — конец вопроса", (int)qend, (int)len);
        check("ответ из запроса: QR выставлен", 0x80, out[2] & 0x80);
        check("ответ из запроса: RD перенесён", 0x01, out[2] & 0x01);
        check("ответ из запроса: AA/TC не выдуманы", 0, out[2] & 0x06);
        check("ответ из запроса: RA выставлен, RCODE ноль", 0x80, out[3]);
        check("ответ из запроса: id клиента", 0xABCD, (out[0] << 8) | out[1]);

        /* A с подстановкой: fake-IP уходит в ответ из запроса тем же
         * build_rewritten_response, что и раньше из ответа. */
        len = build_rewritten_response(q, qend, out, sizeof(out), 1, 0xC6120005u);
        make_response_flags(out);
        check("A из запроса: ancount = 1", 1, out[7]);
        check("A из запроса: fake-IP в rdata", 0,
              memcmp(out + len - 4, "\xC6\x12\x00\x05", 4));
    }

    {
        /* ИМЕНА С ЧУЖИМИ БАЙТАМИ В МЕТКЕ (аудит 2.1.0, D1–D3; стенд аудита audit/dnsname.c).
         * Метка из провода становилась строкой как есть: байт 0 обрывал имя (вопрос в зону
         * нападающего читался как youtube.com, и адрес из его ответа вставал в карту fake-IP),
         * точка внутри метки давала то же имя, что две метки (отравление кэша), табуляция и
         * перевод строки дописывали строки в файл состояния. */
        uint8_t q[600];
        char name[MAX_HOSTNAME];
        uint16_t qtype = 0;
        size_t qend = 0;
        #define MKQ(wire, wl) do {                                                   \
            memset(q, 0, 12); q[0] = 0x11; q[1] = 0x22; q[2] = 0x01; q[5] = 1;       \
            memcpy(q + 12, (wire), (wl)); qn = 12 + (wl);                            \
            q[qn++] = 0; q[qn++] = 1; q[qn++] = 0; q[qn++] = 1; } while (0)
        size_t qn;
        static const uint8_t nul[] = "\x07youtube\x04" "com\x00" "\x08" "attacker\x07" "example";
        MKQ(nul, sizeof(nul));
        check("D1: вопрос с байтом 0 в метке не разобран", -1,
              parse_query(q, qn, name, sizeof(name), &qtype, &qend));
        /* Ответ апстрима на тот же вопрос с A 6.6.6.6 — тоже не разобран: ни правил, ни карты. */
        static const uint8_t a6666[] = { 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 6, 6, 6, 6 };
        uint8_t r[700];
        memcpy(r, q, qn); r[2] = 0x81; r[3] = 0x80; r[7] = 1;
        memcpy(r + qn, a6666, sizeof(a6666));
        struct answer_ip ips[4];
        int n6 = 0;
        check("D1: ответ на такой вопрос не разобран (адрес в карту не идёт)", -1,
              parse_response(r, qn + sizeof(a6666), name, sizeof(name), &qtype, &qend, ips, 4, NULL, 0, &n6));
        static const uint8_t dot[] = "\x0byoutube.com";
        MKQ(dot, sizeof(dot));
        check("D2: точка внутри метки — не разобран", -1,
              parse_query(q, qn, name, sizeof(name), &qtype, &qend));
        static const char *const badl[] = { "x\t198", "x\n198", "a b", "x\x7f", "x\x01", NULL };
        for (int i = 0; badl[i]; i++) {
            uint8_t w[80];
            size_t l = strlen(badl[i]);
            w[0] = (uint8_t)l; memcpy(w + 1, badl[i], l);
            memcpy(w + 1 + l, "\x07youtube\x03" "com", 13);     /* с корнем: 12 байт меток и 0 */
            MKQ(w, 1 + l + 13);
            char what[96];
            snprintf(what, sizeof(what), "D3: метка с байтом 0x%02x не разобрана",
                     (unsigned)(uint8_t)badl[i][1]);
            check(what, -1, parse_query(q, qn, name, sizeof(name), &qtype, &qend));
        }
        /* Законные имена проходят: подчёркивание, дефис, цифры, punycode, регистр, байты UTF-8. */
        static const struct { const char *wire; size_t wl; const char *str; } good[] = {
            /* Длина — с корнем: завершающий байт 0 литерала. */
            { "\x06_dmarc\x07" "Example\x03" "COM", 20, "_dmarc.Example.COM" },
            { "\x0exn--80ak6aa92e\x03" "com", 20, "xn--80ak6aa92e.com" },
            { "\x05" "a-b_c\x02" "1x\x01*", 12, "a-b_c.1x.*" },
            { "\x02\xc3\xa9\x04test", 9, "\xc3\xa9.test" },
        };
        for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
            MKQ(good[i].wire, good[i].wl);
            char what[96];
            snprintf(what, sizeof(what), "законное имя %zu разобрано как есть", i);
            int rc = parse_query(q, qn, name, sizeof(name), &qtype, &qend);
            check(what, 1, rc == 0 && !strcmp(name, good[i].str));
        }
        /* Имя ЗАПИСИ ответа с байтом 0 не отменяет адресов: строкой его никто не читает. */
        static const uint8_t www[] = "\x03www\x04test";
        MKQ(www, sizeof(www));
        memcpy(r, q, qn); r[2] = 0x81; r[3] = 0x80; r[7] = 1;
        static const uint8_t rr[] = { 3, 'x', 0, 'y', 0, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4 };
        memcpy(r + qn, rr, sizeof(rr));
        int na = parse_response(r, qn + sizeof(rr), name, sizeof(name), &qtype, &qend, ips, 4, NULL, 0, &n6);
        check("имя записи ответа с байтом 0: адрес собран", 1,
              na == 1 && ips[0].addr == htonl(0x01020304u) && !strcmp(name, "www.test"));
        #undef MKQ

        /* Кэш: ключ — метки с длинами. NXDOMAIN на однометочное «youtube.com» не отдаётся тому,
         * кто спрашивает настоящий youtube.com (прежде — 29 байт с RCODE 3). */
        struct dcache_cfg dc = { 64, 0, 3600, 300 };
        dcache_config(&dc);
        uint8_t nx[64] = { 0x00, 0x02, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0 };
        memcpy(nx + 12, "\x0byoutube.com\0\0\1\0\1", 17);
        check("D2: NXDOMAIN на однометочное имя кладётся в кэш", 1, dcache_put(1, nx, 29, 1000));
        uint8_t yq[64] = { 0x77, 0x77, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        memcpy(yq + 12, "\x07youtube\x03" "com\0\0\1\0\1", 17);
        uint8_t gb[512];
        check("D2: ...и не отдаётся на вопрос о настоящем youtube.com", 0,
              (int)dcache_get(1, yq, 29, gb, sizeof(gb), 1001));
        memcpy(yq + 12, "\x0bYouTube.com\0\0\1\0\1", 17);
        check("D2: на то же однометочное имя (другой регистр) — отдаётся", 29,
              (int)dcache_get(1, yq, 29, gb, sizeof(gb), 1001));
        dcache_flush();

        /* Имя-строка (файл состояния, --fakeip). */
        check("dns_name_ok: обычное", 1, dns_name_ok("www.example.com"));
        check("dns_name_ok: подчёркивание и punycode", 1, dns_name_ok("_sip._tcp.xn--p1ai"));
        check("dns_name_ok: табуляция", 0, dns_name_ok("x\t198.18.0.5"));
        check("dns_name_ok: пробел", 0, dns_name_ok("a b.test"));
        check("dns_name_ok: пустая метка", 0, dns_name_ok("a..test"));
        check("dns_name_ok: точка в конце", 0, dns_name_ok("a.test."));
        check("dns_name_ok: пустое", 0, dns_name_ok(""));
        check("dns_name_ok: метка 64 байта", 0,
              dns_name_ok("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.test"));
    }

    {
        /* D3: ФАЙЛ СОСТОЯНИЯ, УЖЕ ОТРАВЛЕННЫЙ ПРЕЖНЕЙ ВЕРСИЕЙ, лечится при загрузке. Строка «x» с
         * поддельным адресом youtube.com и настоящим нападающего, имя с пробелом, подмена на адрес
         * пула и строка длиннее буфера (её хвост читался бы отдельной строкой). */
        char dir[] = "/tmp/dnsmatch-poison.XXXXXX";
        if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }
        char path[768];
        snprintf(path, sizeof(path), "%s/state", dir);
        FILE *f = fopen(path, "w");
        fputs("youtube.com\t198.18.0.5\t142.250.1.1\n", f);
        fputs("x\t198.18.0.5\t6.6.6.6\n", f);
        fputs("bad name.test\t198.18.0.6\t6.6.6.6\n", f);
        fputs("loop.test\t198.18.0.7\t198.18.0.9\n", f);
        /* Ровно буфер чтения загрузчика (MAX_HOSTNAME + 128 - 1 байт): хвост — «z.test…». */
        for (int i = 0; i < MAX_HOSTNAME + 128 - 1; i++) fputc('a', f);
        fputs("z.test\t198.18.0.8\t6.6.6.6\n", f);
        fputs("ok.test\t198.18.0.10\t93.184.216.34\n", f);
        fclose(f);
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        memset(&g_fakeip_idx, 0, sizeof(g_fakeip_idx));
        g_fakeip_next = 0;
        g_fakeip_state_path = NULL;
        g_fakeip_dirty = 0;
        fakeip_state_load(path);
        check("D3: загружены youtube.com, loop.test, ok.test", 3, (int)g_fakeip.n);
        check("D3: youtube.com — свой настоящий адрес", 1,
              fakeip_entry_known_real("youtube.com") == 0x8EFA0101u);
        check("D3: «x» на чужом поддельном адресе отвергнута", -1, (int)fakeip_find("x"));
        check("D3: имя с пробелом отвергнуто", -1, (int)fakeip_find("bad name.test"));
        check("D3: хвост длинной строки не стал строкой", -1, (int)fakeip_find("z.test"));
        check("D3: подмена на адрес пула не принята", 0, (int)fakeip_entry_known_real("loop.test"));
        check("D3: строка после длинной цела", 1, fakeip_entry_known_real("ok.test") == 0x5DB8D822u);
        check("D3: отвергнутое помечает файл к перезаписи", 1, g_fakeip_dirty);
        g_fakeip_dirty = 0;
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        memset(&g_fakeip_idx, 0, sizeof(g_fakeip_idx));
        g_fakeip_next = 0;
        unlink(path);
        rmdir(dir);
    }

    {
        /* D5: ПРЕДЕЛ ВЫДАЧИ FAKE-IP НА КЛИЕНТА. Один клиент, спрашивающий случайные имена под
         * правилом, прежде занимал весь пул, и новые имена ВСЕХ клиентов получали настоящий адрес.
         * Теперь за клиентом не больше fakeip_per_client() адресов; сверх — -2 (резолвер отвечает
         * SERVFAIL ему одному), а другой клиент получает адрес как обычно. */
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        memset(&g_fakeip_idx, 0, sizeof(g_fakeip_idx));
        g_fakeip_next = 1;
        g_fakeip_state_path = NULL;
        struct sockaddr_storage ca, cb, c6a, c6b;
        memset(&ca, 0, sizeof(ca)); memset(&cb, 0, sizeof(cb));
        memset(&c6a, 0, sizeof(c6a)); memset(&c6b, 0, sizeof(c6b));
        ((struct sockaddr_in *)&ca)->sin_family = AF_INET;
        ((struct sockaddr_in *)&ca)->sin_addr.s_addr = htonl(0xC0A80166u);   /* 192.168.1.102 */
        ((struct sockaddr_in *)&cb)->sin_family = AF_INET;
        ((struct sockaddr_in *)&cb)->sin_addr.s_addr = htonl(0xC0A80167u);
        ((struct sockaddr_in6 *)&c6a)->sin6_family = AF_INET6;
        inet_pton(AF_INET6, "2001:db8:1:2::aaaa", &((struct sockaddr_in6 *)&c6a)->sin6_addr);
        ((struct sockaddr_in6 *)&c6b)->sin6_family = AF_INET6;
        inet_pton(AF_INET6, "2001:db8:1:2:1234:5678:9abc:def0", &((struct sockaddr_in6 *)&c6b)->sin6_addr);
        uint64_t ka = fakeip_client_key(&ca), kb = fakeip_client_key(&cb);
        check("ключ клиента: разные адреса IPv4 — разные клиенты", 1, ka && kb && ka != kb);
        check("ключ клиента: адреса одной /64 — один клиент", 1,
              fakeip_client_key(&c6a) == fakeip_client_key(&c6b));
        struct sockaddr_storage lo4, lo6;
        memset(&lo4, 0, sizeof(lo4)); memset(&lo6, 0, sizeof(lo6));
        ((struct sockaddr_in *)&lo4)->sin_family = AF_INET;
        ((struct sockaddr_in *)&lo4)->sin_addr.s_addr = htonl(0x7F000001u);
        ((struct sockaddr_in6 *)&lo6)->sin6_family = AF_INET6;
        ((struct sockaddr_in6 *)&lo6)->sin6_addr = in6addr_loopback;
        check("ключ клиента: петля не считается (пересыльщики всей сети)", 1,
              fakeip_client_key(&lo4) == 0 && fakeip_client_key(&lo6) == 0);
        unsigned lim = fakeip_per_client();
        check("предел на клиента — восьмая часть пула", (int)(FAKEIP_POOL_SIZE / 8), (int)lim);
        int okall = 1;
        uint32_t addr = 0;
        char nm[64];
        for (unsigned i = 0; i < lim; i++) {
            snprintf(nm, sizeof(nm), "r%u.flood.test", i);
            if (fakeip_lookup_or_alloc_for(nm, ka, &addr) != 0) { okall = 0; break; }
        }
        check("D5: клиент получает свои адреса до предела", 1, okall);
        check("D5: счёт клиента — ровно предел", (int)lim, (int)fakeip_owner_count(ka));
        check("D5: другой клиент получает адрес", 0,
              fakeip_lookup_or_alloc_for("victim.flood.test", kb, &addr));
        check("D5: и адрес — из пула", 1, addr >= FAKEIP_POOL_BASE && addr < FAKEIP_POOL_BASE + FAKEIP_POOL_SIZE);
        /* У предела клиент сначала возвращает свои простоявшие имена (живых соединений нет —
         * заглушка conntrack с пустым ответом) и снова получает адрес. */
        int (*live_was)(uint8_t *) = g_fakeip_live;
        g_fakeip_live = pool_live_stub;
        g_pool_live_n = 0;
        for (size_t i = 0; i < g_fakeip.n; i++)
            if (g_fakeip.entries[i].owner == ka) g_fakeip.entries[i].last_used -= g_fakeip_idle + 1;
        check("D5: у предела простоявшие имена клиента возвращаются, адрес выдан", 0,
              fakeip_lookup_or_alloc_for("again.flood.test", ka, &addr));
        check("D5: и счёт клиента — одна запись", 1, (int)fakeip_owner_count(ka));
        check("D5: чужое имя возврат не тронул", 1, fakeip_find("victim.flood.test") >= 0);
        okall = 1;
        for (unsigned i = 1; i < lim; i++) {
            snprintf(nm, sizeof(nm), "s%u.flood.test", i);
            if (fakeip_lookup_or_alloc_for(nm, ka, &addr) != 0) { okall = 0; break; }
        }
        check("D5: снова до предела", 1, okall && fakeip_owner_count(ka) == lim);
        check("D5: сверх предела (имена свежие) — отказ (-2), а не адрес", -2,
              fakeip_lookup_or_alloc_for("over.flood.test", ka, &addr));
        check("D5: уже выданное имя клиенту по-прежнему отвечает", 0,
              fakeip_lookup_or_alloc_for("s7.flood.test", ka, &addr));
        check("D5: другой клиент и тогда получает адрес", 0,
              fakeip_lookup_or_alloc_for("victim2.flood.test", kb, &addr));
        g_fakeip_live = live_was;
        for (size_t i = 0; i < g_fakeip.n; i++) free(g_fakeip.entries[i].domain);
        free(g_fakeip.entries);
        sindex_free(&g_fakeip_idx);
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        memset(&g_fakeip_idx, 0, sizeof(g_fakeip_idx));
        fakeip_pool_reset();
        g_fakeip_next = 1;
    }

    {
        /* Долгий путь к файлу состояния fake-IP. Путь задаётся снаружи (--state-file,
         * --state-dir), то есть его длину выбирает не движок, а буфер под имя временного
         * файла был размером в имя ХОСТА (MAX_HOSTNAME, 256). «%s.tmp» в него молча не
         * влезал, и обрезка приходилась на произвольное место пути — в том числе ровно на
         * границу компонента, и тогда обрезанное имя оказывалось существующим КАТАЛОГОМ:
         * fopen падал с EISDIR, функция молча возвращалась, и таблица fake-IP не
         * сохранялась вовсе. Следствие видно только после перезапуска — весь DNAT
         * собирается заново, а прежние адреса у клиентов в кеше уже другие.
         *
         * Стенд ставит длину каталога ровно 255: тогда обрезка «%s.tmp» до 255 символов
         * даёт сам каталог. Проверяется наблюдаемое следствие — файл состояния после
         * rewrite обязан существовать и содержать записанную пару. */
        char dir[512];
        snprintf(dir, sizeof(dir), "/tmp/dnsmatch-long.XXXXXX");
        if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
        size_t at = strlen(dir);
        /* Два уровня по 115 символов добирают путь каталога до 255 (25 + 115 + 115). */
        for (int lvl = 0; lvl < 2; lvl++) {
            at += (size_t)snprintf(dir + at, sizeof(dir) - at, "/%0114d", lvl);
            if (mkdir(dir, 0755) != 0 && errno != EEXIST) { perror("mkdir"); return 1; }
        }
        check("долгий путь: каталог ровно на границе буфера", 255, (int)strlen(dir));
        char path[768];
        snprintf(path, sizeof(path), "%s/fakeip.state", dir);

        memset(&g_fakeip, 0, sizeof(g_fakeip));
        g_fakeip_next = 0;
        uint32_t addr = 0;
        g_fakeip_state_path = NULL;             /* без append: пишет только rewrite */
        check("долгий путь: адрес выдан", 0, fakeip_lookup_or_alloc("long.test", &addr));
        g_fakeip_state_path = path;
        fakeip_state_rewrite();

        FILE *rf = fopen(path, "r");
        check("долгий путь: файл состояния создан", 1, rf != NULL);
        if (rf) {
            char line[512] = {0};
            char *got = fgets(line, sizeof(line), rf);
            check("долгий путь: строка прочитана", 1, got != NULL);
            check("долгий путь: домен на месте", 1, strstr(line, "long.test") != NULL);
            fclose(rf);
        }
        g_fakeip_state_path = NULL;
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        g_fakeip_next = 0;
    }

    /* ---- ПУЛ fake-IP: адреса возвращаются (I-521) ------------------------------------------------
     *
     * Раньше 131070 адресов только выдавались: на 131071-м новом имени — «пул исчерпан» навсегда.
     * Теперь простоявшее имя без живых соединений отдаёт адрес, а имя с соединением, и имя, которое
     * только что спрашивали, — нет. Живые соединения здесь подставляет стенд (g_fakeip_live; в
     * работе это conntrack). */
    {
        size_t cap = FAKEIP_POOL_SIZE - 2;      /* без адреса сети и последнего */
        fakeip_pool_reset();
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        memset(&g_fakeip_idx, 0, sizeof(g_fakeip_idx));
        g_fakeip_next = 1;
        g_fakeip_state_path = NULL;
        char nm[64];
        uint32_t addr = 0;
        int all_ok = 1;
        for (size_t i = 0; i < cap; i++) {
            snprintf(nm, sizeof(nm), "h%zu.pool.test", i);
            if (fakeip_lookup_or_alloc(nm, &addr) != 0) all_ok = 0;
        }
        check("пул: выдан весь пул до последнего адреса", 1, all_ok);
        check("пул: все записи в таблице", (int)cap, (int)g_fakeip.n);
        check("пул: все заняты свежими вопросами — следующее имя отказ", -1,
              fakeip_lookup_or_alloc("over.pool.test", &addr));

        /* Первые 100 имён простояли дольше срока; у первых десяти — живое соединение. */
        time_t now = time(NULL);
        uint32_t live_addr[10];
        for (size_t i = 0; i < 100; i++) g_fakeip.entries[i].last_used = now - 2 * g_fakeip_idle;
        for (size_t i = 0; i < 10; i++) live_addr[i] = g_fakeip.entries[i].addr;
        g_fakeip_live = pool_live_stub;
        g_pool_live_addr = live_addr;
        g_pool_live_n = 10;
        /* Выдача, как прежде, сначала отказывает (дроссель сверки — раз в 10 с) — стенд зовёт сверку
         * сам, а затем идёт обычным путём выдачи. */
        check("пул: вернулось 90 адресов (10 держат соединения)", 90, (int)fakeip_reclaim(now));
        check("пул: ушедшее имя не находится", 1, fakeip_find("h50.pool.test") < 0);
        check("пул: имя с соединением осталось", 1, fakeip_find("h5.pool.test") >= 0);
        check("пул: индекс цел после уплотнения", 1, fakeip_find("h100.pool.test") >= 0 &&
              g_fakeip.entries[fakeip_find("h100.pool.test")].addr ==
              FAKEIP_POOL_BASE + 101);
        int got_ok = 1, dist = 1, no_live = 1;
        static uint8_t seen_a[FAKEIP_POOL_SIZE / 8];
        memset(seen_a, 0, sizeof(seen_a));
        for (int i = 0; i < 90; i++) {
            snprintf(nm, sizeof(nm), "again%d.pool.test", i);
            if (fakeip_lookup_or_alloc(nm, &addr) != 0) { got_ok = 0; continue; }
            uint32_t ix = addr - FAKEIP_POOL_BASE;
            if (seen_a[ix >> 3] & (1u << (ix & 7))) dist = 0;
            seen_a[ix >> 3] |= (uint8_t)(1u << (ix & 7));
            for (int k = 0; k < 10; k++) if (addr == live_addr[k]) no_live = 0;
        }
        check("пул: 90 новых имён получили возвращённые адреса", 1, got_ok);
        check("пул: адреса возвращённые разные", 1, dist);
        check("пул: адрес с живым соединением не выдан заново", 1, no_live);
        check("пул: 91-е имя — снова отказ (занято всё)", -1,
              fakeip_lookup_or_alloc("over2.pool.test", &addr));

        /* conntrack недоступен (-1): решает один срок простоя, а не «никогда». */
        g_pool_live_n = -1;
        for (size_t i = 0; i < g_fakeip.n; i++) g_fakeip.entries[i].last_used = now;
        for (size_t i = 0; i < 7; i++) g_fakeip.entries[i].last_used = now - 2 * g_fakeip_idle;
        check("пул: без conntrack возвращается по сроку простоя", 7, (int)fakeip_reclaim(now));
        check("пул: и выдаётся из возвращённых", 0, fakeip_lookup_or_alloc("nolive.pool.test", &addr));
        fakeip_pool_reset();
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        memset(&g_fakeip_idx, 0, sizeof(g_fakeip_idx));
        g_fakeip_next = 1;
        g_fakeip_live = NULL;
    }
    /* ---- ФОНОВАЯ ПЕРЕЗАПИСЬ ФАЙЛА СОСТОЯНИЯ (I-534): цикл не ждёт fsync ---------------------------------
     * fakeip_state_flush_async сериализует таблицу и отдаёт потоку; файл на месте после fakeip_state_wait, а
     * флаг «грязно» снят сразу. Последний снимок побеждает: два подряд — в файле второй. */
    {
        char dirt[] = "/tmp/dnsmatch-fakeip-XXXXXX";
        char path[128];
        if (!mkdtemp(dirt)) { perror("mkdtemp"); return 1; }
        snprintf(path, sizeof(path), "%s/fakeip.state", dirt);
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        g_fakeip_next = 0;
        g_fakeip_state_path = NULL;
        uint32_t aa = 0;
        fakeip_lookup_or_alloc("bg-one.test", &aa);
        fakeip_lookup_or_alloc("bg-two.test", &aa);
        g_fakeip_state_path = path;
        g_fakeip_dirty = 1;
        fakeip_state_flush_async();
        check("фон: флаг «грязно» снят сразу после передачи потоку", 0, g_fakeip_dirty);
        fakeip_lookup_or_alloc("bg-three.test", &aa);
        g_fakeip_dirty = 1;
        fakeip_state_flush_async();
        fakeip_state_wait();
        char all[2048] = {0};
        FILE *rf = fopen(path, "r");
        size_t got = rf ? fread(all, 1, sizeof(all) - 1, rf) : 0;
        if (rf) fclose(rf);
        check("фон: файл записан потоком, в нём все три домена (последний снимок)", 1,
              got > 0 && strstr(all, "bg-one.test") && strstr(all, "bg-two.test") && strstr(all, "bg-three.test"));
        char tmp[160];
        snprintf(tmp, sizeof(tmp), "%s.tmp", path);
        check("фон: временного файла не осталось", 1, access(tmp, F_OK) != 0);
        unlink(path);
        rmdir(dirt);
        g_fakeip_state_path = NULL;
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        g_fakeip_next = 0;
    }

    /* ---- ФОН И СИНХРОННЫЕ МЕСТА ЧТЕНИЯ ФАЙЛА (I-534): flush ждёт поток, append не теряется ------------------
     * Снимок уже у потока, флаг «грязно» снят. Просьба загрузчика («flush») и выход резолвера зовут
     * fakeip_state_flush: файл обязан лежать на носителе к её возврату, хотя флаг чист. И имя, выданное, пока
     * поток пишет, не пропадает из файла: дописанная строка не должна затираться более старым снимком. */
    {
        char dirt[] = "/tmp/dnsmatch-fakeip-XXXXXX";
        char path[128];
        if (!mkdtemp(dirt)) { perror("mkdtemp"); return 1; }
        snprintf(path, sizeof(path), "%s/fakeip.state", dirt);
        int lost_flush = 0, lost_append = 0;
        for (int round = 0; round < 40; round++) {
            fakeip_pool_reset();
            memset(&g_fakeip, 0, sizeof(g_fakeip));
            memset(&g_fakeip_idx, 0, sizeof(g_fakeip_idx));
            g_fakeip_next = 1;
            g_fakeip_state_path = NULL;
            uint32_t aa = 0;
            char nm[64];
            for (int i = 0; i < 3000; i++) {
                snprintf(nm, sizeof(nm), "r%d-%d.flushwait.test", round, i);
                fakeip_lookup_or_alloc(nm, &aa);
            }
            unlink(path);
            g_fakeip_state_path = path;
            g_fakeip_dirty = 1;
            fakeip_state_flush_async();
            fakeip_state_flush();               /* чисто: но поток ещё пишет, и файл нужен сейчас */
            if (access(path, F_OK) != 0) lost_flush++;
            fakeip_state_wait();
            /* Имя, выданное во время записи снимка, в котором его нет. */
            g_fakeip_dirty = 1;
            fakeip_state_flush_async();
            fakeip_lookup_or_alloc("during-write.flushwait.test", &aa);
            fakeip_state_flush();
            fakeip_state_wait();
            char *all = calloc(1, 1 << 20);
            FILE *rf = fopen(path, "r");
            size_t got = rf && all ? fread(all, 1, (1 << 20) - 1, rf) : 0;
            if (rf) fclose(rf);
            if (!got || !strstr(all, "during-write.flushwait.test")) lost_append++;
            free(all);
        }
        check("фон: flush при чистом флаге дожидается потока (файл на месте)", 0, lost_flush);
        check("фон: имя, выданное во время записи снимка, остаётся в файле", 0, lost_append);
        unlink(path);
        char tmp[160];
        snprintf(tmp, sizeof(tmp), "%s.tmp", path);
        unlink(tmp);
        rmdir(dirt);
        g_fakeip_state_path = NULL;
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        g_fakeip_next = 0;
    }

    /* ---- ГИБРИДНЫЙ СПИСОК: адреса и имена в одном файле -------------------------
     *
     * Проверяется не ruleset_add, а load_rules_into — то есть путь ЧТЕНИЯ ФАЙЛА, потому
     * что именно там теперь стоит разделение: адресные строки этого же файла берёт
     * компилятор набора правил, доменные — резолвер. Через ruleset_add напрямую разделения
     * не видно вовсе, и стенд был бы зелёным при любом поведении читателя.
     *
     * Список ровно тот, который назвал владелец: адрес, имя, подсеть. Плюс диапазон —
     * его выдаёт `steer fit`, и он тоже адрес. */
    {
        char path[] = "/tmp/dnsmatch-hybrid.XXXXXX";
        int fd = mkstemp(path);
        check("гибрид: файл создан", 1, fd >= 0);
        if (fd >= 0) {
            FILE *w = fdopen(fd, "w");
            fputs("1.1.1.1\n"
                  "youtube.com\n"
                  "8.8.8.0/24\n"
                  "10.0.0.1-10.0.0.9\n"
                  "2606:4700::/32\n"
                  "# комментарий\n"
                  "=exact.example\n"
                  "*.wild.example\n", w);
            fclose(w);

            struct ruleset rs;
            memset(&rs, 0, sizeof(rs));
            check("гибрид: файл прочитан", 0, load_rules_into(path, &rs));
            /* Доменных правил ровно три: суффикс, точное, шаблон. Адресные пять строк (одна —
             * IPv6) в резолвер не попали — иначе их было бы восемь, и каждая адресная стала бы
             * правилом RULE_NAMESPACE для имени вроде «8.8.8.0/24». */
            check("гибрид: доменных правил ровно три", 3, (int)rs.n);
            check("гибрид: имя ловится", 1, ruleset_match(&rs, "youtube.com"));
            check("гибрид: поддомен имени ловится", 1, ruleset_match(&rs, "www.youtube.com"));
            check("гибрид: точное ловится", 1, ruleset_match(&rs, "exact.example"));
            check("гибрид: поддомен точного НЕ ловится", 0,
                  ruleset_match(&rs, "sub.exact.example"));
            check("гибрид: шаблон ловится", 1, ruleset_match(&rs, "a.wild.example"));
            check("гибрид: адрес не стал доменным правилом", 0,
                  ruleset_match(&rs, "8.8.8.0/24"));
            check("гибрид: чужое имя не ловится", 0, ruleset_match(&rs, "example.org"));

            /* Классификатор отдельно: он общий на двух читателей, и его ответы — это
             * граница между ними. Ошибка здесь означает строку, которую не взял никто. */
            check("классификатор: 1.1.1.1 адрес", 1, spec_line_is_addr("1.1.1.1"));
            check("классификатор: 8.8.8.0/24 адрес", 1, spec_line_is_addr("8.8.8.0/24"));
            check("классификатор: диапазон адрес", 1,
                  spec_line_is_addr("10.0.0.1-10.0.0.9"));
            check("классификатор: youtube.com не адрес", 0, spec_line_is_addr("youtube.com"));
            check("классификатор: имя с дефисом не адрес", 0,
                  spec_line_is_addr("my-site.example"));
            /* С 1.9 строка IPv6 — адрес (семейство 6, парный набор ipv6_addr), и резолвер её
             * доменным правилом больше не берёт. */
            check("классификатор: IPv6 адрес", 1, spec_line_is_addr("2606:4700::/32"));
            check("классификатор: IPv6 — семейство 6", 6, spec_line_family("2606:4700::/32"));
            check("классификатор: IPv4 — семейство 4", 4, spec_line_family("8.8.8.0/24"));
            check("классификатор: диапазон IPv6", 6,
                  spec_line_family("2001:db8::1-2001:db8::9"));
            check("классификатор: MAC не адрес", 0, spec_line_family("aa:bb:cc:dd:ee:ff"));
            check("классификатор: /129 не адрес", 0, spec_line_family("2001:db8::/129"));
            check("классификатор: MAC это MAC", 1, spec_is_mac("aa:bb:cc:dd:ee:ff"));
            check("классификатор: IPv6 с пятью двоеточиями не MAC", 0,
                  spec_is_mac("a::b:c:d:e"));
            check("классификатор: одиночный IPv6 — хозяин", 1, spec_one_host("fd00::5"));
            check("классификатор: /128 — хозяин", 1, spec_one_host("fd00::5/128"));
            check("классификатор: подсеть IPv6 — не хозяин", 0, spec_one_host("fd00::/64"));
            check("гибрид: IPv6 не стал доменным правилом", 0,
                  ruleset_match(&rs, "2606:4700::/32"));
            unlink(path);
        }
    }

    /* ---- ОДНО ИМЯ В НЕСКОЛЬКИХ ПРАВИЛАХ ------------------------------------------
     *
     * Правило на телевизор и правило на всю сеть законно называют один и тот же YouTube.
     * Пока резолвер клал поддельный адрес в набор ПЕРВОГО совпавшего канала, у клиентов
     * второго на руках оказывался адрес, которого нет ни в одном правиле, — и домен
     * переставал открываться у всех сразу. Проверяется поэтому не «нашёлся ли канал», а
     * СКОЛЬКО их нашлось и кто из них строит ответ. */
    {
        static const char *const yt[] = { "youtube.com", NULL };
        dch_zero(2);
        g_dch_n = 2;
        snprintf(g_dch[0].set, sizeof(g_dch[0].set), "%s", "tv_dom");
        snprintf(g_dch[1].set, sizeof(g_dch[1].set), "%s", "all_dom");
        build(&g_dch[0].rules, yt);
        build(&g_dch[1].rules, yt);

        check("пересечение: совпали ОБА канала", 1, dch_match_mask("youtube.com") == chm2(0, 1));
        check("пересечение: поддомен — тоже оба", 1, dch_match_mask("www.youtube.com") == chm2(0, 1));
        check("пересечение: ответ строит верхний", 0, dch_first(dch_match_mask("youtube.com")));
        check("пересечение: чужое имя — ни один", 0, (int)dch_match_mask("example.org"));
        check("пересечение: пустой набор — канала нет", -1, dch_first(0));

        /* Канал реального адреса поддельного к себе не берёт: в его наборе лежат
         * настоящие адреса из ответа, а поддельного клиент в этом режиме не получает. */
        g_dch[1].realip = 1;
        check("пересечение: realip не берёт поддельный адрес", 1,
              dch_fakeip_only(dch_match_mask("youtube.com")) == chm_one(0));

        ruleset_free(&g_dch[0].rules);
        ruleset_free(&g_dch[1].rules);
        g_dch_n = 0;
    }

    /* ---- ВЫКЛЮЧЕННОЕ ПРАВИЛО РЕЗОЛВЕР НЕ БЕРЁТ -----------------------------------
     *
     * «Выключено» обязано значить «не действует». Компилятор набора выключенный канал
     * пропускал, а резолвер — нет, и получалось хуже, чем «действует»: имя разрешалось в
     * поддельный адрес, набора для которого в ядре нет вовсе. Снаружи это выглядело как
     * сломанный выключатель — «отключить правило не помогает, надо удалить».
     *
     * Проверяется через dch_build на настоящей спеке: пропуск живёт именно там. */
    {
        char lst[] = "/tmp/dnsmatch-off-list.XXXXXX";
        int lf = mkstemp(lst);
        check("выключенное: список создан", 1, lf >= 0);
        if (lf >= 0) {
            FILE *w = fdopen(lf, "w");
            fputs("youtube.com\n", w);
            fclose(w);

            char sp[] = "/tmp/dnsmatch-off-spec.XXXXXX";
            int sf = mkstemp(sp);
            if (sf >= 0) {
                FILE *ws = fdopen(sf, "w");
                fprintf(ws,
                        "{\"schema\":1,"
                        "\"outputs\":{\"vl\":{\"kind\":\"interface\",\"device\":\"lo\"}},"
                        "\"channels\":["
                        "{\"name\":\"off\",\"enabled\":false,"
                        "\"match\":{\"domains_files\":[\"%s\"]},\"out\":\"vl\"}"
                        "]}\n", lst);
                fclose(ws);

                static struct spec cfg;
                struct err e = {0};
                if (load_spec(sp, &cfg, &e) < 0) err_die(&e);
                dch_build(&cfg);
                check("выключенное: канала у резолвера нет", 0, (int)g_dch_n);
                unlink(sp);
            }
            unlink(lst);
        }
    }

    /* ---- ФОРМАТ ТАБЛИЦЫ (src/dnsd/tabfmt.h): сборка → разбор возвращают тот же g_dch --------
     *
     * Контракт демон/резолвер (docs/architecture.md, раздел 4а, «dnsd»): демон строит таблицу
     * из спеки (tabfmt_build — тот же dch_build, что и раньше) и шлёт её текстом резолверу,
     * который её разбирает (tabfmt_parse) БЕЗ спеки вовсе. Если разбор потеряет поле или
     * перепутает порядок — резолвер в режиме --table-fd молча раздаст не те наборы, а стенд
     * этого не покажет никаким другим путём: dch_build здесь не подключается к резолверу
     * заново, сравнение — единственный способ поймать расхождение форматов. */
    {
        char l1[] = "/tmp/dnsmatch-tab-l1.XXXXXX";
        char l2[] = "/tmp/dnsmatch-tab-l2.XXXXXX";
        int f1 = mkstemp(l1), f2 = mkstemp(l2);
        check("формат таблицы: списки созданы", 1, f1 >= 0 && f2 >= 0);
        if (f1 >= 0 && f2 >= 0) {
            FILE *w1 = fdopen(f1, "w"), *w2 = fdopen(f2, "w");
            fputs("web.example\n", w1); fclose(w1);
            fputs("srv.example\nother.example\n", w2); fclose(w2);

            /* Спека v2 (JSON с `version`): поле семейства «46» — у выхода с IPv6; те же каналы
             * спекой v1 (ниже) дают то же семейство. */
            char sp[] = "/tmp/dnsmatch-tab-spec.XXXXXX";
            int sf = mkstemp(sp);
            if (sf >= 0) {
                FILE *ws = fdopen(sf, "w");
                fprintf(ws,
                        "{\"version\":2,"
                        "\"lists\":{\"web\":{\"domains_file\":[\"%s\"]},"
                        "\"srv\":{\"domains_file\":[\"%s\",\"%s\"]}},"
                        "\"outputs\":{\"vpn\":{\"kind\":\"interface\",\"device\":\"lo\"}},"
                        "\"rules\":["
                        "{\"name\":\"web\",\"to\":\"web\",\"out\":\"vpn\"},"
                        "{\"name\":\"srv\",\"to\":\"srv\",\"out\":\"vpn\",\"resolve\":\"realip\"}"
                        "]}\n", l1, l2, l1);
                fclose(ws);

                static struct spec cfg;
                struct err e = {0};
                if (load_spec(sp, &cfg, &e) < 0) err_die(&e);

                char *text = NULL;
                size_t textlen = 0;
                FILE *mem = open_memstream(&text, &textlen);
                tabfmt_build(&cfg, mem);
                fclose(mem);

                /* Снимок ровно того, что tabfmt_build напечатала (dch_build уже отработал
                 * внутри неё), — «дч_build по спеке» из требования стенда. */
                struct snapc { char set[64], out[32], chan[32]; int realip, fam; size_t rules_n;
                               char rules_path[16][256]; };
                static struct snapc snap[16];        /* в спеке стенда каналов два */
                size_t snap_n = g_dch_n;
                for (size_t i = 0; i < snap_n; i++) {
                    /* memcpy целиком, а не snprintf("%s", ...): поля snap зеркалят размер
                     * g_dch (set[64]/out[32]/chan[32]) один в один, а gcc иначе не может
                     * доказать границу источника внутри массива структур g_dch
                     * и завышает её до размера всего массива (-Wformat-truncation). */
                    memcpy(snap[i].set, g_dch[i].set, sizeof(snap[i].set));
                    memcpy(snap[i].out, g_dch[i].out, sizeof(snap[i].out));
                    memcpy(snap[i].chan, g_dch[i].chan, sizeof(snap[i].chan));
                    snap[i].realip = g_dch[i].realip;
                    snap[i].fam = g_dch[i].fam;
                    snap[i].rules_n = g_dch[i].rules_n;
                    for (size_t k = 0; k < g_dch[i].rules_n && k < 16; k++)
                        snprintf(snap[i].rules_path[k], sizeof(snap[i].rules_path[k]),
                                 "%s", g_dch[i].rules_path[k]);
                }
                check("формат таблицы: dch_build дал два канала", 2, (int)snap_n);
                /* Выход interface несёт IPv6, клиенты по умолчанию — устройствами: у обоих
                 * каналов (fake-IP и real-ip) половина IPv6 есть, и таблица говорит «46». */
                for (size_t i = 0; i < snap_n; i++)
                    check("формат таблицы: канал выхода с IPv6 — семейства 4 и 6",
                          DCH_V4 | DCH_V6, snap[i].fam);
                check("формат таблицы: строка канала несёт «|46|»", 1,
                      text && strstr(text, "|0|46|web") != NULL);

                /* g_dch сейчас держит указатели ВНУТРЬ cfg (dch_build, table.c: rules_path —
                 * заимствованные строки спеки, никем не malloc'нутые). tabfmt_parse же исходит
                 * из того, что прошлым владельцем g_dch была ОНА САМА (--table-fd — единственный
                 * режим, где она вообще вызывается, docs/architecture.md, раздел 4а), и
                 * освобождает rules_path free()'ом. В настоящем резолвере это всегда так: сборка
                 * (dch_build) и разбор (tabfmt_parse) в один процесс никогда не приходят вместе.
                 * В этом стенде — приходят, ради самого сравнения, поэтому перед разбором g_dch
                 * обнуляется руками — так же, как обнулён он в свежем процессе резолвера (BSS),
                 * а не через free() чужих указателей. */
                for (size_t i = 0; i < g_dch_n; i++) free(g_dch[i].rules_path);   /* массивы; строки — спеки */
                memset(g_dch, 0, g_dch_cap * sizeof(*g_dch));
                g_dch_n = 0;

                check("формат таблицы: разбор принял текст", 0,
                      tabfmt_parse(text, textlen));
                /* Приёмник из трубы: та же таблица кусками по 7 байт — собирается ровно на последнем,
                 * а досмотр строк идёт с места остановки (tabfmt_feed), а не с начала. */
                {
                    struct tabfmt_feed fd = {0};
                    int done = -1, early = 0;
                    for (size_t o = 0; o < textlen; o += 7) {
                        size_t cn = textlen - o < 7 ? textlen - o : 7;
                        int fr = tabfmt_feed(&fd, text + o, cn);
                        if (fr == 1 && o + cn < textlen) early = 1;
                        if (fr == 1) done = 1;
                        if (fr < 0) done = -2;
                    }
                    check("приёмник таблицы: кусками по 7 байт собралась целиком, не раньше конца", 1,
                          done == 1 && !early && fd.len == 0);
                    free(fd.buf);
                }
                check("формат таблицы: то же число каналов после разбора",
                      (int)snap_n, (int)g_dch_n);
                for (size_t i = 0; i < snap_n && i < g_dch_n; i++) {
                    char what[96];
                    snprintf(what, sizeof(what), "формат таблицы: канал %zu, набор", i);
                    check(what, 0, strcmp(snap[i].set, g_dch[i].set));
                    snprintf(what, sizeof(what), "формат таблицы: канал %zu, выход", i);
                    check(what, 0, strcmp(snap[i].out, g_dch[i].out));
                    snprintf(what, sizeof(what), "формат таблицы: канал %zu, правило", i);
                    check(what, 0, strcmp(snap[i].chan, g_dch[i].chan));
                    snprintf(what, sizeof(what), "формат таблицы: канал %zu, realip", i);
                    check(what, snap[i].realip, g_dch[i].realip);
                    snprintf(what, sizeof(what), "формат таблицы: канал %zu, семейства", i);
                    check(what, snap[i].fam, g_dch[i].fam);
                    snprintf(what, sizeof(what), "формат таблицы: канал %zu, число файлов", i);
                    check(what, (int)snap[i].rules_n, (int)g_dch[i].rules_n);
                    for (size_t k = 0; k < snap[i].rules_n && k < g_dch[i].rules_n; k++) {
                        snprintf(what, sizeof(what), "формат таблицы: канал %zu, файл %zu", i, k);
                        check(what, 0, strcmp(snap[i].rules_path[k], g_dch[i].rules_path[k]));
                    }
                }

                /* Испорченный текст — разбор отказывает, а не берёт что попало. */
                {
                    static const char bad1[] = "не число\n";
                    static const char bad2[] = "2\none|out|0|c\n";
                    check("формат таблицы: нечисловой счётчик — отказ", -1,
                          tabfmt_parse(bad1, sizeof(bad1) - 1));
                    check("формат таблицы: обещали больше строк, чем есть — отказ", -1,
                          tabfmt_parse(bad2, sizeof(bad2) - 1));
                }

                /* Пустая таблица — законный ответ («нет ни одного доменного канала», main.c),
                 * и заодно освобождает то, чем разбор владел (rules_path — strdup, см.
                 * tabfmt.c), не оставляя g_dch занятым для следующего блока стенда. */
                check("формат таблицы: пустая таблица разбирается", 0,
                      tabfmt_parse("0\n", 2));
                check("формат таблицы: пустая таблица — ноль каналов", 0, (int)g_dch_n);

                /* Поле family — «4», «6» или «46» (1.9, IPv6): все три принимаются целиком, без
                 * предупреждений, и ложатся в поле fam канала. */
                {
                    static const char v6only[] = "1\nsix_set|out1|0|6|six\n";
                    check("формат таблицы: family=6 — разбор не отказывает", 0,
                          tabfmt_parse(v6only, sizeof(v6only) - 1));
                    check("формат таблицы: family=6 — канал заведён", 1, (int)g_dch_n);
                    if (g_dch_n == 1)
                        check("формат таблицы: family=6 — только IPv6", DCH_V6, g_dch[0].fam);

                    static const char dual[] = "1\nboth_set|out1|0|46|both\n";
                    check("формат таблицы: family=46 — разбор не отказывает", 0,
                          tabfmt_parse(dual, sizeof(dual) - 1));
                    check("формат таблицы: family=46 — канал заведён", 1, (int)g_dch_n);
                    if (g_dch_n == 1) {
                        check("формат таблицы: family=46 — набор тот, что в строке", 0,
                              strcmp(g_dch[0].set, "both_set"));
                        check("формат таблицы: family=46 — оба семейства", DCH_V4 | DCH_V6,
                              g_dch[0].fam);
                    }
                    static const char v4[] = "1\nfour_set|out1|0|4|four\n";
                    check("формат таблицы: family=4 — разбор не отказывает", 0,
                          tabfmt_parse(v4, sizeof(v4) - 1));
                    if (g_dch_n == 1)
                        check("формат таблицы: family=4 — только IPv4", DCH_V4, g_dch[0].fam);

                    /* Ни «4», ни «6», ни «46» — испорченный текст, а не неизвестное будущее
                     * значение: формат обязан отказать, а не молча решить что-нибудь за
                     * будущего автора протокола. */
                    static const char badfam[] = "1\nx|out1|0|5|x\n";
                    check("формат таблицы: family=5 — отказ", -1,
                          tabfmt_parse(badfam, sizeof(badfam) - 1));

                    /* Пусто на следующий блок стенда, как и выше. */
                    tabfmt_parse("0\n", 2);
                }

                free(text);
                unlink(sp);
            }

            /* Те же два канала спекой v1: выход тот же, клиенты те же — и семейство то же, что у
             * v2, «46» у обоих (перевод v1 → v2 IPv6 не отнимает). */
            char sp1[] = "/tmp/dnsmatch-tab-v1.XXXXXX";
            int sf1 = mkstemp(sp1);
            if (sf1 >= 0) {
                FILE *ws = fdopen(sf1, "w");
                fprintf(ws,
                        "{\"schema\":1,"
                        "\"outputs\":{\"vpn\":{\"kind\":\"interface\",\"device\":\"lo\"}},"
                        "\"channels\":["
                        "{\"name\":\"web\",\"match\":{\"domains_files\":[\"%s\"]},\"out\":\"vpn\"},"
                        "{\"name\":\"srv\",\"match\":{\"domains_files\":[\"%s\",\"%s\"],"
                        "\"mode\":\"realip\"},\"out\":\"vpn\"}"
                        "]}\n", l1, l2, l1);
                fclose(ws);
                static struct spec cfg1;
                struct err e = {0};
                if (load_spec(sp1, &cfg1, &e) < 0) err_die(&e);
                char *text = NULL;
                size_t textlen = 0;
                FILE *mem = open_memstream(&text, &textlen);
                tabfmt_build(&cfg1, mem);
                fclose(mem);
                check("спека v1: два канала", 2, (int)g_dch_n);
                for (size_t i = 0; i < g_dch_n; i++)
                    check("спека v1: канал выхода с IPv6 — IPv4 и IPv6", DCH_V4 | DCH_V6, g_dch[i].fam);
                check("спека v1: строки каналов несут «|46|» (fake-IP и real-ip)", 1,
                      text && strstr(text, "|0|46|web") != NULL && strstr(text, "|1|46|srv") != NULL);
                free(text);
                /* g_dch держит указатели внутрь cfg1 — обнулить руками, как перед разбором
                 * выше, чтобы следующий tabfmt_parse не освобождал чужие строки. */
                for (size_t i = 0; i < g_dch_n; i++) free(g_dch[i].rules_path);
                memset(g_dch, 0, g_dch_cap * sizeof(*g_dch));
                g_dch_n = 0;
                unlink(sp1);
            }
            unlink(l1);
            unlink(l2);
        }
    }

    /* ---- fake-IP: пул, регистр, восстановление, флаги, срок элемента ------------- */
    {
        char dir[] = "/tmp/dnsmatch-fk.XXXXXX";
        if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }
        char path[768];
        snprintf(path, sizeof(path), "%s/state", dir);

        /* Срок элемента набора канала: TTL 0 — не «навечно». */
        check("срок элемента: TTL 0 даёт 1 с, не постоянный элемент", 1, (int)set_ttl_clamp(0));
        check("срок элемента: сутки — потолок", 86400, (int)set_ttl_clamp(86401));
        check("срок элемента: обычный TTL как есть", 300, (int)set_ttl_clamp(300));

        /* Адрес вне пула в файле состояния — брак строки, а не исчерпанный пул. */
        FILE *f = fopen(path, "w");
        fputs("bad.test\t203.0.113.5\n", f);
        fclose(f);
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        memset(&g_fakeip_idx, 0, sizeof(g_fakeip_idx));
        g_fakeip_next = 0;
        g_fakeip_state_path = NULL;
        fakeip_state_load(path);
        check("адрес вне пула в состоянии не загружен", 0, (int)g_fakeip.n);
        uint32_t addr = 0;
        check("после такой строки пул не исчерпан", 0, fakeip_lookup_or_alloc("new.test", &addr));
        check("и адрес выдан из пула", 1, addr >= FAKEIP_POOL_BASE && addr < FAKEIP_POOL_BASE + FAKEIP_POOL_SIZE);

        /* Регистр: ключ таблицы строчный независимо от вызывающего. */
        uint32_t a1 = 0, a2 = 0;
        fakeip_lookup_or_alloc("X.TEST", &a1);
        fakeip_lookup_or_alloc("x.test", &a2);
        check("X.TEST и x.test — один адрес", 1, a1 != 0 && a1 == a2);

        /* Восстановление без ядра: третье поле НЕ становится real_host. */
        f = fopen(path, "w");
        fputs("known.test\t198.18.0.7\t93.184.216.34\n", f);
        fclose(f);
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        memset(&g_fakeip_idx, 0, sizeof(g_fakeip_idx));
        g_fakeip_next = 0;
        fakeip_state_load(path);
        check("трёхполевая строка загружена", 1, (int)g_fakeip.n);
        size_t routed = 99;
        size_t restored = fakeip_rehydrate(-1, &routed);
        check("без netlink ничего не восстановлено", 0, (int)restored);
        check("и real_host сброшен — быстрый путь закрыт", 0, g_fakeip.n ? (int)(g_fakeip.entries[0].real_host != 0) : -1);
        check("маршруты без ядра не утверждались", 0, (int)routed);
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        memset(&g_fakeip_idx, 0, sizeof(g_fakeip_idx));
        g_fakeip_next = 0;
        unlink(path);
        rmdir(dir);

        /* Флаги синтетического ответа из ответа upstream: TC и AD не наследуются. */
        uint8_t up[64] = { 0x12, 0x34, 0x83, 0xA0, 0, 1, 0, 0, 0, 0, 0, 0,
                           1, 'a', 0, 0, 1, 0, 1 };
        size_t qend = 12 + 3 + 4;
        uint8_t out[512];
        size_t len = build_rewritten_response(up, qend, out, sizeof(out), 1, 0xC6120005u);
        check("ответ из upstream собран", 1, len > 0);
        check("TC снят", 0, out[2] & 0x02);
        check("AD снят", 0, out[3] & 0x20);
        check("QR стоит", 0x80, out[2] & 0x80);
    }

    /* ---- fake-IP v6 и real-ip v6 (docs/architecture.md, «4б») ---------------------------
     *
     * Пул fake-IP v6 — пара к IPv4: fdfe:dcba:9876::/96 и поддельный IPv4 в младших 32 битах.
     * Проверяется то, что ломается молча: пара совпадает в обе стороны, у записи один и тот же
     * адрес на оба семейства, первый выданный — не адрес сети; файл состояния с четвёртым полем
     * читается и пишется, прежний формат — тоже, испорченный IPv6 не губит строку; разбор AAAA
     * ответа и сборка ответа с поддельным IPv6. */
    {
        uint8_t a6[16];
        fakeip6_of(0xC6120005u, a6);
        char s6[INET6_ADDRSTRLEN] = "";
        inet_ntop(AF_INET6, a6, s6, sizeof(s6));
        check_str("fake6: пара 198.18.0.5", "fdfe:dcba:9876::c612:5", s6);
        check("fake6: обратно — тот же IPv4", 1, fakeip6_to4(a6) == 0xC6120005u);
        uint8_t other[16];
        inet_pton(AF_INET6, "fdfe:dcba:9876::c0a8:1", other);
        check("fake6: адрес префикса вне 198.18/15 — не поддельный", 0, (int)fakeip6_to4(other));
        inet_pton(AF_INET6, "2001:db8::c612:5", other);
        check("fake6: чужой префикс — не поддельный", 0, (int)fakeip6_to4(other));

        memset(&g_fakeip, 0, sizeof(g_fakeip));
        memset(&g_fakeip_idx, 0, sizeof(g_fakeip_idx));
        g_fakeip_next = 1;
        g_fakeip_state_path = NULL;
        uint32_t a = 0;
        fakeip_lookup_or_alloc("v6.test", &a);
        fakeip6_of(a, a6);
        check("fake6: первая выдача — не адрес сети пула", 1, a6[15] != 0 || a6[14] != 0);
        check("fake6: у записи ещё нет настоящего IPv6", 1, fakeip_entry_get_real6("v6.test") == NULL);
        uint8_t r6[16];
        inet_pton(AF_INET6, "2001:db8::77", r6);
        fakeip_entry_set_real6("v6.test", r6);
        const uint8_t *got6 = fakeip_entry_get_real6("v6.test");
        check("fake6: настоящий IPv6 запомнен", 1, got6 && !memcmp(got6, r6, 16));
        check("fake6: IPv4 записи не тронут", 0, (int)fakeip_entry_get_real("v6.test"));

        char dir[] = "/tmp/dnsmatch-f6.XXXXXX";
        if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }
        char path[768];
        snprintf(path, sizeof(path), "%s/fakeip.state", dir);
        g_fakeip_state_path = path;
        fakeip_state_rewrite();
        FILE *f = fopen(path, "r");
        char line[512] = "";
        if (f) { if (!fgets(line, sizeof(line), f)) line[0] = '\0'; fclose(f); }
        char want[256];
        struct in_addr ia; ia.s_addr = htonl(a);
        snprintf(want, sizeof(want), "v6.test\t%s\t-\t2001:db8::77\n", inet_ntoa(ia));
        check_str("состояние: строка с IPv6 и без IPv4 — «-» на месте IPv4", want, line);

        f = fopen(path, "w");
        fputs("old.test\t198.18.0.9\t93.184.216.34\n"
              "both.test\t198.18.0.10\t93.184.216.35\t2001:db8::a\n"
              "only6.test\t198.18.0.11\t-\t2001:db8::b\n"
              "bad6.test\t198.18.0.12\t93.184.216.36\tне-адрес\n", f);
        fclose(f);
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        memset(&g_fakeip_idx, 0, sizeof(g_fakeip_idx));
        g_fakeip_next = 1;
        fakeip_state_load(path);
        check("состояние: все четыре строки загружены", 4, (int)g_fakeip.n);
        check("состояние: прежняя трёхполевая — IPv4 есть, IPv6 нет", 1,
              fakeip_entry_get_real("old.test") == 0x5DB8D822u && !fakeip_entry_get_real6("old.test"));
        uint8_t w6[16];
        inet_pton(AF_INET6, "2001:db8::a", w6);
        got6 = fakeip_entry_get_real6("both.test");
        check("состояние: четырёхполевая — оба настоящих", 1,
              fakeip_entry_get_real("both.test") == 0x5DB8D823u && got6 && !memcmp(got6, w6, 16));
        check("состояние: «-» — IPv4 не известен, IPv6 есть", 1,
              fakeip_entry_get_real("only6.test") == 0 && fakeip_entry_get_real6("only6.test"));
        check("состояние: испорченный IPv6 — строка цела, IPv4 есть", 1,
              fakeip_entry_get_real("bad6.test") == 0x5DB8D824u && !fakeip_entry_get_real6("bad6.test"));
        size_t routed = 0;
        fakeip_rehydrate(-1, &routed);
        check("восстановление без ядра: настоящий IPv6 сброшен — быстрый путь AAAA закрыт", 1,
              !fakeip_entry_get_real6("both.test") && !fakeip_entry_get_real6("only6.test"));
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        memset(&g_fakeip_idx, 0, sizeof(g_fakeip_idx));
        g_fakeip_next = 1;
        g_fakeip_state_path = NULL;
        unlink(path);
        rmdir(dir);

        /* Ответ апстрима с A и двумя AAAA: A считаются как прежде, AAAA — отдельно. */
        uint8_t resp[160] = { 0x12, 0x34, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0,
                              1, 'a', 0, 0, 28, 0, 1 };
        size_t pos = 19;
        static const uint8_t rr_a[] = { 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4 };
        memcpy(resp + pos, rr_a, sizeof(rr_a)); pos += sizeof(rr_a);
        for (int k = 0; k < 2; k++) {
            static const uint8_t hd[] = { 0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 1, 0, 0, 16 };
            memcpy(resp + pos, hd, sizeof(hd)); pos += sizeof(hd);
            uint8_t ad[16];
            inet_pton(AF_INET6, k ? "2001:db8::2" : "2001:db8::1", ad);
            memcpy(resp + pos, ad, 16); pos += 16;
        }
        char qn[MAX_HOSTNAME];
        uint16_t qt = 0;
        size_t qe = 0;
        struct answer_ip ips[4];
        struct answer_ip6 ips6[4];
        int n6 = -1;
        int n4 = parse_response(resp, pos, qn, sizeof(qn), &qt, &qe, ips, 4, ips6, 4, &n6);
        check("AAAA: записей A — одна", 1, n4);
        check("AAAA: записей AAAA — две", 2, n6);
        uint8_t w2[16];
        inet_pton(AF_INET6, "2001:db8::2", w2);
        check("AAAA: второй адрес и срок", 1, n6 == 2 && !memcmp(ips6[1].addr, w2, 16) &&
                                             ips6[1].ttl == 256);
        check("AAAA: тип вопроса", 28, qt);
        uint8_t out[512];
        size_t len = build_rewritten_response6(resp, qe, out, sizeof(out), a6);
        check("ответ с fake6: длина — вопрос и одна запись AAAA", (int)(qe + 28), (int)len);
        check("ответ с fake6: одна запись", 1, len ? out[7] : -1);
        check("ответ с fake6: тип AAAA, длина 16", 1,
              len && out[qe + 3] == 28 && out[qe + 11] == 16 && !memcmp(out + qe + 12, a6, 16));

        /* Половина IPv6 имени: все совпавшие каналы обязаны её нести. */
        dch_zero(3);
        g_dch_n = 3;
        g_dch[0].fam = DCH_V4 | DCH_V6;
        g_dch[1].fam = DCH_V4 | DCH_V6;
        g_dch[2].fam = DCH_V4;
        check("dch_all_v6: оба канала с IPv6", 1, dch_all_v6(chm2(0, 1)));
        check("dch_all_v6: среди совпавших канал без IPv6 — нет", 0, dch_all_v6(chm2(0, 2)));
        check("dch_all_v6: пусто — нет", 0, dch_all_v6(0));
        memset(g_dch, 0, g_dch_cap * sizeof(*g_dch));
        g_dch_n = 0;
    }

    /* ---- ожидания: номер транзакции и отпечаток вопроса ----------------------------
     *
     * Два свойства, на которых держится «ответ попал к тому, кто спрашивал». Оба прежде
     * не проверялись ничем, и оба ломаются ТИХО: клиент получает чужой адрес, а в журнале
     * ни строки.
     *
     * 1. Номер транзакции составной: младшие биты — слот, старшие — поколение. Раскладка
     *    менялась (было 8+8, стало 10+6), и круг «собрать — разобрать» обязан сходиться
     *    для КАЖДОГО слота, иначе ответ уедет в чужое ожидание.
     * 2. Отпечаток вопроса: поколение шестибитное и когда-нибудь повторится, поэтому
     *    настоящая защита — в том, что ответ несёт тот же вопрос, что мы задали. */
    {
        int bad_round = 0;
        for (int i = 0; i < MAX_PENDING; i++) {
            for (unsigned g = 0; g < 4; g++) {
                g_pending[i].gen = (uint8_t)(g * 17);
                uint16_t tag = pending_tag(&g_pending[i]);
                if ((tag & PENDING_IDX_MASK) != (unsigned)i) bad_round++;
                if (((tag >> PENDING_IDX_BITS) & PENDING_GEN_MASK) !=
                    (g_pending[i].gen & PENDING_GEN_MASK)) bad_round++;
            }
        }
        check("номер транзакции: слот и поколение разбираются обратно у всех мест",
              0, bad_round);
        check("мест в таблице ожиданий хватает медленному резолверу", 1,
              MAX_PENDING / PENDING_TTL_SEC >= 200);
        memset(g_pending, 0, sizeof(g_pending));

        /* А ТЕПЕРЬ ГЛАВНОЕ, чего круг выше поймать не мог: он сравнивал обе стороны уже
         * усечёнными, а на приёме сравнивается ЦЕЛОЕ поле p->gen с шестью битами из
         * номера. Пока поколение писалось в слот целым байтом, всякое значение от 64 и
         * выше не совпадало ни с чем: ответ сверху отбрасывался молча, клиент ждал
         * таймаута и спрашивал заново — те самые «5-7 секунд на резолв» на живом
         * роутере, где счётчик поколений уходит за 64 за первую же сотню запросов.
         *
         * Поэтому проверка идёт по ВСЕМУ кругу счётчика и повторяет обе стороны
         * дословно: слева — присваивание из handle_client_query, справа — сравнение из
         * handle_upstream_response. */
        int bad_gen = 0;
        g_gen_next = 0;
        for (int round = 0; round < 256; round++) {
            struct pending *p = &g_pending[round % MAX_PENDING];
            p->gen = pending_next_gen();
            uint16_t tag = pending_tag(p);
            if (p->gen != (uint8_t)((tag >> PENDING_IDX_BITS) & PENDING_GEN_MASK))
                bad_gen++;
        }
        check("поколение слота переживает весь круг счётчика (0..255)", 0, bad_gen);
        g_gen_next = 0;
        memset(g_pending, 0, sizeof(g_pending));

        /* Два РАЗНЫХ вопроса в одном слоте с одним поколением — ровно тот случай, ради
         * которого отпечаток и заведён: по номеру транзакции они неразличимы. */
        uint8_t q1[64] = { 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
                           3, 'w', 'w', 'w', 2, 'y', 'a', 0, 0, 1, 0, 1 };
        uint8_t q2[64] = { 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
                           3, 'w', 'w', 'w', 2, 'v', 'k', 0, 0, 1, 0, 1 };
        size_t qe = 12 + 8 + 4;
        uint16_t f1 = question_fp(q1, qe), f2 = question_fp(q2, qe);
        check("отпечаток вопроса: разные имена — разные отпечатки", 1, f1 != f2);
        check("отпечаток вопроса: одинаковые байты — один отпечаток", 1,
              f1 == question_fp(q1, qe));
        check("отпечаток вопроса: ненулевой (ноль значит «вопроса нет»)", 1, f1 != 0);

        /* Тип записи — часть вопроса: A и AAAA к одному имени это разные вопросы, и
         * перепутать их ответы значит отдать клиенту адрес не того семейства. */
        uint8_t q3[64];
        memcpy(q3, q1, sizeof(q3));
        q3[qe - 3] = 28;                        /* QTYPE A -> AAAA */
        check("отпечаток вопроса: тип записи учитывается", 1, question_fp(q3, qe) != f1);
    }

    /* ---- НАБОРЫ sing-box (.srs) У РЕЗОЛВЕРА ------------------------------------------------
     *
     * Путь к `.srs` — источник правил наравне с `.lst`: load_rules_into узнаёт набор по подписи
     * и берёт его имена; канал с srs_files получает у резолвера выбор клауз (dch_build), а у
     * составного набора — ещё и сужение каждой клаузы (часть правил со своим l4). Исключения
     * («x, но не y») — своя часть с правилами-исключениями. Файлы — tests/srs, запуск из корня. */
    {
        struct ruleset rs = {0};
        check("srs: путь к набору читается как список", 0,
              load_rules_into("tests/srs/discord.srs", &rs));
        check("srs: имя из набора совпадает", 1, ruleset_match(&rs, "discord.com"));
        check("srs: поддомен суффикса совпадает", 1, ruleset_match(&rs, "cdn.discordapp.com"));
        check("srs: чужое имя — нет", 0, ruleset_match(&rs, "notdiscord.com"));
        ruleset_free(&rs);
        memset(&rs, 0, sizeof(rs));
        check("srs: версия 1 (суффикс двумя ключами)", 0,
              load_rules_into("tests/srs/telegram-v1.srs", &rs));
        check("srs v1: само имя", 1, ruleset_match(&rs, "telegram.org"));
        check("srs v1: поддомен", 1, ruleset_match(&rs, "core.telegram.org"));
        ruleset_free(&rs);

        char sp[] = "/tmp/dnsmatch-srs-spec.XXXXXX";
        int sf = mkstemp(sp);
        if (sf >= 0) {
            FILE *ws = fdopen(sf, "w");
            fprintf(ws, "{\"schema\":1,"
                        "\"outputs\":{\"vl\":{\"kind\":\"interface\",\"device\":\"lo\"}},"
                        "\"channels\":["
                        "{\"name\":\"n\",\"match\":{\"srs_file\":\"tests/srs/dnsmixed.srs\"},"
                        "\"out\":\"vl\"}]}\n");
            fclose(ws);
            static struct spec cfg;
            struct err e = {0};
            if (load_spec(sp, &cfg, &e) < 0) err_die(&e);
            srs_concat_override = 1;
            dch_build(&cfg);
            check("srs: канал резолвера один (составной набор)", 1, (int)g_dch_n);
            check_str("srs: имя набора — составное", "vl_dom_c0_m", g_dch_n ? g_dch[0].set : "");
            check_str("srs: источник — клаузы имён с сужением",
                      "srs:0=udp/50000-65535,1=-,2=-:tests/srs/dnsmixed.srs",
                      g_dch_n && g_dch[0].rules_n ? g_dch[0].rules_path[0] : "");
            if (g_dch_n) {
                struct ruleset m;
                struct dpart *parts;
                size_t pn;
                int comp;
                check("srs: источники прочитаны", 0, dch_rules_load(&g_dch[0], &m, &parts, &pn, &comp));
                g_dch[0].rules = m;
                g_dch[0].parts = parts;
                g_dch[0].parts_n = pn;
                g_dch[0].composite = comp;
                check("srs: набор составной", 1, comp);
                check("srs: имя с сужением совпадает", 1, dch_matches(&g_dch[0], "a.voice.example"));
                check("srs: имя без сужения совпадает", 1, dch_matches(&g_dch[0], "plain.example"));
                check("srs: «и» с исключением — само имя совпадает", 1,
                      dch_matches(&g_dch[0], "www.excl.example"));
                check("srs: исключённое имя — нет", 0, dch_matches(&g_dch[0], "no.excl.example"));
                check("srs: чужое имя — нет", 0, dch_matches(&g_dch[0], "voice.example.com"));
                int udp = 0, full = 0;
                for (size_t k = 0; k < pn; k++) {
                    if (ruleset_match(&parts[k].rules, "a.voice.example") &&
                        parts[k].l4.proto == CH_PROTO_UDP) udp = 1;
                    if (ruleset_match(&parts[k].rules, "plain.example") &&
                        l4match_empty(&parts[k].l4)) full = 1;
                }
                check("srs: у имени с сужением часть udp", 1, udp);
                check("srs: у имени без сужения часть без сужения", 1, full);
                ruleset_free(&g_dch[0].rules);
                dch_parts_free(g_dch[0].parts, g_dch[0].parts_n);
                g_dch[0].parts = NULL;
                g_dch[0].parts_n = 0;
            }
            srs_concat_override = 0;
            dch_build(&cfg);
            check("srs без составных наборов: по каналу на сужение", 2, (int)g_dch_n);
            check_str("… первый — с сужением набора",
                      "srs:0:tests/srs/dnsmixed.srs", g_dch_n ? g_dch[0].rules_path[0] : "");
            srs_concat_override = -1;
            g_dch_n = 0;
            unlink(sp);
        }
    }

    /* ---- adguard_domain: фильтр AdGuard, собранный sing-box ---------------------------------
     *
     * tests/srs/adguard.srs собран `sing-box rule-set convert --type adguard` из adguard.txt —
     * все виды правил («||x^», «|x^», без якоря, со «*», без «^», hosts, регулярное выражение,
     * исключения «@@» и $important), то есть ровно та форма, в которой публикуются фильтры
     * AdGuard (splify2-lists#1): «важные» или «(блок-список и не исключения)». Вердикт резолвера
     * по каждому имени сверяется с вердиктом самого sing-box (adguard.oracle). */
    {
        char sp[] = "/tmp/dnsmatch-adg-spec.XXXXXX";
        int sf = mkstemp(sp);
        if (sf >= 0) {
            FILE *ws = fdopen(sf, "w");
            fprintf(ws, "{\"schema\":1,"
                        "\"outputs\":{\"vl\":{\"kind\":\"interface\",\"device\":\"lo\"}},"
                        "\"channels\":["
                        "{\"name\":\"a\",\"match\":{\"srs_file\":\"tests/srs/adguard.srs\"},"
                        "\"out\":\"vl\"}]}\n");
            fclose(ws);
            static struct spec cfg;
            struct err e = {0};
            if (load_spec(sp, &cfg, &e) < 0) err_die(&e);
            dch_build(&cfg);
            check("adguard: канал резолвера есть", 1, g_dch_n > 0);
            struct ruleset m;
            struct dpart *parts = NULL;
            size_t pn = 0;
            int comp = 0, n_ok = 0, n_all = 0;
            FILE *o = fopen("tests/srs/adguard.oracle", "r");
            if (g_dch_n && o && dch_rules_load(&g_dch[0], &m, &parts, &pn, &comp) == 0) {
                g_dch[0].rules = m;
                g_dch[0].parts = parts;
                g_dch[0].parts_n = pn;
                g_dch[0].composite = comp;
                char line[256], name[200];
                int want;
                while (fgets(line, sizeof(line), o)) {
                    if (line[0] == '#' || sscanf(line, "%199s %d", name, &want) != 2) continue;
                    n_all++;
                    int got = dch_matches(&g_dch[0], name);
                    if (got == want) n_ok++;
                    else printf("  adguard: %s — sing-box %d, резолвер %d\n", name, want, got);
                }
                ruleset_free(&g_dch[0].rules);
                dch_parts_free(g_dch[0].parts, g_dch[0].parts_n);
                g_dch[0].parts = NULL;
                g_dch[0].parts_n = 0;
            }
            if (o) fclose(o);
            check("adguard: эталон прочитан", 1, n_all >= 40);
            check("adguard: вердикты совпадают с sing-box", n_all, n_ok);
            g_dch_n = 0;
            unlink(sp);
        }
    }

    /* ---- пределы без причины (I-523): больше прежнего предела работает ---- */
    {
        /* Журнал имён: 3000 свежих имён — больше прежних 256 — остаются все. */
        for (int i = 0; i < 3000; i++) {
            char nm[64];
            snprintf(nm, sizeof(nm), "Name%d.Example.com", i);
            dlog_note(nm, -1);
        }
        check("журнал имён: 3000 свежих имён хранятся все (прежний предел 256)", 3000, (int)dlog_count());
        dlog_note("name5.example.com", -1);
        check("журнал имён: повторный вопрос не плодит запись", 3000, (int)dlog_count());

        /* real-ip: 5000 разных элементов (прежний предел 2048) и повтор без роста. */
        for (int i = 0; i < 5000; i++) {
            char nm[64];
            snprintf(nm, sizeof(nm), "ri%d.example.com", i);
            realip_note(nm, 0x0a000000u + (uint32_t)i, 300);
        }
        realip_note("ri7.example.com", 0x0a000000u + 7u, 600);
        check("real-ip: 5000 элементов помнятся все (прежний предел 2048)", 5000, (int)realip_count());
        uint8_t a6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
        realip_note6("ri7.example.com", a6, 300);
        check("real-ip: адрес другого семейства — своя запись", 5001, (int)realip_count());

        /* Разбор ответа: 100 записей A и 100 AAAA — прежде собирались 32 и 16. */
        static uint8_t big[8192];
        memset(big, 0, sizeof(big));
        big[0] = 0x12; big[1] = 0x34; big[2] = 0x81; big[3] = 0x80; big[5] = 1;
        big[7] = 100;
        memcpy(big + 12, "\3big\4test\0\0\1\0\1", 14);
        size_t bp = 12 + 14;
        for (int i = 0; i < 100; i++) {
            static const uint8_t h[] = { 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4 };
            memcpy(big + bp, h, sizeof(h)); bp += sizeof(h);
            big[bp++] = 10; big[bp++] = 0; big[bp++] = 0; big[bp++] = (uint8_t)i;
        }
        char bq[MAX_HOSTNAME];
        uint16_t bt = 0;
        size_t be = 0;
        struct answer_ip bips[128];
        struct answer_ip6 bips6[8];
        int bn6 = 0;
        int bn4 = parse_response(big, bp, bq, sizeof(bq), &bt, &be, bips, 128, bips6, 8, &bn6);
        check("разбор ответа: 100 записей A собраны все (прежний предел 32)", 100, bn4);
        check("разбор ответа: последняя запись цела", 1, bn4 == 100 && ((bips[99].addr >> 24) & 0xff) == 99);

        /* Кэш ответов: ответ на 3 КБ (больше 1232) кладётся и достаётся. */
        struct dcache_cfg dc = { 64, 1, 3600, 60 };
        dcache_config(&dc);
        int an = 190;
        static uint8_t cb[8192];
        memset(cb, 0, sizeof(cb));
        cb[0] = 0x22; cb[1] = 0x33; cb[2] = 0x81; cb[3] = 0x80; cb[5] = 1; cb[7] = (uint8_t)an;
        memcpy(cb + 12, "\3big\4test\0\0\1\0\1", 14);
        size_t cp = 26;
        for (int i = 0; i < an; i++) {
            static const uint8_t h[] = { 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 0, 0, 4 };
            memcpy(cb + cp, h, sizeof(h)); cp += sizeof(h);
            cb[cp++] = 10; cb[cp++] = 1; cb[cp++] = 0; cb[cp++] = (uint8_t)i;
        }
        check("кэш: ответ больше 1232 байт кладётся", 1, cp > 1232 && dcache_put(1, cb, cp, 1000));
        uint8_t qq[64] = { 0x44, 0x55, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        memcpy(qq + 12, "\3big\4test\0\0\1\0\1", 14);
        static uint8_t gb[8192];
        size_t gn = dcache_get(1, qq, 26, gb, sizeof(gb), 1010);
        check("кэш: большой ответ выдан целиком, с номером спрашивающего", 1,
              gn == cp && gb[0] == 0x44 && gb[1] == 0x55);
        dcache_flush();
    }

    /* ---- ОБЩИЙ ИНДЕКС КАНАЛОВ (I-536) ---------------------------------------------
     *
     * dch_match_mask ищет имя по одной таблице суффиксов всех каналов, а не проходом по каналам.
     * Сверка с прежним проходом (dch_matches по каждому каналу) на каналах всех видов правил:
     * доменные, точные, шаблоны, регулярные выражения, части с исключениями и без; на именах
     * из совпадающих, чужих и граничных (подстрока без точки, регистр, глубокие поддомены). */
    {
        static const char *const c0[] = { "youtube.com", "=exact.example.org", "Deep.Sub.Example.NET", NULL };
        static const char *const c1[] = { "youtube.com", "example.net", "=only.here.io", NULL };
        static const char *const c2[] = { "*.wild.example.com", "re:^r[0-9]+\\.regex\\.io$", "plain.org", NULL };
        static const char *const c3[] = { "partA.com", "shared.test", NULL };
        static const char *const c3x[] = { "bad.partA.com", NULL };
        static const char *const c4[] = { "shared.test", "last.example", NULL };
        dch_zero(5);
        g_dch_n = 5;
        for (size_t i = 0; i < 5; i++) snprintf(g_dch[i].set, sizeof(g_dch[i].set), "ch%zu", i);
        build(&g_dch[0].rules, c0);
        build(&g_dch[1].rules, c1);
        build(&g_dch[2].rules, c2);
        g_dch[3].parts = calloc(1, sizeof(struct dpart));
        g_dch[3].parts_n = 1;
        build(&g_dch[3].parts[0].rules, c3);
        build(&g_dch[3].parts[0].excl, c3x);
        g_dch[3].parts[0].has_excl = 1;
        build(&g_dch[4].rules, c4);
        static const char *const names[] = {
            "youtube.com", "www.youtube.com", "notyoutube.com", "ube.com", "YOUTUBE.COM", "a.b.c.youtube.com",
            "exact.example.org", "x.exact.example.org", "only.here.io", "a.only.here.io", "example.net",
            "deep.sub.example.net", "x.deep.sub.example.net", "sub.example.net", "q.wild.example.com",
            "wild.example.com", "r12.regex.io", "xr12.regex.io", "plain.org", "a.plain.org", "partA.com",
            "x.partA.com", "bad.partA.com", "y.bad.partA.com", "shared.test", "a.shared.test", "last.example",
            "unknown.invalid", "com", "", "a", NULL };
        int same = 1, any = 0;
        for (size_t i = 0; names[i]; i++) {
            chm_t want = 0;
            for (size_t c = 0; c < g_dch_n; c++)
                if (dch_matches(&g_dch[c], names[i])) want = chm_or(want, chm_one(c));
            chm_t got = dch_match_mask(names[i]);
            if (got != want) { same = 0; printf("  расхождение на «%s»: %u против %u\n", names[i], got, want); }
            if (want) any++;
        }
        check("общий индекс: набор каналов тот же, что у прохода по каждому", 1, same);
        check("общий индекс: сверка не пустая (совпавших имён > 10)", 1, any > 10);
        check("общий индекс: shared.test — оба канала (часть и обычный)", 1,
              dch_match_mask("a.shared.test") == chm2(3, 4));
        check("общий индекс: исключение части работает (bad.partA.com — мимо)", 0,
              (int)dch_match_mask("bad.partA.com"));
        check("общий индекс: точное — только само имя", 1,
              dch_match_mask("exact.example.org") != 0 && dch_match_mask("x.exact.example.org") == 0);

        /* Смена правил сбрасывает индекс: имя, добавленное после первого подбора, находится. */
        check("общий индекс: имени ещё нет", 0, (int)dch_match_mask("late.added.test"));
        ruleset_add(&g_dch[1].rules, (char[]){ "added.test" });
        check("общий индекс: правило добавлено — имя находится", 1,
              dch_match_mask("late.added.test") == chm_one(1));
        ruleset_free(&g_dch[1].rules);
        check("общий индекс: набор освобождён — имя не находится", 0, (int)dch_match_mask("late.added.test"));

        /* Много каналов и много правил: счёт тот же, что у прохода (число каналов не ограничено). */
        dch_zero(300);
        g_dch_n = 300;
        int ok300 = 1;
        for (size_t i = 0; i < 300; i++) {
            char nm[64];
            snprintf(g_dch[i].set, sizeof(g_dch[i].set), "c%zu", i);
            memset(&g_dch[i].rules, 0, sizeof(g_dch[i].rules));
            snprintf(nm, sizeof nm, "d%zu.big.test", i);
            ruleset_add(&g_dch[i].rules, nm);
            snprintf(nm, sizeof nm, "common.big.test");
            ruleset_add(&g_dch[i].rules, nm);
        }
        for (size_t i = 0; i < 300; i += 37) {
            char nm[64];
            snprintf(nm, sizeof nm, "www.d%zu.big.test", i);
            if (dch_match_mask(nm) != chm_one(i)) ok300 = 0;
        }
        chm_t allm = dch_match_mask("x.common.big.test");
        for (size_t i = 0; i < 300; i++) if (!chm_has(allm, i)) ok300 = 0;
        check("общий индекс: 300 каналов, имя в каждом — набор из 300", 1, ok300);
    }

    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
