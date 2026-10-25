/* Скачивание и обработка подписки: то, что раньше жило в оболочке и не проверялось ничем.
 *
 * ЗАЧЕМ ЭТОТ СТЕНД. Работа с подпиской целиком состоит из чужих данных: заголовки ответа
 * пишет панель, MAC приходит от ядра, название подписки приезжает в base64, остаток трафика
 * — числами, которым никто не гарантировал формат. И каждая ошибка здесь молчаливая по
 * построению:
 *
 *   * ИДЕНТИФИКАТОР УСТРОЙСТВА. Изменился на один шаг — и каждый уже заведённый роутер стал
 *     для панели новым устройством. Человек теряет слот и не понимает, почему; подписка при
 *     этом «скачивается», просто вместо узлов приезжает заглушка. Сам идентификатор считает
 *     src/tools/hwid.c, и его значение сверяет с `sha256sum` стенд tests/hwidmatch.sh; здесь —
 *     то, что подписка его называет и отправляет.
 *
 *   * ТОЧКА ОТСЧЁТА ПЕРИОДА. Панель сообщает только конец срока и накопленный расход, а
 *     «в среднем в сутки» считается по двум наблюдениям. Сбросить точку отсчёта не вовремя —
 *     значит показать человеку темп расхода, набранный за минуту, и обещать, что трафик
 *     кончится завтра.
 *
 *   * ПОВТОР ЗА ДРУГИМ ФОРМАТОМ. Панели выбирают формат ответа по клиенту, и списка ссылок
 *     vless:// среди вариантов может не быть ни одного. Не попросив JSON, движок объявляет
 *     исправную подписку пустой.
 *
 * КАК ЭТО ПРОВЕРЯЕТСЯ БЕЗ СЕТИ И БЕЗ КРИПТОБИБЛИОТЕКИ. Файл включает исходник (тот же приём,
 * что в submatch.c и dnsmatch.c) и подставляет свой http_get: клиент libsteer (httpc.c) здесь не
 * линкуется, а его заглушка отдаёт заранее заданные статус, заголовки и тело из файлов песочницы и
 * записывает, что у неё попросили (метод, заголовки запроса). Сам клиент — со всеми переадресациями,
 * cookie, сроками и chunked — проверяет tests/httpmatch.c на настоящем сокете. SHA-256 у
 * идентификатора свой (src/tools/hwid.c), библиотеки он не требует.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

/* Идентификатор и описание устройства переехали в src/tools/hwid.c (он входит и в базовую
 * сборку). Стенд подключает его напрямую — так же, как подключает subfetch.c: проверять
 * чистку значений заголовков надо там, где она живёт, а не через второй экземпляр. */
#include "jsonw.h"
#include "../src/tools/hwid.c"
#include "../src/proto/vless/subfetch.c"
/* base64 названия подписки и разбор узлов — из sub.c, той же функцией, которой их читает
 * подъём туннеля. Исходник включается тем же приёмом; криптобиблиотеки он не требует. */
#include "../src/proto/vless/sub.c"
#include "../src/proto/vless/vless_proto.c"

static int g_pass, g_fail;

static void ck(const char *what, const char *want, const char *got) {
    if (want && got && !strcmp(want, got)) { g_pass++; return; }
    g_fail++;
    printf("FAIL %s\n  ожидалось: %s\n  получено:  %s\n", what,
           want ? want : "(null)", got ? got : "(null)");
}

static void ck_num(const char *what, long long want, long long got) {
    char a[32], b[32];
    snprintf(a, sizeof a, "%lld", want);
    snprintf(b, sizeof b, "%lld", got);
    ck(what, a, b);
}

static void ck_true(const char *what, int cond) {
    ck(what, "да", cond ? "да" : "нет");
}

/* ---- песочница --------------------------------------------------------------------- */

static char T[256];

static void wr(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if (!f) { printf("FAIL не открылся %s\n", path); g_fail++; return; }
    fputs(text, f);
    fclose(f);
}

static char *rd(const char *path) {
    static char buf[8192];
    buf[0] = 0;
    FILE *f = fopen(path, "r");
    if (!f) return buf;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    buf[n] = 0;
    fclose(f);
    return buf;
}

static void mkiface(const char *name, const char *mac, int physical) {
    char p[512];
    snprintf(p, sizeof p, "%s/sys/%s", T, name);
    mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/sys/%s/address", T, name);
    char v[64];
    snprintf(v, sizeof v, "%s\n", mac);
    wr(p, v);
    if (physical) {
        snprintf(p, sizeof p, "%s/sys/%s/device", T, name);
        wr(p, "");
    }
}


/* Перехват stdout: ответы команд — это JSON в stdout, и проверять их надо целиком. */
static int g_stdout_saved = -1;
static char *cap(int (*fn)(void)) {
    char path[512];
    snprintf(path, sizeof path, "%s/out.json", T);
    fflush(stdout);
    g_stdout_saved = dup(1);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    dup2(fd, 1);
    close(fd);
    fn();
    fflush(stdout);
    dup2(g_stdout_saved, 1);
    close(g_stdout_saved);
    return rd(path);
}

/* Есть ли подстрока — самый прямой способ спросить про поле JSON, не заводя разборщик
 * JSON в стенде движка. */
static int has(const char *hay, const char *needle) { return strstr(hay, needle) != NULL; }

/* ---- идентификатор устройства: проверки переехали ----------------------------------
 *
 * Были здесь и ушли в tests/hwidmatch.sh вместе с самим кодом (src/tools/hwid.c). Причина не в
 * аккуратности: здесь они стояли на ПОДДЕЛЬНОМ sha256 и проверяли рецептуру по входу хеша —
 * «хешируется ровно splify2:<mac>, ни байтом больше». Это верная мысль при заглушке, но
 * слабее того, что можно проверить теперь: hwidmatch сверяет ГОТОВОЕ значение с `sha256sum`
 * оболочки, то есть с тем самым эталоном, которым идентификатор считался до движка. Лишний
 * байт на входе такую сверку валит точно так же, а вдобавок она ловит расхождение в самом
 * хешировании, которого заглушка не видела по построению. */

/* ---- проверки: заголовки ответа ---------------------------------------------------- */

static void t_headers(void) {
    char v[256];

    /* ПОСЛЕДНИЙ блок заголовков, а не первый: за перенаправлением приезжает второй, и
     * заголовки подписки лежат именно в нём — в первом только 30x и Location. */
    const char *two =
        "HTTP/1.1 302 Found\n"
        "Location: https://panel.example/sub\n"
        "profile-title: старое\n"
        "\n"
        "HTTP/1.1 200 OK\n"
        "Profile-Title: новое\n";
    v[0] = 0;
    hdr_get(two, "profile-title", v, sizeof v);
    ck("за перенаправлением берётся последний блок", "новое", v);

    /* Регистр имени заголовка не значит ничего: панели пишут их как хотят. */
    v[0] = 0;
    ck_true("имя заголовка регистронезависимо",
            hdr_get("X-HWID-Limit: 3\n", "x-hwid-limit", v, sizeof v));
    ck("значение обрезано от пробелов", "3", v);

    v[0] = 0;
    ck_true("чужого заголовка нет", !hdr_get("a: 1\n", "b", v, sizeof v));

    /* Имя, совпадающее с началом другого, не должно ловиться: `x-hwid` и
     * `x-hwid-not-supported` — разные вещи, и путать их значит объявить заглушкой исправный
     * ответ. */
    v[0] = 0;
    ck_true("частичное совпадение имени не считается",
            !hdr_get("x-hwid-not-supported: 1\n", "x-hwid", v, sizeof v));
}

static void t_ui_field(void) {
    unsigned long long n = 0;
    const char *ui = "upload=100; download=200; total=300; expire=1900000000";
    ck_true("upload прочитан", ui_field(ui, "upload", &n)); ck_num("upload", 100, (long long)n);
    ck_true("download прочитан", ui_field(ui, "download", &n)); ck_num("download", 200, (long long)n);
    ck_true("total прочитан", ui_field(ui, "total", &n)); ck_num("total", 300, (long long)n);
    ck_true("expire прочитан", ui_field(ui, "expire", &n)); ck_num("expire", 1900000000, (long long)n);
    ck_true("чужого поля нет", !ui_field(ui, "quota", &n));

    /* Только цифры. Панель отдаёт байты и unix-время; «unlimited» — чужое соглашение,
     * которое мы не читаем, и принять его за число значило бы показать остаток, которого
     * нет. */
    ck_true("не-число не считается числом", !ui_field("total=unlimited", "total", &n));
    /* Переполнение — это «числу верить нельзя», а не «число большое». */
    ck_true("переполнение отвергается",
            !ui_field("total=99999999999999999999999", "total", &n));
    /* Имя поля целиком, а не по началу: `total` и `totals` — разные поля. */
    ck_true("имя поля сверяется целиком", !ui_field("totals=5", "total", &n));
}

static void t_title(void) {
    char t[64];

    /* base64 с приставкой — так отдают Marzban, Remnawave и 3x-ui. Раскодируется той же
     * функцией, которой движок читает саму подписку; в оболочке ради этой одной строки
     * жила своя реализация base64 на awk. */
    sub_title("profile-title: base64:0KDQvtGB0YHQuNGP\n", t, sizeof t);
    ck("название из base64", "Россия", t);

    sub_title("profile-title: Riot VPN\n", t, sizeof t);
    ck("название открытым текстом", "Riot VPN", t);

    /* Запасной путь: часть панелей называет подписку только так. */
    sub_title("content-disposition: attachment; filename=\"Riot VPN\"\n", t, sizeof t);
    ck("название из content-disposition", "Riot VPN", t);

    /* Кавычки и управляющие символы вон: строка уедет в uci и в JSON. */
    sub_title("profile-title: a\"b\\c\n", t, sizeof t);
    ck("кавычки и обратный слэш убраны", "abc", t);

    sub_title("x-other: 1\n", t, sizeof t);
    ck("панель промолчала — названия нет", "", t);

    /* Обрезка по границе кодовой точки: половина буквы выглядит как поломка панели, а не как
     * длинное имя. Строка ниже длиннее предела в 48 байт ровно на середине буквы. */
    sub_title("profile-title: "
              "ААААААААААААААААААААААААААААААА\n", t, sizeof t);
    ck_true("обрезано по границе буквы", strlen(t) % 2 == 0);
    ck_true("и не длиннее предела", strlen(t) <= 48);
}

static void t_warn(void) {
    const char *w;
    w = device_warn("x-hwid-not-supported: 1\n", 1);
    ck_true("панель не увидела идентификатора — сказано", w && strstr(w, "заглушку"));
    w = device_warn("x-hwid-limit: 3\n", 1);
    ck_true("лимит устройств — сказано", w && strstr(w, "слот"));
    w = device_warn("", 0);
    ck_true("идентификатор не ушёл — сказано", w && strstr(w, "не ушёл"));
    w = device_warn("", 1);
    ck_true("сказать нечего — молчим", w == NULL);
}

/* ---- проверки: остаток трафика и точка отсчёта -------------------------------------- */

static void t_quota(void) {
    char info[512];
    snprintf(info, sizeof info, "%s/sub.userinfo", T);
    unlink(info);
    struct quota q;

    const char *h1 = "subscription-userinfo: upload=10; download=20; total=1000; expire=1900000000\n";
    ck_true("числа панели запомнены", quota_save(info, h1, 0, &q));
    ck_num("расход на момент первого наблюдения", 30, (long long)q.used0);
    long long at0 = q.at0;
    ck_true("точка отсчёта поставлена", q.has_at0 && at0 > 0);

    /* Тот же период: расход вырос, срок и объём те же. Точка отсчёта ОБЯЗАНА уцелеть —
     * иначе измеренный темп расхода, который набирается сутками, обнулялся бы при каждом
     * открытии обзора. */
    const char *h2 = "subscription-userinfo: upload=40; download=60; total=1000; expire=1900000000\n";
    quota_save(info, h2, 0, &q);
    ck_num("точка отсчёта уцелела", at0, q.at0);
    ck_num("и расход в ней прежний", 30, (long long)q.used0);

    /* Сменился срок — новый период. */
    const char *h3 = "subscription-userinfo: upload=40; download=60; total=1000; expire=1950000000\n";
    quota_save(info, h3, 0, &q);
    ck_num("смена срока начинает период заново", 100, (long long)q.used0);

    /* Сменился объём — сменился тариф, значит период тоже новый. */
    quota_save(info, h2, 0, &q);
    at0 = q.at0;
    const char *h4 = "subscription-userinfo: upload=40; download=60; total=2000; expire=1900000000\n";
    quota_save(info, h4, 0, &q);
    ck_num("смена объёма начинает период заново", 100, (long long)q.used0);

    /* Расход УМЕНЬШИЛСЯ — панель обнулила счётчик. Считать это тем же периодом значило бы
     * получить отрицательный темп расхода. */
    quota_save(info, h4, 0, &q);
    const char *h5 = "subscription-userinfo: upload=1; download=1; total=2000; expire=1900000000\n";
    quota_save(info, h5, 0, &q);
    ck_num("обнулённый счётчик начинает период заново", 2, (long long)q.used0);

    /* Заголовка нет — прежние числа СНИМАЮТСЯ. «Осталось 68 ГБ» на подписке, о которой
     * панель молчит, ничем не отличимо от правды и потому хуже честного незнания. */
    ck_true("панель промолчала — это не удача", !quota_save(info, "x: 1\n", 0, &q));
    ck("и файл снят", "", rd(info));

    /* А `keep` — это «спросили не до конца»: так зовёт проба заголовков, после которой при
     * неудаче будет обычная загрузка. Снимать прежние числа она права не имеет. */
    quota_save(info, h1, 0, &q);
    quota_save(info, "x: 1\n", 1, &q);
    ck_true("проба чужие числа не снимает", strstr(rd(info), "total=1000") != NULL);

    /* Заголовок есть, а смысла в нём нет: без объёма и без срока обзор нарисовал бы полосу
     * «осталось 0 из 0». Считаем это молчанием панели. */
    ck_true("заголовок без объёма и срока — молчание",
            !quota_save(info, "subscription-userinfo: upload=1; download=2\n", 0, &q));

    /* Пустое значение в файле — «панель этого не сообщала», и это не нуль: подписка без
     * ограничения объёма не должна выглядеть исчерпанной. */
    const char *h6 = "subscription-userinfo: upload=5; download=5; expire=1900000000\n";
    quota_save(info, h6, 0, &q);
    ck_true("объёма нет — в файле пусто, а не нуль", strstr(rd(info), "total=\n") != NULL);
    struct quota back;
    quota_read(info, &back);
    ck_true("и при чтении объём остаётся неназванным", !back.n.has_total);
    unlink(info);
}

/* ---- проверки: скачивание целиком, через заглушку клиента ---------------------------- */

/* Заглушка http_get (libsteer: httpc.h). Статус, заголовки и тело берёт из файлов песочницы по ключу
 * адреса (…/json — «json», остальное — «main»): rc.<ключ> — отказ клиента (сеть, срок), status.<ключ> —
 * статус вместо 200, hdr.<ключ>, body.<ключ>. Записывает в песочницу, чем и как спросили: метод
 * (seen.method), заголовки запроса (seen.headers) и число обращений (seen.count). Файл rej.hdr — панель
 * отвечает 403 на запрос с заголовками устройства (проверка повтора без них). */
int http_get(const struct http_req *q, struct http_resp *r, char *why, size_t wn) {
    memset(r, 0, sizeof *r);
    if (why && wn) why[0] = 0;
    char p[512];
    const char *key = strlen(q->url) >= 5 && !strcmp(q->url + strlen(q->url) - 5, "/json") ? "json" : "main";
    snprintf(p, sizeof p, "%s/seen.method", T);
    wr(p, q->method ? q->method : "GET");
    snprintf(p, sizeof p, "%s/seen.headers", T);
    wr(p, q->headers ? q->headers : "");
    snprintf(p, sizeof p, "%s/seen.count", T);
    int cnt = atoi(rd(p)) + 1;
    char cs[16];
    snprintf(cs, sizeof cs, "%d", cnt);
    wr(p, cs);

    snprintf(p, sizeof p, "%s/rc.%s", T, key);
    if (access(p, F_OK) == 0) { if (why) snprintf(why, wn, "заглушка: отказ"); return HTTPC_ECONNECT; }
    int status = 200;
    snprintf(p, sizeof p, "%s/status.%s", T, key);
    if (access(p, F_OK) == 0) status = atoi(rd(p));
    snprintf(p, sizeof p, "%s/rej.hdr", T);
    if (q->headers && strstr(q->headers, "x-hwid") && access(p, F_OK) == 0) status = 403;
    r->status = status;
    snprintf(p, sizeof p, "%s/hdr.%s", T, key);
    if (access(p, F_OK) == 0) {
        char *h = strdup(rd(p));
        size_t o = 0;
        for (size_t i = 0; h[i]; i++) if (h[i] != '\r') h[o++] = h[i];
        h[o] = 0;
        r->headers = h;
        r->headers_n = o;
    }
    int head = q->method && !strcmp(q->method, "HEAD");
    if (!head && q->dest_path && status / 100 == 2) {
        snprintf(p, sizeof p, "%s/body.%s", T, key);
        if (access(p, F_OK) != 0) { http_resp_free(r); return HTTPC_ECONNECT; }
        FILE *in = fopen(p, "rb"), *out = fopen(q->dest_path, "wb");
        char buf[4096];
        size_t n;
        while (in && out && (n = fread(buf, 1, sizeof buf, in)) > 0) fwrite(buf, 1, n, out);
        if (in) fclose(in);
        if (out) fclose(out);
    }
    return 0;
}
void http_resp_free(struct http_resp *r) {
    free(r->headers);
    free(r->url);
    free(r->etag);
    memset(r, 0, sizeof *r);
}

static void fixture(const char *key, const char *what, const char *text) {
    char p[512];
    snprintf(p, sizeof p, "%s/%s.%s", T, what, key);
    if (!text) { unlink(p); return; }
    wr(p, text);
}

static char g_url[512], g_out[512], g_info[512];
static int g_rc;
static int call_fetch(void) { return g_rc = cmd_sub_fetch(g_url, g_out, g_info); }
static int call_quota(void) { return g_rc = cmd_sub_quota(g_url, g_info); }

static void t_fetch(void) {
    mkiface("eth0", "c4:41:1e:dd:ee:01", 1);
    snprintf(g_out, sizeof g_out, "%s/sub.txt", T);
    snprintf(g_info, sizeof g_info, "%s/sub.userinfo", T);
    snprintf(g_url, sizeof g_url, "https://panel.example/sub");
    unlink(g_out); unlink(g_info);

    const char *LINKS =
        "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?"
        "type=tcp&security=reality&sni=a.example&pbk=Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDA&"
        "sid=ab12&flow=xtls-rprx-vision#\xd0\x9d\xd0\xbe\xd0\xb4\n";

    /* Обычная удача: тело на месте, заголовки прочитаны, узлы посчитаны той же функцией,
     * которой их читает подъём туннеля. */
    fixture("main", "body", LINKS);
    fixture("main", "hdr",
            "HTTP/1.1 200 OK\r\n"
            "profile-title: base64:0KDQvtGB0YHQuNGP\r\n"
            "subscription-userinfo: upload=1; download=2; total=1000; expire=1900000000\r\n");
    fixture("main", "rc", NULL);
    char *out = cap(call_fetch);
    ck_true("подписка скачана", has(out, "\"ok\":true"));
    ck_true("узел посчитан пригодным", has(out, "\"usable\":1"));
    ck_true("название взято у панели", has(out, "\"title\":\"Россия\""));
    ck_true("остаток трафика в том же ответе", has(out, "\"total\":\"1000\""));
    ck_true("идентификатор устройства назван", has(out, "\"hwid\":\"splify2-"));
    ck_true("и он ушёл в запрос", has(out, "\"hwid_sent\":true"));
    ck_true("файл узлов на месте", strstr(rd(g_out), "vless://") != NULL);
    ck_true("остаток записан рядом", strstr(rd(g_info), "total=1000") != NULL);

    /* КАК МЫ ПРЕДСТАВЛЯЕМСЯ ПАНЕЛИ. Имя в User-Agent и cookie-движок — дело клиента libsteer
     * (httpc.c: по умолчанию «steer/<версия>», cookie на время вызова; их проверяет httpmatch.c на
     * сокете), а здесь — что подписка ИХ НЕ ПЕРЕБИВАЕТ: чужое имя в заголовках запроса (v2rayNG,
     * Mozilla, curl) значило бы врать панели, которая считает устройства, и получать JSON вместо
     * списка ссылок. И что заголовки устройства ушли целиком. */
    char up[640], seen[1024];
    snprintf(up, sizeof up, "%s/seen.headers", T);
    snprintf(seen, sizeof seen, "%s", rd(up));
    ck_true("User-Agent подписка не ставит: имя — у клиента", !has(seen, "User-Agent") && !has(seen, "user-agent"));
    ck_true("идентификатор устройства уходит заголовком x-hwid", has(seen, "x-hwid: splify2-"));
    ck_true("и описание системы с моделью", has(seen, "x-device-os: OpenWrt 25.12.5") && has(seen, "x-ver-os: OpenWrt 25.12.5") &&
                                           has(seen, "x-device-model: Xiaomi AX3000T"));
    ck_true("заголовки разделены CRLF", has(seen, "\r\nx-device-os:"));
    snprintf(up, sizeof up, "%s/seen.method", T);
    ck("подписка — обычный GET", "GET", rd(up));

    /* Временные файлы убраны. Оставленный `.hdr` — это заголовки панели, лежащие в /etc
     * навсегда; оставленный `.tmp` — половина подписки, которую следующий запуск примет за
     * целую. */
    char p[640];
    snprintf(p, sizeof p, "%s.tmp", g_out);
    ck_true("временный файл убран", access(p, F_OK) != 0);
    snprintf(p, sizeof p, "%s.hdr", g_out);
    ck_true("заголовки не остались на диске", access(p, F_OK) != 0);

    /* ПОВТОР ЗА ДРУГИМ ФОРМАТОМ. Панель отдала заглушку — ссылки чужого протокола на
     * localhost, — то есть пригодных узлов нет ни одного. Тогда тот же адрес спрашивается с
     * суффиксом /json, и в ответе стоит именно та ссылка, по которой обновлять дальше. */
    fixture("main", "body", "ss://YWVzOnB3ZA==@127.0.0.1:1234#Неправильный клиент\n");
    fixture("json", "body",
            "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{"
            "\"address\":\"5.6.7.8\",\"port\":443,\"users\":[{"
            "\"id\":\"11111111-2222-3333-4444-555555555555\",\"flow\":\"xtls-rprx-vision\"}]}]},"
            "\"streamSettings\":{\"network\":\"tcp\",\"security\":\"reality\","
            "\"realitySettings\":{\"serverName\":\"a.example\","
            "\"publicKey\":\"Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDA\",\"shortId\":\"ab12\"}}}]}");
    fixture("json", "hdr", "HTTP/1.1 200 OK\r\nprofile-title: JSON\r\n");
    out = cap(call_fetch);
    ck_true("заглушка распознана и формат перезапрошен", has(out, "\"usable\":1"));
    ck_true("в ответе ссылка на /json", has(out, "/sub/json"));
    ck_true("и заголовки взяты от НЕГО", has(out, "\"title\":\"JSON\""));
    ck_true("файл — тот, что приехал вторым", strstr(rd(g_out), "outbounds") != NULL);

    /* Повтор не делается, если уже просили JSON: второй такой же запрос ничего не добавит, а
     * адрес вида «…/json/json» панель не знает вовсе. */
    snprintf(g_url, sizeof g_url, "https://panel.example/sub/json");
    fixture("json", "body", "ss://YWVzOnB3ZA==@127.0.0.1:1234#нет\n");
    out = cap(call_fetch);
    ck_true("у /json второго повтора нет", has(out, "\"usable\":0"));
    ck_true("и ссылка в ответе прежняя", has(out, "\"url\":\"https://panel.example/sub/json\""));

    /* Отказ панели НЕ ТРОГАЕТ прежнюю подписку: туннель работает по тому, что скачано, и
     * подменять рабочие узлы пустотой из-за упавшей сети нельзя. */
    snprintf(g_url, sizeof g_url, "https://panel.example/sub");
    wr(g_out, "vless://прежнее\n");
    fixture("main", "rc", "22");
    fixture("json", "rc", "22");
    out = cap(call_fetch);
    ck_true("отказ назван отказом", has(out, "\"ok\":false"));
    ck_true("прежняя подписка не тронута", strstr(rd(g_out), "прежнее") != NULL);
    fixture("main", "rc", NULL);
    fixture("json", "rc", NULL);

    /* Пустой ответ — тоже отказ, а не «скачали пустую подписку»: пустой файл узлов означает
     * туннель, который никуда не поднимется, причём молча. */
    fixture("main", "body", "");
    out = cap(call_fetch);
    ck_true("пустой ответ панели — отказ", has(out, "\"ok\":false"));
    ck_true("и прежняя подписка снова не тронута", strstr(rd(g_out), "прежнее") != NULL);

    /* Не ссылка — отказ до всякой работы: подставлять «https://» за человека значило бы
     * скачать не то, что он назвал. */
    snprintf(g_url, sizeof g_url, "panel.example/sub");
    /* Отказ уходит в stderr — там же, где движок отвечает всякому, кто позвал его неверно.
     * Строка в выводе стенда поэтому ожидаема и не означает провала. */
    cap(call_fetch);
    ck_num("адрес без схемы отвергается", 2, g_rc);

    /* Путь остатка трафика выводится из пути подписки тем же правилом, каким его выводит
     * splify2: иначе два файла разъехались бы по каталогам при переопределённом пути. */
    char derived[512];
    info_for("/etc/steer/sub.txt", derived, sizeof derived);
    ck("остаток лежит рядом с подпиской", "/etc/steer/sub.userinfo", derived);
    info_for("/etc/steer/subs/second", derived, sizeof derived);
    ck("а без «.txt» — просто рядом", "/etc/steer/subs/second.userinfo", derived);
}

/* ОТКАЗ ПАНЕЛИ НА ЗАГОЛОВКИ УСТРОЙСТВА. Защита перед панелью бывает недовольна лишним заголовком и
 * отвечает отказом именно на них; подписка без HWID лучше никакой, но человеку об этом говорится
 * (hwid_sent=false, а панель при заглушке — device_warn). Статус >= 400 — отказ, как у `curl -f`. */
static void t_reject(void) {
    snprintf(g_url, sizeof g_url, "https://panel.example/sub");
    char p[640];
    snprintf(p, sizeof p, "%s/seen.count", T);
    unlink(p);
    fixture("main", "rc", NULL);
    fixture("main", "body", "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?"
            "type=tcp&security=reality&sni=a.example&pbk=Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDA&sid=ab12#x\n");
    fixture("main", "hdr", "HTTP/1.1 200 OK\r\n");
    snprintf(p, sizeof p, "%s/rej.hdr", T);
    wr(p, "");
    char *out = cap(call_fetch);
    ck_true("панель отвергла заголовки устройства — подписка всё же скачана", has(out, "\"ok\":true"));
    ck_true("и сказано, что идентификатор не ушёл", has(out, "\"hwid_sent\":false"));
    snprintf(p, sizeof p, "%s/seen.count", T);
    ck("и было ровно два захода (с заголовками, без)", "2", rd(p));
    snprintf(p, sizeof p, "%s/seen.headers", T);
    ck("второй заход — без заголовков устройства", "", rd(p));
    snprintf(p, sizeof p, "%s/rej.hdr", T);
    unlink(p);

    /* 404 и прочее >= 400 — отказ, прежний файл не тронут, временный убран. */
    wr(g_out, "vless://прежнее\n");
    fixture("main", "status", "404");
    fixture("json", "status", "404");
    out = cap(call_fetch);
    ck_true("статус 404 — отказ", has(out, "\"ok\":false"));
    ck_true("прежняя подписка не тронута", strstr(rd(g_out), "прежнее") != NULL);
    snprintf(p, sizeof p, "%s.tmp", g_out);
    ck_true("временный файл убран", access(p, F_OK) != 0);
    fixture("main", "status", NULL);
    fixture("json", "status", NULL);
}

/* GZIP, О КОТОРОМ НЕ ПРОСИЛИ. Панель за nginx отдаёт тело сжатым при любом запросе, и curl без
 * --compressed кладёт в файл байты gzip: снято на живой подписке. Сжатие — настоящим gzip, а не
 * заготовкой: и с именем файла в заголовке (FNAME), и без него, как пишет поток. */
static void t_gzip(void) {
    snprintf(g_url, sizeof g_url, "https://panel.example/sub");
    const char *LINKS =
        "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?"
        "type=xhttp&security=reality&sni=a.example&pbk=Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDA&"
        "sid=ab12&mode=stream-one&path=/xhttp#gz\n";
    char src[512], cmd[2600];
    snprintf(src, sizeof src, "%s/plain.txt", T);
    wr(src, LINKS);
    fixture("main", "hdr", "HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\n");
    fixture("main", "rc", NULL);

    snprintf(cmd, sizeof cmd, "gzip -c '%s' > '%s/body.main'", src, T);
    if (system(cmd) != 0) { printf("  ПРОПУСК gzip: нет gzip на машине стенда\n"); return; }
    char *out = cap(call_fetch);
    ck_true("сжатое тело распаковано", has(out, "\"ok\":true") && has(out, "\"usable\":1"));
    ck("в файле узлов — ссылки, а не gzip", LINKS, rd(g_out));

    snprintf(cmd, sizeof cmd, "gzip -c < '%s' > '%s/body.main'", src, T);
    if (system(cmd) == 0) {
        out = cap(call_fetch);
        ck_true("gzip без имени файла — тоже", has(out, "\"usable\":1"));
    }

    /* Обрезанный gzip — отказ, и прежняя подписка цела: половина тела — половина узлов. */
    snprintf(cmd, sizeof cmd, "gzip -c '%s' | head -c 30 > '%s/body.main'", src, T);
    if (system(cmd) == 0) {
        wr(g_out, "vless://прежнее\n");
        out = cap(call_fetch);
        ck_true("обрезанный gzip — отказ", has(out, "\"ok\":false"));
        ck_true("прежняя подписка не тронута", strstr(rd(g_out), "прежнее") != NULL);
    }
    /* Испорченная сумма в хвосте — тоже отказ. */
    snprintf(cmd, sizeof cmd,
             "gzip -c '%s' > '%s/z' && n=$(wc -c < '%s/z') && head -c $((n-8)) '%s/z' > '%s/body.main' && "
             "printf '\\001\\002\\003\\004' >> '%s/body.main' && tail -c 4 '%s/z' >> '%s/body.main'",
             src, T, T, T, T, T, T, T);
    if (system(cmd) == 0) {
        out = cap(call_fetch);
        ck_true("неверный CRC-32 — отказ", has(out, "\"ok\":false"));
    }
}

static void t_quota_cmd(void) {
    snprintf(g_url, sizeof g_url, "https://panel.example/sub");
    snprintf(g_info, sizeof g_info, "%s/sub.userinfo", T);
    unlink(g_info);

    /* Проба заголовков телом не платит: HEAD отдаёт только заголовки, и подписка на десятки
     * узлов ради двух чисел не качается. */
    fixture("main", "hdr",
            "HTTP/1.1 200 OK\r\n"
            "subscription-userinfo: upload=7; download=3; total=500; expire=1900000000\r\n");
    fixture("main", "body", NULL);
    char *out = cap(call_quota);
    ck_true("остаток спрошен", has(out, "\"asked\":true"));
    ck_true("и получен", has(out, "\"total\":\"500\""));
    ck_true("подписка при этом не качалась", strstr(rd(g_info), "total=500") != NULL);

    /* Панель промолчала — это НЕ отказ команды: человек ничего не сделал не так, и код
     * возврата обязан остаться нулевым, иначе интерфейс покажет ошибку на исправной
     * настройке. */
    fixture("main", "hdr", "HTTP/1.1 200 OK\r\n");
    fixture("main", "body", "vless://x\n");
    out = cap(call_quota);
    ck_num("молчание панели — не отказ команды", 0, g_rc);
    ck_true("и об этом сказано словами", has(out, "не сообщила остаток"));

    /* Выбросные файлы пробы убраны: они лежат рядом с настройками, и оставленное тело
     * подписки следующий разбор мог бы принять за саму подписку. */
    char p[640];
    snprintf(p, sizeof p, "%s.probe", g_info);
    ck_true("выбросное тело убрано", access(p, F_OK) != 0);
    snprintf(p, sizeof p, "%s.head", g_info);
    ck_true("заголовки пробы убраны", access(p, F_OK) != 0);
}

/* ---- проверки: заголовки об устройстве ---------------------------------------------
 *
 * ЗАЧЕМ ЭТО ПРОВЕРЯТЬ. Значение уезжает в HTTP-заголовок, а модель роутера приходит из файла,
 * который пишет не наш код: перевод строки внутри значения — это вставка ЧУЖОГО заголовка в
 * запрос.
 *
 * И вторая причина, историческая. В оболочке чистка была написана как `tr -cd '[:print:]'`, и
 * это работает у coreutils, но НЕ у busybox: тот классов не знает и разбирает «[:print:]» как
 * обычный набор символов — то есть оставляет от строки только буквы, из которых составлено имя
 * класса. На роутере «TP-Link Archer C6U v1» превращалось в «inrr», а «OpenWrt 25.12.5» — в
 * «pnrt», и именно это уезжало в панель. Человек видел в списке устройств бессмыслицу и не мог
 * найти среди телефонов свой роутер — ровно то, ради чего эти заголовки и посылаются.
 *
 * Стенд на машине разработчика этого не замечал: на GNU tr обе строки проходят целиком.
 * Здесь такой ловушки нет по построению — байты сравниваются напрямую. */
static void t_device_hdrs(void) {
    char v[80];
    char p[512];

    steer_dev_os(v, sizeof v);
    ck("версия системы не искажается чисткой", "OpenWrt 25.12.5", v);
    steer_dev_model(v, sizeof v);
    ck("модель не искажается чисткой", "Xiaomi AX3000T", v);

    /* Кириллица выбрасывается намеренно: в заголовке HTTP она приезжает панели байтами UTF-8
     * и показывается там мусором, поэтому лучше её отсутствие. */
    snprintf(p, sizeof p, "%s/model", T);
    wr(p, "тестAX3000T\n");
    steer_dev_model(v, sizeof v);
    ck("кириллица в модели выбрасывается", "AX3000T", v);

    /* И то, ради чего чистка вообще существует: перевод строки внутри значения — это вставка
     * чужого заголовка в запрос. Здесь защиты две, и вторая строже первой: файл читается
     * ПОСТРОЧНО, поэтому всё после перевода строки не доходит до чистки вовсе. В оболочке так
     * не было — там значение бралось целиком через `cat`, и защитой была одна чистка. */
    wr(p, "aaa\nX-Evil: 1\n");
    steer_dev_model(v, sizeof v);
    ck("после перевода строки в заголовок не попадает ничего", "aaa", v);
    /* И сама чистка на месте: строка без перевода, но с управляющим символом. */
    wr(p, "aaa\rX-Evil: 1\n");
    steer_dev_model(v, sizeof v);
    ck("возврат каретки из значения убран", "aaaX-Evil: 1", v);

    /* Файла нет — честное умолчание, а не пустой заголовок: пустое значение панель показала бы
     * как устройство без имени. */
    unlink(p);
    steer_dev_model(v, sizeof v);
    ck("без файла модели — честное умолчание", "router", v);
    wr(p, "Xiaomi AX3000T\n");

    /* Длина ограничена: заголовок — не место для страницы текста. */
    snprintf(p, sizeof p, "%s/model", T);
    wr(p, "0123456789012345678901234567890123456789"
          "0123456789012345678901234567890123456789\n");
    steer_dev_model(v, sizeof v);
    ck_num("значение обрезано по пределу", 64, (long long)strlen(v));
    wr(p, "Xiaomi AX3000T\n");

    /* Версия системы читается из файла в кавычках — так её и пишет OpenWrt. */
    snprintf(p, sizeof p, "%s/openwrt_release", T);
    wr(p, "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE=\"24.10.0\"\n");
    steer_dev_os(v, sizeof v);
    ck("кавычки вокруг версии — часть формата, а не значение", "OpenWrt 24.10.0", v);
    unlink(p);
    steer_dev_os(v, sizeof v);
    ck("без файла версии — просто OpenWrt", "OpenWrt", v);
    wr(p, "DISTRIB_RELEASE='25.12.5'\n");
}

/* ---- проверки: несколько подписок --------------------------------------------------
 *
 * Подписок на роутере бывает несколько: у человека две панели, и локации из обеих он
 * складывает в один пул. Движок про этот учёт ничего не знает и знать не должен — ему
 * называют пути, — но именно поэтому пути обязаны соблюдаться БУКВАЛЬНО. Ошибка здесь
 * молчаливая в худшем виде: остаток второй панели, записанный поверх остатка первой,
 * выглядит как правда, а узлы, скачанные в чужой файл, уводят трафик к другому поставщику. */
static void t_multi(void) {
    char out2[512], info2[512], derived[512];
    snprintf(out2, sizeof out2, "%s/subs-green.txt", T);
    snprintf(info2, sizeof info2, "%s/subs-green.userinfo", T);
    /* Путь остатка, который движок ВЫВЕЛ БЫ сам, — и он не должен быть использован, когда
     * названный путь другой. */
    info_for(out2, derived, sizeof derived);
    snprintf(info2, sizeof info2, "%s/elsewhere.userinfo", T);
    ck_true("выведенный и названный пути различаются", strcmp(derived, info2) != 0);

    fixture("main", "body", "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?"
            "type=tcp&security=reality&sni=a.example&"
            "pbk=Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDA&sid=ab12#\xd0\x9d\n");
    fixture("main", "hdr",
            "HTTP/1.1 200 OK\r\n"
            "subscription-userinfo: upload=1; download=1; total=9; expire=1900000000\r\n");
    unlink(out2); unlink(info2); unlink(derived);

    snprintf(g_url, sizeof g_url, "https://second.invalid/sub");
    snprintf(g_out, sizeof g_out, "%s", out2);
    snprintf(g_info, sizeof g_info, "%s", info2);
    cap(call_fetch);
    ck_true("подписка легла по названному пути", strstr(rd(out2), "vless://") != NULL);
    ck_true("остаток лёг по НАЗВАННОМУ пути", strstr(rd(info2), "total=9") != NULL);
    ck_true("а по выведенному не появился", access(derived, F_OK) != 0);

    /* Первая подписка при этом не тронута: у неё свои файлы, и работа со второй в них не
     * заглядывает. */
    char first[512], firstinfo[512];
    snprintf(first, sizeof first, "%s/sub.txt", T);
    snprintf(firstinfo, sizeof firstinfo, "%s/sub.userinfo", T);
    wr(first, "vless://первая\n");
    wr(firstinfo, "total=111\n");
    cap(call_fetch);
    ck_true("файл первой подписки не тронут", strstr(rd(first), "первая") != NULL);
    ck_true("и её остаток тоже", strstr(rd(firstinfo), "total=111") != NULL);
}

int main(void) {
    snprintf(T, sizeof T, "/tmp/subfetchmatch.%d", (int)getpid());
    mkdir(T, 0755);
    char p[512];
    snprintf(p, sizeof p, "%s/sys", T);
    mkdir(p, 0755);
    setenv("STEER_SYSNET", p, 1);
    snprintf(p, sizeof p, "%s/openwrt_release", T);
    wr(p, "DISTRIB_RELEASE='25.12.5'\n");
    setenv("STEER_OPENWRT_RELEASE", p, 1);
    snprintf(p, sizeof p, "%s/model", T);
    wr(p, "Xiaomi AX3000T\n");
    setenv("STEER_SYSINFO_MODEL", p, 1);

    t_headers();
    t_ui_field();
    t_title();
    t_warn();
    t_quota();
    t_fetch();
    t_reject();
    t_gzip();
    t_quota_cmd();
    t_device_hdrs();
    t_multi();

    /* Песочница убирается снаружи скриптом стендов: оставленный каталог после ПРОВАЛА
     * помогает понять, что именно записалось. */
    printf("\n%d проверок пройдено", g_pass);
    if (g_fail) { printf(", %d ПРОВАЛЕНО\n", g_fail); return 1; }
    printf("\nвсе проверки прошли\n");
    return 0;
}
