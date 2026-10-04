#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>

#include "spec.h"
#include "awg.h"
#include "hwid.h"
#include "obfs.h"
#include "cli.h"
#include "srs.h"
#include "ctl.h"
#include "daemon.h"
#include "fogroup.h"
#include "groups.h"
#include "generate.h"
#include "grpurl.h"
#include "jsonw.h"


/* ---- status --------------------------------------------------------------- */
/* Counters come from the live chain, matched by the comment each rule carries —
 * which is why generation puts the channel name there. Without it the numbers
 * exist but belong to nobody. */

/* СНИМОК СОСТОЯНИЯ: зачем движок помнит свой последний ответ.
 *
 * Полный ответ стоит работы: разбор спеки, обход выходов с чтением /sys, чтение счётчиков
 * из живой цепочки nft. Замерено на стенде (mipsel 24kc, 880 МГц): 91 мс на вызов, из них
 * основное — запуск и разбор вывода nft. Пока на это смотрел только круг опроса раз в пять
 * секунд, цена была не видна; но ровно этот ответ нужен ПЕРВЫМ при открытии окна splify2, и
 * там он складывается со всем остальным, что страница спрашивает в тот же миг, — человек
 * ждёт на пустом экране.
 *
 * Поэтому движок пишет свой ответ рядом с остальным состоянием и умеет отдать запомненное
 * немедленно (`--fast`). Снимок обновляют двое: любой полный `status` (то есть каждый круг
 * опроса открытой страницы) и отдельный экземпляр procd раз в пять минут — чтобы на только
 * что открытой странице лежало не вчерашнее.
 *
 * ЧЕСТНОСТЬ ЗДЕСЬ ГЛАВНОЕ. Запомненный ответ отдаётся с двумя полями: `at` — когда его
 * собрали, `cached: true` — что это не измерение, а память. Без них интерфейс нарисовал бы
 * запомненное как живое, и «Работает» стояло бы на упавшем туннеле; в проекте это уже
 * стоило отдельного признака `stale` в самом интерфейсе, и повторять ту же ошибку на
 * ступень ниже незачем.
 *
 * Устаревший снимок при этом НЕ отвергается: смысл `--fast` в том, чтобы показать хоть
 * что-то сразу, а решение «это слишком старо, чтобы показывать» принимает тот, кто
 * спрашивает, — у него есть `at`. Снимка нет вовсе — команда считает всё честно, то есть
 * `--fast` никогда не отвечает пустотой.
 */
void status_snap_path(char *buf, size_t n) {
    snprintf(buf, n, "%s/status.json", steer_state_dir());
}

/* Потолок размера снимка — защита от чужого файла под нашим именем (писать его мог не только
 * движок): снимок читается в память целиком, и файл в сотни мегабайт не должен туда попасть.
 * Настоящий снимок на тысячи каналов — единицы мегабайт. */
#define STATUS_SNAP_MAX (16 * 1024 * 1024)

/* Отдать запомненное. 0 — отдали, -1 — снимка нет или он не похож на наш ответ.
 *
 * `cached` дописывается ПЕРЕД закрывающей скобкой, а не в начало: так порядок полей ответа
 * остаётся тем же, каким его видят все нынешние читатели, и `{"schema":1,...` по-прежнему
 * первое, что стоит в строке. */
int status_fast(FILE *out) {
    char snap[256];
    status_snap_path(snap, sizeof snap);
    FILE *f = fopen(snap, "r");
    if (!f) return -1;
    /* Буфер — в куче и по размеру файла (раньше — статические 256 КиБ bss на каждой коробке, а
     * снимок больше них считался «не нашим», и быстрый путь тихо отключался у большой спеки). */
    fseek(f, 0, SEEK_END);
    long fl = ftell(f);
    rewind(f);
    if (fl < 3 || fl > STATUS_SNAP_MAX) { fclose(f); return -1; }
    char *buf = malloc((size_t)fl + 1);
    if (!buf) { fclose(f); return -1; }
    size_t n = fread(buf, 1, (size_t)fl, f);
    int truncated = n != (size_t)fl;
    fclose(f);
    if (truncated) { free(buf); return -1; }   /* файл менялся под рукой — это не наш снимок */
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == ' ')) n--;
    /* Проверка формы, а не доверие имени файла: оборванная запись оставила бы обрубок,
     * и отдать его значило бы выдать половину JSON за ответ движка. */
    if (n < 3 || buf[0] != '{' || buf[n - 1] != '}') { free(buf); return -1; }
    fwrite(buf, 1, n - 1, out);
    free(buf);
    fputs(",\"cached\":true}\n", out);
    return 0;
}

/* ГРУППА СПЕКИ v2 (kind: group, docs/contract-v1.md, §2): как она выбирает и что выбрала. Только
 * у групп, которые видны снаружи группой: пул v1 (`devices`) выглядит прежним выходом interface, и
 * его объект не меняется (контракт со splify2 меняется в паре). Поля — только добавлены:
 *   pick     — order | latency | manual | balance;
 *   members  — члены по порядку (имена выходов, в том числе вложенных групп);
 *   selected — член, чей лист сейчас несёт трафик группы (null — отказ или сторож ещё не проходил);
 *              у balance — член, в чьё устройство ведёт таблица самой группы (сокеты с её меткой);
 *   alive    — живые члены по последнему проходу; у balance это и есть состав карты раздачи;
 *   select   — manual: выбор человека (команда select) или default, пока выбора не было;
 *   url, latency — latency: адрес проверки и замеры urltest по членам, мс (только измеренные);
 *   latency_failed — latency: живые члены без замера (проверочный адрес через них не ответил) —
 *              поля нет, когда таких нет;
 *   tolerance, interval, idle_timeout — latency: допуск (мс), интервал замера и пауза замера без
 *              трафика (с; 0 — мерить всегда), с умолчаниями платформы;
 *   fastest, why — latency: самый быстрый из живых измеренных членов и почему группа сейчас на
 *              выбранном (group_latency_why: fastest, in_tolerance, no_measure, unmeasured,
 *              pending; idle — замер на паузе без трафика); fastest нет, пока никто не измерен,
 *              why — пока группа никого не выбрала. У группы с одним членом ни того, ни другого;
 *   latency4, latency6 — у группы, меренной по обоим семействам: замеры по IPv4 и IPv6 порознь
 *              (latency тогда — худший из двух у каждого члена); у остальных полей нет;
 *   weights  — balance: веса членов по порядку. */
static void group_emit(FILE *out, const struct spec *sp, const struct output *o) {
    const struct group_cfg *g = out_group(o);
    if (!g || g->shown) return;
    fprintf(out, ",\"group\":{\"pick\":\"%s\",\"members\":[", group_pick_name(g->pick));
    for (size_t k = 0; k < g->members_n; k++)
        fprintf(out, "%s\"%s\"", k ? "," : "", spec_out(sp, g->members[k])->name);
    if (g->cur >= 0 && (size_t)g->cur < g->members_n)
        fprintf(out, "],\"selected\":\"%s\",\"alive\":[", spec_out(sp, g->members[g->cur])->name);
    else
        fprintf(out, "],\"selected\":null,\"alive\":[");
    int n = 0;
    for (size_t k = 0; k < g->members_n; k++)
        if (g->alive[k]) fprintf(out, "%s\"%s\"", n++ ? "," : "", spec_out(sp, g->members[k])->name);
    fprintf(out, "]");
    if (g->pick == PICK_MANUAL && g->sel >= 0 && (size_t)g->sel < g->members_n)
        fprintf(out, ",\"select\":\"%s\"", spec_out(sp, g->members[g->sel])->name);
    if (g->pick == PICK_LATENCY) {
        fprintf(out, ",\"url\":\"%s\",\"latency\":{", g->url[0] ? g->url : GROUP_URL_DEFAULT);
        n = 0;
        for (size_t k = 0; k < g->members_n; k++)
            if (g->lat_ms[k] >= 0)
                fprintf(out, "%s\"%s\":%d", n++ ? "," : "", spec_out(sp, g->members[k])->name, g->lat_ms[k]);
        fprintf(out, "}");
        /* Живые члены без замера и причина выбора. Сторож выбирает по тем же числам тем же
         * правилом (group_latency_pick), а why называет, что из этого вышло: «первый живой», о
         * котором пишут «самый быстрый не работает», — это либо замера нет вовсе (no_measure), либо
         * выбранный не хуже самого быстрого на допуск (in_tolerance). */
        /* У группы с одним членом выбирать не из чего: замера нет и не будет (его ведёт расписание
         * групп от двух членов, folat.c), и «замера нет» тут не неудача — об этом молчим. */
        int multi = g->members_n > 1;
        /* Замер на паузе без трафика (idle_timeout): замера нет не из-за неудачи, и называть членов
         * «без замера» значило бы выдать простой за отказ. */
        int idle = fog_idle_limit(o) > 0 && fog_idle_now(o->name);
        n = 0;
        for (size_t k = 0; multi && !idle && k < g->members_n; k++)
            if (g->alive[k] && g->lat_ms[k] < 0)
                fprintf(out, "%s\"%s\"", n++ ? "," : ",\"latency_failed\":[",
                        spec_out(sp, g->members[k])->name);
        if (n) fputc(']', out);
        int tol = group_tolerance_ms(g), fastest = -1;
        fprintf(out, ",\"tolerance\":%d,\"interval\":%d,\"idle_timeout\":%d", tol, group_interval_s(g),
                fog_idle_limit(o));
        int why = multi ? group_latency_why(g->lat_ms, g->alive, g->members_n, g->cur, tol, &fastest)
                        : GW_NONE;
        if (why == GW_NOMEASURE && idle) why = GW_IDLE;
        if (fastest >= 0)
            fprintf(out, ",\"fastest\":\"%s\"", spec_out(sp, g->members[fastest])->name);
        if (group_why_name(why)) fprintf(out, ",\"why\":\"%s\"", group_why_name(why));
        /* Группа, меренная по обоим семействам (все живые члены несут IPv6, src/daemon/folat.c):
         * замеры по IPv4 и IPv6 порознь; latency тогда — худший из двух, по нему и выбор. */
        int fam = 0;
        for (size_t k = 0; k < g->members_n; k++)
            if (g->lat4_ms[k] != -2 || g->lat6_ms[k] != -2) fam = 1;
        for (int v = 0; fam && v < 2; v++) {
            const int *a = v ? g->lat6_ms : g->lat4_ms;
            fprintf(out, ",\"latency%d\":{", v ? 6 : 4);
            n = 0;
            for (size_t k = 0; k < g->members_n; k++)
                if (a[k] >= 0) fprintf(out, "%s\"%s\":%d", n++ ? "," : "", spec_out(sp, g->members[k])->name, a[k]);
            fprintf(out, "}");
        }
    }
    if (g->pick == PICK_BALANCE) {
        fprintf(out, ",\"weights\":[");
        for (size_t k = 0; k < g->members_n; k++)
            fprintf(out, "%s%u", k ? "," : "", g->weight[k] ? g->weight[k] : 1u);
        fprintf(out, "]");
    }
    fprintf(out, "}");
}

/* Поля выхода, которые знает только демон-супервизор (daemon.h, status_extra_source). */
static void (*g_status_extra)(FILE *out, const char *out_name);

void status_extra_source(void (*fn)(FILE *out, const char *out_name)) {
    g_status_extra = fn;
}

/* Сам ответ. Поток параметром, потому что печатается он ДВАЖДЫ в разные места: в снимок на
 * диске и человеку (точнее, тому, кто позвал). Считать его два раза было бы вдвое дороже
 * ровно того, ради чего снимок и заведён. */
static void status_emit(const struct spec *sp, const struct groups *gr, FILE *out) {
    /* УМЕНИЯ ДВИЖКА — перечнем имён и верхним уровнем.
     *
     * Зачем вообще. Незнакомый ключ спеки движок пропускает МОЛЧА (js_skip) — это и есть
     * совместимость вперёд внутри мажора, — поэтому управляющий слой, записавший новое поле
     * в движок постарше, получает применённую спеку и трафик не туда, куда просил. Узнать
     * поколение до записи он обязан сам, и до сих пор узнавал по косвенным признакам:
     * наличию `lan_devices` здесь и поля `nodes` у выхода kind=vless. Второй признак виден
     * ТОЛЬКО на роутере, где такой выход уже есть, — а смешанный пул нужнее всего там, где
     * его нет вовсе (xsteer плюс wireguard), и там же движок постарше молча уводит канал в
     * blackhole. Интерфейс поэтому вынужден был запрещать пул до первого применённого
     * выхода подписки (splify2, запуск 69).
     *
     * ПОЧЕМУ ИМЕНА, А НЕ НОМЕР ВЕРСИИ. Версию в дерево проставляет релизный workflow, а не
     * коммит: движок из main через два коммита после релиза называет то же число, что и
     * релиз (I-054). Сравнивать по нему — значит однажды объявить умеющим движок, который
     * не умеет. Имя умения печатает тот же код, который его и делает.
     *
     * ДОГОВОР О ПЕРЕЧНЕ. Поля нет вовсе — движок старше 1.3.0, и тогда судить о нём
     * по-прежнему нечем, кроме косвенных признаков. Набор имён может и расти, и сокращаться
     * между версиями: потребитель обязан терпеть незнакомые имена и не должен требовать
     * наличия какого-либо конкретного. */
    /* КОГДА СОБРАН ЭТОТ ОТВЕТ. Печатается всегда, а не только в снимке, и это не
     * избыточность: ответ движка теперь бывает запомненным, и различить измерение от памяти
     * по одному лишь `cached` было бы нечем — интерфейсу нужен возраст, чтобы сказать
     * человеку «данные такой-то давности», а не рисовать их живыми. У живого ответа возраст
     * нулевой, и это тот же контракт, а не особый случай. */
    fprintf(out, "{\"schema\":1,\"at\":%ld,"
                 "\"features\":[\"lan_devices\",\"nodes\",\"pool\",\"active_device\","
                 "\"status_cache\",\"xslink\",\"xsteer_state\",\"spec_schema2\",\"awg\","
                 "\"via\",\"failed\",\"groups\",\"balance_by\",\"exclude\",\"active_nodes\","
                 "\"dns_groups\",\"dns_other\"]",
            (long)time(NULL));
    /* Локальные устройства — следом: интерфейс показывает, с чего забирается трафик, и
     * без этого поля ему пришлось бы читать спеку вторым источником, то есть однажды
     * показать не то, что применено. */
    fprintf(out, ",\"lan_devices\":[");
    for (size_t i = 0; i < sp->lan_dev_n; i++)
        fprintf(out, "%s\"%s\"", i ? "," : "", sp->lan_dev[i]);
    fprintf(out, "],\"outputs\":{");
    for (size_t i = 0; i < sp->out_n; i++) {
        char devpath[128];
        int up = 0;
        if (out_has_device(&sp->out[i])) {
            snprintf(devpath, sizeof(devpath), "/sys/class/net/%s/operstate", sp->out[i].device);
            FILE *df = fopen(devpath, "r");
            if (df) {
                char st[16] = "";
                if (fgets(st, sizeof(st), df)) up = strncmp(st, "down", 4) != 0;
                fclose(df);
            }
        }
        /* Сторож признал выход неработающим и поставил on_fail (запись «-» в `active`): трафик
         * через устройство не идёт, даже если оно поднято. До этой правки status отдавал здесь
         * `up: true`, и интерфейс рисовал живым выход, чей трафик стоит (on_fail=drop) или идёт
         * мимо (direct). Теперь `up: false` и рядом `failed: true` — чем этот случай отличается
         * от упавшего устройства (docs/contract-v1.md, §2). */
        const int failed = out_has_device(&sp->out[i]) && sp->out[i].failed;
        if (failed) up = 0;
        /* Вид — каким выход виден снаружи: группа из пула `devices` спеки v1 — interface, как
         * была (контракт со splify2 меняется в паре, шаг 3 из 1.9). */
        fprintf(out, "%s\"%s\":{\"kind\":\"%s\"", i ? "," : "", sp->out[i].name,
               out_kind_name(&sp->out[i]));
        /* Через какой выход идёт туннель этого выхода (`via`, см. «вложенные выходы» в
         * spec.h). Поля нет, когда туннель идёт напрямую, — как в спеке. Живость цели здесь не
         * повторяется: она видна у самой цели в этом же ответе, а второй источник того же
         * ответа однажды разошёлся бы с первым. */
        if (sp->out[i].over[0]) fprintf(out, ",\"via\":\"%s\"", sp->out[i].over);
        if (out_has_device(&sp->out[i])) {
            struct fwcheck c = fw_check(sp->out[i].device);
            fprintf(out, ",\"device\":\"%s\",\"up\":%s%s,\"mark\":\"0x%08x\",\"table\":%d"
                   ",\"in_firewall\":%s,\"nat\":%s",
                   sp->out[i].device, up ? "true" : "false", failed ? ",\"failed\":true" : "",
                   sp->out[i].mark, sp->out[i].table,
                   c.in_firewall ? "true" : "false", c.masqueraded ? "true" : "false");
            /* С 1.10 `nat` — подмена IPv4 (masq зоны), а `nat6` — IPv6 (masq6), отдельно
             * (fw_check по семействам, fwcheck.c): прежде одно поле засчитывало любое правило
             * masquerade за оба. `nat6` — только у выхода, который несёт IPv6 (out_route6): у
             * остальных IPv6 его правил отвергается, и вопрос о подмене не стоит.
             *
             * `nat6` — «IPv6 на устройстве подменяется», кем бы ни было: masq6 зоны fw4 или наш
             * postrouting_nat6 (ключ `ipv6: nat` у выхода или у владельца устройства —
             * out_ipv6_mode_dev). Прежде поле смотрело только на fw4, и у wg1 с `ipv6: nat`
             * было `nat6: false` при работающей подмене (проверка на QEMU-роутере 4192267) —
             * интерфейсу это читалось как поломка. Кем — отдельным полем `nat6_by` («steer» —
             * своя цепочка, она ставится всегда, когда ключ есть; иначе «fw4»), только при
             * `nat6: true`. */
            if (out_route6(&sp->out[i])) {
                int ours = out_ipv6_mode_dev(sp, &sp->out[i], sp->out[i].device) == OUT_V6_NAT;
                fprintf(out, ",\"nat6\":%s", ours || c.masq6 ? "true" : "false");
                if (ours || c.masq6) fprintf(out, ",\"nat6_by\":\"%s\"", ours ? "steer" : "fw4");
            }
            /* Ключ ipv6 спеки v2 (шаг 8 выпуска 1.10) — как записан; `ipv6_applied: false` —
             * записан, но на этой платформе не действует (телефон, out_ipv6_mode). У донора —
             * `prefix`: записанный или выведенный по ядру сейчас (v6donor_derive), null — не
             * узнать. Поля нет у выхода без ключа — status прежний до байта. */
            const struct output *o6 = &sp->out[i];
            if (o6->ipv6 != OUT_V6_KIND) {
                static const char *const V6[] = { "", "routed", "nat", "off" };
                fprintf(out, ",\"ipv6\":\"%s\"", V6[o6->ipv6]);
                if (out_ipv6_mode(o6) != o6->ipv6) fprintf(out, ",\"ipv6_applied\":false");
            }
            if (spec_v6_donor(sp) == o6) {
                struct v6pfx p = o6->v6pfx;
                if (!o6->v6pfx_given && v6donor_derive(sp, o6, &p) != 1) p.len = 0;
                char ps[64];
                v6pfx_str(&p, ps, sizeof(ps));
                if (p.len) fprintf(out, ",\"prefix\":\"%s\"", ps);
                else fprintf(out, ",\"prefix\":null");
            }
            /* Кандидаты и режим отказа: без них failover не виден из интерфейса, и
             * человек не может понять, почему выход вдруг ведёт в другое устройство. */
            /* Ход подъёма — рядом с up, а не отдельным вызовом: интерфейс уже читает
             * status по кругу, и второй источник дал бы на экране два разных мгновения.
             * Поля нет вовсе, когда сказать нечего (устройство есть, файла нет, он устарел
             * или писавший процесс мёртв) — «не знаем» не должно читаться как «плохо». */
            /* Ход подъёма спрашивается у ВЛАДЕЛЬЦА устройства, а не у выхода, который его назвал:
             * запись перебора узлов пишет клиент vless под своим именем, и пул, ждущий этот
             * туннель, иначе отдавал бы «устройства нет» вместо «проверяю узлы, 3 из 26» — то же
             * враньё, ради снятия которого перебор и стал виден (I-100). У живого устройства
             * спрашивается только выход, чьё устройство создаёт наш процесс: о другом сказать
             * нечего, и читать ради него запись незачем. */
            const struct output *po = out_for_device(sp, &sp->out[i], sp->out[i].device);
            struct probe_status pr = { PROBE_NONE, 0, 0, 0, "" };
            if (!up || out_engine_managed(po)) pr = probe_read(po->name);
            if (!up) {
                if (pr.state == PROBE_RUNNING)
                    fprintf(out, ",\"probe\":{\"state\":\"probing\",\"node\":%d,\"total\":%d}",
                           pr.node, pr.total);
                else if (pr.state == PROBE_FAILED)
                    fprintf(out, ",\"probe\":{\"state\":\"failed\",\"total\":%d}", pr.total);
                /* Номер вне подписки — СВОЁ состояние, а не разновидность failed: интерфейс
                 * обязан уметь сказать «поправьте номер», а не «поменяйте подписку». Оба
                 * числа рядом, потому что порознь они ничего не значат. */
                /* Все кандидаты исключены `exclude`/`exclude_name` — своё состояние: чинится в
                 * «Не брать», а не подпиской. total — кандидатов до исключения. */
                else if (pr.state == PROBE_ALL_EXCLUDED)
                    fprintf(out, ",\"probe\":{\"state\":\"excluded\",\"total\":%d}", pr.total);
                else if (pr.state == PROBE_NO_SUCH_NODE)
                    fprintf(out, ",\"probe\":{\"state\":\"no_such_node\",\"node\":%d"
                                 ",\"total\":%d}", pr.node, pr.total);
            }
            /* Устройство есть, а узел за ним клиент потерял (слежка за узлом под демоном,
             * src/tunnel/pool.c). Обычно выход тогда и в отказе (up:false, failed:true — сторож
             * принял down клиента), но поле своё, а не probe: probe значит «устройства нет, подъём
             * идёт или не удался», а устройство на месте. Причина — словами клиента, время —
             * когда сказал. Поля нет — узел отвечает или сказать нечего (без демона слежки нет). */
            if (pr.state == PROBE_LOST) {
                fprintf(out, ",\"node_down\":{\"why\":");
                jsonw_str(out, pr.why);
                fprintf(out, ",\"since\":%ld}", pr.since);
            }
            /* Кандидаты: у группы — устройства членов по порядку, у выхода — его устройство. */
            size_t mn = out_members_n(sp, &sp->out[i]);
            fprintf(out, ",\"devices\":[");
            for (size_t d = 0; d < mn; d++)
                fprintf(out, "%s\"%s\"", d ? "," : "", out_member(sp, &sp->out[i], d)->device);
            fprintf(out, "],\"on_fail\":\"%s\"",
                   sp->out[i].on_fail == FAIL_DROP ? "drop" :
                   sp->out[i].on_fail == FAIL_ZAPRET ? "zapret" : "direct");
            group_emit(out, sp, &sp->out[i]);
        }
        /* Свои поля вида (kind_ops.status): у vless — выбранные узлы подписки, у interface —
         * обфускация, у awg — рукопожатие и счётчики из ядра (все три — после on_fail, в объекте
         * выхода с устройством), у zapret — очередь, файл стратегии и живость обработчика. */
        {
            const struct kind_ops *k = kind_of(&sp->out[i]);
            if (k->status) k->status(out, sp, &sp->out[i]);
        }
        /* То, что о помощнике выхода знает демон по его событиям (у моста tgws — отставленные
         * пути, paths_down): только в ответе демона-супервизора, подкоманда о них не знает. */
        if (g_status_extra) g_status_extra(out, sp->out[i].name);
        fprintf(out, "}");
    }
    fprintf(out, "},\"channels\":[");

    counters_load();
    for (size_t i = 0; i < gr->n; i++) {
        unsigned long up_p = 0, up_b = 0, dn_p = 0, dn_b = 0;
        int live = counter_find(gr->g[i].name, 0, &up_p, &up_b) == 0;
        int dn = counter_find(gr->g[i].name, 1, &dn_p, &dn_b) == 0;
        fprintf(out, "%s{\"name\":\"%s\",\"out\":\"%s\",\"kind\":\"%s\",\"live\":%s",
               i ? "," : "", gr->g[i].name, gr->g[i].out,
               gr->g[i].domains ? "domains" : "prefixes", live ? "true" : "false");
        if (live) fprintf(out, ",\"packets\":%lu,\"bytes\":%lu", up_p, up_b);
        /* Отдельными именами, а не вторым «bytes»: старое имя значило «наружу» и в таком
         * значении уже разошлось по установленным версиям splify2. Переопределить его
         * значило бы, что новый движок со старым интерфейсом молча показывает не то. */
        if (dn) fprintf(out, ",\"down_packets\":%lu,\"down_bytes\":%lu", dn_p, dn_b);
        /* Набор .srs — один список, сколько бы клауз из него ни попало в группу. */
        fprintf(out, ",\"lists\":%zu,\"channels\":[",
                gr->g[i].files_n + gr->g[i].dfiles_n + gr->g[i].srs_n);
        for (size_t m = 0; m < gr->g[i].members_n; m++)
            fprintf(out, "%s\"%s\"", m ? "," : "", gr->g[i].members[m]);
        fprintf(out, "]}");
    }
    fprintf(out, "]}\n");
}

/* Полный ответ: посчитать, запомнить и напечатать в out.
 *
 * Снимок пишется через временный файл и rename, как и всё прочее состояние: оборванная
 * запись поверх прежнего снимка оставила бы обрубок, а `--fast` тогда отдавал бы половину
 * ответа. Не записалось (нет места, каталог только для чтения) — печатаем и молчим об этом:
 * снимок это УСКОРЕНИЕ, и терять из-за него сам ответ было бы обменом наоборот.
 *
 * Ответ собирается в памяти один раз, и те же байты идут и в снимок, и в out: обход выходов
 * читает /sys, а счётчики — живую цепочку nft, и второй проход дал бы в снимке и в ответе два
 * разных мгновения. Этим же путём отвечает демон (status из памяти, src/daemon/ctl.c) — то
 * есть его ответ и ответ подкоманды собирает один и тот же код, байт в байт. */
void status_answer(const struct spec *sp, const struct groups *gr, FILE *out) {
    char *mem = NULL;
    size_t n = 0;
    FILE *m = open_memstream(&mem, &n);
    if (!m) { status_emit(sp, gr, out); return; }
    status_emit(sp, gr, m);
    if (fclose(m) != 0 || !mem) { free(mem); status_emit(sp, gr, out); return; }

    char snap[256], tmp[288];
    status_snap_path(snap, sizeof snap);
    snprintf(tmp, sizeof tmp, "%s.new", snap);
    mkdir(steer_state_dir(), 0755);
    FILE *f = fopen(tmp, "w");
    if (f) {
        int ok = fwrite(mem, 1, n, f) == n;
        if (fclose(f) != 0 || !ok || rename(tmp, snap) != 0) unlink(tmp);
    }
    fwrite(mem, 1, n, out);
    free(mem);
}

int cmd_status(const char *spec, int fast) {
    static struct spec cfg;
    static struct groups gr;
    /* Запомненное — раньше разбора спеки: смысл `--fast` в том, чтобы не делать работу
     * вовсе. Спека при этом не читается, то есть негодная спека `--fast` не ломает — он
     * отвечает тем, что было применено, пока она была годной. */
    if (fast && status_fast(stdout) == 0) return 0;

    /* Правило 5, docs/architecture.md, раздел 2: err_die здесь довершает то, что раньше делал
     * die() изнутри load_spec/build_groups. */
    struct err e = {0};
    if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
    if (registry_assign(&cfg, &e) < 0) err_die(&e);
    if (build_groups(&cfg, &gr, &e) < 0) err_die(&e);
    /* О том же устройстве, к которому apply привязал таблицу, — см. outputs_adopt_active.
     * Без этого пул, уведённый сторожем на запасное устройство, отдавался бы интерфейсу
     * основным устройством с `up: false`: рабочий выход, нарисованный сломанным. */
    outputs_adopt_active(&cfg);
    status_answer(&cfg, &gr, stdout);
    return 0;
}
