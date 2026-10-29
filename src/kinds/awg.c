/* Выход kind=awg: туннель AmneziaWG/WireGuard в ядре, которым управляет движок.
 *
 * Зачем этот вид и почему файл, а не поля спеки, — в шапке awg.h. Здесь — как.
 *
 * ЖИЗНЕННЫЙ ЦИКЛ. apply (awg_apply_all) для каждого выхода: читает файл, разрешает имена
 * Endpoint, создаёт устройство, если его нет (RTM_NEWLINK с видом "amneziawg", при отсутствии
 * модуля и файле без обфускации — "wireguard"), настраивает его одним сообщением
 * WG_CMD_SET_DEVICE, ставит MTU, адреса и поднимает. Дальше таблицу выхода к устройству
 * привязывает apply_routing — тем же путём, что у kind=interface. Устройство, которое уже
 * есть, НЕ пересоздаётся: настройка ложится поверх, и живые сессии пиров, чьи ключи не
 * менялись, не рвутся (WireGuard не трогает сессию, если ключ, PSK и эндпоинт те же).
 * Пересоздание — только когда поверх нельзя: сменился вид (файл стал требовать AmneziaWG, а
 * устройство — wireguard) или из файла убран параметр AmneziaWG, у которого нет значения
 * «как не задан» (снять Jc или H1 поверх нельзя — модуль оставил бы прежнее).
 * `steer down` и удаление выхода из спеки снимают устройство по реестру в каталоге
 * состояния — как метки и таблицы у registry_assign.
 *
 * БАТАРЕЯ. После apply движок в жизни туннеля не участвует: ни процесса, ни таймеров.
 * Здоровье сторож судит по тому, что ядро и так знает, — свежести последнего рукопожатия и
 * счётчикам пира (WG_CMD_GET_DEVICE), без единого пакета от себя. PersistentKeepalive по
 * умолчанию выключен и включается только файлом: keepalive — это пробуждение радио каждые
 * N секунд.
 *
 * СЕКРЕТЫ. Приватный ключ, PSK и ключ защиты заголовка живут в struct awg_secrets и в буфере
 * сообщения ядру — и то и другое затирается сразу после отправки. Ответ WG_CMD_GET_DEVICE
 * ядро присылает С ПРИВАТНЫМ КЛЮЧОМ (у вызывающего есть CAP_NET_ADMIN), поэтому буфер приёма
 * затирается тоже. В status, журнал и сообщения об ошибках ключи не попадают: разбор
 * называет только имя параметра, никогда значение. */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>

#include "spec.h"
#include "awg.h"
#include "awgdev.h"
#include "nlbuf.h"
#include "run.h"
#include "sockmark.h"

#define LOG_W "steer[warn] awg: "
#define LOG_I "steer[info] awg: "

/* ---- метка сокета туннеля ------------------------------------------------------------ */

/* Через какой выход пускать UDP туннеля — поле `via` выхода (см. «вложенные выходы» в spec.h):
 * имя или NULL. Спрашивается одним местом, чтобы остальной код awg не знал, как поле хранится. */
static const char *awg_out_via(const struct output *o) {
    return o->over[0] ? o->over : NULL;
}

/* Метка сокета туннеля (WGDEVICE_A_FWMARK).
 *
 * С via — метка выхода via: ядро отправляет датаграммы туннеля с этой меткой (WireGuard
 * ставит skb->mark = fwmark устройства), правило движка `fwmark <метка via> lookup <таблица
 * via>` уводит их в устройство via — и туннель оказывается внутри другого туннеля.
 *
 * Без via — метка «мимо каналов движка»: STEER_SELF_MARK на телефоне, 0 на роутере. Почему
 * именно так — у out_underlay_mark в spec.h, и считает метку ОНА: у vless, xsteer, обфускатора и
 * awg одно правило, и держать его в двух местах значило бы однажды развести. Для awg к её доводам
 * добавляется одно: правила каналов на телефоне (self, uid:N) сокет туннеля не ловят и без метки —
 * сокет у WireGuard ядерный, без файла, и `meta skuid` на нём не совпадает, — но собственная метка
 * движка делает это свойством раскладки, а не удачей, и в `steer conns` такие записи не выдаются
 * за трафик приложений.
 *
 * Здесь остаётся только то, что out_underlay_mark не решает, — имя, которого нет: -1. Спека такое
 * отвергает (over_check в model/v1.c), так что это страховка вызова в обход парсера (стенд awgmatch). Выход via
 * без метки (direct; или метка ещё не выдана) означает то же, что via нет. */
int awg_sock_mark(const struct spec *sp, const char *via, uint32_t *mark) {
    struct output t;
    memset(&t, 0, sizeof t);
    *mark = out_underlay_mark(sp, &t);
    if (!via || !*via) return 0;
    snprintf(t.over, sizeof t.over, "%s", via);
    if (!out_over(sp, &t)) return -1;
    *mark = out_underlay_mark(sp, &t);
    return 0;
}

/* ---- реестр устройств и подпись параметров ------------------------------------------- */

static void reg_path(char *buf, size_t n) { snprintf(buf, n, "%s/awg-devices", steer_state_dir()); }

/* Прочитать реестр устройств в кучу: *dst — массив имён (free вызывающему), возвращает число.
 * Число не ограничено: раньше массивы на стеке были на 2 * 16, и устройства сверх них не
 * убирались вместе с выходом. */
static size_t reg_read(char (**dst)[IFNAMSIZ]) {
    *dst = NULL;
    char path[512];
    reg_path(path, sizeof path);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    size_t n = 0, cap = 0;
    char line[64];
    while (fgets(line, sizeof line, f)) {
        char *t = awg_dev_trim(line);
        if (!*t || strlen(t) >= IFNAMSIZ || !name_ok(t)) continue;
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 16;
            char (*nv)[IFNAMSIZ] = realloc(*dst, nc * sizeof(*nv));
            if (!nv) break;
            *dst = nv;
            cap = nc;
        }
        snprintf((*dst)[n++], IFNAMSIZ, "%s", t);
    }
    fclose(f);
    return n;
}

static void reg_write(char devs[][IFNAMSIZ], size_t n) {
    char path[512], tmp[544];
    reg_path(path, sizeof path);
    snprintf(tmp, sizeof tmp, "%s.new", path);
    mkdir(steer_state_dir(), 0755);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    for (size_t i = 0; i < n; i++) fprintf(f, "%s\n", devs[i]);
    if (fclose(f) != 0 || rename(tmp, path) != 0) unlink(tmp);
}


/* ---- замеры счётчиков для сторожа: в памяти круга или в файле ------------------------------
 *
 * ЗАЧЕМ ПАМЯТЬ. Приговор «туннель молчит» (см. «здоровье» ниже) сравнивает счётчики пира с
 * прошлым проходом сторожа, и прошлый замер надо где-то хранить между проходами. Раньше это был
 * файл <state>/awg-<устройство>.hs, и писался он КАЖДЫЙ проход — счётчики и время меняются
 * всегда. На телефоне каталог состояния — /data, то есть флеш, а проход — раз в минуту и по
 * каждому событию сети: это постоянные записи во флеш круглые сутки, против требования
 * владельца о батарее и сне (на роутере state — tmpfs, там это ничего не стоило).
 *
 * На телефоне сторож — `failover --loop` (или демон с --watch): один долгоживущий процесс, и
 * проход идёт в нём же, автоматом на его цикле событий (failover.c). Прошлые замеры проход
 * берёт из памяти процесса и туда же кладёт новые. Замеров в файл круг не пишет вовсе; файл
 * остаётся для одиночного прохода (круг procd на роутере), где памяти между проходами нет. Сна
 * это не касается: во сне проходов нет вовсе. */
struct hs_sample {
    char dev[IFNAMSIZ];
    unsigned long long tx, rx;
    long t;
    int v;
};
/* Замеры в памяти процесса (--loop, демон) — по устройству, растут по их числу. */
static struct hs_sample *g_hs;
static size_t g_hs_n, g_hs_cap;
static int g_hs_mem;

void awg_hs_memory(int on) { g_hs_mem = on; }

static int hs_get(const char *dev, struct hs_sample *out) {
    if (g_hs_mem) {
        for (size_t i = 0; i < g_hs_n; i++)
            if (!strcmp(g_hs[i].dev, dev)) { *out = g_hs[i]; return 0; }
        return -1;
    }
    char p[512];
    snprintf(p, sizeof p, "%s/awg-%s.hs", steer_state_dir(), dev);
    FILE *f = fopen(p, "r");
    if (!f) return -1;
    int ok = fscanf(f, "%llu %llu %ld %d", &out->tx, &out->rx, &out->t, &out->v) == 4;
    fclose(f);
    return ok ? 0 : -1;
}

static void hs_put(const char *dev, const struct hs_sample *s) {
    if (g_hs_mem) {
        size_t i = 0;
        while (i < g_hs_n && strcmp(g_hs[i].dev, dev)) i++;
        if (i == g_hs_n) {
            if (g_hs_n == g_hs_cap) {
                size_t nc = g_hs_cap ? g_hs_cap * 2 : 16;
                struct hs_sample *nh = realloc(g_hs, nc * sizeof(*nh));
                if (!nh) return;
                g_hs = nh;
                g_hs_cap = nc;
            }
            g_hs_n++;
        }
        g_hs[i] = *s;
        snprintf(g_hs[i].dev, sizeof g_hs[i].dev, "%s", dev);
        return;
    }
    char p[512];
    snprintf(p, sizeof p, "%s/awg-%s.hs", steer_state_dir(), dev);
    FILE *f = fopen(p, "w");
    if (!f) return;
    fprintf(f, "%llu %llu %ld %d\n", s->tx, s->rx, s->t, s->v);
    fclose(f);
}


/* ---- настройка одного выхода ------------------------------------------------------------ */

/* Поднять и настроить устройство выхода. loud — apply (предупреждения о файле печатаются);
 * сторож зовёт тихо, чтобы раз в пять минут не повторять одно и то же. 0 — готово. */
/* Член группы `kind: warp`, файла которого ещё нет: точку ему подбирает модуль steer-warpbox и
 * пишет файл сам, а затем просит демон перенастроить член (событие awg, daemon/supd.c). До того
 * поднимать нечего, и это не ошибка файла — ни apply, ни сторож не шумят о нём. */
static int warp_waiting(const struct output *o) {
    return out_owned_by(o, NULL, NULL) && o->owner_out && access(o->awg.conf, F_OK) != 0;
}

/* awg_refresh: следующий awg_configure снимает пиры и ставит заново (новая сессия). */
static int g_awg_fresh;

static int awg_configure(const struct spec *sp, const struct output *o, int loud,
                         const struct kind_name *names, size_t nn) {
    if (warp_waiting(o)) return -1;
    uint32_t fwmark;
    const char *via = awg_out_via(o);
    if (awg_sock_mark(sp, via, &fwmark) != 0) {
        fprintf(stderr, LOG_W "выход %s: via %s — такого выхода нет\n", o->name, via);
        return -1;
    }
    return awg_dev_configure(o->name, o->device, o->awg.conf, fwmark, via, loud, g_awg_fresh, names, nn);
}

/* ---- apply и down ------------------------------------------------------------------------ */

int awg_apply_all(const struct spec *sp) {
    char (*reg)[IFNAMSIZ];
    size_t reg_n = reg_read(&reg), keep_n = 0;
    /* Оставляемые устройства — не больше выходов спеки. */
    char (*keep)[IFNAMSIZ] = calloc(sp->out_n ? sp->out_n : 1, sizeof(*keep));
    if (!keep) { free(reg); return 1; }
    int bad = 0;
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        if (kind_of(o) != &kind_awg) continue;
        /* Два выхода на одно устройство настраивали бы его по очереди, и победил бы второй —
         * молча. Имена выводятся из имён выходов, так что это почти всегда явный `device`. */
        int dup = 0;
        for (size_t k = 0; k < i; k++)
            if (kind_of(&sp->out[k]) == &kind_awg && !strcmp(sp->out[k].device, o->device)) dup = 1;
        if (dup) {
            fprintf(stderr, LOG_W "выход %s: устройство %s уже занято другим выходом kind=awg\n",
                    o->name, o->device);
            bad++;
            continue;
        }
        if (warp_waiting(o))
            fprintf(stderr, LOG_I "выход %s: ждёт точку WARP от модуля steer-warpbox\n", o->name);
        else if (awg_configure(sp, o, 1, NULL, 0) != 0) bad++;
        /* В реестр — даже при отказе: устройство могло быть создано до отказа настройки, и
         * снять его потом должен кто-то. */
        snprintf(keep[keep_n++], IFNAMSIZ, "%.15s", o->device);
    }
    /* Выходы, которых в спеке больше нет: их устройства снимаются. Только наши по виду — имя
     * из реестра могло с тех пор достаться чужому устройству. */
    for (size_t r = 0; r < reg_n; r++) {
        int live = 0;
        for (size_t k = 0; k < keep_n; k++) if (!strcmp(reg[r], keep[k])) live = 1;
        if (live) continue;
        char kind[32] = "";
        if (awg_dev_link_query(reg[r], kind, sizeof kind, NULL) == 0 && awg_dev_ours(kind)) {
            awg_dev_link_delete(reg[r]);
            fprintf(stderr, LOG_I "устройство %s снято — его выхода больше нет\n", reg[r]);
        }
        awg_dev_state_drop(reg[r]);
    }
    if (keep_n || reg_n) reg_write(keep, keep_n);
    free(reg);
    free(keep);
    return bad;
}

int awg_check_all(const struct spec *sp) {
    int bad = 0;
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        if (kind_of(o) != &kind_awg || warp_waiting(o)) continue;
        static struct awg_conf c;
        struct awg_secrets s;
        char err[256];
        if (awg_conf_load(o->awg.conf, &c, &s, err, sizeof err) != 0) {
            fprintf(stderr, LOG_W "выход %s: %s\n", o->name, err);
            bad++;
            continue;
        }
        char verr[512];
        if (awg_via_check(&c, awg_out_via(o), verr, sizeof verr) != 0) {
            fprintf(stderr, LOG_W "выход %s: %s\n", o->name, verr);
            bad++;
        }
        awg_secrets_wipe(&s);
        awg_conf_free(&c);
    }
    return bad;
}

void awg_down_all(void) {
    char (*reg)[IFNAMSIZ];
    size_t n = reg_read(&reg);
    for (size_t i = 0; i < n; i++) {
        char kind[32] = "";
        if (awg_dev_link_query(reg[i], kind, sizeof kind, NULL) == 0 && awg_dev_ours(kind))
            awg_dev_link_delete(reg[i]);
        awg_dev_state_drop(reg[i]);
    }
    free(reg);
    char path[512];
    reg_path(path, sizeof path);
    unlink(path);
}

/* ---- здоровье ------------------------------------------------------------------------------
 *
 * ПО РУКОПОЖАТИЮ, БЕЗ ПРОБ. Пока через туннель идёт трафик, WireGuard обновляет ключи не реже
 * чем раз в REKEY_AFTER_TIME (120 с), а через REJECT_AFTER_TIME (180 с) без нового рукопожатия
 * перестаёт шифровать вовсе. Значит рукопожатие моложе 180 с — туннель жив, и это видно без
 * единого пакета от нас.
 *
 * Старое рукопожатие само по себе НЕ приговор: туннель, по которому никто ничего не шлёт,
 * рукопожатий не делает, и так и должно быть — пробуждать радио ради проверки нельзя.
 * Приговор даёт сравнение счётчиков с прошлым проходом сторожа: если за это время мы что-то
 * отправили (tx вырос — это и данные, и попытки рукопожатия), а в ответ не пришло ни байта (rx
 * стоит), при старом рукопожатии — пир молчит. Прошлого замера нет или он моложе 15 с (две
 * попытки рукопожатия WireGuard идут с шагом 5 с) — прежний приговор, а при его отсутствии —
 * «живо»: сказать нечего, а ошибка в сторону «сломано» при on_fail=drop ставит запрет
 * работающему выходу.
 *
 * ЦЕНА этого выбора, и её надо знать. Упавший выход с on_fail=drop стоит на blackhole: трафик
 * в туннель не идёт, tx не растёт — и следующий проход видит «тишину», то есть «живо», и
 * возвращает маршрут. Если пир по-прежнему мёртв, трафик следующего прохода это покажет, и
 * выход снова уйдёт в отказ. То есть мёртвый туннель проверяется настоящим трафиком раз в два
 * прохода сторожа — это и есть проба, только из того, что человек и так шлёт, без
 * собственных пакетов и таймеров. Кому нужно быстрее — тот задаёт PersistentKeepalive. */
#define AWG_HS_FRESH 180
#define AWG_SAMPLE_MIN 15

static long boot_now(void) {
    struct timespec ts;
#ifdef CLOCK_BOOTTIME
    /* BOOTTIME, а не MONOTONIC: телефон спит, и сон между проходами тоже время — иначе
     * замер «15 секунд назад» после ночи сна значил бы «только что». */
    if (clock_gettime(CLOCK_BOOTTIME, &ts) == 0) return (long)ts.tv_sec;
#endif
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec;
}

static const char *live_kind_of(const char *dev, char *buf, size_t n) {
    if (awg_dev_link_query(dev, buf, n, NULL) != 0 || !awg_dev_ours(buf)) return NULL;
    return buf;
}

int awg_healthy(const struct output *o, const char *dev) {
    char kb[32];
    const char *kind = live_kind_of(dev, kb, sizeof kb);
    if (!kind) return 0;                /* устройства нет или оно не наше */
    static struct awg_live L;
    if (awg_dev_live_read(dev, kind, &L) != 0) return 1;   /* спросить не вышло — не приговор */
    int fresh_s = AWG_HS_FRESH;
    /* RejectAfterTime в файле (AmneziaWG 3) растягивает жизнь ключей — и порог вместе с ней. */
    {
        static struct awg_conf c;
        struct awg_secrets s;
        char err[128];
        if (o && awg_conf_load(o->awg.conf, &c, &s, err, sizeof err) == 0) {
            if ((c.r16_has >> AWG_REJECT_AFTER) & 1) {
                int ra = (int)(c.r16[AWG_REJECT_AFTER] >> 16);
                if (ra > fresh_s) fresh_s = ra;
            }
            awg_secrets_wipe(&s);
            awg_conf_free(&c);
        }
    }
    int64_t newest = 0;
    uint64_t rx = 0, tx = 0;
    for (size_t i = 0; i < L.peer_n; i++) {
        if (L.peer[i].hs > newest) newest = L.peer[i].hs;
        rx += L.peer[i].rx;
        tx += L.peer[i].tx;
    }
    long now = boot_now();
    /* Прошлый замер — из памяти круга или из файла (см. «замеры счётчиков для сторожа»). */
    struct hs_sample prev;
    unsigned long long ptx = 0, prx = 0;
    long pt = 0;
    int pv = -1;
    if (hs_get(dev, &prev) == 0) { ptx = prev.tx; prx = prev.rx; pt = prev.t; pv = prev.v; }
    int verdict;
    int64_t age = newest ? (int64_t)time(NULL) - newest : -1;
    if (newest && age >= 0 && age <= fresh_s) verdict = 1;
    else if (pv < 0 || tx < ptx || rx < prx) verdict = 1;          /* нет замера или счётчики сброшены */
    else if (now - pt < AWG_SAMPLE_MIN) return pv;                  /* рано судить — прежний приговор */
    else verdict = !(tx > ptx && rx == prx);
    struct hs_sample cur = { .tx = tx, .rx = rx, .t = now, .v = verdict };
    hs_put(dev, &cur);
    return verdict;
}

int awg_revive(const struct spec *sp, const struct output *o, const char *dev,
               const struct kind_name *names, size_t n) {
    /* Устройства нет — это не «молчит», а «ещё не поднято»: так бывает при каждом включении
     * движка на телефоне, где сторож стартует раньше, чем выход успел создать устройство, и
     * после ручного `ip link del`. Предупреждение о молчащем пире в этом случае — ложная
     * тревога, которую человек видит в журнале приложения, поэтому причины разведены. */
    char kb[32];
    if (warp_waiting(o)) return 0;
    if (!live_kind_of(dev, kb, sizeof kb))
        fprintf(stderr, LOG_I "%s: устройства нет — поднимаю\n", dev);
    else
        fprintf(stderr, LOG_W "%s: туннель молчит — заново разрешаю Endpoint и перенастраиваю\n", dev);
    if (awg_configure(sp, o, 0, names, n) != 0) return 0;
    return awg_healthy(o, dev);
}

int awg_refresh(const struct spec *sp, const struct output *o) {
    if (warp_waiting(o)) return -1;
    g_awg_fresh = 1;
    int rc = awg_configure(sp, o, 0, NULL, 0);
    g_awg_fresh = 0;
    if (rc == 0) fprintf(stderr, LOG_I "%s: новая точка — туннель перенастроен с новой сессией\n", o->device);
    return rc;
}

/* Имена Endpoint, которые починка разрешит, — чтобы сторож разрешил их заранее, не останавливая
 * цикл демона (kind_name в kinds/kind.h, рабочий поток — src/daemon/gaiw.c). Литерал адреса —
 * тоже имя: getaddrinfo ответит на него сразу, и отдельная ветка ради него не нужна. */
size_t awg_revive_names(const struct spec *sp, const struct output *o, struct kind_name *dst,
                        size_t max) {
    (void)sp;
    static struct awg_conf c;
    struct awg_secrets s;
    char err[256];
    if (awg_conf_load(o->awg.conf, &c, &s, err, sizeof err) != 0) {
        awg_secrets_wipe(&s);
        awg_conf_free(&c);
        return 0;
    }
    int v4only = awg_out_via(o) != NULL;
    size_t n = 0;
    for (size_t i = 0; i < c.peer_n && n < max; i++) {
        if (!c.peer[i].has_ep) continue;
        memset(&dst[n], 0, sizeof dst[n]);
        snprintf(dst[n].host, sizeof dst[n].host, "%s", c.peer[i].ep_host);
        dst[n].port = c.peer[i].ep_port;
        dst[n].v4only = v4only;
        n++;
    }
    awg_secrets_wipe(&s);
    awg_conf_free(&c);
    return n;
}

/* ---- status ------------------------------------------------------------------------------ */

static void ep_str(const struct sockaddr_storage *ss, socklen_t len, char *dst, size_t n) {
    char a[INET6_ADDRSTRLEN] = "";
    if (len >= sizeof(struct sockaddr_in) && ss->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const void *)ss;
        inet_ntop(AF_INET, &s4->sin_addr, a, sizeof a);
        snprintf(dst, n, "%s:%u", a, ntohs(s4->sin_port));
    } else if (len >= sizeof(struct sockaddr_in6) && ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const void *)ss;
        inet_ntop(AF_INET6, &s6->sin6_addr, a, sizeof a);
        snprintf(dst, n, "[%s]:%u", a, ntohs(s6->sin6_port));
    } else dst[0] = '\0';
}

/* Состояние туннеля одним объектом рядом с device/up: status опрашивают раз в несколько
 * секунд, и это один разговор с ядром (дамп устройства) на выход — без проб и без файлов.
 * Итог по пирам сводится: самое свежее рукопожатие, суммы счётчиков, эндпоинт первого пира
 * (у клиента пир один — сервер). Ключей в выводе нет никаких, и публичных тоже: интерфейсу
 * они ни к чему, а лишнее поле в выводе, который уходит в резервные копии и отчёты, — лишнее. */
void awg_status_json(FILE *out, const struct output *o) {
    char kb[32];
    const char *kind = live_kind_of(o->device, kb, sizeof kb);
    static struct awg_live L;
    if (!kind || awg_dev_live_read(o->device, kind, &L) != 0) {
        fprintf(out, ",\"awg\":{\"live\":false}");
        return;
    }
    int64_t newest = 0;
    uint64_t rx = 0, tx = 0;
    for (size_t i = 0; i < L.peer_n; i++) {
        if (L.peer[i].hs > newest) newest = L.peer[i].hs;
        rx += L.peer[i].rx;
        tx += L.peer[i].tx;
    }
    fprintf(out, ",\"awg\":{\"live\":true,\"impl\":\"%s\",\"peers\":%zu", kind, L.peer_n);
    if (newest) {
        long long ago = (long long)time(NULL) - (long long)newest;
        if (ago < 0) ago = 0;
        fprintf(out, ",\"handshake_ago\":%lld", ago);
    } else fprintf(out, ",\"handshake_ago\":null");
    fprintf(out, ",\"rx\":%llu,\"tx\":%llu", (unsigned long long)rx, (unsigned long long)tx);
    char ep[80] = "";
    if (L.peer_n) ep_str(&L.peer[0].ep, L.peer[0].ep_len, ep, sizeof ep);
    if (ep[0]) fprintf(out, ",\"endpoint\":\"%s\"", ep);
    else fprintf(out, ",\"endpoint\":null");
    fprintf(out, "}");
}

/* ---- вид выхода ---------------------------------------------------------------------------
 *
 * awg — туннель AmneziaWG/WireGuard в ядре, который создаёт и настраивает сам движок (зачем — в
 * шапке awg.h). Для остальной части движка это выход С УСТРОЙСТВОМ, как interface: метка,
 * таблица, masquerade. Отличие — чья жизнь устройства: его заводит apply и снимает down, поэтому
 * out_engine_managed про него правда (ifdown/ifup netifd бесполезны), а out_self_natting — ложь:
 * адреса клиентов уходят в туннель как есть и переводятся в адрес туннеля, ровно как у
 * wireguard под netifd. В базовой сборке, а не в extended: ни TLS, ни криптобиблиотека ему не нужны,
 * только netlink. */
static int awg_parse(struct output *o, const struct out_keys *k, struct err *e) {
    snprintf(o->awg.conf, sizeof(o->awg.conf), "%s", k->conf);
    /* Устройство у выхода ОДНО — его создаёт этот выход. Пул из нескольких туннелей
     * собирается выходом kind=interface, в devices которого названо и это устройство;
     * список здесь означал бы устройства, которые никто не создаст. */
    if (k->devices_n > 1 ||
        (k->devices_n == 1 && o->device[0] && strcmp(o->device, k->devices[0]) != 0))
        return err_setc(e, "spec.awg_one_device", "outputs.%s: у kind awg одно устройство — его заводит ядро steer; пул "
            "собирается выходом kind=interface", o->name);
    if (k->devices_n == 1 && !o->device[0])
        snprintf(o->device, sizeof(o->device), "%s", k->devices[0]);
    /* Имя устройства выбирает движок так, чтобы оно не выдавало туннель (см.
     * awg_default_ifname в awg.h). Названное явно обязано тому же правилу: приложение
     * видит имена интерфейсов, и «wg0» рядом с wlan0 — это ровно тот след, которого
     * владелец просил не оставлять. */
    if (o->device[0]) {
        if (strlen(o->device) > 15)
            return err_setc(e, "spec.device_name_long", "outputs.%s: имя устройства длиннее 15 символов", o->name);
        if (awg_ifname_conspicuous(o->device))
            return err_setc(e, "spec.device_name_tunnel", "outputs.%s: имя устройства выдаёт туннель (tun, wg, awg, ppp, vpn…) — "
                "уберите device, и ядро steer выберет имя само", o->name);
    } else awg_default_ifname(o->name, o->device, sizeof(o->device));
    /* Путь к файлу — тем же порядком, что у xsteer: по умолчанию из имени выхода, иначе
     * абсолютный и годный к JSON (печатается в status и diag). */
    if (!o->awg.conf[0])
        snprintf(o->awg.conf, sizeof(o->awg.conf), "%s/awg/%.200s.conf", plat()->etc_dir, o->name);
    else if (o->awg.conf[0] != '/' || !label_ok(o->awg.conf))
        return err_setc(e, "spec.awg_conf_path", "outputs.%s: conf должен быть абсолютным путём без кавычек", o->name);
    return 0;
}

/* Обратное awg_parse (`steer spec convert`): путь и имя устройства, выведенные из имени выхода,
 * не пишутся. */
static void awg_keys_of(const struct output *o, struct out_keys *k) {
    char def[256];
    snprintf(def, sizeof(def), "%s/awg/%.200s.conf", plat()->etc_dir, o->name);
    if (strcmp(def, o->awg.conf) != 0) snprintf(k->conf, sizeof(k->conf), "%s", o->awg.conf);
    char dev[32];
    awg_default_ifname(o->name, dev, sizeof(dev));
    k->device_derived = !strcmp(dev, o->device);
}

/* Мера — свежесть рукопожатия и счётчики пира, которые ядро и так ведёт, без единого пакета от
 * нас. Ни ping, ни проба TCP: и то и другое будило бы радио телефона ради вопроса, на который
 * ответ уже лежит в ядре, — см. awg_healthy выше, там же почему старое рукопожатие само по себе
 * не приговор. */
static int awg_health(const struct spec *sp, const struct output *o, const char *dev) {
    (void)sp;
    return awg_healthy(o, dev);
}

/* Рукопожатие, счётчики, эндпоинт — из ядра, см. awg_status_json. */
static void awg_status(FILE *out, const struct spec *sp, const struct output *o) {
    (void)sp;
    awg_status_json(out, o);
}

const struct kind_ops kind_awg = {
    .name = "awg",
    .caps = KC_DEVICE | KC_MARK | KC_CTMARK | KC_ENGINE_OWNED | KC_OVER | KC_SKIP_ZAPRET | KC_IPV6,
    .keys = KK_CONF,
    .parse = awg_parse,
    .keys_of = awg_keys_of,
    .health = awg_health,
    /* Чинится не ожиданием: процесса, который поднял бы туннель заново, нет — устройство живёт в
     * ядре. Лечится то же, что у netifd лечит ifdown/ifup: см. awg_revive выше. */
    .revive = awg_revive,
    .revive_names = awg_revive_names,
    .status = awg_status,
};
