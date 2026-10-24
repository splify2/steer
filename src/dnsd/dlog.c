#include "dnsd_int.h"
#include "sindex.h"
#include "jsonw.h"

/* ---- журнал имён: `steer dns-log` (команда dns-log управляющего сокета) ----------------
 *
 * ЗАЧЕМ. Экран «Соединения и DNS» приложения (план C1): какие имена недавно спрашивали, в какой
 * канал каждое попало (или мимо всех), сколько раз и когда последний раз. Это ответ на вопрос
 * «почему сайт не идёт в туннель» с другой стороны, чем explain: explain говорит, куда ПОПАЛО
 * БЫ имя, журнал — что на самом деле спрашивали приложения и что им досталось.
 *
 * ЧТО ХРАНИТСЯ. По записи на имя: имя (нижним регистром), доменный канал, в который оно попало
 * при последнем запросе, счётчик запросов и время последнего. Ни адреса клиента, ни типа
 * запроса, ни ответа: «без персональных данных сверх имени» — журнал показывает, КУДА ушло
 * имя, а не КТО и что спросил. Записей — не меньше DLOG_MIN (256), и это «недавние», а не
 * история: самая давняя запись уступает место новому имени, только если она старше DLOG_RECENT_SEC;
 * пока все записи свежее, таблица растёт — у сервера с сотнями клиентов за десять минут бывают
 * тысячи имён, и прежние 256 стирали их за секунды, не показывая человеку почти ничего.
 *
 * ГДЕ. Только в памяти резолвера. Никаких периодических записей на диск — флеш телефона и сон
 * устройства дороже истории, которая после перезапуска резолвера никому не нужна. Журнал
 * отдаётся по запросу, и ради запроса резолвер ничего не пишет на диск тоже.
 *
 * КАК ОТДАЁТСЯ — свой маленький unix-сокет резолвера, <каталог состояния>/dnsd.sock: клиент
 * (`steer dns-log`, её зовёт сервер управляющего сокета) подключается, резолвер сразу пишет
 * журнал одним объектом JSON и закрывает соединение. Запроса нет вовсе — резолвер ничего не
 * читает от собеседника, поэтому медленный или молчащий клиент ему не страшен.
 *
 * Почему сокет, а не «SIGUSR1 — сбросить журнал в файл, который прочтёт ctl». (1) Файл — это
 * запись на флеш на каждое открытие экрана: каталог состояния на телефоне — /data, tmpfs для
 * движка там нет. (2) Сигнал асинхронен: читающему пришлось бы ждать появления файла опросом
 * со сроком — то есть гадать, дописан ли файл и не от прошлого ли он запроса. Сокет отвечает
 * синхронно, ровно тем, что лежит в памяти в эту секунду. (3) Найти резолвер для сигнала —
 * обход /proc (ctl_find); сокет находится по имени.
 *
 * ДОСТУП. Каталог состояния — 0700 и тип steerd_data_file, приложениям не листается; сам сокет
 * создаётся с правами 0600, и резолвер ещё сверяет собеседника (SO_PEERCRED): root или тот же
 * uid, что у него. Сокет в каталоге состояния получает тип каталога (steerd_data_file), своего
 * типа ему не нужно: подключается к нему только домен движка (steerd), в котором живёт и
 * сервер управляющего сокета. Приложение журнал получает только через управляющий сокет.
 *
 * СТОИМОСТЬ НА ЗАПРОС. Поиск имени — по хэшу (корзины с цепочками, FNV-1a, sidx_hash), давность —
 * двусвязный список от свежих к давним: поиск, вытеснение и обновление не зависят от числа записей. */
#define DLOG_MIN 256
#define DLOG_RECENT_SEC 600

struct dlog_ent {
    char name[MAX_HOSTNAME];
    uint32_t hash;
    uint32_t count;
    time_t last;                /* CLOCK_MONOTONIC, секунды: часы телефона после загрузки
                                 * переводит NTP, и «когда» по стенным часам прыгало бы */
    int16_t hit;                /* индекс в g_dch; -1 — мимо всех доменных каналов */
    int32_t chain;              /* следующая запись той же корзины, -1 — конец */
    int32_t newer, older;       /* список давности: свежее и давнее, -1 — край */
};
static struct dlog_ent *g_dlog;
static size_t g_dlog_n, g_dlog_cap;
static int32_t *g_dlog_bk;      /* головы цепочек; размер — степень двойки, вдвое больше g_dlog_cap */
static size_t g_dlog_bkn;
static int32_t g_dlog_head = -1, g_dlog_tail = -1;
int g_dlog_fd = -1;
static char g_dlog_path[PATH_MAX];
static ino_t g_dlog_ino;

static time_t dlog_mono(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec;
}

static void dlog_unlink_list(int32_t i) {
    struct dlog_ent *e = &g_dlog[i];
    if (e->newer >= 0) g_dlog[e->newer].older = e->older; else g_dlog_head = e->older;
    if (e->older >= 0) g_dlog[e->older].newer = e->newer; else g_dlog_tail = e->newer;
}

static void dlog_push_head(int32_t i) {
    struct dlog_ent *e = &g_dlog[i];
    e->newer = -1;
    e->older = g_dlog_head;
    if (g_dlog_head >= 0) g_dlog[g_dlog_head].newer = i; else g_dlog_tail = i;
    g_dlog_head = i;
}

static void dlog_unchain(int32_t i) {
    int32_t *pp = &g_dlog_bk[g_dlog[i].hash & (g_dlog_bkn - 1)];
    while (*pp != i) pp = &g_dlog[*pp].chain;
    *pp = g_dlog[i].chain;
}

static void dlog_chain(int32_t i) {
    int32_t *b = &g_dlog_bk[g_dlog[i].hash & (g_dlog_bkn - 1)];
    g_dlog[i].chain = *b;
    *b = i;
}

/* Расти вдвое; индексы записей остаются теми же, корзины строятся заново. */
static int dlog_grow(void) {
    size_t nc = g_dlog_cap ? g_dlog_cap * 2 : DLOG_MIN;
    int32_t *nb = malloc(nc * 2 * sizeof(*nb));
    if (!nb) return -1;
    struct dlog_ent *ne = realloc(g_dlog, nc * sizeof(*ne));
    if (!ne) { free(nb); return -1; }
    g_dlog = ne;
    free(g_dlog_bk);
    g_dlog_bk = nb;
    g_dlog_bkn = nc * 2;
    for (size_t k = 0; k < g_dlog_bkn; k++) g_dlog_bk[k] = -1;
    g_dlog_cap = nc;
    for (size_t i = 0; i < g_dlog_n; i++) dlog_chain((int32_t)i);
    return 0;
}

/* Сколько записей сейчас (для проверки). */
size_t dlog_count(void) { return g_dlog_n; }

/* Отметить запрос имени qname, попавшего в канал hit (-1 — мимо). */
void dlog_note(const char *qname, int hit) {
    char lname[MAX_HOSTNAME];
    snprintf(lname, sizeof(lname), "%s", qname);
    str_lower(lname);
    uint32_t h = sidx_hash(lname);
    time_t now = dlog_mono();
    int32_t ix = -1;
    if (g_dlog_bkn)
        for (int32_t i = g_dlog_bk[h & (g_dlog_bkn - 1)]; i >= 0; i = g_dlog[i].chain)
            if (g_dlog[i].hash == h && !strcmp(g_dlog[i].name, lname)) { ix = i; break; }
    if (ix >= 0) {
        dlog_unlink_list(ix);
    } else {
        int stale = g_dlog_tail >= 0 && now - g_dlog[g_dlog_tail].last > DLOG_RECENT_SEC;
        if (g_dlog_n >= g_dlog_cap && !stale && dlog_grow() != 0 && g_dlog_tail < 0) return;
        if (g_dlog_n < g_dlog_cap) {
            ix = (int32_t)g_dlog_n++;
        } else {
            ix = g_dlog_tail;                    /* устарела либо расти некуда — самая давняя */
            dlog_unlink_list(ix);
            dlog_unchain(ix);
        }
        struct dlog_ent *e = &g_dlog[ix];
        snprintf(e->name, sizeof(e->name), "%s", lname);
        e->hash = h;
        e->count = 0;
        dlog_chain(ix);
    }
    struct dlog_ent *e = &g_dlog[ix];
    e->count++;
    e->last = now;
    e->hit = (int16_t)hit;
    dlog_push_head(ix);
}

static int dlog_cmp(const void *a, const void *b) {
    const struct dlog_ent *x = *(const struct dlog_ent *const *)a;
    const struct dlog_ent *y = *(const struct dlog_ent *const *)b;
    if (x->last != y->last) return x->last < y->last ? 1 : -1;
    return x->count < y->count ? 1 : x->count > y->count ? -1 : 0;
}

/* Журнал одним объектом JSON — свежие имена первыми. */
static char *dlog_render(size_t *len) {
    char *mem = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&mem, &n);
    if (!f) return NULL;
    struct dlog_ent **ord = malloc((g_dlog_n ? g_dlog_n : 1) * sizeof(*ord));
    if (!ord) { fclose(f); free(mem); return NULL; }
    for (size_t i = 0; i < g_dlog_n; i++) ord[i] = &g_dlog[i];
    qsort(ord, g_dlog_n, sizeof(ord[0]), dlog_cmp);
    time_t mono = dlog_mono(), wall = time(NULL);
    fprintf(f, "{\"schema\":1,\"running\":true,\"size\":%zu,\"names\":[", g_dlog_cap > DLOG_MIN ? g_dlog_cap : (size_t)DLOG_MIN);
    for (size_t i = 0; i < g_dlog_n; i++) {
        const struct dlog_ent *e = ord[i];
        long ago = (long)(mono - e->last);
        fputs(i ? ",{\"name\":" : "{\"name\":", f);
        jsonw_str_ascii(f, e->name);
        fputs(",\"channel\":", f);
        /* Индекс вне таблицы быть не может (таблица каналов не пересобирается до выхода
         * резолвера — см. dch_signature), но граница сверяется всё равно. */
        if (e->hit >= 0 && (size_t)e->hit < g_dch_n) {
            /* Имя канала — имя правила из спеки, и оно бывает кириллицей («Мои сайты»). Писатель
             * ASCII печатал каждый байт UTF-8 как \u00XX — то есть как символ Latin-1, и журнал
             * имён в splify2 показывал «ÐÐ¾Ð¸ ÑÐ°Ð¹ÑÑ» (снято с QEMU-стенда). Спека — JSON, то есть
             * уже UTF-8; экранируются кавычки, обратная черта и управляющие байты. Имя из
             * запроса (выше) и выход (name_ok — ASCII) остаются у писателя ASCII. */
            jsonw_str(f, g_dch[e->hit].chan);
            fputs(",\"out\":", f);
            jsonw_str_ascii(f, g_dch[e->hit].out);
        } else {
            fputs("null,\"out\":null", f);
        }
        /* Каким сервером или группой отвечает резолвер на это имя (по нынешней таблице): у канала —
         * его апстрим, вне правил — `dns.other`; null — прежний путь (DNS роутера). */
        unsigned du = 0;
        if (e->hit >= 0 && (size_t)e->hit < g_dch_n) du = (unsigned)g_dch[e->hit].up;
        else if (e->hit == -1 && g_dup_other && !name_local(e->name)) du = g_dup_other;
        fputs(",\"dns\":", f);
        /* Имя апстрима — ключ dns.upstreams (ASCII) или, у своего сервера правила, имя правила
         * (бывает кириллицей) — пишется как имя канала, UTF-8 как есть. */
        if (du && du <= g_dup_cfg_n) jsonw_str(f, g_dup_cfg[du - 1].u.name);
        else fputs("null", f);
        fprintf(f, ",\"count\":%u,\"last\":%lld,\"ago\":%ld}", e->count,
                (long long)(wall - ago), ago);
    }
    /* Апстримы со своим транспортом и кэш (1.11): состояние, счётчики, последняя ошибка. Ключи
     * добавлены в конец — читатель схемы 1 их не знает и не спотыкается. */
    free(ord);
    fputs("],\"upstreams\":[", f);
    dup_render(f);
    fputs("],\"cache\":", f);
    if (dcache_on()) dcache_render(f);
    else fputs("null", f);
    /* Сервер имён вне правил (`dns.other`): имя, пауза после отказа (секунд до конца; 0 — нет),
     * годных ответов, отказов и вопросов, ушедших вместо него прежним путём. null — не задан. */
    fputs(",\"other\":", f);
    if (g_dup_other && g_dup_other <= g_dup_cfg_n) {
        long now = dup_now_ms();
        long left = dpause_on(&g_other_pause, now) ? (g_other_pause.until_ms - now + 999) / 1000 : 0;
        fputs("{\"name\":", f);
        jsonw_str(f, g_dup_cfg[g_dup_other - 1].u.name);
        fprintf(f, ",\"pause\":%ld,\"ok\":%lu,\"failed\":%lu,\"fallback\":%lu}", left,
                g_other_pause.ok, g_other_pause.fail, g_other_fallback);
    } else {
        fputs("null", f);
    }
    fputs("}\n", f);
    if (fclose(f) != 0) { free(mem); return NULL; }
    *len = n;
    return mem;
}

/* Слушающий сокет журнала. Не вышло — резолвер работает дальше без журнала (строка в stderr):
 * журнал — окно для человека, а не часть разрешения имён. */
void dlog_listen(void) {
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    if ((size_t)snprintf(g_dlog_path, sizeof(g_dlog_path), "%s/dnsd.sock", steer_state_dir()) >=
            sizeof(a.sun_path)) {
        fprintf(stderr, "steer[warn] dnsd: путь сокета журнала слишком длинный — журнала не будет\n");
        g_dlog_path[0] = '\0';
        return;
    }
    memcpy(a.sun_path, g_dlog_path, strlen(g_dlog_path) + 1);   /* длина сверена выше */
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return;
    /* Прежний файл — от упавшего резолвера: второй резолвер на том же каталоге состояния
     * делил бы с первым и dnsd.sig, так что проверять «жив ли сосед» здесь незачем. */
    unlink(g_dlog_path);
    mode_t old = umask(0177);                  /* 0600 с рождения, как у ctl-serve (ctl_listen) */
    int rc = bind(fd, (struct sockaddr *)&a, sizeof(a));
    umask(old);
    if (rc != 0 || listen(fd, 4) != 0) {
        fprintf(stderr, "steer[warn] dnsd: сокет журнала %s: %s — журнала не будет\n",
                g_dlog_path, strerror(errno));
        close(fd);
        g_dlog_path[0] = '\0';
        return;
    }
    struct stat sb;
    g_dlog_ino = stat(g_dlog_path, &sb) == 0 ? sb.st_ino : 0;
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.ptr = &g_dlog_fd;
    g_dlog_fd = fd;
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        close(fd);
        g_dlog_fd = -1;
        unlink(g_dlog_path);
        g_dlog_path[0] = '\0';
    }
}

void dlog_close(void) {
    if (g_dlog_fd < 0) return;
    close(g_dlog_fd);
    g_dlog_fd = -1;
    struct stat sb;
    if (g_dlog_path[0] && g_dlog_ino && stat(g_dlog_path, &sb) == 0 && sb.st_ino == g_dlog_ino)
        unlink(g_dlog_path);
}

/* Подключились к сокету журнала: отдать журнал и закрыть. Запись — со сроком 200 мс на всё:
 * ответ (до ~80 КиБ) обычно целиком ложится в буфер сокета за один вызов, а собеседник,
 * который не читает, не должен держать разрешение имён дольше этого. */
/* Раскладка ответа SO_PEERCRED — struct dnsd_ucred (dnsd_int.h). По той же причине, по какой
 * она своя (_GNU_SOURCE), — accept, а не accept4. */
void dlog_serve(void) {
    for (int k = 0; k < 4; k++) {
        int c = accept(g_dlog_fd, NULL, NULL);
        if (c < 0) return;
        fcntl(c, F_SETFD, FD_CLOEXEC);
        /* Принятый сокет наследует O_NONBLOCK слушающего только в BSD; в Linux — нет, но
         * полагаться на это незачем: запись ниже идёт со сроком, а не с неблокирующим. */
        fcntl(c, F_SETFL, fcntl(c, F_GETFL) & ~O_NONBLOCK);
        struct dnsd_ucred uc;
        socklen_t l = sizeof(uc);
        if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &uc, &l) != 0 ||
            (uc.uid != 0 && uc.uid != geteuid())) {
            close(c);
            continue;
        }
        size_t n = 0;
        char *js = dlog_render(&n);
        if (js) {
            struct timeval tv = { 0, 200000 };
            setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            size_t off = 0;
            while (off < n) {
                ssize_t w = send(c, js + off, n - off, MSG_NOSIGNAL);
                if (w <= 0) break;
                off += (size_t)w;
            }
            free(js);
        }
        close(c);
    }
}

/* Клиент: `steer dns-log` — журнал работающего резолвера как есть. Резолвер не запущен (сокета
 * нет или никто не слушает) — это состояние, а не ошибка: "running":false и код 0, экран
 * покажет «резолвер не запущен». 1 — сокет есть, но ответа нет (права, срок). */
int dlog_print(FILE *out) {
    char path[PATH_MAX];
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    if ((size_t)snprintf(path, sizeof(path), "%s/dnsd.sock", steer_state_dir()) >= sizeof(a.sun_path)) {
        fprintf(stderr, "steer[warn] dns-log: путь сокета журнала слишком длинный\n");
        return 1;
    }
    memcpy(a.sun_path, path, strlen(path) + 1);                 /* длина сверена выше */
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 1;
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        int e = errno;
        close(fd);
        if (e == ENOENT || e == ECONNREFUSED) {
            fprintf(out, "{\"schema\":1,\"running\":false,\"size\":%d,\"names\":[]}\n", DLOG_MIN);
            return 0;
        }
        fprintf(stderr, "steer[warn] dns-log: %s: %s\n", path, strerror(e));
        return 1;
    }
    struct timeval tv = { 3, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char *buf = NULL;
    size_t n = 0, cap = 0;
    for (;;) {
        if (n + 16384 > cap) {
            size_t nc = cap ? cap * 2 : 65536;
            char *q = realloc(buf, nc);
            if (!q) break;
            buf = q;
            cap = nc;
        }
        ssize_t m = recv(fd, buf + n, cap - n, 0);
        if (m < 0 && errno == EINTR) continue;
        if (m <= 0) {
            if (m < 0) n = 0;                  /* срок или обрыв: половина JSON хуже, чем ничего */
            break;
        }
        n += (size_t)m;
    }
    close(fd);
    if (!n || buf[n - 1] != '\n') {
        free(buf);
        fprintf(stderr, "steer[warn] dns-log: резолвер не отдал журнал\n");
        return 1;
    }
    fwrite(buf, 1, n, out);
    free(buf);
    return 0;
}
