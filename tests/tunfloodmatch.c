/* Один клиент LAN не кладёт туннель всем: спрей датаграмм, очередь установщиков и бюджет памяти (аудит 2.1.0,
 * T1 и T2).
 *
 * T1. Клиент шлёт по датаграмме UDP на 20 000 разных адресов (DHT торрента, скан портов, вредонос), узел
 * отвечает на рукопожатие за 300 мс. Прежде каждая пятёрка становилась заявкой установщику, очередь была одна
 * и по порядку прихода: 20 000 заявок, RSS 2,8 → 206 МБ, и ~94 с не открывалось ни одно новое соединение
 * других клиентов, TCP тоже (замер audit/udpflood.c). Здесь — то же, и смотрится то, что видно снаружи:
 * сколько заявок принято (не больше доли источника), что получили остальные датаграммы (ICMP «порт
 * недоступен»), за сколько открывается соединение TCP ДРУГОГО клиента и на сколько выросла память. Дальше
 * — срок заявки в очереди и заявка клиента, ушедшего до рукопожатия.
 *
 * T2. Клиент открывает сотни скачиваний и не читает: узел шлёт без конца. Прежде кольцо каждого росло до
 * 256 КиБ сверх сессии, и предела на процесс не было. Здесь бюджет задан малым (STEER_TUN_MEM_MB=16):
 * учтённое не выходит за бюджет, лишние соединения получают RST, а второй клиент открывает своё и качает.
 *
 * Стенд — tests/tunnelmatch.c с его подменами (узел, транспорт, устройство — сокетная пара), рукопожатие
 * подменено сном. Собирается и против прежнего стека (без границ): тогда проверки T1/T2 проваливаются
 * числами, а проверки новых путей пропускаются (их символов там нет). */
#define main tm_main
#define vless_connect vless_connect_orig
#include "tunnelmatch.c"
#undef vless_connect
#undef main

static int g_hs_ms = 300;
int vless_connect(const struct vless_node *node, struct transport *conn, int timeout_s) {
    int ms = __atomic_load_n(&g_hs_ms, __ATOMIC_RELAXED);
    if (ms > 0) {
        struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
        nanosleep(&ts, NULL);
    }
    return vless_connect_orig(node, conn, timeout_s);
}

static long rss_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char l[256];
    long v = -1;
    while (f && fgets(l, sizeof l, f)) if (!strncmp(l, "VmRSS:", 6)) v = atol(l + 6);
    if (f) fclose(f);
    return v;
}

static void tick(void) {
    g_now_ns = now_ns();
    g_now_s = (time_t)(g_now_ns / 1000000000ull);
}

/* Датаграмма UDP src:sport -> dst:6881 в «устройство». */
static void udp_from(uint32_t src, uint32_t dst, uint16_t sport) {
    unsigned char pkt[28 + 100];
    memset(pkt, 0, sizeof pkt);
    pkt[0] = 0x45; pkt[3] = sizeof pkt; pkt[8] = 64; pkt[9] = 17;
    memcpy(pkt + 12, &src, 4);
    memcpy(pkt + 16, &dst, 4);
    pkt[20] = (unsigned char)(sport >> 8); pkt[21] = (unsigned char)sport;
    pkt[22] = 0x1a; pkt[23] = 0xe1;
    pkt[24] = 0; pkt[25] = 108;
    handle_packet(&g_tun, pkt, sizeof pkt);
}

/* Вычитать устройство; сколько пришло ICMP (протокол 1). Очередь записи потока тоже сливается. */
static int dev_icmp(void) {
    unsigned char p[2048];
    int n = 0;
    for (int round = 0; round < 64; round++) {
        tun_wq_flush();
        int got = 0;
        for (;;) {
            ssize_t r = recv(g_dev_peer, p, sizeof(p), MSG_DONTWAIT);
            if (r <= 0) break;
            got++;
            if (r >= 20 && (p[0] >> 4) == 4 && p[9] == 1) n++;
        }
        if (!got && !tun_wq_pending()) break;
    }
    return n;
}

static int live_pending(void) {
    int p = 0;
    for (int li = 0; li < g_live_n; li++) p += g_conns[g_live[li]].pending;
    return p;
}

/* Проход цикла по готовым заявкам (как в worker_loop). Сколько разобрано. */
static int reap(void) {
    int n = 0;
    tick();
    for (int li = 0; li < g_live_n; ) {
        struct conn *c = &g_conns[g_live[li]];
        if (!c->pending || !__atomic_load_n(&c->done, __ATOMIC_ACQUIRE)) { li++; continue; }
        n++;
        if (!conn_ready(c, &g_tun)) li++;
    }
    return n;
}

/* Дождаться, пока не останется заявок (не дольше ms). */
static void reap_all(int ms) {
    for (int i = 0; i < ms / 10 && live_pending(); i++) {
        reap();
        usleep(10000);
    }
    reap();
}

/* Клиентские концы сокетов, открытые стендом: слоты здесь бывают и за пределом g_cfd стенда-основы (резерв
 * таблицы по умолчанию — спрей прежнего стека занимает десятки тысяч слотов). */
static int g_cli[4096];
static int g_cli_n;

static void drop_all(void) {
    reap_all(30000);
    while (g_live_n) conn_drop(&g_conns[g_live[0]]);
    for (int i = 0; i < g_cli_n; i++) if (g_cli[i] >= 0) close(g_cli[i]);
    g_cli_n = 0;
    dev_icmp();
}

/* Соединение TCP от src: conn_accept на паре сокетов (tcp — по петле TCP, иначе AF_UNIX). */
static struct conn *tcp_from(uint32_t src, uint16_t sport, int tcp, int *cli) {
    int sv[2];
    if ((tcp ? cli_pair_tcp(sv) : cli_pair_unix(sv)) != 0) return NULL;
    struct flow_key k;
    memset(&k, 0, sizeof(k));
    k.src = src; k.dst = SRV_IP; k.sport = sport; k.dport = SRV_PORT; k.proto = 6;
    struct conn *c = conn_accept(sv[0], &k, &g_tun);
    if (!c) { close(sv[1]); *cli = -1; return NULL; }
    if (g_cli_n < (int)(sizeof(g_cli) / sizeof(g_cli[0]))) g_cli[g_cli_n++] = sv[1];
    *cli = sv[1];
    return c;
}

/* Дождаться установщика и разобрать готовность, как цикл. 0 — поток готов. */
static int open_wait(struct conn *c, int ms) {
    for (int i = 0; i < ms; i++) {
        if (__atomic_load_n(&c->done, __ATOMIC_ACQUIRE)) { tick(); return conn_ready(c, &g_tun) ? -1 : 0; }
        usleep(1000);
    }
    return -1;
}

/* Одна порция узла соединению — как проход цикла: только если клиент примет запись (client_can_take_record).
 * Первая порция несёт ответ VLESS (версия, длина дополнения). 1 — прочитано. */
static int node_feed(struct conn *c, int *hdr) {
    if (!c->used || c->srv_closed || !client_can_take_record(c)) return 0;
    g_recv_rc = 0;
    if (!*hdr) {
        g_recv_buf[0] = 0; g_recv_buf[1] = 0;
        memset(g_recv_buf + 2, 'r', 16000);
        g_recv_n = 16002;
        g_recv_rep = 0;
        *hdr = 1;
    } else {
        g_recv_n = 0;
        g_recv_rep_n = 16000;
        g_recv_rep = 4;
    }
    drain_conn(c, &g_tun);
    g_recv_rep = 0;
    g_recv_n = 0;
    return 1;
}

#define CLI_B 0x0264330au               /* 10.51.100.2 — второй клиент */
#define CLI_C 0x0364330au
#define CLI_D 0x0464330au

static void t_udp_spray(void) {
    enum { FLOWS = 20000 };
    dev_icmp();
    long r0 = rss_kb();
    uint64_t t0 = now_ns();
    for (int i = 0; i < FLOWS; i++) {
        tick();
        udp_from(CLI_IP, SRV_IP + htonl((uint32_t)i), 40000);
    }
    double spray_ms = (double)(now_ns() - t0) / 1e6;
    int pend = live_pending();
    int icmp = dev_icmp();
    long r1 = rss_kb();
    printf("  спрей %d датаграмм за %.0f мс: заявок %d, ICMP клиенту %d, RSS %ld -> %ld КиБ (+%ld)\n",
           FLOWS, spray_ms, pend, icmp, r0, r1, r1 - r0);
#ifdef STACK_RC_QEXPIRED
    check((unsigned)pend <= g_lim.pend_src_max,
          "T1: спрей одного клиента — заявок не больше доли источника (четверть предела рода)");
    check(icmp > 0, "T1: отклонённым датаграммам — ICMP «порт недоступен» (не тишина)");
    check(g_refused_pend > 0, "T1: отказы сосчитаны (g_refused_pend)");
#else
    check(pend <= 256, "T1: спрей одного клиента — заявок не больше доли источника");
#endif
    check(r1 - r0 < 32 * 1024, "T1: память от спрея выросла меньше чем на 32 МБ");

    /* Соединение TCP ДРУГОГО клиента, пока очередь UDP полна: открывается за обычное время. */
    tick();
    int cli = -1;
    uint64_t c0 = now_ns();
    struct conn *c = tcp_from(CLI_B, 41000, 0, &cli);
    int ok = 0;
    double open_ms = -1;
    for (int i = 0; c && i < 1000; i++) {
        if (__atomic_load_n(&c->done, __ATOMIC_ACQUIRE)) {
            open_ms = (double)(now_ns() - c0) / 1e6;
            ok = c->rc == 0;
            break;
        }
        usleep(10000);
    }
    printf("  соединение TCP второго клиента под спреем: %s за %.0f мс (рукопожатие %d мс)\n",
           ok ? "открылось" : "НЕ открылось", open_ms < 0 ? 10000.0 : open_ms, g_hs_ms);
    check(ok && open_ms < 1000,
          "T1: под спреем UDP соединение TCP другого клиента открывается меньше чем за 1 с");

    /* Второй клиент открывает и свой поток UDP: доля первого — не общая. */
    tick();
    udp_from(CLI_B, SRV_IP, 40001);
    struct flow_key kb;
    memset(&kb, 0, sizeof(kb));
    kb.src = CLI_B; kb.dst = SRV_IP; kb.sport = 40001; kb.dport = 6881; kb.proto = 17;
    struct conn *u = conn_find(&kb);
    check(u && u->pending, "T1: поток UDP второго клиента принят, пока первый на своём пределе");
    drop_all();
}

#ifdef STACK_RC_QEXPIRED
/* Заявка, простоявшая дольше CQ_WAIT_UDP_MS, установщиком пропускается: рукопожатия к узлу ей не будет. */
static void t_queue_expiry(void) {
    __atomic_store_n(&g_hs_ms, 3000, __ATOMIC_RELAXED);
    unsigned long long e0 = g_q_expired;
    unsigned want = g_lim.pend_src_max;
    for (unsigned i = 0; i < want; i++) { tick(); udp_from(CLI_C, SRV_IP + htonl(100000 + i), 40000); }
    int pend = live_pending();
    reap_all(20000);
    unsigned long long ex = g_q_expired - e0;
    printf("  заявок %d при %u установщиках и рукопожатии 3 с: истекло в очереди %llu\n", pend, g_cq.max, ex);
    check(ex > 0 && ex < (unsigned long long)pend,
          "T1: заявки, простоявшие дольше 5 с, пропущены установщиком (сброс, без рукопожатия к узлу)");
    __atomic_store_n(&g_hs_ms, 300, __ATOMIC_RELAXED);
    drop_all();
}

/* Клиент TCP ушёл (RST), пока заявка ждала: установщик её не исполняет. */
static void t_queue_gone(void) {
    __atomic_store_n(&g_hs_ms, 1500, __ATOMIC_RELAXED);
    /* Занять всех установщиков потоками UDP. */
    for (unsigned i = 0; i < g_cq.max; i++) { tick(); udp_from(CLI_D, SRV_IP + htonl(200000 + i), 40000); }
    usleep(100000);
    int cli = -1;
    tick();
    struct conn *c = tcp_from(CLI_B, 41001, 1, &cli);
    unsigned long long g0 = g_q_gone;
    if (c && cli >= 0) {
        struct linger lg = { 1, 0 };
        setsockopt(cli, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
        close(cli);
        for (int i = 0; i < g_cli_n; i++) if (g_cli[i] == cli) g_cli[i] = -1;
    }
    int ms = -1;
    uint64_t t0 = now_ns();
    for (int i = 0; c && i < 500; i++) {
        if (__atomic_load_n(&c->done, __ATOMIC_ACQUIRE)) { ms = (int)((now_ns() - t0) / 1000000); break; }
        usleep(10000);
    }
    int rc = c ? c->rc : 0;
    reap_all(10000);
    check(c && rc == STACK_RC_QGONE && g_q_gone == g0 + 1 && ms >= 0 && ms < 1500 + 500,
          "T1: заявка клиента, ушедшего до рукопожатия (RST), пропущена — узлу не звонили");
    __atomic_store_n(&g_hs_ms, 300, __ATOMIC_RELAXED);
    drop_all();
}
#endif

/* T2: сотни скачиваний одного клиента, который не читает; узел шлёт без конца. */
static void t_mem_budget(void) {
    enum { N = 250 };
    __atomic_store_n(&g_hs_ms, 0, __ATOMIC_RELAXED);
    long r0 = rss_kb();
    static struct conn *cs[N];
    static int hdr[N];
    int opened = 0, refused = 0;
    for (int i = 0; i < N; i++) {
        tick();
        int cli;
        struct conn *c = tcp_from(CLI_IP, (uint16_t)(42000 + i), 0, &cli);
        if (!c) { refused++; continue; }
        if (open_wait(c, 2000) != 0) { refused++; continue; }
        hdr[opened] = 0;
        cs[opened++] = c;
    }
    /* Узел шлёт без конца: каждому — проходы чтения, пока кольцо принимает (клиент не читает). */
    int fed = 0;
    for (int pass = 0; pass < 40; pass++) {
        tick();
        for (int i = 0; i < opened; i++) fed += node_feed(cs[i], &hdr[i]);
    }
    size_t rings = 0;
    int reading = 0;
    for (int i = 0; i < opened; i++) { rings += cs[i]->rtx.cap; reading += cs[i]->rtx.cap > 0; }
    long r1 = rss_kb();
    printf("  клиент не читает: открыто %d, отказано %d, читали у узла %d (проходов %d), кольца %zu КиБ, "
           "RSS %ld -> %ld КиБ (+%ld)\n", opened, refused, reading, fed, rings / 1024, r0, r1, r1 - r0);
#ifdef STACK_RC_QEXPIRED
    printf("  учтено %zu КиБ из бюджета %zu (доля источника %zu)\n", g_mem_kib, g_lim.mem_budget_kib,
           g_lim.mem_src_kib);
    check(g_mem_kib <= g_lim.mem_budget_kib + RTX_CAP / 1024,
          "T2: учтённая память туннеля не выходит за бюджет (с запасом в одно кольцо)");
    check(refused > 0 && g_refused_mem > 0, "T2: сверх доли источника новые соединения получают RST, отказ сосчитан");
#endif
    check(r1 - r0 < 24 * 1024, "T2: RSS от сотен медленных читателей выросла меньше чем на 24 МБ (бюджет 16)");

    /* Второй клиент: открывает своё соединение и качает (кольцо растёт, данные доходят). */
    tick();
    int cli = -1, bh = 0;
    struct conn *b = tcp_from(CLI_B, 43000, 0, &cli);
    int ok = b && open_wait(b, 2000) == 0;
    int took = 0;
    if (ok) {
        for (int k = 0; k < 4; k++) node_feed(b, &bh);
        unsigned char buf[65536];
        took = (int)cli_get(cli, buf, sizeof(buf));
    }
    printf("  второй клиент: %s, получил %d байт\n", ok ? "соединение открыто" : "соединения нет", took);
    check(ok && took > 0, "T2: второй клиент под давлением первого открывает соединение и получает данные");
    __atomic_store_n(&g_hs_ms, 300, __ATOMIC_RELAXED);
    drop_all();
#ifdef STACK_RC_QEXPIRED
    check(g_mem_kib == 0, "T2: после закрытия всех соединений учтено ноль (счёт не уплывает)");
#endif
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    /* Восемь установщиков: при них спрей держит всех занятыми, а стенд идёт секунды. Бюджет 16 МБ — малым,
     * чтобы его было видно сотнями соединений, а не тысячами. */
    setenv("STEER_TUN_CONNECTORS", "8", 1);
    setenv("STEER_TUN_MEM_MB", "16", 1);
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) != 0 || pipe(g_sess_pipe) != 0) return 2;
    if (write(g_sess_pipe[1], "x", 1) != 1) return 2;
    for (int i = 0; i < TEST_SLOTS; i++) g_cfd[i] = -1;
    memset(&g_tun, 0, sizeof(g_tun));
    g_tun.fd = sp[0];
    fcntl(sp[0], F_SETFL, O_NONBLOCK);
    g_dev_peer = sp[1];
    snprintf(g_node.uuid, sizeof(g_node.uuid), "8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124");
    snprintf(g_node.host, sizeof(g_node.host), "stand");
    g_spare_want = 0;
    stack_setup(&g_dial);
    g_slots_want = 0;               /* резерв по умолчанию, как в работе */
    if (conn_table_init() != 0) return 2;
    tick();
    t_udp_spray();
#ifdef STACK_RC_QEXPIRED
    t_queue_expiry();
    t_queue_gone();
#endif
    t_mem_budget();
    printf(g_fail ? "\ntunfloodmatch: ПРОВАЛ\n" : "\ntunfloodmatch: все проверки прошли\n");
    _exit(g_fail);
}
