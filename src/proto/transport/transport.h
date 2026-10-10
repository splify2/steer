/* Транспорт: как поток протокола (VLESS, позже другие дайлеры) едет до узла.
 *
 * Три яруса снизу вверх, и у каждого свой файл:
 *
 *   сокет         TCP до узла по всем адресам имени, с меткой выхода-подложки (trdial.c);
 *   безопасность  поле security= ссылки узла: none, tls, reality (trsec.c, struct security_ops);
 *   транспорт     поле type= ссылки узла: tcp, grpc, xhttp, ws, httpupgrade (transport.c,
 *                 trgrpc.c, trxhttp.c, trws.c, trupgrade.c; struct transport_ops).
 *
 * ПОЧЕМУ ДВЕ ТАБЛИЦЫ, А НЕ ОДНА ЦЕПОЧКА «tcp → tls → grpc» (docs/architecture.md, «Туннели:
 * стек, дайлер, транспорт»). В первом проекте все они перечислены одним списком
 * transport_ops, но в ссылке узла это ДВА независимых поля, и сочетаются они любые: grpc
 * поверх reality, xhttp поверх tls, tcp без security вовсе. Одна цепочка слоёв одного типа
 * потребовала бы правила, какой слой над каким вправе стоять, — то есть второго способа сказать
 * то, что два поля ссылки говорят и так.
 * Кроме того, слои безопасности различаются ТОЛЬКО рукопожатием: после него у tls и reality
 * одни и те же записи TLS 1.3, у none — сокет как есть. Поэтому у security_ops одна функция,
 * а поток после рукопожатия читает и пишет общий код связи (tr_link_* в transport.c).
 *
 * КТО ЭТИМ ПОЛЬЗУЕТСЯ. Клиент VLESS (proto/vless/client.c: vless_connect и проверка узла) и
 * через него дайлер стека туннеля (proto/vless/vldial.c). Про протокол транспорт не знает
 * ничего: узел приходит ему struct tr_node — теми полями ссылки, которые касаются транспорта,
 * указателями в узел подписки. Поэтому следующий протокол поверх тех же транспортов (trojan,
 * shadowsocks через ws) — это новый дайлер, а не правка этого слоя.
 *
 * При выпуске 1.10 (шаг 4) весь этот каталог уходит в разделяемую libsteer вместе с TLS: модули
 * протоколов пользуются им, а не носят свою копию.
 */
#ifndef STEER_TRANSPORT_H
#define STEER_TRANSPORT_H
#include <stdint.h>
#include <stddef.h>
#include "tls13.h"
#include "h2.h"

/* Коды отказа транспорта. Значения — прежние VLESS_CONN_* клиента: их видят журнал, строка
 * причины проверки узла и стенды, а менять число ради переезда в другой файл незачем.
 * -35 и -36 заняты кодами самого VLESS (client.h) — там они и остались. */
#define TR_EDNS      (-30)
#define TR_ESOCK     (-31)
#define TR_ECONNECT  (-32)
#define TR_EIO       (-33)
#define TR_ECLOSED   (-34)
/* Транспорт требует HTTP/2, а сервер на него не согласился. Отдельный код: всё остальное при
 * этом работает, данные просто не идут, и без имени этой ошибки узел выглядит как
 * «подключается и молчит». */
#define TR_ENOH2     (-37)
#define TR_EGRPC     (-38)   /* поток gRPC устроен не так, как мы умеем читать */
/* ws и httpupgrade (trupgrade.c, trws.c). Отдельные коды, а не один «апгрейд не удался»: человеку
 * здесь нужны РАЗНЫЕ действия. Ответ не 101 — это почти всегда не тот path или host (сервер Xray
 * отвечает 404 на чужой путь), и код ответа называется в тексте; 101 без Upgrade или без верного
 * Accept — ответил не сервер WebSocket, а посредник или кеш; не http/1.1 в ALPN — сервер за TLS
 * выбрал другой протокол, а апгрейд идёт только по HTTP/1.1. */
#define TR_ENOH1      (-39)  /* сервер согласовал в ALPN не http/1.1 */
#define TR_EUPSTATUS  (-40)  /* на запрос Upgrade ответ не 101 (код — в тексте) */
#define TR_ENOUPGRADE (-41)  /* 101 без Upgrade: websocket или Connection: upgrade */
#define TR_EWSACCEPT  (-42)  /* 101 без верного Sec-WebSocket-Accept */
#define TR_EUPTIMEOUT (-43)  /* ответа на запрос Upgrade нет за срок соединения */
#define TR_EUPTOOBIG  (-44)  /* ответ на Upgrade не разобрался: длиннее предела или не HTTP */
#define TR_EWSFRAME   (-45)  /* кадр WebSocket нарушает RFC 6455 */
#define TR_EVENC      (-46)  /* VLESS encryption: рукопожатие или формат (причина — tr_venc_reason) */
#define TR_EVENCAUTH  (-47)  /* VLESS encryption: AEAD не сошёлся — ключи разошлись с сервером */
#define TR_EVENC0RTT  (-48)  /* VLESS encryption: сервер отклонил билет 0-RTT, следующее соединение — полное */

/* Узел глазами транспорта: только то, что касается связи. Указатели — в узел подписки
 * (struct vless_node), без копий: узел живёт дольше любого соединения к нему. */
struct tr_node {
    const char *host;
    uint16_t port;
    const char *type;          /* tcp | grpc | xhttp | ws | httpupgrade */
    const char *security;      /* none | tls | reality */
    const char *sni;           /* маскировочный домен — он же SNI в ClientHello */
    const char *fp;            /* отпечаток браузера */
    const char *pbk;           /* публичный ключ Reality, base64url */
    const char *sid;           /* short id Reality, hex */
    const char *path;          /* xhttp, ws, httpupgrade; у ws/httpupgrade — с `?ed=` (trpath.h) */
    /* ws и httpupgrade: заголовок Host (пусто — sni, затем адрес узла, как у Xray) и свои
     * заголовки запроса строками «Имя: значение\n» (из конфига Xray в подписке, см. vless.h).
     * NULL — то же, что пусто. */
    const char *http_host;
    const char *headers;
    const char *service;       /* grpc serviceName */
    const char *mode;          /* grpc: multi/gun; xhttp: auto/packet-up… */
    /* Длина набивки xhttp, объявленная узлом (см. vless_node.pad_from в vless.h). 0 в pad_to —
     * не объявлено, тогда умолчание Xray. */
    uint16_t pad_from, pad_to;
    /* Предел тела POST packet-up у узла (см. vless_node.post_from). 0 в post_to — не объявлено. */
    uint32_t post_from, post_to;
    /* Reality: открытый ключ ML-DSA-65 для проверки подписи сертификата, base64url (1952 байта в
     * бинарном виде), или NULL. Поле mldsa65Verify конфига Xray, `pqv` ссылки. */
    const char *pqv;
    /* security=tls: клиентская проверка сертификата узла (Xray: pinnedPeerCertSha256, verifyPeerCertByName;
     * sing-box: certificate_public_key_sha256) и явный отказ от неё. Строки — как в vless_node; NULL — нет.
     * insecure — ключ выхода, не подписка. */
    const char *pcs, *pks, *vcn;
    int insecure;
    /* security=tls: ECHConfigList в base64 (Xray echConfigList, `ech=` ссылки) или NULL — без ECH. */
    const char *ech;
    /* VLESS encryption: строка `encryption` узла без изменений (mlkem768x25519plus.…) или NULL —
     * шифрования нет. Разбирает и исполняет vlenc.c поверх готовой связи. */
    const char *encryption;
};

/* Связь: сокет и безопасность над ним — один защищённый поток байт.
 *
 * Отдельной структурой потому, что связей у соединения бывает ДВЕ: xhttp в режимах stream-up и
 * packet-up поднимает вторую под выгрузку (см. trxhttp.c), и рукопожатие у неё то же самое. */
struct tr_link {
    int fd;
    int plain;                 /* security=none: TLS нет вовсе */
    /* Сервер перешёл на прямое копирование (команда direct в Vision): в сокете больше не наши
     * записи TLS, а поток целевого соединения как есть. Ставится извне — тем, кто разбирает
     * кадры Vision (transport_direct), потому что команда живёт в них. */
    int rx_direct;
    /* 1 — в этом рукопожатии гибрид X25519MLKEM768 не предлагать (короткий ClientHello). Ставит
     * tr_link_open: после таймаута длинного Hello и на узле, для которого уже решено, что нужен короткий. */
    int nopq;
    struct tls13 tls;
};

/* Разбор потока сообщений gRPC.
 *
 * Состояние нужно потому, что границы сообщения gRPC, кадра HTTP/2 и записи TLS не
 * совпадают ни в одном месте: одно сообщение может приехать тремя записями, а одна
 * запись — принести полтора сообщения. Держим счётчики, а не буфер: буфер на каждое из
 * 64 соединений стоил бы мегабайт, а счётчики — двадцать байт. */
struct grpc_de {
    unsigned char hdr[5];        /* признак сжатия(1) + длина(4) */
    unsigned char hdr_n;
    uint32_t msg_left;           /* сколько осталось от тела сообщения */
    unsigned char pb[8];         /* тег и длина поля protobuf */
    unsigned char pb_n;
    uint32_t field_left;         /* сколько осталось от поля bytes внутри сообщения */
};

/* Режим xhttp. Определяет, СКОЛЬКО запросов HTTP несёт одно соединение и как они делят
 * направления — а не «формат кадров»: байты в теле у всех трёх одинаковы.
 *
 *   stream-one  один запрос POST: тело запроса наверх, тело ответа вниз. Одно соединение,
 *               один поток, наименьшая задержка. Его и выбирает Xray при reality;
 *   stream-up   два запроса: GET за загрузкой и длинный POST под выгрузку. Нужен там, где
 *               посредник не пропускает двунаправленное тело, но потоковую выгрузку терпит;
 *   packet-up   GET за загрузкой и ЧЕРЕДА коротких POST, по одному на кусок, с номером в
 *               пути. Единственное, что проходит через посредника, который выгрузку
 *               потоком не пропускает вовсе — например через CDN, буферизующий запросы.
 */
enum xhttp_mode { XH_STREAM_ONE = 0, XH_STREAM_UP, XH_PACKET_UP };

/* Вторая связь — под выгрузку xhttp.
 *
 * ПОЧЕМУ ОТДЕЛЬНОЕ СОЕДИНЕНИЕ, А НЕ ВТОРОЙ ПОТОК В ТОМ ЖЕ. stream-up и packet-up требуют,
 * чтобы загрузка и выгрузка шли РАЗНЫМИ запросами и одновременно. В HTTP/2 это два потока
 * в одном соединении, и Xray делает именно так — но у нашего клиента h2 мультиплексора нет
 * по построению (см. заголовок h2.c), и заводить планировщик окон между потоками ради двух
 * ролей, одна из которых только читает, а другая только пишет, дороже, чем второе TCP.
 *
 * Протоколу это ничем не мешает: сервер связывает запросы по идентификатору сессии в ПУТИ,
 * а не по соединению (hub.go в Xray), и по HTTP/1.1 выгрузка вообще всегда идёт отдельным
 * соединением. Цена — второе рукопожатие TLS на соединение, и платят её только эти два
 * режима. */
struct xh_up {
    struct tr_link link;
    struct h2 h2;
    int started;               /* HEADERS первого запроса уже отправлены */
};

/* Состояние xhttp. У stream-one всё, кроме mode, здесь не используется. */
struct xh_state {
    enum xhttp_mode mode;
    struct xh_up up;           /* выгрузка stream-up и packet-up */
    uint64_t seq;              /* номер куска packet-up, с нуля */
    char authority[128];       /* повторяется в каждом запросе череды */
    char up_path[288];         /* путь с идентификатором сессии, без номера куска */
    /* Длина набивки, объявленная узлом. Запоминается здесь, потому что запросы выгрузки
     * (packet-up) собираются уже без узла на руках, а набивка нужна каждому: сервер
     * проверяет её у КАЖДОГО запроса, а не только у первого. */
    uint16_t pad_from, pad_to;
    /* packet-up: размер КАЖДОГО POST — случайный в [post_min, post_max] (scMaxEachPostBytes узла,
     * равномерно, как у клиента Xray); запись больше уходит несколькими кусками. post_max == 0 —
     * предела нет; post_min == 0 — как post_max. post_rng — состояние выбора размера. */
    uint32_t post_max, post_min;
    uint64_t post_rng;
    /* Отказ сервера на кусок выгрузки, прочитанный не записью, а слежкой за второй связью
     * (xhttp_aux_drain): отправка вернёт его первой, как вернула бы, прочитав сама. */
    int drain_err;
};

/* Разбор кадров WebSocket от сервера (RFC 6455, раздел 5) — потоком, по кускам любой длины.
 *
 * Состояние, а не буфер, по той же причине, что у grpc_de: граница кадра не совпадает с границей
 * записи TLS, и кадр в 64 КБ приезжает несколькими записями, а запись — несколькими кадрами.
 * Полезная нагрузка кадров данных отдаётся сразу, по мере прихода; копится только заголовок
 * кадра (до 14 байт) и тело служебного кадра (до 125 байт — предел RFC 6455, 5.5). */
struct ws_rx {
    unsigned char hdr[14];
    uint8_t hdr_n;
    uint8_t in_payload;        /* заголовок разобран, идёт тело кадра */
    uint8_t op;                /* опкод текущего кадра */
    uint8_t in_msg;            /* внутри сообщения, разрезанного на кадры (ждём продолжения) */
    uint64_t left;             /* сколько байт тела текущего кадра ещё не пришло */
    unsigned char ctl[125];    /* тело служебного кадра */
    uint8_t ctl_n;
    /* Пришёл ping — ответить pong с тем же телом. Ответ шлёт тот, кто читает (trws.c), после
     * разбора куска: разбор чистый и в сеть не пишет, чтобы его можно было проверять в памяти.
     * Два ping в одном куске дают один ответ на последний — это разрешает RFC 6455, 5.5.3. */
    uint8_t pong_due;
    uint8_t pong_n;
    unsigned char pong[125];
    uint8_t closed;            /* пришёл close: дальше данных не будет */
    uint8_t close_sent;        /* ответный close уже отправлен */
    uint16_t close_code;       /* код из close; 1005 — кода не было */
};

/* ws и httpupgrade: то, что остаётся после ответа 101.
 *
 * stash — байты, прочитанные вместе с ответом 101, но лежащие ЗА его заголовками: сервер вправе
 * прислать данные сразу за ответом, и одна запись TLS (или одно чтение сокета) приносит их вместе.
 * Выбросить их значило бы разъехаться с сервером на первые же байты потока — у httpupgrade это
 * начало ответа VLESS, у ws — первый кадр. В куче и только когда они есть: это редкость, а
 * буфер в каждом соединении стоил бы 16 КБ на каждое из сотен соединений пула. Кто прочитал, тот
 * и освобождает (tr_h1_free); остаток до чтения освобождает transport_close.
 *
 * РАННИЕ ДАННЫЕ (`?ed=N` в пути, Ed у Xray) меняют, КОГДА уходит запрос и когда разбирается ответ,
 * — ровно как у Xray (подробности — trws.c и trupgrade.c):
 *   ws           запрос откладывается до первой записи (H1_DEFER); запись не длиннее Ed уезжает в
 *                Sec-WebSocket-Protocol, длиннее — отдельно, кадрами после ответа 101;
 *   httpupgrade  запрос уходит сразу, но ответа не ждём: данные идут следом, ответ разбирается
 *                первым чтением (H1_WAIT).
 * Пока ответа 101 нет (H1_WAIT), ws копит свои записи в очереди q — у Xray запись в это время
 * просто ждёт ответа, а цикл туннеля ждать не вправе; очередь уходит кадрами сразу за 101. */
enum { H1_OPEN = 0, H1_DEFER, H1_WAIT };
struct h1_resp;
struct h1_state {
    unsigned char *stash;
    uint32_t stash_n, stash_off;
    struct ws_rx rx;           /* только ws */
    uint8_t phase;             /* H1_OPEN, H1_DEFER, H1_WAIT */
    uint8_t upgraded;          /* ответ 101 принят: у ws при закрытии уходит close 1000 */
    uint32_t ed;               /* Ed из пути (trpath.h) */
    /* Для отложенного запроса ws: копия узла (сама struct tr_node живёт на стеке открывающего,
     * указатели в ней — в узел подписки, который живёт дольше соединения). */
    struct tr_node node;
    struct h1_resp *resp;      /* разбор ответа в H1_WAIT — в куче, на время ожидания */
    char accept[29];           /* ожидаемый Sec-WebSocket-Accept */
    /* ws в H1_WAIT: записи до ответа 101, каждая — [длина 4 байта][данные], в куче. */
    unsigned char *q;
    uint32_t q_n, q_cap;
};

struct transport;

/* Транспорт — поле type= ссылки: как поток протокола уложен внутри защищённой связи.
 *
 * ws и httpupgrade (шаг 5 выпуска 1.10) — ещё две такие таблицы и два файла рядом с trgrpc.c:
 * запрос Upgrade по HTTP/1.1 в open (trupgrade.c), кадры WebSocket в write/read (trws.c; у
 * httpupgrade кадров нет — после ответа 101 поток идёт как есть), ALPN "http/1.1". Ни стек
 * туннеля, ни дайлер при этом не поменялись: они видят транспорт только через transport_write и
 * transport_read. */
struct transport_ops {
    const char *name;          /* как в ссылке узла: tcp, grpc, xhttp, ws, httpupgrade */
    /* Что просить в ALPN, или NULL — тогда расширения нет вовсе. Hello без ALPN проверен на
     * живых узлах, и состав Hello — это то, по чему Reality отличает нас от постороннего:
     * добавлять расширение туда, где оно не нужно, значит менять проверенное ради ничего.
     * Если сервер согласовал ДРУГОЕ, соединение отвергается кодом TR_ENOH2. */
    const char *alpn;
    /* Данные протокола лежат в записях TLS как есть: чтение вправе отдать указатель внутрь
     * расшифрованной записи вместо копии (transport_read_zc). Правда у tcp и httpupgrade — у grpc
     * и xhttp между TLS и данными лежит HTTP/2, у ws — кадры, и тело всё равно перекладывается. */
    int zc;
    /* Открыть транспорт поверх уже защищённой связи: HTTP/2, запросы, вторая связь. NULL —
     * открывать нечего (tcp). На отказе закрывать ничего не нужно: закроет transport_open. */
    int  (*open)(struct transport *t, const struct tr_node *n, int timeout_s);
    int  (*write)(struct transport *t, const unsigned char *d, size_t n);
    /* 0 байт при коде 0 — законно: пришёл служебный кадр HTTP/2. Конец потока — кодом. */
    int  (*read)(struct transport *t, unsigned char *d, size_t cap, size_t *got);
    /* Структура переехала в памяти (запасная сессия стека → таблица соединений): поправить
     * указатели на саму себя. NULL — таких указателей у транспорта нет. */
    void (*moved)(struct transport *t);
    /* Освободить своё сверх основной связи (вторую связь xhttp, остаток после 101). NULL —
     * нечего. */
    void (*close)(struct transport *t);
    /* Лежит ли у транспорта своё непрочитанное, о котором ни ядро, ни связь не знают: остаток
     * после ответа 101, отложенный конец потока ws. Без этого цикл туннеля ушёл бы ждать
     * готовности сокета, а данные остались бы лежать до следующего пакета от сервера — которого
     * может и не быть, если сервер уже всё сказал (см. transport_has_data). NULL — такого нет. */
    int  (*pending)(const struct transport *t);
    /* Транспорт ещё разбирает своё поверх записей TLS (ответ 101 у httpupgrade с ранними
     * данными): чтение без копии (zc) пока нельзя, даже когда своего непрочитанного нет. NULL —
     * такого не бывает. */
    int  (*busy)(const struct transport *t);
    /* Сколько байт запись примет сейчас: окно отправки HTTP/2 (grpc, xhttp). Запись больше этого
     * закончится H2_EWINDOW. NULL — предела нет (tcp, ws, httpupgrade: буфер сокета). */
    long (*room)(struct transport *t);
    /* Вторая связь, о которой событие основного сокета не скажет (xhttp stream-up и packet-up:
     * ответы на выгрузку приходят по ней). aux_fd — её дескриптор, -1 — второй связи нет; цикл
     * туннеля ставит его в epoll. aux_drain читает с неё то, что пришло: 0 — связь жива, не 0 —
     * больше слушать нечего (закрыта или сломана; причина остаётся записи, а не этому вызову).
     * NULL — второй связи у транспорта не бывает. */
    int  (*aux_fd)(const struct transport *t);
    int  (*aux_drain)(struct transport *t);
    /* См. transport_big_write. NULL — нет. */
    int  (*big_write)(const struct transport *t);
};

/* Безопасность — поле security= ссылки. Различаются только рукопожатием (см. шапку). */
struct security_ops {
    const char *name;          /* none | tls | reality */
    /* Рукопожатие поверх l->fd. alpn — от транспорта. На отказе сокет НЕ закрывает: это
     * делает вызывающий, одним и тем же образом у основной связи и у второй. */
    int (*handshake)(struct tr_link *l, const struct tr_node *n, const char *alpn);
};

/* Соединение с узлом: основная связь, транспорт над ней и его состояние. */
struct transport {
    struct tr_link link;
    const struct transport_ops *fr;
    struct h2 h2;              /* только для grpc и xhttp */
    struct grpc_de de;         /* только для grpc */
    struct xh_state xh;        /* только для xhttp */
    struct h1_state h1;        /* только для ws и httpupgrade */
    struct venc *enc;          /* VLESS encryption поверх транспорта (trvenc.c), или NULL */
};

/* VLESS encryption (trvenc.c): рукопожатие поверх открытого транспорта и записи AEAD вместо его
 * transport_write/read. Зовёт transport_open, если у узла задан encryption. */
struct venc;
int tr_venc_open(struct transport *t, const struct tr_node *n, int timeout_s);
int tr_venc_write(struct transport *t, const unsigned char *d, size_t n);
int tr_venc_read(struct transport *t, unsigned char *d, size_t cap, size_t *got);
int tr_venc_pending(const struct transport *t);
void tr_venc_close(struct transport *t);
const char *tr_venc_reason(void);

/* Полное установление: TCP, рукопожатие безопасности, открытие транспорта. 0 — готово; иначе
 * код отказа, и тогда ни дескриптора, ни ключей в куче за соединением не остаётся. */
int transport_open(struct transport *t, const struct tr_node *n, int timeout_s);

/* Обмен данными в форме, которую требует транспорт узла. Вызывающий про транспорт не
 * знает — иначе о нём пришлось бы помнить и в туннеле, и в проверке, и в каждом новом
 * месте, а забытое место означало бы поток, который уходит не в той упаковке. */
int transport_write(struct transport *t, const unsigned char *d, size_t n);

/* Сколько байт данных вызывающего transport_write примет сейчас, после собственной упаковки
 * транспорта (заголовок сообщения gRPC, записи шифрования VLESS); -1 — предела нет. Туннель
 * по этому числу выбирает окно клиента: клиент шлёт то, что узел может принять, а не узнаёт
 * об этом по таймаутам повторной передачи (см. dialer_ops.room). */
long transport_room(struct transport *t);
/* Принимает ли запись ЛЮБОЙ длины одним вызовом, без своих ограничений на неё и без лишней копии
 * на стороне вызывающего (packet-up: запись режется на POST сама). 1 — да; у stream-up и
 * stream-one запись упирается в окно одного потока и кадры, у остальных — в запись TLS, и стек
 * собирает для них не больше TUNNEL_BUF. Шифрование VLESS (enc) переупаковывает записи — для него 0. */
int transport_big_write(const struct transport *t);
int transport_read(struct transport *t, unsigned char *d, size_t cap, size_t *got);

/* Приём БЕЗ ЛИШНЕЙ КОПИИ там, где транспорт это позволяет (transport_ops.zc).
 *
 * *data указывает либо внутрь соединения (на расшифрованную на месте запись), либо в buf —
 * вызывающему всё равно, он читает по указателю. Через это место идёт весь скачиваемый
 * трафик, поэтому копия здесь стоила прохода по памяти на каждый байт загрузки.
 *
 * Правило одно: использовать данные ДО следующего вызова по этому соединению. Подробнее —
 * в tls13.h у tls13_read_ref. */
int transport_read_zc(struct transport *t, unsigned char *buf, size_t cap,
                      const unsigned char **data, size_t *got);

/* Лежат ли у нас уже прочитанные данные, которых ядро не покажет как готовность сокета.
 * Подробности — в transport.c. */
int transport_has_data(const struct transport *t);

/* Сервер объявил прямое копирование (Vision): дальше в сокете не записи TLS, а поток как
 * есть. Зовёт тот, кто разбирает кадры протокола. */
void transport_direct(struct transport *t);

/* Структура переехала в памяти — поправить указатели на саму себя (transport_ops.moved). */
void transport_moved(struct transport *t);

static inline int transport_fd(const struct transport *t) { return t->link.fd; }

/* Дескриптор второй связи транспорта (transport_ops.aux_fd) или -1; слить с неё пришедшее
 * (transport_ops.aux_drain). Подробности — в transport.c. */
int transport_aux_fd(const struct transport *t);
int transport_aux_drain(struct transport *t);

/* Закрыть всё: дескрипторы обеих связей и контексты шифров в куче. Годится и для структуры,
 * которую transport_open не довёл до конца или не открывал вовсе (fd -1). */
void transport_close(struct transport *t);

const char *transport_strerror(int rc);

/* Метка сокетов к узлу (SO_MARK до connect) — для `via`/`over`, см. «вложенные выходы» в
 * spec.h. 0 — не метить. required — метка обязательна: без неё соединение не открывается. */
void transport_set_sock_mark(uint32_t mark, int required);

/* Сколько места обязан дать вызывающий transport_read: транспорты поверх HTTP/2 отдают за
 * один раз до целой записи TLS. */
#define TRANSPORT_MIN_READ_CAP H2_MIN_READ_CAP

/* ---- для файлов этого каталога ------------------------------------------------------ */

extern const struct transport_ops tr_tcp, tr_grpc, tr_xhttp, tr_ws, tr_httpupgrade;
extern const struct security_ops tr_sec_none, tr_sec_tls, tr_sec_reality;

/* ---- ws и httpupgrade: общий запрос Upgrade (trupgrade.c) и кадры (trws.c) ------------- */

/* Открытие ws или httpupgrade поверх защищённой связи. Без ранних данных — запрос Upgrade и ответ
 * 101 синхронно, в пределах timeout_s (открытие идёт в потоке установщика, а не в цикле туннеля),
 * остаток за ответом — в t->h1.stash. С ранними данными — как у Xray (h1_state): ws откладывает
 * запрос до первой записи, httpupgrade шлёт его и ответа не ждёт. ws — 1 для WebSocket, 0 для
 * httpupgrade. */
int tr_h1_upgrade(struct transport *t, const struct tr_node *n, int ws, int timeout_s);

/* Послать запрос Upgrade по узлу t->h1.node; у ws — с новым ключом (ожидаемый Accept — в
 * t->h1.accept) и, если ed не NULL, с ранними данными в Sec-WebSocket-Protocol (base64url без
 * выравнивания, как RawURLEncoding у Xray). */
int tr_h1_send(struct transport *t, int ws, const unsigned char *ed, size_t ed_n);

/* Отложенный ответ (H1_WAIT): скормить кусок входа. 0 — ответ ещё не кончился, 1 — принят
 * (фаза H1_OPEN, *used — сколько байт ушло на заголовки, остальное — уже поток), иначе код TR_*. */
int tr_h1_lazy(struct transport *t, int ws, const unsigned char *in, size_t n, size_t *used);

/* Собрать запрос Upgrade в out — без сети, для открытия и для стенда (tests/wsmatch.c). key —
 * Sec-WebSocket-Key у ws, NULL у httpupgrade; proto — Sec-WebSocket-Protocol (ранние данные) или
 * NULL. Длина запроса либо 0: не влез или путь негоден. */
size_t tr_h1_request(const struct tr_node *n, int ws, const char *key, const char *proto,
                     char *out, size_t cap);

/* Ответ на запрос Upgrade — потоком, по кускам как угодно разрезанного входа. */
struct h1_resp {
    int done;                  /* заголовки ответа кончились */
    int status;                /* код ответа, 0 — строки статуса ещё не было */
    uint8_t up_ok, conn_ok, acc_ok;
    uint8_t seen;              /* какие из трёх заголовков уже встречались */
    uint8_t bad;               /* не HTTP вовсе или длиннее предела */
    uint32_t total;            /* байт заголовков, для предела */
    uint16_t line_n;
    char line[256];            /* текущая строка; длиннее — обрезается (см. trupgrade.c) */
};
/* Скормить кусок; *used — сколько байт ушло на заголовки (остальное — уже поток за ними).
 * accept — ожидаемый Sec-WebSocket-Accept у ws, NULL у httpupgrade. */
void tr_h1_resp_feed(struct h1_resp *r, int ws, const char *accept,
                     const unsigned char *in, size_t n, size_t *used);
/* Итог разобранного ответа: 0 или код TR_* (TR_EUPSTATUS, TR_ENOUPGRADE, TR_EWSACCEPT). */
int tr_h1_resp_verdict(const struct h1_resp *r, int ws);
/* Код ответа последнего отказа TR_EUPSTATUS в этом потоке — для текста причины. */
int tr_h1_last_status(void);
/* Освободить остаток после 101 (t->h1.stash). */
void tr_h1_free(struct transport *t);
/* Случайные байты у ядра (ключ запроса ws, маска кадров). 0 или -1. */
int tr_h1_random(unsigned char *out, size_t n);

/* Sec-WebSocket-Accept для ключа (RFC 6455, 4.2.2): base64(SHA-1(ключ + GUID)), 28 знаков. */
void tr_ws_accept(const char *key, char out[29]);

/* Кадр клиента: заголовок, ключ маски и замаскированное тело (RFC 6455, 5.2–5.3). Клиент ОБЯЗАН
 * маскировать каждый кадр, сервер обязан рвать соединение на незамаскированном. Длина кадра
 * либо 0, если не влез в cap. */
size_t tr_ws_frame(unsigned char *out, size_t cap, int opcode, int fin, const unsigned char key[4],
                   const unsigned char *d, size_t n);

/* Разобрать кусок кадров от сервера: тела кадров данных — в out (out вправе совпадать с in:
 * разбор только сдвигает байты влево), служебные — в состояние (ping, close). Вход потребляется
 * целиком. 0 или TR_EWSFRAME; H2_ETOOBIG — не влезло в out (вызывающий дал меньше входа). */
int tr_ws_parse(struct ws_rx *r, const unsigned char *in, size_t n,
                unsigned char *out, size_t cap, size_t *out_n);

/* TCP до узла по всем адресам имени (trdial.c). Дескриптор либо отрицательный код TR_*. */
int tr_dial(const char *host, uint16_t port, int timeout_s);
/* Соединённый неблокирующий сокет UDP к узлу с той же меткой, что у TCP (trdial.c): датаграммы
 * протоколов прокси (shadowsocks, SOCKS5). Дескриптор либо отрицательный код TR_*. */
int tr_dial_udp(const char *host, uint16_t port);

/* Безопасность по полю ссылки: none, tls, иначе reality (trsec.c). */
const struct security_ops *tr_security(const char *name);

/* Связь целиком: сокет и рукопожатие безопасности. На отказе сокет закрыт и fd == -1. Общая
 * для основной связи и второй связи xhttp — ровно ради того, чтобы они не разошлись. */
int tr_link_open(struct tr_link *l, const struct tr_node *n, const char *alpn, int timeout_s);

/* Ввод-вывод основной связи в форме struct h2_io (ctx — struct tr_link). */
int tr_link_write(void *ctx, const unsigned char *d, size_t n);
int tr_link_read(void *ctx, unsigned char *d, size_t cap, size_t *got);

/* Закрыть связь: сокет и, если это был TLS, ключи в куче. */
void tr_link_close(struct tr_link *l);

#endif
