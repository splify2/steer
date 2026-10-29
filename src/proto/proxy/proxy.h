/* Модуль steer-proxy: протоколы прокси podkop/forkop поверх стека туннеля (docs/proxy.md).
 *
 * Пять протоколов одним пакетом: trojan, shadowsocks, socks, http, vmess. Все они — `kind: tunnel`
 * c `protocol:` соответствующего имени (kinds/proxy.c), узлы берутся из подписки, как у vless и
 * hysteria2. Коннектор sing-box (steer-box-connector) переводит конфиг sing-box в спеку v2 steer и
 * пишет каждый узел ссылкой в свой файл подписки — поэтому форматы узла здесь это стандартные
 * share-ссылки (trojan://, ss://, socks://, http://, vmess://).
 *
 * УСТРОЙСТВО. trojan и vmess везут поток и UDP внутри потока к узлу, как vless: дайлер поверх стека
 * (src/tunnel) и общего транспорта с TLS/Reality (src/proto/transport). http (CONNECT) — тоже
 * поток поверх транспорта, без UDP. shadowsocks и socks5 — поток поверх TCP и, для UDP, своя
 * датаграмма на датаграмму клиента через сокет UDP к узлу (бит DC_UDP_OWN, dialer.h). Общие
 * половины — разбор ссылки и поля транспорта (sublink.h), узел глазами транспорта (sl_tr_node),
 * подъём, перебор узлов и слежку (pxdial.c, pxmain.c) — не дублируются.
 *
 * Узел — struct px_node: половина транспорта/безопасности в vn (общая с vless, sublink.h), а своё у
 * протокола — пароль, метод шифра, идентификатор. Разбирает ссылку pxsub.c. */
#ifndef STEER_PROXY_H
#define STEER_PROXY_H
#include <stddef.h>
#include <stdint.h>
#include "vless.h"
#include "sublink.h"

enum px_proto { PX_TROJAN = 1, PX_SS, PX_SOCKS, PX_HTTP, PX_VMESS };

/* Методы shadowsocks. Имена — как в ss:// и конфиге sing-box; «none»/«plain» — без шифрования
 * (поток как есть). 2022-* — SIP022 с BLAKE3 (отдельный вывод ключей и формат). */
enum ss_method {
    SS_NONE = 0,
    SS_AES128_GCM, SS_AES256_GCM, SS_CHACHA20_POLY1305,
    SS_2022_AES128, SS_2022_AES256, SS_2022_CHACHA20,
};

/* Шифр тела vmess (поле scy / security). auto выбирается как aes-128-gcm, если есть AES-NI, иначе
 * chacha20-poly1305 (так делает v2rayN). zero — без шифрования и без проверки (len-маскирование
 * выключено), none — ChunkStream без AEAD. */
enum vmess_sec { VMESS_AUTO = 0, VMESS_AES128_GCM, VMESS_CHACHA20_POLY1305, VMESS_NONE, VMESS_ZERO };

#define PX_PASS_MAX   256    /* пароль trojan/ss/http, userinfo socks: не короче живых ссылок */
#define PX_USER_MAX   128
#define PX_SS_PSK_MAX 32     /* длина ключа ss: 16 или 32 байта */

struct px_node {
    enum px_proto proto;
    /* Транспорт и безопасность — общие с vless (sublink.h): host, port, type, security, sni, fp,
     * pbk, sid, path, service, mode, http_host, headers, pcs/pks/vcn, ech, pqv, insecure. uuid у
     * прокси не UUID, а секрет userinfo (пароль, имя:пароль) — его разбирает протокол. */
    struct vless_node vn;

    char name[128];
    char user[PX_USER_MAX];              /* socks/http: имя (пусто — без авторизации) */
    char pass[PX_PASS_MAX];              /* trojan/http/socks: пароль; ss: пароль до вывода ключа */

    /* shadowsocks */
    enum ss_method ss_method;
    unsigned char ss_key[PX_SS_PSK_MAX]; /* ключ сессии (AEAD) или iPSK (2022); длина — ss_key_n */
    size_t ss_key_n;
    /* 2022 с несколькими пользователями (iPSK:uPSK): uPSK — последний ключ, iPSK — реле перед ним.
     * Здесь держим только uPSK (ss_key) и, если был iPSK, его один уровень — реле у подписок редко
     * глубже одного; большее объявляется непригодным с причиной. */
    unsigned char ss_ipsk[PX_SS_PSK_MAX];
    size_t ss_ipsk_n;                    /* 0 — одноуровневый ключ */

    /* socks */
    uint8_t socks_ver;                   /* 4, 5; socks4a — те же 4 с именем в запросе */

    /* vmess */
    unsigned char vmess_id[16];
    enum vmess_sec vmess_sec;
    int vmess_aid;                       /* alterId: поддержан только 0 (AEAD-заголовок) */

    char skip_reason[96];
};

#define PX_SKIP_REASONS 8
/* reason — того же размера, что skip_reason узла (96): иначе причина у подписки обрезается. */
struct px_skip { char reason[96]; char example[144]; size_t count; };
struct px_sub_stats {
    size_t skipped;                      /* узлов наших протоколов, непригодных к работе */
    size_t foreign;                      /* ссылок других протоколов */
    struct px_skip reasons[PX_SKIP_REASONS];
    size_t reasons_n, reasons_dropped;
};

/* Разобрать одну ссылку. 0 — узел пригоден; 1 — разобран, но негоден (skip_reason); -1 — не
 * ссылка наших протоколов. want — только этот протокол (0 — любой из пяти). */
int px_parse_url(const char *url, struct px_node *n, enum px_proto want);

/* Подписка целиком: список ссылок по строкам или тот же список в base64. Конфиг sing-box (объект
 * outbounds) здесь не разбирается — его переводит в ссылки коннектор (steer-box-connector). Берутся
 * узлы протокола want (0 — все пять); чужое — в foreign. Число пригодных. */
size_t px_parse_sub(const char *text, struct px_node *out, size_t max, enum px_proto want,
                    struct px_sub_stats *st);
const char *px_sub_text(const char *raw, size_t raw_n, char *dec, size_t dec_n);
/* Подписка из файла: массив в куче (free), *cnt — пригодных; NULL — не открылся, >64 МиБ, нет
 * памяти. Ни число узлов, ни размер файла константой не ограничены. */
struct px_node *px_load_sub(const char *path, enum px_proto want, size_t *cnt,
                            struct px_sub_stats *st);

/* Имя протокола для спеки и ссылки, и обратно. */
const char *px_proto_name(enum px_proto p);

/* Имена шифров для вывода узла (proxy-nodes): метод shadowsocks и шифр тела vmess. */
const char *px_ss_method_name(enum ss_method m);
const char *px_vmess_sec_name(enum vmess_sec v);

/* Отнести непригодный узел к причине (как у vless/hy2). */
void px_skip_note(struct px_sub_stats *st, const struct px_node *n, const char *reason);

#endif
