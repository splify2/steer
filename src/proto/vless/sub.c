/* Разбор подписки: vless:// ссылки в список узлов.
 *
 * Подписка — это base64 от списка ссылок, по одной на строку. Ничего сложнее здесь нет,
 * и именно поэтому разбор живёт в steer, а не в клиенте: он не требует ни криптографии,
 * ни сети, проверяется текстом, и его результат нужен и интерфейсу (показать узлы), и
 * сторожу (выбрать живой).
 *
 * Чужие протоколы (hy2, ss, trojan) пропускаются молча, но считаются: подписка обычно
 * общая, и «в ней 26 узлов, а steer видит 17» должно объясняться цифрой, а не догадкой.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vless.h"
#include "sublink.h"
/* Ради vless_uuid_form: пригодность идентификатора — такая же часть пригодности узла, как
 * транспорт и security, а правило, по которому он превращается в 16 байт, живёт в одном
 * месте — в vless_proto.c. Библиотек это не тянет. */
#include "vless_proto.h"
/* Разбор строки encryption (VLESS encryption): годность узла решается здесь, до подключения. Только строки,
 * без криптографии — сюда же входит стенд подписки, у которого библиотеки нет. */
#include "vencp.h"

/* Строки ссылки, поля транспорта и безопасности, длинные значения узла, проверка сертификата и
 * ключ insecure выхода — в sublink.c: их делит с этим файлом модуль steer-proxy (sublink.h). Здесь
 * остались подписки целиком и VLESS-своё: flow, encryption и идентификатор. */

/* Метка негодного encryption: разбор не удался, причина названа в node_usable. */
static const char SUB_BAD_ENC[] = "!encryption";

/* encryption узла. Пусто и «none» — шифрования нет. Остальное обязано разобраться по правилу Xray
 * (vencp.h): иначе узел помечается меткой и отбраковывается в node_usable. Значение приходит уже
 * раскодированным, с завершающим нулём. */
static void set_encryption(struct vless_node *n, const char *v) {
    n->encryption = NULL;
    if (!v[0] || !strcmp(v, "none")) return;
    struct venc_cfg c;
    if (vencp_parse(v, &c, NULL) != 0) { n->encryption = SUB_BAD_ENC; return; }
    n->encryption = sl_intern(v, strlen(v));
}

/* Пригодность разобранного узла — общее правило для обоих путей разбора; тело ниже. */
static int node_usable(struct vless_node *n);

/* vless://UUID@host:port?params#name
 *
 * Возвращает 0, если ссылка разобрана и узел ПРИГОДЕН. Непригодный узел — это не ошибка
 * подписки: сервер может предлагать транспорт, которого клиент не умеет, и правильное
 * поведение — пропустить его, а не отказаться от всей подписки. */
/* Параметры самого VLESS: flow и encryption (постквантовое шифрование Xray-core, паритет 26.9 —
 * значение длинное, см. sl_intern). Остальные параметры ссылки — транспорт и безопасность
 * (sl_link_param). */
static int vless_own(struct vless_node *n, const char *k, size_t klen, const char *v, size_t vlen) {
    if (klen == 4 && !strncmp(k, "flow", 4)) sl_set_field(n->flow, sizeof(n->flow), v, vlen);
    else if (klen == 10 && !strncmp(k, "encryption", 10)) {
        char *d = sl_param_dup(v, vlen);
        if (d) { set_encryption(n, d); free(d); } else n->encryption = SUB_BAD_ENC;
    }
    else return 0;
    return 1;
}

int vless_parse_url(const char *url, struct vless_node *n) {
    /* Значения по умолчанию — те, что подразумевает VLESS, когда поле опущено: type=tcp и
     * security=none встречаются именно так (их ставят sl_link_parse и node_usable).
     *
     * security=none — это VLESS БЕЗ TLS, голый протокол по TCP. Он поддержан: шифровать там
     * нечего, а сам VLESS реализован целиком. Такой узел осмыслен внутри доверенной сети или за
     * уже защищённым каналом, и отбрасывать его вместе с неподдержанными транспортами было бы
     * ошибкой — причины у них разные. */
    int rc = sl_link_parse(url, "vless://", n, vless_own, NULL, NULL);
    if (rc) return rc;
    /* Пригодность. Проверяется здесь, а не при подключении, чтобы непригодный узел не попал в
     * список кандидатов и сторож не тратил на него попытки. */
    return node_usable(n);
}

/* Пригоден ли РАЗОБРАННЫЙ узел. 0 — да, 1 — нет, причина в n->skip_reason.
 *
 * Отдельной функцией, потому что путей разбора теперь два: ссылка vless:// и конфиг Xray в
 * подписке (см. parse_xray ниже). Правило пригодности у них обязано быть одно — иначе узел,
 * непригодный в одном виде, окажется пригодным в другом, и человек получит «узлов два,
 * туннель не работает, сказать нечего» ровно там, где мы этого и добивались избежать.
 *
 * Поля, которых во ссылке не было, к этому моменту уже заполнены умолчаниями: делает это
 * первая же строка. */
static int node_usable(struct vless_node *n) {
    if (!n->security[0]) snprintf(n->security, sizeof(n->security), "none");

    /* flow=xtls-rprx-vision-udp443 — тот же Vision, но с разрешением UDP/443 в потоке (Xray-core). У нас
     * UDP идёт отдельной командой и без flow, поэтому разрешение ничего не меняет, а имя приводится к
     * обычному: в запросе VLESS Xray тоже отправляет flow без суффикса. */
    if (!strcmp(n->flow, "xtls-rprx-vision-udp443")) snprintf(n->flow, sizeof(n->flow), "xtls-rprx-vision");

    if (n->encryption == SUB_BAD_ENC) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "encryption не поддержан");
        return 1;
    }
    if (sl_link_usable_pre(n)) return 1;

    /* Идентификатор пользователя. Проверяется ЗДЕСЬ по той же причине, что и всё
     * остальное в этом блоке: непригодный узел не должен попасть в кандидаты.
     *
     * Пригодность здесь — это правило Xray (см. vless_uuid_form): либо шестнадцатеричный
     * UUID в 32-36 знаков, либо короткая строка до 30 знаков, из которой UUID выводится
     * хэшем. Панели выдают и то, и другое, и «TMG_74317ba5f91» — законный узел, а не
     * ошибка. Непригодны ровно три случая, и стать 16 байтами они не могут никак:
     * пустая строка, ровно 31 знак (для вывода длинно, для UUID коротко) и длиннее
     * UUID; отдельно — строка нужной длины с посторонним знаком внутри.
     *
     * До этой проверки такой узел считался пригодным, доходил до подключения и молчал:
     * проба отвечала «UUID неразборчив», а туннель ронял соединение без причины. */
    switch (vless_uuid_form(n->uuid)) {
    case VLESS_UUID_EMPTY:
        snprintf(n->skip_reason, sizeof(n->skip_reason), "идентификатор пуст");
        return 1;
    case VLESS_UUID_GAP:
        snprintf(n->skip_reason, sizeof(n->skip_reason),
                 "идентификатор: 31 знак, нужен UUID");
        return 1;
    case VLESS_UUID_TOOLONG:
        snprintf(n->skip_reason, sizeof(n->skip_reason), "идентификатор длиннее UUID");
        return 1;
    case VLESS_UUID_NOTHEX:
        snprintf(n->skip_reason, sizeof(n->skip_reason), "UUID с недопустимым знаком");
        return 1;
    default:
        break;
    }

    return sl_link_usable_post(n);
}

/* ---- подписка в виде конфига Xray -------------------------------------------
 *
 * ЗАЧЕМ ЭТО ВООБЩЕ ЕСТЬ. Панели с привязкой к устройствам выбирают формат ответа по
 * User-Agent, и списка ссылок vless:// среди вариантов может не быть НИ ОДНОГО. Замерено на
 * живой подписке: незнакомому клиенту (steer, curl, sing-box, Nekoray) отдаётся заглушка из
 * ссылок ss:// на localhost:1234 с именами «Неправильный клиент» и «Подключись через Happ»;
 * Happ, v2rayNG и Streisand получают конфиг Xray в JSON; Clash — свой YAML; SFI — конфиг
 * sing-box. То есть подписка, у которой узлы совершенно исправны (проверено пробой: восемь
 * из девяти отвечают), для движка выглядела как «ни одного пригодного узла».
 *
 * Притворяться чужим клиентом — не выход, и не из принципа: JSON приезжает и Happ-у, значит
 * читать его пришлось бы всё равно. Поэтому читаем.
 *
 * ЧТО ИМЕННО ЧИТАЕТСЯ. Массив конфигов `[{...},{...}]` или один конфиг `{...}`; в каждом
 * берутся `outbounds`, а из них — те, у которых `protocol` равен `vless`. Всё остальное
 * (dns, routing, inbounds, freedom, blackhole) пропускается: это настройки клиента, к
 * которому подписка обращается, а не описание узла.
 *
 * Разборщик свой и намеренно маленький — как и ридер спеки (src/lib/jsonr.c), он не общий
 * парсер JSON, а обход ровно той формы, которую ждём. Ридер спеки теперь общий (jsonr.h), но
 * брать его сюда всё равно незачем, по двум причинам. Он строг там, где подписке нужна
 * терпимость: строку длиннее буфера он отвергает через struct err (для имени выхода или пути
 * так и надо — обрезанное имя устройства ядро не возьмёт), а имя узла из панели здесь молча
 * обрезается — это подпись, и из-за длинной подписи терять узел нельзя. И стенд подписки
 * (tests/submatch.c) включает этот файл исходником и собирается в одиночку, без lib/, модели и
 * криптобиблиотеки, — это его главное свойство: чужой текст из интернета проверяется без сети и без
 * docker.
 */
struct sj { const char *p; };

static void sj_ws(struct sj *j) {
    while (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r') j->p++;
}

/* Строка в buf. Экранирование понимается ровно настолько, чтобы \" не оборвала строку: имена
 * узлов приходят из панели и содержат что угодно, а \uXXXX в них не встречается — панели
 * пишут UTF-8 как есть. Непонятая последовательность попадает в buf буквально, и это лучше,
 * чем отказ: имя — единственное поле, которому позволено быть любым. */
static int sj_str(struct sj *j, char *buf, size_t n) {
    sj_ws(j);
    if (*j->p != '"') return -1;
    j->p++;
    size_t i = 0;
    while (*j->p && *j->p != '"') {
        if (*j->p == '\\' && j->p[1]) j->p++;
        if (i + 1 < n) buf[i++] = *j->p;
        j->p++;
    }
    if (*j->p != '"') return -1;
    j->p++;
    if (n) buf[i] = '\0';
    return 0;
}

/* Пропустить одно значение любого типа. Нужен за тем же, за чем js_skip ридеру спеки
 * (src/lib/jsonr.c): чтобы незнакомый ключ
 * не толковался молча, а именно пропускался. */
static void sj_skip(struct sj *j) {
    sj_ws(j);
    if (*j->p == '"') { char t[8]; sj_str(j, t, sizeof(t)); return; }
    if (*j->p == '{' || *j->p == '[') {
        char open = *j->p, close = open == '{' ? '}' : ']';
        int depth = 0;
        do {
            if (*j->p == '"') { char t[8]; sj_str(j, t, sizeof(t)); continue; }
            if (*j->p == open) depth++;
            else if (*j->p == close) depth--;
            j->p++;
        } while (*j->p && depth > 0);
        return;
    }
    while (*j->p && *j->p != ',' && *j->p != '}' && *j->p != ']') j->p++;
}

/* Войти в объект и отдавать его ключи по одному. 0 — ключ в key, 1 — объект кончился,
 * -1 — это не объект. Значение читает вызывающий; не прочитал — обязан позвать sj_skip. */
static int sj_obj_key(struct sj *j, int *first, char *key, size_t key_n) {
    sj_ws(j);
    if (*first) {
        if (*j->p != '{') return -1;
        j->p++;
        *first = 0;
    } else {
        sj_ws(j);
        if (*j->p == ',') j->p++;
    }
    sj_ws(j);
    if (*j->p == '}') { j->p++; return 1; }
    if (sj_str(j, key, key_n) != 0) return -1;
    sj_ws(j);
    if (*j->p != ':') return -1;
    j->p++;
    return 0;
}

/* Тот же приём для массива: 0 — элемент начинается здесь, 1 — массив кончился. */
static int sj_arr_next(struct sj *j, int *first) {
    sj_ws(j);
    if (*first) {
        if (*j->p != '[') return -1;
        j->p++;
        *first = 0;
    } else {
        sj_ws(j);
        if (*j->p == ',') j->p++;
        /* После элемента бывает только запятая или конец массива. Всё прочее — брак, и на
         * нём разбор обязан ОСТАНОВИТЬСЯ: прежде он отвечал «есть следующий элемент», не
         * сдвигая указатель, а читатель элемента на не-объекте тоже не сдвигался — и цикл
         * крутился вечно на `[null]`, `[}`, порте строкой и ещё четырёх формах кривого JSON,
         * который приходит из интернета (подписка с панели). Висел и процесс туннеля, и
         * интерфейс. */
        else if (*j->p != ']') return -1;
    }
    sj_ws(j);
    if (*j->p == ']') { j->p++; return 1; }
    return 0;
}

/* Настройки ws или httpupgrade из конфига — до того, как станет известно, какой из двух у узла.
 * Конфиг вправе нести оба объекта (и ещё xhttpSettings) сразу, а решает network — который может
 * стоять и после них, поэтому разобранное складывается сюда и переносится в узел в конце
 * (xray_stream). Иначе путь из wsSettings затирал бы путь xhttp у узла xhttp. */
struct upg_cfg {
    char path[sizeof(((struct vless_node *)0)->path)];
    char host[sizeof(((struct vless_node *)0)->http_host)];
    char headers[sizeof(((struct vless_node *)0)->headers)];
    uint8_t bad;
};

static int ci_eq(const char *a, const char *b) {
    for (; *a && *b; a++, b++) {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (char)(y + 32);
        if (x != y) return 0;
    }
    return *a == *b;
}

/* headers конфига Xray (map[string]string) — в строки «Имя: значение\n».
 *
 * Отбраковка (bad), а не молчаливый пропуск, потому что заголовок узла — часть облика, который
 * продавец выбрал для своего сервера или CDN перед ним: узел, ушедший без него, может
 * отвечать 403 и выглядеть мёртвым. Негодно:
 *   - значение не строкой — Xray такой конфиг не загрузит вовсе;
 *   - имя не из знаков токена HTTP или длиннее 40, значение с управляющим знаком (перевод строки
 *     сделал бы из одного заголовка два) или длиннее 250 — запрос у нас собирается из строк;
 *   - у ws — Upgrade, Connection и Sec-WebSocket-Key/Version/Extensions: gorilla на них отказывает
 *     («duplicate header not allowed»), то есть и у Xray узел не открылся бы. У httpupgrade Xray их
 *     принимает (ключ как написан, Connection и Upgrade транспорт ставит поверх своими
 *     каноническими ключами) — и здесь принимаются, запрос повторяет Xray (trupgrade.c);
 *   - Host у httpupgrade — Xray отвергает конфиг («"headers" can't contain "host"»). У ws Host
 *     из headers Xray переносит в host (если тот пуст) и из заголовков убирает — так и здесь.
 *   - не влезло в буфер узла. */
static void xray_headers(struct sj *j, struct upg_cfg *u, int hu) {
    int f = 1;
    char key[64], val[256];
    size_t o = strlen(u->headers);
    while (sj_obj_key(j, &f, key, sizeof(key)) == 0) {
        sj_ws(j);
        if (*j->p != '"') { sj_skip(j); u->bad = 1; continue; }
        val[0] = '\0';
        sj_str(j, val, sizeof(val));
        size_t kn = strlen(key), vn = strlen(val);
        if (ci_eq(key, "host")) {
            if (hu) u->bad = 1;
            else if (!u->host[0]) sl_set_field(u->host, sizeof(u->host), val, vn);
            continue;
        }
        int ok = kn > 0 && kn <= 40 && vn <= 250;
        for (size_t i = 0; ok && i < kn; i++) {
            unsigned char c = (unsigned char)key[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  (c && strchr("!#$%&'*+-.^_`|~", c))))
                ok = 0;
        }
        for (size_t i = 0; ok && i < vn; i++) {
            unsigned char c = (unsigned char)val[i];
            if ((c < 0x20 && c != '\t') || c == 0x7f) ok = 0;
        }
        if (!hu && (ci_eq(key, "upgrade") || ci_eq(key, "connection") ||
                    ci_eq(key, "sec-websocket-key") || ci_eq(key, "sec-websocket-version") ||
                    ci_eq(key, "sec-websocket-extensions")))
            ok = 0;
        if (!ok || o + kn + 2 + vn + 1 >= sizeof(u->headers)) { u->bad = 1; continue; }
        o += (size_t)snprintf(u->headers + o, sizeof(u->headers) - o, "%s: %s\n", key, val);
    }
}

/* wsSettings и httpupgradeSettings: path, host, headers. Пустой host не затирает Host из
 * headers (у Xray пустой host — «не задан»). */
static void xray_upg(struct sj *j, struct upg_cfg *u, int hu) {
    int f = 1;
    char k[64];
    while (sj_obj_key(j, &f, k, sizeof(k)) == 0) {
        sj_ws(j);
        if (!strcmp(k, "path") && *j->p == '"') sj_str(j, u->path, sizeof(u->path));
        else if (!strcmp(k, "host") && *j->p == '"') {
            char h[sizeof(u->host)] = "";
            sj_str(j, h, sizeof(h));
            if (h[0]) snprintf(u->host, sizeof(u->host), "%s", h);
        } else if (!strcmp(k, "headers") && *j->p == '{') xray_headers(j, u, hu);
        else sj_skip(j);
    }
}

static int sj_bool(struct sj *j);

/* streamSettings: транспорт, security и всё, что зависит от них. */
static void xray_stream(struct sj *j, struct vless_node *n) {
    int first = 1;
    char k[64];
    struct upg_cfg ws, hu;
    memset(&ws, 0, sizeof(ws));
    memset(&hu, 0, sizeof(hu));
    while (sj_obj_key(j, &first, k, sizeof(k)) == 0) {
        if (!strcmp(k, "network")) {
            sj_str(j, n->type, sizeof(n->type));
            /* raw — каноническое имя tcp у Xray с 24.9.30; панели пишут его всё чаще. */
            if (!strcmp(n->type, "raw")) snprintf(n->type, sizeof(n->type), "tcp");
            /* websocket — второе имя ws у Xray (infra/conf: case "ws", "websocket"). */
            if (!strcmp(n->type, "websocket")) snprintf(n->type, sizeof(n->type), "ws");
        }
        else if (!strcmp(k, "tcpSettings") || !strcmp(k, "rawSettings")) {
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof(k2)) == 0) {
                if (strcmp(k2, "header") != 0) { sj_skip(j); continue; }
                int f3 = 1;
                char k3[64], ty[16] = "";
                while (sj_obj_key(j, &f3, k3, sizeof(k3)) == 0) {
                    if (!strcmp(k3, "type")) sj_str(j, ty, sizeof ty); else sj_skip(j);
                }
                if (!strcmp(ty, "http")) n->tcp_http = 1;
            }
        }
        else if (!strcmp(k, "wsSettings")) xray_upg(j, &ws, 0);
        else if (!strcmp(k, "httpupgradeSettings")) xray_upg(j, &hu, 1);
        else if (!strcmp(k, "security")) sj_str(j, n->security, sizeof(n->security));
        else if (!strcmp(k, "realitySettings") || !strcmp(k, "tlsSettings")) {
            /* Оба объекта несут serverName и fingerprint; publicKey и shortId бывают только
             * у reality. Разбирать их одним куском можно потому, что имена полей не спорят:
             * узел объявляет ровно один из двух. */
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof(k2)) == 0) {
                if (!strcmp(k2, "serverName")) sj_str(j, n->sni, sizeof(n->sni));
                else if (!strcmp(k2, "fingerprint")) sj_str(j, n->fp, sizeof(n->fp));
                else if (!strcmp(k2, "publicKey")) sj_str(j, n->pbk, sizeof(n->pbk));
                else if (!strcmp(k2, "shortId")) sj_str(j, n->sid, sizeof(n->sid));
                else if (!strcmp(k2, "mldsa65Verify") || !strcmp(k2, "pqv")) {
                    char *pv = malloc(4096);
                    if (pv) { pv[0] = '\0'; sj_str(j, pv, 4096); sl_set_pqv(n, pv); free(pv); }
                    else sj_skip(j);
                }
                else if (!strcmp(k2, "pinnedPeerCertSha256") || !strcmp(k2, "pcs")) {
                    char pv[1100] = "";
                    sj_str(j, pv, sizeof pv);
                    sl_add_pins(n, pv, 0);
                }
                else if (!strcmp(k2, "verifyPeerCertByName") || !strcmp(k2, "vcn")) {
                    char vv[300] = "";
                    sj_str(j, vv, sizeof vv);
                    sl_set_vcn(n, vv);
                }
                else if (!strcmp(k2, "allowInsecure")) { if (sj_bool(j)) n->allow_insecure = 1; }
                else if (!strcmp(k2, "echConfigList")) {
                    char ev[1400] = "";
                    sj_str(j, ev, sizeof ev);
                    sl_set_ech(n, ev);
                }
                else sj_skip(j);
            }
        } else if (!strcmp(k, "grpcSettings")) {
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof(k2)) == 0) {
                if (!strcmp(k2, "serviceName")) sj_str(j, n->service, sizeof(n->service));
                else sj_skip(j);
            }
        } else if (!strcmp(k, "xhttpSettings") || !strcmp(k, "splithttpSettings")) {
            /* splithttpSettings — прежнее имя того же транспорта; панели с ним ещё живут. */
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof(k2)) == 0) {
                if (!strcmp(k2, "path")) sj_str(j, n->path, sizeof(n->path));
                else if (!strcmp(k2, "mode")) sj_str(j, n->mode, sizeof(n->mode));
                /* В конфигурации это поле лежит прямо здесь, а не в `extra`: `extra` — форма
                 * ССЫЛКИ, в которую те же настройки заворачивают, когда конфигурации нет. */
                else if (!strcmp(k2, "xPaddingBytes")) {
                    char pb[32];
                    sj_str(j, pb, sizeof(pb));
                    sl_pad_range(n, pb);
                }
                /* Число или строка «от-до»: сырое слово, разбирается как в ссылке. */
                else if (!strcmp(k2, "scMaxEachPostBytes")) {
                    sj_ws(j);
                    const char *b = j->p;
                    sj_skip(j);
                    char raw[48];
                    size_t l = (size_t)(j->p - b);
                    if (l < sizeof raw) { memcpy(raw, b, l); raw[l] = 0; sl_post_range(n, raw); }
                }
                else if (!strcmp(k2, "extra")) {
                    /* Вложенный extra (форма ссылки внутри конфига): тот же просмотр, что у ссылки. */
                    const char *b = j->p;
                    sj_skip(j);
                    size_t l = (size_t)(j->p - b);
                    char *cp = malloc(l + 1);
                    if (cp) { memcpy(cp, b, l); cp[l] = 0; sl_parse_extra(n, cp); free(cp); }
                }
                else if (!strcmp(k2, "downloadSettings")) {
                    sj_ws(j);
                    if (strncmp(j->p, "null", 4) != 0) n->xh_extra = 1;
                    sj_skip(j);
                }
                else if (!strcmp(k2, "sessionPlacement") || !strcmp(k2, "sessionIDPlacement") ||
                         !strcmp(k2, "seqPlacement") || !strcmp(k2, "uplinkDataPlacement") ||
                         !strcmp(k2, "xPaddingMethod")) {
                    char v[32] = "";
                    sj_ws(j);
                    if (*j->p == '"') sj_str(j, v, sizeof v); else sj_skip(j);
                    if (sl_xh_setting_bad(k2, v)) n->xh_extra = 1;
                }
                else if (!strcmp(k2, "xPaddingObfsMode")) { if (sj_bool(j)) n->xh_extra = 1; }
                else sj_skip(j);
            }
        } else sj_skip(j);
    }
    const struct upg_cfg *u = !strcmp(n->type, "ws") ? &ws : !strcmp(n->type, "httpupgrade") ? &hu : NULL;
    if (u) {
        snprintf(n->path, sizeof(n->path), "%s", u->path);
        snprintf(n->http_host, sizeof(n->http_host), "%s", u->host);
        snprintf(n->headers, sizeof(n->headers), "%s", u->headers);
        n->headers_bad = u->bad;
    }
}

/* settings исходящего vless: vnext[0] — адрес, порт и первый пользователь.
 *
 * Именно первый и только он: подписка описывает узел для ОДНОГО человека, и второго
 * пользователя в ней не бывает. Появится — возьмём первого и не станем притворяться, что
 * умеем больше. */
static void json_encryption(struct sj *j, struct vless_node *n) {
    char *ev = malloc(4096);
    if (!ev) { sj_skip(j); return; }
    ev[0] = '\0';
    if (sj_str(j, ev, 4096) == 0) set_encryption(n, ev);
    free(ev);
}

static void xray_settings(struct sj *j, struct vless_node *n) {
    int first = 1;
    char k[64];
    while (sj_obj_key(j, &first, k, sizeof(k)) == 0) {
        /* Упрощённая форма исходящего (Xray 25+): address, port, id, flow, encryption прямо в settings,
         * без vnext и users. */
        if (!strcmp(k, "address")) { sj_str(j, n->host, sizeof(n->host)); continue; }
        if (!strcmp(k, "id")) { sj_str(j, n->uuid, sizeof(n->uuid)); continue; }
        if (!strcmp(k, "flow")) { sj_str(j, n->flow, sizeof(n->flow)); continue; }
        if (!strcmp(k, "encryption")) { json_encryption(j, n); continue; }
        if (!strcmp(k, "port")) {
            sj_ws(j);
            char num[16];
            if (*j->p == '"') sj_str(j, num, sizeof(num));
            else {
                size_t i = 0;
                while (*j->p >= '0' && *j->p <= '9' && i + 1 < sizeof(num)) num[i++] = *j->p++;
                num[i] = '\0';
                if (!i) sj_skip(j);
            }
            n->port = sl_port_of(num);
            continue;
        }
        if (strcmp(k, "vnext") != 0) { sj_skip(j); continue; }
        int fa = 1, taken = 0;
        while (sj_arr_next(j, &fa) == 0) {
            if (taken) { sj_skip(j); continue; }
            taken = 1;
            int fo = 1;
            char k2[64];
            while (sj_obj_key(j, &fo, k2, sizeof(k2)) == 0) {
                if (!strcmp(k2, "address")) sj_str(j, n->host, sizeof(n->host));
                else if (!strcmp(k2, "port")) {
                    sj_ws(j);
                    char num[16];
                    /* Число или число строкой: панели пишут и так, и так. Прочее — брак,
                     * пропускается как значение, чтобы разбор не разъехался по объекту. */
                    if (*j->p == '"') sj_str(j, num, sizeof(num));
                    else {
                        size_t i = 0;
                        while (*j->p >= '0' && *j->p <= '9' && i + 1 < sizeof(num))
                            num[i++] = *j->p++;
                        num[i] = '\0';
                        if (!i) sj_skip(j);
                    }
                    n->port = sl_port_of(num);
                } else if (!strcmp(k2, "users")) {
                    int fu = 1, u_taken = 0;
                    while (sj_arr_next(j, &fu) == 0) {
                        if (u_taken) { sj_skip(j); continue; }
                        u_taken = 1;
                        int fu2 = 1;
                        char k3[64];
                        while (sj_obj_key(j, &fu2, k3, sizeof(k3)) == 0) {
                            if (!strcmp(k3, "id")) sj_str(j, n->uuid, sizeof(n->uuid));
                            else if (!strcmp(k3, "flow")) sj_str(j, n->flow, sizeof(n->flow));
                            else if (!strcmp(k3, "encryption")) json_encryption(j, n);
                            else sj_skip(j);
                        }
                    }
                } else sj_skip(j);
            }
        }
    }
}

/* ---- sing-box: outbounds с type=vless ---------------------------------------------------------
 *
 * Панели, отдающие конфиг sing-box (клиент SFI, Hiddify, Karing), кладут узлы в тот же массив
 * `outbounds`, что и Xray, но плоско: type/tag/server/server_port/uuid/flow и объекты tls и transport.
 * Отличия от Xray, из-за которых нужен отдельный разбор: имя вида — type, а не protocol; порт — число
 * server_port; TLS — объект с вложенными utls и reality; в transport заголовок Host — строка или
 * массив строк. Ранние данные ws: max_early_data + early_data_header_name; при имени
 * Sec-WebSocket-Protocol это `?ed=N` Xray (наш ws так и умеет), при пустом sing-box кладёт данные в
 * путь — форма, которой у Xray нет, и мы ранние данные тогда не включаем (соединение сработает и без
 * них: сервер sing-box принимает обычный запрос). */
/* Дописать «Имя: значение\n» в буфер заголовков; -1, если не влезло или имя пусто. Без snprintf: он
 * предупреждает об усечении там, где усечение мы сами исключили проверкой длины. */
static int hdr_append(char *dst, size_t cap, const char *k, const char *v) {
    size_t o = strlen(dst), kn = strlen(k), vn = strlen(v);
    if (!kn || o + kn + vn + 4 >= cap) return -1;
    memcpy(dst + o, k, kn);
    dst[o + kn] = ':'; dst[o + kn + 1] = ' ';
    memcpy(dst + o + kn + 2, v, vn);
    dst[o + kn + 2 + vn] = '\n'; dst[o + kn + 3 + vn] = '\0';
    return 0;
}

static uint16_t port_of_num(long v) { return (v > 0 && v < 65536) ? (uint16_t)v : 0; }

static int sj_bool(struct sj *j) {
    sj_ws(j);
    if (!strncmp(j->p, "true", 4)) { j->p += 4; return 1; }
    if (!strncmp(j->p, "false", 5)) { j->p += 5; return 0; }
    sj_skip(j);
    return 0;
}

/* Число: либо 123, либо "123". */
static long sj_num(struct sj *j) {
    sj_ws(j);
    char b[24] = "";
    if (*j->p == '"') sj_str(j, b, sizeof b);
    else { size_t i = 0; while (*j->p >= '0' && *j->p <= '9' && i + 1 < sizeof b) b[i++] = *j->p++; b[i] = 0; if (!i) sj_skip(j); }
    return atol(b);
}

struct sb_ws { long ed; char ed_hdr[40]; };

static void sb_tls(struct sj *j, struct vless_node *n, int *enabled, int *reality) {
    int f = 1;
    char k[64];
    while (sj_obj_key(j, &f, k, sizeof k) == 0) {
        if (!strcmp(k, "enabled")) *enabled = sj_bool(j);
        else if (!strcmp(k, "server_name")) sj_str(j, n->sni, sizeof n->sni);
        else if (!strcmp(k, "insecure")) { if (sj_bool(j)) n->allow_insecure = 1; }
        else if (!strcmp(k, "ech")) {
            /* {"enabled": true, "config": ["-----BEGIN ECH CONFIGS-----", "base64…", "-----END ECH CONFIGS-----"]}.
             * Строки PEM склеиваются без рамки; без config (только query_server_name) — запрос из DNS, не поддержан. */
            int f2 = 1, on = 1, have = 0;
            char k2[64], joined[1400] = "";
            size_t jl = 0;
            while (sj_obj_key(j, &f2, k2, sizeof k2) == 0) {
                if (!strcmp(k2, "enabled")) on = sj_bool(j);
                else if (!strcmp(k2, "config")) {
                    int fa = 1;
                    char line[1400];
                    int r = sj_arr_next(j, &fa);          /* < 0 — не массив, а одна строка */
                    do {
                        line[0] = '\0';
                        if (sj_str(j, line, sizeof line) != 0) break;
                        size_t ll = strlen(line);
                        if (line[0] != '-' && jl + ll < sizeof joined) { memcpy(joined + jl, line, ll + 1); jl += ll; have = 1; }
                        r = r < 0 ? 1 : sj_arr_next(j, &fa);
                    } while (r == 0);
                } else sj_skip(j);
            }
            if (on && have) sl_set_ech(n, joined);
            else if (on) n->ech = SL_ECH_DNS;
        }
        else if (!strcmp(k, "certificate_public_key_sha256")) {
            /* Массив строк base64: SHA-256 от SubjectPublicKeyInfo. Строка вместо массива — тоже. */
            char pv[80];
            int fa = 1;
            int r = sj_arr_next(j, &fa);
            if (r == 0) {
                do { pv[0] = '\0'; sj_str(j, pv, sizeof pv); sl_add_pins(n, pv, 1); } while (sj_arr_next(j, &fa) == 0);
            } else if (r < 0) { pv[0] = '\0'; sj_str(j, pv, sizeof pv); sl_add_pins(n, pv, 1); }
        }
        else if (!strcmp(k, "utls")) {
            int f2 = 1, on = 1;
            char k2[64], fp[sizeof n->fp] = "";
            while (sj_obj_key(j, &f2, k2, sizeof k2) == 0) {
                if (!strcmp(k2, "enabled")) on = sj_bool(j);
                else if (!strcmp(k2, "fingerprint")) sj_str(j, fp, sizeof fp);
                else sj_skip(j);
            }
            if (on && fp[0]) snprintf(n->fp, sizeof n->fp, "%s", fp);
        } else if (!strcmp(k, "reality")) {
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof k2) == 0) {
                if (!strcmp(k2, "enabled")) *reality = sj_bool(j);
                else if (!strcmp(k2, "public_key")) sj_str(j, n->pbk, sizeof n->pbk);
                else if (!strcmp(k2, "short_id")) sj_str(j, n->sid, sizeof n->sid);
                else sj_skip(j);
            }
        } else sj_skip(j);
    }
}

static void sb_transport(struct sj *j, struct vless_node *n, struct sb_ws *w, struct upg_cfg *u) {
    int f = 1;
    char k[64];
    while (sj_obj_key(j, &f, k, sizeof k) == 0) {
        if (!strcmp(k, "type")) {
            sj_str(j, n->type, sizeof n->type);
            if (!strcmp(n->type, "websocket")) snprintf(n->type, sizeof n->type, "ws");
        }
        else if (!strcmp(k, "path")) sj_str(j, u->path, sizeof u->path);
        else if (!strcmp(k, "host")) {
            sj_ws(j);
            if (*j->p == '[') { int fa = 1; char h[sizeof u->host]; int got = 0;
                while (sj_arr_next(j, &fa) == 0) { if (got++) sj_skip(j); else sj_str(j, h, sizeof h); }
                if (got) snprintf(u->host, sizeof u->host, "%s", h); }
            else sj_str(j, u->host, sizeof u->host);
        }
        else if (!strcmp(k, "service_name")) sj_str(j, n->service, sizeof n->service);
        else if (!strcmp(k, "max_early_data")) w->ed = sj_num(j);
        else if (!strcmp(k, "early_data_header_name")) sj_str(j, w->ed_hdr, sizeof w->ed_hdr);
        else if (!strcmp(k, "headers")) {
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof k2) == 0) {
                sj_ws(j);
                char v[sizeof u->host] = "";
                if (*j->p == '[') { int fa = 1, got = 0;
                    while (sj_arr_next(j, &fa) == 0) { if (got++) sj_skip(j); else sj_str(j, v, sizeof v); } }
                else if (*j->p == '"') sj_str(j, v, sizeof v);
                else { sj_skip(j); u->bad = 1; continue; }
                if (ci_eq(k2, "host")) { if (!u->host[0]) snprintf(u->host, sizeof u->host, "%s", v); }
                else {
                    if (hdr_append(u->headers, sizeof u->headers, k2, v) != 0) u->bad = 1;
                }
            }
        } else sj_skip(j);
    }
}

/* Один outbound sing-box уже прочитан в поля; здесь — свести в узел. Вызывается из xray_outbound,
 * когда встретился ключ type (у Xray его на этом уровне нет). */
static void sb_outbound_body(struct sj *j, struct vless_node *n, char *proto, size_t proto_n) {
    /* Возврат сюда после первого ключа невозможен: разбор идёт единым проходом в xray_outbound,
     * поэтому функция читает остаток объекта сама. */
    int first = 1, tls_on = 0, reality = 0;
    char k[64];
    struct sb_ws w; struct upg_cfg u;
    memset(&w, 0, sizeof w); memset(&u, 0, sizeof u);
    while (sj_obj_key(j, &first, k, sizeof k) == 0) {
        if (!strcmp(k, "type")) sj_str(j, proto, proto_n);
        else if (!strcmp(k, "tag")) { sj_str(j, n->name, sizeof n->name); sl_utf8_trim_tail(n->name); }
        else if (!strcmp(k, "server")) sj_str(j, n->host, sizeof n->host);
        else if (!strcmp(k, "server_port")) n->port = port_of_num(sj_num(j));
        else if (!strcmp(k, "uuid")) sj_str(j, n->uuid, sizeof n->uuid);
        else if (!strcmp(k, "flow")) sj_str(j, n->flow, sizeof n->flow);
        else if (!strcmp(k, "tls")) sb_tls(j, n, &tls_on, &reality);
        else if (!strcmp(k, "transport")) sb_transport(j, n, &w, &u);
        else sj_skip(j);
    }
    snprintf(n->security, sizeof n->security, "%s", reality ? "reality" : tls_on ? "tls" : "none");
    if (!n->type[0]) snprintf(n->type, sizeof n->type, "tcp");
    if (!strcmp(n->type, "ws") && w.ed > 0 && !strcmp(w.ed_hdr, "Sec-WebSocket-Protocol") && !strchr(u.path, '?')) {
        size_t o = strlen(u.path);
        if (!o) { u.path[0] = '/'; u.path[1] = 0; o = 1; }
        snprintf(u.path + o, sizeof u.path - o, "?ed=%ld", w.ed);
    }
    if (!strcmp(n->type, "ws") || !strcmp(n->type, "httpupgrade")) {
        snprintf(n->path, sizeof n->path, "%s", u.path);
        snprintf(n->http_host, sizeof n->http_host, "%s", u.host);
        snprintf(n->headers, sizeof n->headers, "%s", u.headers);
        n->headers_bad = u.bad;
    }
}

/* Один outbound. 1 — это узел vless и он записан в n, 0 — не наш. */
static int xray_outbound(struct sj *j, struct vless_node *n) {
    memset(n, 0, sizeof(*n));
    /* Умолчание транспорта — tcp, как у ссылки: конфиг без streamSettings или без network
     * законен (так и подразумевает Xray), а пустое слово давало «транспорт  не поддержан». */
    snprintf(n->type, sizeof(n->type), "tcp");
    int first = 1, is_vless = 0;
    char k[64], proto[32] = "";
    /* Какой это формат — Xray (protocol) или sing-box (type)? Предпросмотр ключей верхнего уровня, как
     * у remarks: порядок ключей не задан, а разбор идёт единым проходом. */
    {
        const char *save = j->p;
        int f0 = 1, has_protocol = 0, has_type = 0;
        char k0[64];
        while (sj_obj_key(j, &f0, k0, sizeof k0) == 0) {
            if (!strcmp(k0, "protocol")) has_protocol = 1;
            else if (!strcmp(k0, "type")) has_type = 1;
            sj_skip(j);
        }
        j->p = save;
        if (has_type && !has_protocol) {
            sb_outbound_body(j, n, proto, sizeof proto);
            return !strcmp(proto, "vless");
        }
    }
    /* Порядок ключей в JSON не задан, поэтому protocol может оказаться ПОСЛЕ settings.
     * Значит читаем всё, а решаем в конце: разбор чужого исходящего в свободные поля никому
     * не вредит, потому что узел всё равно не будет взят. */
    while (sj_obj_key(j, &first, k, sizeof(k)) == 0) {
        if (!strcmp(k, "protocol")) sj_str(j, proto, sizeof(proto));
        /* tag из конфигурации Xray обрезается тем же байтовым пределом, что и имя из
         * фрагмента ссылки, — и рвётся так же. */
        else if (!strcmp(k, "tag")) { sj_str(j, n->name, sizeof(n->name)); sl_utf8_trim_tail(n->name); }
        else if (!strcmp(k, "settings")) xray_settings(j, n);
        else if (!strcmp(k, "streamSettings")) xray_stream(j, n);
        else sj_skip(j);
    }
    is_vless = !strcmp(proto, "vless");
    return is_vless;
}

/* Имя, которое панель показала человеку, лежит в remarks КОНФИГА, а не в tag исходящего.
 *
 * Снято на живой панели (ответ клиенту Happ): семь конфигов, у пяти из них tag исходящего —
 * одно и то же слово «proxy», а различает их только remarks («Германия», «Финляндия», …).
 * У остальных двух tag вида «tl-8-1-43al6bgvgg4» — со СЛУЧАЙНЫМ суффиксом, который панель
 * меняет на каждый запрос. То есть на этом формате имя из tag даёт либо пять одинаковых
 * «proxy», либо имя, которое меняется само по себе при каждом обновлении подписки, — и
 * человек в списке узлов splify2 не может ни отличить их друг от друга, ни узнать вчерашний.
 *
 * ПРЕДПРОСМОТР, А НЕ ЧТЕНИЕ ПО ХОДУ. В ответе панели remarks стоит ПОСЛЕ outbounds: пока
 * поток дойдёт до него, узлы уже записаны и переименовывать было бы нечего — указатель
 * назад не отматывается. Поэтому объект конфига сначала пробегается на один только remarks
 * (sj_skip ничего не копирует), а потом разбирается заново с начала. Второго прохода по
 * всему тексту подписки при этом нет: пробег ограничен одним конфигом.
 *
 * Процентная форма здесь НЕ раскрывается, в отличие от имени из #фрагмента ссылки: remarks —
 * поле JSON, и «%2F» в нём означает ровно эти три знака. Тот же довод, что у tag выше. */
static void xray_remarks(struct sj *j, char *out, size_t n) {
    out[0] = '\0';
    const char *save = j->p;
    int first = 1;
    char k[64];
    while (sj_obj_key(j, &first, k, sizeof(k)) == 0) {
        if (!strcmp(k, "remarks")) { sj_str(j, out, n); sl_utf8_trim_tail(out); }
        else sj_skip(j);
    }
    j->p = save;
}

/* Имя узла из remarks конфига. ord — какой это по счёту исходящий vless В ЭТОМ конфиге.
 *
 * Второму и дальше приписывается номер: конфиг с балансировщиком несёт два узла — основной
 * и запасной, — и без номера оба назывались бы одинаково. Номер, а не tag: tag у таких
 * исходящих как раз и есть та случайная строка, от которой имя уводится.
 *
 * Номер в скобках, а не через «#»: панели сами нумеруют узлы решёткой («Мобильная связь #1»),
 * и «Мобильная связь #1 #2» читается как опечатка, а «Мобильная связь #1 (2)» — как второй
 * узел той же строки подписки.
 *
 * Обрезка возможна только у remarks длиной почти в весь буфер имени; тогда номер до имени
 * не доедет и два узла снова совпадут. Это лучше, чем ради номера отрезать человеку имя. */
static void xray_name(struct vless_node *nd, const char *remarks, size_t ord) {
    if (ord == 0) snprintf(nd->name, sizeof(nd->name), "%s", remarks);
    else snprintf(nd->name, sizeof(nd->name), "%s (%zu)", remarks, ord + 1);
    sl_utf8_trim_tail(nd->name);
}

/* Конфиг целиком: массив конфигов или один. Возвращает число ПРИГОДНЫХ узлов. */
static size_t parse_xray(const char *text, struct vless_node *out, size_t max,
                         struct vless_sub_stats *st) {
    struct sj j = { text };
    size_t n = 0;
    sj_ws(&j);
    /* Один конфиг заворачивается в массив из одного: дальше путь общий. */
    int wrapped = (*j.p == '{');
    int fa = 1;
    if (wrapped) fa = 0;                    /* массива нет — сразу разбираем объект */
    for (;;) {
        if (!wrapped) {
            int r = sj_arr_next(&j, &fa);
            if (r != 0) break;
        }
        const char *cfg_before = j.p;
        /* Тело одного конфига: узлы — из outbounds, имя им — из remarks (xray_remarks). */
        char remarks[sizeof(((struct vless_node *)0)->name)];
        xray_remarks(&j, remarks, sizeof(remarks));
        size_t ord = 0;
        int fc = 1;
        char k[64];
        int seen_ob = 0;
        while (sj_obj_key(&j, &fc, k, sizeof(k)) == 0) {
            if (strcmp(k, "outbounds") != 0) { sj_skip(&j); continue; }
            seen_ob = 1;
            int fo = 1;
            while (sj_arr_next(&j, &fo) == 0) {
                struct vless_node node;
                const char *before = j.p;
                int ours = xray_outbound(&j, &node);
                if (j.p == before) break;               /* разбор не двинулся — уходим */
                if (!ours) continue;
                /* До проверки пригодности: имя уходит и в список узлов, и в объяснение
                 * пропуска (sl_skip_note берёт его как пример), а человеку в обоих местах
                 * нужно одно и то же слово — то, которое он видит в панели. */
                if (remarks[0]) xray_name(&node, remarks, ord);
                ord++;
                if (n >= max) {
                    /* Мест больше нет. Считаем как пропущенный, а не теряем молча: то же
                     * обещание, что у списка ссылок — арифметика обязана сходиться. */
                    sl_skip_note(st, &node, "узлов больше, чем помещается");
                    continue;
                }
                if (node_usable(&node) == 0) out[n++] = node;
                else sl_skip_note(st, &node, node.skip_reason);
            }
        }
        (void)seen_ob;
        if (wrapped) break;
        if (j.p == cfg_before) break;                   /* конфиг не разобрался — не крутимся */
    }
    return n;
}

/* ---- Clash / Mihomo: proxies с type: vless -------------------------------------------------------
 *
 * Панели отдают клиентам Clash YAML: список `proxies:`, у каждого узла плоский набор ключей и вложенные
 * *-opts (ws-opts, reality-opts, grpc-opts, xhttp-opts). Записаны бывают двумя способами — блоком
 * (`- name: x` и ключи с отступом) и потоком (`- {name: x, type: vless, reality-opts: {public-key: k}}`,
 * так пишут конвертеры), и разбор обязан уметь оба.
 *
 * Общий YAML-разбор (src/lib/ynode.c) здесь не берётся: он отказывает на якорях и алиасах целиком, а
 * подписка с якорем в блоке proxy-groups не должна терять узлы; и он тянет libyaml в стенд, который
 * проверяет чужой текст в одиночку. Вместо него — разбор ровно той формы, которую ждём: каждый узел
 * «сплющивается» в пары путь=значение (`reality-opts.public-key`, `ws-opts.headers.Host`, `alpn.0`), а
 * узел строится по путям. Что не разобралось (якорь-алиас `*a`, многострочные скаляры) — значение
 * пропускается, узел получает то, что удалось. Якоря `&a` перед значением отбрасываются. */
#define YF_MAX 96
struct yflat {
    char buf[12288];
    size_t used, n;
    struct { const char *k, *v; } kv[YF_MAX];
};

static void yf_add(struct yflat *f, const char *path, size_t pn, const char *val, size_t vn) {
    if (f->n >= YF_MAX || f->used + pn + vn + 2 > sizeof f->buf) return;
    char *k = f->buf + f->used;
    memcpy(k, path, pn); k[pn] = 0;
    char *v = k + pn + 1;
    memcpy(v, val, vn); v[vn] = 0;
    f->used += pn + vn + 2;
    f->kv[f->n].k = k; f->kv[f->n].v = v; f->n++;
}

static const char *yf_get(const struct yflat *f, const char *path) {
    for (size_t i = 0; i < f->n; i++) if (!strcmp(f->kv[i].k, path)) return f->kv[i].v;
    return NULL;
}
/* Без учёта регистра: Host/host в headers. */
static const char *yf_geti(const struct yflat *f, const char *path) {
    for (size_t i = 0; i < f->n; i++) if (ci_eq(f->kv[i].k, path)) return f->kv[i].v;
    return NULL;
}

/* Скаляр с p: в кавычках или простой. flow != 0 — простой кончается на , } ]. Возвращает указатель за
 * скаляром; значение — в out (раскавыченное), длина в *on. */
static const char *y_scalar(const char *p, const char *end, int flow, char *out, size_t cap, size_t *on) {
    size_t o = 0;
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    /* Якорь/тег перед значением. */
    while (p < end && (*p == '&' || *p == '!')) { while (p < end && *p != ' ' && *p != '\t') p++; while (p < end && (*p == ' ' || *p == '\t')) p++; }
    if (p < end && (*p == '"' || *p == '\'')) {
        char q = *p++;
        while (p < end && *p != q) {
            if (q == '"' && *p == '\\' && p + 1 < end) p++;
            else if (q == '\'' && *p == '\'' && p + 1 < end && p[1] == '\'') p++;
            if (o + 1 < cap) out[o++] = *p;
            p++;
        }
        if (p < end) p++;
    } else {
        const char *st0 = p;
        while (p < end && *p != '\n' && *p != '\r') {
            if (flow && (*p == ',' || *p == '}' || *p == ']')) break;
            /* flow == 2 — ключ: кончается на «:» с пробелом (или концом) следом. */
            if (flow == 2 && *p == ':' && (p + 1 >= end || p[1] == ' ' || p[1] == '\n' || p[1] == '\r')) break;
            if (*p == '#' && p > st0 && (p[-1] == ' ' || p[-1] == '\t')) break;
            if (o + 1 < cap) out[o++] = *p;
            p++;
        }
        while (o && (out[o - 1] == ' ' || out[o - 1] == '\t')) o--;
    }
    out[o] = 0;
    *on = o;
    return p;
}

static const char *y_flow(struct yflat *f, const char *p, const char *end, char *path, size_t pn, int depth);

/* Значение в потоковой записи: {…}, […] или скаляр. */
static const char *y_flow_val(struct yflat *f, const char *p, const char *end, char *path, size_t pn, int depth) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    if (p < end && (*p == '{' || *p == '[')) return y_flow(f, p, end, path, pn, depth + 1);
    char v[3300];
    size_t vn;
    p = y_scalar(p, end, 1, v, sizeof v, &vn);
    if (v[0] != '*') yf_add(f, path, pn, v, vn);
    return p;
}

static const char *y_flow(struct yflat *f, const char *p, const char *end, char *path, size_t pn, int depth) {
    if (depth > 6 || p >= end) return end;
    char open = *p++;
    unsigned idx = 0;
    for (;;) {
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',')) p++;
        if (p >= end) return end;
        if (*p == '}' || *p == ']') return p + 1;
        char np[200];
        size_t npn;
        if (open == '{') {
            char key[96];
            size_t kn;
            p = y_scalar(p, end, 2, key, sizeof key, &kn);
            while (p < end && (*p == ' ' || *p == '\t')) p++;
            if (p < end && *p == ':') p++;
            npn = (size_t)snprintf(np, sizeof np, "%.*s%s%s", (int)pn, path, pn ? "." : "", key);
        } else {
            npn = (size_t)snprintf(np, sizeof np, "%.*s%s%u", (int)pn, path, pn ? "." : "", idx++);
        }
        if (npn >= sizeof np) npn = sizeof np - 1;
        p = y_flow_val(f, p, end, np, npn, depth);
    }
}

/* Строка блока: отступ и текст без него. */
static const char *y_line(const char *p, const char *end, size_t *ind, const char **e) {
    size_t i = 0;
    while (p + i < end && p[i] == ' ') i++;
    const char *s = p + i, *q = s;
    while (q < end && *q != '\n') q++;
    *ind = i;
    *e = q;
    return s;
}

/* Один узел блока: p — начало строки «- …» (отступ dash); результат — начало строки после узла. */
static const char *y_item(struct yflat *f, const char *p, const char *end, size_t dash) {
    struct lvl { size_t ind; char path[200]; } st[6];
    int sp = 1, first = 1;
    st[0].ind = 0; st[0].path[0] = 0;
    char lastkey[200] = "";
    unsigned seq = 0;
    while (p < end) {
        size_t ind;
        const char *e;
        const char *s = y_line(p, end, &ind, &e);
        const char *next = e < end ? e + 1 : e;
        if (e > s && e[-1] == '\r') e--;
        if (s >= e || *s == '#' || (e - s >= 3 && !strncmp(s, "---", 3))) { p = next; continue; }
        if (first) {
            first = 0;
            s += 1; ind += 1;                                   /* тире */
            while (s < e && *s == ' ') { s++; ind++; }
            if (s < e && *s == '{') {
                char none[1] = "";
                y_flow(f, s, end, none, 0, 0);
                int d = 0;
                const char *q = s;
                for (; q < end; q++) { if (*q == '{') d++; else if (*q == '}' && --d == 0) break; }
                while (q < end && *q != '\n') q++;
                return q < end ? q + 1 : q;
            }
        } else if (ind <= dash) {
            if (!(ind == dash && 0)) return p;
        }
        if (!first && ind > dash && (*s == '-' && (e - s == 1 || s[1] == ' '))) {
            char v[3300];
            size_t vn;
            y_scalar(s + 1, e, 0, v, sizeof v, &vn);
            char np[200];
            int n2 = snprintf(np, sizeof np, "%s.%u", lastkey, seq++);
            if (lastkey[0] && n2 > 0 && n2 < (int)sizeof np && v[0] != '*') yf_add(f, np, (size_t)n2, v, vn);
            p = next;
            continue;
        }
        while (sp > 1 && st[sp - 1].ind >= ind) sp--;
        char key[96];
        size_t kn;
        const char *c = y_scalar(s, e, 2, key, sizeof key, &kn);
        while (c < e && (*c == ' ' || *c == '\t')) c++;
        if (c >= e || *c != ':') { p = next; continue; }
        c++;
        char np[200];
        int n2 = snprintf(np, sizeof np, "%s%s%s", st[sp - 1].path, st[sp - 1].path[0] ? "." : "", key);
        if (n2 <= 0 || n2 >= (int)sizeof np) { p = next; continue; }
        while (c < e && (*c == ' ' || *c == '\t')) c++;
        if (c >= e || *c == '#') {
            snprintf(lastkey, sizeof lastkey, "%s", np);
            seq = 0;
            if (sp < 6) { st[sp].ind = ind; snprintf(st[sp].path, sizeof st[sp].path, "%s", np); sp++; }
        } else if (*c == '{' || *c == '[') {
            y_flow(f, c, end, np, (size_t)n2, 0);
        } else {
            char v[3300];
            size_t vn;
            y_scalar(c, e, 0, v, sizeof v, &vn);
            if (v[0] != '*') yf_add(f, np, (size_t)n2, v, vn);
        }
        p = next;
    }
    return p;
}

/* Плоский узел → узел vless. 1 — это vless и он записан в n. */
static int clash_node(const struct yflat *f, struct vless_node *n) {
    memset(n, 0, sizeof *n);
    const char *v;
    if (!(v = yf_get(f, "type")) || strcmp(v, "vless")) return 0;
    snprintf(n->type, sizeof n->type, "tcp");
    if ((v = yf_get(f, "name"))) { sl_set_field(n->name, sizeof n->name, v, strlen(v)); sl_utf8_trim_tail(n->name); }
    if ((v = yf_get(f, "server"))) sl_set_field(n->host, sizeof n->host, v, strlen(v));
    if ((v = yf_get(f, "port"))) n->port = sl_port_of(v);
    if ((v = yf_get(f, "uuid"))) sl_set_field(n->uuid, sizeof n->uuid, v, strlen(v));
    if ((v = yf_get(f, "flow"))) sl_set_field(n->flow, sizeof n->flow, v, strlen(v));
    if ((v = yf_get(f, "servername")) || (v = yf_get(f, "sni"))) sl_set_field(n->sni, sizeof n->sni, v, strlen(v));
    if ((v = yf_get(f, "client-fingerprint"))) sl_set_field(n->fp, sizeof n->fp, v, strlen(v));
    /* Clash/mihomo: `fingerprint` — SHA-256 сертификата узла (то же, что pinnedPeerCertSha256 Xray),
     * `skip-cert-verify` — allowInsecure. */
    if ((v = yf_get(f, "fingerprint")) && v[0]) sl_add_pins(n, v, 0);
    if ((v = yf_get(f, "skip-cert-verify")) && sl_truthy(v)) n->allow_insecure = 1;
    if ((v = yf_get(f, "ech-opts.config")) && v[0]) sl_set_ech(n, v);
    const char *pbk = yf_get(f, "reality-opts.public-key");
    if (pbk) {
        sl_set_field(n->pbk, sizeof n->pbk, pbk, strlen(pbk));
        if ((v = yf_get(f, "reality-opts.short-id"))) sl_set_field(n->sid, sizeof n->sid, v, strlen(v));
        if ((v = yf_get(f, "reality-opts.mldsa65-verify")) || (v = yf_get(f, "reality-opts.pqv"))) sl_set_pqv(n, v);
        snprintf(n->security, sizeof n->security, "reality");
    } else {
        v = yf_get(f, "tls");
        snprintf(n->security, sizeof n->security, "%s", v && (!strcmp(v, "true") || !strcmp(v, "True")) ? "tls" : "none");
    }
    if ((v = yf_get(f, "encryption"))) set_encryption(n, v);
    const char *net = yf_get(f, "network");
    if (net) {
        if (!strcmp(net, "raw")) net = "tcp";
        sl_set_field(n->type, sizeof n->type, net, strlen(net));
    }
    const char *upg = yf_get(f, "ws-opts.v2ray-http-upgrade");
    if (!strcmp(n->type, "ws") && upg && !strcmp(upg, "true")) snprintf(n->type, sizeof n->type, "httpupgrade");
    if (!strcmp(n->type, "ws") || !strcmp(n->type, "httpupgrade")) {
        struct upg_cfg u;
        memset(&u, 0, sizeof u);
        if ((v = yf_get(f, "ws-opts.path"))) sl_set_field(u.path, sizeof u.path, v, strlen(v));
        if ((v = yf_geti(f, "ws-opts.headers.host"))) sl_set_field(u.host, sizeof u.host, v, strlen(v));
        for (size_t i = 0; i < f->n; i++) {
            const char *k = f->kv[i].k;
            if (strncmp(k, "ws-opts.headers.", 16) != 0 || ci_eq(k + 16, "host")) continue;
            if (hdr_append(u.headers, sizeof u.headers, k + 16, f->kv[i].v) != 0) u.bad = 1;
        }
        const char *ed = yf_get(f, "ws-opts.max-early-data"), *eh = yf_get(f, "ws-opts.early-data-header-name");
        if (ed && atol(ed) > 0 && eh && !strcmp(eh, "Sec-WebSocket-Protocol") && !strchr(u.path, '?')) {
            size_t o = strlen(u.path);
            if (!o) { u.path[0] = '/'; u.path[1] = 0; o = 1; }
            snprintf(u.path + o, sizeof u.path - o, "?ed=%ld", atol(ed));
        }
        snprintf(n->path, sizeof n->path, "%s", u.path);
        snprintf(n->http_host, sizeof n->http_host, "%s", u.host);
        snprintf(n->headers, sizeof n->headers, "%s", u.headers);
        n->headers_bad = u.bad;
    } else if (!strcmp(n->type, "grpc")) {
        if ((v = yf_get(f, "grpc-opts.grpc-service-name"))) sl_set_field(n->service, sizeof n->service, v, strlen(v));
    } else if (!strcmp(n->type, "xhttp")) {
        if ((v = yf_get(f, "xhttp-opts.path"))) sl_set_field(n->path, sizeof n->path, v, strlen(v));
        if ((v = yf_get(f, "xhttp-opts.mode"))) sl_set_field(n->mode, sizeof n->mode, v, strlen(v));
        if ((v = yf_get(f, "xhttp-opts.x-padding-bytes"))) sl_pad_range(n, v);
    }
    return 1;
}

/* Clash YAML целиком. Возвращает число пригодных узлов; foreign — узлы других протоколов (в st). */
static size_t parse_clash(const char *text, struct vless_node *out, size_t max, struct vless_sub_stats *st) {
    const char *end = text + strlen(text), *p = text;
    size_t n = 0, dash = 0;
    int in_list = 0;
    struct yflat *f = malloc(sizeof *f);
    if (!f) return 0;
    while (p < end) {
        size_t ind;
        const char *e;
        const char *s = y_line(p, end, &ind, &e);
        const char *next = e < end ? e + 1 : e;
        if (!in_list) {
            if (ind == 0 && (!strncmp(s, "proxies:", 8) || !strncmp(s, "Proxy:", 6))) {
                const char *c = s + (s[0] == 'p' ? 8 : 6);
                while (c < e && *c == ' ') c++;
                if (c < e && *c != '#') break;                 /* «proxies: []» и т.п.: узлов нет */
                in_list = 1;
                dash = (size_t)-1;
            }
            p = next;
            continue;
        }
        if (s >= e || *s == '#') { p = next; continue; }
        if (ind == 0 && *s != '-') break;                     /* следующий ключ верхнего уровня */
        if (*s == '-' && (s + 1 == e || s[1] == ' ')) {
            if (dash == (size_t)-1) dash = ind;
            if (ind != dash) { p = next; continue; }
            f->n = 0; f->used = 0;
            p = y_item(f, p, end, dash);
            struct vless_node node;
            if (!clash_node(f, &node)) { if (st) st->foreign++; continue; }
            if (n >= max) { sl_skip_note(st, &node, "узлов больше, чем помещается"); continue; }
            if (node_usable(&node) == 0) out[n++] = node;
            else sl_skip_note(st, &node, node.skip_reason);
            continue;
        }
        p = next;
    }
    free(f);
    return n;
}

/* Это Clash YAML? В любой строке верхнего уровня стоит «proxies:» (или «Proxy:» — прежнее имя). Список
 * ссылок и base64 такой строки не содержат: в base64 нет двоеточия. */
static int looks_clash(const char *t) {
    for (const char *p = t; *p; ) {
        if (!strncmp(p, "proxies:", 8) || !strncmp(p, "Proxy:", 6)) return 1;
        const char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

/* Предел длины ОДНОЙ ссылки подписки.
 *
 * Было 2048, и этого перестало хватать. Reality с постквантовой подписью (Xray-core 25.9+)
 * кладёт в ссылку параметр `pqv` — ПУБЛИЧНЫЙ КЛЮЧ ML-DSA-65 целиком, в base64url. Ключ
 * весит 1952 байта, в base64url это ровно 2603 знака, и вся ссылка выходит 2860 байт —
 * столько и снято на живой подписке. Подписка из одной такой ссылки давала «пригодных
 * узлов: 0» и объяснение «ссылка длиннее 2048 байт», то есть выход собрать было не из чего,
 * притом что сама подписка скачивалась и была верна.
 *
 * ЭТО ПОДПИСЬ, А НЕ ОБМЕН КЛЮЧАМИ, и путать их дорого: постквантовый обмен у Reality идёт
 * группой X25519MLKEM768 в key_share (см. reality.h), а `pqv` — совсем про другое: им
 * сервер дополнительно подписывает свой временный сертификат, и проверяет эту подпись
 * клиент: reality.c включает проверку, когда параметр задан (tls13.c → cert_reality_check_pq). Ключ
 * хранится в общей таблице (sl_intern).
 *
 * 8192, а не 4096: запас взят на вырост ключа (у ML-DSA-87 он 2592 байта, то есть 3456
 * знаков), а буфер живёт на стеке ОДНОЙ подкоманды CLI, рядом с которой уже стоят два
 * статических буфера по 256 КБ под текст подписки, — восемь килобайт здесь ничего не
 * решают. Разбор в рабочих потоках туннеля (стек 128 КБ) этот путь не проходит. */
#define SUB_LINE_MAX 8192

/* Знак, из которых состоит имя схемы: `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`
 * (RFC 3986 §3.1), с поправкой на то, что подписки пишут схемы строчными. */
static int scheme_ch(char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '+' || c == '.' || c == '-';
}

/* Приклеенная без разделителя ссылка, схемы которой мы не знаем. Возвращает место самого
 * «://» приклеенной ссылки либо NULL.
 *
 * ЗАЧЕМ ЭТО ОТДЕЛЬНО ОТ РАЗДЕЛИТЕЛЯ ВЫШЕ. Разделитель отступает к началу следующей ссылки
 * по ИМЕНИ схемы из закрытого списка, и там это единственно верный способ: на паре
 * «…#one» + «vless://…» общее правило по форме отступило бы к началу «onevless» — имя,
 * правильное по форме, — и вторая ссылка перестала бы быть ссылкой vless. Список эту
 * двусмысленность решает знанием, и отбирать у него эту работу нельзя.
 *
 * Но когда список не нашёл ничего, пара всё равно склеена — просто мы не знаем, где
 * граница. Тогда единственный честный ответ не «поделим как-нибудь», а «назовём вслух»:
 * узел объявляется непригодным с причиной, в которой стоит схема приклеенной ссылки.
 * Прежде первый узел приезжал в интерфейс с чужим хвостом вместо имени, а второй исчезал,
 * не попав ни в один счётчик, и ни одно число при этом не расходилось — одна ссылка, один
 * узел (I-208, воспроизводит журнал steer#2; владелец согласился на «Б+В» в splicicd#23).
 *
 * СХЕМА ПРИ ЭТОМ НЕ НАЗЫВАЕТСЯ, И ЭТО НЕ СКРОМНОСТЬ. Назвать её по форме нельзя: отступ от
 * «://» по знакам схемы на «…#oneanytls://…» даёт «oneanytls», и сказать человеку «склейка
 * с oneanytls://» значило бы соврать с уверенным видом. Ровно та же двусмысленность, из-за
 * которой список схем и существует. Поэтому наружу идёт то, что известно точно: длина
 * хвоста и его первые байты — по ним место склейки находится в тексте подписки, а имя
 * протокола человек прочтёт там сам.
 *
 * ВТОРОЙ ПРИЗНАК — `@` В ПРИКЛЕЕННОЙ ССЫЛКЕ, и без него правило было бы вредным. Продавцы
 * пишут в имя узла адрес своего канала («#канал https://t.me/shop»), и по одной только
 * форме схемы такой узел объявлялся бы непригодным — то есть общее правило отняло бы
 * рабочие узлы у тех, у кого сегодня всё в порядке. Ссылка прокси несёт учётные данные
 * перед хостом, адрес канала — нет; этим они и различаются. Ссылки без `@` (vmess как
 * base64, ss в старой форме) в списке схем есть, значит сюда не доходят.
 *
 * Ищется ПЕРВОЕ вхождение: если склеек больше одной, назвать надо ту, что ближе к началу,
 * — с неё и потерялось. */
static const char *glued_tail(const char *b, const char *e) {
    for (const char *q = b + 1; q + 3 <= e; q++) {
        if (strncmp(q, "://", 3) != 0) continue;
        const char *sc = q;
        while (sc > b && scheme_ch(sc[-1])) sc--;
        /* Дошли до начала ссылки — это схема САМОЙ ссылки, делить нечего. */
        if (sc == b) continue;
        size_t sl = (size_t)(q - sc);
        /* Не короче двух знаков и не длиннее пятнадцати: односложное «x://» скорее
         * случайность в имени узла, чем протокол, а имён схем длиннее пятнадцати у
         * прокси не бывает. Первый знак — буква, как требует RFC 3986. */
        if (sl < 2 || sl > 15 || sc[0] < 'a' || sc[0] > 'z') continue;
        int creds = 0;
        for (const char *t = q + 3; t < e && *t != '#'; t++)
            if (*t == '@') { creds = 1; break; }
        if (!creds) continue;
        return q;
    }
    return NULL;
}

/* Одна запись о склейке. Границей служит e, а не терминатор: в ветке длины ссылка в буфер
 * не копируется, а сказать про склейку надо и там — иначе неразделённая пара и настоящая
 * длинная ссылка дают ОДИН журнал («ссылка длиннее 8191 байт»), то есть один симптом на
 * две разные починки. Ровно это и стоит второй половиной обращения steer#2. */
static void glue_note(struct vless_sub_stats *st, const char *glue, const char *e) {
    size_t tail = (size_t)(e - glue);
    size_t show = tail < 32 ? tail : 32;
    struct vless_node t;
    memset(&t, 0, sizeof t);
    snprintf(t.name, sizeof t.name, "хвост %zu байт: %.*s", tail, (int)show, glue);
    sl_skip_note(st, &t, "ссылки склеены без разделителя");
}

/* Разобрать текст подписки (уже декодированный из base64) в массив узлов.
 * Возвращает число ПРИГОДНЫХ; остальное — в st (может быть NULL). */
size_t vless_parse_sub(const char *text, struct vless_node *out, size_t max,
                       struct vless_sub_stats *st) {
    size_t n = 0;
    if (st) memset(st, 0, sizeof(*st));
    const char *p = text;
    /* Форма определяется ПЕРВЫМ непробельным знаком, а не поиском подстроки: '[' или '{'
     * бывает только у JSON, а список ссылок с них не начинается никогда. Прежнее правило в
     * tunnel.c искало «://» и на конфиге Xray срабатывало случайно — там «https://» лежит
     * внутри настроек DNS. Случайность в распознавании чужого формата — это отказ, который
     * появится ровно тогда, когда панель уберёт одну строчку из своего конфига. */
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p == '[' || *p == '{') return parse_xray(p, out, max, st);
    if (looks_clash(p)) return parse_clash(p, out, max, st);
    while (*p) {
        while (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t') p++;
        if (!*p) break;
        /* Конец ссылки — перевод строки ИЛИ начало следующей схемы. Подписки часто
         * приходят без завершающего перевода, а некоторые панели склеивают ссылки без
         * разделителя вовсе; при разборе только по переводу последняя ссылка тогда
         * склеивалась со следующей и терялась молча. */
        const char *e = p;
        while (*e && *e != '\n' && *e != '\r') {
            if (e > p && !strncmp(e, "://", 3)) {
                /* Отступаем к началу схемы — по ИМЕНИ СХЕМЫ, а не по алфавиту.
                 *
                 * Отступ по алфавиту («пока слева буквы и цифры») съедал хвост имени
                 * узла: в «...#onevless://b@...» он уходил до самого '#', граница
                 * ставилась перед «onevless», и вторая ссылка начиналась со лишних
                 * букв — то есть переставала быть vless-ссылкой и уходила в чужие
                 * протоколы. На склеенной подписке так терялся КАЖДЫЙ второй узел,
                 * а первому обнулялось имя. Условие срабатывало почти всегда: имена
                 * узлов кончаются буквой или цифрой чаще, чем нет.
                 *
                 * Список отсортирован по УБЫВАНИЮ длины, и берётся первое совпадение —
                 * то есть самое длинное. Короткое имя схемы обязано проигрывать
                 * длинному, иначе граница встаёт внутри чужого слова: «ss» совпадает
                 * с хвостом самого «vless», и разбор рубил бы каждую ссылку по её же
                 * собственной схеме. По той же причине после самого длинного совпадения
                 * к более коротким не переходим: если оно указывает на начало ЭТОЙ
                 * ссылки, делить нечего.
                 *
                 * Имя узла, оканчивающееся именем схемы («...#Express» перед «ss://»),
                 * разделится верно: сравниваются ровно байты перед «://». */
                static const char *const schemes[] = {
                    "hysteria2", "wireguard", "hysteria", "trojan", "vmess",
                    "vless", "tuic", "hy2", "ssr", "ss"
                };
                const char *s2 = NULL;
                for (size_t si = 0; si < sizeof(schemes) / sizeof(*schemes); si++) {
                    size_t sl = strlen(schemes[si]);
                    if ((size_t)(e - p) < sl) continue;
                    if (strncmp(e - sl, schemes[si], sl) != 0) continue;
                    /* Строго больше: равенство означает схему САМОЙ этой ссылки. */
                    if ((size_t)(e - p) > sl) s2 = e - sl;
                    break;
                }
                if (s2) { e = s2; break; }
            }
            e++;
        }

        char line[SUB_LINE_MAX];
        size_t len = (size_t)(e - p);
        if (len >= sizeof(line)) {
            /* Ссылка длиннее буфера. Считается непригодной, а не пропадает: см. ниже —
             * счётчики обязаны сходиться с числом ссылок в тексте.
             *
             * Предел назван ЧИСЛОМ ИЗ БУФЕРА, а не переписан в строке: прежде здесь стояло
             * «длиннее 2048 байт» словами, и предел с сообщением разошлись бы при первой же
             * правке буфера — человек читал бы про 2048 там, где отказали на 8192. */
            char why[64];
            snprintf(why, sizeof why, "ссылка длиннее %zu байт", sizeof(line) - 1);
            const char *glue = strncmp(p, "vless://", 8) ? NULL : glued_tail(p, e);
            if (glue) {
                /* Склейка называется РАНЬШЕ длины: длина здесь следствие, а не причина, и
                 * человеку, у которого панель не поставила разделитель, «ссылка длиннее
                 * 8191 байт» не говорит ничего о том, что делать. */
                glue_note(st, glue, e);
            } else if (!strncmp(p, "vless://", 8)) {
                /* Пример — длина и начало адреса узла (I-209). Одна причина без измерения
                 * не отличает ссылку чуть длиннее предела (поднимать предел) от блоба на
                 * десятки килобайт (искать разделитель), а sl_skip_note схлопывает причины по
                 * тексту, так что измерению место только здесь. Начало — после '@': до
                 * него идентификатор, которому в журнале, уезжающем в трекер, не место. */
                const char *at = memchr(p, '@', len);
                const char *from = at ? at + 1 : p;
                size_t rest = (size_t)(e - from);
                struct vless_node t;
                memset(&t, 0, sizeof t);
                snprintf(t.name, sizeof t.name, "%zu байт: %s%.*s", len, at ? "…@" : "",
                         (int)(rest < 32 ? rest : 32), from);
                sl_skip_note(st, &t, why);
            }
            /* ЧУЖОЙ ПРОТОКОЛ ЗДЕСЬ ТОЖЕ СЧИТАЕТСЯ. Короткую ссылку hy2/ss/trojan ветка ниже
             * учитывает в foreign — именно затем, чтобы расхождение «26 узлов в подписке, 17
             * у steer» объяснялось числом. Длиннее буфера такая ссылка не считалась нигде, и
             * арифметика (usable + skipped + foreign) не сходилась ровно на самом неожиданном
             * тексте подписки. Признак тот же, что у короткой («есть „://“»), только границу
             * даёт e, а не терминатор: строка здесь не копировалась в буфер. */
            else if (st) {
                for (const char *q = p; q + 3 <= e; q++)
                    if (!strncmp(q, "://", 3)) { st->foreign++; break; }
            }
        } else {
            memcpy(line, p, len);
            line[len] = '\0';
            /* Причина одна на все склейки — это один класс поломки подписки, и
             * группировать его по узлам незачем; всё, что различает случаи, уходит в
             * пример. Разбирать такую ссылку не пробуем вовсе: имя узла у неё заведомо
             * чужое, а адрес — может быть, и «может быть» здесь хуже честного отказа. */
            const char *glue = strncmp(line, "vless://", 8)
                                   ? NULL : glued_tail(line, line + len);
            if (glue) {
                glue_note(st, glue, line + len);
            } else if (!strncmp(line, "vless://", 8)) {
                struct vless_node node;
                int rc = vless_parse_url(line, &node);
                /* rc == 0 — узел взят; иначе НЕ ВЗЯТ, и для счётчика это одно и то
                 * же — узел, которого человек в списке не увидит, — а для объяснения
                 * разное: у «транспорт не поддержан» (1) причина уже названа разбором,
                 * у «ссылку не разобрали» (-1) её приходится называть здесь, потому
                 * что разбор бросил ссылку раньше, чем добрался до пригодности.
                 * Раньше -1 не считался нигде, и ссылка исчезала бесследно —
                 * так пропадал, например, узел с IPv6-литералом в host: первое
                 * двоеточие оказывается внутри скобок, порт читается как 0, разбор
                 * возвращает -1. Заголовок этого файла обещает обратное: «в ней 26
                 * узлов, а steer видит 17» должно объясняться цифрой. */
                /* Мест больше нет — считаем как пропущенный, а не бросаем остаток текста
                 * непрочитанным: то же обещание, что у конфига Xray, — арифметика
                 * usable + skipped + foreign обязана сходиться с числом ссылок. */
                if (rc == 0 && n < max) out[n++] = node;
                else if (rc == 0) sl_skip_note(st, &node, "узлов больше, чем помещается");
                else sl_skip_note(st, &node, rc > 0 ? node.skip_reason
                                                 : "ссылка не разобрана");
            } else if (strstr(line, "://") && st) {
                /* hy2, ss, trojan и прочее. Считаем, но не трогаем: подписка общая, а
                 * «26 узлов в подписке, 17 у steer» должно объясняться числом. */
                st->foreign++;
            }
        }
        p = e;
    }
    return n;
}

/* Привести прочитанный файл подписки к тексту, который понимает vless_parse_sub.
 *
 * Три вида, и различаются они первым непробельным знаком, а не догадкой:
 *   '[' или '{'  — конфиг Xray в JSON, отдаётся как есть;
 *   есть «://»   — список ссылок, отдаётся как есть;
 *   иначе        — base64, раскодируется в dec.
 *
 * Раньше это решение жило в tunnel.c одной строкой `if (!strstr(raw, "://"))`, и на конфиге
 * Xray оно срабатывало ПО СЛУЧАЙНОСТИ: «://» там есть внутри настроек DNS. Здесь оно потому,
 * что здесь его можно проверить стендом — туннель требует и сети, и TUN, и TLS.
 *
 * Возвращает raw или dec; ни то, ни другое не освобождается — буферы вызывающего. */
const char *vless_sub_text(const char *raw, size_t raw_n, char *dec, size_t dec_n) {
    const char *p = raw;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p == '[' || *p == '{') return raw;
    if (looks_clash(p)) return raw;
    if (strstr(raw, "://")) return raw;
    b64_decode(raw, raw_n, dec, dec_n);
    return dec;
}

/* Подписка из файла целиком: буферы и массив узлов — в куче по размеру файла и числу узлов в нём.
 * Раньше буферы были статикой в 256 КиБ, а узлов — 128 (статика в 157 КБ): подписка длиннее
 * теряла хвост, узлов больше — «не помещаются». Мест под узлы столько, сколько в тексте ссылок
 * («://») и объектов Xray («"protocol"») — верхняя граница числа узлов; остаток арифметики
 * (usable + skipped + foreign) сходится, как и прежде. Потолок файла — 64 МиБ: защита от файла-
 * не-подписки под этим именем, а не размер подписки (тысяча узлов — сотни килобайт).
 * NULL — файл не открылся, слишком велик или нет памяти; иначе массив (free), *cnt — узлов. */
#define VLESS_SUB_FILE_MAX ((size_t)64 << 20)
struct vless_node *vless_load_sub(const char *path, size_t *cnt, struct vless_sub_stats *st) {
    *cnt = 0;
    if (st) memset(st, 0, sizeof(*st));
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long fl = ftell(f);
    rewind(f);
    if (fl < 0 || (size_t)fl > VLESS_SUB_FILE_MAX) { fclose(f); return NULL; }
    size_t sz = (size_t)fl;
    char *raw = malloc(sz + 1), *dec = malloc(sz + 16);
    if (!raw || !dec) { fclose(f); free(raw); free(dec); return NULL; }
    size_t n = fread(raw, 1, sz, f);
    fclose(f);
    raw[n] = '\0';
    dec[0] = '\0';
    const char *text = vless_sub_text(raw, n, dec, sz + 16);
    size_t hint = 1;
    for (const char *q = text; (q = strstr(q, "://")); q += 3) hint++;
    for (const char *q = text; (q = strstr(q, "\"protocol\"")); q += 10) hint++;
    struct vless_node *nodes = calloc(hint, sizeof(*nodes));
    if (nodes) *cnt = vless_parse_sub(text, nodes, hint, st);
    free(raw);
    free(dec);
    return nodes;
}
