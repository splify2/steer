/* Ссылка узла в форме Xray: строки ссылки и поля транспорта (sublink.c).
 *
 * Вынесено из разбора подписки VLESS (sub.c), когда тем же полям понадобился второй хозяин — модуль
 * steer-proxy (src/proto/proxy): ссылка trojan:// и JSON vmess:// несут ровно те же поля транспорта и
 * безопасности, что vless:// (type, security, sni, fp, pbk, sid, path, host, serviceName, mode,
 * extra, pcs, vcn, ech, allowInsecure, pqv, headerType), и годность их обязана решаться одним
 * правилом: узел, пригодный у одного протокола и непригодный с тем же транспортом у другого, —
 * это два правила, которые разойдутся. Поэтому файл живёт в libsteer и общий у модулей steer-vless
 * и steer-proxy, как общий у них сам транспорт (src/proto/transport).
 *
 * Узел — struct vless_node: его половина транспорта и безопасности здесь, а VLESS-своё (flow,
 * encryption, UUID) разбирает и проверяет sub.c. Чего здесь нет — подписок целиком (список ссылок,
 * конфиги Xray и sing-box, YAML Clash): это знание VLESS, оно осталось в sub.c.
 *
 * Ни сети, ни криптографии: стенды подписки собирают файл без библиотек. */
#ifndef STEER_SUBLINK_H
#define STEER_SUBLINK_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "vless.h"
#include "transport.h"

/* ---- строки ссылки -------------------------------------------------------------------------- */

/* Адрес, по которому собеседника не бывает в принципе (0.0.0.0, ::, петля, широковещательный). */
int sl_host_leads_nowhere(const char *h);
/* Имя это (1) или адрес IPv4/IPv6 (0) — строкой, без разрешения имён. */
int sl_host_is_name(const char *h);
void sl_pct_decode(char *s);
void sl_set_field(char *dst, size_t n, const char *src, size_t len);
/* Поле в процентной форме: раскодировать, потом обрезать по полю. */
void sl_set_pct(char *dst, size_t n, const char *src, size_t len);
/* Снять с конца строки неполную последовательность UTF-8. */
void sl_utf8_trim_tail(char *s);
/* Имя узла: процентная форма, обрезка по буферу без оборванных знаков. */
void sl_set_name(char *dst, size_t n, const char *src);
/* Escape-последовательность строки JSON или YAML в двойных кавычках: p указывает на знак ПОСЛЕ
 * обратной косой черты (текст оканчивается нулём). В out (до 4 байт) пишется UTF-8, в *olen — сколько;
 * возвращается, сколько знаков после косой черты прочитано. \uXXXX с суррогатной парой
 * (\ud83d\udcf1 — эмодзи) даёт один знак, одинокий суррогат — U+FFFD; yaml включает \xXX и
 * \UXXXXXXXX. Непонятая последовательность отдаёт сам знак, как и раньше. */
size_t sl_unescape(const char *p, int yaml, char out[4], size_t *olen);
/* Порт из строки цифр: 1..65535, иначе 0. */
uint16_t sl_port_of(const char *s);
/* UUID (16 байт) из строки: 32 шестнадцатеричных знака, дефисы необязательны (форма vmess id). 0 —
 * разобран, -1 — не UUID. Короткую строку хэшем (как делает VLESS, vless_uuid_form) здесь НЕ
 * выводим: vmess id всегда полный UUID. */
int sl_uuid_parse(const char *s, unsigned char out[16]);
/* 1, true, yes — «включено». */
int sl_truthy(const char *v);
/* Значение параметра в куче, процентная форма раскрыта; NULL — нет памяти. */
char *sl_param_dup(const char *v, size_t vlen);

/* ---- длинные значения и проверка сертификата ------------------------------------------------ */

/* Метки непригодных значений: указатель сравнивается с адресом, поэтому они — одни на libsteer. */
extern const char SL_BAD_PQV[], SL_FULL[], SL_BAD_PIN[], SL_BAD_ECH[], SL_ECH_DNS[];
/* Общая таблица длинных строк (pqv, encryption, отпечатки): одинаковые значения — один экземпляр. */
const char *sl_intern(const char *v, size_t n);
void sl_set_pqv(struct vless_node *n, const char *v);
void sl_add_pins(struct vless_node *n, const char *v, int spki);
void sl_set_vcn(struct vless_node *n, const char *v);
void sl_set_ech(struct vless_node *n, const char *v);
/* xhttp: длина набивки «512» или «50-150» и поле extra ссылки (JSON). */
void sl_pad_range(struct vless_node *n, const char *v);
void sl_post_range(struct vless_node *n, const char *v);
/* 1: значение этой настройки xhttp требует запросов, которых клиент не делает (см. sublink.c). */
int sl_xh_setting_bad(const char *key, const char *val);
void sl_parse_extra(struct vless_node *n, const char *extra);

/* ---- ссылка целиком ------------------------------------------------------------------------- */

/* Свой параметр протокола: 1 — разобран (дальше не смотреть), 0 — не его. */
typedef int (*sl_own_fn)(struct vless_node *n, const char *k, size_t klen, const char *v, size_t vlen);

/* схема://секрет@хост:порт?параметры#имя. Узел обнуляется; секрет (до '@', как есть) ложится в
 * n->uuid, а его начало и длина в ссылке — в *secret и *secret_n (для протокола, которому нужен
 * длиннее поля или раскодированным). Параметры: сначала own (может быть NULL), затем поля
 * транспорта и безопасности (sl_link_param). type по умолчанию — tcp. 0 — разобрана (годность ещё
 * не проверена), -1 — не эта схема или ссылка не разбирается. */
int sl_link_parse(const char *url, const char *scheme, struct vless_node *n, sl_own_fn own,
                  const char **secret, size_t *secret_n);
/* Поле транспорта или безопасности ссылки: 1 — разобрано, 0 — не из них. */
int sl_link_param(struct vless_node *n, const char *k, size_t klen, const char *v, size_t vlen);

/* Годность транспорта и безопасности узла, в две половины — между ними протокол проверяет своё
 * (у VLESS — идентификатор), чтобы порядок причин у VLESS остался прежним. 0 — годен, 1 — нет
 * (причина в skip_reason). pre: значения, которые не разобрались (pqv, отпечатки, ech), tcp
 * headerType=http, обфускация xhttp, проверка сертификата и allowInsecure. post: security,
 * tls без sni, reality без pbk, транспорт и его путь, адрес «отвечать некому», режим xhttp. */
int sl_link_usable_pre(struct vless_node *n);
int sl_link_usable_post(struct vless_node *n);

/* Ключ `insecure` выхода — vless_set_insecure (vless.h): им же решается allowInsecure у узлов
 * протоколов steer-proxy. */

/* ---- причины пропуска ----------------------------------------------------------------------- */

/* Отнести непригодный узел к его причине (группировка по тексту, пример — имя узла или хост:порт). */
void sl_skip_note(struct vless_sub_stats *st, const struct vless_node *n, const char *reason);

/* ---- узел глазами транспорта ---------------------------------------------------------------- */

/* Указатели в узел, без копий. Проверка сертификата — только у security=tls: у reality эти поля
 * ничего не значат. Встроена здесь, а не в sublink.c, чтобы разбору подписки (стенды без
 * транспорта) не тянуть за собой transport.c. */
static inline void sl_tr_node(const struct vless_node *n, struct tr_node *t) {
    t->host = n->host;
    t->port = n->port;
    t->type = n->type;
    t->security = n->security;
    t->sni = n->sni;
    t->fp = n->fp;
    t->pbk = n->pbk;
    t->sid = n->sid;
    t->path = n->path;
    t->service = n->service;
    t->mode = n->mode;
    t->pad_from = n->pad_from;
    t->pad_to = n->pad_to;
    t->post_from = n->post_from;
    t->post_to = n->post_to;
    t->http_host = n->http_host;
    t->headers = n->headers;
    t->pqv = n->pqv;
    int tls = !strcmp(n->security, "tls");
    t->pcs = tls ? n->pcs : NULL;
    t->pks = tls ? n->pks : NULL;
    t->vcn = tls ? n->vcn : NULL;
    t->ech = tls ? n->ech : NULL;
    t->insecure = tls && n->insecure;
    t->encryption = n->encryption;
}

#endif
