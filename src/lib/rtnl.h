/* rtnetlink в процессе: правила и таблицы маршрутизации IPv4 — прочитать текстом `ip` и
 * поставить то немногое, что нужно пробе сторожа.
 *
 * ЗАЧЕМ. Сторож (src/daemon/failover.c) на каждом проходе сверяет фактическую маршрутизацию
 * выхода — `ip -4 rule show` и `ip -4 route show table N` — и на каждой пробе ICMP ставит и
 * снимает правило пробы. Пока это делали запуски `ip`, проход стоил процессов: два на выход
 * на сверку и четыре на пробу, раз в минуту и по каждому событию сети. Решение владельца для
 * сторожа в демоне — без процессов на проход (docs/architecture.md, «4а»), и чтения с правилом
 * пробы уходят сюда: это те же вопросы к ядру, только без fork и exec.
 *
 * ТЕКСТОМ `ip`, А НЕ СТРУКТУРАМИ. Решение «разъехалось ли состояние» принимает чистая функция
 * route_facts_of (и её соседи rule_copies_of, rt_line_parse), и она закрыта стендом
 * failovermatch на дословных дампах `ip` с живого роутера. Отдать ей другой вход значило бы
 * завести вторую логику сверки рядом с проверенной. Поэтому дамп netlink печатается в той же
 * форме, что у iproute2, — ровно в объёме полей, которые эти функции читают (приоритет, метка с
 * маской, таблица и действие у правил; тип, назначение, устройство, метрика у маршрутов), — и
 * разбор остаётся одним.
 *
 * Разница с `ip`, о которой надо знать: таблицы печатаются номерами, кроме local, main и
 * default (iproute2 заменил бы номер именем из rt_tables, если кто-то его завёл, — разбор к
 * этому готов в обе стороны), а маршруты таблицы отбираются здесь, а не ядром: фильтр дампа по
 * таблице ядро применяет только к сокету с NETLINK_GET_STRICT_CHK, а этот сокет его не ставит.
 *
 * Синхронно: ядро отвечает на запрос rtnetlink внутри того же системного вызова, ждать тут
 * нечего. Буферы статические — зовёт это только основной поток. */
#ifndef STEER_RTNL_H
#define STEER_RTNL_H

#include <stddef.h>
#include <netinet/in.h>

/* Дамп правил IPv4 (v6 == 0) или IPv6 строками `ip -4 rule show`, текстом в куче, любой длины:
 * буфер растёт, пока дамп не влезет целиком (по правилу на выход и семейство, а выходов не 16:
 * обрезанный дамп выдавал бы правила поздних выходов за снятые, и сверка перепривязывала бы их
 * без конца). Пустая строка — ядро не прислало ни одного правила (ядро без IPv6); NULL — спросить
 * не вышло (ошибка или нехватка памяти), «состояние не прочитать», на что рассчитан
 * route_facts_of. Иначе free() вызывающему. */
char *rtnl_rules_dup(int v6);

/* Маршруты таблицы table строками `ip -4 route show table N` (v6 — `ip -6 route show table N`:
 * маршрутизация IPv6 выходов, docs/architecture.md, «4б»), текстом в куче любой длины, как у
 * rtnl_rules_dup. Пустая строка — пустая таблица; NULL — не прочитать (ядро без IPv6 тоже).
 * Запрет (blackhole, unreachable, prohibit) в IPv6 печатается без `dev lo`, который ядро
 * приписывает ему там. */
char *rtnl_routes_dup(int table, int v6);

/* Правило `from SRC lookup TABLE priority PRIO`: add — поставить, иначе снять. 0 или errno. */
int rtnl_rule_from(int add, struct in_addr src, int table, int prio);

/* `ip [-6] rule add fwmark MARK/MASK table TABLE [priority PRIO]` (fam — 4 или 6; prio 0 — не
 * передавать, ядро выберет само, как `ip rule add` без pref). Копия, которая уже стоит, — успех.
 * 0 или errno. Этим страж правил демона возвращает снятое снаружи правило выхода сразу, без
 * запуска ip (src/daemon/rulewd.c). */
int rtnl_rule_fwmark(int fam, uint32_t mark, uint32_t mask, int table, int prio);

/* `ip -4 route replace default dev <ifindex> table TABLE` (scope link, как у iproute2 без
 * шлюза). 0 или errno. */
int rtnl_route_default_dev(int table, int ifindex);

/* `ip -6 route replace prohibit default metric METRIC table TABLE` — запасной запрет таблицы IPv6
 * выхода (STEER_BACKSTOP_METRIC в spec.h). Устройство ядро назначает само: в IPv6 запрет всегда
 * висит на lo. 0 или errno. Этим страж правил демона возвращает запрет, который ядро сняло вместе
 * с lo (src/daemon/rulewd.c, «ЗАПРЕТ IPv6 УХОДИТ ВМЕСТЕ С lo»). */
int rtnl_route6_backstop(int table, int metric);

/* `ip -4 route flush table TABLE`: снять всё, что в таблице лежит. 0 или errno. */
int rtnl_table_flush(int table);

/* Вопросы diag — те, что он задавал запуском `ip` (diag стоил около двадцати процессов;
 * docs/architecture.md, «4а», «Сокет и протокол»).
 *
 * Есть ли маршрут IPv6 по умолчанию в таблице main — `ip -6 route show default | grep -q .`:
 * 1 — есть, 0 — нет, -1 — спросить не вышло. */
int rtnl_default6(void);

/* Устройства маршрутов по умолчанию таблицы main, IPv4 и IPv6 (`ip route show default`, `ip -6 route
 * show default`): cb — на каждый такой маршрут с именем устройства (одно имя может прийти дважды).
 * Набор @wan_dev плагинов (steer-api 1.2, 5.3). 0 — спросили; -1 — спросить не вышло. */
int rtnl_default_devs(void (*cb)(const char *dev, void *ctx), void *ctx);

/* Через какое устройство ядро отправит пакет к dst — `ip route get dst`, поле dev (с учётом
 * правил, как и у iproute2). 0 — имя в dev; иначе errno, dev пуст. */
int rtnl_route_dev(struct in_addr dst, char *dev, size_t n);

/* Маршруты таблицы main IPv6, по которым сторож выводит префикс донора (шаг 8 выпуска 1.10,
 * v6donor_derive в failover.c): нуль-маршруты `unreachable P` (dst_len > 0) — их ставит netifd на
 * каждый делегированный префикс, чтобы не было петли, — и маршруты по умолчанию с источником
 * `default from P …` (src_len > 0) — их ставит netifd на префикс провайдера (sourcefilter). Адреса
 * — 16 байт в порядке сети, oif — номер устройства (0 — нет). Массив — в куче (free вызывающему;
 * при нуле записей может быть NULL), число записей — результат, -1 — прочитать не вышло. */
struct rtnl_route6 {
    uint8_t dst[16], src[16];
    uint8_t dst_len, src_len;
    unsigned type;
    int oif;
};
int rtnl_main6_routes(struct rtnl_route6 **out);

/* Адреса IPv6 всех устройств — `ip -6 addr show` с признаками, которых getifaddrs не отдаёт:
 * flags — IFA_F_* (IFA_F_DEPRECATED ставится и по сроку предпочтения 0: адрес «устарел» — netifd
 * снял префикс, из которого его выдал, и новых соединений с него ядро не заводит). ifindex —
 * номер устройства. Массив в куче и число записей — как у rtnl_main6_routes. Нужны diag (IPv6 от
 * хоста): устаревший адрес LAN из снятого префикса — не «адрес из префикса хоста». */
struct rtnl_addr6 {
    uint8_t a[16];
    uint8_t plen;
    int ifindex;
    uint32_t flags;
};
int rtnl_addrs6(struct rtnl_addr6 **out);

#endif
