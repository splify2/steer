/* Apply-сверка демона (docs/architecture.md, «4а», «Apply-сверка»): apply и reload сравнивают
 * новую спеку с применённой по частям и трогают только то, что изменилось.
 *
 * ЧАСТИ И КАК ОНИ СРАВНИВАЮТСЯ.
 *   Набор правил — отпечаток (FNV-1a 64) текста, который печатает generate по дереву, без
 *     счётчиков: план их из ядра не читает, поэтому текст зависит только от спеки, списков и
 *     раскладки. И без засева карты fake-IP из файла состояния резолвера (g_print_state_seed,
 *     доводы — у print_elements в src/compile/print.c): файл растёт с каждым выданным адресом,
 *     а элементы, которые засев поставил бы, в незаменённой таблице уже положил сам резолвер, —
 *     с засевом в отпечатке любое новое имя в сети делало бы следующий reload полной заменой
 *     таблицы. Текст для ядра (apply-commit --ruleset) засев несёт как прежде. Совпал с отпечатком последнего нашего nft -f, таблица в ядре — та самая (номер
 *     таблицы, NFT_MSG_GETTABLE по netlink, без запуска nft) и в ней ничего не изменено снаружи
 *     (отпечаток таблицы в ядре, ниже «СВЕРКА С ЯДРОМ») — nft не зовётся вовсе: ни
 *     транзакции, ни сброса наборов, которые наполняет резолвер, ни пересчёта счётчиков. Не
 *     совпал — одной транзакцией, как у подкоманды (ruleset_load в apply.c: «добавить — удалить —
 *     новая таблица», счётчики переносятся), отказ ядра — прежний откат спеки.
 *   Маршрутизация — подпись по выходу: вид, метка, таблица, on_fail, пул устройств, файл awg
 *     (out_route_sig в apply.c). Привязываются заново только выходы с новой подписью и новые —
 *     и те, чьи правило или таблица в ядре разошлись с ожидаемым (ниже, «СВЕРКА С ЯДРОМ»);
 *     правило и таблица убранного выхода (или прежняя метка выхода, которому реестр дал другую)
 *     снимаются, как у cleanup_stale_routing, если метку не несёт никто из оставшихся.
 *   Помощники — сверка подписей в супервизоре (helpers_merge через supd_spec_changed): apply
 *     зовёт её, а не перезапуск всех.
 *   Таблица резолвера — пишется в трубу, только если изменился её текст или файлы списков, на
 *     которые она ссылается (supd.c, tab_send).
 *   Сторож — внеочередной проход, только если изменились выходы: подпись сторожа (маршрут, via,
 *     выбор по задержке) или помощники.
 *
 * ЧТО ДЕМОН ЗНАЕТ О ПРИМЕНЁННОМ. Только то, что применил сам (struct recon_state). После старта
 * демона — ничего, и первый apply или reload применяет всё, как подкоманда: спеку до него мог
 * ставить init (`steer apply`), и верить, что в ядре именно она, демону не на чем. Применённое
 * забывается, когда движок выключен (правила снимает init, включённый движок их ставит init же) и
 * когда применение не прошло целиком. Чужое вмешательство в ядро — `steer down`, `steer apply` из
 * init — меняет номер таблицы или убирает её, и сверка видит это по netlink: тогда тоже всё
 * заново. На ядре до 4.16 номера таблиц нет, и там видно только «таблица есть или нет»; init
 * телефона ставит ту же сохранённую спеку, что держит демон, так что разойтись им не на чем.
 *
 * СВЕРКА С ЯДРОМ, А НЕ ТОЛЬКО С ПАМЯТЬЮ. Прежде неизменная спека значила «в ядро не идём», если
 * таблица та же (номер). Проверка на QEMU-роутере (2026-09-27)
 * показала, чего это стоит: снятое руками правило канала в prerouting_mark (номер таблицы от
 * этого не меняется) — трафик канала шёл напрямую, а `steer apply`, `steer reload` и reapply
 * из init.d отвечали «менять нечего»; помог только перезапуск службы. Так же молча оставались
 * снятые маршрут таблицы выхода вместе с его правилом (правило без таблицы страж правил за
 * чужое снятие не считает — см. rulewd.c, — а маршрут вернул только проход сторожа через
 * минуту). Явный apply и reload — ровно то, чем человек чинит «что-то не так», и отвечать
 * «всё стоит» он обязан по ядру, а не по памяти. Поэтому на неизменной спеке сверяются ещё три
 * вещи, все по netlink и без единого запуска nft или ip (две — в процессе демона, сводка
 * элементов — в ребёнке-плане):
 *
 *   Набор правил — отпечаток таблицы в ядре (nfd_table_fp, src/lib/nftdump.c: цепочки, правила
 *     по порядку, заголовки наборов; без номеров, счётчиков и элементов наборов) против
 *     отпечатка, снятого сразу после нашего последнего nft -f (recon_applied). Разошлись — набор
 *     ставится заново той же одной транзакцией, что при смене спеки.
 *     Почему «как было сразу после загрузки», а не «как вышло бы из текста generate». Текст —
 *     это язык nft, а ядро отдаёт атрибуты netlink; свести одно к другому — значит повторить
 *     разбор и компиляцию nft (или звать `nft -j list` на каждый apply и сравнивать его печать,
 *     которая зависит от версии nft). Снимок ядра после загрузки и есть ожидаемое: его поставил
 *     наш nft -f из нашего текста, и с тех пор сами по себе в таблице меняются только элементы
 *     наборов (резолвер, сторож) и счётчики — они в отпечаток не входят. Цена — четыре обмена
 *     netlink на все семейства сразу (таблицы, цепочки, наборы — только заголовки, правила —
 *     сотни объектов), доли миллисекунды на роутере.
 *     Снимает ожидаемое не демон, а ребёнок apply-commit — сразу после своего nft -f, и
 *     передаёт строкой вывода (recon_kernel_print): между nft -f и выходом ребёнка идут
 *     привязка выходов, awg и masquerade — секунды, и чужая правка таблицы в это время,
 *     снятая демоном уже после выхода ребёнка, вошла бы в ожидаемое и не нашлась бы никогда.
 *     Окно остаётся — от конца nft -f до дампа в том же ребёнке, миллисекунды, — и правка
 *     в него неотличима от нашей: у ядра нет «чья это транзакция» (номер поколения растёт и
 *     от каждого элемента резолвера).
 *     Почему замена, а не точечная починка. Вернуть одно снятое правило на его место — это
 *     свой nft с позицией и ссылками на безымянные наборы; замена таблицы у нас уже есть,
 *     атомарна и проверена, счётчики каналов переносит, а наборы, которые наполняет резолвер,
 *     он же и возвращает: демон после замены набора посылает ему таблицу и неизменной
 *     (supd_spec_changed с replaced), и резолвер ставит заново постоянные элементы fake-IP и
 *     элементы real-ip с оставшимся сроком (proxy.c, reassert_routes; realip.c). Карту fake-IP
 *     generate засевает из файла состояния, метки «пущен напрямую» возвращает apply-commit по
 *     таблицам выходов, карты раздачи balance — внеочередной проход сторожа (diff.watch).
 *     Чего отпечаток не видит — элементов именованных наборов (почему — в nftdump.c): их
 *     сверяет сводка ниже, «СВЕРКА ЭЛЕМЕНТОВ».
 *
 *   Элементы статических наборов — сводка (recon_kernel_elems) против снятой после нашего
 *     nft -f; разошлась — та же замена набора одной транзакцией. Ниже, «СВЕРКА ЭЛЕМЕНТОВ».
 *
 *   Маршрутизация выходов — правило fwmark и таблица каждого выхода с устройством, которого
 *     сверка по подписи не тронула бы. Ожидаемое — по памяти сторожа (outs): выход, который
 *     сторож признал неработающим («-» в записи active), должен стоять так, как ставит его
 *     on_fail (routing_failed_ok, та же проверка, что у сторожа), — такой выход возвращает
 *     внеочередной проход сторожа: перепривязка apply к устройству сняла бы его решение до
 *     следующего прохода. Остальные — «правило стоит, а таблица ведёт в одно из устройств
 *     выхода» или, если ни одного устройства нет, то, что ставит apply без устройства (запрет
 *     при on_fail=drop, пустая таблица при direct и zapret). Не так — выход привязывается
 *     заново (apply_routing_one, как при смене подписи), и сторожу — внеочередной проход. Какое
 *     именно устройство группы несёт трафик, здесь не сверяется: это решение сторожа, и его
 *     проход идёт сразу следом. Прочитать правила не вышло — маршруты не сверяются (по незнанию
 *     перепривязывать живой выход хуже, чем не заметить поломку, — как у сторожа).
 *
 * СВЕРКА НА ПРОХОДЕ СТОРОЖА (решение владельца, 2026-09-28). Сверка на apply и reload чинит
 * только тогда, когда человек что-то заметил и нажал «Применить». Снятое снаружи правило канала
 * до этого молча пускало трафик мимо туннеля — часами, если никто не смотрит. Поэтому с --watch
 * отпечаток набора правил сверяется с ядром на КАЖДОМ проходе сторожа (recon_kernel_drift; зовёт
 * сервер сокета перед проходом — watchd_conf.kcheck):
 *   - что сверяется — номер таблицы inet и отпечаток наших таблиц, то же, что на apply, но БЕЗ
 *     элементов наборов: четыре обмена netlink (nfd_table_fp), в процессе демона, без единого
 *     процесса — проход по здоровому ядру по-прежнему не запускает никого (владелец строго:
 *     «без fork на проход»);
 *   - что делается при расхождении — строка в журнал и починка в очередь изменяющих команд
 *     демона: reload без соединения (ctl.c, srv_resync) — тот же путь, что apply той же спеки,
 *     то есть план, recon_decide (он увидит то же расхождение и поставит набор правил заново
 *     одной транзакцией) и перечитывание, после которого резолвер возвращает свои элементы.
 *     Второго пути применения нет, и цикл демона nft -f не ждёт: план и nft -f — в детях, как
 *     у apply, а проход откладывается до конца починки, как при любой изменяющей команде (он и
 *     она пишут одни и те же таблицы);
 *   - своя замена набора правил, которая сейчас в полёте, расхождением не считается: проход не
 *     начинается, пока идёт изменяющая команда (watchd_conf.busy), а сверка на проходе ещё раз
 *     смотрит, не занята ли очередь и не ждёт ли в ней починка. Применённое (номер и отпечаток)
 *     демон запоминает до того, как отпустит очередь, — между концом apply-commit и новым
 *     ожидаемым прохода не бывает;
 *   - таблицы inet нет — движок снят (`steer down`): чинить нечего, как у стража правил. Номер
 *     таблицы другой — таблицу заменил кто-то мимо демона (`steerd apply` подкомандой, скрипт):
 *     это тоже расхождение, и починка ставит набор правил демона — вместе с элементами
 *     резолвера, которых в чужой таблице нет;
 *   - починок не больше трёх за пять минут (RESYNC_BURST, ctl.c): тот, кто правит нашу таблицу
 *     без остановки, не должен превращать каждый проход в компиляцию и nft -f. Отказ — строка в
 *     журнал, одна на окно; расхождение, объяснимое пропажей или появлением устройства раздачи
 *     (цепочку ingress ядро снимает вместе с ним), — вне этого счёта, в своём пределе (доводы —
 *     у srv_kcheck в ctl.c, «ЛИМИТ МОЛЧАЛ»);
 *   - без демона (`steer failover --loop`, прямой вызов) сверки на проходе нет: помнить
 *     применённое там некому;
 *   - на телефоне — то же самое: раскладка старого ядра (таблицы ip и ip6 рядом с inet)
 *     входит в тот же отпечаток теми же четырьмя дампами.
 * Прочитать ядро не вышло — проход ничего не решает (решит следующий): незнание здесь не повод
 * компилировать и ставить набор заново, как на явном apply.
 *
 * СВЕРКА ЭЛЕМЕНТОВ СТАТИЧЕСКИХ НАБОРОВ (решение владельца, 2026-09-28). Отпечаток элементов
 * именованных наборов не видит, и снятый руками адрес адресного списка apply прежде не
 * возвращал. Теперь на apply и reload (не на проходе сторожа: сотни тысяч элементов — дорого)
 * сверяется ещё сводка элементов (recon_kernel_elems):
 *   Какие наборы — те, чьи элементы целиком задаёт наш nft -f: именованные, не карты (fake-IP,
 *     раздача balance — MAP), не объекты (OBJECT), не наполняемые правилами (EVAL) и не набор
 *     «пущен напрямую» (FAILOPEN_SET: метки в нём ставят сторож и apply-commit). Отбор — по
 *     заголовку набора в ядре, а не по именам генератора: набор новой цепочки или раскладки
 *     попадает в сверку сам.
 *   Доменные наборы (флаг timeout) — сверяется часть, которую можно отличить. В них вперемешку
 *     лежат элементы списков и .srs канала (из nft -f, без срока), адреса real-ip (резолвер,
 *     всегда со сроком: set_ttl_clamp нуля не даёт) и поддельные адреса fake-IP (резолвер, без
 *     срока, но всегда из пула 198.18.0.0/15 или fdfe:dcba:9876::/96; ключ набора начинается с
 *     адреса и у составного набора). В сводку идут элементы без срока с адресом вне пула — то
 *     есть элементы списков. Маркеры конца диапазона (флаг INTERVAL_END) здесь не сверяются: у
 *     элемента real-ip маркер конца ядро хранит без срока (nftnl.c), и отнести маркер к списку
 *     или к резолверу по ядру нечем, — так что снятый или добавленный диапазон виден, а
 *     суженный с тем же началом нет. Адрес списка внутри пула fake-IP не сверяется тоже (пул —
 *     зарезервированный диапазон RFC 2544, спискам в нём делать нечего). Исключить доменные
 *     наборы целиком было бы нечестно: у выхода, куда ведут и адресный, и доменный каналы,
 *     генератор кладёт подсети списка в доменный набор, и на роутере это обычный случай.
 *   Резолвер пишет в доменный набор и посреди дампа, а ядро обходит набор, пропуская уже
 *     отданное по счёту: вставка перед курсором сдвигает его, и склеенный дамп дал бы ложное
 *     расхождение — замену набора правил на пустом месте. Поэтому у доменного набора смотрится
 *     номер поколения в ответах дампа (nfd_set_elems, *stable: он растёт с каждой транзакцией, и
 *     так отвечает и 4.9): у всех ответов один — снимок цельный; разный — дамп заново, три таких
 *     подряд — «не прочитать», и элементы в этот раз не сверяются. Сначала было «два дампа до
 *     совпадения», но дамп набора в 200 тысяч подсетей стоит секунды (замер ниже), и второй
 *     удваивал цену ровно в обычном случае. Статический набор, кроме нас, не пишет никто — там
 *     номер поколения не смотрится: его двигают и элементы резолвера в других наборах.
 *   Хэш, а не счётчик: счётчик не видит замены одного элемента другим. Сводка — сумма по модулю
 *     2^64 перемешанных хэшей элементов (FNV-1a по ключу, концу ключа и флагу конца, затем
 *     fmix64): от порядка, в котором ядро отдаёт элементы (у rbtree, hash и pipapo он свой), она
 *     не зависит, считается за один проход без памяти под элементы, а совпасть у двух разных
 *     множеств может с вероятностью порядка 2^-64. Сумма, а не xor: xor гасит пару одинаковых.
 *     По наборам — такая же сумма от (семейство, имя, число, сумма); число элементов — ещё и для
 *     строки журнала.
 *   Ожидаемое — сразу после нашего nft -f, ребёнком apply-commit (строка recon-kernel), как и
 *     отпечаток: свести текст generate к элементам ядра значило бы повторить nft (auto-merge
 *     склеивает соседние подсети, интервалы ядро хранит по-своему). Текущее — ребёнок apply-plan
 *     (флаг --kernel-elems; демон передаёт его, когда ожидаемое есть): дамп сотен тысяч
 *     элементов идёт не в цикле демона, status отвечает сразу. Разошлось — та же замена набора
 *     правил одной транзакцией; адреса fake-IP и real-ip после неё возвращает резолвер, как при
 *     любой замене.
 *   Цена снята замером на 200 тысячах подсетей (2026-09-28).
 *
 * ГДЕ ИДЁТ РАБОТА. Компиляция — не в процессе демона, а ребёнком на команду: `steer apply-plan`
 * (проверки dry-run и отпечатки частей) и, если есть что применять, `steer apply-commit` (только
 * названные части). Процесс на apply, а не на проход — это допустимо и здесь лучше потока:
 *   - компиляция больших списков — секунды процессора и десятки мегабайт памяти пиком; в ребёнке
 *     цикл демона свободен (status отвечает сразу), а память возвращается системе с его выходом,
 *     и куча демона, который живёт месяцами, не растёт пиками;
 *   - компилятор держит глобальное состояние (g_nftc, перенесённые счётчики, реестр меток), и
 *     status демона читает те же счётчики в процессе — поток-рабочий делил бы их без замков;
 *   - сбой компилятора (die на битом списке, зависание nft) задевает только ребёнка, как и
 *     прежде, а срок команды убивает его группу целиком.
 * Прежний путь делал то же двумя детьми — dry-run и apply, то есть компилировал дважды на каждый
 * apply; сейчас на неизменной спеке компиляция одна (план), а nft и ip не запускаются вовсе. План
 * внешних процессов не зовёт: раскладку набора правил (проба ядра через nft) демон узнаёт у
 * первого плана и дальше передаёт готовой. nft -f и ip — в apply-commit, ребёнке демона, чей
 * выход приходит через loop_child.
 *
 * Подкоманда `steer apply` (init.d, rpcd, init телефона) не меняется: она проходит все шаги
 * подряд, тем же кодом (apply.c). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <endian.h>
#include <sys/socket.h>
#include <sys/time.h>
/* netinet/in.h — раньше linux/netfilter.h (он тянет linux/in.h): в обратном порядке glibc видит
 * struct in_addr дважды, а rtnl.h ниже его требует. */
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include "recon.h"
#include "nftdump.h"
#include "rtnl.h"
#include "fostate.h"
#include "failover_int.h"

#define LOG_W "steer[warn] ctl: "

/* Наши таблицы в ядре (nfd_table_fp): inet — всегда, ip и ip6 — те, что ставит раскладка старого
 * ядра (legacy.c); появившаяся или пропавшая таблица раскладки — тоже другой отпечаток. 0 —
 * снято; -1 — ядро не ответило. */
static int kernel_fp(struct nfd_tfp *t) {
    return nfd_table_fp(nft_table(), t) == 0 ? 0 : -1;
}

/* Маршрутизация выхода в ядре против ожидаемого (шапка, «СВЕРКА С ЯДРОМ»). */
enum { KR_OK, KR_REBIND, KR_WATCH };

static int kernel_route(const struct spec *sp, const struct output *so, struct fo_store *outs,
                        const char *rules, const char *rules6, const char **why) {
    static char routes[8192];
    if (rtnl_routes_text(so->table, routes, sizeof(routes)) != 0) return KR_OK;
    struct route_facts f = route_facts_of(rules, routes, so->mark, so->table);
    if (!f.known) return KR_OK;
    char rec[32];
    active_get_st(outs, so->name, rec, sizeof(rec));
    if (!strcmp(rec, "-")) {
        if (routing_failed_ok(&f, so->on_fail)) return KR_OK;
        *why = "маршрутизация выхода в отказе — не та, что ставит его on_fail";
        return KR_WATCH;
    }
    size_t mn = out_members_n(sp, so);
    int present = 0, member = 0;
    if (!mn) {
        present = device_present(so->device);
        member = f.table == TBL_DEV && !strcmp(f.dev, so->device);
    }
    for (size_t k = 0; k < mn; k++) {
        const struct output *mo = out_member(sp, so, k);
        if (device_present(mo->device)) present = 1;
        if (f.table == TBL_DEV && !strcmp(f.dev, mo->device)) member = 1;
    }
    if (!f.rule) { *why = "правила fwmark нет"; return KR_REBIND; }
    /* Таблица ведёт в одно из устройств выхода — годится (TBL_OTHER — маршрут есть, но устройство
     * из него не вычитать: не трогаем). Иначе годится только то, что ставит apply, когда ни
     * одного устройства нет: запрет при on_fail=drop, пустая таблица при direct и zapret. */
    int ok = member || f.table == TBL_OTHER ||
             (!present && (so->on_fail == FAIL_DROP
                               ? f.table == TBL_BLACKHOLE || (f.table == TBL_EMPTY && f.backstop)
                               : f.table == TBL_EMPTY));
    if (!ok) {
        *why = f.table == TBL_EMPTY ? "таблица выхода пуста" : "таблица выхода ведёт не туда";
        return KR_REBIND;
    }
    if (out_route6(so) && rules6[0]) {
        static char routes6[8192];
        if (rtnl_routes_text6(so->table, routes6, sizeof(routes6)) != 0) return KR_OK;
        struct route_facts f6 = route_facts_of(rules6, routes6, so->mark, so->table);
        if (!f6.known) return KR_OK;
        if (!f6.rule) { *why = "правила fwmark IPv6 нет"; return KR_REBIND; }
        /* При живом IPv4 половина IPv6 — маршрут в устройство или запрет (IPv6 на устройстве
         * выключен), но не пустота: пустая таблица IPv6 пустила бы IPv6 выхода напрямую. */
        if (member && f6.table == TBL_EMPTY && !f6.backstop) {
            *why = "таблица IPv6 выхода пуста";
            return KR_REBIND;
        }
    }
    return KR_OK;
}

static const struct output *recon_spec_out(const struct spec *sp, const char *name) {
    for (size_t i = 0; sp && i < sp->out_n; i++)
        if (!strcmp(sp->out[i].name, name)) return &sp->out[i];
    return NULL;
}

void recon_init(struct recon_state *st) {
    memset(st, 0, sizeof(*st));
    st->nftc = -1;
}

void recon_forget(struct recon_state *st) {
    st->valid = 0;
    st->n = 0;
}

void recon_plan_free(struct recon_plan *p) {
    free(p->out);
    free(p->stale);
    memset(p, 0, sizeof(*p));
}

void recon_diff_free(struct recon_diff *d) {
    free(d->route);
    free(d->route_kern);
    free(d->drop);
    memset(d, 0, sizeof(*d));
}

void recon_state_free(struct recon_state *st) {
    free(st->out);
    free(st->w);
    memset(st, 0, sizeof(*st));
    st->nftc = -1;
}

/* Место в растущем массиве под ещё одну запись: 0 — есть, -1 — нет памяти. */
static int room(void **arr, size_t *cap, size_t n, size_t esz) {
    if (n < *cap) return 0;
    size_t nc = *cap ? *cap * 2 : 16;
    void *p = realloc(*arr, nc * esz);
    if (!p) return -1;
    *arr = p;
    *cap = nc;
    return 0;
}

int recon_plan_parse(const char *text, size_t n, struct recon_plan *p) {
    recon_plan_free(p);
    p->nftc = -1;
    p->nftc = -1;
    int have_fp = 0;
    const char *end = text + n;
    for (const char *ln = text; ln < end; ) {
        const char *e = memchr(ln, '\n', (size_t)(end - ln));
        size_t len = e ? (size_t)(e - ln) : (size_t)(end - ln);
        char line[256];
        if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy(line, ln, len);
        line[len] = '\0';
        ln = e ? e + 1 : end;
        if (!strncmp(line, "nftc ", 5)) {
            p->nftc = atoi(line + 5);
        } else if (!strncmp(line, "ruleset ", 8)) {
            p->fp = strtoull(line + 8, NULL, 16);
            have_fp = 1;
        } else if (!strncmp(line, "counts ", 7)) {
            if (sscanf(line + 7, "%zu %zu", &p->ch_n, &p->out_n) != 2) return -1;
        } else if (!strncmp(line, "out ", 4)) {
            if (room((void **)&p->out, &p->cap, p->n, sizeof(*p->out)) != 0) return -1;
            struct recon_out *o = &p->out[p->n];
            if (sscanf(line + 4, "%31s %x %d %d %d %llx %llx", o->name, &o->mark, &o->table,
                       &o->routed, &o->awg, &o->rsig, &o->wsig) != 7)
                return -1;
            p->n++;
        } else if (!strncmp(line, "kelems ", 7)) {
            unsigned long long el, en;
            if (sscanf(line + 7, "%llx %llu", &el, &en) == 2) {
                p->kel_ok = 1;
                p->kel = el;
                p->kel_n = en;
            }
        } else if (!strncmp(line, "stale ", 6)) {
            if (room((void **)&p->stale, &p->stale_cap, p->stale_n, sizeof(*p->stale)) != 0) return -1;
            if (sscanf(line + 6, "%x %d", &p->stale[p->stale_n].mark,
                       &p->stale[p->stale_n].table) == 2)
                p->stale_n++;
        }
    }
    return have_fp && p->nftc >= 0 ? 0 : -1;
}

static const struct recon_out *out_find(const struct recon_out *v, size_t n, const char *name) {
    for (size_t i = 0; i < n; i++)
        if (!strcmp(v[i].name, name)) return &v[i];
    return NULL;
}

static void drop_add(struct recon_diff *d, const struct recon_plan *p, unsigned mark, int table) {
    if (!mark) return;
    for (size_t i = 0; i < p->n; i++)
        if (p->out[i].mark == mark) return;      /* метку несёт выход новой спеки */
    for (size_t i = 0; i < d->drop_n; i++)
        if (d->drop[i].mark == mark && d->drop[i].table == table) return;
    if (room((void **)&d->drop, &d->drop_cap, d->drop_n, sizeof(*d->drop)) != 0) return;
    d->drop[d->drop_n].mark = mark;
    d->drop[d->drop_n].table = table;
    d->drop_n++;
}

void recon_decide(const struct recon_state *st, const struct recon_plan *p, const struct spec *sp,
                  struct fo_store *outs, struct recon_diff *d) {
    memset(d, 0, sizeof(*d));
    int full = !st->valid;
    /* Номер таблицы и отпечаток — одним снимком (nfd_table_fp, четыре обмена netlink). */
    struct nfd_tfp t;
    memset(&t, 0, sizeof(t));
    int krc = full ? -1 : kernel_fp(&t);
    if (!full && krc != 0) {
        /* Что стоит, не знаем — набор ставится заново. */
        full = 1;
        d->watch = 1;
        fprintf(stderr, LOG_W "набор правил в ядре не прочитать — ставлю набор правил заново\n");
    }
    /* Таблицы нет или она не та, что ставили мы, — в ядре побывал кто-то ещё (`steer down`,
     * `steer apply` из init): что там теперь стоит, не знаем — всё заново. */
    if (!full && (!(t.fams & 1) || t.handle != st->handle)) full = 1;
    d->ruleset = full || st->fp != p->fp;
    /* Таблица та же, а внутри — то ли, что ставили мы (шапка, «СВЕРКА С ЯДРОМ»). */
    if (!d->ruleset && t.fp != st->kfp) {
        d->ruleset = 1;
        d->watch = 1;
        fprintf(stderr, LOG_W "набор правил в ядре изменён снаружи (цепочки, правила или наборы "
                              "не те, что ставило ядро steer) — ставлю набор правил заново\n");
    }
    /* Элементы статических наборов (шапка, «СВЕРКА ЭЛЕМЕНТОВ»): сводку ядра снял план. Нет её
     * у плана или у применённого — элементы не сверяются. */
    if (!d->ruleset && st->kel_ok && p->kel_ok && (p->kel != st->kel || p->kel_n != st->kel_n)) {
        d->ruleset = 1;
        d->watch = 1;
        fprintf(stderr, LOG_W "элементы статических наборов в ядре не те, что ставило ядро steer (в "
                              "ядре %llu, после загрузки было %llu) — ставлю набор правил заново\n",
                (unsigned long long)p->kel_n, (unsigned long long)st->kel_n);
    }
    /* Правила выходов — одним дампом на все выходы, и только если сверять есть что. */
    char *rules = NULL, *rules6 = NULL;      /* дампы правил — в куче, любой длины (rtnl_rules_dup) */
    int rules_read = 0;
    for (size_t i = 0; i < p->n; i++) {
        const struct recon_out *o = &p->out[i];
        if (!o->routed) continue;
        const struct recon_out *was = full ? NULL : out_find(st->out, st->n, o->name);
        int kern = 0;      /* привязка только из-за расхождения с ядром (recon_diff.route_kern) */
        if (was && was->routed && was->rsig == o->rsig) {
            /* Подпись та же — сверить с ядром. Выход берётся из спеки в памяти: при той же
             * подписи вид, метка, таблица, on_fail, устройства и IPv6 у неё те же, что в плане
             * (сверяются ещё метка и таблица — на случай, если спека в памяти не та). */
            const struct output *so = recon_spec_out(sp, o->name);
            if (!so || !out_has_device(so) || so->mark != o->mark || so->table != o->table)
                continue;
            if (!rules_read) {
                rules_read = 1;
                rules = rtnl_rules_dup(0);
                rules6 = rtnl_rules_dup(1);
            }
            /* Пустой дамп правил — «спросить не вышло» (на живой коробке правил ядра три). */
            if (!rules || !rules[0]) continue;
            const char *why = "";
            int kr = kernel_route(sp, so, outs ? outs : &fo_store_files, rules, rules6 ? rules6 : "",
                                  &why);
            if (kr == KR_OK) continue;
            d->watch = 1;
            fprintf(stderr, LOG_W "выход %s: %s — %s\n", o->name, why,
                    kr == KR_REBIND ? "привязываю заново" : "сторожу внеочередной проход");
            if (kr == KR_WATCH) continue;
            kern = 1;
        }
        /* route и route_kern растут вместе (одна ёмкость): рост route_kern — по ёмкости route. */
        size_t old_cap = d->route_cap;
        if (room((void **)&d->route, &d->route_cap, d->route_n, sizeof(*d->route)) != 0) continue;
        if (d->route_cap != old_cap) {
            unsigned char *nk = realloc(d->route_kern, d->route_cap);
            if (!nk) { d->route_cap = old_cap; continue; }
            d->route_kern = nk;
        }
        d->route_kern[d->route_n] = (unsigned char)kern;
        snprintf(d->route[d->route_n++], sizeof(d->route[0]), "%s", o->name);
        if (o->awg) d->awg = 1;
    }
    for (size_t i = 0; i < p->stale_n; i++) drop_add(d, p, p->stale[i].mark, p->stale[i].table);
    if (st->valid)
        for (size_t i = 0; i < st->n; i++) {
            const struct recon_out *was = &st->out[i];
            const struct recon_out *now = out_find(p->out, p->n, was->name);
            if (now && now->mark == was->mark && now->table == was->table) continue;
            drop_add(d, p, was->mark, was->table);
            if (was->awg && (!now || !now->awg)) d->awg = 1;
        }
    free(rules);
    free(rules6);
    if (full) d->awg = d->masq = 1;
    else d->masq = d->route_n || d->drop_n;
}

int recon_diff_any(const struct recon_diff *d) {
    return d->ruleset || d->route_n || d->drop_n || d->awg;
}

char *recon_commit_argv(const struct recon_diff *d, const char *exe, const char *spec,
                        const char *state_dir, int nftc, char **av) {
    /* Размер по построению: имя выхода ≤ 31 + запятая, метка:таблица ≤ 8 + 1 + 11 + запятая,
     * плюс nftc. Ровно столько и выделяется — списки любой длины помещаются целиком. */
    size_t n = 64 + d->route_n * 33 + d->drop_n * 22;
    char *buf = malloc(n);
    if (!buf) return NULL;
    size_t k = 0, off = 0;
    av[k++] = (char *)exe;
    av[k++] = "apply-commit";
    av[k++] = "--spec";
    av[k++] = (char *)spec;
    if (state_dir) { av[k++] = "--state-dir"; av[k++] = (char *)state_dir; }
    if (nftc >= 0) {
        int w = snprintf(buf + off, n - off, "%d", nftc);
        av[k++] = "--nftc";
        av[k++] = buf + off;
        off += (size_t)w + 1;
    }
    if (d->ruleset) av[k++] = "--ruleset";
    if (d->awg) av[k++] = "--awg";
    if (d->masq) av[k++] = "--masq";
    if (d->route_n && off < n) {
        char *s = buf + off;
        size_t l = 0;
        for (size_t i = 0; i < d->route_n; i++)
            l += (size_t)snprintf(s + l, n - off - l, "%s%s", i ? "," : "", d->route[i]);
        av[k++] = "--route";
        av[k++] = s;
        off += l + 1;
    }
    if (d->drop_n && off < n) {
        char *s = buf + off;
        size_t l = 0;
        for (size_t i = 0; i < d->drop_n; i++)
            l += (size_t)snprintf(s + l, n - off - l, "%s%x:%d", i ? "," : "", d->drop[i].mark,
                                  d->drop[i].table);
        av[k++] = "--drop";
        av[k++] = s;
        off += l + 1;
    }
    av[k] = NULL;
    return buf;
}

void recon_applied(struct recon_state *st, const struct recon_plan *p, const struct recon_diff *d,
                   const struct recon_kernel *k) {
    if (d->ruleset || !st->valid) {
        /* Номер нашей новой таблицы — чтобы следующий раз узнать, не подменил ли её кто, — и её
         * отпечаток: не изменил ли кто что-то внутри. Снимает их ребёнок apply-commit сразу
         * после своего nft -f (шапка, «СВЕРКА С ЯДРОМ»): здесь, после его выхода, в ожидаемое
         * вошла бы и чужая правка, сделанная, пока он привязывал выходы. Строки от ребёнка нет
         * (он не дошёл до неё или ядро ему не ответило) — снимаем сами, как прежде. Не
         * спросилось и так — применённое не запоминаем: следующий apply применит набор заново. */
        struct nfd_tfp t;
        /* Сводку элементов сам демон не снимает: дамп сотен тысяч элементов — не для его
         * цикла; без строки ребёнка элементы до следующего nft -f не сверяются. */
        st->kel_ok = 0;
        if (k && k->ok) {
            st->handle = k->handle;
            st->kfp = k->kfp;
            st->kel_ok = k->el_ok;
            st->kel = k->el;
            st->kel_n = k->el_n;
        } else if (kernel_fp(&t) == 0 && (t.fams & 1)) {
            st->handle = t.handle;
            st->kfp = t.fp;
        } else {
            recon_forget(st);
            return;
        }
    }
    st->valid = 1;
    st->fp = p->fp;
    if (p->n > st->cap) {
        size_t nc = p->n;
        struct recon_out *no = realloc(st->out, nc * sizeof(*no));
        if (!no) { recon_forget(st); return; }      /* не запомнили — следующий apply применит всё */
        st->out = no;
        st->cap = nc;
    }
    if (p->n) memcpy(st->out, p->out, p->n * sizeof(p->out[0]));
    st->n = p->n;
}

int recon_kernel_drift(const struct recon_state *st, const char **why) {
    if (!st->valid) return -1;
    struct nfd_tfp t;
    if (kernel_fp(&t) != 0) return -1;
    if (!(t.fams & 1)) return 2;
    if (t.handle != st->handle) {
        *why = "таблицу ядра steer заменили мимо демона";
        return 1;
    }
    if (t.fp != st->kfp) {
        *why = "цепочки, правила или наборы не те, что ставило ядро steer";
        return 1;
    }
    return 0;
}

/* ---- сводка элементов статических наборов (шапка, «СВЕРКА ЭЛЕМЕНТОВ») ---------------------- */

/* Флаги наборов (NFT_SET_*) — числами: заголовки тулчейна бывают старше ядра, ABI не меняется. */
#define KEL_ANONYMOUS 0x01
#define KEL_MAP       0x08
#define KEL_TIMEOUT   0x10
#define KEL_EVAL      0x20
#define KEL_OBJECT    0x40

#define KEL_FNV_INIT  14695981039346656037ULL

static void kel_mix(uint64_t *h, const void *p, size_t n) {
    const unsigned char *b = p;
    for (size_t i = 0; i < n; i++) { *h ^= b[i]; *h *= 1099511628211ULL; }
}

/* Перемешивание перед суммой (fmix64 из MurmurHash3): у FNV-1a соседние ключи дают близкие
 * младшие биты, и сумма таких хэшей хуже различала бы множества. */
static uint64_t kel_fmix(uint64_t k) {
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53ULL;
    k ^= k >> 33;
    return k;
}

/* Адрес из пула fake-IP в начале ключа: 198.18.0.0/15 (ключ IPv4 — 4 байта, у составного набора
 * «адрес . протокол . порт» — 12) или fdfe:dcba:9876::/96 (16 и 24). Пул — src/dnsd/dnsd_int.h
 * (FAKEIP_POOL_BASE) и FAKEIP6_PREFIX_BYTES в spec.h. */
static int kel_fake(const uint8_t *k, size_t n) {
    static const uint8_t p6[12] = { FAKEIP6_PREFIX_BYTES };
    if (n == 4 || n == 12) return k[0] == 198 && (k[1] & 0xfe) == 18;
    if (n == 16 || n == 24) return !memcmp(k, p6, sizeof(p6));
    return 0;
}

struct kel_sum {
    int partial;                    /* доменный набор: только элементы списков */
    uint64_t sum, n;
};

static void kel_elem(void *arg, const struct nfd_elem *e) {
    struct kel_sum *s = arg;
    if (e->data) return;            /* у набора данных нет; карта сюда не попадает */
    int end = (e->flags & NFT_SET_ELEM_INTERVAL_END) != 0;
    if (s->partial && (e->timeout || end || kel_fake(e->key, e->klen))) return;
    uint64_t h = KEL_FNV_INIT;
    uint32_t kl = (uint32_t)e->klen, el = (uint32_t)e->kelen;
    kel_mix(&h, &kl, sizeof(kl));
    kel_mix(&h, e->key, e->klen);
    kel_mix(&h, &el, sizeof(el));
    if (e->key_end) kel_mix(&h, e->key_end, e->kelen);
    kel_mix(&h, &end, sizeof(end));
    s->sum += kel_fmix(h);
    s->n++;
}

static void kel_reset(void *arg) {
    struct kel_sum *s = arg;
    s->sum = s->n = 0;
}

struct kel_sets {
    struct nfd_set v[256];
    size_t n;
    int over;
};

static void kel_set(void *arg, const struct nfd_set *s) {
    struct kel_sets *c = arg;
    if (s->flags & (KEL_ANONYMOUS | KEL_MAP | KEL_EVAL | KEL_OBJECT)) return;
    if (!strcmp(s->name, FAILOPEN_SET)) return;
    /* Префикс хоста у донора IPv6: элементы ведёт сторож (v6donor_sync, failover.c) — выведенный
     * префикс меняется без смены спеки, и сверка считала бы каждое такое изменение чужой правкой. */
    if (!strcmp(s->name, V6DONOR_SET)) return;
    if (c->n == sizeof(c->v) / sizeof(c->v[0])) { c->over = 1; return; }
    c->v[c->n++] = *s;
}

int recon_kernel_elems(uint64_t *sum, uint64_t *n) {
    *sum = *n = 0;
    static struct kel_sets sets;
    memset(&sets, 0, sizeof(sets));
    if (nfd_sets(nft_table(), kel_set, &sets) != 0 || sets.over) return -1;
    uint64_t total = 0, total_n = 0;
    for (size_t i = 0; i < sets.n; i++) {
        const struct nfd_set *st = &sets.v[i];
        struct kel_sum s = { (st->flags & KEL_TIMEOUT) != 0, 0, 0 };
        /* Доменный набор пишет и резолвер — дамп, посреди которого прошла транзакция, заново
         * (шапка); три таких подряд — «не прочитать». */
        int stable = 0;
        for (int tries = 0; !stable; tries++) {
            if (tries == 3) return -1;
            kel_reset(&s);
            if (nfd_set_elems(st->family, nft_table(), st->name, kel_elem, kel_reset, &s,
                              &stable) != 0)
                return -1;
            if (!s.partial) stable = 1;
        }
        uint64_t h = KEL_FNV_INIT;
        kel_mix(&h, &st->family, sizeof(st->family));
        kel_mix(&h, st->name, strlen(st->name) + 1);
        kel_mix(&h, &s.n, sizeof(s.n));
        kel_mix(&h, &s.sum, sizeof(s.sum));
        total += kel_fmix(h);
        total_n += s.n;
    }
    *sum = total;
    *n = total_n;
    return 0;
}

/* Строка ребёнка apply-commit: `recon-kernel НОМЕР ОТПЕЧАТОК СВОДКА ЧИСЛО` (шестнадцатеричные,
 * число — десятичное; «-» вместо сводки и числа — сводку снять не вышло) или `recon-kernel -` —
 * не вышло ничего. Слово своё и в начале строки: человеку в ответе apply она не показывается
 * (recon_kernel_take вырезает её в демоне). */
#define RK_WORD "recon-kernel "

void recon_kernel_print(FILE *f) {
    struct nfd_tfp t;
    if (kernel_fp(&t) != 0 || !(t.fams & 1)) {
        fprintf(f, RK_WORD "-\n");
        return;
    }
    fprintf(f, RK_WORD "%016llx %016llx", (unsigned long long)t.handle, (unsigned long long)t.fp);
    uint64_t el = 0, en = 0;
    if (recon_kernel_elems(&el, &en) == 0)
        fprintf(f, " %016llx %llu\n", (unsigned long long)el, (unsigned long long)en);
    else
        fprintf(f, " - -\n");
}

void recon_kernel_take(char *text, size_t *n, struct recon_kernel *k) {
    memset(k, 0, sizeof(*k));
    if (!text) return;
    const size_t wl = sizeof(RK_WORD) - 1;
    for (size_t i = 0; i + wl <= *n; ) {
        char *ln = text + i;
        char *e = memchr(ln, '\n', *n - i);
        size_t len = e ? (size_t)(e - ln) + 1 : *n - i;
        if (len > wl && !memcmp(ln, RK_WORD, wl)) {
            char buf[128];
            size_t bl = len - wl < sizeof(buf) - 1 ? len - wl : sizeof(buf) - 1;
            memcpy(buf, ln + wl, bl);
            buf[bl] = '\0';
            unsigned long long h, f, el, en;
            int got = sscanf(buf, "%llx %llx %llx %llu", &h, &f, &el, &en);
            if (got >= 2) {
                k->ok = 1;
                k->handle = h;
                k->kfp = f;
            }
            if (got == 4) {
                k->el_ok = 1;
                k->el = el;
                k->el_n = en;
            }
            memmove(ln, ln + len, *n - i - len);
            *n -= len;
            text[*n] = '\0';          /* внутри прежней длины: строка стала короче */
            continue;
        }
        i += len;
    }
}

int recon_watch_changed(struct recon_state *st, const struct recon_plan *p) {
    int changed = !st->wvalid || st->wn != p->n;
    for (size_t i = 0; i < p->n && !changed; i++) {
        size_t k = 0;
        while (k < st->wn && strcmp(st->w[k].name, p->out[i].name)) k++;
        if (k == st->wn || st->w[k].wsig != p->out[i].wsig) changed = 1;
    }
    if (p->n > st->wcap) {
        void *nw = realloc(st->w, p->n * sizeof(*st->w));
        if (!nw) { st->wvalid = 0; st->wn = 0; return 1; }   /* не запомнили — в следующий раз «изменилось» */
        st->w = nw;
        st->wcap = p->n;
    }
    for (size_t i = 0; i < p->n; i++) {
        snprintf(st->w[i].name, sizeof(st->w[i].name), "%s", p->out[i].name);
        st->w[i].wsig = p->out[i].wsig;
    }
    st->wn = p->n;
    st->wvalid = 1;
    return changed;
}

/* ---- номер таблицы по netlink ------------------------------------------------------------------
 *
 * Один запрос NFT_MSG_GETTABLE с именем таблицы: ответ несёт NFTA_TABLE_HANDLE — номер, который
 * ядро выдаёт каждой новой таблице из общего счётчика (с Linux 4.16). Наш nft -f удаляет таблицу
 * и создаёт её заново, то есть после каждого применения номер новый, а резолвер, который кладёт в
 * наборы адреса, номер не меняет. Запуска nft это не стоит: сверка неизменной спеки не зовёт ни
 * одного процесса. Срок ответа — секунда: ядро отвечает сразу, а зависнуть циклу демона на
 * сокете нельзя. */
#ifndef NFTA_TABLE_HANDLE
#define NFTA_TABLE_HANDLE 4
#endif

int recon_table_handle(const char *name, uint64_t *h) {
    *h = 0;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0) return -1;
    struct timeval tv = { 1, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    union { struct nlmsghdr nh; char b[256]; } req;
    memset(&req, 0, sizeof(req));
    size_t nl = strlen(name) + 1;
    struct nfgenmsg *g = (struct nfgenmsg *)NLMSG_DATA(&req.nh);
    g->nfgen_family = NFPROTO_INET;
    g->version = NFNETLINK_V0;
    struct nlattr *a = (struct nlattr *)((char *)g + NLMSG_ALIGN(sizeof(*g)));
    a->nla_type = NFTA_TABLE_NAME;
    a->nla_len = (uint16_t)(NLA_HDRLEN + nl);
    memcpy((char *)a + NLA_HDRLEN, name, nl);
    req.nh.nlmsg_len = (uint32_t)(NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*g)) + NLA_ALIGN(a->nla_len));
    req.nh.nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETTABLE;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nh.nlmsg_seq = 1;
    if (sendto(fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    int rc = -1, done = 0;
    _Alignas(struct nlmsghdr) char buf[8192];
    while (!done) {
        ssize_t m = recv(fd, buf, sizeof(buf), 0);
        if (m < 0 && errno == EINTR) continue;
        if (m <= 0) break;
        for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (size_t)m);
             nh = NLMSG_NEXT(nh, m)) {
            if (nh->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *er = NLMSG_DATA(nh);
                if (er->error == -ENOENT) rc = 1;
                else if (er->error != 0) rc = -1;
                done = 1;
                break;
            }
            if (nh->nlmsg_type == NLMSG_DONE) { done = 1; break; }
            if ((nh->nlmsg_type & 0xff) != NFT_MSG_NEWTABLE) continue;
            rc = 0;
            const char *p = (const char *)NLMSG_DATA(nh) + NLMSG_ALIGN(sizeof(struct nfgenmsg));
            const char *e = (const char *)nh + nh->nlmsg_len;
            while (p + NLA_HDRLEN <= e) {
                const struct nlattr *at = (const struct nlattr *)p;
                if (at->nla_len < NLA_HDRLEN || p + at->nla_len > e) break;
                if ((at->nla_type & NLA_TYPE_MASK) == NFTA_TABLE_HANDLE &&
                    at->nla_len >= NLA_HDRLEN + 8) {
                    uint64_t v;
                    memcpy(&v, p + NLA_HDRLEN, 8);
                    *h = be64toh(v);
                }
                p += NLA_ALIGN(at->nla_len);
            }
        }
    }
    close(fd);
    return rc;
}
