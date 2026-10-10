#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "spec.h"
#include "registry.h"

/* Marks and tables live well away from what splify (0x40000/0x80000, tables
 * 200/202) and mwan3 use, so both can run on one box while the migration is in
 * progress. One bit per output keeps `nft` output readable. */
/* База метки и число бит — в spec.h: их знает не только распорядитель, но и тот, кто
 * ставит правило и генерирует ruleset, а маска выводится из них же. */
#define MARK_BASE   STEER_MARK_BASE
/* Первый номер таблицы — данные профиля (src/profile/profile.h): у мини-сборки tgws свой ряд
 * (316), почему — в src/profile/tgws.c. Полный движок берёт 300 и дальше, минуя 316
 * (steer_slot_table ниже), — сколько, решает поле метки (marks.h). */
#define TABLE_BASE  (prof()->table_base)

/* Номер таблицы маршрутизации места и место таблицы (-1 — таблица не из нашего ряда).
 *
 * Ряд — TABLE_BASE + место, но у полного движка (база 300) ряд ОБХОДИТ номер 316: это таблица
 * мини-сборки tgws (profile/tgws.c, .table_base = 316), которая ставится рядом и уже стоит на
 * роутерах с этим номером. Раньше ряд просто кончался на 315, теперь он длиннее — поэтому номера
 * с 316 сдвинуты на один вверх, а места 0..15 остались с прежними таблицами 300..315. Верхняя
 * граница ряда — не константа: место выдаёт только поле метки (steer_mark_slots, marks.h). */
#define TGWS_TABLE 316
static int steer_slot_table(unsigned slot) {
    int t = TABLE_BASE + (int)slot;
    return TABLE_BASE < TGWS_TABLE && t >= TGWS_TABLE ? t + 1 : t;
}
static int steer_table_slot(int table) {
    int t = table - TABLE_BASE;
    if (t < 0) return -1;
    if (TABLE_BASE < TGWS_TABLE && table == TGWS_TABLE) return -1;
    if (TABLE_BASE < TGWS_TABLE && table > TGWS_TABLE) t--;
    return (unsigned)t < steer_mark_slots() ? t : -1;
}

/* ---- mark/table registry -------------------------------------------------- */
/* Persisted, because an output must keep its mark across restarts: a reboot that
 * reshuffles marks leaves stale `ip rule` entries pointing at the wrong table,
 * and the symptom is traffic silently taking someone else's path. */
static void rt_tables_write(const struct spec *s);

int registry_assign(struct spec *s, struct err *e) {
    char path[512];
    snprintf(path, sizeof(path), "%s/registry", steer_state_dir());
    FILE *f = fopen(path, "r");
    if (f) {
        char name[32];
        unsigned mark;
        int table;
        while (fscanf(f, "%31s %x %d\n", name, &mark, &table) == 3) {
            /* Метка вне НАШЕЙ маски — не наша: реестр остался от сборки с другим диапазоном
             * (мини-сборка до своего бита писала 08000000). Взять её значило бы ставить
             * `and ~маска or метка` с битом за пределами маски, который сравнение
             * `mark and маска == метка` не увидит никогда, — то есть правило стоит, а не
             * срабатывает. Такой выход получает метку заново, как новый. */
            if (!mark || (mark & ~STEER_MARK_MASK)) continue;
            for (size_t i = 0; i < s->out_n; i++)
                if (!strcmp(s->out[i].name, name) && out_needs_mark(&s->out[i])) {
                    s->out[i].mark = mark;
                    s->out[i].table = table;
                }
        }
        fclose(f);
    }
    int from_top = getenv("STEER_MARK_ORDER") &&
                   !strcmp(getenv("STEER_MARK_ORDER"), "top");

    /* ЗАНЯТЫЕ МЕСТА. Место — это пара «метка, таблица»: метка `база * (место + 1)` и
     * таблица `TABLE_BASE + место`. Занятость считается по ОБОИМ полям, и вот почему.
     *
     * До перехода на значения выход получал бит, то есть метку `база << номер`. У
     * старших битов это база, умноженная на 16, 32, 64 и 128, — такого значения новая
     * раздача не выдаст никому (места идут подряд от нуля, в пределах числа слотов метки), поэтому по метке эти
     * выходы не опознать (steer_value_slot ответит -1). Зато их ТАБЛИЦА всегда лежала в
     * 300..307, то есть в пределах ряда, — по ней место и занимается. Так реестр, доживший с прежней сборки,
     * переживает обновление без единой перетасовки: метка остаётся та, что уже стоит в
     * пакетах и правилах, а новые выходы просто садятся на свободные места. */
    unsigned nslots = STEER_MARK_SLOTS;   /* мест — сколько даёт поле метки (marks.h) */
    unsigned char *taken = calloc(nslots ? nslots : 1, 1);
    if (!taken) return err_set(e, "%s", "out of memory: mark slot table");
    for (size_t i = 0; i < s->out_n; i++) {
        if (!s->out[i].mark) continue;
        if (s->out[i].mark % MARK_BASE == 0) {
            int sl = steer_value_slot(s->out[i].mark / MARK_BASE);
            if (sl >= 0) taken[sl] = 1;
        }
        int sl = steer_table_slot(s->out[i].table);
        if (sl >= 0) taken[sl] = 1;
    }

    for (size_t i = 0; i < s->out_n; i++) {
        /* Место в реестре (метку и таблицу) получает выход со своей меткой — все виды, кроме
         * direct (out_needs_mark). */
        if (!out_needs_mark(&s->out[i]) || s->out[i].mark) continue;
        /* СВЕРХУ ИЛИ СНИЗУ. Обычно места раздаются снизу: первый выход получает нулевое,
         * второй первое и так далее. Но на роутере движок бывает не один — рядом с полным
         * ставится микропакет tgws со своей спекой и своим состоянием, — и оба, начав с
         * нуля, выдали бы своим выходам ОДНУ И ТУ ЖЕ метку. Метка живёт в пакете, а не в
         * таблице: правило маршрутизации одного экземпляра увело бы трафик другого в свою
         * таблицу, и раздельными таблицами правил это не лечится.
         *
         * Поэтому второй экземпляр запускается с STEER_MARK_ORDER=top и раздаёт места
         * сверху вниз. Из места выводятся и метка, и номер таблицы маршрутизации, и порт
         * моста, и очередь обхода, — значит одной этой переменной хватает, чтобы развести
         * экземпляры целиком. */
        unsigned slot = 0;
        int found = 0;
        if (from_top) {
            for (unsigned k = nslots; k-- > 0;)
                if (!taken[k]) { slot = k; found = 1; break; }
        } else {
            for (unsigned k = 0; k < nslots; k++)
                if (!taken[k]) { slot = k; found = 1; break; }
        }
        if (!found) {
            /* Настоящий предел раскладки, и называется он цифрами раскладки, а не константой
             * кода: сколько мест даёт поле метки, какие это биты и сколько уже занято. */
            char msg[400];
            snprintf(msg, sizeof(msg), "out of mark slots for output %.31s: outputs with a mark are at most "
                     "%u (mark field is %d bits, %d-%d; values that a neighbour's rewrite of bits "
                     "16-23 could turn into another output's mark are not handed out), and all %u "
                     "are taken", s->out[i].name, nslots, (int)STEER_MARK_BITS, STEER_MARK_LOBIT,
                     STEER_MARK_HIBIT, nslots);
            free(taken);
            return err_set(e, "%s", msg);
        }
        taken[slot] = 1;
        s->out[i].mark = MARK_BASE * steer_slot_value(slot);
        s->out[i].table = steer_slot_table(slot);
    }
    free(taken);
    /* Прежде чем писать — сравнить с тем, что уже на диске. registry_assign
     * зовут все подкоманды, включая status, который интерфейс опрашивает каждые
     * пять секунд: безусловная перезапись — это ~17 тысяч записей файла в сутки
     * с неизменным содержимым. Сравнивается будущий текст целиком, а не «были ли
     * новые назначения»: перезапись заодно вычищает строки исчезнувших выходов,
     * и пропускать её можно только когда файл уже дословно совпадает. */
    /* Строка — не больше 96 байт (имя ≤ 31, метка ≤ 8, таблица ≤ 11, пробелы и конец строки), и
     * буфер берётся по числу выходов, а не по числу выходов, которое кто-то когда-то назвал
     * пределом. */
    size_t wcap = s->out_n * 96 + 1, wn = 0;
    char *want = malloc(wcap);
    if (!want) return err_set(e, "%s", "out of memory: registry text");
    for (size_t i = 0; i < s->out_n; i++)
        if (out_needs_mark(&s->out[i])) {
            int w = snprintf(want + wn, wcap - wn, "%s %x %d\n",
                             s->out[i].name, s->out[i].mark, s->out[i].table);
            if (w < 0 || (size_t)w >= wcap - wn) break; /* не бывает, но не рвём буфер */
            wn += (size_t)w;
        }
    f = fopen(path, "r");
    if (f) {
        char *have = malloc(wn + 1);
        size_t hn = have ? fread(have, 1, wn + 1, f) : (size_t)-1;
        fclose(f);
        int same = have && hn == wn && memcmp(have, want, wn) == 0;
        free(have);
        if (same) { free(want); return 0; }
    }
    mkdir(steer_state_dir(), 0755);
    f = fopen(path, "w");
    if (!f) { free(want); return 0; }   /* best effort: apply still works, next boot re-assigns */
    fwrite(want, 1, wn, f);
    fclose(f);
    free(want);
    rt_tables_write(s);
    return 0;
}

/* Объявить имена таблиц маршрутизации системе.
 *
 * ЗАЧЕМ. Номера таблиц (300, 301, ...) не говорят ничего: `ip route show table 300` требует
 * помнить, какой выход это был, а `ip rule show` печатает номер. iproute2 умеет имена —
 * для этого и существует /etc/iproute2/rt_tables.d, — и тогда диагностика становится
 * обычной: `ip route show table steer_vpn`. Проверено на живом роутере (10.8.1.87,
 * OpenWrt 25.12 с ip-full): имя из rt_tables.d принимается и в add, и в show.
 *
 * ПОЧЕМУ КАТАЛОГ, А НЕ САМ rt_tables. Файл rt_tables принадлежит пакету iproute2;
 * дописывать в чужой файл значило бы драться с его обновлением. Каталог .d для этого и
 * заведён.
 *
 * ПОЧЕМУ СРАВНЕНИЕ ПЕРЕД ЗАПИСЬЮ. registry_assign зовут все подкоманды, включая status,
 * который интерфейс опрашивает каждые пять секунд, — это та же причина, по которой не
 * перезаписывается сам реестр (см. выше): безусловная запись означала бы ~17 тысяч записей
 * файла в сутки с неизменным содержимым.
 *
 * Отказ здесь ничего не ломает: имена — удобство диагностики, номера работают и без них.
 * Поэтому молча, без предупреждений: на busybox-ip имён нет вовсе, и жаловаться было бы не
 * на что. */
static void rt_tables_write(const struct spec *s) {
    /* Платформа без каталога имён (телефон: /etc там — ссылка в системный раздел только для
     * чтения, src/platform/android.c) — и mkdir в чужой системный каталог при каждом status
     * пробовать незачем. */
    const char *dir = steer_rt_tables_dir();
    if (!dir) return;
    char path[512];
    /* Файл — свой у каждого профиля: мини-сборка с тем же именем перезаписывала бы имена таблиц
     * полного движка своими. */
    snprintf(path, sizeof(path), "%s/%s", dir, prof()->rt_tables_file);

    size_t wcap = s->out_n * 64 + 1, wn = 0;   /* «таблица steer_имя\n» — не больше 64 байт */
    char *want = malloc(wcap);
    if (!want) return;
    for (size_t i = 0; i < s->out_n; i++) {
        if (!out_needs_mark(&s->out[i]) || !s->out[i].table) continue;
        /* Имя с приставкой: таблица принадлежит выходу, но пространство имён общее для всей
         * коробки, и «vpn» там заняли бы и mwan3, и человек руками. */
        int w = snprintf(want + wn, wcap - wn, "%d steer_%s\n",
                         s->out[i].table, s->out[i].name);
        if (w < 0 || (size_t)w >= wcap - wn) break;
        wn += (size_t)w;
    }

    FILE *f = fopen(path, "r");
    if (f) {
        char *have = malloc(wn + 1);
        size_t hn = have ? fread(have, 1, wn + 1, f) : (size_t)-1;
        fclose(f);
        int same = have && hn == wn && memcmp(have, want, wn) == 0;
        free(have);
        if (same) { free(want); return; }
    }
    /* Каталога может не быть: iproute2 создаёт его не всегда, а на busybox-сборке его нет
     * вовсе. mkdir по одному уровню — родителя (/etc/iproute2) тоже может не быть. */
    char parent[512];
    snprintf(parent, sizeof(parent), "%s", dir);
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) { *slash = '\0'; mkdir(parent, 0755); }
    mkdir(dir, 0755);
    f = fopen(path, "w");
    if (f) {
        fwrite(want, 1, wn, f);
        fclose(f);
    }
    free(want);
}
