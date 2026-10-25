/* Распаковка ustar (+gzip) в каталог с защитой от выхода за него (src/lib/untar.c).
 *
 * Для пакетов плагинов: архив приходит из сети и подписан, но распаковщик не верит и подписи —
 * путь с «..», абсолютный путь, запись сквозь символьную ссылку и ссылка наружу отвергаются
 * здесь, а не там, где вызывающий «обязан был проверить». Разбор формата — ровно то, что нужно
 * пакету: обычные файлы, каталоги, символьные ссылки; ustar с префиксом, GNU-длинные имена (L, K)
 * и pax-заголовки (x, g: path, linkpath, size). Жёсткие ссылки, устройства и очереди — отказ.
 *
 * ПОРЯДОК И ХЕШИ. Для каждой записи, по мере распаковки, зовётся обратный вызов; у файла в нём
 * уже лежит SHA-256 записанных байт — MANIFEST пакета сверяет хеши, не перечитывая файлы.
 * Вызов идёт после записи файла целиком: ненулевой ответ прерывает распаковку (UNTAR_ECB), а то,
 * что уже лежит на диске, убирает вызывающий (весь dest — временный каталог пакета).
 *
 * dest создаётся, если его нет (один уровень); файл, который уже есть, — отказ (O_EXCL): распаковка
 * идёт в пустой каталог. Права: mode & 0777 (setuid/setgid/sticky не переносятся), владелец и время
 * не переносятся; права каталогов выставляются в самом конце, чтобы закрытый каталог не мешал
 * положить в него файлы. Предела на размеры и числа нет; max_bytes — выбор вызывающего (0 — без
 * предела), он сверяется по объявленным размерам до записи файла. */
#ifndef STEER_UNTAR_H
#define STEER_UNTAR_H
#include <stddef.h>

#define UNTAR_FILE    1
#define UNTAR_DIR     2
#define UNTAR_SYMLINK 3

struct untar_entry {
    const char *path;               /* нормализованный путь внутри dest: без «./», «//», «..» */
    int type;                       /* UNTAR_FILE, UNTAR_DIR, UNTAR_SYMLINK */
    unsigned mode;                  /* mode & 0777 из архива */
    unsigned long long size;        /* размер файла; у каталога и ссылки 0 */
    unsigned char sha256[32];       /* SHA-256 содержимого файла; у остальных нули */
    const char *link;               /* цель символьной ссылки, иначе NULL */
};

/* 0 — продолжать; иное — прервать. Указатели живут только на время вызова. */
typedef int (*untar_cb)(void *arg, const struct untar_entry *e);

struct untar_opts {
    untar_cb cb;                    /* может быть NULL */
    void *arg;
    unsigned long long max_bytes;   /* предел суммы размеров файлов; 0 — без предела */
};

#define UNTAR_EFORMAT (-1)          /* не tar: заголовок, контрольная сумма, обрыв посреди записи */
#define UNTAR_EPATH   (-2)          /* путь или ссылка выходит за dest, либо идёт сквозь ссылку */
#define UNTAR_ETYPE   (-3)          /* тип записи не поддержан (жёсткая ссылка, устройство…) */
#define UNTAR_EGZ     (-4)          /* gzip испорчен или оборван */
#define UNTAR_EIO     (-5)          /* файловая система отказала */
#define UNTAR_ECB     (-6)          /* обратный вызов прервал распаковку */
#define UNTAR_EBIG    (-7)          /* сумма размеров больше max_bytes */
#define UNTAR_ENOMEM  (-8)

/* Все три: 0 — распаковано; отрицательное — код выше, why (если не NULL) — одной строкой. */
int untar_gz(const void *gz, size_t n, const char *dest, const struct untar_opts *o, char *why, size_t wn);
/* Файл .tar.gz отображается в память (mmap): размер архива адресным пространством и не ограничен. */
int untar_gz_file(const char *path, const char *dest, const struct untar_opts *o, char *why, size_t wn);
/* Несжатый tar из памяти. */
int untar_mem(const void *tar, size_t n, const char *dest, const struct untar_opts *o, char *why, size_t wn);

#endif
