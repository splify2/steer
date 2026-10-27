/* Устройство AmneziaWG/WireGuard по файлу — слой под видом awg (src/kinds/awgdev.c). Общий у вида awg ядра
 * и программы плагина warpbox: модели спеки в нём нет. */
#ifndef STEER_AWGDEV_H
#define STEER_AWGDEV_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "awg.h"

struct kind_name;

struct awg_live_peer {
    uint8_t pub[AWG_KEY_LEN];
    int64_t hs;                     /* время последнего рукопожатия, секунды эпохи; 0 — не было */
    uint64_t rx, tx;
    struct sockaddr_storage ep;
    socklen_t ep_len;
};

struct awg_live {
    size_t peer_n;
    struct awg_live_peer peer[AWG_MAX_PEERS * 2];
    uint32_t fwmark;
};

/* Поднять и настроить устройство dev по файлу conf_path: создать, если нет (amneziawg, при
 * отсутствии модуля и файле без обфускации — wireguard), настроить одним сообщением, MTU, адреса,
 * подъём. fwmark — метка сокета туннеля (подложка или «мимо каналов»); via — имя подложки (только
 * для слов журнала и правила «через подложку — только IPv4»), NULL — напрямую. who — как назвать
 * в журнале («выход nl»). loud — предупреждения о файле; fresh — пиры заново (новая сессия);
 * names — ответы сторожа на имена Endpoint (NULL — разрешить самим). 0 — готово. */
int awg_dev_configure(const char *who, const char *dev, const char *conf_path, uint32_t fwmark,
                      const char *via, int loud, int fresh, const struct kind_name *names, size_t nn);

/* Устройство: 0 — есть (kind — вид ядра, index — номер; оба необязательны), иначе errno. */
int awg_dev_link_query(const char *ifname, char *kind, size_t kn, int *index);
int awg_dev_link_delete(const char *ifname);
/* Вид устройства — наш туннель (amneziawg или wireguard). */
int awg_dev_ours(const char *kind);
/* Пиры устройства из ядра (рукопожатие, счётчики, эндпоинт). 0 — прочитано. */
int awg_dev_live_read(const char *ifname, const char *kind, struct awg_live *L);
/* Забыть файлы состояния устройства (подпись параметров, замер счётчиков). */
void awg_dev_state_drop(const char *dev);
/* Обрезать пробелы по краям (на месте). */
char *awg_dev_trim(char *s);

#endif
