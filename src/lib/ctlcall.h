/* Разговор с управляющим сокетом демона со стороны спрашивающего (протокол v1, docs/ctl.md).
 *
 * ЗАЧЕМ ОБЩИМ ФАЙЛОМ. Спрашивают демон двое: клиент `steer` (src/client/main.c) — им идут
 * status, diag, apply и остальные команды демона, — и сам движок steerd, когда его позвали
 * подкомандой мимо клиента при живом демоне (rpcd на роутере зовёт `steerd status` напрямую).
 * У подкоманды нет памяти демона: ход перебора узлов vless, замеры групп, живое состояние
 * помощников знает только он, и ответ подкоманды был бы неполным. Разбор ответа — ровно то,
 * что пишет сервер (src/daemon/ctl.c), и двух копий у него быть не должно.
 *
 * Файл живёт в самом нижнем слое (src/lib) и зависит только от libc и выбора платформы (путь
 * сокета по умолчанию): клиент весит десятки килобайт и остаётся таким. */
#ifndef STEER_CTLCALL_H
#define STEER_CTLCALL_H

#include <stddef.h>

/* Пределы протокола v1 — те же, что у сервера (src/daemon/ctl.c, CTL_LINE_MAX, CTL_BODY_MAX). */
#define CTLCALL_LINE_MAX 512
#define CTLCALL_BODY_MAX (1024L * 1024L)

struct ctlcall_str { char *p; size_t n; };

/* Ответ сервера: код и вывод одноимённой подкоманды, отказ сервера (error, message), чью спеку он
 * обслуживает (version), флаги apply. Строки — malloc'ом, освобождает ctlcall_resp_free. */
struct ctlcall_resp {
    int has_code, code;
    struct ctlcall_str out, err, error, message, spec_path, state_dir;
    struct ctlcall_str ecode, args;    /* слово отказа подкоманды (docs/errors.md) и объект подстановок как текст JSON */
    int truncated, enabled, applied;   /* -1 — поля нет (truncated — 0) */
};

/* Сокет: path, иначе STEER_SOCKET, иначе путь платформы. Возвращает выбранный путь. */
const char *ctlcall_socket(const char *path);

/* Соединиться (срок чтения timeout_s; 0 — без срока). -1 — нет. */
int ctlcall_open(int timeout_s);

/* Один запрос — один ответ: строка JSON до '\n' (malloc; без '\n'). NULL — соединения нет или
 * ответ не пришёл за срок. */
char *ctlcall_roundtrip(const char *line, const char *body, size_t body_n, int timeout_s);

/* Разобрать ответ. 0 — разобран. */
int ctlcall_parse(const char *s, struct ctlcall_resp *r);
void ctlcall_resp_free(struct ctlcall_resp *r);

/* Демон на сокете обслуживает эти же спеку и каталог состояния (NULL — умолчания платформы)?
 * Пути сверяются после realpath; пара spec.json/spec.yaml — по лежащему файлу. timeout_s — срок
 * ответа на version. */
int ctlcall_same_daemon(const char *spec, const char *state_dir, int timeout_s);

/* Читающую команду line (с '\n') — демону этих спеки и каталога состояния: его stdout и stderr —
 * в свои, возврат — его код. -1 — демона нет, он чужой, не ответил, отказал без кода или обрезал
 * вывод: тогда не напечатано ничего, и вызывающий отвечает сам. */
int ctlcall_forward(const char *line, const char *spec, const char *state_dir, int timeout_s);

#endif
