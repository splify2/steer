/* Проверка подписи Ed25519 в формате usign/signify (src/lib/sigverify.c).
 *
 * Формат файла — две текстовые строки: «untrusted comment: …» и base64 от байтов
 *   публичный ключ:  "Ed" ‖ keynum(8) ‖ ключ(32)
 *   подпись:         "Ed" ‖ keynum(8) ‖ подпись(64)
 * Подпись берётся над самим сообщением (usign и signify -S без -z). Алгоритм «ED» (подпись над
 * BLAKE2b/SHA-512 дайджестом, новые версии signify) не поддержан и отвергается как SIGV_EALG:
 * пакеты подписываются usign. Криптография — sc_ed25519_verify (scrypto.h). */
#ifndef STEER_SIGVERIFY_H
#define STEER_SIGVERIFY_H
#include <stddef.h>
#include "scrypto.h"

#define SIGV_EFORMAT  (-1)   /* файл не разбирается: нет строки с base64, не base64, чужая длина */
#define SIGV_EALG     (-2)   /* алгоритм не «Ed» */
#define SIGV_EKEYNUM  (-3)   /* keynum подписи не совпал с keynum ключа (подпись другим ключом) */
#define SIGV_EBAD     (-4)   /* подпись не сошлась: сообщение или подпись испорчены */
#define SIGV_EIO      (-5)   /* файл не прочитался (sigv_check_file) */
#define SIGV_ENOMEM   (-6)

struct sigv_key {
    unsigned char keynum[8];
    unsigned char pk[SC_ED25519_PK];
};
struct sigv_sig {
    unsigned char keynum[8];
    unsigned char sig[SC_ED25519_SIG];
};

/* Разобрать публичный ключ / подпись из текста файла (n байт, завершающий ноль не нужен). Строки
 * могут кончаться «\n» или «\r\n»; хвост после второй строки отвергается, лишние пробелы — нет. */
int sigv_parse_key(const char *text, size_t n, struct sigv_key *k);
int sigv_parse_sig(const char *text, size_t n, struct sigv_sig *s);

/* Сверить keynum и подпись над msg. 0 — верна. */
int sigv_verify(const struct sigv_key *k, const struct sigv_sig *s, const void *msg, size_t msg_n);

/* Из набора доверенных ключей выбрать тот, чей keynum в подписи, и проверить. Возвращает индекс
 * ключа (>= 0) или отказ: SIGV_EKEYNUM, когда ключа с таким keynum в наборе нет. keynum — не
 * секрет и не защита (его можно подделать), он лишь отличает «чужой ключ» от «испорченная подпись». */
int sigv_verify_any(const struct sigv_key *keys, size_t nkeys, const struct sigv_sig *s,
                    const void *msg, size_t msg_n);

/* ПОДПИСЬ ИЗ НЕСКОЛЬКИХ БЛОКОВ (ротация ключей, s2p.md): файл — один или больше блоков по две строки,
 * по одному на ключ издателя. Число блоков не ограничено. sigv_parse_sigs разбирает файл целиком; блок
 * с чужим алгоритмом или испорченным base64 — отказ всего файла. */
struct sigv_sigs {
    struct sigv_sig *v;
    size_t n;
};
int sigv_parse_sigs(const char *text, size_t n, struct sigv_sigs *out);
void sigv_sigs_free(struct sigv_sigs *s);

/* Годится любой блок, для которого в наборе есть ключ с тем же keynum и подпись сходится: возвращает
 * индекс ПОДПИСАВШЕГО блока в s->v (>= 0); *key_idx (если не NULL) — индекс его ключа в keys. Ни один
 * не годится: SIGV_EKEYNUM, если ни у одного блока нет ключа в наборе (вызывающий назовёт номера из
 * s->v[i].keynum — sigv_keynum_hex), иначе SIGV_EBAD. Роль ключа и отозванные номера — дело вызывающего:
 * он собирает в keys только годные ключи. */
int sigv_verify_blocks(const struct sigv_key *keys, size_t nkeys, const struct sigv_sigs *s,
                       const void *msg, size_t msg_n, size_t *key_idx);

/* Номер ключа строчными hex-знаками (16 знаков и ноль) — так его пишет usign -F. */
void sigv_keynum_hex(const unsigned char keynum[8], char out[17]);

/* То же над файлом целиком (читается в память: Ed25519 хеширует сообщение до подписи, потоком его
 * не проверить). */
int sigv_check_file(const struct sigv_key *k, const struct sigv_sig *s, const char *path);

#endif
