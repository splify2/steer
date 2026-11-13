/* Дополнение к стандартной раскладке lld (INSERT): выбросить .pdr — описатели процедур MIPS для отладчика,
 * которые clang кладёт в каждый объект. Секция без SHF_ALLOC, и `-s` её не снимает (0,4 МБ на mipsel в 2.1.3).
 * Подключает build/build-libs.sh целям MIPS. */
SECTIONS { /DISCARD/ : { *(.pdr) } } INSERT AFTER .text;
