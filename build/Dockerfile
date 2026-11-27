# Кросс-компилятор для steer: musl-статика под все архитектуры OpenWrt плюс исходники
# wolfSSL для расширенной части (VLESS/Reality, xsteer, мост tgws).
#
# Почему zig, а не набор тулчейнов: движку нужен статический musl-бинарник, и Debian'ов
# cross-gcc здесь не годится дважды — статический glibc это ~800 КБ на 35 КБ программы
# при 7 МБ флеша, а его mipsel-цель собрана под HARD FLOAT, тогда как OpenWrt mipsel_24kc
# работает на soft-float: такой бинарник умирает с SIGILL на Mi Router 4C, то есть пакет
# ставится, а демон не может запуститься ни разу. Один zig на 45 МБ покрывает все ISA.
#
# Почему wolfSSL ИСХОДНИКАМИ, а не пакетом libwolfssl OpenWrt:
#
# Reality, TLS 1.3 и xsteer — это X25519, HKDF, ChaCha20-Poly1305 и AES-GCM. Писать это самому
# было бы худшим решением в проекте: ошибка в криптографии не ломается заметно, она тихо
# перестаёт защищать. Пакет libwolfssl в OpenWrt есть, но собран без QUIC (включить его опцией
# меню нельзя), а его SONAME несёт хеш опций (libwolfssl.so.5.9.1.e624513f) и меняется с каждым
# обновлением — бинарник, слинкованный с ним, ломается (docs/architecture.md, «Криптография»).
# Поэтому исходники едут в образ и компилируются тем же zig, что и остальное, со
# своими опциями (build/wolfssl/user_settings.h): у бинарника СВОЯ wolfSSL, и что именно оказалось
# на роутере, его не касается вовсе. Пакетом libsteer-wolfssl (.so) эта же сборка станет на шаге 4.
#
# Прежде здесь лежала mbedtls 3.6.2; она снята целиком (решение владельца 2026-09-28: QUIC в ней нет,
# второго криптостека на флеше владелец не хочет). Образ с ней — прежний тег steer-builder:mbedtls,
# этот — steer-builder:wolfssl (build.sh, STEER_BUILDER_IMAGE).
FROM alpine:3.20

ARG ZIG_VERSION=0.13.0
ARG ZIG_SHA256=d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea

RUN apk add --no-cache curl xz python3 openssl binutils \
 && curl -fsSL -o /tmp/zig.tar.xz \
      "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz" \
 && echo "${ZIG_SHA256}  /tmp/zig.tar.xz" | sha256sum -c - \
 && mkdir -p /opt && tar xf /tmp/zig.tar.xz -C /opt \
 && ln -s "/opt/zig-linux-x86_64-${ZIG_VERSION}/zig" /usr/local/bin/zig \
 && rm /tmp/zig.tar.xz \
 && zig version

# Zig 0.13: libc.S использует PTR32 для экспортов time64, но задаёт только PTR64.
# Определяем его в 32-битной ветке импортной libc; сам libc роутера не меняется.
RUN sed -i '/^#define WEAK64 \.globl$/i #define PTR32' "/opt/zig-linux-x86_64-${ZIG_VERSION}/lib/libc/musl/libc.S"

# ВЕРСИЯ wolfSSL И ЕЁ СУММА ЗАПИСАНЫ НЕ ЗДЕСЬ, а в build/wolfssl/fetch.sh — одном месте на все
# сборки (образ, стенды на хосте, проверку под телефон): образ копирует скрипт и зовёт его. Скрипт
# сверяет sha256 тарбола и отказывается распаковывать несошедшийся (I-033: прежде тарбол mbedtls
# распаковывался тем, что отдал сервер). Сменить версию — правка двух строк в fetch.sh; образ
# пересоберётся сам, потому что копия скрипта — слой образа.
#
# Только исходники: собирать их будет вызывающий (build/wolfssl/build.sh), под нужную цель. Готовых
# .a в образе нет намеренно — иначе пришлось бы держать по копии на каждую из девяти архитектур и
# следить, чтобы они не разъехались с опциями в дереве.
COPY wolfssl/fetch.sh /opt/steer-wolfssl-fetch.sh
RUN sh /opt/steer-wolfssl-fetch.sh /opt/wolfssl \
 && ls /opt/wolfssl/wolfssl/wolfcrypt/settings.h

# ngtcp2 (QUIC, шаг 7 выпуска 1.10) — тем же способом: версия и сумма записаны в build/ngtcp2/fetch.sh,
# образ копирует скрипт вместе с нашими патчами (Brutal) и зовёт его; скрипт сверяет sha256 и накладывает
# патчи. Другая версия или другой патч — другой слой, образ пересобирается сам. Утилита patch в
# базовом Alpine отсутствует (busybox собран без неё), поэтому ставится пакетом. Готовых .a нет
# по той же причине, что у wolfSSL: рецепт build/ngtcp2/build.sh собирает под нужную цель.
RUN apk add --no-cache patch make
COPY ngtcp2/fetch.sh /opt/steer-ngtcp2/fetch.sh
COPY ngtcp2/patches /opt/steer-ngtcp2/patches
RUN sh /opt/steer-ngtcp2/fetch.sh /opt/ngtcp2 \
 && ls /opt/ngtcp2/lib/ngtcp2_brutal.c

# ЗАПЛАТКА ЗАГЛУШКИ libc.so ДЛЯ 32-БИТНЫХ ЦЕЛЕЙ (шаг 4 выпуска 1.10, разделяемая раскладка).
#
# Статический бинарник zig собирает с настоящим musl (libc.a из исходников), и там всё на месте. Но
# бинарник, слинкованный с разделяемой libsteer.so, — динамический, и вместо libc.a zig подставляет
# заглушку libc.so, собранную из перечня символов musl/libc.S. Заголовки musl на 32-битных
# архитектурах подменяют time(), clock_gettime(), gmtime(), stat() и десяток соседей их
# 64-битными вариантами (__time64, __clock_gettime64, __gmtime64, __fstat_time64…), а перечень
# в libc.S отдаёт эти символы только под `#ifdef PTR32` — и на mips/mipsel макрос не выставляется,
# так что заглушка их не содержит, и компоновщик отвечает «undefined symbol: __clock_gettime64» на
# любой вызов времени. Настоящий libc.so роутера эти символы экспортирует (проверено по
# libc_1.2.5-r4_mipsel_24kc.ipk из OpenWrt 24.10: __clock_gettime64, __time64, __gmtime64,
# __localtime64_r, __fstat_time64, __stat_time64, __nanosleep_time64, __sigtimedwait_time64,
# __timerfd_settime64), поэтому заплатка касается только заглушки: она добавляет эти имена ко всем
# целям (лишнее для 64-битных ничему не мешает — на них никто не ссылается). Заглушка нужна
# компоновщику и в бинарник не попадает: во время работы символы разрешает настоящий musl.
RUN f="/opt/zig-linux-x86_64-${ZIG_VERSION}/lib/libc/musl/libc.S" \
 && sed -i 's/^#ifdef PTR32$/#if 1/' "$f" \
 && test "$(grep -c '^#ifdef PTR32$' "$f")" = 0

ENV WOLFSSL_DIR=/opt/wolfssl
ENV NGTCP2_DIR=/opt/ngtcp2
WORKDIR /src
ENTRYPOINT ["/usr/local/bin/zig"]
