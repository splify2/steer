# Сборка ядра steer для OSS Scanner (github.com/anthropics/oss-scanner): контекст — корень репозитория,
# исходники в /src. Сеть есть только на этом шаге, поэтому всё, что нужно стендам, ставится здесь же:
# исходники wolfSSL и ngtcp2 (для внешних модулей и разделяемой раскладки) качаются скриптами build/*/fetch.sh
# со сверкой sha256.
FROM debian:bookworm
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates build-essential clang make pkg-config git python3 python3-yaml \
      nftables iproute2 iptables iputils-ping netcat-openbsd socat curl openssl \
      dnsutils busybox util-linux procps \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

# Сборка как у сопровождающих (Makefile дописывает -I сам), с отладочной информацией и указателями кадров.
RUN make -j"$(nproc)" CFLAGS="-O1 -g -fno-omit-frame-pointer -Wall -Wextra"

# Исходники для внешних модулей и libsteer.so — пока сеть есть.
RUN sh build/wolfssl/fetch.sh build/wolfssl-host/src \
    && sh build/ngtcp2/fetch.sh build/ngtcp2-host/src

# Дешёвые стенды: часть требует root и сетевых пространств имён и в контейнере пропускается сама.
# Провал стенда сборку не роняет.
RUN (timeout 1800 make test CFLAGS="-O1 -g -fno-omit-frame-pointer -Wall -Wextra" < /dev/null \
     || echo "WARNING: make test reported failures")
