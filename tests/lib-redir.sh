# Перенаправление TCP к слушателю модуля для стендов без демона (R-152). На роутере правило ставит демон по
# метке выхода (карта tcp_redir, compile/generate.c); у стенда меток нет, и правило — по устройству: в хуке
# nat output маршрут уже выбран, поэтому TCP, который ядро повело бы в устройство туннеля, виден по oifname.
# Порт — 9480 плюс место выхода (out_tcp_port): у единственного выхода стенда место 0, порт 9480.
#
#   redir_dev ПРОСТРАНСТВО УСТРОЙСТВО [ПОРТ]   — свой TCP пространства (клиент на «роутере»)
#   redir_dst ПРОСТРАНСТВО ПОДСЕТЬ [ПОРТ]      — TCP, пришедший в пространство к подсети (клиент за «LAN»)
redir_table() {
    ip netns exec "$1" nft list table inet steer_stand_redir >/dev/null 2>&1 && return 0
    ip netns exec "$1" nft -f - <<NFT
table inet steer_stand_redir {
    chain out { type nat hook output priority -101; policy accept; }
    chain pre { type nat hook prerouting priority -101; policy accept; }
}
NFT
}
# IPv6 — правилом своего семейства, как у демона (generate.c: build_tcp_redir): в таблице inet `ip protocol` смотрит
# только IPv4. Правило IPv6 безвредно там, где IPv6 нет, поэтому ставится всегда.
redir_dev() {
    redir_table "$1" && ip netns exec "$1" nft add rule inet steer_stand_redir out oifname "\"$2\"" \
        ip protocol tcp counter redirect to :"${3:-9480}" &&
    ip netns exec "$1" nft add rule inet steer_stand_redir out oifname "\"$2\"" \
        meta nfproto ipv6 meta l4proto tcp counter redirect to :"${3:-9480}"
}
# Подсеть IPv6 (в записи есть «:») ловится правилом IPv6, иначе IPv4.
redir_dst() {
    redir_table "$1" || return 1
    case "$2" in
    *:*) ip netns exec "$1" nft add rule inet steer_stand_redir pre ip6 daddr "$2" \
             meta l4proto tcp counter redirect to :"${3:-9480}" ;;
    *)   ip netns exec "$1" nft add rule inet steer_stand_redir pre ip daddr "$2" \
             ip protocol tcp counter redirect to :"${3:-9480}" ;;
    esac
}
