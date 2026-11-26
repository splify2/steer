# Проверяется итог приложения, не сетевые байты sent (в них QUIC overhead/retransmit).
function integer(s) { return s ~ /^[0-9]+$/ }
function decimal(s) { return s ~ /^[0-9]+([.][0-9]+)?$/ }
function value(s, key) { return substr(s, length(key) + 2) }
function field(s, key) { return index(s, key "=") == 1 }
function canonical(s) { sub(/^0+/, "", s); return s == "" ? "0" : s }
FILENAME == ARGV[1] && /^client([[:space:]]|$)/ {
    clients++
    if (NF != 9 || $1 != "client" || !field($2,"queued") || !field($3,"sent") ||
        !field($4,"lost") || !field($5,"pkts") || !field($6,"cwnd") ||
        !field($7,"rtt_us") || !field($8,"brutal") || !field($9,"replied")) next
    for (i=2;i<=9;i++) {
        split($i,part,"=")
        if (length(part[1])+1 >= length($i) || !integer(part[2]) || $i != part[1] "=" part[2]) next
    }
    if (i != 10) next
    queued=canonical(value($2,"queued"))
    sent=canonical(value($3,"sent"))
    brutal=value($8,"brutal")
    replied=value($9,"replied")
    if (queued == "0" || sent == "0" || replied != "1" ||
        brutal != (mode == "brutal" ? "1" : "0")) next
    client_ok=1
}
FILENAME == ARGV[2] && /^total([[:space:]]|$)/ {
    servers++
    if (NF != 4 || $1 != "total" || !field($2,"bytes") ||
        !field($3,"secs") || !field($4,"mbit")) next
    bytes=value($2,"bytes"); secs=value($3,"secs"); mbit=value($4,"mbit")
    if (!integer(bytes) || !decimal(secs) || !decimal(mbit)) next
    bytes=canonical(bytes)
    if (bytes == "0") next
    server_ok=1
}
END {
    if (clients != 1 || servers != 1 || !client_ok || !server_ok || "x" queued != "x" bytes) exit 1
    print mbit
}
