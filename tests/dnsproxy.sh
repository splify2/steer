#!/bin/sh
# Пересылка запросов резолвером: живой процесс, петля, без root и без сети наружу.
#
# Зачем именно живой процесс. Наверх резолвер ходит ОДНИМ постоянным сокетом, а ответы
# всех ожиданий приходят на него вперемешку — различить их можно только по номеру
# транзакции, который движок переписывает на свой при отправке и возвращает клиентский
# на место в ответе. Ошибиться тут можно ровно двумя способами, и оба не видны в
# отдельно взятой функции: клиенту уходит чужой номер (его резолвер молча выбросит
# ответ, и имя «не разрешается» без единой строки в журнале) или ответ попадает в чужой
# слот и уезжает не тому клиенту. Поэтому здесь поднимается настоящий dnsd с поддельным
# апстримом на петле и проверяется сквозной путь.
#
# Прежняя схема — сокет на каждый запрос — такой проверки не требовала: номер не
# трогался вовсе. Стенд появился вместе с постоянным сокетом.
set -u
BIN="${STEER:-./build/steer}"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
# python3 нужен для поддельного апстрима и клиента. Его отсутствие — не провал стенда:
# остальной набор офлайновый и на голой машине обязан проходить.
command -v python3 >/dev/null 2>&1 || { echo "dnsproxy: python3 нет — пропускаю"; exit 0; }

tmp="$(mktemp -d)"
trap 'kill ${DPID:-0} ${UPID:-0} ${DPID2:-0} ${DPID3:-0} ${UPID3:-0} 2>/dev/null; exec 3>&- 2>/dev/null; rm -rf "$tmp"' EXIT
# Выход без IPv6 в фикстурах — мост Telegram (kind: tgws), вид плагина tgws: каталог плагинов дерева.
sh tests/plugroot.sh "$tmp/plugins" "${BUILD:-build}" >/dev/null || { echo "dnsproxy: каталог плагинов не собран"; exit 2; }
STEER_PLUGINS_ROOT="$tmp/plugins"; STEER_PLUGINS_ETC="$tmp/plugetc"; export STEER_PLUGINS_ROOT STEER_PLUGINS_ETC

LPORT=15300
UPORT=15353

cat > "$tmp/upstream.py" <<'PY'
import socket, struct, sys, threading
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.settimeout(20)
seen = []

# TCP на том же порту: резолвер спрашивает наверх по TCP то, что к нему пришло по TCP. Ответ
# по TCP — ДРУГИМ адресом (…35 против …34 по UDP): так клиент видит, каким путём шёл вопрос.
# big.test — ответ на 300 записей (больше 4 КБ, то есть больше любого буфера датаграммы
# резолвера): по TCP он обязан пройти целиком.
def tcp_answer(q):
    qend = 12
    while q[qend]: qend += 1 + q[qend]
    qend += 5
    name = q[12:qend - 4]
    n = 300 if name == b'\x03big\x04test\x00' else 1
    hdr = q[:2] + b'\x81\x80' + q[4:6] + struct.pack('>HHH', n, 0, 0)
    ans = b''.join(b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
                   + bytes([93, 184, (216 + i // 256) % 256, (35 + i) % 256]) for i in range(n))
    return hdr + q[12:qend] + ans

def recvn(c, k):
    b = b''
    while len(b) < k:
        d = c.recv(k - len(b))
        if not d: return None
        b += d
    return b

def tcp_conn(c):
    c.settimeout(10)
    try:
        while True:
            h = recvn(c, 2)
            if not h: break
            q = recvn(c, struct.unpack('>H', h)[0])
            if not q: break
            r = tcp_answer(q)
            c.sendall(struct.pack('>H', len(r)) + r)
            with open(sys.argv[2] + '.tcp', 'a') as f: f.write('q\n')
    except Exception:
        pass
    c.close()

def tcp_srv():
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    t.bind(("127.0.0.1", int(sys.argv[1]))); t.listen(64)
    while True:
        c, _ = t.accept()
        threading.Thread(target=tcp_conn, args=(c,), daemon=True).start()
threading.Thread(target=tcp_srv, daemon=True).start()
try:
    while True:
        data, addr = s.recvfrom(2048)
        seen.append(data[:2])
        qend = 12
        while data[qend]: qend += 1 + data[qend]
        qend += 5
        hdr = data[:2] + b'\x81\x80' + data[4:6] + b'\x00\x01\x00\x00\x00\x00'
        ans = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + bytes([93, 184, 216, 34])
        s.sendto(hdr + data[12:qend] + ans, addr)
        # Пишется ПОСЛЕ КАЖДОЙ датаграммы, а не в конце: стенд снимает апстрим сразу
        # после клиента, не дожидаясь его таймаута, и итог, записанный только на выходе,
        # не появлялся вовсе — проверка сравнивала «0 0» и всегда проваливалась.
        open(sys.argv[2], "w").write("%d %d" % (len(seen), len(set(seen))))
except socket.timeout:
    pass
PY

cat > "$tmp/client.py" <<'PY'
import socket, struct, sys
port, n = int(sys.argv[1]), int(sys.argv[2])
ok = bad_id = lost = bad_addr = 0
for i in range(1, n + 1):
    tid = 0x1000 + i
    q = (struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
         + b'\x07example\x03com\x00' + struct.pack('>HH', 1, 1))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    s.sendto(q, ('127.0.0.1', port))
    try:
        d, _ = s.recvfrom(2048)
    except socket.timeout:
        lost += 1; continue
    if struct.unpack('>H', d[:2])[0] != tid: bad_id += 1
    elif d[-4:] != bytes([93, 184, 216, 34]): bad_addr += 1
    else: ok += 1
print("%d %d %d %d" % (ok, bad_id, lost, bad_addr))
PY

cat > "$tmp/tcpclient.py" <<'PY'
# Клиент по TCP: конвейер (несколько запросов одной записью, до первого ответа), ответ больше
# 4 КБ, медленный клиент (полсообщения и тишина) не мешает остальным, и простой закрывается.
import socket, struct, sys, time
port, what = int(sys.argv[1]), sys.argv[2]

def q(tid, name, qtype=1):
    b = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    for l in name.split('.'): b += bytes([len(l)]) + l.encode()
    return b + b'\x00' + struct.pack('>HH', qtype, 1)

def framed(m): return struct.pack('>H', len(m)) + m

def recvn(c, k):
    b = b''
    while len(b) < k:
        d = c.recv(k - len(b))
        if not d: return None
        b += d
    return b

def reply(c):
    h = recvn(c, 2)
    if not h: return None
    return recvn(c, struct.unpack('>H', h)[0])

def conn():
    c = socket.create_connection(('127.0.0.1', port), timeout=4)
    return c

if what == 'pipeline':
    # Три запроса одной записью: два разных имени и одно повторно. Ответы могут прийти в любом
    # порядке — сопоставление по номеру.
    c = conn()
    names = {0x2001: 'example.com', 0x2002: 'other.test', 0x2003: 'www.example.com'}
    c.sendall(b''.join(framed(q(t, n)) for t, n in names.items()))
    got = {}
    for _ in names:
        r = reply(c)
        if r is None: break
        got[struct.unpack('>H', r[:2])[0]] = r
    ok = sum(1 for t in names if t in got and got[t][-4:] == bytes([93, 184, 216, 35]))
    # Затем в том же соединении — ещё пять последовательно, запрос-ответ.
    seq = 0
    for i in range(5):
        c.sendall(framed(q(0x3000 + i, 'seq%d.test' % i)))
        r = reply(c)
        if r and struct.unpack('>H', r[:2])[0] == 0x3000 + i and r[-4:] == bytes([93, 184, 216, 35]):
            seq += 1
    print(ok, seq)
elif what == 'many':
    # Сто соединений одновременно — больше прежних 32 (TCP_MAX_CONN): все открыты до первого
    # вопроса, значит, места нет ни у кого лишнего, и каждое обязано получить свой ответ.
    n = 100
    cs = [conn() for _ in range(n)]
    for i, c in enumerate(cs): c.sendall(framed(q(0x6000 + i, 'many%d.test' % i)))
    ok = 0
    for i, c in enumerate(cs):
        r = reply(c)
        if r and struct.unpack('>H', r[:2])[0] == 0x6000 + i and r[-4:] == bytes([93, 184, 216, 35]):
            ok += 1
    print(ok)
elif what == 'big':
    c = conn()
    c.sendall(framed(q(0x4242, 'big.test')))
    r = reply(c)
    print(len(r) if r else 0, struct.unpack('>H', r[6:8])[0] if r else 0)
elif what == 'slow':
    # Полсообщения — и тишина. Пока это соединение висит, UDP и другое TCP-соединение
    # обязаны получать ответы: цикл резолвера не ждёт медленного клиента.
    s = conn()
    s.sendall(b'\x00')
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3)
    u.sendto(q(0x5151, 'example.com'), ('127.0.0.1', port))
    try:
        d, _ = u.recvfrom(2048); udp = 1 if d[:2] == b'\x51\x51' else 0
    except socket.timeout:
        udp = 0
    c = conn()
    c.sendall(framed(q(0x5252, 'other.test')))
    r = reply(c)
    tcp = 1 if r and r[:2] == b'\x52\x52' else 0
    print(udp, tcp)
elif what == 'idle':
    # Соединение без запросов закрывается резолвером по простою (10 с), а не держит место.
    c = conn(); c.settimeout(20)
    t0 = time.time()
    try:
        d = c.recv(1)
    except socket.timeout:
        d = b'x'
    el = time.time() - t0
    print('closed' if d == b'' and 8 <= el <= 14 else 'open %.1f' % el)
PY

printf 'example.com\n' > "$tmp/d.lst"
printf '{"schema":1,"from_default":["127.0.0.0/8"],'\
'"outputs":{"direct":{"kind":"direct"},"vpn":{"kind":"interface","device":"lo"}},'\
'"channels":[{"name":"c","match":{"domains_files":["%s/d.lst"],"mode":"realip"},"out":"vpn"}]}' \
    "$tmp" > "$tmp/spec.json"

python3 "$tmp/upstream.py" "$UPORT" "$tmp/up.txt" & UPID=$!
sleep 1
"$BIN" dnsd --spec "$tmp/spec.json" --state-dir "$tmp/state" \
    --listen-port "$LPORT" --upstream-port "$UPORT" > "$tmp/log" 2>&1 & DPID=$!
sleep 1

if ! kill -0 "$DPID" 2>/dev/null; then
    echo "FAIL резолвер не поднялся:"; cat "$tmp/log"; exit 1
fi

python3 "$tmp/tcpclient.py" "$LPORT" idle > "$tmp/idle.txt" 2>&1 & IDLE=$!
set -- $(python3 "$tmp/client.py" "$LPORT" 20)
ok=$1 bad_id=$2 lost=$3 bad_addr=$4
tcp_pipe="$(python3 "$tmp/tcpclient.py" "$LPORT" pipeline 2>&1)"
tcp_big="$(python3 "$tmp/tcpclient.py" "$LPORT" big 2>&1)"
tcp_slow="$(python3 "$tmp/tcpclient.py" "$LPORT" slow 2>&1)"
tcp_many="$(python3 "$tmp/tcpclient.py" "$LPORT" many 2>&1)"
wait "$IDLE"
tcp_idle="$(cat "$tmp/idle.txt")"
# Тишина: ожиданий в пути нет, соединения TCP закрыты по простою — резолверу не на что
# просыпаться. Раньше он всё равно просыпался раз в секунду (epoll_wait с таймаутом 1000 мс
# ради тика), и на телефоне это было 60 пробуждений в минуту при выключенном экране.
# Меряется счётчиком добровольных переключений контекста самого процесса; одно лишнее
# допускается — последний тик, который и обнаружил, что всё затихло.
sleep 2
cs0=$(awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$DPID/status")
sleep 3
cs1=$(awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$DPID/status")
quiet=$(( cs1 - cs0 ))
[ "$quiet" -le 1 ] && quiet=ok
kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null
sleep 1
kill "$UPID" 2>/dev/null; wait "$UPID" 2>/dev/null

pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1))
        printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}

check "все 20 запросов получили ответ" "20" "$ok"
check "ни одного ответа с чужим номером транзакции" "0" "$bad_id"
check "ни одного потерянного" "0" "$lost"
check "адрес в ответе не искажён" "0" "$bad_addr"

# Наверх по UDP ушло столько же запросов, сколько пришло снизу по UDP (20 и один из стенда
# медленного клиента), и номера у них РАЗНЫЕ: слот
# переиспользуется, но поколение в старшем байте меняет номер, иначе запоздавший ответ
# на закрытое ожидание попал бы в чужой слот.
up="$(cat "$tmp/up.txt" 2>/dev/null || echo '0 0')"
check "наверх ушли все запросы и все с разными номерами" "21 21" "$up"

# DNS по TCP (RFC 7766): тот же путь, что у датаграммы, ответ — по TCP, наверх — тоже по TCP.
check "TCP: конвейер из трёх запросов одной записью и пять подряд — все ответы по TCP сверху" \
    "3 5" "$tcp_pipe"
check "TCP: ответ больше 4 КБ (300 записей) пришёл целиком" "4826 300" "$tcp_big"
check "TCP: медленный клиент не держит цикл — UDP и другое соединение отвечают" "1 1" "$tcp_slow"
check "TCP: сто соединений одновременно (прежний предел 32) — все ответы пришли" "100" "$tcp_many"
check "TCP: соединение без запросов закрыто по простою" "closed" "$tcp_idle"
check "в тишине резолвер не просыпается (добровольных переключений за 3 с не больше одного)" \
    "ok" "$quiet"
check "TCP: наверх по TCP ушли ровно вопросы клиентов TCP" "110" \
    "$(cat "$tmp/up.txt.tcp" 2>/dev/null | wc -l | tr -d ' ')"

# ---- --table-fd: таблица каналов из трубы демона, а не из спеки самим резолвером -----------
# docs/architecture.md, раздел 4а, «dnsd»: dnsd принимает таблицу через дескриптор, который
# демон завёл бы для дочернего резолвера. Здесь его роль играет труба, которую заполняет
# `steer dnsd-table` (та же сборка, что напечатала бы демону), — резолвер спеку в этом режиме
# не открывает вовсе.
#
# Сигнал «канал совпал или нет» — без единой нитки к nftables (этот стенд намеренно обходится
# без root и без сети наружу, см. шапку файла): запрос HTTPS (тип 65) на СОВПАВШЕЕ имя резолвер
# гасит в NODATA прямо из вопроса, ни разу не спросив апстрим (dns_query, proxy.c, «Подавление —
# свойство правила, а не данных из ответа») — ровно поэтому сигнал верен и без единой транзакции
# ядра. Несовпавшее имя идёт напрямую, и апстрим здесь отвечает настоящей записью — значит
# ANCOUNT (число записей в ответе, байты 6-7 заголовка) 0 значит «канал забрал домен», 1 —
# «домена в таблице нет». Разбор именно этого поля, а не адреса: NODATA не несёт вовсе
# ресурсной записи, сравнивать в ней нечего. (До 1.9 сигналом был AAAA; теперь у спеки v2 на AAAA
# имени под правилом с половиной IPv6 резолвер отвечает адресом — это проверяется ниже отдельно.)
cat > "$tmp/upstream-aaaa.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.settimeout(20)
while True:
    data, addr = s.recvfrom(2048)
    qend = 12
    while data[qend]: qend += 1 + data[qend]
    qend += 5
    hdr = data[:2] + b'\x81\x80' + data[4:6] + b'\x00\x01\x00\x00\x00\x00'
    ans = b'\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10' + b'\x20\x01\x0d\xb8' + b'\x00' * 12
    s.sendto(hdr + data[12:qend] + ans, addr)
PY
cat > "$tmp/qaaaa.py" <<'PY'
import socket, struct, sys
port, name = int(sys.argv[1]), sys.argv[2]
qtype = int(sys.argv[3]) if len(sys.argv) > 3 else 28   # 28 = AAAA, 65 = HTTPS
q = struct.pack('>HHHHHH', 0x7a7a, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
q += b'\x00' + struct.pack('>HH', qtype, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, ('127.0.0.1', port))
try:
    d, _ = s.recvfrom(2048)
    print(struct.unpack('>H', d[6:8])[0])  # ANCOUNT
except socket.timeout:
    print('timeout')
PY

LPORT2=15301
UPORT2=15364
printf 'swap.test\n' > "$tmp/tab.lst"
# Таблица 1: канал с доменным правилом на swap.test. Таблица 2 — ТА ЖЕ спека, но с ПУСТЫМ
# списком каналов: не файл правил меняется (это уже умеет HUP, reload_rules — не про него
# этот стенд), а само число каналов и их состав. Это ровно то, чего построчное перечитывание
# списков никогда не делает: dch_build решает его один раз при запуске (или — здесь — один раз
# на таблицу). Совпадение исчезает и появляется вместе с таблицей — прямое доказательство, что
# резолвер живёт по НОВОЙ таблице целиком, а не донашивает старую с обновлёнными файлами.
mk_tabspec() {  # "1" — канал с swap.test в списке; "" — каналов нет вовсе
    f="$tmp/tabspec-$1.json"
    chans='[]'
    [ -n "$1" ] && chans="[{\"name\":\"c\",\"match\":{\"domains_files\":[\"$tmp/tab.lst\"]},\"out\":\"vpn\"}]"
    printf '{"schema":1,"from_default":["127.0.0.0/8"],'\
'"outputs":{"direct":{"kind":"direct"},"vpn":{"kind":"interface","device":"lo"}},'\
'"channels":%s}' "$chans" > "$f"
    printf '%s' "$f"
}
tabspec_on="$(mk_tabspec 1)"
tabspec_off="$(mk_tabspec '')"

mkfifo "$tmp/tabpipe"
# fd 3 — НАШ конец, открытый и на чтение, и на запись: писать в трубу можно, не дожидаясь
# читателя, и наш же конец не даёт нам самим поймать EOF раньше времени. Резолверу открывается
# ОТДЕЛЬНЫЙ, только читающий fd 4 (see ниже, при запуске) — если бы он вместо этого унаследовал
# fd 3 как есть, его СОБСТВЕННАЯ же копия читала-и-писала бы одну и ту же трубу, и закрытие
# нашего конца никогда не дало бы ему увидеть EOF: труба остаётся «с открытым писателем» до тех
# пор, пока хоть кто-то — не важно, мы или он сам, — держит открытым конец на запись.
exec 3<>"$tmp/tabpipe"
"$BIN" dnsd-table --spec "$tabspec_on" --state-dir "$tmp/state2" >&3

# `3<&-`: без него апстрим тоже унаследовал бы наш конец трубы и держал бы у себя открытым
# писатель, которого мы позже закрываем, — резолвер тогда не увидел бы EOF никогда, пока не
# убит и апстрим (та же причина, что у 3<&- при запуске dnsd ниже).
python3 "$tmp/upstream-aaaa.py" "$UPORT2" 3<&- & UPID2=$!
sleep 1
# `3<&-` закрывает унаследованный fd 3 ИМЕННО для этого процесса (наш собственный fd 3 в
# шелле не трогается), `4<...` открывает резолверу свежий read-only конец той же трубы — уже
# не блокируясь: наш fd 3 в этот момент открыт как писатель, поэтому open() на чтение не ждёт.
# Каталог состояния заводит демон; здесь его роль у стенда — в нём управляющий сокет резолвера,
# без которого ждать нового демона незачем (забрать было бы не через что).
mkdir -p "$tmp/state2"
"$BIN" dnsd --table-fd 4 --state-dir "$tmp/state2" --orphan-timeout 2 \
    --listen-port "$LPORT2" --upstream-port "$UPORT2" \
    3<&- 4<"$tmp/tabpipe" > "$tmp/log2" 2>&1 & DPID2=$!
sleep 1
if ! kill -0 "$DPID2" 2>/dev/null; then
    echo "FAIL резолвер (--table-fd) не поднялся:"; cat "$tmp/log2"; exit 1
fi

tab_on_hit="$(python3 "$tmp/qaaaa.py" "$LPORT2" swap.test 65)"
tab_on_miss="$(python3 "$tmp/qaaaa.py" "$LPORT2" other.test 65)"

# Тишина и здесь: труба таблицы в epoll — событие только на настоящей записи, не пустое
# пробуждение по таймеру. Тот же счётчик, что у первого резолвера (тот же запас в 2 с — отдать
# последнему тику время снять ожидание только что отвеченного запроса ДО начала окна).
sleep 2
cs2_0=$(awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$DPID2/status")
sleep 3
cs2_1=$(awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$DPID2/status")
quiet2=$(( cs2_1 - cs2_0 ))
[ "$quiet2" -le 1 ] && quiet2=ok

"$BIN" dnsd-table --spec "$tabspec_off" --state-dir "$tmp/state2" >&3
sleep 1
tab_off_hit="$(python3 "$tmp/qaaaa.py" "$LPORT2" swap.test 65)"
# Тот же $DPID2, тот же PID в OS: не respawn под тем же именем переменной, а kill -0 на РОВНО
# тот процесс, что подняли выше, — упал бы он и procd (здесь — никто) поднял бы замену, у
# замены был бы другой PID, а мы всё ещё спрашиваем старый.
still_up="down"; kill -0 "$DPID2" 2>/dev/null && still_up="up"

# Закрыть трубу — демона нет (упал): резолвер отвечает дальше по последней таблице и ждёт нового
# демона --orphan-timeout (здесь 2 с, src/dnsd/adopt.c), а не дождавшись — выходит сам, без TERM.
# Ждать его пятью секундами, дольше make test терпеть зависший процесс не должен.
exec 3>&-
sleep 0.3
orphan_ans="$(python3 "$tmp/qaaaa.py" "$LPORT2" other.test 65) $(python3 "$tmp/qaaaa.py" "$LPORT2" swap.test 65)"
closed="still running"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$DPID2" 2>/dev/null || { closed="exited"; break; }
    sleep 0.5
done
kill "$DPID2" 2>/dev/null; wait "$DPID2" 2>/dev/null
kill "$UPID2" 2>/dev/null; wait "$UPID2" 2>/dev/null

check "table-fd: первая таблица — swap.test совпал (HTTPS погашен, ANCOUNT 0)" "0" "$tab_on_hit"
check "table-fd: первая таблица — чужое имя без канала (ANCOUNT 1)" "1" "$tab_on_miss"
check "table-fd: в тишине резолвер не просыпается" "ok" "$quiet2"
check "table-fd: после второй таблицы процесс тот же, не перезапустился" "up" "$still_up"
check "table-fd: вторая таблица без каналов — swap.test больше не совпадает (ANCOUNT 1)" \
    "1" "$tab_off_hit"
check "table-fd: труба закрыта — резолвер отвечает по последней таблице" "1 1" "$orphan_ans"
check "table-fd: нового демона нет за срок — резолвер завершается сам" "exited" "$closed"

# ---- AAAA имён под правилом (1.9, IPv6, docs/architecture.md, «4б») --------------------------
# Три правила на один апстрим, который на всё отвечает настоящей записью AAAA:
#   r6 — real-ip в выход с IPv6 (interface): настоящий AAAA уходит клиенту (и адрес — в набор
#        «<канал>6», которого на этой машине нет: вставка отказывает, ответ от этого не зависит);
#   f6 — fake-IP в выход с IPv6: поддельный IPv6 выдаётся только после ack ядра по карте fakeip6,
#        а её здесь нет — ответ пустой, а не настоящий AAAA мимо выхода (сам fake6 — dnsnft.sh);
#   t4 — выход без IPv6 (tgws): пустой ответ сразу, клиент идёт по IPv4;
# имя вне правил — настоящий AAAA как есть. Всё это — спека v2; та же спека записью v1 отвечает на
# AAAA тем же, что у v2 (перевод v1 → v2 IPv6 не отнимает) — проверка в конце.
LPORT3=15302
UPORT3=15365
for n in r6 f6 t4; do printf '%s.test\n' "$n" > "$tmp/$n.lst"; done
printf '{"version":2,"lan":{"addr":["127.0.0.0/8"]},'\
'"lists":{"r6":{"domains_file":"%s/r6.lst"},"f6":{"domains_file":"%s/f6.lst"},'\
'"t4":{"domains_file":"%s/t4.lst"}},'\
'"outputs":{"vpn":{"kind":"interface","device":"lo"},"tg":{"kind":"tgws","domain":"example.com"}},'\
'"rules":[{"name":"r6","to":"r6","out":"vpn","resolve":"realip"},'\
'{"name":"f6","to":"f6","out":"vpn"},'\
'{"name":"t4","to":"t4","out":"tg"}]}' \
    "$tmp" "$tmp" "$tmp" > "$tmp/spec6.json"
printf '{"schema":1,"from_default":["127.0.0.0/8"],'\
'"outputs":{"vpn":{"kind":"interface","device":"lo"},"tg":{"kind":"tgws","domain":"example.com"}},'\
'"channels":[{"name":"r6","match":{"domains_files":["%s/r6.lst"],"mode":"realip"},"out":"vpn"},'\
'{"name":"f6","match":{"domains_files":["%s/f6.lst"]},"out":"vpn"},'\
'{"name":"t4","match":{"domains_files":["%s/t4.lst"]},"out":"tg"}]}' \
    "$tmp" "$tmp" "$tmp" > "$tmp/spec6v1.json"
tab6="$(STEER_NFT_INGRESS=1 "$BIN" dnsd-table --spec "$tmp/spec6.json" 2>/dev/null)"
python3 "$tmp/upstream-aaaa.py" "$UPORT3" & UPID3=$!
sleep 1
STEER_NFT_INGRESS=1 "$BIN" dnsd --spec "$tmp/spec6.json" --state-dir "$tmp/state3" \
    --listen-port "$LPORT3" --upstream-port "$UPORT3" > "$tmp/log3" 2>&1 & DPID3=$!
sleep 1
if ! kill -0 "$DPID3" 2>/dev/null; then
    echo "FAIL резолвер (AAAA) не поднялся:"; cat "$tmp/log3"; exit 1
fi
a_r6="$(python3 "$tmp/qaaaa.py" "$LPORT3" r6.test)"
a_f6="$(python3 "$tmp/qaaaa.py" "$LPORT3" f6.test)"
a_t4="$(python3 "$tmp/qaaaa.py" "$LPORT3" t4.test)"
a_out="$(python3 "$tmp/qaaaa.py" "$LPORT3" out.test)"
kill "$DPID3" 2>/dev/null; wait "$DPID3" 2>/dev/null
# Спека v1 с теми же каналами — тот же апстрим, свой резолвер: ответы те же, что у спеки v2.
LPORT4=15303
tab6v1="$(STEER_NFT_INGRESS=1 "$BIN" dnsd-table --spec "$tmp/spec6v1.json" 2>/dev/null)"
STEER_NFT_INGRESS=1 "$BIN" dnsd --spec "$tmp/spec6v1.json" --state-dir "$tmp/state4" \
    --listen-port "$LPORT4" --upstream-port "$UPORT3" > "$tmp/log4" 2>&1 & DPID4=$!
sleep 1
v1_r6="$(python3 "$tmp/qaaaa.py" "$LPORT4" r6.test)"
v1_f6="$(python3 "$tmp/qaaaa.py" "$LPORT4" f6.test)"
v1_out="$(python3 "$tmp/qaaaa.py" "$LPORT4" out.test)"
kill "$DPID4" 2>/dev/null; wait "$DPID4" 2>/dev/null
kill "$UPID3" 2>/dev/null; wait "$UPID3" 2>/dev/null

check "таблица: правила в выход с IPv6 — семейства 4 и 6" "2" \
    "$(printf '%s\n' "$tab6" | grep -c '^vpn_dom[a-z0-9_]*|vpn|[01]|46|')"
check "таблица: правило в выход без IPv6 — только 4" "1" \
    "$(printf '%s\n' "$tab6" | grep -c '^tg_dom|tg|0|4|t4|')"
check "AAAA: real-ip в выход с IPv6 — настоящий адрес (ANCOUNT 1)" "1" "$a_r6"
check "AAAA: fake-IP без карты fakeip6 в ядре — пустой ответ, не настоящий AAAA" "0" "$a_f6"
check "AAAA: правило в выход без IPv6 — пустой ответ" "0" "$a_t4"
check "AAAA: имя вне правил — настоящий адрес" "1" "$a_out"
check "спека v1: семейства в таблице те же, что у v2" \
    "$(printf '%s\n' "$tab6" | awk -F'|' 'NF > 4 { printf "%s%s", s, $4; s = " " }')" \
    "$(printf '%s\n' "$tab6v1" | awk -F'|' 'NF > 4 { printf "%s%s", s, $4; s = " " }')"
check "спека v1: AAAA real-ip в выход с IPv6 — как у v2 (настоящий адрес)" "$a_r6" "$v1_r6"
check "спека v1: AAAA fake-IP без карты fakeip6 — как у v2 (пустой ответ)" "$a_f6" "$v1_f6"
check "спека v1: имя вне правил — настоящий адрес" "1" "$v1_out"

# ---- политика семейства правила (R-154, docs/spec-v2.md: family, on_family_unavailable) -------
# Тот же апстрим (на всё — настоящая запись), четыре правила real-ip (ядро резолверу не нужно):
#   p4 — family: 4, выход с IPv6:       AAAA пуст, A — настоящий (ANCOUNT 1);
#   p6 — family: 6, выход с IPv6:       AAAA настоящий, A пуст — не настоящий адрес мимо правила;
#   pf — family: 6, выход без IPv6, запас (fallback): работает по IPv4 — AAAA пуст, A настоящий;
#   pk — family: 6, выход без IPv6, block: имя не открывается — A и AAAA нулевые адреса.
cat > "$tmp/qrr.py" <<'PY'
import socket, struct, sys
port, name, qtype = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
q = struct.pack('>HHHHHH', 0x7b7b, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
q += b'\x00' + struct.pack('>HH', qtype, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, ('127.0.0.1', port))
try:
    d, _ = s.recvfrom(2048)
    n = struct.unpack('>H', d[6:8])[0]
    qe = 12
    while d[qe]: qe += 1 + d[qe]
    qe += 5                                     # конец вопроса; дальше первая запись ответа
    rd = b''
    if n:
        rl = struct.unpack('>H', d[qe + 10:qe + 12])[0]
        rd = d[qe + 12:qe + 12 + rl]
    print(n, 'zero' if n and not any(rd) else 'real' if n else '-')
except socket.timeout:
    print('timeout')
PY
for n in p4 p6 pf pk; do printf '%s.test\n' "$n" > "$tmp/$n.lst"; done
printf '{"version":2,"lan":{"addr":["127.0.0.0/8"]},'\
'"lists":{"p4":{"domains_file":"%s/p4.lst"},"p6":{"domains_file":"%s/p6.lst"},'\
'"pf":{"domains_file":"%s/pf.lst"},"pk":{"domains_file":"%s/pk.lst"}},'\
'"outputs":{"vpn":{"kind":"interface","device":"lo"},"tg":{"kind":"tgws","domain":"example.com"}},'\
'"rules":[{"name":"p4","to":"p4","out":"vpn","resolve":"realip","family":"4"},'\
'{"name":"p6","to":"p6","out":"vpn","resolve":"realip","family":"6"},'\
'{"name":"pf","to":"pf","out":"tg","resolve":"realip","family":"6"},'\
'{"name":"pk","to":"pk","out":"tg","resolve":"realip","family":"6","on_family_unavailable":"block"}]}' \
    "$tmp" "$tmp" "$tmp" "$tmp" > "$tmp/specfam.json"
tabfam="$(STEER_NFT_INGRESS=1 "$BIN" dnsd-table --spec "$tmp/specfam.json" 2>/dev/null)"
LPORT5=15304
python3 "$tmp/upstream-aaaa.py" "$UPORT3" & UPID5=$!
sleep 1
STEER_NFT_INGRESS=1 "$BIN" dnsd --spec "$tmp/specfam.json" --state-dir "$tmp/state5" \
    --listen-port "$LPORT5" --upstream-port "$UPORT3" > "$tmp/log5" 2>&1 & DPID5=$!
sleep 1
if ! kill -0 "$DPID5" 2>/dev/null; then
    echo "FAIL резолвер (семейство) не поднялся:"; cat "$tmp/log5"; exit 1
fi
fq() { python3 "$tmp/qrr.py" "$LPORT5" "$1" "$2"; }
fam_p4="$(fq p4.test 1) / $(fq p4.test 28)"
fam_p6="$(fq p6.test 1) / $(fq p6.test 28)"
fam_pf="$(fq pf.test 1) / $(fq pf.test 28)"
fam_pk="$(fq pk.test 1) / $(fq pk.test 28)"
kill "$DPID5" 2>/dev/null; wait "$DPID5" 2>/dev/null
kill "$UPID5" 2>/dev/null; wait "$UPID5" 2>/dev/null

check "таблица: семейства правил с политикой — 4, 6, 4 (запас), 6 с блоком (режим 2); режим real-ip — 1" \
    "p4:4:1 p6:6:1 pf:4:1 pk:6:2" \
    "$(printf '%s\n' "$tabfam" | awk -F'|' 'NF > 4 { printf "%s%s:%s:%s", s, $5, $4, $3; s = " " }')"
check "family: 4 — A настоящий, AAAA пуст" "1 real / 0 -" "$fam_p4"
check "family: 6 — A пуст (не настоящий адрес мимо правила), AAAA настоящий" "0 - / 1 real" "$fam_p6"
check "family: 6, выход без IPv6, fallback — по IPv4: A настоящий, AAAA пуст" "1 real / 0 -" "$fam_pf"
check "family: 6, выход без IPv6, block — A и AAAA нулевые" "1 zero / 1 zero" "$fam_pk"

printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
