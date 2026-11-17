# Архитектурный план Steer 3.0.0

Статус: архитектурное решение для разработки, не описание выпущенных возможностей.
План покрывает всю систему; критерии первого выпуска и последовательность PR —
[steer-3.0-delivery.md](steer-3.0-delivery.md). Детальный проект нового ABI —
в [SDK provider contract](https://github.com/splify2/plugin-sdk/blob/main/docs/provider-v1-draft.md)
(до публикации доступен в checkout `plugin-sdk/docs/provider-v1-draft.md`).
Владелец решения — архитектор текущей задачи; агенты реализуют ограниченные задания.
Текущая база: Steer 70d11ebb6ab7b618508e1bbb593a3d28a9cf4d08,
SDK 6859f94ab4c046a9625b4dc58406ad77b88c4d8c плюс рабочие изменения settings.schema.

## 1. Цель и неизменяемые свойства

Steer — универсальное ядро маршрутизации для сервера, клиента и шлюза.
Linux — первая проверяемая платформа, OpenWrt, Windows, Android — целевые;
iOS — отдельный ограниченный клиентский профиль после проверки Network Extension.
Все возможности UI принадлежат одному опциональному плагину Steer UI.
Протоколы и features — C/Rust плагины. Go upstream используется как источник
wire-контракта и независимая сторона interop-тестов, не как runtime-зависимость.
Mieru исключён из реализации: это только пример будущего стороннего расширения.

Сохраняем достигнутое преимущество Steer по размеру, памяти и производительности.
Оно является ограничением архитектуры, а не будущим обещанием. Нет обязательного
UI/runtime, копии сетевого стека на протокол, глобального mutex на пути пакета,
JSON/RPC на каждую передачу данных или неограниченных очередей. Код протоколов
не встраивается обязательно в каждую поставку. Мобильная статическая регистрация
сохраняет модульность на этапе сборки.

## 2. Границы и репозитории

| Репозиторий | Владеет | Не владеет |
|---|---|---|
| steer | core, общий сетевой стек, route engine, DNS, scheduler, plugin manager, platform adapters, SDK host implementation | протокольные wire handlers и браузерные формы |
| plugin-sdk | форматы, provider ABI, C headers/Rust bindings, lint/pack/sign, contract fixtures | сетевые реализации и самостоятельный менеджер |
| steer-protocols | исходники существующих протоколов и новые inbound halves, features, upstream interop | независимый стек net1 и UI |
| steer-ui | HTTP management host C/Rust, browser UI, встроенные формы всех поддержанных features, Linux/OpenWrt adapters | dataplane, второй plugin manager |
| splify2 / andromeda | поддерживаемая сторона миграции | новая целевая реализация |
| steer-box-connector | совместимость podkop/forkop | изменения сторонних проектов |

Существующие splify2/plugins, splify2-core-plugins и extended-plugins не
переименовываются: их индексы и package IDs являются контрактом установок.
Два новых source repo — steer-ui и steer-protocols. Выпуск пакетов остаётся
отдельным процессом. Один исходный репозиторий может собирать много .s2p.
steer_main/steer_extended — профили/алиасы поставки, а не требование объединить
все протоколы в один загружаемый бинарник. Старые IDs vless/hysteria2/proxy/awg/
warpbox и зависимости сохраняются в переходных пакетах.

## 3. Core и перенос net1

Слои core:
1. Базовые ресурсы: allocator, monotonic time, event loop, таймеры, отмена,
   bounded buffers, async IO, entropy, credentials/secret handles.
2. Сетевые примитивы: TCP streams, UDP associations, packet IO, TUN integration,
   TLS, QUIC, HTTP transports и DNS. Их реализация обслуживается вместе с core.
3. Flow engine: metadata → policy → outbound/group → relay; accounting и health.
4. Control plane: конфигурация, dependency resolution, generation transaction,
   durable state, runtime reconciliation, capability discovery.
5. Адаптер ОС: event/IO backend, device/capture, route install, privilege broker,
   service lifecycle и package capability detection.

Net1 сегодня отдаёт внутренние структуры platform_ops/transport/pool/tun/qc
через fingerprint ABI и SONAME libs2p-net.so.1. Поэтому удаление net1 первым
коммитом запрещено. Переход:
A. Зафиксировать exports/fingerprint, текущие артефакты и regression baseline.
B. Ввести новый opaque provider API параллельно legacy API. Сетевые реализации
   остаются одного происхождения; build ownership переходит core.
C. Core поставляет общий runtime; каждый протокол переводится на новый API
   отдельным проверенным изменением, с замером размера и памяти.
D. Старый net1 пакет и путь RUNPATH остаются для старых бинарников. Compatibility
   shim допустим только если реально соблюдает прежнюю раскладку/поведение;
   иначе сохраняем точную старую библиотеку и отказываем несовместимым сочетаниям.
E. Удаление legacy library разрешается после отсутствия reverse dependencies,
   завершения rollback window и проверки offline recovery. Не переиспользовать
   прежний SONAME для несовместимого ABI.

Общие transports относятся core. Специфичные VLESS/Reality/Vision wire semantics
и протокольная аутентификация — provider. TLS-адаптации Reality проходят через
узкий TLS extension API; не копировать TLS stack в каждый provider.

## 4. Provider contract

Новый контракт имеет отдельную ось steer-provider-api, независимую от старых
steer-api/steer-abi. Draft не объявляется поддержанным runtime. Loader обязан
fail-closed проверить ось и execution mode; старому менеджеру нельзя дать
манифест, обязательные новые поля которого он просто игнорирует. До реализации
проверки новый формат не распространяется как устанавливаемый stable .s2p.

Дескриптор provider: package identity, provider ID, directions (inbound/outbound),
flow classes (stream/datagram/device), transports/security variants, платформы,
схемы параметров, зависимости и требуемые host capabilities. Направления и
комбинации объявляются независимо; наличие клиента не доказывает сервер.

Lifecycle: validate → prepare → activate → quiesce → drain → destroy.
validate не открывает listener и не меняет сеть. prepare создаёт ограниченные
ресурсы и может отказать; activate публикует listener только в новой generation.
quiesce прекращает новые соединения, drain имеет deadline; destroy освобождает
всё. Объекты соединений удерживают ссылку на generation/provider до завершения.
Отказ одного входа не становится молчаливым direct fallback.

C ABI: size/version/capability negotiated tables, fixed-width integers, opaque
handles и spans. На границе нет struct platform_ops, sockaddr, fd, FILE*,
Rust Vec/String/trait object или C++ exceptions. Явные retain/release и allocator
ownership; Rust panic не пересекает FFI. Pending operation завершается ровно
один раз успехом, отказом или отменой. Callback не вызывается после destroy;
реентерабельность/поток callback определены. Backpressure передаётся до источника.

Data API: inbound принимает transport, проверяет protocol auth, выдаёт ядру
accepted flow с destination (domain/IP+port), source, inbound ID, user ID и
flow class. Destination domain не теряется до policy/DNS. Core выбирает маршрут
и вызывает outbound open_stream/open_datagram. UDP сохраняет границы, source/
destination, association lifetime; не превращается в TCP stream. TCP сохраняет
half-close и deadlines. Внешние socket handles не являются частью общего API.

Исходящий stream передаётся парой origin-owned handle/API: операции выполняются
только через таблицу создавшего его backend. Native socket и протокольный stream
не приводятся к одной внутренней структуре. Для TLS/H2 нужен асинхронный
`finish_write`: он упорядочен после ранее принятых записей, запрещает новые записи
после принятия, но сохраняет чтение. Неподдерживаемый half-close возвращает явный
отказ, а не синтетический EOF. Это требование нового draft companion-контракта;
существующий экспериментальный `stream_v1` пока реализует только native socket.

TLS и HTTP transports нового пути составляются поверх такого stream reference,
в том числе поверх detour. Адаптер не извлекает native fd и не создаёт отдельный
поток или socketpair для каждого соединения. TLS engine принимает и выдаёт
ограниченные порции байтов; adapter переносит backpressure, отмену и deadlines
на нижний слой. Trust material готовится вне сетевого owner loop и удерживается
поколением. Проверка сертификата и имени обязательна для обычного TLS; изменение
ClientHello fingerprint или поддержки REALITY объявляется отдельной capability,
а не скрывается за общим признаком TLS. Текущий legacy `tls13_handshake_auth`
принимает fd; его наличие ещё не означает готовность такого составного backend.

В `experimental/provider/tls_stream_backend` реализован source-only адаптер
обычного TLS 1.3/X25519 с общей очередью подготовки ClientHello и проверки
сертификата. `transportprobe_build.py --origin-probe` проверяет композицию
VLESS → TLS → native stream против закреплённого Xray и Go-сервера, включая
ответ после EOF, ранний retire binding и освобождение worker последним.
Независимый прогон на четырёх owner loops с ASan/UBSan прошёл; неверное имя,
недоверенный сертификат и лимит handshake возвращают ошибку открытия с полным
завершением lifecycle. Дополнительный независимый ASan/UBSan-прогон проверяет
пять одновременных открытий на одном backend каждого owner: одно отменяется,
одно отклоняется по лимиту handshake, три передают данные и завершаются.
Оба сервера прошли этот сценарий с порциями нижнего IO по одному байту;
Go-сервер также подтвердил ответ после TLS EOF без вызова нижнего finish_write.
Тот же сценарий с Xray прошёл независимую сборку ThreadSanitizer; готовый архив
wolfSSL в этом прогоне не был целиком инструментирован.
Эти проверки не подтверждают REALITY, другие fingerprint профили или регистрацию
адаптера в работающем host/spec runtime. Отдельный независимый ASan/UBSan-прогон
на четырёх owners проверил отмену после запуска подготовки ClientHello и во время
проверки сертификата: публичные ссылки освобождаются до продолжения worker,
а backend остаётся жив до завершения его приватной работы. Проверены также
ошибка worker после фактического результата, закрытие нижнего потока между
готовностью TLS и публикацией, отказ освобождения job/нижнего потока с явным
восстановлением. Задержанная подготовка одного соединения не мешает остальным
соединениям общего backend завершить обмен. Эти fault-сценарии используют
линкерные обёртки только тестового executable, без механизма инъекции в продукте.

Первичная инициализация общего crypto backend синхронизируется на уровне самого
экземпляра backend, используемого TLS, QUIC и проверкой сертификатов. Отдельные
`pthread_once` в разных потребителях или DSO не дают общей гарантии. Проверка
холодного старта запускает эти пути одновременно в свежем процессе; успешные
повторные соединения после прогрева её не заменяют. Это обязательное условие
многопоточной интеграции, а не утверждение о проверенности всех текущих сборок.

Успешный open передаёт одну ссылку на stream, ошибка — ни одной. Отмена может
проиграть уже поставленному в очередь успеху: получатель всё равно закрывает и
освобождает возвращённый stream. Provider table и поколение удерживаются до
освобождения stream и всех operation handles, включая уже завершённые операции.
Handshake выполняется пошагово на owning shard через core IO; блокирующий legacy
connect нельзя скрывать за общей таблицей или отдельным потоком на соединение.

Основной execution mode для доверенных штатных providers — native libraries
в одном dataplane-процессе с core-owned runtime. Шарды event loop обслуживают
многие соединения и providers; нет обязательного процесса/потока/стека на протокол.
Library sharing не означает isolation: сбой native provider может остановить
dataplane. Supervisor сохраняет management endpoint и ограничивает restart loop.
Опциональный process mode изолирует группу providers, а не обязательно один
пакет; вся цепь inbound→policy→outbound по возможности размещается в одном worker.
Control messages отделены от data; в штатном relay нет RPC на каждый chunk.
Cross-worker transfer — отдельный bounded transport с измеренными издержками;
этот режим не входит в первый ABI/runtime gate. Legacy exec helpers продолжают
работать через адаптер. Hot unload запрещён при незавершённых callbacks/flows;
новый несовместимый native binary активируется rolling restart dataplane.
Loader C ABI shared module и статическая регистрация используют один descriptor;
мобильная сборка не обещает загрузку произвольных исполняемых пакетов.

WireGuard — device provider: управление kernel interface/peers и ввод пакетов
в policy, не имитация stream listener. Linux/OpenWrt приоритетно kernel backend.
На других ОС capability определяется фактическим backend; userspace fallback
не включается незаметно. WARP сохраняет feature-логику регистрации/health,
выдавая свои выходы; все её формы находятся в Steer UI.

## 5. Спека и разрешение плагинов

Новый формат version: 3. Чтение v1/v2 сохраняется с конвертацией в нормализованную
IR; v3 не пишется поверх v2 автоматически. Схема ниже — draft и не runtime support.

```yaml
version: 3
plugin_remotes:
  official:
    url: https://example.invalid/steer/index.json
    trust: official
plugins:
  steer_main:
    remote: official
    package: steer-main
    version: "*" # constraint; точная версия берётся из lock
inbounds:
  local:
    plugin: socks:steer_main
    listen: {address: 127.0.0.1, port: 1080}
    options: {auth: none}
outbounds:
  direct:
    type: direct
  vpn:
    plugin: vless:steer_main
    options: {} # реальные обязательные ключи проверяются схемой provider
routing:
  rules:
    - name: local-vpn
      match: {inbound: [local]}
      outbound: vpn
  default: direct
```

Фиксируем plugin: provider:alias (ровно одно двоеточие). Alias выбирает запись
plugins, remote выбирается только там. Поддержка provider подтверждается
подписанным manifest package/bundle, а не именем репозитория. Builtins direct,
block, group используют type; plugin и type взаимоисключающие. options —
протокольные параметры, listen — общие параметры listener. Groups, subscriptions,
DNS, secrets и users получают самостоятельные schema definitions после этого
минимального vertical slice; неподдержанные поля отвергаются, не игнорируются.

Remote URL — подписанный индекс, не git clone/build script. GitHub shorthand
может быть удобством resolve, но не доверием. Trust roots хранятся вне спеки:
импорт чужого YAML не добавляет доверенный ключ. Resolve скачивает метаданные,
проверяет подпись/срок/отзыв/antirollback/target и выдаёт reviewable plan.
Fetch/install исполняют одобренный dependency plan; apply использует локальный
lock и не ходит в сеть. Lock фиксирует package/version/provider mapping,
artifact hash, index digest, signer, target, API ranges, transitive deps.
Lock также содержит remotes snapshots: alias → URL/trust name/index digest/signer.
URL и trust должны точно совпасть с intent; повторное имя remote не разрешает
незаметно заменить источник. Имя trust не заменяет криптографическую проверку
закреплённого ключа в локальном trust store.
Конкурирующие aliases одного package не означают загрузку двух версий native
library в один namespace. Resolver либо дедуплицирует совместимую версию, либо
отказывает с конфликтом; side-by-side versions только отдельным execution mode.
В первом v3 package ID глобален в installed namespace: один package из разных
remote aliases отвергается как ambiguous origin, даже если их URL совпадают.
Для нескольких aliases одного package используется одна remote запись.

## 6. Маршрутизация и применение

Normalized IR отделяет intent от backend. Classifiers используют inbound/user,
source IP/process где доступно, destination domain/IP/port/protocol. Первая
совпавшая rule, затем explicit default. TCP/UDP выбирают generation на создании
flow. Health group selection для новых flows не ломает существующие без
явной политики. DNS requests имеют routing context, TTL и prevention of loops;
исходящий tunnel control traffic не захватывает собственный inbound повторно.

Исполнитель использует типизированные node/edge/rule views компилятора
`experimental/spec`, а не восстанавливает конфигурацию из диагностического JSON.
План владеет исходными options до завершения подготовки; асинхронная подготовка
копирует нужные данные либо удерживает план. Результат выбора маршрута связывается
с immutable backend instance и его поколением, а не с отдельной веткой relay
для каждого имени протокола. Groups выбирают такое же binding для нового flow.

Для UDP ядро владеет ограниченным кэшем fixed-remote targets внутри конкретной
клиентской ассоциации. Протокольный адаптер запрашивает target через policy и
получает origin-owned datagram reference; самостоятельно сокеты не открывает.
Область кэша включает протокольную UDP-сессию, source, identity и generation,
а не только пользователя или аутентифицированное QUIC-соединение. Ответ из
старой сессии не должен получить идентификатор новой. Idle eviction разрешён
после освобождения всех public references и IO operations; исчерпание общего
бюджета associations/targets возвращает явную ошибку. Retire прекращает новые
открытия, сохраняя предусмотренное завершение уже принятых операций.

Экспериментальный UDP router поддерживает immutable registry подготовленных
provider bindings. Внутри ассоциации ключ кэша включает destination и выбранный
binding: одинаковый адрес через разные выходы не объединяет сокеты или ответы.
Выбор проверяет поколение, класс потока и возможности провайдера до открытия;
ошибка выбора не разрешает прямой выход. Registry удерживает экземпляры
провайдеров до завершения private cleanup. Атомарный lifetime lease не разрешает
параллельные вызовы одного context: методы сериализуются его owner loop.
Если destroy пока невозможен из-за private cleanup, её завершение должно
уведомить owner и запустить повторную сборку поколения. Нельзя ждать только
финального lease callback, когда сам router ещё удерживает его parent pin.
Уведомление планирует работу после возврата текущего callback; оно не уничтожает
router внутри его pump. Проверка освобождения включает период без трафика и
запросов управления, чтобы STATUS polling не скрывал отсутствующее уведомление.
Это отдельный проверяемый модуль; управляемый HY2 пока использует прежний
конструктор DIRECT/BLOCK, а исполнение полной spec v3 ещё не подключено.

При reload уже открытый UDP target сохраняет своё поколение; новый destination
проходит policy текущего поколения. Адаптер может удерживать несколько
generation-scoped route contexts одной реальной протокольной сессии, но их
суммарные targets/operations/bytes учитываются одним бюджетом сессии. Reload
не обнуляет лимиты и не позволяет снова открыть retired context. Retired
listener не принимает новые сессии или destinations; уже принятый обмен
завершается по правилам drain. Фрагменты одного UDP-пакета объединяются только
при совпадении session, packet ID, fragment count и точного destination;
смена адреса не должна переносить собранную полезную нагрузку под другую policy.

Лимиты отдельных UDP-сессий дополняет общий бюджет сервиса, переживающий reload.
При совместном buffer host сохраняется резерв TCP по байтам и количеству
буферов. UDP резервирует свой лимит до выделения памяти; его учитывают receive
buffers, очереди отправки, частично собранные пакеты и временное перекрытие
буферов при сборке. Освобождение после отмены происходит только после возврата
владения. Новое соединение или поколение не создаёт новый общий бюджет.
Обработка targets и исходящих фрагментов ограничивается за один проход с
продолжением в следующем обороте event loop, чтобы большой пакет или очередь
не задерживали соседние соединения и управление.

Stream и datagram backend используют одинаковую модель открытия: host-selected
binding, скопированные flow metadata, абсолютный monotonic deadline и один
отложенный результат с origin-owned reference. До открытия проверяется точное
поколение; lease удерживается до освобождения соединения и всех операций,
включая уже завершённые, но ещё не освобождённые. Optional bound/peer metadata
действуют только внутри callback и описывают реальный endpoint. Диагностика
ошибки принадлежит результату операции, а не общему mutable last-error.
Передача между worker и owning loop использует синхронизированную очередь;
подготовленный объект не изменяется обоими потоками одновременно. Наличие
четырёх отдельных owner loops не разрешает конкурентные вызовы одного handle.

Worker-prepared состояние переносимо между потоками пула после синхронизированной
передачи: подготовка и поздняя очистка могут выполняться разными workers,
без одновременного доступа. Ошибка подготовки очищается в том же вызове;
owner-bound handles сохраняют привязку к своему loop. Скрытая зависимость
prepared объекта от thread-local состояния недопустима. Device job удерживает
namespace fd и восстанавливает исходный namespace worker перед повторным
использованием потока. При отказе восстановления поток выводится из работы;
фактический результат уже выполненной операции всё равно передаётся владельцу,
а следующие задачи не запускаются в оставшемся чужом namespace.

В source-only `experimental/provider/host_worker` этот scope реализован хостом:
fd дублируется при admission, исходный namespace берётся из
`/proc/thread-self/ns/net`. Автоматического respawn нет; при потере последнего
worker оставшиеся задачи получают отложенную ошибку без запуска provider.
Реальный enter/restore проверяется отдельным `host-worker-namespace-actual-test`
в disposable namespace; отказ restore — инъекцией в
`host-worker-namespace-test`. `execution-async-test` проверяет отмену после
успешной подготовки до owner callback и очистку на другом потоке пула.
Эти проверки не означают, что новый executor уже подключён к применению
конфигурации работающего прототипа.

Общий packet reader не должен ждать освобождения очереди одного перегруженного
owner и тем самым останавливать остальных. Планировщик ограничивает как память
отложенных пакетов, так и работу за оборот, сохраняя порядок внутри flow;
переполнение учитывается явно. Уменьшение таймаута ожидания само по себе не
доказывает исправление: сравниваются потери и задержка соседнего здорового owner
при намеренно остановленном потребителе. Legacy `reader_loop` больше не ждёт
до 20 мс на каждом пакете полного кольца: отбрасывает только его избыточный
пакет со счётчиком и продолжает читать для остальных владельцев. Дополнительной
очереди или памяти это исправление не добавляет. Throughput-тест
не заменяет проверку изоляции перегрузки. В частности,
`tests/run-tunnel-mt.sh` перенаправляет TCP к слушателям через `redir_dev`
и проверяет отсутствие TCP-пакетов в TUN: этот сценарий не нагружает
указанную очередь reader. `tests/tun-reader-build.sh` собирает отдельный тест
реального reader; режим `--tun` требует disposable network namespace и
`STEER_TEST_READER_NETNS=1`. В Linux-проверке заполненное кольцо одного owner
задерживало здорового примерно на 1,287 с до исправления и примерно на 1 мс
после него. Проверены обычный трафик, перегрузка и возобновление потребления:
порядок принятых пакетов сохранён, 64 избыточных пакета полного кольца учтены
как потери, память двух колец осталась 786432 байта. ASan/UBSan/LSan прошли
на настоящем kernel TUN. Это проверка малых UDP-пакетов и SPSC-пути;
она не доказывает отсутствие потерь при любой нагрузке или свойства oversized
mailbox-пути и не является измерением производительности всех платформ.

Для общих generation leases admission и retire имеют одну атомарную точку
упорядочивания: проверка «ещё активно» отдельно от увеличения счётчика
недостаточна. Нулевой refcount также не доказывает завершение последнего
producer: owner не освобождает lease/eventfd, пока producer ещё публикует
уведомление. Финализатор выполняется на owning loop после публикации завершения
последнего освобождения; тесты должны управляемо задерживать эту публикацию
одновременно с retire/destroy, а не проверять только итоговый счётчик.

Абсолютное monotonic время и сроки требуют 64-битного типа на всех платформах.
Прежние signed `long` milliseconds переполнялись на 32-битной платформе примерно
после 24,9 суток uptime. В рабочем дереве часы loop/helpers и абсолютные сроки
переводятся на `int64_t`; относительные интервалы с legacy `long` сохраняются с
ограничением при преобразовании. `tests/clock64match.c` проверяет конверсию,
поля helpers и реальные loop timers на подставных часах через границы INT32_MAX
и UINT32_MAX. Тест прошёл на настоящем ELF i386 (`sizeof(long)==4`) и x86_64
с ASan/UBSan; отрицательный контроль на прежнем коде воспроизводит усечение.
Это не заменяет проверку всех потребителей (`ctl`, `folat`, `foprobe`, `rulewd`,
`urltest`, супервизоры), экспортов и layout перед выпуском либо испытаний на
ARM/MIPS OpenWrt. Системные часы при тесте не меняются.

Наличие API-таблицы не означает готовность provider: compiler inventory отражает
реально доступную комбинацию направления, flow class, транспорта и security,
а подготовка ещё может завершиться ошибкой. `steer-linux-v1` остаётся временным
входным форматом прототипа; расширение его форм не заменяет исполнение полной v3.

Apply: parse → validate references/capabilities → resolve against lock →
compile IR → diff resources → prepare new generation → readiness → durable
configuration commit → memory-only publication → drain old. Все шаги имеют
transaction ID. Для kernel devices общий coordinator создаёт ID и надёжно
записывает intent с точной provider recovery record ДО первой внешней мутации;
последующие записи фиксируют фактический результат, включая неопределённый.
Запись intent не означает, что новая конфигурация уже применена. После сбоя
coordinator сопоставляет журнал с committed revision: незавершённые эффекты
очищает только после проверки владения, а уже committed revision не откатывает
на основании отсутствующего callback. Неопределённое состояние требует
reconcile и не допускает автоматического повторного включения устройства.

Разрешение на мутацию выдаётся из owner-cache только для одной точной durable
intent-записи: transaction, instance и sequence вместе с operation, generation,
provider/version и recovery identity. Повторное совпадение остальных полей не
делает старый запрос разрешением на новую попытку. Claim потребляется до
enqueue; release удерживающего ресурсы permit не восстанавливает claim.
Первый вариант не переиспользует даже отклонённый enqueue: фиксируется
UNCHANGED, а повтор требует нового intent. Это контракт интеграции, не
утверждение о подключённом coordinator.

В `experimental/spec/execution_journal.{c,h}` реализованы Linux-примитивы
неизменяемых записей intent/outcome/reconcile и ограниченного сканирования после
перезапуска. Отдельный filesystem-тест проверяет потерянный результат,
неопределённую durability после rename, аварийный выход до rename, FIFO и
повреждённые записи; ASan/UBSan/LSan прошли. Распознанные временные файлы
учитываются в лимите и не дают права менять сеть. Отдельный
`execution_reservations` восстанавливает ограниченные резервы по durable
ownership anchor: ACTIVE/UNKNOWN не освобождают место для teardown, grant
сам занимает запись, а поздний результат старого intent не меняет состояние
нового. Проверены перезапуск, отказ нового COMMIT при неопределённом результате,
отказ устаревшего reconcile и сохранение cleanup reserve (ASan/UBSan/LSan).
Это ещё не подключённый coordinator: применение разрешений до мутации,
восстановление относительно committed revision и безопасная очистка завершённых
транзакций остаются обязательными этапами интеграции.

`device_authority_service` сериализует запись ledger на общем worker pool и
выдаёт разрешения из ограниченного owner-cache только после INTENT_SYNCED.
При ошибке worker сохраняется фактическая квитанция записи, но admission
блокируется отдельно. После ошибки directory fsync разрешена явная worker-side
проверка всего журнала → fsync каталога → повторная проверка. Она снимает лишь
неопределённость хранения; старые claims не становятся READY снова. Поздняя
отмена или истёкший срок доставки результата также не снимают owner-side fence.
Для неопределённого результата устройства остаются factual UNKNOWN и новый
точный intent на guarded retire. Ошибка worker не снимается восстановлением
одного только хранилища.

Тесты authority проверяют одноразовость, удержание scope до освобождения jobs
и permits, ошибки worker/fsync, повторное восстановление и поздние результаты.
ASan/UBSan/LSan и TSan прошли для проверенных сценариев; тест удаления использует
реальный принадлежащий стенду eventfd, а не WireGuard. Подключение этого сервиса
к device factory и полному host apply ещё не выполнено. Остановка сервиса сама
по себе не обещает drain: оставшиеся намерения должны получить достоверный
результат либо оставаться явно удержанными для восстановления.

Ресурс bind/listen collision учитывает TCP/UDP, wildcard, IPv4/v6 dual stack,
exclusive device ownership. Для same-port replacement используется handover
через host-owned listener, когда backend это поддерживает; иначе панель явно
показывает restart gap. Нельзя обещать полную атомарность между nft, kernel WG,
files и процессами: journal + compensating rollback, restore failure виден
как degraded. До commit сохраняется старая рабочая конфигурация; после commit
результат определяется фактически сохранённой revision, а не успехом ответа.

Восстановление kernel resources после сбоя требует доказательства владения,
сохранённого до изменения сети: идентификаторы запуска ОС и namespace, а также
проверяемая метка принадлежащего транзакции ресурса. Имя, kind и ifindex сами по
себе недостаточны после перезапуска или повторного использования индекса.
Неопознанный интерфейс или nft table не усыновляется и не удаляется по имени.
При откате WG сначала отключается или удаляется подтверждённо принадлежащий
ему интерфейс, затем снимается его guard; обратный порядок открывает окно
нефильтрованного трафика. Это требование управляемой интеграции, а не свойство,
уже доказанное изолированным lifecycle-тестом адаптера.

Netlink-вызовы из bounded workers должны быть независимы: буфер ответа и его
очистка принадлежат одной операции, а счётчики запросов не создают общей
изменяемой памяти без синхронизации. Лимит памяти учитывается на число одновременно
работающих операций; перенос большого общего буфера на стек каждого вызова не
считается достаточным решением для OpenWrt. Ожидание ответа ограничено абсолютным
deadline, включая повторные recv и EINTR. Проверки параллельных read-only запросов
и потерянного ACK обязательны до подключения адаптера к нескольким workers.
Сам по себе успешный последовательный namespace-тест этого не доказывает.

Отмена подготовки и истечение её срока запрещают последующую публикацию.
После передачи изменения в durable commit потеря HTTP/control-ответа уже не
доказывает откат: если rename выполнен, runtime должен соответствовать новому
снимку. Мост UI различает отказ до отправки запроса и неизвестный результат
после отправки. Для неизвестного результата нет автоматического повторного
APPLY; панель сохраняет черновик и сверяет revision/document/status с ядром.
Ошибка directory fsync после rename означает действующую конфигурацию с
неподтверждённой долговечностью, а не сохранение прежней ревизии.

Для QUIC и других соединений с несколькими flows quiesce запрещает также
новые потоки внутри уже установленного соединения. Каждый новый flow проверяет
текущие inbound admission и auth epoch; уже принятый удерживает свою generation
до завершения всех IO callbacks. Retire listener не равен закрытию UDP socket:
сокет и состояние протокола остаются для drain существующих flows до заданного
срока. Подготовленный listener не допускает application flows до публикации.
Если backend не умеет передать тот же UDP endpoint новой generation, повторное
занятие адреса до завершения drain явно отклоняется; SO_REUSEPORT не подменяет
handover. Эти требования следуют lifecycle SDK; их исполнение проверяется
отдельно от успешного bind и протокольного echo.

Секреты — typed references, выдаются только нужному provider; отсутствуют в
status/diff/log/export по умолчанию. Secret rotation меняет generation и имеет
конкретный restart/drain policy. Публичный inbound без auth требует явного
осознанного разрешения, loopback SOCKS допустим без auth. Management endpoint
изолирован от proxy listener и имеет отдельную auth/RBAC модель.

## 7. Платформы

| ОС | Первый режим | Сетевой backend | Ограничения проверки |
|---|---|---|---|
| Linux | proxy server/client | sockets + optional TUN/nft/netlink/kernel WG | WSL для functional tests; native Linux для perf и kmod |
| OpenWrt | gateway + local proxy | Linux fast paths + procd/netifd adapters | musl, flash/RAM budgets, sysupgrade, реальные ARM/MIPS |
| Windows | local proxy затем capture | IOCP/socket adapter, optional TUN/route service | Windows CI и подписанные driver/service требования отдельно |
| Android | VPN client | VpnService TUN handle и protected sockets | lifecycle/permission/background limits; no root assumption |
| iOS | исследовательский VPN client | Network Extension packet tunnel | entitlement, app lifecycle, distribution/static providers; server parity не обещается |

Capabilities отвечают отдельно built/supported/available/authorized; название
ОС не является доказательством доступности TUN или WG. Linux explicit profile
добавляется без смены legacy fallback openwrt. Generic socket server не требует
nft/TUN/root. Глобальные DNS/route/firewall изменения только при явно выбранном
capture режиме. Нельзя считать WSL benchmark реальным performance release gate.

## 8. Steer UI

Один устанавливаемый плагин, browser assets + C/Rust management host. Статические
assets общие для Linux/OpenWrt; framework только build-time, Node на устройстве
не нужен. Управление доступно при остановленном dataplane: control supervisor
и dataplane имеют разные состояния. Остановка routing не означает потерю UI;
полное отключение UI-плагина убирает endpoint, сохраняя настройки.

Контракт management API versioned: capabilities, config snapshot/revision,
validate/diff/apply job, job status/cancel, runtime state/events, plugin plan,
users/credentials/subscriptions, diagnostics. Optimistic revision check не даёт
второму окну затереть первое. Idempotency keys у mutations, bounded event replay,
resync при разрыве. Unix socket/Windows named pipe local transport; HTTP наружу
только через auth/TLS boundary. Не выдавать произвольный CLI execute endpoint.

Входы → правила → выходы; contextual inspector; отдельный табличный режим для
больших наборов; keyboard/mobile/a11y; пользователь видит outcome и причину
отказа. Draft → diff → validate → apply. Не включать autoapply на каждый символ
по умолчанию. Public endpoint для share link отличается от bind address.
UI WARP/прочих features встроен в Steer UI; generic schema forms допускают
сторонние providers без загрузки произвольного JS из protocol packages.

## 9. Совместимость и миграция

Три независимые совместимости: wire upstream, сохранённая конфигурация, plugin
binary/API. Ни одна не выводится из двух других. Текущие C outbound implementations
сохраняются и покрываются regression до перемещения исходников.

Migration tool сначала inspect/plan без записи: v1/v2, paths, plugin versions,
settings, subscription refs, keys, routes, UI preferences, legacy consumers.
Backup включает manifest и secret-bearing файлы с прежними правами. Conversion
строит v3 + lock рядом, оставляя старую конфигурацию. Включение — отдельный шаг
после validation и smoke; rollback восстанавливает binary/plugin generation,
config и service registration. Старые clients/RPC получают adapter пока заявлен
support window; неизвестные поля v2 сохраняются или дают явный отказ, не теряются.

net1 removal, protocol extraction и UI cutover не выполняются одной транзакцией
релиза. Порядок: SDK contracts → host capability → один provider → interop/perf →
remaining providers → UI vertical slice → legacy migration → platforms.
Podkop/forkop адаптируются только в connector. Не менять upstream-пользователей.

## 10. Upstream и inbound

Upstream фиксируется полным commit, source paths, build flags и лицензией на
конкретные использованные файлы. Go runtime допускается в test lab, не в пакете.
Сначала переносить поведение/fixtures, не transliterate код. Переиспользовать
проверенные C outbound codecs где это сохраняет wire semantics. Не писать
криптографические примитивы заново. Заимствования сохраняют notices; лицензия
зависимостей проверяется до объединения в распространяемый бинарник.

Для каждого протокола отдельные строки upstream client→Steer inbound и Steer
outbound→upstream server. Дополнительно old Steer client/server→new совместимая
сторона. Каждая transport/security/cipher версия имеет свой результат.
VLESS basic, Reality, Vision, XUDP/mux, encryption extensions — разные capability
rows. HY2 H3 auth, status 233, QUIC DATAGRAM, fragmentation, masquerade и obfs
проверяются отдельно. WG — kernel peers/devices/route cleanup, не stream codec.
SOCKS auth, UDP association ownership и HTTP CONNECT policy тестируются отдельно.
Unsupported не означает pass. Никаких wildcard обещаний «весь Xray».

Обязательны IPv4/IPv6/domain, auth failure, malformed/truncated frames, replay,
clock skew где уместно, MTU/loss/reorder, TCP half-close, cancellation/backpressure,
restart/drain, occupied port и cleanup. Upstream pins и исходные пути — в
steer-protocols/docs/upstream-compatibility.md. Mieru не реализуется.

## 11. Производительность и этапы допуска

До изменений снять baseline pinned Steer: stripped binary + compressed package,
resident/PSS idle и under load, allocations per flow, CPU per Gbit/s, handshake
rate, latency p50/p95/p99, throughput, packet loss, startup/reload/drain time.
Те же toolchain/flags/kernel/CPU/governor/payload/concurrency; несколько повторов,
сохранённые сырые результаты. На OpenWrt дополнительно flash/install peak RAM.
Включённый и выключенный UI измеряются отдельно. Сравнение имеет provenance;
старые результаты tools/bench не переносятся автоматически на новую сборку.

Численный budget утверждается по реальной baseline, не выдумывается из головы.
Любой регресс размера/RAM/CPU/latency требует разбора и явного принятия; без
него этап не считается готовым. Microbench не заменяет upstream interop, stress,
ASan/UBSan/fuzz и пользовательский end-to-end. Zero-copy — только измеренное
свойство конкретного участка, не обещание для encrypted traffic.

| Этап | Результат | Gate |
|---|---|---|
| A | draft SDK schemas, baseline harness, platform capability API | compatibility/unit tests; legacy без изменений |
| B | provider host + SOCKS stream/datagram vertical slice | upstream interop, lifecycle и perf |
| C | core-owned network runtime + legacy net1 compatibility | old plugins load/rollback, outbound regression |
| D | VLESS затем HY2, WG и остальные текущие protocol inbounds | матрица variants и resource cleanup |
| E | Steer UI Linux с реальным core и Linux migration | подключение→правило→выход, revision/auth/recovery, upgrade/offline rollback |
| F | OpenWrt migration и integration | upgrade/remove/rollback/offline/sysupgrade |
| G | Windows/Android и iOS feasibility | native platform CI и реальное устройство |

Этапы D/E допускают параллельную реализацию после стабильного B, но не
независимое изобретение transport/API. UI не блокирует работу CLI/core.
