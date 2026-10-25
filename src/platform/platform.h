/* Платформа, на которой запущен движок: роутер OpenWrt или телефон Android.
 *
 * Решение владельца (docs/architecture.md, раздел 2, правило 2): «Платформа — модуль,
 * выбираемый при запуске. Отличия телефона от роутера лежат в platform/android.c и
 * platform/openwrt.c за одной таблицей struct platform_ops. Один бинарник сам определяет, где
 * он запущен, а --platform переопределяет выбор для стендов. #ifdef STEER_ANDROID в общем коде
 * нет.»
 *
 * ЧТО ЗДЕСЬ, А ЧТО У СЛОЁВ. Платформа — самый нижний слой после lib: её спрашивают разбор спеки
 * (zapret и каналы на само устройство), реестр (поле метки), компилятор, демон, резолвер и
 * протоколы. Поэтому таблица держит ДАННЫЕ и ПРИЗНАКИ — пути, раскладку меток, «есть ли fw4»,
 * «оживляет ли сторож интерфейсы через netifd», — а код, который по признаку работает
 * (цепочки output для каналов на телефон, masquerade правилом iptables, метка сети netd у
 * резолвера), живёт у своего слоя и спрашивает признак. Положи мы построители цепочек сюда,
 * платформа зависела бы от компилятора, а стенды модели, которые её линкуют, — от всего
 * движка.
 *
 * ПРИЗНАКИ НАЗВАНЫ ПО СВОЙСТВУ, а не по имени платформы: общий код спрашивает «есть ли fw4», а
 * не «не Android ли это». Третья платформа (настольный Linux без fw4) тогда — ещё одна
 * таблица, а не развилка на три ветки в каждом месте.
 *
 * ВЫБОР (platform.c, plat()): --platform или STEER_PLATFORM, затем умолчание сборки
 * (-DSTEER_DEFAULT_PLATFORM=android у цели build/steer-android и в Android.bp — они ведут себя
 * как прежде, где бы ни запустились), затем признаки среды (Android — /system/build.prop или
 * ANDROID_ROOT, OpenWrt — /etc/openwrt_release), и если ничего не узнано — openwrt. Код обеих
 * платформ есть в любом бинарнике. */
#ifndef STEER_PLATFORM_H
#define STEER_PLATFORM_H
#include <stddef.h>
#include <stdint.h>

struct platform_ops {
    const char *name;                 /* как пишется в --platform и STEER_PLATFORM */
    int (*detect)(void);              /* 1 — похоже, что запущены здесь; NULL — не узнаётся */

    /* ---- пути (почему корни одним местом — в шапке openwrt.c) -------------------------- */
    const char *etc_dir;              /* спека, списки, файлы выходов, сокет управления */
    const char *state_dir;            /* реестр, fake-ip, пробы; --state-dir переопределяет */
    const char *tmp_dir;              /* времянки набора правил и проб */
    const char *lists_dir;            /* куда put-file кладёт файлы приложения */
    const char *spec_path;            /* спека по умолчанию */
    const char *ctl_sock;             /* сокет управления (ctl-serve) */
    const char *rt_tables_d;          /* имена таблиц для iproute2; NULL — не ведутся */
    const char *tun_dev;              /* узел TUN */
    const char *tun_hint;             /* что сказать, когда узла нет */
    const char *const *ca_dirs;       /* системное хранилище корней, NULL-конец; NULL — нет */

    /* ---- раскладка метки (подробно — marks.h) ------------------------------------------- */
    uint32_t mark_base;               /* младший бит поля метки движка */
    unsigned mark_bits;               /* ширина поля */
    uint32_t mark_mask;               /* маска поля — PLAT_MARK_MASK(база, ширина) */
    unsigned rule_pref;               /* приоритет ip rule выходов; 0 — не передавать pref */
    unsigned probe_pref;              /* приоритет правила пробы сторожа */
    uint32_t reroute_bit;             /* бит перемаршрутизации в старой раскладке; 0 — нет */
    uint32_t self_mark;               /* метка собственного трафика движка; 0 — не метится */
    uint32_t tunnel_bit;              /* бит собственного трафика туннеля через via; 0 — нет */
    unsigned app_uid_min;             /* первый UID приложений (канал «self») */

    /* ---- что на платформе есть ---------------------------------------------------------- */
    unsigned local_channels : 1;      /* каналы на само устройство: from self / uid:N */
    /* DNS самого устройства — в резолвер движка (цепочка output_dns, local_dns_redirect). Телефон —
     * да: приложения спрашивают netd, и иначе имена под правилами им не достались бы. Роутер с
     * каналами на себя (STEER_ROUTER_SELF, platform.c) — нет: его DNS — это dnsmasq, а dnsmasq у
     * podkop и forkop спрашивает 127.0.0.42, то есть коннектор, который сам спрашивает dnsd; заворот
     * отправил бы вопрос dnsmasq в dnsd, а имя вне правил — обратно в dnsmasq, по кругу. */
    unsigned local_dns : 1;
    unsigned zapret : 1;              /* системный zapret: бит пропуска и on_fail zapret */
    unsigned fw4 : 1;                 /* firewall4: проверки зоны и masquerade после apply */
    unsigned netifd : 1;              /* сторож оживляет интерфейс ifdown/ifup и procd */
    unsigned iptables_masq : 1;       /* masquerade выходов — правилом nat iptables движка */
    unsigned lan_bridge : 1;          /* раздача через мост Linux (diag про br_netfilter) */
    /* Устройства раздачи (lan_devices) живут постоянно, а не появляются и исчезают по требованию.
     * От этого зависит, вешать ли разметку каналов на хук ingress этих устройств (compile/
     * generate.c, «разметка на ingress»): цепочка ingress привязана к устройству, исчезнувшее
     * устройство ядро из неё вынимает, а с последним снимает и саму цепочку. Где устройства
     * раздачи создаёт включение раздачи (телефон: rndis0, wlan1, ncm0), каждое включение и
     * выключение меняло бы набор правил в ядре и звало бы его полную замену. */
    unsigned lan_devs_persist : 1;
    /* Раздачу IPv6 в LAN ведут netifd и odhcpd — настройка человека, по которой адреса префикса
     * хоста доходят до клиентов (ip6prefix, ip6assign). Тогда действуют `ipv6: routed` и `ipv6:
     * nat` у выхода (шаг 8 выпуска 1.10, spec.h: out_ipv6_mode). На телефоне раздачей IPv6
     * владеет Tethering Android, и эти режимы там — отсутствие ключа с предупреждением. */
    unsigned lan_ipv6_host : 1;
    unsigned warn_iptables_nat : 1;   /* старое ядро: предупреждать о живом nat iptables */
    unsigned dnsd_origdst : 1;        /* резолвер переспрашивает того, к кому шёл запрос (умолчание) */
    const char *ctl_allow_domain;     /* SELinux-домен клиента сокета; NULL — проверки нет */
    /* Таблица «пакет → UID» (package_name из наборов sing-box, src/model/srsplan.c); NULL —
     * приложений на платформе нет, и правило набора про приложение не выражается. */
    const char *packages_list;

    /* ---- устройство для заголовков подписки (src/tools/hwid.c) --------------------------- */
    const char *os_release;           /* файл версии системы; NULL — только имя os_name */
    const char *os_name;              /* имя системы */
    const char *model_path;           /* где ядро или система называет модель */
    const char *model_fallback;       /* модель, если не названа */
};

/* Маска поля выводится из базы и ширины, а не пишется третьим числом: три записанных руками
 * числа разошлись бы при первом изменении любого из них (marks.h). Полем, а не выражением у
 * каждого читателя, — маску спрашивают в каждом правиле, и считать её заново незачем. */
#define PLAT_MARK_MASK(base, bits) ((((1u << (bits)) - 1u)) * (base))

extern const struct platform_ops plat_openwrt, plat_android;

/* Выбранная платформа. Выбор делается при первом вызове и дальше не меняется. */
const struct platform_ops *plat(void);
/* Платформа по имени или NULL. */
const struct platform_ops *plat_by_name(const char *name);
/* Выбрать явно (--platform): 0 — выбрана, -1 — нет такой. Имя уходит и в окружение
 * (STEER_PLATFORM), чтобы процессы, которые движок запускает сам (dnsd, помощники выходов),
 * работали на той же платформе. */
int plat_select(const char *name);
/* Имена всех платформ через запятую — для сообщений об ошибке. */
const char *plat_names(void);

/* Каталог состояния этого запуска: --state-dir, если задан, иначе путь платформы. */
const char *steer_state_dir(void);
void steer_set_state_dir(const char *dir);        /* NULL — вернуть путь платформы */
/* Каталог имён таблиц iproute2; NULL — платформа их не ведёт. Сеттер — шов стендов. */
const char *steer_rt_tables_dir(void);
void steer_set_rt_tables_dir(const char *dir);    /* NULL — вернуть путь платформы */
/* "<etc_dir>/<name>" в buf; возвращает buf. */
const char *plat_etc_path(char *buf, size_t n, const char *name);
/* КАТАЛОГ ВЫБОРА ЧЕЛОВЕКА — то, что обязано пережить перезагрузку (выбор `select` группы
 * pick: manual). Каталог состояния на роутере — tmpfs (/var/lib/steer живёт в /var → /tmp), и
 * запись там переживает перезапуск службы, но не перезагрузку. Постоянный носитель — каталог,
 * где лежит сама спека этого запуска (у пакета — etc платформы: /etc/steer на роутере, он же
 * объявлен в keep.d и переживает sysupgrade; /data/misc/steer на телефоне): выбор — такая же
 * настройка человека, как спека, только сделанная командой, а не правкой файла. Каталог
 * спеки, а не etc платформы, — затем, чтобы стенд с `--spec $tmp/spec.yaml` писал выбор к себе,
 * а не в /etc машины.
 *
 * steer_set_keep_dir_of — по пути спеки, которую читает этот запуск (NULL — умолчание: etc
 * платформы); зовут точки входа, разобравшие --spec (main.c, демон). */
const char *steer_keep_dir(void);
void steer_set_keep_dir_of(const char *spec_path);

/* СПЕКА ПО УМОЛЧАНИЮ — spec.json или spec.yaml рядом (docs/spec-v2.md, «Файл спеки»).
 * plat_spec_yaml — путь spec.yaml рядом с spec_path. plat_spec_default — какую из двух читать:
 * spec.yaml, если есть только она, иначе spec_path (и когда нет ни одной — прежний путь, в
 * который пишет управляющий слой). Обе сразу — отказ «две спеки» у load_spec, а не выбор. */
const char *plat_spec_yaml(void);
const char *plat_spec_default(void);
/* Файл спеки за путём, названным явно: путь из пары по умолчанию (spec.json или spec.yaml — так
 * их называет init-скрипт, `--spec /etc/steer/spec.json`) значит «какая из двух лежит сейчас»
 * (plat_spec_default), любой другой путь и NULL (→ умолчание) — как есть. Так же поступает
 * load_spec; нужно тем, кто открывает файл спеки сам: демон (куда ctl apply кладёт тело, что
 * отвечает version) и клиент (тот ли это демон, что читать для apply). */
const char *plat_spec_resolve(const char *path);

#endif
