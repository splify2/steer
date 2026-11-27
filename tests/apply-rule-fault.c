/* Только тестовая сборка: отказ выбранной операции до отправки ядру.
 * Остальные netlink-запросы и всё состояние обрабатывает настоящее ядро. */
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void hit(const char *what) {
    int f = open("/tmp/rule-fault-hit", O_WRONLY | O_CREAT | O_APPEND, 0600);
    size_t n = strlen(what);
    if (f < 0 || write(f, what, n) != (ssize_t)n || close(f) != 0) _exit(125);
}
int __real_socket(int, int, int);
int __wrap_socket(int family, int type, int protocol) {
    const char *mode = getenv("STEER_TEST_RULE_MODE");
    if (family == AF_INET6 && type == (SOCK_DGRAM | SOCK_CLOEXEC) && !protocol &&
        mode && !strcmp(mode, "no-family6")) {
        hit("no-family6\n"); errno = EAFNOSUPPORT; return -1;
    }
    return __real_socket(family, type, protocol);
}
ssize_t __real_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t __wrap_sendto(int fd, const void *buf, size_t len, int flags,
                      const struct sockaddr *to, socklen_t tolen) {
    const char *flag = getenv("STEER_TEST_RULE_FAULT");
    if (flag && access(flag, F_OK) == 0 && to && to->sa_family == AF_NETLINK &&
        len >= NLMSG_LENGTH(sizeof(struct rtmsg))) {
        const struct nlmsghdr *h = buf;
        const struct rtmsg *r = NLMSG_DATA(h);
        const char *mode = getenv("STEER_TEST_RULE_MODE");
        if (h->nlmsg_type == RTM_NEWRULE &&
            ((!mode && r->rtm_family == AF_INET) ||
             (mode && !strcmp(mode,"rule6") && r->rtm_family == AF_INET6))) {
            hit(r->rtm_family == AF_INET6 ? "rule6\n" : "rule4\n");
            errno = EACCES;
            return -1;
        }
        if (mode && h->nlmsg_type == RTM_NEWROUTE &&
            ((r->rtm_family == AF_INET6 && r->rtm_type == RTN_PROHIBIT) ||
             (r->rtm_family == AF_INET && r->rtm_type == RTN_BLACKHOLE))) {
            int n = RTM_PAYLOAD(h), metric = 0;
            for (struct rtattr *a = RTM_RTA(r); RTA_OK(a,n); a = RTA_NEXT(a,n))
                if (a->rta_type == RTA_PRIORITY) metric = 1;
            const char *op = r->rtm_family == AF_INET ? (metric ? "backstop4" : "fallback4")
                                                       : (metric ? "backstop6" : "fallback6");
            if (!strcmp(mode, op)) {
                hit(op); hit("\n"); errno = EACCES; return -1;
            }
        }
    }
    return __real_sendto(fd, buf, len, flags, to, tolen);
}
