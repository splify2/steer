/* Только тестовая сборка: отказ конкретного RTM_NEWRULE до отправки ядру.
 * Остальные netlink-запросы и всё состояние обрабатывает настоящее ядро. */
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

ssize_t __real_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t __wrap_sendto(int fd, const void *buf, size_t len, int flags,
                      const struct sockaddr *to, socklen_t tolen) {
    const char *flag = getenv("STEER_TEST_RULE_FAULT");
    if (flag && access(flag, F_OK) == 0 && to && to->sa_family == AF_NETLINK &&
        len >= NLMSG_LENGTH(sizeof(struct rtmsg))) {
        const struct nlmsghdr *h = buf;
        const struct rtmsg *r = NLMSG_DATA(h);
        if (h->nlmsg_type == RTM_NEWRULE && r->rtm_family == AF_INET) {
            int f = open("/tmp/rule-fault-hit", O_WRONLY | O_CREAT | O_APPEND, 0600);
            if (f >= 0) { (void)write(f, "hit\n", 4); close(f); }
            errno = EACCES;
            return -1;
        }
    }
    return __real_sendto(fd, buf, len, flags, to, tolen);
}
