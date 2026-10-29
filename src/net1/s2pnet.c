/* net1: версия ABI и отпечаток раскладки (s2pnet.h). */
#include "s2pnet.h"

const struct s2p_net_abi *s2p_net_abi(void) {
    static struct s2p_net_abi a;
    if (!a.size) {
        a.major = S2P_NET_ABI_MAJOR;
        a.minor = S2P_NET_ABI_MINOR;
        a.fingerprint = s2p_net_fingerprint_calc();
        a.version = S2P_NET_VERSION;
        a.size = sizeof(a);
    }
    return &a;
}
