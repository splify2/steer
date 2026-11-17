#include <wolfssl/ssl.h>
#include "steer_init.h"
static int init_result = -1;
#ifdef _WIN32
#include <windows.h>
static INIT_ONCE init_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK initialize(PINIT_ONCE once, PVOID arg, PVOID *ctx) {
    (void)once; (void)arg; (void)ctx;
    init_result = wolfSSL_Init() == WOLFSSL_SUCCESS ? 0 : -1;
    return TRUE;
}
int wolfSSL_steer_init(void) {
    return InitOnceExecuteOnce(&init_once, initialize, NULL, NULL) ? init_result : -1;
}
#else
#include <pthread.h>
static pthread_once_t init_once = PTHREAD_ONCE_INIT;
static void initialize(void) {
    init_result = wolfSSL_Init() == WOLFSSL_SUCCESS ? 0 : -1;
}
int wolfSSL_steer_init(void) {
    return pthread_once(&init_once, initialize) == 0 ? init_result : -1;
}
#endif
