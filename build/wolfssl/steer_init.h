#ifndef STEER_WOLFSSL_INIT_H
#define STEER_WOLFSSL_INIT_H
/* Implemented once in the physical crypto backend, never in a consumer DSO.
 * Stable initialization result; consumers must not call wolfSSL_Cleanup while
 * any Steer consumer can still create contexts or use crypto objects. */
int wolfSSL_steer_init(void);
#endif
