/* Test-only link wrapper. A failed startup reaches its first loop_run while
 * draining retired bindings. Deliver SIGTERM before that dispatch so stop()
 * observes the partially cleaned host. No production test hook. */
#include "loop.h"
#include <signal.h>
#include <stdlib.h>
int __real_loop_run(struct loop *);
int __wrap_loop_run(struct loop *loop)
{
    if (raise(SIGTERM)) abort();
    return __real_loop_run(loop);
}
