/* Reuse the coordinator's deterministic fake-backend fixture to emit a valid
 * v3 linked-selection journal, without creating any kernel/network objects. */
#define main coordinator_full_test_main
#include "kernel_wg_coordinator_test.c"
#undef main

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    linked_selection(argv[1]);
    return 0;
}
