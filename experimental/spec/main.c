/* SPDX-License-Identifier: GPL-3.0-only */
#include "spec.h"
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    struct steer_spec_plan *plan; struct steer_spec_summary summary;
    FILE *input; char *source; size_t length;
    if (argc != 2) { fputs("usage: steer-spec-compile spec.yaml\n", stderr); return 64; }
    input = fopen(argv[1], "rb");
    if (!input) { fputs("spec input unavailable\n", stderr); return 66; }
    source = malloc(STEER_SPEC_MAX_BYTES + 1u);
    if (!source) { fclose(input); return 70; }
    length = fread(source, 1, STEER_SPEC_MAX_BYTES + 1u, input);
    if (ferror(input) || length > STEER_SPEC_MAX_BYTES) { free(source); fclose(input); return 65; }
    fclose(input);
    /* No forged inventory: v3 executor/provider binding is not wired yet.
     * Embedders pass trusted host descriptors through the C API instead. */
    plan = steer_spec_compile(source, length, NULL, 0); free(source);
    if (!plan) return 70;
    summary = steer_spec_summary(plan); steer_spec_write_json(plan, stdout); steer_spec_destroy(plan);
    return !summary.syntax_valid ? 65 : !summary.topology_valid ? 66 : !summary.runtime_ready ? 78 : 0;
}
