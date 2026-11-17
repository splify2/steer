/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef STEER_DRAFT_INBOUND_TLS_H
#define STEER_DRAFT_INBOUND_TLS_H
#include <stddef.h>
#include <stdint.h>
struct steer_draft_tls_material {
    uint8_t *certificate,*private_key;
    size_t certificate_length,private_key_length;
};
/* Reads regular PEM/DER files only (symlinks to regular files are allowed).
 * Certificate chain <=1MiB, key <=64KiB. No diagnostics contain file contents.
 * out must be fresh/cleared. Caller must clear after TLS context copies the
 * material, including failures. This is bounded synchronous preparation IO;
 * O_NONBLOCK prevents FIFO open hangs, not regular-file latency. */
int steer_draft_tls_material_load(const char *,const char *,struct steer_draft_tls_material *);
void steer_draft_tls_material_clear(struct steer_draft_tls_material *);
#endif
