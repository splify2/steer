#ifndef STEER_TLS13_ENGINE_H
#define STEER_TLS13_ENGINE_H
#include <stddef.h>
#include <stdint.h>

/* Source-only incremental companion. No legacy tls13 layout/export changes.
 * All calls are serialized by one owner. No sockets, RNG, DNS, trust files,
 * certificate-store locks, callbacks or worker creation occur in this API.
 * Host admission accounts permanent storage separately from handshake workspace.
 */
struct tls13;
struct tls13_engine;
struct tls13_engine_limits {
    uint32_t max_records, max_messages;
    size_t max_handshake_message, max_certificate;
};
struct tls13_engine_options {
    /* A complete, already prepared TLS record containing one ClientHello.
     * Inputs are copied at init; the key is wiped after the handshake. The
     * initial engine is standard TLS1.3 only: no ECH/REALITY/PSK/HRR fallback. */
    const unsigned char *client_hello;
    size_t client_hello_length;
    const unsigned char *x25519_private; /* exactly32 bytes */
    struct tls13_engine_limits limits;
};
enum tls13_engine_state {
    TLS13_ENGINE_HANDSHAKE,
    TLS13_ENGINE_AUTH_PENDING,
    TLS13_ENGINE_FINISH_DRAIN,
    TLS13_ENGINE_READY,
    TLS13_ENGINE_FAILED
};
struct tls13_engine_auth {
    /* Borrowed until auth_complete/destroy. A verifier job must copy all bytes
     * before leaving the owner, then retain its own context/generation pin.
     * It must never call back into destroyed/reused engine storage. */
    const unsigned char *certificate, *certificate_verify, *transcript;
    size_t certificate_length, certificate_verify_length, transcript_length;
};

size_t tls13_engine_storage_size(void);
int tls13_engine_workspace_size(const struct tls13_engine_options *, size_t *);
/* Caller storage has malloc-compatible alignment and lives until destroy.
 * borrowed_tls is fresh/uninitialized and becomes exclusively engine-owned;
 * caller must not invoke legacy TLS APIs, move/copy it or use its fd field.
 * Destroy frees its crypto contexts but never frees either caller allocation.
 * Workspace can be recycled only after workspace_in_use becomes false.
 * out/options are valid separate objects and must not alias either storage,
 * workspace, borrowed_tls, ClientHello or private-key input. These nonaliasing
 * preconditions apply before even clearing *out. Other buffer overlaps are
 * rejected before mutation. On init failure *out=NULL and neither caller
 * allocation remains owned. borrowed_tls must not overlap CH/key inputs. */
int tls13_engine_init(void *storage, size_t storage_length, struct tls13 *borrowed_tls,
                      void *workspace, size_t workspace_length,
                      const struct tls13_engine_options *, struct tls13_engine **out);
enum tls13_engine_state tls13_engine_state(const struct tls13_engine *);
int tls13_engine_error(const struct tls13_engine *);
int tls13_engine_workspace_in_use(const struct tls13_engine *);

/* Consume at most one complete record per call, preserving every unconsumed
 * pipelined byte. A pending borrowed plaintext/output/auth view applies bounded
 * backpressure. EAGAIN means no input consumed, never EOF. */
int tls13_engine_feed(struct tls13_engine *, const unsigned char *, size_t, size_t *consumed);
int tls13_engine_output(const struct tls13_engine *, const unsigned char **, size_t *);
int tls13_engine_output_consume(struct tls13_engine *, size_t);
int tls13_engine_auth_snapshot(const struct tls13_engine *, struct tls13_engine_auth *);
/* Zero means chain/name/signature verification succeeded using prepared trust.
 * The server Finished was already checked; success queues ClientFinished but
 * READY is published only after its entire ciphertext is consumed by lower IO.
 * A nonzero verification result fails closed, without sending ClientFinished. */
int tls13_engine_auth_complete(struct tls13_engine *, int verification_error);
int tls13_engine_plaintext(const struct tls13_engine *, const unsigned char **, size_t *);
int tls13_engine_plaintext_consume(struct tls13_engine *, size_t);
/* One bounded record, copied before return. No new write while output is held.
 * KU control is emitted first and returns EAGAIN without accepting app bytes.
 * An adapter chooses its own deferred operation callback only after lower IO
 * has accepted all ciphertext corresponding to the accepted app prefix. */
int tls13_engine_write(struct tls13_engine *, const unsigned char *, size_t, size_t *accepted);
/* Zero accepts a permanent write barrier immediately, even while older
 * ciphertext is held. close_notify is queued once that flight drains; later
 * KU requests cannot starve it because no more Application Data is permitted.
 * Read remains usable. The SDK adapter separately rejects finish until its
 * upper write callback has delivered the accepted byte count. This pure
 * engine instruction does not itself represent a deferred SDK operation. */
int tls13_engine_finish_write(struct tls13_engine *);
int tls13_engine_local_finished(const struct tls13_engine *);
int tls13_engine_peer_finished(const struct tls13_engine *);
/* Raw lower EOF is clean only after authenticated close_notify and no partial
 * TLS/handshake record; empty application/control records never imply EOF. */
int tls13_engine_eof(struct tls13_engine *);
void tls13_engine_destroy(struct tls13_engine *);
#endif
