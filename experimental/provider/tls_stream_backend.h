#ifndef STEER_EXPERIMENTAL_TLS_STREAM_BACKEND_H
#define STEER_EXPERIMENTAL_TLS_STREAM_BACKEND_H
#include "route_stream.h"
#include "host_worker.h"
#include "tls13_engine.h"
#include "certverify.h"

struct steer_draft_tls_stream_backend;
#define STEER_DRAFT_TLS13_STANDARD_X25519 UINT32_C(1)
/* Source-only immutable profile. Prepare roots on a configuration worker;
 * roots remain owned by the host through backend destruction, including all
 * private jobs. Strings/policy are bounded and copied by create. TLS1.3 with
 * the existing custom standard-X25519 ClientHello is the initial capability.
 * REALITY/ECH/PQ/other fingerprint variants are not substituted or advertised.
 * Empty required_alpn permits any actually offered selection (or none); h2 or
 * http/1.1 requires that exact selection before sending ClientFinished. */
struct steer_draft_tls_stream_profile {
    uint32_t kind;
    struct steer_pv1_span server_name,required_alpn;
    const struct cert_trust *roots;
    const struct cert_policy *policy;
    struct tls13_engine_limits engine;
};
struct steer_draft_tls_stream_limits {
    uint32_t max_streams,max_operations,max_handshakes,max_references;
    uint64_t max_queued_bytes,max_handshake_bytes;
};
/* Same owner loop for worker/lower/API/callbacks. No socket/DNS authority or FD
 * extraction; lower receives copied original metadata. Fresh ClientHello/key
 * preparation and certificate/name/CV checks use the shared bounded worker.
 * Caller keeps worker/buffers/roots alive until successful destroy.
 * Open success transfers a usable TLS stream only after final-flight drain;
 * optional endpoints remain unavailable rather than claiming socket identity.
 * Deadline is absolute and checked again at deferred publication.
 *
 * Public release consumes after close + exported op releases. Private lower IO
 * and worker results retain separate context/budgets/binding pins; no callback
 * may access the consumed public handle. Cancel/shutdown cannot force a running
 * verifier to stop, and destruction waits actual callback/release quiescence. */
struct steer_pv1_error steer_draft_tls_stream_backend_create(struct loop *,
    struct steer_pv1_host *buffers,struct steer_draft_host_worker *,
    const struct steer_draft_stream_binding *lower,
    const struct steer_draft_tls_stream_profile *,const struct steer_draft_tls_stream_limits *,
    uint64_t generation,uint64_t instance_token,void (*retired)(void *),void *,
    struct steer_draft_tls_stream_backend **);
const struct steer_draft_stream_binding *steer_draft_tls_stream_binding(const struct steer_draft_tls_stream_backend *);
struct steer_pv1_error steer_draft_tls_stream_backend_retire(struct steer_draft_tls_stream_backend *);
struct steer_pv1_error steer_draft_tls_stream_backend_destroy(struct steer_draft_tls_stream_backend *);
uint32_t steer_draft_tls_stream_quarantined(const struct steer_draft_tls_stream_backend *);
/* No automatic retry of malformed/refused foreign releases. Bounded explicit
 * recovery inspects at most32 quarantined references per call. */
struct steer_pv1_error steer_draft_tls_stream_recover(struct steer_draft_tls_stream_backend *,uint32_t *recovered);
#endif
