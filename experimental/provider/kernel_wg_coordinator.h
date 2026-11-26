#ifndef STEER_DRAFT_KERNEL_WG_COORDINATOR_H
#define STEER_DRAFT_KERNEL_WG_COORDINATOR_H

#include "kernel_wg_guard_record.h"
#include "../spec/execution_journal.h"

/* Isolated, synchronous worker profile. No network backend is implicit. All
 * callbacks are serialized and must verify the pinned/current netns and boot
 * against the owned identity, respect the deadline and refuse foreign state.
 * No name-only adoption, no network helpers selected by config or fallback. */
struct steer_draft_wg_backend {
    int (*create_down)(void *,const struct steer_draft_wg_identity *,int mtu,uint64_t,int *);
    int (*stage_down)(void *,const struct steer_draft_wg_identity *,int,const struct awg_conf *,
        const struct awg_secrets *,uint32_t mark,uint64_t);
    /* bind exclusive DROP if publish==0; replace the exact prior guard otherwise.
     * A CHANGED result must report the captured new handle, even on error.
     * UNCHANGED must be a fact; return EFFECT_UNCERTAIN for unknown results. */
    int (*guard)(void *,const struct steer_draft_wg_guard_record *,int publish,uint64_t,
        uint32_t *effect,uint64_t *handle);
    /* Verify exact owned DOWN link and exact DROP guard before bringing it UP. */
    int (*up)(void *,const struct steer_draft_wg_guard_record *,uint64_t);
    int (*retire_link)(void *,const struct steer_draft_wg_identity *,uint64_t);
    /* Fresh lookup by exact recorded inet table name. Successful absence
     * reports 0 + empty comment; errors must never be reported as absence. */
    int (*lookup_guard)(void *,const struct steer_draft_wg_guard_record *,uint64_t,
        uint64_t *,char comment[256]);
    /* Recheck captured ifindex is absent and delete only by exact table
     * marker+handle (not name); success means that exact guard is absent. */
    int (*retire_guard)(void *,const struct steer_draft_wg_guard_record *,uint64_t);
};

struct steer_draft_wg_tx {
    uint64_t transaction,generation,instance;
    uint8_t plan_digest[32];
};

struct steer_draft_wg_candidate {
    struct steer_draft_wg_identity link;
    /* Minted by the prepared guard before any mutation. */
    char table[26],marker[42];
    const struct awg_conf *config;
    const struct awg_secrets *keys; /* borrowed, caller wipes */
    uint32_t mark;
};

struct steer_draft_wg_ready {
    struct steer_draft_wg_guard_record guard;
    uint16_t listen_port;
};
#define STEER_INBOUND_BARRIER_UNKNOWN 0u
#define STEER_INBOUND_BARRIER_CLOSED 1u
#define STEER_INBOUND_BARRIER_OPEN 2u
#define STEER_INBOUND_BARRIER_ABSENT 3u

/* Positive errno. On failure ready stays unchanged and cleanup_error reports
 * whether candidate cleanup is still needed. The previous generation is never
 * mutated here. Caller owns promotion/commit and retirement of the previous
 * generation. Only disjoint listen ports; the isolated caller must also
 * provision disjoint prefixes/routes and other resources. */
int steer_draft_wg_coordinator_apply(struct steer_spec_journal *,const struct steer_draft_wg_backend *,
    void *,const struct steer_draft_wg_tx *,const struct steer_draft_wg_candidate *,
    const struct steer_draft_wg_ready *previous,uint64_t deadline,const atomic_uint *cancel,
    struct steer_draft_wg_ready *ready,int *cleanup_error);

/* Clean up one explicitly selected transaction (never decide which generation
 * to keep). After a complete journal scan: link first, then exact guard.
 * A lost guard outcome leaves a matching-marker table unresolved, not owned. */
int steer_draft_wg_coordinator_recover(struct steer_spec_journal *,const struct steer_draft_wg_backend *,
    void *,const struct steer_draft_wg_tx *,uint64_t deadline);

/* Exclusive bounded single-slot experimental store. Do not share its directory
 * with the standalone staging API or the general device authority ledger. */
struct steer_draft_wg_selection;
int steer_draft_wg_selection_open(const char *,uint32_t max_records,struct steer_draft_wg_selection **);
/* Role-scoped journal: accepts only entries explicitly written as inbound,
 * never the existing role-ambiguous/outbound journal format. */
int steer_draft_wg_selection_open_inbound(const char *,uint32_t max_records,struct steer_draft_wg_selection **);
int steer_draft_wg_selection_is_inbound(const struct steer_draft_wg_selection *);
void steer_draft_wg_selection_close(struct steer_draft_wg_selection *);

/* The externally committed prototype_store document is the ONLY selection.
 * A missing document passes an all-zero revision; IO/corruption is not absence.
 * Digest covers the exact validated persisted bytes. Set without_wg only
 * after validating a committed linked document that intentionally omits WG;
 * a WG journal entry at that generation is then contradictory. */
struct steer_draft_wg_revision { uint64_t generation; uint8_t digest[32]; int without_wg; };
typedef int (*steer_draft_wg_verify_ready)(void *,const struct steer_draft_wg_guard_record *,uint64_t);
/* Read and sync the complete journal, resolve external generation+digest and
 * verify the live selected resource before cleaning anything. next_revision
 * includes the committed revision and failed attempts. Call at startup (no
 * live drains), not after ordinary linked publication. Cleanup errors do not
 * authorize fallback. */
int steer_draft_wg_selection_startup(struct steer_draft_wg_selection *,const struct steer_draft_wg_backend *,
    void *,const struct steer_draft_wg_revision *,steer_draft_wg_verify_ready,
    uint64_t deadline,uint64_t *next_revision,struct steer_draft_wg_guard_record *selected);
/* Staging only. Returns exact durable candidate identity, allowing allocation
 * and validation of its runtime binding before commit. On NOT_RENAMED
 * use startup with the old revision; on RENAMED do not clean either side
 * until the exact document has been durably recovered. */
int steer_draft_wg_selection_stage(struct steer_draft_wg_selection *,const struct steer_draft_wg_backend *,
    void *,const struct steer_draft_wg_revision *,uint16_t previous_port,
    const struct steer_draft_wg_tx *,const struct steer_draft_wg_candidate *,
     uint64_t deadline,struct steer_draft_wg_ready *);
/* Inbound-only first device: durable link/guard intent, stage and UP under a
 * confirmed DROP guard. No allow-policy publication. The caller keeps the
 * prepared guard alive. Publication requires a confirmed matching store receipt
 * and a confirmed closed independent barrier at the higher participant
 * boundary; this low-level API cannot verify the receipt. Old eager APIs are
 * unchanged. */
int steer_draft_wg_selection_stage_closed(struct steer_draft_wg_selection *,const struct steer_draft_wg_backend *,
    void *,const struct steer_draft_wg_revision *,const struct steer_draft_wg_tx *,
    const struct steer_draft_wg_candidate *,uint64_t,struct steer_draft_wg_ready *);
#define STEER_INBOUND_PUBLICATION_NONE 0u
/* CONFIRMED requires CHANGED plus a synced journal outcome, even if the
 * backend also returned an error. UNKNOWN never authorizes opening. */
#define STEER_INBOUND_PUBLICATION_CONFIRMED 1u
#define STEER_INBOUND_PUBLICATION_UNKNOWN 2u
int steer_draft_wg_selection_publish_closed(struct steer_draft_wg_selection *,const struct steer_draft_wg_backend *,
    void *,const struct steer_draft_wg_revision *,const struct steer_draft_wg_tx *,
    uint64_t,struct steer_draft_wg_ready *,uint32_t *);
/* Owner has stopped admission and joined this generation's bindings.
 * The durable selected revision is rechecked; it cannot be retired here. */
int steer_draft_wg_selection_retire(struct steer_draft_wg_selection *,const struct steer_draft_wg_backend *,
    void *,const struct steer_draft_wg_revision *,uint64_t generation,uint64_t deadline);
/* No-WG selection only. Require the exact published physical guard record;
 * a missing/mismatched record is an error, not successful retirement. */
int steer_draft_wg_selection_retire_inbound_exact(struct steer_draft_wg_selection *,
    const struct steer_draft_wg_backend *,void *,const struct steer_draft_wg_revision *,
    const struct steer_draft_wg_guard_record *,uint64_t);
int steer_draft_wg_selection_inbound_had_published(struct steer_draft_wg_selection *,
    const struct steer_draft_wg_revision *,uint64_t,int *);
/* No kernel effects. Record a new full revision digest against the exact
 * currently selected physical PUBLISHED outcome (never another alias).
 * Caller must attest unchanged WG intent and live keys before this call. */
int steer_draft_wg_selection_reuse(struct steer_draft_wg_selection *,const struct steer_draft_wg_revision *,
    const struct steer_draft_wg_tx *,const struct steer_draft_wg_guard_record *,uint64_t deadline);

#endif
