# Shared host worker (source-only)

`host_worker` is a fixed 1..4-thread service on one owner loop. Admission bounds
live jobs including completed unreleased references, per-input bytes and total
copied input bytes. Result allocations need a separate provider/coordinator
budget. Inputs are copied and wiped; queue cancellation never admits extra
bytes. No per-flow/device threads or automatic retries are created.

Callbacks use the existing owner loop/eventfd and bounded32-result snapshots.
Guard ownership spans foreign run return, owner callback return and exported job
release. Cancel is cooperative through the shared `cancel.h` token. A queued
cancel can skip work; once run returns, its factual result is delivered unchanged.
The callback owns its result pointer even during shutdown. Slow kernel/filesystem
work cannot be forcibly terminated; destroy refuses until worker exit, all
callbacks and job releases, and the deferred drain notification have completed.

`submit_ns` duplicates the target namespace descriptor and performs entry and
restoration on the worker, never the owner. Failed restoration retains factual
error/value, adds a separate quarantine flag, and exits the contaminated worker.
Healthy workers continue; if none remain, queued jobs complete unavailable and
new submissions refuse. No silent respawn occurs. Providers cannot change a
namespace outside this scope or store worker thread affinity in prepared state.

Normal tests cover cancellation, quotas, guard reentry, stalled/healthy workers,
held completions and concurrent quarantine/drain registration. The namespace
failure fixture injects setns failure; `host-worker-namespace-actual-test` is a
separate root-only test using a fresh unshare namespace and verifies real entry,
restore, next-job baseline and unchanged owner namespace. It changes no live
network configuration.

The typed spec async adapter additionally fences a late-cancelled prepared
execution before owner handoff while retaining worker cleanup ownership. A
two-worker fixture keeps the original prepare thread blocked while a different
pool worker discards its transferred prepared state.
