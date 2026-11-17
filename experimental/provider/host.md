# Minimal draft host base table

Source-only integration with the existing buffer host definition in `buffers.c`.
No second definition, loader, provider invocation, lifecycle, IO, system clock,
production wiring or stable SDK support is introduced. Host API major 1/minor 0
are local draft values, not an advertised stable compatibility axis.

`steer_draft_host_create` requires clock and log callbacks plus borrowed service
record/context that remain immutable/live for the host's lifetime. Calls and
callbacks are serialized on the owning shard with no reentry. The caller supplies
an actual monotonic nanosecond clock, and a bounded log sink; this layer creates
neither. It drops logs over 4096 bytes, invalid NULL/nonempty spans and severities
outside 3/4/6/7. It does not rate-limit, redact secrets or retain message spans.
Sink storage/rate limits and the prohibition on secrets remain caller duties.

`get_table` exposes only buffers at the exact draft layout; all unknown table or
layout requests return UNSUPPORTED with NULL output. Existing buffer-only hosts
continue to work but `steer_draft_host_get_api` rejects them as UNSUPPORTED.
No synthetic zero-clock fallback is offered. The returned base table is used
only with configured live hosts. Unknown/stale native pointers are not sandboxed.

Buffer limits/refcount/allocator ownership are unchanged. Destroy uses existing
`steer_draft_buffers_destroy`, refusing live buffers. Only buffers are tracked:
caller must additionally ensure no pending callback/provider can reference the
host before destruction; this is not the future provider lifecycle barrier.

`host_test.c` exercises actual table lookup and buffer allocation through it,
missing services, rejection of buffer-only hosts, unknown table/layout, table
prefix, caller clock routing, log size/severity/NULL bounds, reference handling
and destroy refusal while buffers are live. It performs no native IO.

Strict C11 and ASan/UBSan execution passed on WSL Ubuntu x86_64 Linux,
GCC 15.2.0, on 2026-11-17. See [commands and scope](README.md#executed-validation).
These standalone checks do not establish production integration or concurrency safety.
No production source list or installed build target was added.
