# Bounded inbound guard snapshot capture (experimental)

`steer_inbound_guard_capture_verify` reads the current inet table with
`nft -j -n list table` using `run_output_until` and an absolute monotonic
caller deadline. Capture is into a private anonymous memfd; output is capped at
64 KiB. The exact trusted plan is supplied by the caller, never by the snapshot.
The comparator's supported profile and limits are documented in
`inbound_guard_verify.md`. This function starts only a read-only nft command.

It returns zero on a matching snapshot and positive errno on failure. A child
nonzero exit is EIO; run errors retain errno (including ETIMEDOUT and EFBIG);
empty output is EPROTO and oversize output is EFBIG. Memfd, read, parse and comparator failures do
not become successful observations. It checks the deadline before capture,
after capture, during read, and before reporting success. Like `run_output_until`,
reaping an uninterruptible kernel task cannot be guaranteed to finish by the
deadline. The process environment/PATH and nft executable must be trusted.
This is not an atomic snapshot relative to concurrent privileged writers.

Run in a disposable network namespace:

```sh
SDK=/absolute/path/to/plugin-sdk sh tests/inbound-guard-capture.sh /tmp/opencode/inbound-guard-capture
```

The test performs an actual C read+verify of the real managed guard fixture,
checks exact errno for an expired deadline, an actual timed-out nft process,
a missing table, an injected memfd read failure, empty output and output over 64 KiB. The
nft replacements in the timeout/size cases exist only in the isolated test
process PATH. No key/peer identity or host integration is claimed.

The experimental `steer_linked_inbound_recover_checked` invokes this function
inside selection startup, after owned-link/namespace checks and before
unselected cleanup. Its narrow plan, trust boundaries and real-journal tests
are described in `linked_inbound_recovery.md`. This function by itself is not
peer attestation or an advertised inbound capability.
