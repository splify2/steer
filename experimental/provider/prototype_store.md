# Optional durable prototype configuration store

`prototype_store.{c,h}` is a standalone Linux store. It is not connected to the
foreground host yet and does not change the startup source file. The owner must
explicitly select an existing private state directory. It must belong to the
effective UID and deny all group/other permissions; a final-component directory
symlink is rejected. All operations use its retained directory fd. A 0600 regular
single-link `.writer.lock` file is exclusively locked, nonblocking, through store
close. A competing writer fails rather than racing configuration revisions.
Calls require one serialized owner. Ownership may transfer between bootstrap,
writer thread and joined shutdown through external synchronization establishing
happens-before; there is no thread-local state or concurrent-call support.

Prepare accepts a parser-owned config, whose canonical document contains typed
environment references instead of credential values. Generation must be nonzero,
canonical document at most 64 KiB. The module never resolves credential refs or
logs document contents. It writes a version-specific JSON envelope containing
`revision` and `document` into a random exclusive same-directory 0600 temporary
file, handles partial writes, fsyncs the file and closes it. A failed prepare
clears the output, deletes only its own temp, and leaves `config.json` unchanged.
Only one transaction can be live. Caller data can be released after prepare.

Commit does not consume its transaction; every path finishes with abort to free
transaction state. It returns common error plus an explicit phase:

- `NOT_RENAMED`: rename failed; old committed config and runtime may remain.
- `RENAMED`: new `config.json` is visible, but directory fsync failed. Durability
  across a crash is uncertain. It is incorrect to claim rollback or delete the
  new config as cleanup.
- `SYNCED`: file and directory fsync succeeded. This is the durable success gate.

Repeated commit returns the same stored result. Abort removes only an unrenamed
temp, then consumes the transaction even if unlink reports IO. It never deletes
or rewrites committed `config.json`. Crash-orphaned temps are not loaded and are
not automatically removed; they are bounded refs-only 0600 files. Close refuses
a live transaction. No filesystem configuration outside the selected state
directory is changed.

The integration order must be: validate canonical config and expected revision;
prepare every fallible listener/runtime resource; prepare file; commit file;
publish already-prepared runtime through a no-fail swap. A `NOT_RENAMED` error
aborts prepared resources and preserves old runtime. Once rename succeeds,
runtime publication must match the newly visible revision. A directory-sync
error then needs an explicit durability-uncertain response with the actual new
revision; it cannot be reported as ordinary successful durable apply or as
unchanged old runtime. The current host needs a separate prepared runtime object
before this store can be integrated correctly.

`load` opens one committed file snapshot, rejects symlinks, unsafe modes,
non-regular/multiply-linked files, malformed envelopes and oversized data, then
parses the document using its stored generation. It returns an owned config;
missing file is `UNSUPPORTED`. Proposed startup behavior when a state directory
is explicitly enabled: load committed state first; use the explicit source file
only for first initialization when no committed file exists. Corrupt committed
state must fail visibly instead of silently reverting to source. Subsequent
applies never overwrite that source file. Initial commit must follow the same
fallible-runtime-prepare / disk-commit / no-fail-publication order. Without the
state option, existing ephemeral behavior remains unchanged.

IO is synchronous and bounded in bytes, but fsync latency is not bounded. The
host must choose where durable disk work runs; this module does not introduce
another loop or thread and does not claim fsync cannot delay a shared loop.
Filesystem, storage hardware and OS guarantees limit crash durability. Revision
compare-and-swap and runtime publication are core responsibilities, not supplied
by this file primitive.

`prototype_store_test.c` passes strict C11 and ASan/UBSan with leak detection on
WSL Ubuntu x86_64 Linux, 2026-11-17. It includes the source with deterministic
fsync/rename wrappers: injected file-sync ENOSPC and rename failure preserve the
old revision; injected directory-sync failure exposes the new revision while
returning `RENAMED` uncertainty. Tests also cover abort, repeat commit, writer
competition, live-transaction close refusal, exact 0600 mode, corrupt load,
unsafe/symlink directory/config rejection and temp cleanup. Link this test with
the same parser/policy/ynode/libyaml sources as `prototype_config_test`; do not
also compile store.c because the test includes its fault-injected translation
unit. Actual process-crash/power-loss tests and integration are not performed.
