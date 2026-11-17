# Draft post-query admission

Pure source-only validator for a provider table already returned by query. This
is NOT the signed manifest gate before dlopen, a signature verifier, sandbox,
loader, capability detector, API negotiation engine or production integration.
The host supplies exact expected package/version/provider, target tuple, approved
API range text, schema digest and bounded available host capability IDs from
independently trusted metadata. It must establish API compatibility beforehand;
matching text alone proves no semver compatibility. The expected target must be
the actual runtime identity independently validated before loading native code.
Unknown negotiation or
metadata must never be turned into an admission success through this utility.

The function checks provider prefix through destroy, descriptor prefix through
digest, target prefix through endian and each combination prefix through security
before reading their remaining fields. Every layout must equal the current draft
layout. Tail bytes are accepted but not read. All six lifecycle callbacks must be
present; none is invoked. Descriptor target and expected target are independently
validated. Exact target comparison covers OS, CPU, ABI, libc, pointer width and
endianness. IDs/target labels are visible ASCII, 1..128 bytes; package version and
API range are bounded to 256 bytes, range permitting ASCII spaces. Embedded NUL
and non-ASCII bytes are rejected; spans need no trailing terminator.

Execution modes: 1..8 values, all must be trusted-native (unknown extras reject).
Combinations: 1..128 pointers, each must name an inbound/outbound direction and
stream/datagram/device flow class with nonempty bounded transport/security IDs.
The utility validates declared tuple syntax, not actual protocol support,
available provider services, protocol-specific cross constraints or a selected
request's tuple. No transport/security vocabulary is frozen here.
Required host caps: at most 64, each must appear in the host's
at-most-64 supplied capability list. Zero required caps and empty host list are
allowed. Duplicate entries are harmless and not deduplicated. SHA256 digest is
compared as 32 exact bytes; the utility does not compute or verify schema content.

Rejections return fixed code plus field enum, never caller-controlled text or
secret data. Work and memory reads are bounded by the stated limits; no allocation,
callback invocation or IO. Every non-NULL pointer and advertised backing span/
array must be valid for the call. Versioned pointers need a readable size word;
size checks cannot defend a forged pointer or lying module. Native trusted ABI
is not a security sandbox. Expectations and tables must remain immutable during
validation. Validation does not retain them or authorize a subsequent load.

`admission_test.c` source covers valid tuples and identity, short prefixes,
missing lifecycle callbacks, unknown layout, absent descriptor, mismatching
package/version/provider/API text, embedded NUL and oversize identity, short or
mismatching target, digest mismatch, mode and capability bounds, unknown required
capability, absent/invalid/short tuples, direction/class validation, unknown
expectations and no lifecycle invocation (stubs abort if called).

Strict C11 and ASan/UBSan execution passed on WSL Ubuntu x86_64 Linux,
GCC 15.2.0, on 2026-11-17. See [commands and scope](README.md#executed-validation).
These standalone checks do not establish production integration or concurrency safety.
No production source list or installed build target was added.
