# Shared wolfSSL initialization

The pinned wolfSSL5.9.4 Linux profile has a statically initialized pthread mutex. The audit's double-mutex explanation does not apply. A separate real cold-start race was reproduced: `wolfSSL_CTX_new_ex` reads `initRefCount` without the mutex while `wolfSSL_Init` updates it through the roots loader. Both source locations were instrumented with TSan by rebuilding pinned `src/ssl.c`; the other dependency objects were not instrumented.

`build/wolfssl/steer_init.c` now owns one permanent initialization result in the physical crypto backend. Both QUIC context creation and roots loading call `wolfSSL_steer_init`. Consumer DSOs contain no fallback once. Initialization failure is remembered; Steer does not cleanup/reinitialize the backend while consumers can exist. The recipe compiles the helper into static archives, includes its source/header in the rebuild stamp, and the shared backend exports the same helper. Android's backend includes the source too; Android and Windows builds have not been exercised by this Linux gate.

The initialization protocol requires crypto compatibility axis2.0. Old consumers requiring ^1.x must be rejected before loading: their independent raw Init calls can still race a new context creation. Retaining the published raw `wolfSSL_Init` symbol preserves the symbol ledger, not permission to mix old and new initialization protocols. Wire protocols are unchanged. New consumers against an old archive fail to link; there is no unsafe fallback.

Reproduction (use verified pinned dependency source and recipe-built archive):

```sh
TSAN_OPTIONS=halt_on_error=1 sh tests/crypto-cold-build.sh WOLFSSL_SOURCE WOLFSSL_ARCHIVE NGTCP2_ARCHIVE /tmp/cold-static
TSAN_OPTIONS=halt_on_error=1 sh tests/crypto-shared-cold-build.sh WOLFSSL_SOURCE PIC_WOLFSSL_ARCHIVE NGTCP2_ARCHIVE /tmp/cold-shared
```

Each run launches ten fresh processes. Four workers concurrently create client/server QUIC contexts and independent DER roots stores. The static gate also injects initialization failure and requires exactly one initialization attempt across four concurrent callers. The shared gate uses separate QUIC and roots consumer DSOs and the generated backend export map. This is a scoped cold-start regression, not a blanket race/soak claim for external dependencies.

Linux evidence checkpoint (2026-11-17): pinned wolfSSL source tarball SHA256 `7256bfc89b183a75183806c7debfa203443873b0b4a562e1b80d68e01b45ac57`, corrected noasm POSIX server profile with ECC-import validation and recipe-generated thread-safe-date marker. Effective macros include `WOLFSSL_PTHREADS` and `WOLFSSL_MUTEX_INITIALIZER=PTHREAD_MUTEX_INITIALIZER`; `WC_THREADSHARED` is empty in this profile. The original mixed cold binary reports the counter race at pinned ssl.c551/2606; the fixed recipe-built archive passes ten fresh TSan processes and three ASan/UBSan/LSan processes, including the permanent-failure fixture. External objects other than ssl.c remain uninstrumented. Existing warm managed-HY2 evidence does not substitute for this test.

The matching-new-consumer shared gate also passed ten fresh TSan processes with `LD_BIND_NOW=1`: QUIC and roots were separate DSOs linked to one backend DSO using the generated export map. A separate single-thread legacy-symbol probe resolved and called retained `wolfSSL_Init`; this checks symbol retention only and does not authorize old/new plugin mixing. Crypto-axis admission must reject the incompatible major before loading. The PIC dependency recipe is required for this gate; a non-PIC ngtcp2 archive is correctly rejected by the shared linker.

The signed-package admission regression is available as
`S2P=/path/to/s2p PM_CRYPTO_ONLY=1 sh tests/pluginmgrmatch.sh /path/to/steerd`.
Run it from the Steer source root against a freshly built manager. Its expected
crypto axis defaults to the current CLI header, without an environment override.
The Linux checkpoint passed all three assertions: a package requiring `^1.0`
is rejected, the diagnostic identifies the current `2.0` axis, and a package
requiring `^2.0` installs successfully. This is an installation admission test;
the separate shared-library gate above verifies actual matching consumer calls.
