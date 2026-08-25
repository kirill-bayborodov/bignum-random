# Track B Caller Context and Fault-Injection Results

**Status:** Candidate engineering evidence; not a CAVP, CMVP, or FIPS validation claim.

## Scope

This gate covers the caller-allocated context adapter, its entropy-provider boundary, and deterministic lifecycle fault injection. The adapter owns no heap allocation and never retains the provider callback or provider context. The provider is synchronous and must fill exactly 32 bytes for each instantiate or reseed request.

## Artifact-level checklist

| Artifact | Documentation | Build/static gate | Dynamic gate | Result |
|---|---|---|---|---|
| `include/bignum_ctr_drbg_context.h` | File, callback, type, field, ownership, status and function contracts present | Strict C11 include/compile | API exercised by fault harness | **PASS** |
| `src/bignum_ctr_drbg_context.c` | File and static-helper contracts present; provider/error rationale documented | `-Wall -Wextra -Werror -pedantic`; cppcheck clean | Strict and ASan/UBSan harness runs | **PASS** |
| `tools/test_ctr_drbg_context_faults.c` | File-level intent, deterministic provider oracle and expected transitions documented | Strict C11 compile; cppcheck clean | Fault matrix below | **PASS** |
| `docs/TRACK_B_CONTEXT_API_BOUNDARY.md` | Caller allocation, provider ownership and migration rules synchronized | Path/command review | Reviewed against implementation | **PASS** |

## Fault matrix

| Scenario | Expected result | Observed result |
|---|---|---|
| NULL context passed to init | `ERROR_NULL_ARG` | **PASS** |
| Image-integrity verification fails | `ERROR_STATE`, state `ERROR`, generation blocked | **PASS** |
| Generate from `ERROR` | `ERROR_STATE`, output unchanged | **PASS** |
| Provider returns failure during instantiate | Provider status returned, state `ERROR`, partial DRBG state cleared | **PASS** |
| Provider callback after `ERROR` | No callback invocation; `ERROR_STATE` | **PASS** |
| Successful startup and provider-backed instantiate | State `READY` | **PASS** |
| Provider-backed generate | `SUCCESS`, state remains `READY` | **PASS** |
| Uninstantiate | DRBG storage zeroized, state `ZEROIZED` | **PASS** |
| Generate after zeroization | `ERROR_STATE` | **PASS** |
| Restart after zeroization | Startup KAT succeeds and state returns `READY` | **PASS** |

## Commands and results

The deterministic harness was built and executed with:

```sh
gcc -std=c11 -Wall -Wextra -Werror -pedantic -Iinclude \
  tools/test_ctr_drbg_context_faults.c src/bignum_ctr_drbg.c \
  src/bignum_ctr_drbg_module.c src/bignum_ctr_drbg_context.c \
  -o /tmp/bignum-random-drbg-build/test_context_faults
/tmp/bignum-random-drbg-build/test_context_faults
```

The output was `caller context/provider fault injection: PASS`. The same harness built with AddressSanitizer and UndefinedBehaviorSanitizer also produced `caller context/provider fault injection: PASS`.

The final repository gate additionally passed both C-only and YASM-linked AES-256 CTR_DRBG suites: **240/240 PR=false** and **240/240 PR=true** records for each backend. The existing protected C11 and production ASM test targets each completed with **0/5 failures**. `cppcheck` and `git diff --check` were clean, and neither `Makefile` nor `.github/workflows/ci.yml` was modified.

## Remaining CSTL gates

The context type is opaque-style rather than a strict incomplete C type because the current protected build has no allocation/API integration target. Before a validation submission, the implementation must freeze the exact context size and alignment version, decide whether the initialization cookie is an approved design element, define approved entropy-source health tests and error mappings, add fork/thread and provider concurrency evidence, and integrate the boundary into the validated module image. The current provider is a deterministic test seam and must not be reachable from an Approved production build.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[2]: https://csrc.nist.gov/pubs/fips/140-3/final "NIST FIPS 140-3"
