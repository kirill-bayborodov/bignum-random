# Track B State, Self-Test, Integrity, and SSP Design

**Status:** Engineering design for independent laboratory pre-review.  
**Scope:** The proposed software module containing the Approved DRBG and the bounded `bignum_random` service.  
**Certification status:** This design is not a FIPS 140-3 validation or a claim of Approved operation.

## Design objectives

The Track B implementation must fail closed. No Approved service may run before successful startup self-tests and image integrity verification, and no Approved service may continue after an integrity, health-test, DRBG, entropy, or internal-state failure. The current direct Linux `getrandom(2)` function is an engineering baseline only. The Approved service must consume output from the selected Approved DRBG; its range reduction is a deterministic bounded transform and must not be described as the DRBG.

FIPS 140-3 validation covers the module and its operation, not merely a function-level test result. The final state and evidence must be mapped to the applicable ISO/IEC 19790 requirements, ISO/IEC 24759 test methods, and CMVP SP 800-140 supplements [1] [2].

## Proposed context

The public Approved API should require an explicit caller-owned context. The context is opaque outside the module and must be initialized, used, and explicitly zeroized according to the lifecycle below. No raw entropy cache in implicit ELF TLS is used by the Approved service.

| Context component | Classification | Lifetime | Required control |
|---|---|---|---|
| DRBG key and internal value | SSP | From instantiate until uninstantiate/zeroize | Never exposed; constant-time handling where applicable; verified zeroization. |
| Reseed counter and limits | Security-relevant state | Context lifetime | Bounds checked; transition to `RESEED_REQUIRED` before limit violation. |
| Entropy input and nonce/personalization material | Sensitive transient input | One instantiate/reseed operation | Caller/provider ownership documented; clear after use; never returned. |
| Health-test state and failure latch | Module state | Context/module lifetime | Monotonic failure behavior; Approved services inhibited after failure. |
| Range candidate | Transient non-SSP unless policy says otherwise | One request/attempt | Stack or context-owned; clear before return on both success and failure. |
| Integrity digest/trusted anchor | Integrity metadata | Module image/startup | Protected from ordinary service writes; verified before `READY`. |
| Provider/cache state | Platform/entropy state | Provider-defined | Explicitly scoped; no unreviewed raw-byte reuse in Approved mode. |

The context must be aligned and sized independently of the public `bignum_t` representation. It must not contain pointers to caller-owned buffers after an operation returns. The final structure definition requires field-by-field Doxygen documentation and a versioned ABI policy.

## State machine

| State | Entry condition | Permitted operations | Exit condition | Failure behavior |
|---|---|---|---|---|
| `UNINITIALIZED` | Zeroized storage or process start | `module_startup`, `context_init` | Self-test and integrity sequence begins | No Approved generation; return `NOT_READY`. |
| `SELF_TEST` | Startup sequence accepted | KATs, integrity verification, health-test initialization | All checks pass -> `READY` | Any failure latches `ERROR`; no partial state is usable. |
| `READY` | Startup checks passed | Approved instantiate/reseed/generate and bounded sampling | Reseed threshold -> `RESEED_REQUIRED`; fatal event -> `ERROR` | Operation output unchanged; relevant state zeroized where required. |
| `RESEED_REQUIRED` | Counter/age/PR request requires reseed | Entropy acquisition and DRBG reseed only | Success -> `READY` | Entropy or reseed failure -> `ERROR` or policy-defined retry state, never silent generation. |
| `ERROR` | Self-test, integrity, health, entropy, DRBG, or invariant failure | Status/diagnostic service only | Explicit approved lifecycle reset | All Approved services remain inhibited. |
| `ZEROIZED` | Explicit uninstantiate, fatal cleanup, or shutdown | No cryptographic service | Controlled reinitialize -> `SELF_TEST` | Any attempted use returns `NOT_READY`. |

State transitions must be atomic from the caller's perspective. If a generate request fails, `*out` and the public bound remain unchanged. If the context enters `ERROR`, it must not return a successful sample from bytes obtained before the failure.

## Startup and conditional self-tests

The final implementation must specify the exact self-test sequence and its relationship to the first service request. A proposed sequence is:

1. Establish the module image identity and verify the software integrity value against a trusted anchor.
2. Enter `SELF_TEST` and run the AES primitive KAT for every implementation variant included in the validation target.
3. Run the CTR_DRBG instantiate/generate/reseed/uninstantiate known-answer sequence using fixed entropy input, nonce, personalization string, and additional input vectors.
4. Verify the bounded range transform with deterministic DRBG bytes, including power-of-two, non-power-of-two, one-word, multiword, zero-result, equality-rejection, and normalization cases.
5. Initialize entropy-source health-test state and provider status without treating ordinary statistical tests of final `bignum_random` outputs as an entropy-source validation.
6. Enter `READY` only if all checks pass; otherwise clear sensitive temporary state and latch `ERROR`.

Conditional tests must cover the events defined by the final DRBG and entropy architecture, including reseed, entropy-provider transition, software-load/update transition, and any processor-specific implementation selection. The exact set is a CSTL scope decision and must not be inferred solely from the current unit-test suite.

## Integrity control

The module must define a reproducible release image and a trusted integrity mechanism. The integrity measurement must cover all executable code, read-only tables, relevant configuration, and any assembly/C objects inside the logical boundary. The release process must record source commit, submodule commits, compiler/YASM/linker versions, flags, ELF model, and final binary hash.

A startup integrity failure must prevent entry to `READY`. Runtime mutable state must not be allowed to modify the measured image. The trusted anchor, update procedure, rollback policy, and error response belong in the Security Policy and operational-environment guide.

## SSP lifecycle and zeroization

Raw entropy bytes, DRBG key/value state, seed material, and any derived sensitive state require a formal SSP classification. The module must not rely on compiler-visible `memset` being retained for zeroization; the final implementation needs a reviewed zeroization primitive and evidence that C and YASM builds preserve its semantics. Zeroization must be applied on normal uninstantiate, error cleanup, context destruction, and failed self-test paths.

The OS provider must not return internal cache addresses or retain caller pointers. If batching is retained for a non-Approved service, it must be a separate boundary with separate documentation and must not be reachable from Approved mode. Fork behavior must be explicitly specified: either forbid use across fork without reinitialization, or define a child-process transition that invalidates all inherited DRBG and provider state before any Approved generation.

## Error and service policy

| Condition | Public status | State effect | Output effect |
|---|---|---|---|
| Context is null or not initialized | `NOT_READY` or `INVALID_ARGUMENT` | Unchanged | Output unchanged. |
| Startup KAT fails | `SELF_TEST_FAILURE` | Latch `ERROR` | Output unchanged. |
| Integrity check fails | `INTEGRITY_FAILURE` | Latch `ERROR` | Output unchanged. |
| Entropy provider unavailable | `ENTROPY_FAILURE` | `RESEED_REQUIRED` or `ERROR`, per approved policy | Output unchanged. |
| DRBG request exceeds limit | `RESEED_REQUIRED` or `INVALID_ARGUMENT` | No unsafe generation | Output unchanged. |
| Range bound invalid | `INVALID_ARGUMENT` | Context remains usable | Output unchanged. |
| Internal invariant violation | `INTERNAL_FAILURE` | Latch `ERROR` | Output unchanged; clear sensitive temporaries. |
| Explicit uninstantiate | `SUCCESS` | `ZEROIZED` | No random output is published. |

Status names, values, retryability, state transitions, and output preservation must be frozen in the public header before implementation. The implementation must not expose raw `errno`, syscall numbers, entropy bytes, or DRBG state through a diagnostic API in Approved mode.

## Test evidence required

The validation-grade test package must contain deterministic tests for every state transition and every status in the table. It must include known-answer vectors, tampered-image tests, corrupted-context tests, fault-injected entropy failures, `EINTR`, short reads, early initialization behavior, reseed limits, fork/exec boundaries, concurrent independent contexts, failed self-test inhibition, zeroization checks, and ABI/link-model variants.

Randomness statistical tests may support engineering assurance but cannot replace algorithm KATs, entropy-source evidence, or CSTL testing. Coverage must distinguish C source coverage, assembly instruction/control-flow evidence, and black-box state-machine coverage.

## References

[1]: https://csrc.nist.gov/pubs/fips/140-3/final "NIST FIPS 140-3"

[2]: https://csrc.nist.gov/pubs/sp/800/140/final "NIST SP 800-140"

[3]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[4]: https://csrc.nist.gov/pubs/sp/800/90/b/final "NIST SP 800-90B"

[5]: https://csrc.nist.gov/pubs/sp/800/90/c/final "NIST SP 800-90C"
