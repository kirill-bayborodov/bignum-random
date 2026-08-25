# Full-Module Security Review for Inline DF Activation

**Review status:** Inline DF remains test-only. No production dispatcher change is approved by this review.

## Scope and Method

The review covered the public service boundary, caller-allocated context, module lifecycle wrapper, inner CTR_DRBG operations, entropy-provider boundary, AES/BCC/DF assembly leaves, fork ownership checks, continuous entropy health tests, fault-injection tests, and production-object symbol isolation. Existing deterministic fault, fork, health, dispatch, and service tests were rebuilt against the current assembly object and passed.

The inline DF candidate was assessed as a replacement for the current expanded-key BCC calls inside a test-only DF variant. Its direct C11 equivalence, boundary suite, zeroization probe, and ASan/UBSan harness had already passed; this review focuses on whether those properties remain safe when reached through the complete module lifecycle.

## Transition Matrix

| Entry condition | Operation | Success transition | Failure transition | Secret cleanup assessment |
|---|---|---|---|---|
| Initialized, `UNINITIALIZED` | Startup with verified image | `READY` | `ERROR` on integrity/KAT failure | KAT locals are cleared; no provider is called |
| Initialized, `READY` | Instantiate | DRBG initialized; module remains `READY` | Provider/DRBG error latches `ERROR` | Context wrapper clears entropy; provider failure clears DRBG |
| Initialized, `READY` or `RESEED_REQUIRED` | Reseed | `READY` | Error latches `ERROR` | Context wrapper clears entropy; provider failure clears DRBG |
| Initialized, `READY` | Generate | `READY` | `RESEED_REQUIRED` at interval limit; other errors latch `ERROR` | Success path clears candidate/additional-input/block buffers |
| Initialized, `ERROR` | Any service operation | None | `ERROR_STATE`; no provider call | No new secret buffer is created at outer boundary |
| Initialized, any valid state | Uninstantiate | `ZEROIZED` | N/A | Module storage and context storage are cleared |
| Forked context | Any context operation | None | `ERROR_STATE` due process-owner mismatch | Context cannot use inherited DRBG state |
| Invalid provider output or failed health test | Instantiate/Reseed | None | `ERROR` | Entropy buffer is cleared and partial DRBG state is cleared |

## Findings

### Finding F-01: Inner Generate Error Cleanup Is Not Structured

**Status: Closed.** `bignum_ctr_drbg_generate` now initializes its temporary objects and routes validation failures, reseed-limit returns, DF failures, and the normal success path through one `cleanup` label. The label clears `candidate`, `add_data`, and `block` before returning the preserved status. The outer module continues to latch `ERROR` for non-reseed failures, while output and state commit remain success-only operations.

The cleanup refactor was followed by strict compilation, context/provider fault tests, fork isolation, health tests, production vector regression, ASan/UBSan, Memcheck, cppcheck, and diff hygiene checks. All passed.

### Finding F-02: Inner Instantiate/Reseed Error Cleanup Requires a Unified Exit Review

The current instantiate and reseed functions clear their local `input` and `seed` buffers after the DF/update sequence. Their input validation returns before secret material is copied, and the DF failure path reaches the cleanup statements. This behavior is currently correct, but it should remain covered by a fault-injection test that forces DF failure after temporary data has been populated.

**Severity:** Medium verification gap. **Status:** Closed for the test-only controlled-failure harness. A temporary dispatcher failure after temporary input setup returned `ERROR_STATE`, preserved output and context, and recorded all three unified cleanup calls. This seam is not part of production sources. The remaining production requirement is to retain equivalent coverage after any actual dispatcher switch.

### Finding F-03: Assembly Candidate Has No Self-Contained Validation

The inline candidate intentionally has no pointer or length validation. This is acceptable only when the C test-only variant and the eventual production dispatcher prove the same precondition boundary as the existing BCC leaf. Direct calls with invalid parameters are outside the leaf contract and must never be reachable from public APIs.

**Severity:** Accepted design constraint. **Status:** Controlled, not a defect. **Required action:** Preserve dispatcher validation and symbol-isolation checks during activation review.

### Finding F-04: Candidate Activation Must Preserve Existing State Semantics

The inline candidate changes only the BCC implementation inside Block_Cipher_df. It must not alter module state transitions, reseed-counter handling, provider invocation count, output-preservation behavior, or fork ownership checks. Existing full-module tests passed with the current production dispatcher, but they do not yet exercise an inline-backed DF through the complete context/service path.

**Severity:** Medium activation gate. **Status:** Closed for the test-only variant. The full-module inline DF dispatcher variant passed context/provider fault, health, fork, service, concurrency, and vector tests. The actual production switch remains separately gated by release-image audit, fallback validation, target-host benchmark, and explicit activation approval.

## Executed Evidence

| Gate | Result |
|---|---|
| Context/provider fault injection | PASS |
| Fork ownership isolation | PASS |
| Entropy RCT/APT fault tests | PASS |
| Backend dispatch and AES-NI detection | PASS |
| Controlled service lifecycle | PASS |
| Production PR=false/true vector regression | 240/240 and 240/240 PASS |
| Inline DF C11 differential suite | 4096/4096 PASS |
| Inline BCC direct equivalence | All 16-byte lengths 16–1056 PASS |
| Inline candidate zeroization probe | PASS |
| Inline direct ASan/UBSan equivalence | PASS |
| Production object test-hook isolation | PASS |

## Activation Recommendation

Do not activate inline DF in the production dispatcher yet. The candidate's cryptographic and leaf-level behavior is strong, but full-module activation is now gated by release and change-control requirements rather than unresolved F-01/F-02/F-04 defects. F-01 is complete; F-02 and F-04 are closed for test-only evidence. The remaining activation work is the production release-image audit, non-AES-NI fallback validation, target-host benchmark, documentation/change-control update, and explicit activation approval. After those actions, rerun the complete fault, lifecycle, zeroization, vector, sanitizer, Memcheck, and production-image isolation gates on the actual production dispatcher.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[2]: https://csrc.nist.gov/pubs/fips/140-3/final "FIPS 140-3 Security Requirements for Cryptographic Modules"
