# Track B Architecture Decision

**Status:** Approved for engineering development; not a FIPS 140-3 validation claim.  
**Baseline:** `v0.0.0` / commit `3163a6b7b44d87fe222fbeefa40e00b0268930df`.  
**Decision owner:** Project owner.  
**Decision:** Build a complete software cryptographic module around an Approved deterministic random bit generator and expose bounded `bignum_random` as a service that consumes Approved RBG output.

## Decision summary

The current direct Linux `getrandom(2)` design is retained only as an engineering baseline. It is not treated as the validated cryptographic primitive. The Track B target boundary contains a DRBG, its entropy-input and health-test integration, lifecycle state, self-tests, software integrity mechanism, and the bounded integer service. A Linux provider may supply entropy to the boundary only under an explicitly documented and laboratory-approved entropy/RBG construction.

The initial DRBG candidate is **CTR_DRBG using AES-256 with the derivation function**, subject to confirmation against the current CMVP Approved Security Functions list, the selected CAVP validation path, and the target security strength. The project must not claim that this candidate is Approved until the exact implementation and certificate scope are confirmed by the selected CSTL. AES-256 is a design candidate, not a certificate.

## Logical boundary

| Inside the proposed module | Outside the proposed module |
|---|---|
| Public Approved and non-Approved service interfaces | Calling application and its object ownership |
| `bignum_random` range transform and output normalization | Linux kernel implementation and scheduler |
| Approved CTR_DRBG implementation and lifecycle state | CPU microcode and physical entropy circuitry |
| Entropy-provider adapter and its documented contract | Host distribution packaging outside the validated image |
| Health tests, self-tests, failure latch, and service gating | Benchmark tools and test-only fault-injection controls |
| Sensitive state, transient buffers, zeroization, and integrity metadata | Developer workstation and CI service itself |
| Exact validated software image and build identity | Unsupported kernels, ABIs, link models, and CPU families |

The boundary must be redrawn if the laboratory determines that the host operating-system RNG is an external validated component or an excluded operational-environment service. The final Security Policy, not this engineering decision, controls the certification claim.

## Proposed service model

The Approved service obtains bytes from the Approved RBG, applies the specified unbiased rejection transform, and writes a normalized result only on success. The range transform contains no key material and is not itself claimed as a DRBG. The non-Approved direct-`getrandom` baseline must either be removed from the validated image or be clearly separated and inhibited whenever the module is in Approved mode.

The preferred state model is an explicit module context owned by the caller or by a narrowly defined module lifecycle object. It contains DRBG state, reseed counters, health-test state, failure latch, and zeroization metadata. The current implicit ELF TLS raw-entropy cache is not the Track B target because it complicates SSP classification, fork semantics, image scope, and laboratory evidence. It may remain only in the pre-validation baseline branch and must not be silently mixed with Approved state.

## Required state machine

| State | Allowed operation | Transition on failure |
|---|---|---|
| `UNINITIALIZED` | No Approved generation | `instantiate` after validated entropy and startup checks |
| `SELF_TEST` | Self-tests only | `READY` on success; `ERROR` on failure |
| `READY` | Approved instantiate/reseed/generate and bounded service | `ERROR` on health, integrity, DRBG, or entropy failure |
| `RESEED_REQUIRED` | Reseed only; no ordinary generation | `READY` on successful reseed; `ERROR` on failure |
| `ERROR` | Diagnostic/status service only | Explicit lifecycle reset/reload governed by policy |
| `ZEROIZED` | No cryptographic service | Re-instantiate only through approved lifecycle |

The state machine must be represented in the API and tested as a fail-closed machine. A status return alone is insufficient if an Approved service can continue after a self-test or integrity failure.

## Platform policy

The first validation target is a precisely frozen Linux x86-64 operational environment with a specified kernel range, distribution image, compiler, assembler, linker, ELF relocation model, and CPU feature set. The raw syscall number and System V AMD64 register convention are implementation details of this target. A later port to another architecture is a new operational-environment claim and requires separate evidence.

The current Linux provider uses `getrandom(2)` with flags zero and requests no more than 256 bytes. Linux documents special behavior for initialized `urandom` reads up to 256 bytes, but the provider must still handle short reads, `EINTR`, initialization blocking, and terminal failure. The final module must document whether these conditions cause retry, reseed-required, service inhibition, or an operator-visible error.

## Non-goals and prohibitions

This decision does not claim FIPS validation, CAVP validation, SP 800-90B entropy validation, or SP 800-90C RBG validation. It does not authorize an unreviewed fallback from the Approved DRBG to raw kernel bytes. It does not authorize test hooks, benchmark instrumentation, RDRAND experiments, or hidden environment switches inside the Approved image. It does not permit changing the validated boundary merely to make a benchmark pass.

## Exit criteria for architecture phase

The architecture phase is complete only when the project owner and the selected CSTL can agree on the logical boundary, the Approved DRBG profile, the entropy-source treatment, the target security strength, the operational environment, the self-test and integrity approach, and the status of the current direct-kernel baseline. Until then, implementation work must be labelled Track B engineering preparation rather than certification work.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[2]: https://csrc.nist.gov/pubs/fips/140-3/final "NIST FIPS 140-3"

[3]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program "NIST CAVP"

[4]: https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-standards "NIST CMVP FIPS 140-3 Standards"

[5]: https://csrc.nist.gov/pubs/sp/800/90/b/final "NIST SP 800-90B"

[6]: https://csrc.nist.gov/pubs/sp/800/90/c/final "NIST SP 800-90C"

[7]: https://man7.org/linux/man-pages/man2/getrandom.2.html "Linux getrandom(2)"
