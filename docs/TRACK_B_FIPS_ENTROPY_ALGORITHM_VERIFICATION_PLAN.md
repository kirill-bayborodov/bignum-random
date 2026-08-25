# FIPS Verification Plan: Entropy Source and Approved Algorithm Scope

**Purpose:** Define the verification work required before the Track B candidate can be presented to a CSTL for entropy and algorithm-scope decisions.

**Status:** Planning artifact; not a validation claim.

## Official Scope Notes

The CMVP entropy-validation guidance states that FIPS 140-2 and FIPS 140-3 module submissions must include documentation justifying conformance to SP 800-90B when applicable, and identifies SP 800-90C RBG validation as a separate submission path [6]. NIST describes CAVP algorithm validation as a prerequisite to cryptographic module validation and states that algorithm validation alone does not satisfy module-validation requirements [7]. The current ACVP DRBG specification covers injected entropy/other inputs and instantiate, generate, and reseed algorithm behavior, while excluding the entropy source, health testing, uninstantiate, automatic reseed and error-condition validation [8]. The project plan therefore keeps entropy-source, lifecycle, health, integrity and module-boundary evidence separate from DRBG algorithm vectors.

## Workstream A: Entropy-Source Treatment

| Step | Verification activity | Required evidence | Decision owner |
|---:|---|---|---|
| A1 | Freeze the entropy boundary | Data-flow diagram from Linux `getrandom(2)` to entropy buffer, health tests and DRBG instantiate/reseed | Project owner and CSTL |
| A2 | Identify source construction | Determine whether the source is an external validated component, an OS dependency, or an entropy source requiring SP 800-90B assessment | CSTL |
| A3 | Define source model | Document source type, conditioning assumptions, claimed min-entropy, startup behavior, blocking, short reads, `EINTR`, and terminal errors | Entropy assessor |
| A4 | Evaluate health tests | Map RCT/APT parameters to the source assessment; document startup and continuous test scope and failure response | Entropy assessor/CSTL |
| A5 | Validate interface contract | Prove exact output length, no partial-success acceptance, transient ownership, zeroization, provider non-retention and error mapping | Engineering + CSTL |
| A6 | Map RBG construction | Select applicable SP 800-90C construction and identify which components are inside/outside the module | CSTL |
| A7 | Produce operational evidence | Capture kernel/distribution/toolchain versions, system call behavior, supported configurations and change policy | Engineering + CSTL |

The existing provider tests demonstrate engineering behavior only. They do not establish min-entropy, source independence, or acceptance of Linux `getrandom(2)` as an Approved entropy component.

## Workstream B: Approved Algorithm Scope

| Step | Verification activity | Required evidence | Exit criterion |
|---:|---|---|---|
| B1 | Select exact CTR_DRBG profile | Security strength, AES key size, seed length, entropy input length, nonce/personalization policy, additional input, reseed and prediction-resistance capabilities | Written capability profile approved by CSTL |
| B2 | Confirm Approved function status | Check active CMVP/CAVP scope and determine whether the exact implementation, AES variant and DF capability can be tested | Applicable validation path identified |
| B3 | Freeze implementation variants | Decide whether YASM AES-NI, C11 fallback, inline DF candidate, and any other CPU-dependent paths are in scope | Variant matrix signed off |
| B4 | Establish algorithm evidence | C11 reference, YASM equivalence, known-answer vectors, ACVP/CAVP test harness mapping and independent code review | Complete algorithm evidence package |
| B5 | Define service mapping | Specify which public services consume DRBG output, how range reduction is classified, and which services are non-Approved | Security Policy service table complete |
| B6 | Verify lifecycle coupling | Prove startup KAT/integrity gate precedes service use, and that entropy, health, DRBG, fault and reseed failures inhibit output | Full transition matrix passes |
| B7 | Freeze change control | Record source commit, assembly object, compiler/YASM/linker flags, ELF model, CPU policy, binary hash and rollback revision | Reproducible release record |

## Required Test Matrix

The CSTL package should include injected entropy and deterministic algorithm inputs for instantiate, generate, reseed, additional input, prediction resistance, and boundary limits. It should also include invalid pointers/lengths, short or interrupted provider reads, health failures, startup integrity failure, KAT failure, fork ownership mismatch, reseed-required transition, zeroized-context use, output preservation, and complete temporary-state cleanup.

## Decision Gates

| Gate | Condition | Current status |
|---|---|---|
| E-1 | Entropy boundary and source classification accepted | OPEN |
| E-2 | SP 800-90B/90C treatment and min-entropy evidence accepted | OPEN |
| E-3 | Exact Approved algorithm/capability scope selected | OPEN |
| E-4 | All claimed CPU implementation variants frozen | OPEN |
| E-5 | CAVP/ACVP path and test package agreed | OPEN |
| E-6 | Security Policy service/SSP/lifecycle mapping complete | OPEN |
| E-7 | Integrity mechanism and reproducible image identity complete | OPEN |
| E-8 | Final production dispatcher activation approved | OPEN |

## Recommended Sequence

First obtain a CSTL decision on entropy-source treatment and exact CTR_DRBG capability scope. Do not expand implementation claims while those decisions are open. Next freeze the module boundary and operational environment, prepare the validation-grade test package, implement or integrate the trusted image-integrity mechanism, and only then consider changing the production dispatcher to the inline DF backend. The final activation must be followed by a complete regression and release-image audit using the exact claimed image.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[2]: https://csrc.nist.gov/pubs/sp/800/90/b/final "NIST SP 800-90B"

[3]: https://csrc.nist.gov/pubs/sp/800/90/c/final "NIST SP 800-90C"

[4]: https://csrc.nist.gov/pubs/fips/140-3/final "NIST FIPS 140-3"

[5]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program "NIST CAVP"

[6]: https://csrc.nist.gov/projects/cryptographic-module-validation-program/entropy-validations "NIST CMVP Entropy Validations"

[7]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program "NIST CAVP and module-validation relationship"

[8]: https://pages.nist.gov/ACVP/draft-vassilev-acvp-drbg.html "NIST ACVP DRBG JSON specification"
