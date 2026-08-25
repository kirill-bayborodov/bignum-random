# Track B Implementation Gate

**Status:** Open engineering gate; candidate implementation slice in progress.  
**Current baseline:** Track B architecture, DRBG traceability, state/self-test/SSP design, and explicit context/ASM boundary are documented. The owner selected **Option A** as an engineering direction: implement this repository's own AES-256 CTR_DRBG candidate and prepare it for CSTL submission. No FIPS validation claim is made.

## Why the Approved DRBG cannot be guessed

The project can implement a technically correct AES-256 CTR_DRBG candidate, but a locally written candidate is not automatically an Approved security function. NIST describes CAVP algorithm validation as a prerequisite for cryptographic module validation [1]. Therefore the implementation must not label a new local DRBG, raw Linux `getrandom(2)`, or the bounded rejection transform as FIPS Approved before the exact algorithm implementation and validation scope are accepted.

The current Makefile selects either `src/bignum_random.c` or `src/bignum_random.asm` as the production object. It does not compile a second DRBG translation unit. Because the Makefile is a protected file, the first implementation must use one of two explicitly approved packaging strategies: integrate the complete context/DRBG implementation into both selected production sources, or introduce a prevalidated external library as a vendor distribution whose boundary is documented and linked by the existing build rules. A partial C-only API would compile in one mode and fail or silently disappear in the ASM mode, which is unacceptable.

## Gate inputs required before production implementation

| Input | Why it is blocking | Acceptable evidence |
|---|---|---|
| Exact Approved DRBG profile | Security strength, seed length, nonce/personalization rules, reseed limits, prediction resistance, and additional-input semantics must be frozen. | CSTL-approved architecture decision referencing the applicable SP 800-90A profile. |
| Algorithm implementation strategy | A locally written algorithm and a validated algorithm are not interchangeable claims. | CAVP certificate, validated vendor library scope, or explicit CSTL agreement to test this implementation. |
| Entropy treatment | Linux `getrandom(2)` may be an external source or an entropy input; its treatment controls SP 800-90B/90C evidence. | Entropy-source validation/justification and provider contract accepted by the lab. |
| Module boundary | The DRBG, range service, OS provider, benchmark code, and distribution must be classified. | Boundary diagram and Security Policy draft. |
| Protected build constraint | No Makefile or CI edits are allowed. | Packaging decision that builds both C11 and YASM paths with identical public semantics. |
| Test-vector source | KAT vectors cannot be invented from an unverified implementation. | Authoritative SP 800-90A/CAVP vectors and reproducible vector runner. |

## Allowed work before gate closure

The team may implement non-cryptographic scaffolding: versioned status values, opaque-context ownership rules, a provider callback interface for deterministic tests, state-machine transitions, output-preservation rules, documentation, and tests that use a clearly labelled test provider. Such code must remain non-Approved until it is connected to the selected DRBG and passes the authoritative KAT suite.

The team may also prepare an ASM leaf boundary for AES or DRBG operations, but it must not be called from an Approved service until its C11 reference, vectors, ABI review, side-channel review, and CAVP strategy are complete. Benchmark improvements do not override the gate.

## First implementation slice after closure

1. Add the explicit context/status API to both production build paths without hidden TLS state.
2. Add a deterministic provider seam that is compiled out of the validated image or is provably unreachable in Approved mode.
3. Implement the selected CTR_DRBG in C11 with complete Doxygen and authoritative KAT vectors.
4. Add startup/conditional self-tests and a fail-closed state latch.
5. Port only the measured cryptographic leaf to YASM while retaining the C state machine.
6. Execute fault injection, sanitizers, Helgrind, ABI/link-model checks, and exact-image evidence.

## Decision record

The project owner selected **(A)**: implement and submit this repository's own AES-256 CTR_DRBG candidate. This is an engineering decision, not CSTL approval and not evidence of CAVP or CMVP validation. The gate remains open until the exact profile, implementation boundary, entropy treatment, vector results, self-tests, image-integrity evidence, and protected-build packaging are reviewed with the laboratory. Writing a new assembly DRBG before those controls are complete would still create an unsubstantiated FIPS claim rather than certification progress.

## References

[1]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program "NIST Cryptographic Algorithm Validation Program"

[2]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[3]: https://csrc.nist.gov/pubs/sp/800/90/b/final "NIST SP 800-90B"

[4]: https://csrc.nist.gov/pubs/sp/800/90/c/final "NIST SP 800-90C"

[5]: https://csrc.nist.gov/pubs/fips/140-3/final "NIST FIPS 140-3"
