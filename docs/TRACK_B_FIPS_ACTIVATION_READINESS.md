# Track B FIPS Activation Readiness

**Status:** Engineering readiness checkpoint; no FIPS 140-3 or CAVP claim.

## Scope

This checkpoint evaluates the current AES-256 CTR_DRBG with derivation function implementation, the YASM AES/BCC/DF leaves, the inline BCC optimization candidate, the caller-allocated lifecycle context, the entropy-provider boundary, and the proposed Linux x86-64 operational environment. The inline DF candidate is still not selected by the production dispatcher.

## Evidence Status

| Area | Current evidence | Status |
|---|---|---|
| C11 DRBG reference | Strict C11 implementation and vector runner | PASS as engineering evidence |
| YASM AES/BCC/DF leaves | KATs, direct equivalence, boundary fuzzing, snapshots | PASS as engineering evidence |
| Inline BCC/DF candidate | 4096/4096 DF cases; test-only full-module variant | PASS as candidate evidence; not production active |
| F-01 cleanup | Unified cleanup path in inner generate | CLOSED |
| F-02 controlled DF failure | Output/context preservation, ERROR status, cleanup trace | CLOSED for test-only seam |
| F-04 full-module inline variant | Lifecycle, provider, fork, health, service, concurrency and vector tests | CLOSED for test-only variant |
| Non-AES-NI fallback | C11-only shared library, both 240-case suites | PASS |
| Release distribution | `make dist CONFIG=release USE_ASM=yes`, archive symbol and hook scan | PASS with existing bundled smoke-test source exception |
| Production object metadata | `.note.GNU-stack` present; exported archive symbol is `bignum_random` | PASS for inspected artifact |
| FIPS certification | Certificate, CSTL scope, final Security Policy, entropy-source disposition | OPEN; external process |

## Release-Image Audit Result

The existing distribution recipe produces `libbignum_random.a`, generated `bignum_random.h`, `README.md`, `LICENSE`, and `test_bignum_random_runner.c`. The library and generated production header contain no test/fault/snapshot/zeroization-hook markers. The runner source is intentionally included by the pre-existing distribution recipe and is not linked into the library; the final validated image must classify or exclude it according to the laboratory-approved packaging boundary.

The inspected object contains `.note.GNU-stack`, and the archive's defined production symbol is `bignum_random`. A reproducible release manifest and exact binary hash are still required for a certification submission.

## FIPS-Oriented Remaining Gates

### G-01: Freeze the module boundary and Security Policy

The project owner and selected CSTL must finalize whether the Linux `getrandom(2)` provider is inside the module, an external validated component, or an operational-environment dependency. The Security Policy must identify the Approved services, non-Approved services, roles, SSPs, error states, operational environment, and supported configurations.

### G-02: Confirm the Approved algorithm and validation scope

The exact CTR_DRBG capability profile, security strength, entropy input requirements, prediction-resistance mode, reseed policy, and CPU-dependent implementation scope must be confirmed against the active CMVP/CAVP process. Passing local vectors is not a certificate.

### G-03: Production activation change control

If inline DF is selected, the actual production dispatcher change must be a separately reviewed commit. It must preserve AES-NI capability gating and C11 fallback behavior, and its image manifest, symbol map, compiler/assembler/linker flags, and rollback revision must be recorded.

### G-04: Independent entropy and health evidence

The entropy provider requires a laboratory-approved treatment under SP 800-90B/90C or applicable CMVP guidance. Existing RCT/APT tests demonstrate engineering behavior but do not establish source min-entropy or validation.

### G-05: Integrity and self-test evidence

The external image-integrity mechanism, trusted anchor, exact startup ordering, power-up KAT, conditional tests, failure inhibition, and operator-visible error behavior must be specified and independently reviewed.

### G-06: Frozen operational environment

The target Linux distribution, kernel range, compiler, YASM, linker, ELF model, CPU feature policy, package contents, build identity, and change policy must be frozen. Non-AES-NI fallback is technically tested, but each claimed configuration must be included in the approved scope or explicitly excluded.

### G-07: Final activation regression

After and only after explicit engineering/security approval, rerun strict build, both vector suites, full context/service lifecycle, controlled fault transitions, health, fork, concurrency, zeroization, ASan/UBSan, Memcheck, cppcheck, production-image isolation, and target-host paired median/MAD benchmarks against the actual production dispatcher.

## Recommendation

The project is ready for a formal CSTL-oriented activation review, not for a FIPS claim. F-01, F-02, F-04, candidate equivalence, fallback, and current release-image smoke checks provide strong engineering evidence. Inline DF should remain test-only until G-01 through G-07 are explicitly resolved and the production activation change receives approval.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[2]: https://csrc.nist.gov/pubs/sp/800/90/b/final "NIST SP 800-90B"

[3]: https://csrc.nist.gov/pubs/sp/800/90/c/final "NIST SP 800-90C"

[4]: https://csrc.nist.gov/pubs/fips/140-3/final "NIST FIPS 140-3"

[5]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program "NIST CAVP"
