# Track B Current State Review

**Review basis:** repository `main` at the pre-health-boundary commit `4dd41a0faa852beec844e5156adde8342c823bf1`, plus the uncommitted health-boundary changes currently under review. The review is an engineering assessment and is not a FIPS validation decision.

## Current architecture

The repository contains two deliberately separate paths. The legacy `bignum_random` family function remains the protected production target and uses its established C11/YASM implementation. The Track B candidate is a separate C11 AES-256 CTR_DRBG with derivation function, lifecycle wrapper, caller-allocated context adapter, AES-NI leaf and runtime fallback dispatcher. Expanded AES schedule declarations are internal-only, and candidate harnesses live under `tools/` so the protected Makefile wildcard does not treat them as production tests.

The caller context now carries opaque-style DRBG/lifecycle storage, an initialization marker and creator process identifier. A forked child cannot use an inherited context; it must initialize new storage. The entropy provider is synchronous and borrowed, supplies exactly 32 bytes, is never retained, and is called only in permitted lifecycle states.

## Evidence matrix

| Area | Evidence | Status |
|---|---|---|
| AES-256 CTR_DRBG `use df`, PR=false | 240/240 C11 and 240/240 YASM-linked records | PASS |
| AES-256 CTR_DRBG `use df`, PR=true | 240/240 C11 and 240/240 YASM-linked records | PASS |
| Lifecycle and self-test | Integrity gate, KAT, error latch, zeroization harness | PASS |
| Caller context/provider faults | Strict and ASan/UBSan deterministic harness | PASS |
| RCT/APT candidate health faults | Constant-symbol RCT and 64-byte-window APT harness | PASS |
| Thread isolation | Four independent pthread contexts; Helgrind clean | PASS |
| Fork isolation | Child rejects inherited creator PID; parent remains valid | PASS |
| Legacy C11 regression | 5/5 tests | PASS |
| Legacy ASM regression | 5/5 tests | PASS |
| Static checks | Strict compile, cppcheck, diff check | PASS |
| GitHub Actions | Recent C/ASM CI runs completed successfully through commit `4dd41a0` | PASS |

## Production-image audit

The release archive produced by `make dist CONFIG=release USE_ASM=yes` contains only `bignum_random.o` and `bignum_core.o`. Symbol and string scans found no candidate DRBG, entropy-provider, health-test, deterministic-provider, fault-hook, RDRAND or direct `getrandom` references. The archive is static and its objects have no dynamic section. The distribution runner passed.

This is a packaging-isolation result for the current legacy image. It is not proof that a future Approved image will exclude test seams after candidate integration. A future validated image needs a frozen build manifest, symbol allowlist, link map, dependency inventory, exact-image digest and repeatable audit.

## Strengths

The project has strong deterministic evidence at the cryptographic leaf and complete legacy C11 line coverage. C11 and YASM outputs agree across both prediction-resistance suites, lifecycle failures are fail-closed, the provider is not retained, and process/thread isolation has explicit dynamic tests. Protected build constraints were respected throughout: neither `Makefile` nor `.github/workflows/ci.yml` was modified.

## Findings and blockers

The current RCT/APT thresholds and window are candidate engineering defaults. They must be derived and justified for the selected entropy source and operating environment under SP 800-90B evidence; they must not be presented as universal or certified parameters. The candidate health state is private but currently embedded in a public-sized opaque-style storage type rather than a strict incomplete type, because the protected build does not yet provide an allocation/API integration target.

The legacy production image remains non-Approved compatibility code and is not the candidate DRBG module. The final module still requires an approved entropy source, startup and continuous health-test policy, exact image-integrity verification, provider failure mapping, full CAVP/CMVP evidence, and a controlled production build that deliberately includes the Approved boundary while excluding deterministic test providers.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/90/b/final "NIST SP 800-90B"

[2]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[3]: https://csrc.nist.gov/pubs/fips/140-3/final "NIST FIPS 140-3"
