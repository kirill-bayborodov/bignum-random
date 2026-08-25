# v0.1.0 Self-Test and Integrity Evidence

**Artifact:** `v0.1.0` at commit `03cf951806923cd87359bea792b1f5b6ee59bb79`.

**Current engineering HEAD:** `f492d3c4a9ab30ae8c1baf1fe27301864afb2d6b`. Later commits contain post-release security, optimization, and documentation evidence; they are not silently attributed to the v0.1.0 tag.

**Certification status:** Engineering evidence only. This report is not a FIPS 140-3 validation claim.

## Self-Test Controls

The module startup sequence accepts an externally supplied image-integrity result, enters `SELF_TEST`, runs a fixed power-up CTR_DRBG KAT sequence, and enters `READY` only when both checks succeed. A false integrity result or KAT failure latches `ERROR`. Service operations are inhibited in `ERROR`; context uninstantiate zeroizes storage and permits a controlled future startup sequence.

| Self-test/control | Evidence artifact | Result |
|---|---|---|
| Startup with failed integrity result | `tools/test_ctr_drbg_context_faults.c` | PASS; `ERROR` latch and generation inhibition |
| Startup with verified integrity result | Context/service tests | PASS; `READY` reached |
| Power-up AES/CTR_DRBG KAT sequence | `src/bignum_ctr_drbg_module.c` | PASS in service lifecycle tests |
| Instantiate/reseed/generate KAT path | Module startup `power_up_kat()` | PASS |
| Failed provider transition | Context fault test | PASS; `ERROR`, no later service |
| Entropy health failure | `tools/test_ctr_drbg_health.c` | PASS; failure is fail-closed |
| Uninstantiate and restart | Context fault/service tests | PASS; storage zeroized, controlled restart |
| Fork ownership transition | `tools/test_ctr_drbg_context_fork.c` | PASS; inherited context rejected |
| Concurrent independent contexts | `tools/test_ctr_drbg_context_mt.c` | PASS |
| Assembly AES-256 KAT | `tools/test_ctr_drbg_aes_asm.c` | PASS |
| NIST-style DRBG vectors | `tests/test_bignum_random.c` conditional C11 vector mode | PR=false 240/240; PR=true 240/240; 480 total |

## Integrity Evidence

The current interface treats image integrity as an external boolean gate. The startup API does not calculate or verify a digest, hold a trusted anchor, define an update signature policy, or record a reproducible image hash internally. Therefore, the engineering evidence proves fail-closed response to a failed external result, but does not prove a complete FIPS software-integrity mechanism.

| Integrity control | Current evidence | Status |
|---|---|---|
| Pre-READY integrity gate | `image_integrity_verified` startup parameter | PASS as boundary behavior |
| Failure inhibits services | Context fault test | PASS |
| Trusted anchor | Not implemented in repository | OPEN |
| Exact image digest/signature verification | External to current code | OPEN |
| Reproducible build identity | Commit/tag recorded; full toolchain manifest not frozen | OPEN |
| Measured object/configuration scope | Release archive inspection only | OPEN |
| Runtime protection of measured image | Design requirement documented | OPEN |
| Update and rollback policy | Not defined for CSTL submission | OPEN |

## v0.1.0 Release-Image Checks

The existing release recipe produced `libbignum_random.a`, generated `bignum_random.h`, `README.md`, `LICENSE`, and the existing smoke-test source. The production library and generated header contained no test/fault/snapshot/zeroization-hook markers. The archive exposed the expected `bignum_random` symbol, and the inspected object contained `.note.GNU-stack`. The smoke-test source is classified as a packaging exception because the existing recipe includes it but does not link it into the library.

These checks do not establish that the v0.1.0 tag includes post-release F-01 hardening or later inline-candidate evidence. The exact tag scope was rebuilt independently for this report. The source archive manifest was generated at `/tmp/v010-evidence/v0.1.0-source.sha256`; the built shared-library evidence hash was recorded at `/tmp/v010-evidence/v0.1.0-built-library.sha256` as `94c273aeb01f9aa887d22e575bed6e2829897dbe9f5a9b78d6b1f064c75d7669`. The hash is an evidence identifier, not an implemented trusted-anchor verification mechanism.

The exact-tag run passed caller/provider fault injection, fork ownership isolation, entropy RCT/APT tests, backend dispatch, controlled service lifecycle, concurrent context isolation, and both 240-case NIST-style vector suites. Strict C11 compilation used `-std=c11 -Wall -Wextra -Werror -pedantic -O2`; the assembly object was built with YASM for ELF64. The current tag therefore has reproducible local test evidence, while the FIPS integrity mechanism remains an open implementation and CSTL-scope item.

## Required CSTL Evidence Package

The submission package must add a trusted integrity mechanism and document its trusted anchor, measured image scope, build inputs, verification timing, failure response, update process, rollback policy, and exact binary hash. The package must bind these artifacts to the final Security Policy and to the frozen operational environment. Local KAT and vector results remain supporting engineering evidence and do not replace CAVP or CSTL assessment.

## References

[1]: https://csrc.nist.gov/pubs/fips/140-3/final "NIST FIPS 140-3"

[2]: https://csrc.nist.gov/pubs/sp/800/140/final "NIST SP 800-140"

[3]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"
