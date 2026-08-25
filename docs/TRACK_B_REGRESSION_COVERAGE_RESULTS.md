# Track B Full Regression and Coverage Results

**Status:** Candidate engineering evidence; not a CAVP, CMVP, or FIPS validation claim.

## Regression matrix

| Artifact or mode | Command family | Result |
|---|---|---|
| Legacy C11 production tests | `make test CONFIG=release USE_ASM=no` | **0/5 failed** |
| Legacy production ASM tests | `make test CONFIG=release USE_ASM=yes` | **0/5 failed** |
| Existing ASM under AddressSanitizer | `make test_sanitize SAN=address CONFIG=debug USE_ASM=yes` | **5 tests, 0 failures, 0 sanitizer issues** |
| Existing ASM under UBSan | `make test_sanitize SAN=undefined CONFIG=debug USE_ASM=yes` | **5 tests, 0 failures, 0 sanitizer issues** |
| Existing MT test under Helgrind | `make test_helgrind CONFIG=debug USE_ASM=yes` | **0/1 runs found races** |
| Candidate DRBG PR=false C11 | CAVP-style RSP runner | **240/240 PASS** |
| Candidate DRBG PR=true C11 | CAVP-style RSP runner | **240/240 PASS** |
| Candidate DRBG PR=false YASM-linked | CAVP-style RSP runner | **240/240 PASS** |
| Candidate DRBG PR=true YASM-linked | CAVP-style RSP runner | **240/240 PASS** |
| Caller context fault injection | Strict and ASan/UBSan harness | **PASS** |
| Caller context concurrent isolation | 4 pthread workers, independent contexts/providers | **PASS** |
| Caller context fork isolation | Parent/child inherited-context rejection | **PASS**, including ASan/UBSan child run |
| Entropy RCT/APT health faults | Constant-symbol RCT and 64-byte-window APT injection | **PASS**, strict and ASan/UBSan |

The protected `Makefile` and `.github/workflows/ci.yml` were not modified. Candidate-specific harnesses remain under `tools/` because the protected Makefile treats every `tests/*.c` file as a production test target.

## C11 gcov coverage

The legacy C11 test matrix was rebuilt with `--coverage` using command-line flag overrides only. Candidate lifecycle coverage was collected separately with a deterministic fault-injection harness. Percentages below distinguish executed lines from branches that were taken at least once.

| Source artifact | Lines executed | Branches executed | Branches taken at least once | Calls executed |
|---|---:|---:|---:|---:|
| `src/bignum_random.c` legacy | **100.00% (50/50)** | 95.24% (40/42) | 90.48% (38/42) | 100.00% (6/6) |
| `src/bignum_ctr_drbg.c` | **97.35% (220/226)** | 94.37% (134/142) | 67.61% (96/142) | 96.25% (77/80) |
| `src/bignum_ctr_drbg_module.c` | **83.33% (50/60)** | 84.62% (44/52) | 50.00% (26/52) | 92.31% (12/13) |
| `src/bignum_ctr_drbg_context.c` | **85.92% (61/71)** | 94.44% (34/36) | 55.56% (20/36) | 82.35% (28/34) |
| `tools/test_ctr_drbg_context_faults.c` | **97.67% (42/43)** | 100.00% (60/60) | 51.67% (31/60) | 50.94% (27/53) |
| `tools/test_ctr_drbg_context_fork.c` | **85.00% (17/20)** | 85.71% (24/28) | 46.43% (13/28) | 42.11% (8/19) |
| `tools/test_ctr_drbg_context_mt.c` | **86.67% (26/30)** | 100.00% (32/32) | 62.50% (20/32) | 100.00% (9/9) |

The legacy C11 line result is complete for the current test matrix. Candidate DRBG and context percentages are deterministic harness coverage, not a claim that every lifecycle branch is complete. The remaining uncovered candidate branches should be exercised by provider health-test failures, reseed-limit transition through the caller boundary, and malformed input combinations. Fork and parallel lifecycle behavior now have dedicated deterministic harness evidence.

## Assembly coverage model

YASM does not emit GCC `.gcno`/`.gcda` source coverage. The AES-NI leaf is therefore evaluated through FIPS 197 KAT equivalence, full CAVP-style vector equivalence in both PR modes, runtime dispatch tests, sanitizer-linked execution, ELF metadata inspection, and microbenchmark evidence. No gcov percentage is assigned to assembly.

## Reproduction

```sh
# Legacy regression.
make test CONFIG=release USE_ASM=no
make test CONFIG=release USE_ASM=yes
make test_sanitize SAN=address CONFIG=debug USE_ASM=yes
make test_sanitize SAN=undefined CONFIG=debug USE_ASM=yes
make test_helgrind CONFIG=debug USE_ASM=yes

# Candidate lifecycle fault gate.
gcc -std=c11 -Wall -Wextra -Werror -pedantic -Iinclude \
  tools/test_ctr_drbg_context_faults.c src/bignum_ctr_drbg.c \
  src/bignum_ctr_drbg_module.c src/bignum_ctr_drbg_context.c \
  -o /tmp/bignum-random-drbg-build/test_context_faults
/tmp/bignum-random-drbg-build/test_context_faults
```

## Remaining gates

Coverage is evidence for review and does not substitute for CSTL/CAVP/CMVP testing. The concurrency and fork behavior stage is now covered by deterministic harnesses. The candidate now also applies private byte-symbol RCT/APT-like continuous checks before entropy enters the DRBG. The thresholds remain engineering candidates pending entropy-source assessment and CSTL review; they are not a validation claim.
