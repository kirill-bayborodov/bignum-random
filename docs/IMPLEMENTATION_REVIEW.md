# Implementation Review: `bignum_random`

**Reviewed revision:** working tree, 25 August 2026.
**Scope:** public API, C11 reference, hybrid x86-64 YASM implementation, tests, adapter, profiles, README, distribution, and protected build files.
**Protected files:** `Makefile` and `.github/workflows/ci.yml` are unchanged.

## Review conclusion

`bignum_random` is functionally complete and produces a normalized cryptographically random `bignum_t` in `[0, upper_bound)`. It validates every public precondition, uses Linux `getrandom(2)`, applies unbiased rejection sampling, and publishes `out` only after a valid candidate has been accepted. The final YASM path preserves the public status and output contract while adding a safe, private per-thread entropy cache for active lengths below `BIGNUM_CAPACITY`; full-capacity calls use direct kernel entropy instead.

The latest controlled paired full matrix passes its performance gate: all 24 profile × mode groups match, no group exceeds the configured 5% regression threshold and baseline MAD floor, and the final ASM candidate has a **−27.031% median latency delta** or **1.3705× median speed-up** against its paired C11 baseline. This is a host- and workload-qualified result, not an architecture-independent promise.

## Final quality-gate evidence

| Gate | Command or evidence | Result |
|---|---|---|
| C11 contract tests | `make test CONFIG=release USE_ASM=no` | Pass: 5 / 5 binaries. |
| C11 coverage | `gcov -b -c` after all C11 tests | 100.00% lines; 95.24% executed branches; 90.48% branches taken at least once. |
| Final ASM contract tests | `make test CONFIG=release USE_ASM=yes` | Pass: 5 / 5 binaries, including the post-fork child scenario. |
| Static analysis | `make lint` | Pass, exit status 0. Vendor/adapter `missingInclude` lines are informational include-path messages. |
| AddressSanitizer | `make test_sanitize SAN=address CONFIG=debug USE_ASM=yes` | Pass: 5 test binaries, 0 issues. |
| UndefinedBehaviorSanitizer | `make test_sanitize SAN=undefined CONFIG=debug USE_ASM=yes` | Pass: 5 test binaries, 0 issues. |
| Race detection | `make test_helgrind CONFIG=debug USE_ASM=yes` | Pass: MT test, 0 races. |
| ELF TLS inspection | `readelf -SW` and `readelf -rW build/bignum_random.o` | Pass: `.tbss` has TLS flag and local-exec `R_X86_64_TPOFF32` relocations. |
| Distribution | `make dist CONFIG=release USE_ASM=yes` | Pass: static library, single header, and distribution runner created successfully. |
| README example | Literal English README example with documented include/link flags | Compiles and exits successfully. |
| Protected files | `git diff --name-only` review | Pass: no `Makefile` or CI change. |
| Doxygen build | `Doxyfile` / `Doxyfile.in` discovery | N/A: no configuration exists; documented DOC-11 exception remains. |

## Per-artifact QG checklist

| Artifact | Applicable QG findings | Status |
|---|---|---|
| `include/bignum_random.h` | File/type/function Doxygen; named statuses; ownership; aliasing; output transaction; C11 stateless versus YASM TLS cache; fork/thread-safety; complexity. | PASS |
| `src/bignum_random.c` | File/static-function Doxygen; readable C11 `getrandom` reference; rejection sampling and transaction rationale. | PASS |
| `src/bignum_random.asm` | File/symbol boundary contract; System V registers, stack and syscall clobbers; `.tbss` representation; cache/PID fork invalidation; direct full-capacity path; error semantics and rationale comments. | PASS |
| `tests/test_bignum_random.c` | File/helper/test Doxygen; deterministic status, range, transaction, one-word, representative multiword, and fork-child oracle. | PASS |
| `tests/test_bignum_random_extra.c` | Property/fuzz input generation, 20,000-case range oracle and capacity boundary documentation. | PASS |
| `tests/test_bignum_random_mt.c` | Independent-thread setup, range/integrity oracle and worker lifecycle documentation. | PASS |
| `tests/test_bignum_random_runner.c` | Distribution integration contract and singleton oracle. | PASS |
| Benchmark adapter and ST/MT runners | Public vocabulary, fixture ownership, production-operation binding, checksum, CLI/status protocol. | PASS |
| JSON profiles and adjacent documents | Schema, vocabulary, profile tables, examples, run/modify/comparison/failure documentation. | PASS |
| `README.md` | English GNU/Open Source-style goal, platform, clone/submodule recovery, dependencies, API, complete example, build/test, benchmark, distribution, contribution, reporting, and license sections. | PASS |
| `docs/BENCHMARK_ANALYSIS_AND_ASM_OPTIMIZATION.md` | Versioned algorithm, cache lifecycle, final paired methodology, raw evidence paths, quality evidence, and reproducible commands. | PASS |
| `docs/QUALITY_GATES_DOCUMENTATION_C11_JSON.md` | Mandatory supplied QG remains versioned and referenced by current review material. | PASS |

## Final benchmark evidence

C11 and final hybrid ASM were run consecutively on the same CPU affinity (`0-1`) using the committed full profile matrix, 7 repetitions, 30,000 ST iterations, 60,000 total MT iterations, warm-up 2,000, data count 256, seed `0x9E3779B97F4A7C15`, and two workers. The host was an Intel Xeon Processor at 2.10 GHz with Linux kernel `6.18.38+`.

| Metric | Result |
|---|---:|
| Matched groups | 24 |
| Missing groups | 0 |
| Regression groups | 0 |
| ASM median delta | **−27.031%** |
| ASM mean delta | **−23.585%** |
| ASM ST median delta | **−26.265%** |
| ASM MT median delta | **−28.517%** |
| Median speed-up | **1.3705×** |
| Best observed group | `singleton-one-kernel` / MT: **1.720×** |

Generated raw evidence is retained under `benchmarks/reports/` with the `random_c11_hybrid_paired_*`, `random_asm_hybrid_paired_*`, and `hybrid_paired_delta_analysis.txt` names. The previous historical 23-regression comparison and intermediate TLS-only three-regression comparison are not final evidence; they were preserved only to explain why the final hybrid design dispatches full-capacity requests directly.

## Documented exception

**Artifact scope:** source/API documentation. **Gate:** DOC-11, generated Doxygen build. **Reason:** this repository has no `Doxyfile` or `Doxyfile.in`; adding one is outside the supplied template and protected build scope. **Risk:** automated Doxygen-warning detection is unavailable. **Mitigation:** source/header documentation was manually reviewed, all documented commands and the README example were executed, and every artifact is recorded in this checklist. **Removal condition:** add a reviewed Doxygen configuration and a warning-free documentation target without weakening existing CI or Makefile rules.

## Remaining limitations

The public API intentionally has no injectable entropy provider. Therefore a deterministic test cannot force kernel `EINTR` or a permanent `getrandom(2)` failure; those paths are structurally reviewed and retain the documented error semantics. The YASM cache is a Linux x86-64 ELF local-exec implementation detail. It improves repeated-call throughput but does not change uniformity, CSPRNG source, public ownership, or named status behavior.

## References

[1] [Linux `getrandom(2)` manual page](https://man7.org/linux/man-pages/man2/getrandom.2.html)
