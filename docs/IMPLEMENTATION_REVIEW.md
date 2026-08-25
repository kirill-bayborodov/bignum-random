# Итоговый review реализации `bignum_random`

**Проверенная редакция:** рабочее дерево `bignum-random` от 25 августа 2026 года.
**Область review:** публичный API, C11 reference, YASM implementation, tests, adapter, JSON profiles, README, distribution и запрещённые build/CI-файлы.

## Итог

Реализация функционально завершена: `bignum_random` выдаёт нормализованный криптографически случайный `bignum_t` из `[0, upper_bound)`, использует Linux `getrandom(2)` и rejection sampling без modulo bias. Ошибки являются именованными и транзакционными: `out` изменяется только после принятия candidate. `getrandom(2)` предназначен для криптографических random bytes, а корректный пользователь обязан проверять return value и short reads.[1]

Все final correctness, sanitizer, Helgrind, lint и distribution gates проходят. **Performance objective не прошёл:** final YASM variant не превзошёл C11 baseline на reviewed full matrix. Это не скрыто и не считается successful performance claim; подробности приведены в разделе «Benchmark evidence».

## Review-проверки

| Проверка | Команда или evidence | Результат |
|---|---|---|
| C11 contract tests | `make test CONFIG=release USE_ASM=no` | PASS: 5 / 5 binaries. |
| C11 coverage | `gcov -b -c` после всех C11 tests | 100.00% line, 95.24% executed branch, 90.48% branches taken at least once. |
| Final ASM contract tests | `make test CONFIG=release USE_ASM=yes` | PASS: 5 / 5 binaries. |
| AddressSanitizer | `make test_sanitize SAN=address CONFIG=debug USE_ASM=yes` | PASS: 5 tests, 0 sanitizer issues. |
| UndefinedBehaviorSanitizer | `make test_sanitize SAN=undefined CONFIG=debug USE_ASM=yes` | PASS: 5 tests, 0 sanitizer issues. |
| Race detection | `make test_helgrind CONFIG=debug USE_ASM=yes` | PASS: MT test, 0 races. |
| Static analysis | `make lint` | PASS, exit status 0. Cppcheck emits informational `missingInclude` messages for Makefile include paths and vendor sources only. |
| Distribution | `make dist CONFIG=release USE_ASM=yes` | PASS: archive, single header and distribution runner created successfully. |
| README example | Компиляция и запуск literal example из README с documented include/link flags | PASS: example compiled and exited successfully. |
| Doxygen build | Поиск `Doxyfile` / `Doxyfile.in` до depth 3 | N/A: в repository нет Doxygen configuration; source Doxygen reviewed manually. |
| Whitespace | `git diff --check` | PASS: no errors. |
| Protected files | `git diff --name-only` for `Makefile` and `.github/workflows/ci.yml` | PASS: neither file changed. |
| Template cleanup | active-code grep for `bignum_template` | PASS: no stale references. |

The unexecuted C11 branch lines are the OS-dependent `getrandom(2)` error paths: interruption with `EINTR` and a permanent entropy failure. The public contract and ASM counterpart cover those paths, but deterministic forcing would require an entropy-source test seam that does not exist in the fixed API.

## Per-artifact checklist

| Artifact | Review of contract, documentation and safety | Status |
|---|---|---|
| `include/bignum_random.h` | Doxygen API, exact half-open range, named statuses, alias rule, ownership, normalization, complexity and thread-safety documented. | PASS |
| `src/bignum_random.c` | C11 reference validates before entropy, loops on short/EINTR reads, masks high bits, rejects `candidate >= n`, commits one accepted stack record. | PASS |
| `src/bignum_random.asm` | System V AMD64 callee-saved registers preserved; direct syscall clobbers respected; no C calls; output commit occurs only after acceptance; `.note.GNU-stack` supplied. | PASS for correctness; see performance finding. |
| `tests/test_bignum_random.c` | Deterministic null, alias, range, length, normalization, singleton, range and input-preservation scenarios. | PASS |
| `tests/test_bignum_random_extra.c` | 20,000 deterministic fuzz/property bounds plus one/two/full-capacity boundaries. | PASS |
| `tests/test_bignum_random_mt.c` | Eight independent pthread workers, 1,000 operations each, range and input-preservation oracle. | PASS |
| `tests/test_bignum_random_runner.c` | Distribution object/archive smoke test for deterministic `[0,1)` result. | PASS |
| `tests/benchmark_adapter/test_bignum_random_benchmark_adapter.c` | Adapter vocabulary, binding, callback lifecycle and production operation tests. | PASS |
| `benchmarks/adapter/bignum_random_benchmark_adapter.h` | Public adapter vocabulary/status contract documented. | PASS |
| `benchmarks/adapter/bignum_random_benchmark_adapter.c` | Deterministic positive upper-bound fixtures; actual measured operation calls production API; checksum observes output. | PASS |
| `benchmarks/bench_bignum_random.c` | Thin ST benchmark-core binding with stable process status mapping. | PASS |
| `benchmarks/bench_bignum_random_mt.c` | Thin MT benchmark-core binding without project-global state. | PASS |
| `benchmarks/profiles/bignum_random_standard.json` | Valid schema-1 smoke matrix; all profile tokens accepted by adapter. | PASS |
| `benchmarks/profiles/bignum_random_full.json` | Valid schema-1 full C11/ASM comparison matrix with stable profile identifiers. | PASS |
| Companion profile documents | Both JSON files have schema, vocabulary, profile table, complete JSON, run/modify, baseline/comparison and failure sections. | PASS |
| `README.md` | API, platform boundary, build, test, distribution and benchmark instructions synchronized with final source. | PASS |
| `docs/QUALITY_GATES_DOCUMENTATION_C11_JSON.md` | User-supplied mandatory quality-gate document stored as versioned repository artifact. | PASS |

The deleted `bignum_template` header, source, tests, adapter, runners and profile documents were reviewed as stale template artifacts. Each was replaced by the corresponding `bignum_random` artifact shown above; no active source retains the template identifier.

## Benchmark evidence

The C11 baseline was gathered with `USE_ASM=no`, the full profile manifest, five repetitions, 20,000 ST calls, 40,000 MT total calls, 1,000 warm-up calls, data count 256, seed `0x9E3779B97F4A7C15`, two pinned CPUs and two MT workers. It contains 120 raw samples at:

```text
benchmarks/reports/random_c11_baseline_matrix.json
```

The initial direct-syscall ASM comparison was run in a different time window and reported **23 regression groups** above its 5% threshold and C11 MAD noise floor. Those artifacts remain retained as historical evidence:

```text
benchmarks/reports/random_asm_reworked_matrix.json
benchmarks/reports/random_asm_reworked_matrix_summary.json
```

A subsequent paired matrix ran C11 and ASM consecutively under identical workload and affinity. It matched all 24 profile × mode groups, showed a median **−3.927%** ASM delta, and retained one `range-near-capacity-e2e` MT regression of **+7.990%**. The gate therefore still returns nonzero and the implementation is accepted for correctness, but it cannot claim complete non-regression. Full methodology, assembly coverage evidence, group-level deltas and compatible optimizations are in [`BENCHMARK_ANALYSIS_AND_ASM_OPTIMIZATION.md`](BENCHMARK_ANALYSIS_AND_ASM_OPTIMIZATION.md).

| Benchmark gate | Result | Interpretation |
|---|---|---|
| Profile-set compatibility | PASS | `missing_profiles = 0`. |
| Raw matrix protocol | PASS | ST/MT runners emitted parseable completion protocol and 120 samples. |
| C11 baseline availability | PASS | Reviewed raw artifact and statistical summary exist. |
| Historical ASM non-regression gate | FAIL | 23 groups are slower; the runs occurred in different time windows. |
| Fresh paired ASM non-regression gate | FAIL | 1 / 24 groups is slower beyond threshold and paired baseline noise floor. |
| Claim of universally faster ASM | BLOCKED | Paired median is favourable, but one profile remains a confirmed regression. |

## Documented exception

**Artifact scope:** all documented source files. **Gate:** DOC-11 / generated Doxygen build. **Reason:** repository contains no `Doxyfile` or `Doxyfile.in`, therefore a reproducible Doxygen command cannot be executed without introducing a new build configuration outside the supplied template. **Risk:** automated Doxygen-warning detection is unavailable. **Mitigation:** public/internal comments were reviewed manually, the README example compiled unchanged, and all repository-provided build/test gates pass. **Removal condition:** add and review a project Doxygen configuration, then execute it warning-free in CI or an explicit documentation target.

## Required follow-up for performance work

A real speed-up needs a reviewed API-level batching design rather than a micro-optimization around one `getrandom(2)` call per public sample. A possible proposal is an explicit caller-owned `bignum_random_context_t` that refills bounded kernel entropy in batches and is never shared across threads. Such a change must define fork behavior, zeroization, state ownership, cache exhaustion, test injection and cryptographic review. It would modify the public API and implementation, but does **not** require changes to the protected `Makefile` or CI workflow. Until that design is approved, the current direct-syscall YASM implementation remains the correct functional implementation.

## References

[1] [Linux `getrandom(2)` manual page](https://man7.org/linux/man-pages/man2/getrandom.2.html)
