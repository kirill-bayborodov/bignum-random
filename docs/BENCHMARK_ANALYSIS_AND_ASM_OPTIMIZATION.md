# Hybrid ASM Optimization and Quality Report for `bignum_random`

**Review date:** 25 August 2026.
**Reviewed implementation:** `src/bignum_random.asm`, Linux x86-64 System V AMD64.
**Protected files:** neither `Makefile` nor `.github/workflows/ci.yml` was changed.

## Executive conclusion

The production assembly implementation now materially outperforms the C11 reference on the controlled paired full matrix while passing the benchmark regression gate. The final design retains rejection sampling and Linux `getrandom(2)` as the cryptographic entropy source. It uses a private ELF thread-local raw-entropy cache for short and medium ranges, and it bypasses that cache for full-capacity 256-byte requests where batching cannot amortize a syscall.

The final controlled comparison contains 24 matched profile × mode groups, has **zero regressions**, a **27.031% median reduction in nanoseconds per call**, and a **1.3705× median speed-up** for the YASM implementation. The strongest groups are one-word ranges, where cache amortization yields up to **1.720×** speed-up. Every result is tied to a specific workload, host, configuration, repetition count, and statistical comparison; it is not a universal hardware claim.

## Final algorithm and security boundary

The public API remains `bignum_random(out, upper_bound)` and keeps its existing named-status, half-open range, rejection-sampling, and transactional-output contract. The C11 reference is intentionally stateless and requests entropy for every candidate. The YASM path uses the following policy.

| Bound active-word span | Entropy path | Rationale |
|---|---|---|
| 1 to 31 words | Private 32-word ELF TLS cache | A `getrandom(2)` refill is amortized across later calls in the same thread. |
| 32 words | Direct `getrandom(2)` fill | The request consumes one complete cache refill, so cache bookkeeping cannot amortize the syscall. |
| Child after `fork()` | Cache is discarded before use | The assembly compares `getpid` to the cache owner PID on every cache-eligible call; a changed PID forces a fresh kernel refill. |

Each cache is in an ELF `.tbss` section with the TLS flag and uses local-exec `R_X86_64_TPOFF32` relocations. Every pthread therefore has separate cache words, index, available count, and cached PID; there is no process-global mutable cache or lock. ELF TLS provides distinct storage for each thread, and x86-64 local-exec accesses storage relative to `%fs` with a link-time thread-pointer offset.[2]

The cache holds only raw bytes returned by `getrandom(2)`. It does not derive entropy, reduce modulo the bound, retain caller pointers, or publish candidate state before acceptance. Linux `getrandom(2)` return values remain checked for short reads and `EINTR`; permanent failure returns `BIGNUM_RANDOM_ERROR_ENTROPY` without changing `out`.[1]

## Implemented assembly optimizations

| Change | Implementation | Correctness invariant |
|---|---|---|
| Single direction-flag clear | `cld` executes once after the System V prologue; no path sets DF. | DF is clear on every normal return. |
| One-word candidate path | Avoids generic temporary initialization; commits a fully cleared caller record only after an accepted word. | Inactive tail is zero and output remains transactional. |
| Full-capacity path | Writes all 32 candidate words directly from `getrandom(2)` and skips cache bookkeeping. | Every candidate word is overwritten; `len` is written only after acceptance. |
| TLS batching | Caches 32 raw words only in current-thread `.tbss`; refills through robust `getrandom` loop. | No shared state; fork PID mismatch discards inherited cache. |
| Direct full-range entropy loop | Handles short reads and `EINTR` without the PID/TLS checks that harmed 256-byte profiles. | Same named entropy-failure semantics as C11. |
| One-word publish | Clears the full output record then stores accepted word and normalized length directly. | Zero sample has `len == 0`; nonzero sample has `len == 1`. |

The first TLS-cache experiment improved short ranges but regressed all full-capacity groups because it paid `getpid`, cache-state, and word-consumption overhead for a request that consumed a complete cache. The final hybrid dispatch removes that waste. This evidence is why the final design selects entropy path by active-word span instead of applying one cache policy to every request.

## Final paired benchmark evidence

The final baseline and candidate were executed consecutively under CPU affinity `0-1` on an Intel Xeon Processor at 2.10 GHz running Linux kernel `6.18.38+`. Both used the committed full manifest, 7 repetitions, 30,000 single-thread iterations, 60,000 total multithread iterations, 2,000 warm-up calls, data count 256, fixed seed `0x9E3779B97F4A7C15`, and two workers. The baseline uses `USE_ASM=no`; the candidate uses `USE_ASM=yes`.

| Final paired aggregate | Result |
|---|---:|
| Matched profile × mode groups | 24 |
| Missing profile groups | 0 |
| Regression groups at 5% threshold and MAD floor | 0 |
| Median ASM delta | **−27.031%** |
| Mean ASM delta | **−23.585%** |
| ST median ASM delta | **−26.265%** |
| MT median ASM delta | **−28.517%** |
| Median speed-up | **1.3705×** |

| Representative profile | C11 median ns/call | ASM median ns/call | ASM delta | Speed-up |
|---|---:|---:|---:|---:|
| `singleton-one-kernel` / MT | 509.886 | 296.529 | −41.844% | 1.720× |
| `word-one-e2e` / MT | 450.640 | 272.486 | −39.534% | 1.654× |
| `word-one-kernel` / ST | 743.698 | 520.766 | −29.976% | 1.428× |
| `mixed-variable-e2e` / ST | 1,104.167 | 815.820 | −26.114% | 1.353× |
| `range-half-kernel` / MT | 658.031 | 545.617 | −17.083% | 1.206× |
| `range-near-capacity-e2e` / ST | 1,659.844 | 1,636.037 | −1.434% | 1.015× |

The raw final evidence is retained in these ignored generated artifacts:

```text
benchmarks/reports/random_c11_hybrid_paired_matrix.json
benchmarks/reports/random_c11_hybrid_paired_matrix_summary.json
benchmarks/reports/random_asm_hybrid_paired_matrix.json
benchmarks/reports/random_asm_hybrid_paired_matrix_summary.json
benchmarks/reports/hybrid_paired_delta_analysis.txt
```

The older cross-session comparison that showed 23 regressions is retained for traceability only. It is not performance evidence for the final implementation because baseline and candidate did not run in the same controlled window. The final paired run is the authoritative conclusion.

## ASM coverage and quality evidence

YASM does not create `.gcno` or `.gcda` files, so `gcov` cannot provide a meaningful assembly line percentage. The assembly path is reviewed with executable contract tests, sanitizer instrumentation of C callers, race detection, ELF inspection, and instruction-level Callgrind evidence instead.

| Evidence | Scope | Result |
|---|---|---|
| `make test CONFIG=release USE_ASM=yes` | Five test binaries: contract, property/fuzz, MT, distribution, adapter | Passes with `0 / 5 failed`. |
| Deterministic fork scenario | Parent warms cache; child samples after `fork()` and parent checks child exit/result contract | Passes. |
| AddressSanitizer | All five ASM-selected test binaries | No issues. |
| UndefinedBehaviorSanitizer | All five ASM-selected test binaries | No issues. |
| Helgrind | Eight-worker independent-object test | No races. |
| `readelf` inspection | `.tbss` section and TLS relocations | `.tbss` is `NOBITS` with `WAT` flags; local-exec `R_X86_64_TPOFF32` relocations are present. |
| Callgrind | Deterministic assembly API execution | Instruction-level execution is recorded; source-line gcov attribution is unavailable by design. |

The validation status paths, accepted one-word path, multiword comparison, normalization, fixed-capacity path, distribution linkage, independent threads, and child post-fork API call are dynamically exercised. Kernel-injected `EINTR` and permanent `getrandom` failure remain structurally reviewed but are not deterministically injectable through the fixed public API. Introducing such an injection seam would be a separately reviewed API/testing design, not a Makefile or CI change.

## Reproducibility commands

```bash
make clean
make test CONFIG=release USE_ASM=yes
make lint

make clean
make test_sanitize SAN=address CONFIG=debug USE_ASM=yes
make clean
make test_sanitize SAN=undefined CONFIG=debug USE_ASM=yes
make clean
make test_helgrind CONFIG=debug USE_ASM=yes

make clean
taskset --cpu-list 0-1 make bench_matrix USE_ASM=no \
  REPORT_NAME=random_c11_hybrid_paired \
  BENCH_MATRIX_PROFILE=benchmarks/profiles/bignum_random_full.json \
  BENCH_MATRIX_REPETITIONS=7 \
  BENCH_MATRIX_ITERATIONS=30000 \
  BENCH_MATRIX_MT_TOTAL_ITERATIONS=60000 \
  BENCH_MATRIX_WARMUP=2000 \
  BENCH_MATRIX_DATA_COUNT=256 \
  BENCH_MATRIX_SEED=0x9E3779B97F4A7C15 \
  MT_THREADS=2

make clean
taskset --cpu-list 0-1 make bench_matrix USE_ASM=yes \
  REPORT_NAME=random_asm_hybrid_paired \
  BENCH_MATRIX_PROFILE=benchmarks/profiles/bignum_random_full.json \
  BENCH_MATRIX_REPETITIONS=7 \
  BENCH_MATRIX_ITERATIONS=30000 \
  BENCH_MATRIX_MT_TOTAL_ITERATIONS=60000 \
  BENCH_MATRIX_WARMUP=2000 \
  BENCH_MATRIX_DATA_COUNT=256 \
  BENCH_MATRIX_SEED=0x9E3779B97F4A7C15 \
  MT_THREADS=2 \
  BENCH_BASELINE=benchmarks/reports/random_c11_hybrid_paired_matrix.json \
  BENCH_REGRESSION_THRESHOLD_PCT=5
```

## QG status and remaining limits

The final review maps the header, C reference, YASM source, tests, benchmark adapter, profile JSON, companion documents, README, and review reports to the artifact-level checklist in [`QUALITY_GATES_DOCUMENTATION_C11_JSON.md`](QUALITY_GATES_DOCUMENTATION_C11_JSON.md). The public contract, C/ASM boundary, cache ownership, fork behavior, benchmark protocol, and generated-evidence lifecycle are documented next to their artifacts.

No Doxygen configuration exists in this repository, so no documentation-generation command is available. This remains the documented DOC-11 exception: source comments and all executable README commands are reviewed manually. The cache design intentionally changes the YASM internal entropy-retention behavior; the public signature and output/status contract are unchanged.

## References

[1] [Linux `getrandom(2)` manual page](https://man7.org/linux/man-pages/man2/getrandom.2.html)

[2] [MaskRay, “All about thread-local storage”](https://maskray.me/blog/2021-02-14-all-about-thread-local-storage)
