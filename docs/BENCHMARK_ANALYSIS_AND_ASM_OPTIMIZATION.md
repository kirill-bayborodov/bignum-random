# ASM coverage и углублённый анализ производительности `bignum_random`

**Дата анализа:** 25 августа 2026 года.
**Реализация:** `src/bignum_random.asm`, Linux x86-64 System V AMD64, прямой `getrandom(2)` syscall.
**Ограничение:** `Makefile` и `.github/workflows/ci.yml` не изменялись.

## Исполнение и coverage ASM-версии

YASM не генерирует `.gcno/.gcda`, поэтому `gcov` не может корректно приписать line/branch coverage машинному коду ASM. Вместо ложного «процента gcov для ASM» использованы три дополняющих evidence: полный debug test suite, Callgrind instruction-level execution функции `bignum_random`, и статическая mapping сценариев на named return paths.

| Evidence | Команда | Результат |
|---|---|---|
| Debug ASM suite | `make test CONFIG=debug USE_ASM=yes` | **5 / 5 binaries passed**. |
| AddressSanitizer | `make test_sanitize SAN=address CONFIG=debug USE_ASM=yes` | **5 tests, 0 issues**. |
| UndefinedBehaviorSanitizer | `make test_sanitize SAN=undefined CONFIG=debug USE_ASM=yes` | **5 tests, 0 issues**. |
| Thread analysis | `make test_helgrind CONFIG=debug USE_ASM=yes` | MT test passed; **0 races**. |
| Instruction evidence | `valgrind --tool=callgrind --collect-jumps=yes --dump-instr=yes ./bin/test_bignum_random` | `bignum_random` executed; Callgrind recorded **161,957 instruction references** in the symbol during deterministic contract testing. |

| ASM path or invariant | Test evidence | Coverage classification |
|---|---|---|
| `BIGNUM_RANDOM_ERROR_NULL_ARG` | `test_invalid_arguments_preserve_output` passes `NULL` input and output paths. | Executed. |
| `BIGNUM_RANDOM_ERROR_ALIAS` | Same deterministic test passes equal pointers. | Executed. |
| `BIGNUM_RANDOM_ERROR_RANGE` | Same deterministic test passes `len == 0`. | Executed. |
| `BIGNUM_RANDOM_ERROR_LENGTH` | Same deterministic test passes `len > BIGNUM_CAPACITY`. | Executed. |
| `BIGNUM_RANDOM_ERROR_NORMALIZATION` | Same deterministic test uses a nonzero `len` with zero high word. | Executed. |
| Successful singleton and rejection loop | 64 `[0, 1)` samples plus range-3 sampling. Bound one makes rejection probabilistic at approximately one half per candidate; 64 invocations make execution of the retry edge overwhelmingly likely, but it is not a deterministic branch oracle. | Executed success; retry statistically exercised. |
| Multi-word comparison, normalization and publish | Representative `2^64 + 1`, 20,000 fuzz/property ranges and full-capacity boundary cases. | Executed. |
| Independent concurrency | Eight workers × 1,000 samples; Helgrind run. | Executed. |
| `EINTR` retry and terminal entropy failure | Linux kernel did not inject these outcomes; public API has no entropy-provider seam. | Not deterministically executable in the existing contract. |

> **Coverage conclusion.** The final ASM implementation has strong dynamic evidence for every validation status, normal acceptance, multiword comparison, normalization, publication, distribution linkage and MT behavior. The two kernel-dependent error branches remain structurally reviewed but require an explicit injectable entropy-provider test seam or controlled syscall fault injection to be made deterministic. Such a seam would be an API/design change, not a Makefile or CI change.

Raw execution evidence is retained under `benchmarks/reports/asm_test_execution.log`, `callgrind_asm_bignum_random.out` and `callgrind_asm_bignum_random.txt`.

## Почему первоначальный benchmark выглядел как 23 регрессии

Раннее сравнение использовало C11 baseline и ASM candidate, собранные в разных временных окнах. Эти artifacts показали 23 / 24 regression groups. Однако обе реализации вызывают kernel CSPRNG, а syscall latency, scheduler contention, page/cache state и CPU frequency существенно влияют на single-session nano-second measurements. Следовательно, такой cross-session comparison не отделяет code delta от drift среды.

Для проверки этого риска выполнена новая **paired matrix**: C11 и ASM запускались подряд, с тем же manifest SHA-256 `ff0bb64a2235f2221f8a42deea3d10683b7f89b6a5b865b6adaf7fdcdeaf259e`, CPU affinity `0-1`, пятью repetitions, 20,000 ST iterations, 40,000 total MT iterations, warm-up 1,000, data count 256, seed `0x9E3779B97F4A7C15` и двумя workers. Среда — Intel Xeon 2.10 GHz, kernel `6.18.38+`.

| Paired result | Значение |
|---|---:|
| Matched profile × mode groups | 24 |
| Missing groups | 0 |
| Benchmark-framework regression groups | 1 |
| Median delta по всем группам | **−3.927%** для ASM |
| Mean delta по всем группам | **−3.473%** для ASM |
| ST median delta | **−0.264%** для ASM |
| MT median delta | **−6.695%** для ASM |
| Единственная regression | `range-near-capacity-e2e` / MT: **+7.990%**, 921.985 ns/call против 853.770 ns/call, baseline MAD 0.946%. |

Таким образом, исходная формулировка о повсеместной 23-group regression является устаревшей для итогового кода и была следствием несопоставимых временных окон. Но один стабильный near-capacity MT regression остаётся. Следовательно, корректный вывод строже, чем «ASM быстрее»: **ASM в paired experiment ускоряет типичную MT workload, статистически сопоставим с C11 в ST и регрессирует в одном worst-case MT profile.** Автоматический regression gate всё ещё возвращает nonzero status, поэтому performance target не следует считать полностью закрытым.

## Причины наблюдаемого поведения

Для одного вызова C11 reference и ASM выполняют один `getrandom(2)` request размером до 256 bytes. Поэтому основная стоимость — kernel transition и CSPRNG extraction, а не only integer arithmetic. Малые односоставные bounds в paired matrix получают modest gain от прямого syscall path, который устраняет wrapper/errno work. При многопоточном near-capacity end-to-end profile каждый worker одновременно запрашивает максимальный объём, и процесс конкурирует за kernel RNG path; здесь выигрыш user-space инструкций маскируется contention.

ASM также сознательно очищает полный temporary `bignum_t`, нормализует candidate и публикует фиксированные 33 qwords. Эти операции сохраняют atomic output contract, но становятся заметнее, когда 256-byte entropy request и thread scheduling уже насыщают measured interval. C compiler при `-O2` использует эффективные `rep stosq`/`rep movsq` sequences и может одинаково хорошо размещать state; hand-written assembly не получает автоматического преимущества только от смены синтаксиса.

| Наблюдение | Техническая причина | Consequence |
|---|---|---|
| Cross-session result: 23 regressions | Несопоставимый system state между historical C11 и ASM runs. | Не годится как causal evidence. |
| Paired ST near parity | Syscall dominates; both paths execute equivalent rejection sampling. | Микро-оптимизации дают малый эффект. |
| Paired MT gain в большинстве групп | Прямой syscall path и code layout уменьшают часть userspace overhead. | Есть ограниченный потенциал. |
| Near-capacity MT regression | 256-byte request, full-record zero/copy, rejection/compare work и contention проявляются одновременно. | Основная цель оптимизации. |
| Data-dependent retry | Rejection sampling корректен, но runtime зависит от bound bit pattern. | Нельзя заменить на `% n` без modulo bias. |

## Конкретные ASM-оптимизации без изменений Makefile и CI

Следующие изменения допустимы в `src/bignum_random.asm`, `include/bignum_random.h`, tests и benchmark documents; они не требуют затрагивать CI или Makefile. Они расположены по ожидаемой пользе и risk.

| Приоритет | Изменение | Точный ASM-level подход | Expected effect | Correctness / review risk |
|---|---|---|---|---|
| 1 | Убрать повторный `cld` | Выполнить `cld` один раз после prologue; удалить повторные `cld` перед candidate clear и publish. System V ABI требует DF clear на entry/return, а syscall не устанавливает DF. | Небольшое, но free сокращение инструкций на every candidate. | Low; требуется ABI regression test. |
| 2 | Fast path для one-word bound | После validation branch на `len == 1`; использовать один 64-bit candidate, mask, compare и direct output store/zero tail без generic loops. | Существенно для `singleton` и `word` profiles, где paired gain уже виден. | Medium; нужны exact tests for 1, 2, 3, `UINT64_MAX`. |
| 3 | Fast path для full-capacity bound | После `len == BIGNUM_CAPACITY`, пропустить generic active-length arithmetic; fixed 256-byte request, fixed top-word access and `rep movsq` full record. | Адресует near-capacity profile; уменьшает loop/control overhead. | Medium; preserve output on entropy error and full normalization. |
| 4 | Условно пропускать no-op mask | Если highest word уже имеет 64-bit length, `top_mask == UINT64_MAX`; не выполнять memory load/AND/store top word. | Small but deterministic for bounds with high bit set. | Low. |
| 5 | Publish by normalized length | Вместо zeroing full temporary record на каждой attempt: заполнить active words, normalize; on success copy active prefix and clear only output tail. Use `rep movsq` plus `rep stosq` with exact counts. | Может сократить stores for short bounds. | Medium/high; must preserve zero inactive words after every success and be benchmarked independently. |
| 6 | Отделить expected full-read syscall fast path | После syscall compare `rax` with requested byte count; перейти directly to mask/compare when equal, retaining loop only for short-read/EINTR. | Small for Linux requests <=256 bytes. | Low; preserves mandatory return-value checks.[1] |
| 7 | Вернуть cached entropy только через explicit context API | Добавить отдельный caller-owned `bignum_random_context_t`, который batch-refills `getrandom` bytes; legacy function remains stateless and direct. | Largest possible throughput gain; reduces syscalls. | High: requires lifecycle, fork/zeroization/thread ownership and cryptographic review. |

The first six options preserve the public one-shot function and can be implemented incrementally, each with a paired matrix against the unchanged profile set. The context design must not be silently inserted as process-global mutable state: doing so would violate current reentrancy and testability contract.

## Recommended optimisation sequence

First implement priorities 1, 2 and 4 as one reviewable micro-optimisation change, run all ASM tests and a paired full matrix. Next implement the fixed full-capacity fast path, because it directly targets the only measured regression. Only after both results are stable should prefix/tail publication be attempted. If the one remaining MT regression persists, accept that it is kernel-contended and move high-throughput use cases to an explicit context API rather than weakening the current one-shot cryptographic contract.

## Reproducibility commands

```bash
make clean
make test CONFIG=debug USE_ASM=yes
valgrind --tool=callgrind --collect-jumps=yes --dump-instr=yes \
  --callgrind-out-file=benchmarks/reports/callgrind_asm_bignum_random.out \
  ./bin/test_bignum_random

make clean
taskset --cpu-list 0-1 make bench_matrix USE_ASM=no \
  REPORT_NAME=random_c11_paired \
  BENCH_MATRIX_PROFILE=benchmarks/profiles/bignum_random_full.json \
  BENCH_MATRIX_REPETITIONS=5 \
  BENCH_MATRIX_ITERATIONS=20000 \
  BENCH_MATRIX_MT_TOTAL_ITERATIONS=40000 \
  BENCH_MATRIX_WARMUP=1000 \
  BENCH_MATRIX_DATA_COUNT=256 \
  BENCH_MATRIX_SEED=0x9E3779B97F4A7C15 \
  MT_THREADS=2

make clean
taskset --cpu-list 0-1 make bench_matrix USE_ASM=yes \
  REPORT_NAME=random_asm_paired \
  BENCH_MATRIX_PROFILE=benchmarks/profiles/bignum_random_full.json \
  BENCH_MATRIX_REPETITIONS=5 \
  BENCH_MATRIX_ITERATIONS=20000 \
  BENCH_MATRIX_MT_TOTAL_ITERATIONS=40000 \
  BENCH_MATRIX_WARMUP=1000 \
  BENCH_MATRIX_DATA_COUNT=256 \
  BENCH_MATRIX_SEED=0x9E3779B97F4A7C15 \
  MT_THREADS=2 \
  BENCH_BASELINE=benchmarks/reports/random_c11_paired_matrix.json \
  BENCH_REGRESSION_THRESHOLD_PCT=5
```

## References

[1] [Linux `getrandom(2)` manual page](https://man7.org/linux/man-pages/man2/getrandom.2.html)
