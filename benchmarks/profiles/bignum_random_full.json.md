# Полная benchmark-матрица `bignum_random`

## Назначение

`bignum_random_full.json` является reviewed source manifest для сравнительных C11/ASM измерений `bignum_random`. Его потребляет C11 executable `bench_matrix` из `libs/benchmark-framework/dist/tools/`. Набор разделяет цену singleton, однословного, многословного, variable/mixed и near-capacity диапазонов, а также различает `kernel-only` и `end-to-end` scope. Каждый measured callback получает свежую криптографическую энтропию; фиксированный seed управляет только construction верхних границ.

## Расположение и жизненный цикл

Это versioned исходный JSON в `benchmarks/profiles/`. Изменения принадлежат bignum-random adapter-у, а не benchmark-framework. Raw samples и statistical summary создаются под `benchmarks/reports/`; они не заменяют manifest и не должны коммититься как approved baseline без отдельного review. Полный manifest совместим с standard manifest только по общему vocabulary, но baseline group sets между ними не взаимозаменяемы.

## Schema

| Поле | Тип | Обязательное | Правило версии 1 |
|---|---:|---:|---|
| `schema_version` | integer | Да | Ровно `1`; другие значения unsupported. |
| `description` | string | Да | Описывает operation and coverage axes. |
| `profiles` | array | Да | Непустой список уникальных objects. |
| `profiles[].id` | string | Да | Уникальный stable key для statistics group. |
| `profiles[].input_kind` | string | Да | Одно из значений domain vocabulary. |
| `profiles[].operation_kind` | string | Да | Одно из значений range-operation vocabulary. |
| `profiles[].measure_mode` | string | Да | `kernel-only` или `end-to-end`. |
| `profiles[].size_profile` | string | Да | Определяет word length positive upper bound. |
| `profiles[].capacity_profile` | string | Да | `normal` либо `near-capacity`. |

Schema version 1 не обещает forward compatibility для неизвестных fields или values. Добавление обязательного поля либо semantic reinterpretation существующего поля требует новой schema version, обновления adapter validation, обоих companion documents и новой reviewed baseline.

## Vocabulary

| Ось | Значения | Значение для `bignum_random` |
|---|---|---|
| `input_kind` | `zero`, `nonzero`, `mixed` | `zero` создаёт valid bound one, `nonzero` — deterministic positive profile-sized bound, `mixed` — чередование этих безопасных bounds. |
| `operation_kind` | `random-one`, `random-word`, `random-range`, `random-mixed` | Классифицирует форму `[0, n)`; не заменяет вызов системного CSPRNG псевдослучайным fixture generator-ом. |
| `measure_mode` | `kernel-only`, `end-to-end` | Первый исключает copy input state, второй включает; `getrandom(2)` входит в measure scope обоих. |
| `size_profile` | `one`, `quarter`, `half`, `variable`, `near-capacity` | Выбирает 1, 8, 16, deterministic variable или 32 active 64-bit words. |
| `capacity_profile` | `normal`, `near-capacity` | `near-capacity` задаёт 32-word valid upper bound и не измеряет malformed record. |

## Profile table

| Identifier | Scenario | Input | Operation | Measure | Size / capacity |
|---|---|---|---|---|---|
| `singleton-one-kernel` | Singleton baseline | singleton 1 | random-one | kernel | one / normal |
| `singleton-one-e2e` | Singleton full lifecycle | singleton 1 | random-one | end-to-end | one / normal |
| `word-one-kernel` | 64-bit range | nonzero | random-word | kernel | one / normal |
| `word-one-e2e` | 64-bit full lifecycle | nonzero | random-word | end-to-end | one / normal |
| `range-quarter-kernel` | 512-bit range | nonzero | random-range | kernel | quarter / normal |
| `range-half-kernel` | 1024-bit range | nonzero | random-range | kernel | half / normal |
| `range-half-e2e` | 1024-bit full lifecycle | nonzero | random-range | end-to-end | half / normal |
| `range-variable-kernel` | Seed-derived length | nonzero | random-range | kernel | variable / normal |
| `mixed-variable-kernel` | Alternating singleton/range | mixed | random-mixed | kernel | variable / normal |
| `mixed-variable-e2e` | Alternating full lifecycle | mixed | random-mixed | end-to-end | variable / normal |
| `range-near-capacity-kernel` | 2048-bit boundary | nonzero | random-range | kernel | near-capacity / near-capacity |
| `range-near-capacity-e2e` | 2048-bit full lifecycle | nonzero | random-range | end-to-end | near-capacity / near-capacity |

## Complete example

```json
{
  "schema_version": 1,
  "description": "A valid near-capacity bignum_random profile",
  "profiles": [
    {
      "id": "range-near-capacity-kernel",
      "input_kind": "nonzero",
      "operation_kind": "random-range",
      "measure_mode": "kernel-only",
      "size_profile": "near-capacity",
      "capacity_profile": "near-capacity"
    }
  ]
}
```

## How to run

Сначала получите C11 baseline с неизменённым compiler configuration и зафиксированными параметрами. Для exploratory smoke допускаются малые iteration counts; production conclusion требует reviewed workload с достаточным числом repetitions.

```bash
make bench_matrix CONFIG=release USE_ASM=no \
  REPORT_NAME=random_c11_baseline \
  BENCH_MATRIX_PROFILE=benchmarks/profiles/bignum_random_full.json \
  BENCH_MATRIX_REPETITIONS=7 \
  BENCH_MATRIX_ITERATIONS=200000 \
  BENCH_MATRIX_MT_TOTAL_ITERATIONS=400000 \
  BENCH_MATRIX_WARMUP=10000 \
  BENCH_MATRIX_DATA_COUNT=4096 \
  BENCH_MATRIX_SEED=0x9E3779B97F4A7C15 \
  MT_THREADS=2
```

Команда создаёт `benchmarks/reports/random_c11_baseline_matrix.json` и `benchmarks/reports/random_c11_baseline_matrix_summary.json`. C11 matrix tool сохраняет command, stdout, exit status, host metadata, manifest hash and parsed `ns_per_call`; output values не являются reproducible и не используются как baseline oracle.

## How to modify

Добавляйте profile только с unique stable `id`, vocabulary из таблицы и одной понятной scenario axis. Затем обновите эту таблицу, standard manifest если scenario должен входить в smoke coverage, оба companion documents и adapter unit tests при расширении vocabulary. Выполните JSON parse current `bench_matrix`, short ST/MT matrix и review group-set impact. Не меняйте существующий `id` для другой semantics: baseline comparison трактует его как ту же группу.

## Baseline and comparison

ASM candidate сравнивается исключительно с reviewed C11 artifact при совпадающих full manifest hash, profile identifiers, compiler, `CONFIG=release`, CPU affinity, seed, warm-up, data count, threads, total work и repetitions. Запустите candidate через тот же manifest и передайте C11 raw matrix как explicit baseline:

```bash
make bench_matrix CONFIG=release USE_ASM=yes \
  REPORT_NAME=random_asm_candidate \
  BENCH_MATRIX_PROFILE=benchmarks/profiles/bignum_random_full.json \
  BENCH_MATRIX_REPETITIONS=7 \
  BENCH_MATRIX_ITERATIONS=200000 \
  BENCH_MATRIX_MT_TOTAL_ITERATIONS=400000 \
  BENCH_MATRIX_WARMUP=10000 \
  BENCH_MATRIX_DATA_COUNT=4096 \
  BENCH_MATRIX_SEED=0x9E3779B97F4A7C15 \
  MT_THREADS=2 \
  BENCH_BASELINE=benchmarks/reports/random_c11_baseline_matrix.json \
  BENCH_REGRESSION_THRESHOLD_PCT=5
```

Regression gate rejects missing or extra profile groups and rejects a candidate only when its median exceeds both the percentage threshold and C11 baseline MAD noise floor. Because syscall and scheduler latency vary, report medians, dispersion and environment rather than interpreting one run as a stable cryptographic-performance claim.

## Failure handling

A malformed JSON document, unknown schema, missing required field, duplicate profile id or wrong JSON type causes the C11 matrix tool to return nonzero. A profile whose vocabulary passes JSON syntax but fails adapter validation terminates the corresponding invocation nonzero. A random-generation entropy error appears as an adapter operation error. `MT total iterations` not divisible by worker count is rejected before workers start. An absent or incompatible baseline group set produces a failed statistics comparison rather than silently ignoring a profile.
