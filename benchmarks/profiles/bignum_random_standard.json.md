# Стандартная benchmark-матрица `bignum_random`

## Назначение

`bignum_random_standard.json` — короткий versioned manifest для C11-инструмента `bench_matrix`, распространяемого в `libs/benchmark-framework/dist/tools/`. Он проверяет рабочие сценарии генерации случайного `bignum_t` в полуинтервале `[0, n)`: singleton-диапазон, односоставное слово, обычный многословный диапазон, mixed fixture и допустимую границу capacity. Manifest не измеряет ошибочные входы, потому что benchmark должен выполнять только успешную production-операцию.

## Расположение и жизненный цикл

Файл является исходной конфигурацией, редактируемой вместе с adapter-ом `benchmarks/adapter/bignum_random_benchmark_adapter.c`. Он не генерируется и не должен заменяться результатом benchmark. Сопутствующие `*_matrix.json` и `*_matrix_summary.json` создаются в `benchmarks/reports/`, игнорируются Git и не изменяют этот manifest.

## Schema

| Поле | Тип | Обязательное | Смысл |
|---|---:|---:|---|
| `schema_version` | integer | Да | Поддерживается только значение `1`. |
| `description` | string | Да | Человеко-читаемое назначение набора. |
| `profiles` | array | Да | Непустой список независимых workload profiles. |
| `profiles[].id` | string | Да | Стабильный уникальный identifier для baseline comparison. |
| `profiles[].input_kind` | string | Да | Форма детерминированного верхнего предела. |
| `profiles[].operation_kind` | string | Да | Транспортная категория диапазона random-операции. |
| `profiles[].measure_mode` | string | Да | `kernel-only` или `end-to-end`. |
| `profiles[].size_profile` | string | Да | Число слов upper bound. |
| `profiles[].capacity_profile` | string | Да | Обычная или near-capacity граница. |

Добавление поля с изменением schema требует нового `schema_version`, обновления adapter-а, обоих companion documents и проверки текущим C11 consumer. Неизвестная версия schema завершает matrix tool с ошибкой CLI/JSON и не создаёт корректный summary.

## Vocabulary

| Ось | Допустимые значения | Семантика adapter-а |
|---|---|---|
| `input_kind` | `zero`, `nonzero`, `mixed` | `zero` обозначает **singleton bound 1**, а не недопустимый zero bound; `mixed` чередует singleton и nonzero bounds. |
| `operation_kind` | `random-one`, `random-word`, `random-range`, `random-mixed` | Выбирает singleton, однословный, profile-sized либо чередующийся диапазон. Каждый callback вызывает production `bignum_random`. |
| `measure_mode` | `kernel-only`, `end-to-end` | Первый исключает подготовительную copy state, второй включает её в elapsed interval. Энтропия входит в оба режима. |
| `size_profile` | `one`, `quarter`, `half`, `variable`, `near-capacity` | Длина positive upper bound в 64-bit words. |
| `capacity_profile` | `normal`, `near-capacity` | `near-capacity` принудительно создаёт длину `BIGNUM_CAPACITY`; это valid success path. |

## Profile table

| Identifier | Scenario | Input | Operation | Measure | Size / capacity |
|---|---|---|---|---|---|
| `singleton-one-kernel` | Минимальный непустой диапазон | singleton 1 | `random-one` | kernel | one / normal |
| `word-one-kernel` | 64-bit upper bound | nonzero | `random-word` | kernel | one / normal |
| `range-half-e2e` | Обычный многословный диапазон | nonzero | `random-range` | end-to-end | half / normal |
| `mixed-variable-kernel` | Переменное чередование bounds | mixed | `random-mixed` | kernel | variable / normal |
| `range-near-capacity-kernel` | 2048-bit boundary range | nonzero | `random-range` | kernel | near-capacity / near-capacity |

## Complete example

```json
{
  "schema_version": 1,
  "description": "One valid bignum_random profile",
  "profiles": [
    {
      "id": "word-one-kernel",
      "input_kind": "nonzero",
      "operation_kind": "random-word",
      "measure_mode": "kernel-only",
      "size_profile": "one",
      "capacity_profile": "normal"
    }
  ]
}
```

## How to run

Запустите короткий воспроизводимый smoke matrix из корня проекта. Значения workload фиксируют количество вызовов и topology; random output не фиксируется, но raw artifact сохраняет протокол и host metadata.

```bash
make bench_matrix CONFIG=release \
  REPORT_NAME=random_c11_standard \
  BENCH_MATRIX_PROFILE=benchmarks/profiles/bignum_random_standard.json \
  BENCH_MATRIX_REPETITIONS=1 \
  BENCH_MATRIX_ITERATIONS=1000 \
  BENCH_MATRIX_MT_TOTAL_ITERATIONS=2000 \
  BENCH_MATRIX_WARMUP=10 \
  BENCH_MATRIX_DATA_COUNT=32 \
  MT_THREADS=2
```

Ожидаются `benchmarks/reports/random_c11_standard_matrix.json` и `benchmarks/reports/random_c11_standard_matrix_summary.json`. Каждый successful sample содержит строку `benchmark=...` непосредственно перед `Benchmark finished.`.

## How to modify

Для добавления profile выберите уникальный стабильный `id`, используйте только vocabulary из таблицы, обновите profile table в этом документе и в full-manifest document, затем выполните команду smoke matrix. Изменение или удаление уже reviewed `id` несовместимо с baseline group set; создайте новый identifier вместо silent semantic change.

## Baseline and comparison

Сравнение допускается только при одинаковом manifest profile set, C11/ASM revision, compiler, CPU affinity, repetitions, iteration counts, warm-up, data count, thread count и `measure_mode`. `benchmark_stats` сравнивает median каждой пары `profile_id × mode` и сообщает regression только при превышении одновременно percentage threshold и baseline MAD noise floor. Новый baseline создаётся вручную из reviewed reproducible run и никогда не заменяется автоматически.

## Failure handling

Malformed JSON, отсутствующее обязательное поле, duplicate profile identifier или `schema_version != 1` завершают matrix tool с nonzero status. Unsupported vocabulary проходит JSON parse, но adapter отклоняет workload до valid benchmark operation; это также nonzero run. Если `MT total iterations` не делится на `MT_THREADS`, Makefile прекращает запуск до matrix execution. Ошибка `getrandom(2)` отображается как operation failure, а не как случайно успешный profile.
