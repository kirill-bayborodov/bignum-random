# bignum-random

`bignum-random` — модуль C11/x86-64 YASM для выборки криптографически стойкого беззнакового `bignum_t` из полуинтервала **`[0, n)`**. Эталонная C11-реализация и production ASM-путь используют Linux `getrandom(2)` с urandom source. Модуль не применяет `% n`: он маскирует candidate до битовой длины `n` и выполняет rejection sampling, поэтому не создаёт modulo bias для произвольной положительной верхней границы.[1]

> **Граница платформы.** Версия 1.0.0 предназначена для Linux x86-64 с System V AMD64 ABI. Вызов может блокироваться, пока ядро инициализирует urandom source; это корректное свойство криптографического источника, а не fallback на предсказуемый generator.[1]

## Distribution и зависимости

`bignum-core` является Git submodule в `libs/bignum-core`. `benchmark-framework` поставляется как vendor distribution в `libs/benchmark-framework/dist`, а не собирается из исходников потребляющим проектом. CI распаковывает опубликованный `dist` artifact именно в этот каталог; локальная подготовка должна повторять ту же схему.

| Компонент | Путь | Назначение |
|---|---|---|
| `bignum-core` | `libs/bignum-core` | Определяет little-endian fixed-capacity `bignum_t` и `BIGNUM_CAPACITY`. |
| `benchmark-framework` | `libs/benchmark-framework/dist` | Поставляет `benchmark_core.h`, static library, `bench_matrix` и `benchmark_stats`. |
| `make`, `gcc`, `yasm` | System PATH | Сборка C11, YASM и distribution. |
| `cppcheck`, `valgrind`, `pthread` | System PATH / libc | Static analysis, Helgrind и MT tests. |
| `perf`, `taskset` | System PATH | Необязательные performance counters и CPU affinity. |

Клонируйте проект вместе с required core submodule, затем восстановите submodules существующего clone стандартной командой.

```bash
git clone --recurse-submodules https://github.com/kirill-bayborodov/bignum-random.git
cd bignum-random
git submodule update --init --recursive
```

Скачайте последний reviewed `benchmark-framework` distribution в `libs/benchmark-framework/dist`. Его SHA-256 и release version должны фиксироваться в evidence конкретного benchmark run; не подменяйте library локально собранной непроверенной версией.

## Public API

Публичный header — [`include/bignum_random.h`](include/bignum_random.h). `upper_bound` является borrowed normalized positive endpoint, `out` — caller-owned destination. Оба объекта не должны alias; API не выделяет и не сохраняет память.

```c
bignum_random_status_t bignum_random(bignum_t *out,
                                     const bignum_t *upper_bound);
```

| Условие | Named status | Состояние объектов |
|---|---|---|
| `out == NULL` или `upper_bound == NULL` | `BIGNUM_RANDOM_ERROR_NULL_ARG` | Ничего не dereference; существующий output не меняется. |
| `out == upper_bound` | `BIGNUM_RANDOM_ERROR_ALIAS` | Оба records остаются неизменными. |
| `upper_bound->len == 0` | `BIGNUM_RANDOM_ERROR_RANGE` | Интервал пуст; output неизменён. |
| `upper_bound->len > BIGNUM_CAPACITY` | `BIGNUM_RANDOM_ERROR_LENGTH` | Malformed core record; output неизменён. |
| Старшее active word равно нулю | `BIGNUM_RANDOM_ERROR_NORMALIZATION` | Unnormalized positive bound; output неизменён. |
| `getrandom(2)` не завершил candidate | `BIGNUM_RANDOM_ERROR_ENTROPY` | Частичный candidate не публикуется; вызов можно повторить. |
| Valid positive normalized bound | `BIGNUM_RANDOM_SUCCESS` | `out` normalized и равномерно распределён в `[0, upper_bound)`. |

Алгоритм сначала валидирует bounds, затем получает количество random bytes, равное active word span. Он очищает биты выше `bit_length(upper_bound)`, сравнивает candidate с `upper_bound` и повторяет запрос, если candidate не меньше bound. Для `k = bit_length(n)` вероятность принятия больше одной второй, поэтому expected candidate count меньше двух; тем не менее число retries data-dependent и не предназначено для context, где такое timing leakage секретно.

## Минимальный пример

Ниже показан полный caller-owned scenario с проверкой named status. Bound `2^64 + 1` нормализован, а output storage существует весь вызов.

```c
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "bignum_random.h"

int main(void)
{
    bignum_t upper_bound;
    bignum_t value;

    memset(&upper_bound, 0, sizeof(upper_bound));
    upper_bound.words[0] = UINT64_C(1);
    upper_bound.words[1] = UINT64_C(1);
    upper_bound.len = 2U;

    if (bignum_random(&value, &upper_bound) != BIGNUM_RANDOM_SUCCESS) {
        fputs("random sampling failed\n", stderr);
        return 1;
    }
    return 0;
}
```

Соберите example после release build. `-no-pie` соответствует текущему family Makefile; при использовании static distribution предпочитайте описанную ниже библиотеку.

```bash
make build CONFIG=release USE_ASM=yes
gcc example.c build/bignum_random.o \
  -I./include -I./libs/bignum-core/include \
  -o example -no-pie
./example
```

## Build, tests и quality gates

Пока ASM production path не создан, C11 baseline собирается с `USE_ASM=no`. После создания `src/bignum_random.asm` значение `USE_ASM=auto` выбирает YASM; `USE_ASM=yes` выбирает его явно. Полный suite включает deterministic public contract, property/fuzz-style ranges, independent-object MT, distribution runner и benchmark-adapter tests.

```bash
make clean
make test CONFIG=release USE_ASM=no
make lint

make clean
make test_sanitize SAN=address CONFIG=debug USE_ASM=no
make clean
make test_sanitize SAN=undefined CONFIG=debug USE_ASM=no
make clean
make test_helgrind CONFIG=debug USE_ASM=no
```

C11 coverage измеряется через `gcov` с test binaries, собранными с `--coverage`. На review фиксируются line, branch и call coverage вместе с неисполненными platform-dependent error paths. Требования к file Doxygen, statuses, tests, JSON companion documents и ASM boundary находятся в [`docs/QUALITY_GATES_DOCUMENTATION_C11_JSON.md`](docs/QUALITY_GATES_DOCUMENTATION_C11_JSON.md).

## Benchmarks

`benchmarks/adapter/` переводит neutral benchmark-core fields в deterministic **positive upper bounds**. Seed влияет только на construction bound; случайные output values намеренно не повторяются между runs. Checksum наблюдает result и bound, не выдавая random output как fixed oracle.

| Profile axis | Допустимые значения | Значение |
|---|---|---|
| `input_kind` | `zero`, `nonzero`, `mixed` | `zero` создаёт singleton bound `1`, а не invalid bound `0`; `mixed` чередует safe cases. |
| `operation_kind` | `random-one`, `random-word`, `random-range`, `random-mixed` | Форма upper bound для одной production random operation. |
| `measure_mode` | `kernel-only`, `end-to-end` | Исключает либо включает copy/preparation state; системная entropy остаётся внутри обоих. |
| `size_profile` | `one`, `quarter`, `half`, `variable`, `near-capacity` | Число 64-bit words upper bound. |
| `capacity_profile` | `normal`, `near-capacity` | Valid boundary range, не malformed input. |

Используйте standard manifest для short smoke run и full manifest для reviewed baseline. Каждый successful runner обязан вывести одну строку `benchmark=...` непосредственно перед `Benchmark finished.`; matrix tool проверяет этот порядок.

```bash
make bench_matrix CONFIG=release USE_ASM=no \
  REPORT_NAME=random_c11_smoke \
  BENCH_MATRIX_PROFILE=benchmarks/profiles/bignum_random_standard.json \
  BENCH_MATRIX_REPETITIONS=1 \
  BENCH_MATRIX_ITERATIONS=1000 \
  BENCH_MATRIX_MT_TOTAL_ITERATIONS=2000 \
  BENCH_MATRIX_WARMUP=10 \
  BENCH_MATRIX_DATA_COUNT=32 \
  MT_THREADS=2
```

Full baseline and ASM comparison instructions, JSON schema, profile identifiers, failure semantics and regression policy are maintained beside the manifests: [`bignum_random_standard.json.md`](benchmarks/profiles/bignum_random_standard.json.md) and [`bignum_random_full.json.md`](benchmarks/profiles/bignum_random_full.json.md). Compare only matching profile set, machine topology, compiler, configuration, seed, total work, worker count and measurement scope. Syscall and scheduler variation require median/MAD evidence, not a single timing number.

## Installation и cleanup

Object-file distribution and static-library/single-header distribution are generated by the unchanged Makefile. Both commands run the distribution integration runner.

```bash
make install CONFIG=release USE_ASM=yes
make dist CONFIG=release USE_ASM=yes
make clean
```

`make bench_cl` additionally requires a kernel-compatible profiler at the `PERF` path configured by the Makefile. If the host does not provide that binary, use `bench_matrix`: it uses no hardware PMU events and remains the required C11 baseline/ASM comparison route.

## Contribution

Любое изменение API, statuses, benchmark vocabulary, profile ID или observable output должно изменять implementation, public documentation, tests and companion JSON documents в одном reviewable diff. Не изменяйте `.github/workflows/ci.yml` или `Makefile`; если новый operation cannot be integrated within their existing contract, оформите отдельное proposal с path, причиной, risk и removal condition. Перед review выполните applicable commands из этого README и per-artifact checklist из quality-gate document.

## License

Проект лицензирован по [MIT License](LICENSE).

## References

[1] [Linux `getrandom(2)` manual page](https://man7.org/linux/man-pages/man2/getrandom.2.html)
