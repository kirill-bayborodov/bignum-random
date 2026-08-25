# bignum-random

[![C/ASM CI](https://github.com/kirill-bayborodov/bignum-random/actions/workflows/ci.yml/badge.svg)](https://github.com/kirill-bayborodov/bignum-random/actions/workflows/ci.yml)
[![GitHub release](https://img.shields.io/github/v/release/kirill-bayborodov/bignum-random?label=release)](https://github.com/kirill-bayborodov/bignum-random/releases/latest)

`bignum-random` is a standalone C11 and x86-64 YASM module for sampling a cryptographically random unsigned `bignum_t` from the half-open interval **`[0, n)`**. The public operation validates the caller-supplied normalized upper bound, obtains entropy from Linux `getrandom(2)`, restricts a candidate to the bound bit width, and uses rejection sampling instead of `% n`. This avoids modulo bias for every positive bound.[1]

The module is part of the `bignum-lib` family. It follows the family build, test, distribution, benchmark, documentation, and machine-readable runner conventions. The production assembly path targets Linux x86-64 using the System V AMD64 ABI; the C11 source is a readable reference implementation and baseline.

> **Platform boundary.** Version 1.0.0 requires Linux x86-64 and the `getrandom(2)` system call. A call may block while the kernel initializes its urandom source. This is a cryptographic-source property, not a fallback to a predictable pseudo-random generator.[1]

## Features

- **Unbiased bounded sampling:** rejection sampling creates a uniform value in `[0, upper_bound)` without modulo reduction bias.
- **Cryptographic entropy:** the C11 and YASM paths obtain candidate bytes from Linux `getrandom(2)`.
- **Explicit status contract:** `bignum_random_status_t` distinguishes null arguments, aliasing, empty ranges, malformed lengths, non-normalized bounds, and entropy failures.
- **Transactional output:** the complete `out` object changes only after an accepted, normalized candidate has been produced.
- **Reentrant operation:** no mutable process-global state, heap allocation, or file descriptor is used. The ASM path caches unused raw entropy per ELF thread and invalidates inherited bytes after a process-ID change.
- **Production YASM path:** the assembly implementation documents the System V AMD64 register, stack, representation, syscall-clobber, and error contracts.
- **Deterministic verification:** API, property/fuzz-style, multithreaded, distribution-runner, and benchmark-adapter tests are included.
- **Reproducible measurements:** single-thread and multithread benchmark runners consume versioned JSON manifests and emit the `benchmark=...` then `Benchmark finished.` protocol expected by the matrix tools.

## Distribution and dependencies

The required `bignum-core` component is a Git submodule at `libs/bignum-core`. `benchmark-framework` is used as a reviewed vendor distribution at `libs/benchmark-framework/dist`; consumer builds do not compile that framework from an arbitrary local source checkout.

| Component | Expected location | Purpose |
|---|---|---|
| `bignum-core` | `libs/bignum-core` | Defines little-endian fixed-capacity `bignum_t` and `BIGNUM_CAPACITY`. |
| `benchmark-framework` | `libs/benchmark-framework/dist` | Supplies `benchmark_framework.h`, the static library, `bench_matrix`, and `benchmark_stats`. |
| `make` | System `PATH` | Drives the existing build, test, distribution, and benchmark targets. |
| `gcc` | System `PATH` | Compiles and links the C11 reference, tests, runners, and distributions. |
| `yasm` | System `PATH` | Assembles the Linux x86-64 production object. |
| `cppcheck` | System `PATH` | Runs static analysis through `make lint`. |
| `valgrind` | System `PATH` | Provides Helgrind and optional Callgrind evidence. |
| `pthread` | C library | Supports multithread tests and benchmark runners. |
| `taskset` | System `PATH` | Pins comparison runs to a controlled CPU set. |

Clone the repository with its required submodule:

```bash
git clone --recurse-submodules https://github.com/kirill-bayborodov/bignum-random.git
cd bignum-random
```

For an existing clone, recover all declared submodules with:

```bash
git submodule update --init --recursive
```

Place the reviewed `benchmark-framework` distribution in `libs/benchmark-framework/dist`, exactly as the existing CI workflow does. Record its release and SHA-256 alongside every reviewed benchmark report. Do not silently substitute an unreviewed locally built framework.

## Public API and contract

The canonical interface is declared in [`include/bignum_random.h`](include/bignum_random.h):

```c
bignum_random_status_t bignum_random(
    bignum_t *out,
    const bignum_t *upper_bound);
```

`upper_bound` is a borrowed, positive, normalized exclusive endpoint. `out` is caller-owned writable storage and must not alias `upper_bound`. The function performs no allocation and never retains caller memory. The C11 reference retains no entropy bytes; the YASM path may retain unused raw `getrandom(2)` bytes in private ELF thread-local storage to amortize a later call. That cache is never shared across threads and is invalidated after a process-ID change.

| Condition | Named status | Observable result |
|---|---|---|
| `out == NULL` or `upper_bound == NULL` | `BIGNUM_RANDOM_ERROR_NULL_ARG` | No object is dereferenced; any live output remains unchanged. |
| `out == upper_bound` | `BIGNUM_RANDOM_ERROR_ALIAS` | Both records remain unchanged. |
| `upper_bound->len == 0` | `BIGNUM_RANDOM_ERROR_RANGE` | The interval is empty; `out` remains unchanged. |
| `upper_bound->len > BIGNUM_CAPACITY` | `BIGNUM_RANDOM_ERROR_LENGTH` | The core record is malformed; `out` remains unchanged. |
| The highest active word is zero | `BIGNUM_RANDOM_ERROR_NORMALIZATION` | The positive bound is not normalized; `out` remains unchanged. |
| `getrandom(2)` cannot fill the candidate | `BIGNUM_RANDOM_ERROR_ENTROPY` | No partial candidate is published; the call may be retried. |
| A valid positive normalized bound | `BIGNUM_RANDOM_SUCCESS` | `out` is normalized and uniformly distributed in `[0, upper_bound)`. |

For `k = bit_length(upper_bound)`, sampling occurs in `[0, 2^k)`. The candidate high bits are masked, and candidates greater than or equal to the bound are rejected. The acceptance probability is greater than one half, so the expected number of candidates is below two. Retry count is nevertheless data-dependent; do not use this one-shot API where the retry timing itself is secret-sensitive.

The operation is reentrant and thread-safe for independent objects. The C11 path is stateless; the YASM path has only private ELF thread-local cache state and no shared mutable state. Concurrent access to the same `bignum_t` object, where another thread may write it, still requires external synchronization by the caller.

## Quick start

The following complete caller-owned example samples a value below `2^64 + 1`. It checks the named status and has no cleanup step because the library neither allocates nor transfers ownership.

```c
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bignum_random.h"

int main(void)
{
    bignum_t upper_bound;
    bignum_t value;
    bignum_random_status_t status;

    memset(&upper_bound, 0, sizeof(upper_bound));
    upper_bound.words[0] = UINT64_C(1);
    upper_bound.words[1] = UINT64_C(1);
    upper_bound.len = 2U;

    status = bignum_random(&value, &upper_bound);
    if (status != BIGNUM_RANDOM_SUCCESS) {
        fputs("bignum_random failed\n", stderr);
        return 1;
    }

    return 0;
}
```

Build and run the example after producing the release object:

```bash
make build CONFIG=release USE_ASM=yes
gcc example.c build/bignum_random.o \
  -I./include -I./libs/bignum-core/include \
  -o example -no-pie
./example
```

## Build, test, and quality gates

Use `USE_ASM=no` to select the C11 reference baseline. `USE_ASM=yes` selects the production YASM implementation explicitly; `USE_ASM=auto` selects it when `src/bignum_random.asm` is available.

```bash
make clean
make test CONFIG=release USE_ASM=no
make lint

make clean
make test CONFIG=release USE_ASM=yes
make lint

make clean
make test_sanitize SAN=address CONFIG=debug USE_ASM=yes
make clean
make test_sanitize SAN=undefined CONFIG=debug USE_ASM=yes
make clean
make test_helgrind CONFIG=debug USE_ASM=yes
```

A successful test suite ends with:

```text
=== Summary: 0 / 5 failed ===
```

The test artifacts provide deterministic public-contract scenarios, 20,000 property/fuzz-style range checks, independent-object multithread checks, distribution integration, and benchmark-adapter validation.

| Test artifact | Scope |
|---|---|
| `tests/test_bignum_random.c` | Deterministic argument, status, range, normalization, and output-preservation contract tests. |
| `tests/test_bignum_random_extra.c` | Property/fuzz-style range oracle and capacity-boundary tests. |
| `tests/test_bignum_random_mt.c` | Eight independent pthread workers and range-preservation checks. |
| `tests/test_bignum_random_runner.c` | Static-distribution smoke test for the exported production symbol. |
| `tests/benchmark_adapter/test_bignum_random_benchmark_adapter.c` | Adapter vocabulary, callback binding, fixture, production-operation, and checksum tests. |

C11 source coverage is collected through `gcov` from binaries built with `--coverage`. Assembly does not produce `.gcno/.gcda`; review uses complete dynamic test execution, ABI-facing tests, sanitizers, Helgrind, and Callgrind instruction evidence instead. The YASM cache retains raw entropy only within the current thread and discards inherited cache bytes after a process-ID change; fork behavior is therefore part of the assembly review. The required per-artifact documentation and verification rules are in [`docs/QUALITY_GATES_DOCUMENTATION_C11_JSON.md`](docs/QUALITY_GATES_DOCUMENTATION_C11_JSON.md).

## Benchmarks

`benchmarks/adapter/` maps neutral benchmark-core fields to deterministic, valid positive bounds. The seed controls bound construction only; random output values are intentionally not repeatable. The checksum consumes the produced result and bound so the compiler cannot remove the measured production call.

| Profile axis | Allowed values | Meaning |
|---|---|---|
| `input_kind` | `zero`, `nonzero`, `mixed` | `zero` creates singleton bound `1`, never invalid bound `0`; `mixed` alternates valid cases. |
| `operation_kind` | `random-one`, `random-word`, `random-range`, `random-mixed` | Selects the upper-bound shape for one production random operation. |
| `measure_mode` | `kernel-only`, `end-to-end` | Excludes or includes setup/restoration; entropy acquisition remains in both modes. |
| `size_profile` | `one`, `quarter`, `half`, `variable`, `near-capacity` | Selects the upper-bound active-word span. |
| `capacity_profile` | `normal`, `near-capacity` | Selects a valid boundary range rather than malformed input. |

Use the standard manifest for a short smoke run and the full manifest for a reviewed comparison. Each runner must print one `benchmark=...` line immediately before `Benchmark finished.`; the matrix consumer validates that order.

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

Compare C11 and ASM only with the same manifest, compiler configuration, CPU affinity, topology, seed, total work, worker count, and measurement scope. A reviewed claim needs medians, MAD noise evidence, raw reports, and a paired or interleaved execution plan; one timing number is not a performance conclusion. The full manifest companion documents define schema, profile IDs, failure semantics, and comparison policy: [`bignum_random_standard.json.md`](benchmarks/profiles/bignum_random_standard.json.md) and [`bignum_random_full.json.md`](benchmarks/profiles/bignum_random_full.json.md).

For the current optimization evidence, see [`docs/BENCHMARK_ANALYSIS_AND_ASM_OPTIMIZATION.md`](docs/BENCHMARK_ANALYSIS_AND_ASM_OPTIMIZATION.md).

## Installation, distribution, and cleanup

The unchanged Makefile produces an object distribution and a static-library plus single-header distribution. Both distribution targets execute the integration runner.

```bash
make install CONFIG=release USE_ASM=yes
make dist CONFIG=release USE_ASM=yes
make clean
```

`make bench_cl` additionally requires a kernel-compatible profiler at the `PERF` path defined by the existing Makefile. If that binary is unavailable, use `bench_matrix`; it does not require hardware PMU events and is the supported C11/ASM comparison route.

## Contributing

Contributions are welcome under the project license. Please open an issue before proposing a public API or entropy-source change with security implications. A patch that changes an API signature, named status, benchmark vocabulary, profile identifier, or observable runner protocol must update implementation, public documentation, tests, and JSON companion documents in the same reviewable change.

Do not change `.github/workflows/ci.yml` or `Makefile` for a module-level feature. If the existing contract cannot support a required capability, submit a separate proposal stating the path, rationale, risk, alternatives, and removal condition. Before requesting review, run the applicable commands above and complete the per-artifact checklist in the Quality Gates document.

## Reporting bugs and security issues

Report reproducible non-security defects through the repository issue tracker, including the commit SHA, Linux distribution and kernel, compiler and YASM versions, exact command, expected result, and actual result. Do not publish a suspected entropy, memory-safety, or cryptographic weakness in a public issue before the maintainer has had an opportunity to assess it; contact the repository maintainer privately through the GitHub profile instead.

## License

This project is distributed under the [MIT License](LICENSE). The license permits use, copying, modification, distribution, and sublicensing subject to the included copyright and permission notice.

## References

[1] [Linux `getrandom(2)` manual page](https://man7.org/linux/man-pages/man2/getrandom.2.html)
