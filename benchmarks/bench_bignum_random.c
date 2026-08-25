/**
 * @file bench_bignum_random.c
 * @brief Single-thread benchmark-core entry point for bignum_random.
 * @details Command-line parsing, deterministic fixture lifecycle, warm-up,
 * timing, and the required `benchmark=...` followed by `Benchmark finished.`
 * protocol are owned by the distributed benchmark-core library. This executable
 * only installs the project adapter and maps named setup/core statuses to ISO C
 * process success or failure.
 */
#include "bignum_random_benchmark_adapter.h"

#include <benchmark_framework.h>

/**
 * @brief Runs the single-thread bounded-random benchmark command.
 * @details All documented benchmark-core CLI options are forwarded unchanged.
 * Successful invocation prints exactly one machine-readable completion record
 * and its trailing marker; setup or core failure returns process code one.
 * @param[in] argc ISO C argument count forwarded to benchmark-core.
 * @param[in] argv ISO C argument vector forwarded to benchmark-core.
 * @return Zero only after `benchmark_core_run_st` returns
 * `BENCHMARK_CORE_STATUS_SUCCESS`; one otherwise.
 */
int main(int argc, char **argv)
{
    benchmark_adapter_t adapter;

    if (bignum_random_benchmark_adapter_init(&adapter) != BIGNUM_RANDOM_BENCHMARK_STATUS_SUCCESS) {
        return 1;
    }
    return benchmark_core_run_st(argc, argv, &adapter) == BENCHMARK_CORE_STATUS_SUCCESS ? 0 : 1;
}
