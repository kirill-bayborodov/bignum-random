/**
 * @file bench_bignum_random_mt.c
 * @brief Multi-thread benchmark-core entry point for bignum_random.
 * @details The distributed benchmark-core creates worker-private mutable state,
 * performs warm-up, synchronizes measured workers, and emits the stable MT
 * protocol. This thin executable binds only the bignum-random adapter and does
 * not introduce project-global synchronization or a competing timing scope.
 */
#include "bignum_random_benchmark_adapter.h"

#include <benchmark_framework.h>

/**
 * @brief Runs the multi-thread bounded-random benchmark command.
 * @details The core validates thread count and total-iteration divisibility
 * before worker creation. Its successful output remains the only source of the
 * required `benchmark=bignum_random_mt ...` completion protocol.
 * @param[in] argc ISO C argument count forwarded to benchmark-core.
 * @param[in] argv ISO C argument vector forwarded to benchmark-core.
 * @return Zero only after `benchmark_core_run_mt` reports named success; one
 * for adapter setup failure, invalid arguments, or a benchmark-core error.
 */
int main(int argc, char **argv)
{
    benchmark_adapter_t adapter;

    if (bignum_random_benchmark_adapter_init(&adapter) != BIGNUM_RANDOM_BENCHMARK_STATUS_SUCCESS) {
        return 1;
    }
    return benchmark_core_run_mt(argc, argv, &adapter) == BENCHMARK_CORE_STATUS_SUCCESS ? 0 : 1;
}
