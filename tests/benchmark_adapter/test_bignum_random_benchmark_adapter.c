/**
 * @file test_bignum_random_benchmark_adapter.c
 * @brief Unit tests for the bignum_random benchmark-framework adapter.
 * @details The suite uses fixed workload metadata to verify adapter validation,
 * callback binding, deterministic source-state construction, and a successful
 * production operation. It checks callback statuses and state-size boundaries;
 * it does not assert a random output value because fresh operating-system
 * entropy is intentionally part of the measured operation.
 */
#include "bignum_random_benchmark_adapter.h"
#include "bignum_random.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Returns a fully valid random-range workload fixture.
 * @return A value-owned workload with static string storage and stable seed.
 */
static benchmark_workload_t valid_workload(void)
{
    return (benchmark_workload_t){
        .data_mode = "custom",
        .input_kind = "nonzero",
        .operation_kind = "random-range",
        .measure_mode = "kernel-only",
        .size_profile = "half",
        .capacity_profile = "normal",
        .seed = UINT64_C(0x9E3779B97F4A7C15),
        .warmup = 3U,
        .data_count = 8U
    };
}

/**
 * @brief Checks project vocabulary acceptance and rejection statuses.
 * @details The exact oracle accepts the documented workload and rejects NULL
 * and an unrelated shift token before benchmark-core allocates any state.
 * @return One when all expected statuses match, otherwise zero.
 */
static int test_validation_contract(void)
{
    benchmark_workload_t workload = valid_workload();

    if (bignum_random_benchmark_validate_workload(NULL) !=
        BIGNUM_RANDOM_BENCHMARK_STATUS_NULL_ARGUMENT) return 0;
    if (bignum_random_benchmark_validate_workload(&workload) !=
        BIGNUM_RANDOM_BENCHMARK_STATUS_SUCCESS) return 0;
    workload.operation_kind = "shift-word";
    return bignum_random_benchmark_validate_workload(&workload) ==
        BIGNUM_RANDOM_BENCHMARK_STATUS_INVALID_PROFILE;
}

/**
 * @brief Verifies callback installation and invokes the complete callback lifecycle.
 * @details Storage is intentionally larger than the documented adapter state
 * size. The test asserts a non-NULL callback binding, deterministic source
 * setup success, random operation success, and a callable checksum reduction.
 * @return One when the lifecycle conforms to benchmark-core callback statuses.
 */
static int test_binding_and_callbacks(void)
{
    benchmark_adapter_t adapter;
    benchmark_workload_t workload = valid_workload();
    unsigned char state_storage[2U * sizeof(bignum_t)];
    uint64_t checksum;

    if (bignum_random_benchmark_adapter_init(NULL) !=
        BIGNUM_RANDOM_BENCHMARK_STATUS_NULL_ARGUMENT) return 0;
    if (bignum_random_benchmark_adapter_init(&adapter) !=
        BIGNUM_RANDOM_BENCHMARK_STATUS_SUCCESS) return 0;
    if (adapter.state_size > sizeof(state_storage) || adapter.benchmark_name == NULL ||
        adapter.initialize == NULL || adapter.operation == NULL || adapter.checksum == NULL) return 0;

    memset(state_storage, 0, sizeof(state_storage));
    if (adapter.initialize(state_storage, UINT64_C(17), &workload, adapter.adapter_context) !=
        BENCHMARK_ADAPTER_STATUS_SUCCESS) return 0;
    if (adapter.operation(state_storage, UINT64_C(3), &workload, adapter.adapter_context) !=
        BENCHMARK_ADAPTER_STATUS_SUCCESS) return 0;
    checksum = adapter.checksum(state_storage, UINT64_C(3), adapter.adapter_context);
    return checksum != UINT64_C(0);
}

/**
 * @brief Executes every adapter contract scenario.
 * @return ISO C process success only when validation and callbacks pass.
 */
int main(void)
{
    int failed = 0;

    printf("--- Starting bignum_random benchmark adapter tests ---\n");
    if (test_validation_contract()) printf("test_validation_contract: PASSED\n");
    else { printf("test_validation_contract: FAILED\n"); ++failed; }
    if (test_binding_and_callbacks()) printf("test_binding_and_callbacks: PASSED\n");
    else { printf("test_binding_and_callbacks: FAILED\n"); ++failed; }
    printf("--- bignum_random benchmark adapter tests: %s ---\n", failed == 0 ? "PASSED" : "FAILED");
    return failed == 0 ? 0 : 1;
}
