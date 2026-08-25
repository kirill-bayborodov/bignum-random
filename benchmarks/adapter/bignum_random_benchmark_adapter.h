/**
 * @file bignum_random_benchmark_adapter.h
 * @brief Project adapter contract for bignum_random benchmarks.
 * @details The adapter translates neutral `benchmark-core` workload metadata
 * into valid normalized positive upper bounds for `bignum_random`. It uses a
 * deterministic fixture generator only for benchmark input construction; every
 * measured operation obtains fresh cryptographic entropy from the production
 * API. The adapter owns no heap allocation and exposes only caller-owned
 * callback bindings.
 *
 * @version 1.0.0
 */
#ifndef BIGNUM_RANDOM_BENCHMARK_ADAPTER_H
#define BIGNUM_RANDOM_BENCHMARK_ADAPTER_H

#include <benchmark_core.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Reports project-level adapter setup and workload-validation results.
 * @details The benchmark core receives only its own callback statuses. This
 * enum lets unit tests and callers distinguish a missing binding from an
 * unsupported bignum-random profile before a benchmark run is attempted.
 */
typedef enum bignum_random_benchmark_status {
    BIGNUM_RANDOM_BENCHMARK_STATUS_SUCCESS = 0, /**< Binding or validation completed; requested output is valid. */
    BIGNUM_RANDOM_BENCHMARK_STATUS_NULL_ARGUMENT = 1, /**< A required adapter or workload pointer is NULL; no output binding is modified. */
    BIGNUM_RANDOM_BENCHMARK_STATUS_INVALID_PROFILE = 2 /**< One or more workload tokens are outside the documented random vocabulary; no run is prepared. */
} bignum_random_benchmark_status_t;

/**
 * @brief Installs benchmark-core callbacks for bounded cryptographic sampling.
 * @details The installed state record contains a caller-independent normalized
 * upper bound and output slot. Initialization creates deterministic bounds;
 * the measured callback invokes `bignum_random` once on its mutable record.
 * @param[out] adapter Caller-owned binding to initialize; NULL is rejected and
 * left unchanged. The binding remains valid while this module is linked.
 * @return `BIGNUM_RANDOM_BENCHMARK_STATUS_SUCCESS` on a complete binding,
 * otherwise `BIGNUM_RANDOM_BENCHMARK_STATUS_NULL_ARGUMENT` with no write.
 * @post On success all callback fields and the state size satisfy the public
 * `benchmark_adapter_t` contract.
 * @thread_safety Reentrant; no adapter-global mutable state is used.
 */
bignum_random_benchmark_status_t bignum_random_benchmark_adapter_init(
    benchmark_adapter_t *adapter);

/**
 * @brief Validates the bignum_random vocabulary carried by benchmark-core.
 * @details Accepted input kinds are `zero`, `nonzero`, and `mixed`; operation
 * kinds are `random-one`, `random-word`, `random-range`, and `random-mixed`.
 * Size profiles are `one`, `quarter`, `half`, `variable`, and `near-capacity`.
 * Capacity and measurement profiles retain their core meanings. Validation does
 * not acquire entropy and does not modify the borrowed workload.
 * @param[in] workload Borrowed immutable workload descriptor; NULL is invalid.
 * @return A named project adapter status; success means every token can produce
 * a valid positive range endpoint, while failure exposes no partial state.
 * @thread_safety Safe for concurrent calls on independent immutable workloads.
 */
bignum_random_benchmark_status_t bignum_random_benchmark_validate_workload(
    const benchmark_workload_t *workload);

#ifdef __cplusplus
}
#endif

#endif /* BIGNUM_RANDOM_BENCHMARK_ADAPTER_H */
