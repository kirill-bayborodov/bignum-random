/**
 * @file bignum_random_benchmark_adapter.c
 * @brief Benchmark-core callbacks for bounded cryptographic bignum sampling.
 * @details The adapter separates reproducible benchmark fixtures from production
 * entropy. `initialize` deterministically creates only the normalized exclusive
 * upper bound. `operation` then calls `bignum_random`, whose `getrandom(2)`
 * usage remains inside the measured operation. The checksum reads both range
 * endpoint and sampled result to prevent compiler elimination without exposing
 * random values as a stable fixture oracle.
 *
 * @version 1.0.0
 */
#include "bignum_random_benchmark_adapter.h"
#include "bignum_random.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/** @brief FNV-1a offset basis used for a non-cryptographic benchmark checksum. */
#define RANDOM_BENCHMARK_FNV_OFFSET UINT64_C(1469598103934665603)
/** @brief FNV-1a multiplication factor used for a non-cryptographic checksum. */
#define RANDOM_BENCHMARK_FNV_PRIME UINT64_C(1099511628211)

/**
 * @brief Holds one benchmark-core mutable record for bignum_random.
 * @details The core first creates an immutable source copy of this state, then
 * supplies a private mutable copy to each measured operation. Both records are
 * value-owned by benchmark-core; neither callback allocates or retains storage.
 */
typedef struct random_benchmark_state {
    bignum_t upper_bound; /**< [in] Deterministic normalized positive exclusive endpoint. */
    bignum_t output; /**< [out] Most recent bignum_random sample; valid after successful operation only. */
} random_benchmark_state_t;

/**
 * @brief Compares two non-NULL workload vocabulary tokens.
 * @param[in] left Borrowed optional token.
 * @param[in] right Borrowed optional token.
 * @return One only when both pointers are non-NULL and their text is identical.
 */
static int equal_text(const char *left, const char *right)
{
    return left != NULL && right != NULL && strcmp(left, right) == 0;
}

/**
 * @brief Checks one token against a NULL-terminated vocabulary table.
 * @param[in] value Borrowed token to validate.
 * @param[in] vocabulary Borrowed NULL-terminated allowed-token table.
 * @return One when value is present, otherwise zero; no input is modified.
 */
static int allowed(const char *value, const char *const *vocabulary)
{
    if (value == NULL || vocabulary == NULL) return 0;
    for (size_t index = 0U; vocabulary[index] != NULL; ++index) {
        if (equal_text(value, vocabulary[index])) return 1;
    }
    return 0;
}

/**
 * @brief Mixes a deterministic 64-bit fixture seed.
 * @details This is not an entropy source and is never passed as random output.
 * It only constructs stable nonzero range endpoints from the manifest seed and
 * record index, letting C and ASM benchmarks receive matching input domains.
 * @param[in] value Deterministic fixture input word.
 * @return A mixed deterministic fixture word.
 */
static uint64_t mix64(uint64_t value)
{
    value += UINT64_C(0x9E3779B97F4A7C15);
    value = (value ^ (value >> 30U)) * UINT64_C(0xBF58476D1CE4E5B9);
    value = (value ^ (value >> 27U)) * UINT64_C(0x94D049BB133111EB);
    return value ^ (value >> 31U);
}

/**
 * @brief Chooses a valid positive upper-bound length from a profile.
 * @param[in] workload Borrowed validated workload metadata.
 * @param[in] sequence_index Stable benchmark-core record index.
 * @return A word count in the closed range `[1, BIGNUM_CAPACITY]`.
 */
static size_t words_for_profile(const benchmark_workload_t *workload, uint64_t sequence_index)
{
    if (equal_text(workload->capacity_profile, "near-capacity") ||
        equal_text(workload->size_profile, "near-capacity")) return BIGNUM_CAPACITY;
    if (equal_text(workload->size_profile, "one")) return 1U;
    if (equal_text(workload->size_profile, "quarter")) return BIGNUM_CAPACITY / 4U;
    if (equal_text(workload->size_profile, "half")) return BIGNUM_CAPACITY / 2U;
    return 1U + (size_t)(mix64(workload->seed ^ sequence_index) % BIGNUM_CAPACITY);
}

/**
 * @brief Creates a deterministic normalized positive benchmark bound.
 * @details A singleton range uses one as the endpoint. Every other path fills
 * exactly the profile-selected number of words and sets the high word's top bit
 * so that the record is normalized and represents the selected size. `mixed`
 * alternates the singleton and normal paths by record index.
 * @param[out] bound Caller-owned record to initialize completely.
 * @param[in] workload Borrowed already-validated workload.
 * @param[in] sequence_index Stable source-record index from benchmark-core.
 * @return No status; all supported profiles produce a valid positive bound.
 */
static void initialize_bound(bignum_t *bound, const benchmark_workload_t *workload,
                             uint64_t sequence_index)
{
    const int singleton = equal_text(workload->input_kind, "zero") ||
        equal_text(workload->operation_kind, "random-one") ||
        (equal_text(workload->input_kind, "mixed") && (sequence_index & UINT64_C(1)) == 0U) ||
        (equal_text(workload->operation_kind, "random-mixed") && (sequence_index & UINT64_C(1)) == 0U);
    const size_t length = equal_text(workload->operation_kind, "random-word") ?
        1U : words_for_profile(workload, sequence_index);

    memset(bound, 0, sizeof(*bound));
    if (singleton) {
        bound->words[0] = UINT64_C(1);
        bound->len = 1U;
        return;
    }
    for (size_t word = 0U; word < length; ++word) {
        bound->words[word] = mix64(workload->seed + sequence_index + (uint64_t)word);
    }
    bound->words[length - 1U] |= UINT64_C(1) << 63U;
    bound->len = length;
}

/**
 * @brief Initializes one immutable random-sampling source record.
 * @param[out] opaque Zeroed benchmark-core state storage of adapter state size.
 * @param[in] sequence_index Stable source-record sequence index.
 * @param[in] workload Borrowed immutable workload metadata.
 * @param[in] context Unused adapter context, always NULL for this module.
 * @return `BENCHMARK_ADAPTER_STATUS_SUCCESS` for a complete record or
 * `BENCHMARK_ADAPTER_STATUS_INPUT_ERROR` if callback arguments are invalid.
 */
static benchmark_adapter_status_t initialize(void *opaque, uint64_t sequence_index,
                                             const benchmark_workload_t *workload, void *context)
{
    random_benchmark_state_t *state = opaque;

    (void)context;
    if (state == NULL || workload == NULL ||
        bignum_random_benchmark_validate_workload(workload) != BIGNUM_RANDOM_BENCHMARK_STATUS_SUCCESS) {
        return BENCHMARK_ADAPTER_STATUS_INPUT_ERROR;
    }
    initialize_bound(&state->upper_bound, workload, sequence_index);
    memset(&state->output, 0, sizeof(state->output));
    return BENCHMARK_ADAPTER_STATUS_SUCCESS;
}

/**
 * @brief Invokes one production random-sampling operation on mutable state.
 * @details The output is reset by `bignum_random` only after acceptance. The
 * bound remains immutable for the entire benchmark invocation. The iteration
 * number is not used because every operation must receive fresh kernel entropy.
 * @param[in,out] opaque Private mutable `random_benchmark_state_t` record.
 * @param[in] iteration Logical benchmark iteration, intentionally unused.
 * @param[in] workload Borrowed workload metadata, intentionally unused here.
 * @param[in] context Unused adapter context.
 * @return Framework success only when bignum_random succeeds; any named random
 * error is exposed as `BENCHMARK_ADAPTER_STATUS_OPERATION_ERROR`.
 */
static benchmark_adapter_status_t operation(void *opaque, uint64_t iteration,
                                            const benchmark_workload_t *workload, void *context)
{
    random_benchmark_state_t *state = opaque;

    (void)iteration;
    (void)workload;
    (void)context;
    if (state == NULL ||
        bignum_random(&state->output, &state->upper_bound) != BIGNUM_RANDOM_SUCCESS) {
        return BENCHMARK_ADAPTER_STATUS_OPERATION_ERROR;
    }
    return BENCHMARK_ADAPTER_STATUS_SUCCESS;
}

/**
 * @brief Produces an observable checksum of one random benchmark record.
 * @details The non-cryptographic checksum reads every active bound and output
 * word. It is a correctness/anti-elimination transport value, not a measure of
 * randomness quality and not a stable value across separate benchmark runs.
 * @param[in] opaque Borrowed completed `random_benchmark_state_t` record.
 * @param[in] iteration Logical iteration mixed into the checksum.
 * @param[in] context Unused adapter context.
 * @return A deterministic reduction for this concrete record and iteration.
 */
static uint64_t checksum(const void *opaque, uint64_t iteration, void *context)
{
    const random_benchmark_state_t *state = opaque;
    uint64_t hash = RANDOM_BENCHMARK_FNV_OFFSET;

    (void)context;
    if (state == NULL) return UINT64_C(0);
    for (size_t word = 0U; word < BIGNUM_CAPACITY; ++word) {
        hash ^= state->upper_bound.words[word];
        hash *= RANDOM_BENCHMARK_FNV_PRIME;
        hash ^= state->output.words[word];
        hash *= RANDOM_BENCHMARK_FNV_PRIME;
    }
    hash ^= (uint64_t)state->upper_bound.len;
    hash *= RANDOM_BENCHMARK_FNV_PRIME;
    hash ^= (uint64_t)state->output.len;
    hash *= RANDOM_BENCHMARK_FNV_PRIME;
    return hash ^ iteration;
}

bignum_random_benchmark_status_t bignum_random_benchmark_validate_workload(
    const benchmark_workload_t *workload)
{
    static const char *const input[] = { "zero", "nonzero", "mixed", NULL };
    static const char *const operation[] = {
        "random-one", "random-word", "random-range", "random-mixed", NULL
    };
    static const char *const measure[] = { "end-to-end", "kernel-only", NULL };
    static const char *const size[] = { "one", "quarter", "half", "variable", "near-capacity", NULL };
    static const char *const capacity[] = { "normal", "near-capacity", NULL };

    if (workload == NULL) return BIGNUM_RANDOM_BENCHMARK_STATUS_NULL_ARGUMENT;
    if (!allowed(workload->input_kind, input) || !allowed(workload->operation_kind, operation) ||
        !allowed(workload->measure_mode, measure) || !allowed(workload->size_profile, size) ||
        !allowed(workload->capacity_profile, capacity)) {
        return BIGNUM_RANDOM_BENCHMARK_STATUS_INVALID_PROFILE;
    }
    return BIGNUM_RANDOM_BENCHMARK_STATUS_SUCCESS;
}

bignum_random_benchmark_status_t bignum_random_benchmark_adapter_init(benchmark_adapter_t *adapter)
{
    if (adapter == NULL) return BIGNUM_RANDOM_BENCHMARK_STATUS_NULL_ARGUMENT;
    *adapter = (benchmark_adapter_t){
        .benchmark_name = "bignum_random",
        .state_size = sizeof(random_benchmark_state_t),
        .success_code = BENCHMARK_ADAPTER_STATUS_SUCCESS,
        .adapter_context = NULL,
        .initialize = initialize,
        .operation = operation,
        .checksum = checksum
    };
    return BIGNUM_RANDOM_BENCHMARK_STATUS_SUCCESS;
}
