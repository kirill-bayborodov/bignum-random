/**
 * @file test_bignum_random.c
 * @brief Deterministic public-contract tests for bignum_random.
 * @details The cryptographic source deliberately prevents an exact value oracle.
 * These tests instead use fixed bounds and verify the complete observable
 * contract on every call: named status, strict range membership, normalized
 * output, input preservation, and transactional failure behavior. Repeated
 * sampling uses only invariant checks and does not assume a particular stream.
 */
#include "bignum_random.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Initializes a normalized bignum from a little-endian word sequence.
 * @param[out] value Writable record to initialize.
 * @param[in] words Little-endian words; NULL is permitted only with zero count.
 * @param[in] length Exact normalized active-word count.
 * @return No status; test fixtures provide valid arguments.
 */
static void set_value(bignum_t *value, const uint64_t *words, size_t length)
{
    memset(value, 0, sizeof(*value));
    if (length > 0U) memcpy(value->words, words, length * sizeof(words[0]));
    value->len = length;
}

/**
 * @brief Compares two normalized fixed-capacity unsigned bignums.
 * @param[in] left First borrowed normalized value.
 * @param[in] right Second borrowed normalized value.
 * @return Negative, zero, or positive according to unsigned numeric ordering.
 */
static int compare_values(const bignum_t *left, const bignum_t *right)
{
    size_t index = left->len > right->len ? left->len : right->len;

    while (index > 0U) {
        uint64_t left_word;
        uint64_t right_word;

        --index;
        left_word = index < left->len ? left->words[index] : UINT64_C(0);
        right_word = index < right->len ? right->words[index] : UINT64_C(0);
        if (left_word < right_word) return -1;
        if (left_word > right_word) return 1;
    }
    return 0;
}

/**
 * @brief Verifies normalized representation and strict half-open range output.
 * @param[in] value Borrowed output record returned by bignum_random.
 * @param[in] bound Borrowed normalized positive exclusive upper bound.
 * @return One when every representation and range invariant holds, otherwise zero.
 */
static int is_valid_sample(const bignum_t *value, const bignum_t *bound)
{
    if (value->len > BIGNUM_CAPACITY) return 0;
    if (value->len > 0U && value->words[value->len - 1U] == UINT64_C(0)) return 0;
    for (size_t index = value->len; index < BIGNUM_CAPACITY; ++index) {
        if (value->words[index] != UINT64_C(0)) return 0;
    }
    return compare_values(value, bound) < 0;
}

/**
 * @brief Exercises null, alias, empty-range, length, and normalization errors.
 * @details Each failure scenario starts with a distinct canary output snapshot.
 * The oracle requires the named status and byte-for-byte output preservation,
 * proving that validation occurs before entropy acquisition or output mutation.
 * @return One on success and zero on the first contract violation.
 */
static int test_invalid_arguments_preserve_output(void)
{
    const uint64_t seven[] = { UINT64_C(7) };
    bignum_t output;
    bignum_t before;
    bignum_t bound;

    set_value(&output, seven, 1U);
    before = output;
    if (bignum_random(&output, NULL) != BIGNUM_RANDOM_ERROR_NULL_ARG ||
        memcmp(&output, &before, sizeof(output)) != 0) return 0;

    set_value(&bound, seven, 1U);
    if (bignum_random(&bound, &bound) != BIGNUM_RANDOM_ERROR_ALIAS) return 0;

    memset(&bound, 0, sizeof(bound));
    if (bignum_random(&output, &bound) != BIGNUM_RANDOM_ERROR_RANGE ||
        memcmp(&output, &before, sizeof(output)) != 0) return 0;

    bound.len = BIGNUM_CAPACITY + 1U;
    if (bignum_random(&output, &bound) != BIGNUM_RANDOM_ERROR_LENGTH ||
        memcmp(&output, &before, sizeof(output)) != 0) return 0;

    memset(&bound, 0, sizeof(bound));
    bound.len = 1U;
    if (bignum_random(&output, &bound) != BIGNUM_RANDOM_ERROR_NORMALIZATION ||
        memcmp(&output, &before, sizeof(output)) != 0) return 0;
    return 1;
}

/**
 * @brief Verifies the unique output for the singleton interval `[0, 1)`.
 * @details The fixed bound one gives an exact oracle despite nondeterministic
 * entropy: every accepted candidate must be zero and must have normalized
 * length zero. The loop also checks that repeated entropy calls remain valid.
 * @return One when all 64 samples equal zero, otherwise zero.
 */
static int test_singleton_range(void)
{
    const uint64_t one[] = { UINT64_C(1) };
    bignum_t bound;

    set_value(&bound, one, 1U);
    for (size_t iteration = 0U; iteration < 64U; ++iteration) {
        bignum_t output;

        memset(&output, 0xA5, sizeof(output));
        if (bignum_random(&output, &bound) != BIGNUM_RANDOM_SUCCESS ||
            output.len != 0U || output.words[0] != UINT64_C(0) ||
            !is_valid_sample(&output, &bound)) return 0;
    }
    return 1;
}

/**
 * @brief Checks strict range and input preservation for fixed representative bounds.
 * @details Bounds 2, 3, and `2^64 + 1` exercise a power of two, a rejection-
 * sampling case, and a two-word bit-length boundary. The reference oracle is
 * numeric comparison rather than a predicted random byte sequence.
 * @return One when 768 successful samples obey every invariant, otherwise zero.
 */
static int test_representative_ranges(void)
{
    const uint64_t bounds[][2] = {
        { UINT64_C(2), UINT64_C(0) },
        { UINT64_C(3), UINT64_C(0) },
        { UINT64_C(1), UINT64_C(1) }
    };
    const size_t lengths[] = { 1U, 1U, 2U };

    for (size_t case_index = 0U; case_index < 3U; ++case_index) {
        bignum_t bound;
        bignum_t snapshot;

        set_value(&bound, bounds[case_index], lengths[case_index]);
        snapshot = bound;
        for (size_t iteration = 0U; iteration < 256U; ++iteration) {
            bignum_t output;

            memset(&output, 0x5A, sizeof(output));
            if (bignum_random(&output, &bound) != BIGNUM_RANDOM_SUCCESS ||
                !is_valid_sample(&output, &bound) ||
                memcmp(&bound, &snapshot, sizeof(bound)) != 0) return 0;
        }
    }
    return 1;
}

/**
 * @brief Runs all deterministic public-contract scenarios.
 * @details Each line identifies the exact scenario so a CI failure exposes the
 * violated API invariant without relying on a non-reproducible sampled value.
 * @return ISO C process success only when all listed scenarios pass.
 */
int main(void)
{
    int failed = 0;

    printf("--- Starting deterministic bignum_random tests ---\n");
    if (test_invalid_arguments_preserve_output()) printf("test_invalid_arguments_preserve_output: PASSED\n");
    else { printf("test_invalid_arguments_preserve_output: FAILED\n"); ++failed; }
    if (test_singleton_range()) printf("test_singleton_range: PASSED\n");
    else { printf("test_singleton_range: FAILED\n"); ++failed; }
    if (test_representative_ranges()) printf("test_representative_ranges: PASSED\n");
    else { printf("test_representative_ranges: FAILED\n"); ++failed; }
    printf("--- Deterministic bignum_random tests: %s ---\n", failed == 0 ? "PASSED" : "FAILED");
    return failed == 0 ? 0 : 1;
}
