/**
 * @file test_bignum_random_extra.c
 * @brief Property and fuzz-style tests for bignum_random.
 * @details The module treats the Linux cryptographic stream as opaque and uses
 * a deterministic xorshift generator only to construct 20,000 normalized upper
 * bounds. For every generated bound, the oracle verifies the public outcome:
 * success, normalized output, strict numeric membership in `[0, bound)`, and
 * byte-for-byte preservation of the input. This is property testing, not a
 * statistical claim about the operating-system random source.
 */
#include "bignum_random.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Advances the deterministic fixture generator.
 * @param[in,out] state Non-NULL test-owned generator state.
 * @return A reproducible non-cryptographic 64-bit test word.
 */
static uint64_t next_fixture_word(uint64_t *state)
{
    *state ^= *state << 7U;
    *state ^= *state >> 9U;
    *state ^= *state << 8U;
    return *state;
}

/**
 * @brief Compares two unsigned bignum records numerically.
 * @param[in] left Borrowed normalized or zero value.
 * @param[in] right Borrowed normalized or zero value.
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
 * @brief Checks every normalized-output and range postcondition.
 * @param[in] output Borrowed record returned after a successful sample.
 * @param[in] bound Borrowed normalized positive exclusive upper bound.
 * @return One when the complete public postcondition holds, otherwise zero.
 */
static int valid_sample(const bignum_t *output, const bignum_t *bound)
{
    if (output->len > BIGNUM_CAPACITY) return 0;
    if (output->len > 0U && output->words[output->len - 1U] == UINT64_C(0)) return 0;
    for (size_t index = output->len; index < BIGNUM_CAPACITY; ++index) {
        if (output->words[index] != UINT64_C(0)) return 0;
    }
    return compare_values(output, bound) < 0;
}

/**
 * @brief Exercises 20,000 deterministic random normalized range endpoints.
 * @details The fixed seed and iteration count make failure reproduction exact.
 * Each bound has 1 through 32 active words and an explicitly nonzero top word.
 * The oracle is independent of random bytes: it accepts every in-range value
 * but rejects malformed output, an altered input, or any out-of-range value.
 * @return One when all generated cases satisfy the contract, otherwise zero.
 */
static int test_fuzzed_ranges_against_invariants(void)
{
    uint64_t state = UINT64_C(0xD1B54A32D192ED03);

    for (size_t iteration = 0U; iteration < 20000U; ++iteration) {
        bignum_t bound;
        bignum_t snapshot;
        bignum_t output;
        const size_t length = 1U + (size_t)(next_fixture_word(&state) % BIGNUM_CAPACITY);

        memset(&bound, 0, sizeof(bound));
        for (size_t word = 0U; word < length; ++word) bound.words[word] = next_fixture_word(&state);
        bound.words[length - 1U] |= UINT64_C(1);
        bound.len = length;
        snapshot = bound;
        memset(&output, 0xC3, sizeof(output));

        if (bignum_random(&output, &bound) != BIGNUM_RANDOM_SUCCESS ||
            !valid_sample(&output, &bound) || memcmp(&bound, &snapshot, sizeof(bound)) != 0) {
            return 0;
        }
    }
    return 1;
}

/**
 * @brief Verifies representation boundaries including the full 2048-bit range.
 * @details The cases use exact powers of two. The result may vary, but every
 * output must fit the one-word, 65-bit, and full-capacity half-open intervals
 * and must not expose stale tail words from prior stack candidates.
 * @return One when all 384 boundary samples obey the postcondition, otherwise zero.
 */
static int test_capacity_boundaries(void)
{
    const size_t lengths[] = { 1U, 2U, BIGNUM_CAPACITY };

    for (size_t case_index = 0U; case_index < 3U; ++case_index) {
        bignum_t bound;
        const size_t length = lengths[case_index];

        memset(&bound, 0, sizeof(bound));
        bound.words[length - 1U] = UINT64_C(1);
        bound.len = length;
        for (size_t iteration = 0U; iteration < 128U; ++iteration) {
            bignum_t output;

            memset(&output, 0x7E, sizeof(output));
            if (bignum_random(&output, &bound) != BIGNUM_RANDOM_SUCCESS ||
                !valid_sample(&output, &bound)) return 0;
        }
    }
    return 1;
}

/**
 * @brief Runs deterministic property and boundary regression scenarios.
 * @return ISO C process success only when every invariant-oriented test passes.
 */
int main(void)
{
    int failed = 0;

    printf("--- Starting extended bignum_random tests ---\n");
    if (test_fuzzed_ranges_against_invariants()) printf("test_fuzzed_ranges_against_invariants: PASSED\n");
    else { printf("test_fuzzed_ranges_against_invariants: FAILED\n"); ++failed; }
    if (test_capacity_boundaries()) printf("test_capacity_boundaries: PASSED\n");
    else { printf("test_capacity_boundaries: FAILED\n"); ++failed; }
    printf("--- Extended bignum_random tests: %s ---\n", failed == 0 ? "PASSED" : "FAILED");
    return failed == 0 ? 0 : 1;
}
