/**
 * @file bignum_random.c
 * @brief C11 reference implementation of bounded cryptographic bignum sampling.
 * @details This Linux implementation obtains entropy only through `getrandom(2)`
 * with its default urandom source. It validates the caller's normalized positive
 * upper bound, draws a full-width candidate, clears bits above the bound's bit
 * length, and retries if the candidate is not strictly smaller than the bound.
 * This rejection method preserves a uniform distribution for every positive
 * bound and avoids the modulo bias of `random_value % upper_bound`.
 *
 * The routine keeps all candidate state on the stack. It never changes the
 * caller-owned output until it has an accepted normalized candidate, so every
 * documented error path is transactional. The C source deliberately prioritizes
 * explicit validation and readable correctness over the later YASM fast path.
 *
 * @version 1.0.0
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "bignum_random.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>
#include <sys/types.h>

/**
 * @brief Validates the fixed-capacity normalized upper-bound representation.
 * @details A length above capacity would make the core record malformed. A
 * zero length describes the zero value and therefore an empty `[0, 0)` range.
 * For a nonzero length, the final active word must be nonzero; inactive tail
 * words are deliberately ignored because they are outside the bignum value.
 * @param[in] upper_bound Borrowed non-NULL candidate range endpoint.
 * @return `BIGNUM_RANDOM_SUCCESS` for a normalized positive bound, otherwise
 * the precise named status; no caller-owned object is modified.
 */
static bignum_random_status_t validate_upper_bound(const bignum_t *upper_bound)
{
    if (upper_bound->len > BIGNUM_CAPACITY) return BIGNUM_RANDOM_ERROR_LENGTH;
    if (upper_bound->len == 0U) return BIGNUM_RANDOM_ERROR_RANGE;
    if (upper_bound->words[upper_bound->len - 1U] == UINT64_C(0)) {
        return BIGNUM_RANDOM_ERROR_NORMALIZATION;
    }
    return BIGNUM_RANDOM_SUCCESS;
}

/**
 * @brief Counts the significant bits in one nonzero 64-bit word.
 * @details The loop is bounded by the word width and is used only for the
 * highest active word of a validated bound. It avoids compiler-specific count-
 * leading-zero intrinsics in the portable C11 reference implementation.
 * @param[in] word Nonzero most-significant bignum word.
 * @return Integer bit length in the closed range `[1, 64]`.
 */
static size_t word_bit_length(uint64_t word)
{
    size_t bits = 0U;

    while (word != UINT64_C(0)) {
        ++bits;
        word >>= 1U;
    }
    return bits;
}

/**
 * @brief Fills a caller-provided byte span from the Linux cryptographic RNG.
 * @details `getrandom(2)` can report a short read or be interrupted. This loop
 * advances only by the bytes actually returned, retries `EINTR`, and reports a
 * named entropy failure for every other result. The module requests at most
 * `BIGNUM_CAPACITY * sizeof(uint64_t)` bytes, which is 256 bytes for the core
 * representation, but still verifies the return value rather than relying on
 * the Linux small-read guarantee.
 * @param[out] bytes Caller-owned writable byte storage of `count` bytes; it is
 * not retained after return and may be NULL only when `count` is zero.
 * @param[in] count Number of entropy bytes requested.
 * @return `BIGNUM_RANDOM_SUCCESS` only when all bytes were written; otherwise
 * `BIGNUM_RANDOM_ERROR_ENTROPY`. Partial stack data is never published.
 */
static bignum_random_status_t fill_entropy(unsigned char *bytes, size_t count)
{
    size_t filled = 0U;

    while (filled < count) {
        const ssize_t received = getrandom(bytes + filled, count - filled, 0U);

        if (received > 0) {
            filled += (size_t)received;
            continue;
        }
        if (received < 0 && errno == EINTR) continue;
        return BIGNUM_RANDOM_ERROR_ENTROPY;
    }
    return BIGNUM_RANDOM_SUCCESS;
}

/**
 * @brief Compares a full candidate word array with a normalized upper bound.
 * @details Both operands are interpreted as unsigned little-endian arrays of
 * exactly `upper_bound->len` words. Scanning from the highest word downward
 * ensures numeric rather than lexicographic little-endian ordering. A zero
 * candidate top word is valid and naturally compares below a nonzero bound.
 * @param[in] candidate Candidate words with at least `upper_bound->len` items.
 * @param[in] upper_bound Borrowed validated positive bound.
 * @return A negative value when candidate is smaller, zero when equal, and a
 * positive value when candidate is greater; neither input is modified.
 */
static int compare_candidate(const uint64_t *candidate, const bignum_t *upper_bound)
{
    size_t index = upper_bound->len;

    while (index > 0U) {
        --index;
        if (candidate[index] < upper_bound->words[index]) return -1;
        if (candidate[index] > upper_bound->words[index]) return 1;
    }
    return 0;
}

/**
 * @brief Removes zero high words from an accepted candidate record.
 * @details Entropy is initially written across the upper bound's active word
 * span. An accepted value can have leading zero words, including the sampled
 * zero, so normalization restores the `bignum_t` representation invariant
 * before the record is committed to the caller.
 * @param[in,out] value Stack-owned accepted candidate with zeroed inactive tail.
 * @return No status is required because the bounded loop cannot fail.
 */
static void normalize_candidate(bignum_t *value)
{
    while (value->len > 0U && value->words[value->len - 1U] == UINT64_C(0)) {
        --value->len;
    }
}

bignum_random_status_t bignum_random(bignum_t *out, const bignum_t *upper_bound)
{
    bignum_random_status_t status;
    bignum_t candidate;
    const size_t active_words = upper_bound != NULL ? upper_bound->len : 0U;
    size_t top_bits;
    uint64_t top_mask;

    if (out == NULL || upper_bound == NULL) return BIGNUM_RANDOM_ERROR_NULL_ARG;
    if (out == upper_bound) return BIGNUM_RANDOM_ERROR_ALIAS;

    status = validate_upper_bound(upper_bound);
    if (status != BIGNUM_RANDOM_SUCCESS) return status;

    top_bits = word_bit_length(upper_bound->words[active_words - 1U]);
    top_mask = top_bits == 64U ? UINT64_MAX : ((UINT64_C(1) << top_bits) - UINT64_C(1));

    for (;;) {
        /* Zeroing every record prevents stale candidate tail words from being
         * published and makes normalization independent of prior rejections. */
        memset(&candidate, 0, sizeof(candidate));
        status = fill_entropy((unsigned char *)candidate.words,
                              active_words * sizeof(candidate.words[0]));
        if (status != BIGNUM_RANDOM_SUCCESS) return status;

        /* Restrict candidates to the exact bit domain `[0, 2^k)`, where `k`
         * is the bound bit length. Rejecting values >= bound is then unbiased. */
        candidate.words[active_words - 1U] &= top_mask;
        if (compare_candidate(candidate.words, upper_bound) >= 0) continue;

        candidate.len = active_words;
        normalize_candidate(&candidate);
        *out = candidate;
        return BIGNUM_RANDOM_SUCCESS;
    }
}
