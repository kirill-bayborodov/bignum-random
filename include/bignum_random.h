/**
 * @file bignum_random.h
 * @brief Public API for a cryptographically random bounded bignum.
 * @details The module samples a uniformly distributed unsigned `bignum_t` from
 * the half-open interval `[0, upper_bound)`. It uses the Linux `getrandom(2)`
 * urandom source and rejection sampling rather than a remainder reduction, so
 * a non-power-of-two bound does not introduce modulo bias. The API owns no
 * memory, does not retain entropy bytes, and modifies the
 * caller-owned output only after a valid sample has been produced.
 *
 * The implementation targets Linux on x86-64. The `upper_bound` input must use
 * the normalized fixed-capacity representation defined by `bignum.h`: zero has
 * `len == 0`, and a nonzero value has `1 <= len <= BIGNUM_CAPACITY` with a
 * nonzero most-significant word. Independent calls are reentrant; concurrent
 * access to an object that another thread writes still requires caller-side
 * synchronization.
 *
 * @version 1.0.0
 */
#ifndef BIGNUM_RANDOM_H
#define BIGNUM_RANDOM_H

#include <bignum.h>

#ifndef BIGNUM_CAPACITY
#error "bignum.h must define BIGNUM_CAPACITY"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Reports the outcome of bounded cryptographic random sampling.
 * @details Success is the only status that writes `*out`. Every failure status
 * preserves the complete caller-owned output record, enabling a caller to
 * retry after correcting an input or a transient entropy-source failure.
 */
typedef enum bignum_random_status {
    BIGNUM_RANDOM_SUCCESS = 0, /**< A uniform sample was stored in `*out`; `0 <= *out < *upper_bound`. */
    BIGNUM_RANDOM_ERROR_NULL_ARG = -1, /**< `out` or `upper_bound` is NULL; no object is dereferenced and `*out` is unchanged when valid. */
    BIGNUM_RANDOM_ERROR_RANGE = -2, /**< `upper_bound` represents zero; the interval is empty and `*out` is unchanged. */
    BIGNUM_RANDOM_ERROR_LENGTH = -3, /**< `upper_bound->len` exceeds fixed capacity; `*out` is unchanged. */
    BIGNUM_RANDOM_ERROR_NORMALIZATION = -4, /**< A nonzero bound has a zero most-significant word; `*out` is unchanged. */
    BIGNUM_RANDOM_ERROR_ENTROPY = -5, /**< Linux `getrandom(2)` could not fill a candidate; `*out` is unchanged and the call may be retried. */
    BIGNUM_RANDOM_ERROR_ALIAS = -6 /**< `out` aliases `upper_bound`; both records are unchanged. */
} bignum_random_status_t;

/**
 * @brief Samples a cryptographically random unsigned bignum in `[0, upper_bound)`.
 * @details The function validates the bound before obtaining entropy. It derives
 * the bit length of the normalized upper bound, requests exactly enough random
 * bytes from Linux `getrandom(2)`, masks unused high bits, and rejects any
 * candidate not strictly smaller than `upper_bound`. Repeating those steps until
 * acceptance gives every value in the requested interval the same probability.
 * Candidate storage is automatic and is copied to `*out` only after acceptance.
 *
 * @param[out] out Caller-owned writable destination. It must point to one live
 * `bignum_t`; it may not alias `upper_bound`. The function writes a normalized
 * value only with `BIGNUM_RANDOM_SUCCESS` and otherwise preserves all bytes.
 * @param[in] upper_bound Caller-owned borrowed normalized positive bound. The
 * pointed-to object is read only for the duration of the call and is never
 * modified. A zero bound, a length above `BIGNUM_CAPACITY`, an unnormalized
 * nonzero bound, or aliasing with `out` is rejected.
 * @return A named `bignum_random_status_t` status. On success `*out` is a
 * normalized uniformly distributed value in `[0, *upper_bound)`; on failure
 * `*out` and `*upper_bound` are unchanged.
 * @pre `out` and `upper_bound` designate non-overlapping live `bignum_t`
 * objects for the whole call when neither is NULL. Equal pointers are detected
 * and rejected with `BIGNUM_RANDOM_ERROR_ALIAS`.
 * @post Successful output has `len == 0` exactly when its sampled value is
 * zero; otherwise `words[len - 1] != 0` and all words at or above `len` are
 * zero.
 * @warning The call may block before Linux initializes its urandom source.
 * Rejection sampling has data-dependent iteration count and must not be used
 * where that timing is itself secret-sensitive.
 * @thread_safety Reentrant and safe for independent concurrent calls; no
 * mutable global state, file descriptor, or heap allocation is used.
 * @complexity O(BIGNUM_CAPACITY) time and O(BIGNUM_CAPACITY) automatic space
 * per candidate; expected candidate count is below two for the selected bit
 * length and any positive bound.
 */
bignum_random_status_t bignum_random(bignum_t *out, const bignum_t *upper_bound);

#ifdef __cplusplus
}
#endif

#endif /* BIGNUM_RANDOM_H */
