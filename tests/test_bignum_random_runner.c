/**
 * @file test_bignum_random_runner.c
 * @brief Distribution integration smoke test for bignum_random.
 * @details The Makefile copies and compiles this source against the generated
 * object-file and static-library distributions. Bound one is intentionally the
 * complete deterministic API example: independently of entropy, the only legal
 * sample in `[0, 1)` is the normalized zero bignum.
 */
#include "bignum_random.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Validates the distributed public header and linked implementation.
 * @details The test checks the named success status, exact deterministic value,
 * and input preservation after one bounded sample.
 * @return ISO C process success when distribution integration passes.
 */
int main(void)
{
    bignum_t bound;
    bignum_t output;
    bignum_t snapshot;

    memset(&bound, 0, sizeof(bound));
    bound.words[0] = UINT64_C(1);
    bound.len = 1U;
    snapshot = bound;
    memset(&output, 0xBC, sizeof(output));

    if (bignum_random(&output, &bound) != BIGNUM_RANDOM_SUCCESS ||
        output.len != 0U || output.words[0] != UINT64_C(0) ||
        memcmp(&bound, &snapshot, sizeof(bound)) != 0) {
        fprintf(stderr, "bignum_random distribution runner: FAILED\n");
        return 1;
    }
    printf("bignum_random distribution runner: PASSED\n");
    return 0;
}
