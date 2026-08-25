/**
 * @file bignum_ctr_drbg_os_entropy.c
 * @brief Stateless Linux getrandom(2) entropy-provider implementation.
 */
#define _GNU_SOURCE
#include "internal/bignum_ctr_drbg_os_entropy.h"

#include <errno.h>
#include <sys/random.h>
#include <sys/types.h>

/**
 * @brief Reads a complete entropy buffer from the Linux urandom source.
 * @param provider_context [in] Must be NULL; no provider state is accepted.
 * @param out [out] Complete writable output range.
 * @param out_len [in] Requested byte count.
 * @return SUCCESS only after the complete range is filled.
 */
bignum_ctr_drbg_status_t bignum_ctr_drbg_os_entropy_provider(
    void *provider_context, uint8_t *out, size_t out_len)
{
    size_t offset = 0U;
    if (provider_context != NULL || out == NULL) return BIGNUM_CTR_DRBG_ERROR_NULL_ARG;
    if (out_len == 0U) return BIGNUM_CTR_DRBG_ERROR_INPUT;
    while (offset < out_len) {
        ssize_t received = getrandom(out + offset, out_len - offset, 0U);
        if (received > 0) {
            offset += (size_t)received;
        } else if (received < 0 && errno == EINTR) {
            continue;
        } else {
            return BIGNUM_CTR_DRBG_ERROR_ENTROPY_SOURCE;
        }
    }
    return BIGNUM_CTR_DRBG_SUCCESS;
}
