/**
 * @file bignum_ctr_drbg_os_entropy.h
 * @brief Production Linux entropy-provider adapter for candidate Track B.
 * @details This adapter reads from the Linux urandom source through
 * getrandom(2), retries EINTR, accepts short reads, and maps all source
 * failures to a named non-success status. It retains no state and is not a
 * deterministic test provider. Entropy-source validation remains a separate
 * SP 800-90B and operating-environment responsibility.
 */
#ifndef BIGNUM_CTR_DRBG_OS_ENTROPY_H
#define BIGNUM_CTR_DRBG_OS_ENTROPY_H

#include "bignum_ctr_drbg_context.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fills a provider buffer from Linux getrandom(2), urandom source.
 * @param provider_context [in] Ignored; must be NULL for the production adapter.
 * @param out [out] Complete caller-owned output buffer.
 * @param out_len [in] Number of bytes requested; the DRBG context uses 32.
 * @return SUCCESS only after all bytes are read; NULL/invalid arguments return
 * ERROR_NULL_ARG or ERROR_INPUT; syscall failures return ERROR_ENTROPY_SOURCE.
 * @post No provider state is retained; caller health checks remain responsible
 * for continuous entropy-source health testing.
 * @thread_safety Stateless and safe for concurrent calls.
 */
bignum_ctr_drbg_status_t bignum_ctr_drbg_os_entropy_provider(
    void *provider_context, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* BIGNUM_CTR_DRBG_OS_ENTROPY_H */
