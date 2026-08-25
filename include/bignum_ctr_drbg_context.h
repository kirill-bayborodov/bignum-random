/**
 * @file bignum_ctr_drbg_context.h
 * @brief Caller-allocated Approved-service context boundary for candidate Track B.
 * @details The context object is allocated and owned by the caller, but its
 * storage is intentionally opaque: callers must use only these functions and
 * must not inspect or modify the backing bytes. The service owns no heap
 * memory and retains no provider pointer after context zeroization.
 */
#ifndef BIGNUM_CTR_DRBG_CONTEXT_H
#define BIGNUM_CTR_DRBG_CONTEXT_H

#include "bignum_ctr_drbg_module.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Supplies exactly one entropy input to an Approved context operation.
 * @details The callback is synchronous. It receives a caller-owned output
 * buffer and must fill all `out_len` bytes or return a non-success status.
 * The provider context is borrowed and is never freed by this library.
 * @param provider_context [in] Provider-owned state; may be NULL only when
 * the provider contract explicitly permits it.
 * @param out [out] Caller-allocated entropy buffer owned by the library for
 * the duration of the callback; valid for exactly `out_len` bytes.
 * @param out_len [in] Always `BIGNUM_CTR_DRBG_KEY_BYTES` for this API.
 * @return `BIGNUM_CTR_DRBG_SUCCESS` only when every output byte was written;
 * otherwise a failure status and the context enters ERROR.
 * @thread_safety The provider defines its own concurrency contract; this
 * callback is not invoked concurrently for one context.
 */
typedef bignum_ctr_drbg_status_t (*bignum_ctr_drbg_entropy_provider_fn)(
    void *provider_context, uint8_t *out, size_t out_len);

/**
 * @brief Caller-owned, opaque-style storage for one Approved context.
 * @details The caller allocates this object with automatic, static, or heap
 * storage and retains ownership. The implementation uses only the private
 * bytes; callers must not copy, compare, or modify an initialized object.
 * A context is valid after `init` and remains usable until uninstantiate.
 */
typedef struct bignum_ctr_drbg_context {
    max_align_t alignment; /**< Alignment anchor; caller must preserve object alignment. */
    unsigned char storage[sizeof(bignum_ctr_drbg_module_ctx)]; /**< Private lifecycle and DRBG storage; implementation-owned after init. */
    uint64_t cookie; /**< Initialization marker; callers must not inspect or modify it. */
    uint64_t owner_process_id; /**< Creator process identifier; forked copies are fail-closed. */
} bignum_ctr_drbg_context_t;

/**
 * @brief Returns the required caller allocation size for one context.
 * @return `sizeof(bignum_ctr_drbg_context_t)` bytes.
 * @thread_safety Pure query; safe concurrently.
 */
size_t bignum_ctr_drbg_context_size(void);

/**
 * @brief Initializes caller-owned context storage to UNINITIALIZED.
 * @param context [out] Caller-allocated, correctly aligned context object.
 * @return Named status; NULL returns `BIGNUM_CTR_DRBG_ERROR_NULL_ARG`.
 * @post The context contains no prior state and requires startup.
 * @warning Reinitialization zeroizes prior bytes and invalidates any prior provider association.
 * @thread_safety Not safe concurrently with operations on the same context.
 */
bignum_ctr_drbg_status_t bignum_ctr_drbg_context_init(bignum_ctr_drbg_context_t *context);

/**
 * @brief Runs image-integrity gate and power-up self-tests.
 * @param context [in,out] Initialized caller-owned context.
 * @param image_integrity_verified [in] Nonzero only after an external exact-image verification succeeds.
 * @return `BIGNUM_CTR_DRBG_SUCCESS` in READY; failure latches ERROR.
 * @post No provider is called and no entropy is retained.
 * @thread_safety Not safe concurrently on the same context.
 */
bignum_ctr_drbg_status_t bignum_ctr_drbg_context_startup(
    bignum_ctr_drbg_context_t *context, int image_integrity_verified);

/**
 * @brief Instantiates the DRBG using entropy obtained from the provider.
 * @param context [in,out] READY context.
 * @param provider [in] Synchronous borrowed callback; non-NULL.
 * @param provider_context [in] Borrowed provider state; not retained after uninstantiate.
 * @param nonce [in] Exactly 16 nonce bytes, borrowed for the call.
 * @param personalization [in] Optional borrowed personalization bytes.
 * @param personalization_len [in] Length not exceeding the candidate limit.
 * @return `BIGNUM_CTR_DRBG_SUCCESS` after provider-filled entropy and instantiate; provider or DRBG failure latches ERROR.
 * @post The context retains only DRBG state, never the provider pointer.
 * @thread_safety Not safe concurrently on the same context.
 */
bignum_ctr_drbg_status_t bignum_ctr_drbg_context_instantiate(
    bignum_ctr_drbg_context_t *context,
    bignum_ctr_drbg_entropy_provider_fn provider, void *provider_context,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *personalization, size_t personalization_len);

/**
 * @brief Reseeds the context with one provider entropy input.
 * @param context [in,out] READY or RESEED_REQUIRED context.
 * @param provider [in] Synchronous borrowed callback; non-NULL.
 * @param provider_context [in] Borrowed provider state.
 * @return `BIGNUM_CTR_DRBG_SUCCESS` and READY, or a failure with ERROR.
 * @post Provider output and temporary buffers are zeroized before return.
 * @thread_safety Not safe concurrently on the same context.
 */
bignum_ctr_drbg_status_t bignum_ctr_drbg_context_reseed(
    bignum_ctr_drbg_context_t *context,
    bignum_ctr_drbg_entropy_provider_fn provider, void *provider_context);

/**
 * @brief Generates bytes through the initialized DRBG.
 * @param context [in,out] READY context.
 * @param out [out] Caller-allocated output; unchanged on failure.
 * @param out_len [in] At most the candidate request limit.
 * @return `BIGNUM_CTR_DRBG_SUCCESS`, `BIGNUM_CTR_DRBG_ERROR_RESEED_REQUIRED`, or a named failure status.
 * @post No provider is called and no raw getrandom fallback is reachable.
 * @thread_safety Not safe concurrently on the same context.
 */
bignum_ctr_drbg_status_t bignum_ctr_drbg_context_generate(
    bignum_ctr_drbg_context_t *context, uint8_t *out, size_t out_len,
    const uint8_t *additional_input, size_t additional_input_len);

/**
 * @brief Zeroizes the context and marks it ZEROIZED.
 * @param context [in,out] Caller-owned context; NULL is ignored.
 * @post All DRBG state is zeroized and subsequent service operations fail.
 * @thread_safety Not safe concurrently on the same context.
 */
void bignum_ctr_drbg_context_uninstantiate(bignum_ctr_drbg_context_t *context);

/**
 * @brief Returns the observable lifecycle state.
 * @param context [in] Caller-owned initialized context; NULL maps to ERROR.
 * @return A named `bignum_ctr_drbg_module_state_t` value.
 * @thread_safety Safe for a stable context; concurrent mutation is forbidden.
 */
bignum_ctr_drbg_module_state_t bignum_ctr_drbg_context_state(
    const bignum_ctr_drbg_context_t *context);

#ifdef __cplusplus
}
#endif

#endif /* BIGNUM_CTR_DRBG_CONTEXT_H */
