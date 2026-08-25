/**
 * @file bignum_ctr_drbg_context.c
 * @brief Implements the caller-allocated entropy-provider boundary.
 * @details The adapter keeps provider callbacks and provider state transient:
 * they are used only during instantiate/reseed and are never stored in the
 * context. Entropy buffers are zeroized on every return path. A provider or
 * DRBG failure clears the DRBG state and latches the module in ERROR.
 */
#include "bignum_ctr_drbg_context.h"

#include <stddef.h>
#include <string.h>

#define BIGNUM_CONTEXT_COOKIE UINT64_C(0x425247434f4e5445)

_Static_assert(offsetof(bignum_ctr_drbg_context_t, storage) % _Alignof(bignum_ctr_drbg_module_ctx) == 0,
               "caller context storage must preserve module alignment");
_Static_assert(sizeof(((bignum_ctr_drbg_context_t *)0)->storage) >= sizeof(bignum_ctr_drbg_module_ctx),
               "caller context storage must contain the module context");

/**
 * @brief Clears sensitive bytes through a volatile byte store.
 * @param memory [in,out] Borrowed writable byte range.
 * @param length [in] Number of bytes to clear.
 * @post Every byte in the range is zero.
 */
static void secure_zero(void *memory, size_t length)
{
    volatile uint8_t *p = (volatile uint8_t *)memory;
    while (length-- != 0U) *p++ = 0U;
}

/** @brief Maps valid opaque storage to its private module object. */
static bignum_ctr_drbg_module_ctx *module_of(bignum_ctr_drbg_context_t *context)
{
    return (bignum_ctr_drbg_module_ctx *)(void *)context->storage;
}

/** @brief Maps valid const opaque storage to its private module object. */
static const bignum_ctr_drbg_module_ctx *module_const_of(const bignum_ctr_drbg_context_t *context)
{
    return (const bignum_ctr_drbg_module_ctx *)(const void *)context->storage;
}

/**
 * @brief Checks the private initialization marker.
 * @return Nonzero only for context storage initialized by this adapter.
 */
static int context_is_initialized(const bignum_ctr_drbg_context_t *context)
{
    return context != NULL && context->cookie == BIGNUM_CONTEXT_COOKIE;
}

/**
 * @brief Zeroizes partial DRBG state and latches module ERROR.
 * @param module [in,out] Private module object owned by the context.
 * @post No prior DRBG state remains and all service calls are blocked.
 */
static void latch_provider_failure(bignum_ctr_drbg_module_ctx *module)
{
    bignum_ctr_drbg_uninstantiate(&module->drbg);
    module->state = BIGNUM_CTR_DRBG_MODULE_ERROR;
}

/**
 * @brief Obtains one fixed-size entropy input from a borrowed provider.
 * @param provider [in] Synchronous provider callback.
 * @param provider_context [in] Borrowed provider state.
 * @param entropy [out] Caller-owned temporary 32-byte buffer.
 * @return Provider status; no partial success is accepted.
 */
static bignum_ctr_drbg_status_t obtain_entropy(
    bignum_ctr_drbg_entropy_provider_fn provider, void *provider_context,
    uint8_t entropy[BIGNUM_CTR_DRBG_KEY_BYTES])
{
    bignum_ctr_drbg_status_t status;
    if (provider == NULL) return BIGNUM_CTR_DRBG_ERROR_NULL_ARG;
    status = provider(provider_context, entropy, BIGNUM_CTR_DRBG_KEY_BYTES);
    return status == BIGNUM_CTR_DRBG_SUCCESS ? BIGNUM_CTR_DRBG_SUCCESS : status;
}

size_t bignum_ctr_drbg_context_size(void)
{
    return sizeof(bignum_ctr_drbg_context_t);
}

bignum_ctr_drbg_status_t bignum_ctr_drbg_context_init(bignum_ctr_drbg_context_t *context)
{
    if (context == NULL) return BIGNUM_CTR_DRBG_ERROR_NULL_ARG;
    secure_zero(context, sizeof(*context));
    context->cookie = BIGNUM_CONTEXT_COOKIE;
    return BIGNUM_CTR_DRBG_SUCCESS;
}

bignum_ctr_drbg_status_t bignum_ctr_drbg_context_startup(
    bignum_ctr_drbg_context_t *context, int image_integrity_verified)
{
    if (!context_is_initialized(context)) return BIGNUM_CTR_DRBG_ERROR_STATE;
    return bignum_ctr_drbg_module_startup(module_of(context), image_integrity_verified);
}

bignum_ctr_drbg_status_t bignum_ctr_drbg_context_instantiate(
    bignum_ctr_drbg_context_t *context,
    bignum_ctr_drbg_entropy_provider_fn provider, void *provider_context,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *personalization, size_t personalization_len)
{
    uint8_t entropy[BIGNUM_CTR_DRBG_KEY_BYTES];
    bignum_ctr_drbg_status_t status;
    bignum_ctr_drbg_module_ctx *module;
    if (!context_is_initialized(context)) return BIGNUM_CTR_DRBG_ERROR_STATE;
    module = module_of(context);
    if (module->state != BIGNUM_CTR_DRBG_MODULE_READY) return BIGNUM_CTR_DRBG_ERROR_STATE;
    status = obtain_entropy(provider, provider_context, entropy);
    if (status != BIGNUM_CTR_DRBG_SUCCESS) {
        latch_provider_failure(module);
        secure_zero(entropy, sizeof(entropy));
        return status;
    }
    status = bignum_ctr_drbg_module_instantiate(module, entropy, sizeof(entropy), nonce, nonce_len, personalization, personalization_len);
    secure_zero(entropy, sizeof(entropy));
    return status;
}

bignum_ctr_drbg_status_t bignum_ctr_drbg_context_reseed(
    bignum_ctr_drbg_context_t *context,
    bignum_ctr_drbg_entropy_provider_fn provider, void *provider_context)
{
    uint8_t entropy[BIGNUM_CTR_DRBG_KEY_BYTES];
    bignum_ctr_drbg_status_t status;
    bignum_ctr_drbg_module_ctx *module;
    if (!context_is_initialized(context)) return BIGNUM_CTR_DRBG_ERROR_STATE;
    module = module_of(context);
    if (module->state != BIGNUM_CTR_DRBG_MODULE_READY &&
        module->state != BIGNUM_CTR_DRBG_MODULE_RESEED_REQUIRED) return BIGNUM_CTR_DRBG_ERROR_STATE;
    status = obtain_entropy(provider, provider_context, entropy);
    if (status != BIGNUM_CTR_DRBG_SUCCESS) {
        latch_provider_failure(module);
        secure_zero(entropy, sizeof(entropy));
        return status;
    }
    status = bignum_ctr_drbg_module_reseed(module, entropy, sizeof(entropy), NULL, 0U);
    secure_zero(entropy, sizeof(entropy));
    return status;
}

bignum_ctr_drbg_status_t bignum_ctr_drbg_context_generate(
    bignum_ctr_drbg_context_t *context, uint8_t *out, size_t out_len,
    const uint8_t *additional_input, size_t additional_input_len)
{
    if (!context_is_initialized(context)) return BIGNUM_CTR_DRBG_ERROR_STATE;
    return bignum_ctr_drbg_module_generate(module_of(context), out, out_len, additional_input, additional_input_len);
}

void bignum_ctr_drbg_context_uninstantiate(bignum_ctr_drbg_context_t *context)
{
    bignum_ctr_drbg_module_ctx *module;
    if (context == NULL) return;
    if (!context_is_initialized(context)) {
        secure_zero(context, sizeof(*context));
        return;
    }
    module = module_of(context);
    bignum_ctr_drbg_module_uninstantiate(module);
    secure_zero(context->storage, sizeof(context->storage));
    module = module_of(context);
    module->state = BIGNUM_CTR_DRBG_MODULE_ZEROIZED;
}

bignum_ctr_drbg_module_state_t bignum_ctr_drbg_context_state(
    const bignum_ctr_drbg_context_t *context)
{
    if (!context_is_initialized(context)) return BIGNUM_CTR_DRBG_MODULE_ERROR;
    return bignum_ctr_drbg_module_state(module_const_of(context));
}
