/**
 * @file bignum_ctr_drbg_service.c
 * @brief Controlled production-facing candidate service adapter.
 */
#include "internal/bignum_ctr_drbg_service.h"
#include "internal/bignum_ctr_drbg_os_entropy.h"

bignum_ctr_drbg_status_t bignum_ctr_drbg_service_init(
    bignum_ctr_drbg_context_t *context)
{
    return bignum_ctr_drbg_context_init(context);
}

bignum_ctr_drbg_status_t bignum_ctr_drbg_service_startup(
    bignum_ctr_drbg_context_t *context, int image_integrity_verified)
{
    return bignum_ctr_drbg_context_startup(context, image_integrity_verified);
}

bignum_ctr_drbg_status_t bignum_ctr_drbg_service_instantiate(
    bignum_ctr_drbg_context_t *context,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *personalization, size_t personalization_len)
{
    return bignum_ctr_drbg_context_instantiate(
        context, bignum_ctr_drbg_os_entropy_provider, NULL,
        nonce, nonce_len, personalization, personalization_len);
}

bignum_ctr_drbg_status_t bignum_ctr_drbg_service_reseed(
    bignum_ctr_drbg_context_t *context)
{
    return bignum_ctr_drbg_context_reseed(
        context, bignum_ctr_drbg_os_entropy_provider, NULL);
}

bignum_ctr_drbg_status_t bignum_ctr_drbg_service_generate(
    bignum_ctr_drbg_context_t *context, uint8_t *out, size_t out_len,
    const uint8_t *additional_input, size_t additional_input_len)
{
    return bignum_ctr_drbg_context_generate(
        context, out, out_len, additional_input, additional_input_len);
}

void bignum_ctr_drbg_service_uninstantiate(bignum_ctr_drbg_context_t *context)
{
    bignum_ctr_drbg_context_uninstantiate(context);
}

bignum_ctr_drbg_module_state_t bignum_ctr_drbg_service_state(
    const bignum_ctr_drbg_context_t *context)
{
    return bignum_ctr_drbg_context_state(context);
}
