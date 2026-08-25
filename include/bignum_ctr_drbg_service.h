/**
 * @file bignum_ctr_drbg_service.h
 * @brief Candidate production-facing DRBG service boundary.
 * @details This API deliberately exposes no entropy callback, provider context,
 * expanded AES key, health state, or test hook. It binds entropy acquisition
 * to the controlled OS adapter. It is an engineering boundary, not a FIPS
 * validation claim.
 */
#ifndef BIGNUM_CTR_DRBG_SERVICE_H
#define BIGNUM_CTR_DRBG_SERVICE_H

#include "bignum_ctr_drbg_context.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Initializes caller-owned service storage. */
bignum_ctr_drbg_status_t bignum_ctr_drbg_service_init(
    bignum_ctr_drbg_context_t *context);

/** @brief Runs external image-integrity gate and power-up KAT. */
bignum_ctr_drbg_status_t bignum_ctr_drbg_service_startup(
    bignum_ctr_drbg_context_t *context, int image_integrity_verified);

/** @brief Instantiates using only the bound production OS entropy adapter. */
bignum_ctr_drbg_status_t bignum_ctr_drbg_service_instantiate(
    bignum_ctr_drbg_context_t *context,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *personalization, size_t personalization_len);

/** @brief Reseeds using only the bound production OS entropy adapter. */
bignum_ctr_drbg_status_t bignum_ctr_drbg_service_reseed(
    bignum_ctr_drbg_context_t *context);

/** @brief Generates bytes from the initialized candidate service. */
bignum_ctr_drbg_status_t bignum_ctr_drbg_service_generate(
    bignum_ctr_drbg_context_t *context, uint8_t *out, size_t out_len,
    const uint8_t *additional_input, size_t additional_input_len);

/** @brief Zeroizes service storage and marks it ZEROIZED. */
void bignum_ctr_drbg_service_uninstantiate(
    bignum_ctr_drbg_context_t *context);

/** @brief Returns the service lifecycle state. */
bignum_ctr_drbg_module_state_t bignum_ctr_drbg_service_state(
    const bignum_ctr_drbg_context_t *context);

#ifdef __cplusplus
}
#endif

#endif /* BIGNUM_CTR_DRBG_SERVICE_H */
