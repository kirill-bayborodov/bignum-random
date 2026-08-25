/**
 * @file bignum_ctr_drbg_module.h
 * @brief Candidate fail-closed lifecycle wrapper around the C11 CTR_DRBG.
 * @details This is an engineering boundary for Track B. The caller must
 * provide an independently verified image-integrity result to startup. A
 * false result or a KAT failure latches ERROR and inhibits all services.
 * This interface is not evidence of FIPS validation.
 */
#ifndef BIGNUM_CTR_DRBG_MODULE_H
#define BIGNUM_CTR_DRBG_MODULE_H

#include "bignum_ctr_drbg.h"

typedef enum bignum_ctr_drbg_module_state {
    BIGNUM_CTR_DRBG_MODULE_UNINITIALIZED = 0,
    BIGNUM_CTR_DRBG_MODULE_SELF_TEST = 1,
    BIGNUM_CTR_DRBG_MODULE_READY = 2,
    BIGNUM_CTR_DRBG_MODULE_RESEED_REQUIRED = 3,
    BIGNUM_CTR_DRBG_MODULE_ERROR = 4,
    BIGNUM_CTR_DRBG_MODULE_ZEROIZED = 5
} bignum_ctr_drbg_module_state_t;

typedef struct bignum_ctr_drbg_module_ctx {
    bignum_ctr_drbg_ctx drbg;
    bignum_ctr_drbg_module_state_t state;
} bignum_ctr_drbg_module_ctx;

bignum_ctr_drbg_status_t bignum_ctr_drbg_module_startup(
    bignum_ctr_drbg_module_ctx *module, int image_integrity_verified);

bignum_ctr_drbg_status_t bignum_ctr_drbg_module_instantiate(
    bignum_ctr_drbg_module_ctx *module,
    const uint8_t *entropy, size_t entropy_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *personalization, size_t personalization_len);

bignum_ctr_drbg_status_t bignum_ctr_drbg_module_reseed(
    bignum_ctr_drbg_module_ctx *module,
    const uint8_t *entropy, size_t entropy_len,
    const uint8_t *additional_input, size_t additional_input_len);

bignum_ctr_drbg_status_t bignum_ctr_drbg_module_generate(
    bignum_ctr_drbg_module_ctx *module,
    uint8_t *out, size_t out_len,
    const uint8_t *additional_input, size_t additional_input_len);

void bignum_ctr_drbg_module_uninstantiate(bignum_ctr_drbg_module_ctx *module);

bignum_ctr_drbg_module_state_t bignum_ctr_drbg_module_state(
    const bignum_ctr_drbg_module_ctx *module);

#endif /* BIGNUM_CTR_DRBG_MODULE_H */
