#include "bignum_ctr_drbg_module.h"

#include <string.h>

static void module_zeroize(bignum_ctr_drbg_module_ctx *module)
{
    bignum_ctr_drbg_uninstantiate(&module->drbg);
    module->state = BIGNUM_CTR_DRBG_MODULE_ZEROIZED;
}

static bignum_ctr_drbg_status_t power_up_kat(void)
{
    static const uint8_t entropy[32] = {
        0x2d,0x4c,0x9f,0x46,0xb9,0x81,0xc6,0xa0,0xb2,0xb5,0xd8,0xc6,0x93,0x91,0xe5,0x69,
        0xff,0x13,0x85,0x14,0x37,0xeb,0xc0,0xfc,0x00,0xd6,0x16,0x34,0x02,0x52,0xfe,0xd5
    };
    static const uint8_t nonce[16] = {
        0x0b,0xf8,0x14,0xb4,0x11,0xf6,0x5e,0xc4,0x86,0x6b,0xe1,0xab,0xb5,0x9d,0x3c,0x32
    };
    static const uint8_t reseed_entropy[32] = {
        0x93,0x50,0x0f,0xae,0x4f,0xa3,0x2b,0x86,0x03,0x3b,0x7a,0x7b,0xac,0x9d,0x37,0xe7,
        0x10,0xdc,0xc6,0x7c,0xa2,0x66,0xbc,0x86,0x07,0xd6,0x65,0x93,0x77,0x66,0xd2,0x07
    };
    static const uint8_t expected[64] = {
        0x32,0x2d,0xd2,0x86,0x70,0xe7,0x5c,0x0e,0xa6,0x38,0xf3,0xcb,0x68,0xd6,0xa9,0xd6,
        0xe5,0x0d,0xdf,0xd0,0x52,0xb7,0x72,0xa7,0xb1,0xd7,0x82,0x63,0xa7,0xb8,0x97,0x8b,
        0x67,0x40,0xc2,0xb6,0x5a,0x95,0x50,0xc3,0xa7,0x63,0x25,0x86,0x6f,0xa9,0x7e,0x16,
        0xd7,0x40,0x06,0xbc,0x96,0xf2,0x62,0x49,0xb9,0xf0,0xa9,0x0d,0x07,0x6f,0x08,0xe5
    };
    bignum_ctr_drbg_ctx ctx;
    uint8_t output[64];
    bignum_ctr_drbg_status_t status;
    memset(&ctx, 0, sizeof(ctx));
    status = bignum_ctr_drbg_instantiate(&ctx, entropy, sizeof(entropy), nonce, sizeof(nonce), NULL, 0U);
    if (status == BIGNUM_CTR_DRBG_SUCCESS) status = bignum_ctr_drbg_reseed(&ctx, reseed_entropy, sizeof(reseed_entropy), NULL, 0U);
    if (status == BIGNUM_CTR_DRBG_SUCCESS) status = bignum_ctr_drbg_generate(&ctx, output, sizeof(output), NULL, 0U);
    if (status == BIGNUM_CTR_DRBG_SUCCESS) status = bignum_ctr_drbg_generate(&ctx, output, sizeof(output), NULL, 0U);
    if (status == BIGNUM_CTR_DRBG_SUCCESS && memcmp(output, expected, sizeof(output)) != 0) status = BIGNUM_CTR_DRBG_ERROR_STATE;
    bignum_ctr_drbg_uninstantiate(&ctx);
    memset(output, 0, sizeof(output));
    return status;
}

static bignum_ctr_drbg_status_t require_ready(const bignum_ctr_drbg_module_ctx *module)
{
    if (module == NULL) return BIGNUM_CTR_DRBG_ERROR_NULL_ARG;
    if (module->state == BIGNUM_CTR_DRBG_MODULE_READY) return BIGNUM_CTR_DRBG_SUCCESS;
    if (module->state == BIGNUM_CTR_DRBG_MODULE_RESEED_REQUIRED) return BIGNUM_CTR_DRBG_ERROR_RESEED_REQUIRED;
    return BIGNUM_CTR_DRBG_ERROR_STATE;
}

bignum_ctr_drbg_status_t bignum_ctr_drbg_module_startup(
    bignum_ctr_drbg_module_ctx *module, int image_integrity_verified)
{
    bignum_ctr_drbg_status_t status;
    if (module == NULL) return BIGNUM_CTR_DRBG_ERROR_NULL_ARG;
    if (module->state != BIGNUM_CTR_DRBG_MODULE_UNINITIALIZED && module->state != BIGNUM_CTR_DRBG_MODULE_ZEROIZED) {
        return BIGNUM_CTR_DRBG_ERROR_STATE;
    }
    module->state = BIGNUM_CTR_DRBG_MODULE_SELF_TEST;
    if (image_integrity_verified == 0) {
        module->state = BIGNUM_CTR_DRBG_MODULE_ERROR;
        return BIGNUM_CTR_DRBG_ERROR_STATE;
    }
    status = power_up_kat();
    if (status != BIGNUM_CTR_DRBG_SUCCESS) {
        module->state = BIGNUM_CTR_DRBG_MODULE_ERROR;
        return status;
    }
    module->state = BIGNUM_CTR_DRBG_MODULE_READY;
    return BIGNUM_CTR_DRBG_SUCCESS;
}

bignum_ctr_drbg_status_t bignum_ctr_drbg_module_instantiate(
    bignum_ctr_drbg_module_ctx *module, const uint8_t *entropy, size_t entropy_len,
    const uint8_t *nonce, size_t nonce_len, const uint8_t *personalization, size_t personalization_len)
{
    bignum_ctr_drbg_status_t status;
    if (module == NULL) return BIGNUM_CTR_DRBG_ERROR_NULL_ARG;
    status = require_ready(module);
    if (status != BIGNUM_CTR_DRBG_SUCCESS) return status;
    status = bignum_ctr_drbg_instantiate(&module->drbg, entropy, entropy_len, nonce, nonce_len, personalization, personalization_len);
    if (status != BIGNUM_CTR_DRBG_SUCCESS) module->state = BIGNUM_CTR_DRBG_MODULE_ERROR;
    return status;
}

bignum_ctr_drbg_status_t bignum_ctr_drbg_module_reseed(
    bignum_ctr_drbg_module_ctx *module, const uint8_t *entropy, size_t entropy_len,
    const uint8_t *additional_input, size_t additional_input_len)
{
    bignum_ctr_drbg_status_t status;
    if (module == NULL) return BIGNUM_CTR_DRBG_ERROR_NULL_ARG;
    if (module->state != BIGNUM_CTR_DRBG_MODULE_READY && module->state != BIGNUM_CTR_DRBG_MODULE_RESEED_REQUIRED) return BIGNUM_CTR_DRBG_ERROR_STATE;
    status = bignum_ctr_drbg_reseed(&module->drbg, entropy, entropy_len, additional_input, additional_input_len);
    if (status == BIGNUM_CTR_DRBG_SUCCESS) module->state = BIGNUM_CTR_DRBG_MODULE_READY;
    else module->state = BIGNUM_CTR_DRBG_MODULE_ERROR;
    return status;
}

bignum_ctr_drbg_status_t bignum_ctr_drbg_module_generate(
    bignum_ctr_drbg_module_ctx *module, uint8_t *out, size_t out_len,
    const uint8_t *additional_input, size_t additional_input_len)
{
    bignum_ctr_drbg_status_t status;
    if (module == NULL) return BIGNUM_CTR_DRBG_ERROR_NULL_ARG;
    status = require_ready(module);
    if (status != BIGNUM_CTR_DRBG_SUCCESS) return status;
    status = bignum_ctr_drbg_generate(&module->drbg, out, out_len, additional_input, additional_input_len);
    if (status == BIGNUM_CTR_DRBG_ERROR_RESEED_REQUIRED) module->state = BIGNUM_CTR_DRBG_MODULE_RESEED_REQUIRED;
    else if (status != BIGNUM_CTR_DRBG_SUCCESS) module->state = BIGNUM_CTR_DRBG_MODULE_ERROR;
    return status;
}

void bignum_ctr_drbg_module_uninstantiate(bignum_ctr_drbg_module_ctx *module)
{
    if (module != NULL) module_zeroize(module);
}

bignum_ctr_drbg_module_state_t bignum_ctr_drbg_module_state(const bignum_ctr_drbg_module_ctx *module)
{
    return module == NULL ? BIGNUM_CTR_DRBG_MODULE_ERROR : module->state;
}
