#include "bignum_ctr_drbg.h"
#include "bignum_ctr_drbg_context.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint8_t entropy[32] = {
    0x2d,0x4c,0x9f,0x46,0xb9,0x81,0xc6,0xa0,0xb2,0xb5,0xd8,0xc6,0x93,0x91,0xe5,0x69,
    0xff,0x13,0x85,0x14,0x37,0xeb,0xc0,0xfc,0x00,0xd6,0x16,0x34,0x02,0x52,0xfe,0xd5
};
static const uint8_t nonce[16] = {
    0x0b,0xf8,0x14,0xb4,0x11,0xf6,0x5e,0xc4,0x86,0x6b,0xe1,0xab,0xb5,0x9d,0x3c,0x32
};

#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); return 1; } } while (0)

int main(void)
{
    bignum_ctr_drbg_ctx ctx;
    bignum_ctr_drbg_ctx snapshot;
    bignum_ctr_drbg_ctx uninitialized = {0};
    bignum_ctr_drbg_module_ctx module;
    uint8_t output[32];
    uint8_t original_output[sizeof(output)];
    uint8_t oversized[1025];
    memset(&ctx, 0xa5, sizeof(ctx));
    snapshot = ctx;
    CHECK(bignum_ctr_drbg_instantiate(NULL, entropy, sizeof(entropy), nonce, sizeof(nonce), NULL, 0) == BIGNUM_CTR_DRBG_ERROR_NULL_ARG);
    CHECK(bignum_ctr_drbg_instantiate(&ctx, entropy, sizeof(entropy) - 1U, nonce, sizeof(nonce), NULL, 0) == BIGNUM_CTR_DRBG_ERROR_INPUT);
    CHECK(memcmp(&ctx, &snapshot, sizeof(ctx)) == 0);
    CHECK(bignum_ctr_drbg_generate(&uninitialized, output, sizeof(output), NULL, 0) == BIGNUM_CTR_DRBG_ERROR_STATE);
    CHECK(bignum_ctr_drbg_reseed(&uninitialized, entropy, sizeof(entropy), NULL, 0) == BIGNUM_CTR_DRBG_ERROR_STATE);
    CHECK(bignum_ctr_drbg_instantiate(&ctx, entropy, sizeof(entropy), nonce, sizeof(nonce), NULL, 0) == BIGNUM_CTR_DRBG_SUCCESS);
    memset(output, 0xa5, sizeof(output));
    memcpy(original_output, output, sizeof(output));
    CHECK(bignum_ctr_drbg_generate(&ctx, output, sizeof(output), NULL, 1U) == BIGNUM_CTR_DRBG_ERROR_INPUT);
    CHECK(memcmp(output, original_output, sizeof(output)) == 0);
    CHECK(bignum_ctr_drbg_generate(&ctx, NULL, sizeof(output), NULL, 0) == BIGNUM_CTR_DRBG_ERROR_NULL_ARG);
    memset(oversized, 0, sizeof(oversized));
    CHECK(bignum_ctr_drbg_generate(&ctx, output, sizeof(output), oversized, sizeof(oversized)) == BIGNUM_CTR_DRBG_ERROR_INPUT);
    ctx.reseed_counter = UINT64_C(281474976710657);
    memcpy(original_output, output, sizeof(output));
    CHECK(bignum_ctr_drbg_generate(&ctx, output, sizeof(output), NULL, 0) == BIGNUM_CTR_DRBG_ERROR_RESEED_REQUIRED);
    CHECK(memcmp(output, original_output, sizeof(output)) == 0);

    memset(&module, 0, sizeof(module));
    CHECK(bignum_ctr_drbg_module_startup(&module, 0) == BIGNUM_CTR_DRBG_ERROR_STATE);
    CHECK(bignum_ctr_drbg_module_state(&module) == BIGNUM_CTR_DRBG_MODULE_ERROR);
    CHECK(bignum_ctr_drbg_module_generate(&module, output, sizeof(output), NULL, 0) == BIGNUM_CTR_DRBG_ERROR_STATE);
    memset(&module, 0, sizeof(module));
    CHECK(bignum_ctr_drbg_module_startup(&module, 1) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_module_instantiate(&module, entropy, sizeof(entropy), nonce, sizeof(nonce), NULL, 0) == BIGNUM_CTR_DRBG_SUCCESS);
    module.drbg.reseed_counter = UINT64_C(281474976710657);
    CHECK(bignum_ctr_drbg_module_generate(&module, output, sizeof(output), NULL, 0) == BIGNUM_CTR_DRBG_ERROR_RESEED_REQUIRED);
    CHECK(bignum_ctr_drbg_module_state(&module) == BIGNUM_CTR_DRBG_MODULE_RESEED_REQUIRED);
    CHECK(bignum_ctr_drbg_module_generate(&module, output, sizeof(output), NULL, 0) == BIGNUM_CTR_DRBG_ERROR_RESEED_REQUIRED);
    bignum_ctr_drbg_module_uninstantiate(&module);
    CHECK(bignum_ctr_drbg_module_state(&module) == BIGNUM_CTR_DRBG_MODULE_ZEROIZED);
    {
        bignum_ctr_drbg_ctx zero = {0};
        CHECK(memcmp(&module.drbg, &zero, sizeof(module.drbg)) == 0);
        CHECK(module.state == BIGNUM_CTR_DRBG_MODULE_ZEROIZED);
    }
    puts("candidate DRBG negative paths: PASS");
    return 0;
}
