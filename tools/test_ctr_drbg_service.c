/**
 * @file test_ctr_drbg_service.c
 * @brief Tests the controlled production-facing service boundary.
 * @details The test can use only service functions and therefore cannot inject
 * a deterministic provider. It verifies startup, OS-backed instantiate,
 * generation, output presence, and zeroization lifecycle.
 */
#include "bignum_ctr_drbg_service.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); return 1; } } while (0)

int main(void)
{
    static const uint8_t nonce[16] = {
        0x0b,0xf8,0x14,0xb4,0x11,0xf6,0x5e,0xc4,0x86,0x6b,0xe1,0xab,0xb5,0x9d,0x3c,0x32
    };
    bignum_ctr_drbg_context_t context;
    uint8_t output[32];
    CHECK(bignum_ctr_drbg_service_init(&context) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_service_startup(&context, 1) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_service_instantiate(&context, nonce, sizeof(nonce), NULL, 0U) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_service_state(&context) == BIGNUM_CTR_DRBG_MODULE_READY);
    memset(output, 0, sizeof(output));
    CHECK(bignum_ctr_drbg_service_generate(&context, output, sizeof(output), NULL, 0U) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(memcmp(output, (uint8_t[32]){0}, sizeof(output)) != 0);
    bignum_ctr_drbg_service_uninstantiate(&context);
    CHECK(bignum_ctr_drbg_service_state(&context) == BIGNUM_CTR_DRBG_MODULE_ZEROIZED);
    puts("controlled production DRBG service: PASS");
    return 0;
}
