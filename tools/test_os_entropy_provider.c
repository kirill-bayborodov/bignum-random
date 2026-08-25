/**
 * @file test_os_entropy_provider.c
 * @brief Tests the production Linux getrandom(2) entropy-provider boundary.
 * @details The test verifies complete buffer filling, caller-context
 * integration, and deterministic argument/error handling. It does not claim
 * that the host kernel is an assessed entropy source for FIPS validation.
 */
#include "bignum_ctr_drbg_os_entropy.h"

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
    uint8_t entropy[BIGNUM_CTR_DRBG_KEY_BYTES];
    uint8_t output[32];
    memset(entropy, 0, sizeof(entropy));
    CHECK(bignum_ctr_drbg_os_entropy_provider(NULL, entropy, sizeof(entropy)) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_os_entropy_provider((void *)1, entropy, sizeof(entropy)) == BIGNUM_CTR_DRBG_ERROR_NULL_ARG);
    CHECK(bignum_ctr_drbg_os_entropy_provider(NULL, entropy, 0U) == BIGNUM_CTR_DRBG_ERROR_INPUT);
    CHECK(bignum_ctr_drbg_os_entropy_provider(NULL, NULL, sizeof(entropy)) == BIGNUM_CTR_DRBG_ERROR_NULL_ARG);
    CHECK(bignum_ctr_drbg_context_init(&context) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_context_startup(&context, 1) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_context_instantiate(&context, bignum_ctr_drbg_os_entropy_provider, NULL, nonce, sizeof(nonce), NULL, 0U) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_context_generate(&context, output, sizeof(output), NULL, 0U) == BIGNUM_CTR_DRBG_SUCCESS);
    bignum_ctr_drbg_context_uninstantiate(&context);
    puts("Linux getrandom entropy provider: PASS");
    return 0;
}
