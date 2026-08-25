/**
 * @file test_ctr_drbg_context_faults.c
 * @brief Deterministic lifecycle and entropy-provider fault-injection test.
 * @details The provider callback is a controlled oracle. Tests assert that
 * integrity or provider failures latch ERROR, prevent output, and do not
 * retain entropy-provider state. A successful path verifies the caller-owned
 * context lifecycle through READY, generate, and ZEROIZED.
 */
#include "bignum_ctr_drbg_context.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/** Fixed provider state used only by this deterministic test. */
typedef struct fault_provider {
    unsigned int calls; /**< Number of synchronous provider invocations. */
    int fail;           /**< Nonzero makes the callback return ERROR_INPUT. */
    uint8_t fill;       /**< Deterministic byte written to every requested byte. */
} fault_provider_t;

static bignum_ctr_drbg_status_t provider_callback(
    void *provider_context, uint8_t *out, size_t out_len)
{
    fault_provider_t *provider = (fault_provider_t *)provider_context;
    if (provider == NULL || out == NULL || out_len != BIGNUM_CTR_DRBG_KEY_BYTES) {
        return BIGNUM_CTR_DRBG_ERROR_INPUT;
    }
    provider->calls++;
    memset(out, provider->fill, out_len);
    return provider->fail ? BIGNUM_CTR_DRBG_ERROR_INPUT : BIGNUM_CTR_DRBG_SUCCESS;
}

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
        return 1; \
    } \
} while (0)

int main(void)
{
    static const uint8_t nonce[16] = {
        0x0b,0xf8,0x14,0xb4,0x11,0xf6,0x5e,0xc4,0x86,0x6b,0xe1,0xab,0xb5,0x9d,0x3c,0x32
    };
    bignum_ctr_drbg_context_t context;
    fault_provider_t provider = {0U, 0, 0x5aU};
    uint8_t output[32];
    uint8_t untouched[sizeof(output)];

    CHECK(bignum_ctr_drbg_context_size() == sizeof(context));
    CHECK(bignum_ctr_drbg_context_init(NULL) == BIGNUM_CTR_DRBG_ERROR_NULL_ARG);
    CHECK(bignum_ctr_drbg_context_init(&context) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_context_state(&context) == BIGNUM_CTR_DRBG_MODULE_UNINITIALIZED);
    CHECK(bignum_ctr_drbg_context_startup(&context, 0) == BIGNUM_CTR_DRBG_ERROR_STATE);
    CHECK(bignum_ctr_drbg_context_state(&context) == BIGNUM_CTR_DRBG_MODULE_ERROR);
    memset(output, 0xa5, sizeof(output));
    memcpy(untouched, output, sizeof(output));
    CHECK(bignum_ctr_drbg_context_generate(&context, output, sizeof(output), NULL, 0U) == BIGNUM_CTR_DRBG_ERROR_STATE);
    CHECK(memcmp(output, untouched, sizeof(output)) == 0);

    CHECK(bignum_ctr_drbg_context_init(&context) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_context_startup(&context, 1) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_context_state(&context) == BIGNUM_CTR_DRBG_MODULE_READY);
    provider.fail = 1;
    CHECK(bignum_ctr_drbg_context_instantiate(&context, provider_callback, &provider, nonce, sizeof(nonce), NULL, 0U) == BIGNUM_CTR_DRBG_ERROR_INPUT);
    CHECK(provider.calls == 1U);
    CHECK(bignum_ctr_drbg_context_state(&context) == BIGNUM_CTR_DRBG_MODULE_ERROR);
    CHECK(bignum_ctr_drbg_context_generate(&context, output, sizeof(output), NULL, 0U) == BIGNUM_CTR_DRBG_ERROR_STATE);
    CHECK(bignum_ctr_drbg_context_reseed(&context, provider_callback, &provider) == BIGNUM_CTR_DRBG_ERROR_STATE);

    CHECK(bignum_ctr_drbg_context_init(&context) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_context_startup(&context, 1) == BIGNUM_CTR_DRBG_SUCCESS);
    provider.fail = 0;
    CHECK(bignum_ctr_drbg_context_instantiate(&context, provider_callback, &provider, nonce, sizeof(nonce), NULL, 0U) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_context_state(&context) == BIGNUM_CTR_DRBG_MODULE_READY);
    CHECK(bignum_ctr_drbg_context_generate(&context, output, sizeof(output), NULL, 0U) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_context_state(&context) == BIGNUM_CTR_DRBG_MODULE_READY);
    bignum_ctr_drbg_context_uninstantiate(&context);
    CHECK(bignum_ctr_drbg_context_state(&context) == BIGNUM_CTR_DRBG_MODULE_ZEROIZED);
    CHECK(bignum_ctr_drbg_context_generate(&context, output, sizeof(output), NULL, 0U) == BIGNUM_CTR_DRBG_ERROR_STATE);
    CHECK(bignum_ctr_drbg_context_startup(&context, 1) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_context_state(&context) == BIGNUM_CTR_DRBG_MODULE_READY);
    bignum_ctr_drbg_context_uninstantiate(&context);

    puts("caller context/provider fault injection: PASS");
    return 0;
}
