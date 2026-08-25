/**
 * @file test_ctr_drbg_health.c
 * @brief Fault-injection tests for candidate continuous entropy health checks.
 * @details The first provider mode creates an RCT failure. The second mode
 * instantiates with distinct bytes and then creates an APT failure across the
 * second 64-byte health window. Both failures must latch ERROR and block use.
 */
#include "bignum_ctr_drbg_context.h"

#include <stdint.h>
#include <stdio.h>

/** Provider modes used to exercise distinct health-test failure classes. */
typedef enum health_provider_mode {
    HEALTH_PROVIDER_CONSTANT = 0,
    HEALTH_PROVIDER_DISTINCT = 1,
    HEALTH_PROVIDER_APT_FAILURE = 2
} health_provider_mode_t;

typedef struct health_provider {
    health_provider_mode_t mode; /**< Selected deterministic output mode. */
    unsigned int calls; /**< Number of callback invocations. */
} health_provider_t;

static bignum_ctr_drbg_status_t provider(void *provider_context, uint8_t *out, size_t out_len)
{
    health_provider_t *state = (health_provider_t *)provider_context;
    size_t i;
    if (state == NULL || out == NULL || out_len != BIGNUM_CTR_DRBG_KEY_BYTES) return BIGNUM_CTR_DRBG_ERROR_INPUT;
    state->calls++;
    if (state->mode == HEALTH_PROVIDER_CONSTANT) {
        for (i = 0U; i < out_len; ++i) out[i] = 0x00U;
    } else if (state->mode == HEALTH_PROVIDER_DISTINCT) {
        for (i = 0U; i < out_len; ++i) out[i] = (uint8_t)(i + 1U);
    } else {
        for (i = 0U; i < out_len; ++i) out[i] = (i < out_len / 2U) ? 0xa5U : 0x5aU;
    }
    return BIGNUM_CTR_DRBG_SUCCESS;
}

#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); return 1; } } while (0)

int main(void)
{
    static const uint8_t nonce[16] = {
        0x0b,0xf8,0x14,0xb4,0x11,0xf6,0x5e,0xc4,0x86,0x6b,0xe1,0xab,0xb5,0x9d,0x3c,0x32
    };
    bignum_ctr_drbg_context_t context;
    health_provider_t state = {HEALTH_PROVIDER_CONSTANT, 0U};
    uint8_t output[16];

    CHECK(bignum_ctr_drbg_context_init(&context) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_context_startup(&context, 1) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_context_instantiate(&context, provider, &state, nonce, sizeof(nonce), NULL, 0U) == BIGNUM_CTR_DRBG_ERROR_ENTROPY_HEALTH);
    CHECK(state.calls == 1U);
    CHECK(bignum_ctr_drbg_context_state(&context) == BIGNUM_CTR_DRBG_MODULE_ERROR);
    CHECK(bignum_ctr_drbg_context_generate(&context, output, sizeof(output), NULL, 0U) == BIGNUM_CTR_DRBG_ERROR_STATE);

    CHECK(bignum_ctr_drbg_context_init(&context) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_context_startup(&context, 1) == BIGNUM_CTR_DRBG_SUCCESS);
    state.mode = HEALTH_PROVIDER_DISTINCT;
    CHECK(bignum_ctr_drbg_context_instantiate(&context, provider, &state, nonce, sizeof(nonce), NULL, 0U) == BIGNUM_CTR_DRBG_SUCCESS);
    state.mode = HEALTH_PROVIDER_APT_FAILURE;
    CHECK(bignum_ctr_drbg_context_reseed(&context, provider, &state) == BIGNUM_CTR_DRBG_ERROR_ENTROPY_HEALTH);
    CHECK(bignum_ctr_drbg_context_state(&context) == BIGNUM_CTR_DRBG_MODULE_ERROR);
    CHECK(bignum_ctr_drbg_context_generate(&context, output, sizeof(output), NULL, 0U) == BIGNUM_CTR_DRBG_ERROR_STATE);
    bignum_ctr_drbg_context_uninstantiate(&context);
    puts("entropy provider RCT/APT fault injection: PASS");
    return 0;
}
