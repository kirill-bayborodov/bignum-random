/**
 * @file test_ctr_drbg_context_fork.c
 * @brief Verifies fail-closed behavior for forked copies of a context.
 * @details The parent initializes a DRBG context, then forks. The child
 * inherits bytes but has a different process identifier and must reject state
 * access. The parent waits for the child and remains able to uninstantiate.
 */
#include "bignum_ctr_drbg_context.h"

#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static bignum_ctr_drbg_status_t provider(void *provider_context, uint8_t *out, size_t out_len)
{
    size_t i;
    (void)provider_context;
    if (out == NULL || out_len != BIGNUM_CTR_DRBG_KEY_BYTES) return BIGNUM_CTR_DRBG_ERROR_INPUT;
    for (i = 0U; i < out_len; ++i) out[i] = (uint8_t)(i + 1U);
    return BIGNUM_CTR_DRBG_SUCCESS;
}

#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); return 1; } } while (0)

int main(void)
{
    static const uint8_t nonce[16] = {
        0x0b,0xf8,0x14,0xb4,0x11,0xf6,0x5e,0xc4,0x86,0x6b,0xe1,0xab,0xb5,0x9d,0x3c,0x32
    };
    bignum_ctr_drbg_context_t context;
    pid_t child;
    int status;
    CHECK(bignum_ctr_drbg_context_init(&context) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_context_startup(&context, 1) == BIGNUM_CTR_DRBG_SUCCESS);
    CHECK(bignum_ctr_drbg_context_instantiate(&context, provider, NULL, nonce, sizeof(nonce), NULL, 0U) == BIGNUM_CTR_DRBG_SUCCESS);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        uint8_t output[16];
        if (bignum_ctr_drbg_context_state(&context) != BIGNUM_CTR_DRBG_MODULE_ERROR ||
            bignum_ctr_drbg_context_generate(&context, output, sizeof(output), NULL, 0U) != BIGNUM_CTR_DRBG_ERROR_STATE) _exit(1);
        _exit(0);
    }
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    bignum_ctr_drbg_context_uninstantiate(&context);
    CHECK(bignum_ctr_drbg_context_state(&context) == BIGNUM_CTR_DRBG_MODULE_ZEROIZED);
    puts("caller context fork isolation: PASS");
    return 0;
}
