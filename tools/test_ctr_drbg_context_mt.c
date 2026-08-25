/**
 * @file test_ctr_drbg_context_mt.c
 * @brief Concurrent caller-context isolation test.
 * @details Each worker owns one caller-allocated context and one provider
 * state. Workers perform startup, instantiate, repeated generate, and
 * uninstantiate concurrently. The oracle is that every operation succeeds,
 * each context reaches ZEROIZED, and no worker observes another worker's
 * provider state or lifecycle.
 */
#include "bignum_ctr_drbg_context.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WORKER_COUNT 4U
#define GENERATE_COUNT 64U

typedef struct worker {
    unsigned int id; /**< Stable worker identifier used to derive test bytes. */
    unsigned int calls; /**< Provider calls observed by this worker only. */
    int failure; /**< Nonzero if any operation or output invariant failed. */
    bignum_ctr_drbg_context_t context; /**< Independent caller-owned context. */
} worker_t;

static bignum_ctr_drbg_status_t worker_provider(void *provider_context, uint8_t *out, size_t out_len)
{
    worker_t *worker = (worker_t *)provider_context;
    size_t i;
    if (worker == NULL || out == NULL || out_len != BIGNUM_CTR_DRBG_KEY_BYTES) return BIGNUM_CTR_DRBG_ERROR_INPUT;
    worker->calls++;
    for (i = 0U; i < out_len; ++i) out[i] = (uint8_t)(worker->id * 17U + i + 1U);
    return BIGNUM_CTR_DRBG_SUCCESS;
}

static void *worker_main(void *argument)
{
    static const uint8_t nonce[16] = {
        0x0b,0xf8,0x14,0xb4,0x11,0xf6,0x5e,0xc4,0x86,0x6b,0xe1,0xab,0xb5,0x9d,0x3c,0x32
    };
    worker_t *worker = (worker_t *)argument;
    uint8_t output[32];
    unsigned int i;
    if (bignum_ctr_drbg_context_init(&worker->context) != BIGNUM_CTR_DRBG_SUCCESS ||
        bignum_ctr_drbg_context_startup(&worker->context, 1) != BIGNUM_CTR_DRBG_SUCCESS ||
        bignum_ctr_drbg_context_instantiate(&worker->context, worker_provider, worker,
                                            nonce, sizeof(nonce), NULL, 0U) != BIGNUM_CTR_DRBG_SUCCESS) {
        worker->failure = 1;
        return NULL;
    }
    for (i = 0U; i < GENERATE_COUNT; ++i) {
        memset(output, 0, sizeof(output));
        if (bignum_ctr_drbg_context_generate(&worker->context, output, sizeof(output), NULL, 0U) != BIGNUM_CTR_DRBG_SUCCESS) {
            worker->failure = 1;
            break;
        }
    }
    bignum_ctr_drbg_context_uninstantiate(&worker->context);
    if (bignum_ctr_drbg_context_state(&worker->context) != BIGNUM_CTR_DRBG_MODULE_ZEROIZED) worker->failure = 1;
    return NULL;
}

int main(void)
{
    pthread_t threads[WORKER_COUNT];
    worker_t workers[WORKER_COUNT];
    unsigned int i;
    for (i = 0U; i < WORKER_COUNT; ++i) {
        memset(&workers[i], 0, sizeof(workers[i]));
        workers[i].id = i + 1U;
        if (pthread_create(&threads[i], NULL, worker_main, &workers[i]) != 0) return 1;
    }
    for (i = 0U; i < WORKER_COUNT; ++i) {
        if (pthread_join(threads[i], NULL) != 0 || workers[i].failure != 0 || workers[i].calls != 1U) return 1;
    }
    puts("caller context concurrent isolation: PASS");
    return 0;
}
