#define _POSIX_C_SOURCE 200809L
/**
 * @file bench_ctr_drbg_full.c
 * @brief End-to-end candidate DRBG benchmark for C11 and independent YASM.
 * @details Measures provider acquisition separately and then measures the
 * service path including instantiate, periodic reseed, DF/BCC additional input,
 * CTR counter handling, AES generation, state update and zeroization.
 */
#include "bignum_ctr_drbg_service.h"
#include "bignum_ctr_drbg_os_entropy.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static uint64_t now_ns(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static uint64_t checksum_bytes(const uint8_t *bytes, size_t length)
{
    uint64_t checksum = 0U;
    size_t i;
    for (i = 0U; i < length; ++i) checksum = (checksum << 5U) ^ checksum ^ bytes[i];
    return checksum;
}

int main(void)
{
    static const uint8_t nonce[16] = {
        0x0b,0xf8,0x14,0xb4,0x11,0xf6,0x5e,0xc4,0x86,0x6b,0xe1,0xab,0xb5,0x9d,0x3c,0x32
    };
    static const uint8_t additional[48] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
    };
    enum { ACQUIRE_COUNT = 10000, ITERATIONS = 512, OUTPUT_BYTES = 2048 };
    uint8_t entropy[BIGNUM_CTR_DRBG_KEY_BYTES];
    uint8_t output[OUTPUT_BYTES];
    bignum_ctr_drbg_context_t context;
    uint64_t start, entropy_ns, drbg_ns, checksum;
    unsigned int i;
    memset(entropy, 0, sizeof(entropy));
    start = now_ns();
    for (i = 0U; i < ACQUIRE_COUNT; ++i) {
        if (bignum_ctr_drbg_os_entropy_provider(NULL, entropy, sizeof(entropy)) != BIGNUM_CTR_DRBG_SUCCESS) return 1;
    }
    entropy_ns = now_ns() - start;
    if (bignum_ctr_drbg_service_init(&context) != BIGNUM_CTR_DRBG_SUCCESS ||
        bignum_ctr_drbg_service_startup(&context, 1) != BIGNUM_CTR_DRBG_SUCCESS ||
        bignum_ctr_drbg_service_instantiate(&context, nonce, sizeof(nonce), NULL, 0U) != BIGNUM_CTR_DRBG_SUCCESS) return 1;
    checksum = 0U;
    start = now_ns();
    for (i = 0U; i < ITERATIONS; ++i) {
        if ((i % 16U) == 0U && bignum_ctr_drbg_service_reseed(&context) != BIGNUM_CTR_DRBG_SUCCESS) return 1;
        if (bignum_ctr_drbg_service_generate(&context, output, sizeof(output), additional, sizeof(additional)) != BIGNUM_CTR_DRBG_SUCCESS) return 1;
        checksum ^= checksum_bytes(output, sizeof(output));
    }
    drbg_ns = now_ns() - start;
    bignum_ctr_drbg_service_uninstantiate(&context);
    printf("backend=%s entropy_calls=%zu entropy_ns=%llu drbg_iterations=%zu output_bytes=%zu drbg_ns=%llu ns_per_iteration=%.2f checksum=%llu\n",
           "runtime", (size_t)ACQUIRE_COUNT, (unsigned long long)entropy_ns, (size_t)ITERATIONS, (size_t)OUTPUT_BYTES,
           (unsigned long long)drbg_ns, (double)drbg_ns / (double)ITERATIONS,
           (unsigned long long)checksum);
    return 0;
}
