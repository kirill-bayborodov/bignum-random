#define _POSIX_C_SOURCE 200809L
#include "bignum_ctr_drbg_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <time.h>

static uint64_t now_ns(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static uint64_t run_c(const uint8_t *key, const uint8_t *input, uint8_t *output, size_t count)
{
    uint64_t checksum = 0U;
    size_t i;
    for (i = 0U; i < count; ++i) {
        uint8_t expanded[BIGNUM_CTR_DRBG_EXPANDED_KEY_BYTES];
        bignum_ctr_drbg_aes256_expand_key(key, expanded);
        bignum_ctr_drbg_aes256_encrypt_expanded(expanded, input, output);
        checksum ^= output[i & 15U];
        input += BIGNUM_CTR_DRBG_BLOCK_BYTES;
        output += BIGNUM_CTR_DRBG_BLOCK_BYTES;
    }
    return checksum;
}

static uint64_t run_asm(const uint8_t *key, const uint8_t *input, uint8_t *output, size_t count)
{
    uint64_t checksum = 0U;
    size_t i;
    for (i = 0U; i < count; ++i) {
        uint8_t expanded[BIGNUM_CTR_DRBG_EXPANDED_KEY_BYTES];
        bignum_ctr_drbg_aes256_expand_key_asm(key, expanded);
        bignum_ctr_drbg_aes256_encrypt_expanded_asm(expanded, input, output);
        checksum ^= output[i & 15U];
        input += BIGNUM_CTR_DRBG_BLOCK_BYTES;
        output += BIGNUM_CTR_DRBG_BLOCK_BYTES;
    }
    return checksum;
}

int main(void)
{
    static const uint8_t key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    enum { COUNT = 100000 };
    uint8_t input[COUNT * BIGNUM_CTR_DRBG_BLOCK_BYTES];
    uint8_t c_output[COUNT * BIGNUM_CTR_DRBG_BLOCK_BYTES];
    uint8_t asm_output[COUNT * BIGNUM_CTR_DRBG_BLOCK_BYTES];
    uint64_t start, c_ns, asm_ns, c_sum, asm_sum;
    size_t i;
    for (i = 0U; i < sizeof(input); ++i) input[i] = (uint8_t)(i * 29U + 7U);
    start = now_ns();
    c_sum = run_c(key, input, c_output, COUNT);
    c_ns = now_ns() - start;
    start = now_ns();
    asm_sum = run_asm(key, input, asm_output, COUNT);
    asm_ns = now_ns() - start;
    if (c_sum != asm_sum || __builtin_memcmp(c_output, asm_output, sizeof(c_output)) != 0) return 1;
    printf("blocks=%zu c_expand_encrypt_ns=%llu asm_expand_encrypt_ns=%llu speedup=%.3fx checksum=%llu\n",
           (size_t)COUNT, (unsigned long long)c_ns, (unsigned long long)asm_ns,
           (double)c_ns / (double)asm_ns, (unsigned long long)c_sum);
    return 0;
}
