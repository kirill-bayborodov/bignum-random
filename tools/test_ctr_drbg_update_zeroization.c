/**
 * @file test_ctr_drbg_update_zeroization.c
 * @brief Verifies test-instrumented YASM CTR_DRBG_Update zeroization.
 * @details The probe symbol is linked only in this test build. Production
 * assembly is built without BIGNUM_DRBG_ZEROIZE_PROBE and has no test hook.
 */
#include "bignum_ctr_drbg_internal.h"

#include <stdint.h>
#include <stdio.h>

static int probe_failed;

void bignum_ctr_drbg_zeroization_probe(const uint8_t *memory, size_t length)
{
    size_t i;
    if (length != 304U) {
        probe_failed = 1;
        return;
    }
    for (i = 0U; i < length; ++i) {
        if (memory[i] != 0U) {
            probe_failed = 1;
            return;
        }
    }
}

int main(void)
{
    static const uint8_t provided[48] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
    };
    uint8_t key[32];
    uint8_t v[16];
    uint8_t key_before[32];
    uint8_t v_before[16];
    size_t i;
    int state_changed = 0;
    for (i = 0U; i < sizeof(key); ++i) key[i] = (uint8_t)(0xa0U + i);
    for (i = 0U; i < sizeof(v); ++i) v[i] = (uint8_t)(0xf0U + i);
    for (i = 0U; i < sizeof(key); ++i) key_before[i] = key[i];
    for (i = 0U; i < sizeof(v); ++i) v_before[i] = v[i];
    bignum_ctr_drbg_update_asm(provided, key, v);
    for (i = 0U; i < sizeof(key); ++i) if (key[i] != key_before[i]) state_changed = 1;
    for (i = 0U; i < sizeof(v); ++i) if (v[i] != v_before[i]) state_changed = 1;
    if (probe_failed != 0 || state_changed == 0) {
        fprintf(stderr, "YASM CTR_DRBG_Update zeroization/state test failed\n");
        return 1;
    }
    puts("YASM CTR_DRBG_Update zeroization probe: PASS");
    return 0;
}
