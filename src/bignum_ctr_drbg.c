/**
 * @file bignum_ctr_drbg.c
 * @brief Readable C11 candidate AES-256 CTR_DRBG implementation.
 * @details Implements the AES block cipher, BCC, Block_Cipher_df and the
 * instantiate/reseed/generate state transitions from NIST SP 800-90A Rev. 1.
 * This is deliberately a self-contained reference leaf; it is not yet the
 * optimized assembly implementation and does not by itself establish FIPS
 * validation.
 */
#include "bignum_ctr_drbg.h"

#include <limits.h>
#include <string.h>

#define AES_ROUNDS 14U
#define AES_EXPANDED_KEY_BYTES 240U
#define DRBG_RESEED_INTERVAL UINT64_C(281474976710656)

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t result = 0U;
    unsigned int i;
    for (i = 0U; i < 8U; ++i) {
        if ((b & 1U) != 0U) result ^= a;
        a = (uint8_t)((a & 0x80U) != 0U ? (uint8_t)(a << 1U) ^ 0x1bU : (uint8_t)(a << 1U));
        b = (uint8_t)(b >> 1U);
    }
    return result;
}

static uint8_t gf_pow(uint8_t a, unsigned int exponent)
{
    uint8_t result = 1U;
    while (exponent != 0U) {
        if ((exponent & 1U) != 0U) result = gf_mul(result, a);
        a = gf_mul(a, a);
        exponent >>= 1U;
    }
    return result;
}

static uint8_t rotl8(uint8_t value, unsigned int shift)
{
    return (uint8_t)((value << shift) | (value >> (8U - shift)));
}

static uint8_t aes_sbox(uint8_t value)
{
    const uint8_t inverse = value == 0U ? 0U : gf_pow(value, 254U);
    return (uint8_t)(inverse ^ rotl8(inverse, 1U) ^ rotl8(inverse, 2U) ^
                     rotl8(inverse, 3U) ^ rotl8(inverse, 4U) ^ 0x63U);
}

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24U) | ((uint32_t)p[1] << 16U) |
           ((uint32_t)p[2] << 8U) | (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24U);
    p[1] = (uint8_t)(value >> 16U);
    p[2] = (uint8_t)(value >> 8U);
    p[3] = (uint8_t)value;
}

static uint32_t aes_sub_word(uint32_t word)
{
    return ((uint32_t)aes_sbox((uint8_t)(word >> 24U)) << 24U) |
           ((uint32_t)aes_sbox((uint8_t)(word >> 16U)) << 16U) |
           ((uint32_t)aes_sbox((uint8_t)(word >> 8U)) << 8U) |
           (uint32_t)aes_sbox((uint8_t)word);
}

static uint32_t aes_rot_word(uint32_t word)
{
    return (word << 8U) | (word >> 24U);
}

static uint32_t aes_rcon(unsigned int round)
{
    uint8_t value = 1U;
    unsigned int i;
    for (i = 1U; i < round; ++i) value = gf_mul(value, 2U);
    return (uint32_t)value << 24U;
}

static void aes_expand_key(const uint8_t key[32], uint8_t expanded[240])
{
    unsigned int i;
    for (i = 0U; i < 8U; ++i) {
        memcpy(expanded + 4U * i, key + 4U * i, 4U);
    }
    for (i = 8U; i < 60U; ++i) {
        uint32_t word = load_be32(expanded + 4U * (i - 1U));
        if ((i % 8U) == 0U) word = aes_sub_word(aes_rot_word(word)) ^ aes_rcon(i / 8U);
        else if ((i % 8U) == 4U) word = aes_sub_word(word);
        word ^= load_be32(expanded + 4U * (i - 8U));
        store_be32(expanded + 4U * i, word);
    }
}

static void aes_add_round_key(uint8_t state[16], const uint8_t *round_key)
{
    unsigned int i;
    for (i = 0U; i < 16U; ++i) state[i] ^= round_key[i];
}

static void aes_sub_bytes(uint8_t state[16])
{
    unsigned int i;
    for (i = 0U; i < 16U; ++i) state[i] = aes_sbox(state[i]);
}

static void aes_shift_rows(uint8_t state[16])
{
    uint8_t tmp[16];
    unsigned int row, col;
    memcpy(tmp, state, sizeof(tmp));
    for (row = 0U; row < 4U; ++row) {
        for (col = 0U; col < 4U; ++col) {
            state[4U * col + row] = tmp[4U * ((col + row) % 4U) + row];
        }
    }
}

static void aes_mix_columns(uint8_t state[16])
{
    unsigned int col;
    for (col = 0U; col < 4U; ++col) {
        uint8_t *s = state + 4U * col;
        const uint8_t a0 = s[0], a1 = s[1], a2 = s[2], a3 = s[3];
        s[0] = (uint8_t)(gf_mul(a0, 2U) ^ gf_mul(a1, 3U) ^ a2 ^ a3);
        s[1] = (uint8_t)(a0 ^ gf_mul(a1, 2U) ^ gf_mul(a2, 3U) ^ a3);
        s[2] = (uint8_t)(a0 ^ a1 ^ gf_mul(a2, 2U) ^ gf_mul(a3, 3U));
        s[3] = (uint8_t)(gf_mul(a0, 3U) ^ a1 ^ a2 ^ gf_mul(a3, 2U));
    }
}

static void aes_encrypt_block(const uint8_t key[32], const uint8_t input[16], uint8_t output[16])
{
    uint8_t expanded[AES_EXPANDED_KEY_BYTES];
    uint8_t state[16];
    unsigned int round;
    aes_expand_key(key, expanded);
    memcpy(state, input, sizeof(state));
    aes_add_round_key(state, expanded);
    for (round = 1U; round < AES_ROUNDS; ++round) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, expanded + 16U * round);
    }
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, expanded + 16U * AES_ROUNDS);
    memcpy(output, state, sizeof(state));
    memset(expanded, 0, sizeof(expanded));
    memset(state, 0, sizeof(state));
}

static void secure_zero(void *memory, size_t length)
{
    volatile uint8_t *p = (volatile uint8_t *)memory;
    while (length-- != 0U) *p++ = 0U;
}

static void increment_v(uint8_t v[16])
{
    size_t i = 16U;
    while (i-- != 0U) {
        if (++v[i] != 0U) break;
    }
}

static void bcc(const uint8_t key[32], const uint8_t *data, size_t data_len, uint8_t output[16])
{
    uint8_t chaining[16] = {0};
    uint8_t block[16];
    size_t offset;
    for (offset = 0U; offset < data_len; offset += 16U) {
        size_t i;
        for (i = 0U; i < 16U; ++i) block[i] = (uint8_t)(chaining[i] ^ data[offset + i]);
        aes_encrypt_block(key, block, chaining);
    }
    memcpy(output, chaining, 16U);
    secure_zero(chaining, sizeof(chaining));
    secure_zero(block, sizeof(block));
}

static bignum_ctr_drbg_status_t block_cipher_df(
    const uint8_t *input, size_t input_len, uint8_t output[48])
{
    uint8_t s[4U + 4U + BIGNUM_CTR_DRBG_MAX_INPUT_BYTES + 16U];
    uint8_t data[16U + sizeof(s)];
    uint8_t temp[48];
    uint8_t key[32];
    uint8_t x[16];
    size_t s_len = 9U + input_len;
    size_t temp_len = 0U;
    unsigned int i;
    if (input_len > BIGNUM_CTR_DRBG_MAX_INPUT_BYTES || (input_len != 0U && input == NULL)) {
        return BIGNUM_CTR_DRBG_ERROR_INPUT;
    }
    store_be32(s, (uint32_t)input_len);
    store_be32(s + 4U, BIGNUM_CTR_DRBG_SEED_BYTES);
    if (input_len != 0U) memcpy(s + 8U, input, input_len);
    s[8U + input_len] = 0x80U;
    while ((s_len % 16U) != 0U) s[s_len++] = 0U;
    for (i = 0U; i < 32U; ++i) key[i] = (uint8_t)i;
    for (i = 0U; temp_len < sizeof(temp); ++i) {
        memset(data, 0, 16U);
        store_be32(data, i);
        memcpy(data + 16U, s, s_len);
        bcc(key, data, 16U + s_len, temp + temp_len);
        temp_len += 16U;
    }
    memcpy(key, temp, sizeof(key));
    memcpy(x, temp + sizeof(key), sizeof(x));
    for (i = 0U; i < sizeof(temp) / sizeof(x); ++i) {
        aes_encrypt_block(key, x, temp + 16U * i);
        memcpy(x, temp + 16U * i, sizeof(x));
    }
    memcpy(output, temp, 48U);
    secure_zero(s, sizeof(s));
    secure_zero(data, sizeof(data));
    secure_zero(temp, sizeof(temp));
    secure_zero(key, sizeof(key));
    secure_zero(x, sizeof(x));
    return BIGNUM_CTR_DRBG_SUCCESS;
}

static void ctr_drbg_update(const uint8_t provided_data[48], uint8_t key[32], uint8_t v[16])
{
    uint8_t temp[48];
    uint8_t block[16];
    size_t i;
    for (i = 0U; i < sizeof(temp); i += 16U) {
        increment_v(v);
        aes_encrypt_block(key, v, block);
        memcpy(temp + i, block, 16U);
    }
    for (i = 0U; i < sizeof(temp); ++i) temp[i] ^= provided_data[i];
    memcpy(key, temp, 32U);
    memcpy(v, temp + 32U, 16U);
    secure_zero(temp, sizeof(temp));
    secure_zero(block, sizeof(block));
}

static bignum_ctr_drbg_status_t make_seed(
    const uint8_t *entropy, size_t entropy_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *personalization, size_t personalization_len,
    uint8_t seed[48])
{
    uint8_t input[BIGNUM_CTR_DRBG_MAX_INPUT_BYTES];
    size_t total;
    if (entropy == NULL || nonce == NULL || entropy_len != 32U || nonce_len != 16U ||
        personalization_len > BIGNUM_CTR_DRBG_MAX_INPUT_BYTES ||
        (personalization_len != 0U && personalization == NULL)) return BIGNUM_CTR_DRBG_ERROR_INPUT;
    if (personalization_len > BIGNUM_CTR_DRBG_MAX_INPUT_BYTES - entropy_len - nonce_len) return BIGNUM_CTR_DRBG_ERROR_INPUT;
    total = entropy_len + nonce_len + personalization_len;
    memcpy(input, entropy, entropy_len);
    memcpy(input + entropy_len, nonce, nonce_len);
    if (personalization_len != 0U) memcpy(input + entropy_len + nonce_len, personalization, personalization_len);
    {
        bignum_ctr_drbg_status_t status = block_cipher_df(input, total, seed);
        secure_zero(input, sizeof(input));
        return status;
    }
}

bignum_ctr_drbg_status_t bignum_ctr_drbg_instantiate(
    bignum_ctr_drbg_ctx *ctx, const uint8_t *entropy, size_t entropy_len,
    const uint8_t *nonce, size_t nonce_len, const uint8_t *personalization, size_t personalization_len)
{
    bignum_ctr_drbg_ctx candidate;
    uint8_t seed[48];
    bignum_ctr_drbg_status_t status;
    if (ctx == NULL) return BIGNUM_CTR_DRBG_ERROR_NULL_ARG;
    status = make_seed(entropy, entropy_len, nonce, nonce_len, personalization, personalization_len, seed);
    if (status != BIGNUM_CTR_DRBG_SUCCESS) return status;
    memset(&candidate, 0, sizeof(candidate));
    ctr_drbg_update(seed, candidate.key, candidate.v);
    candidate.reseed_counter = 1U;
    candidate.initialized = 1U;
    *ctx = candidate;
    secure_zero(&candidate, sizeof(candidate));
    secure_zero(seed, sizeof(seed));
    return BIGNUM_CTR_DRBG_SUCCESS;
}

bignum_ctr_drbg_status_t bignum_ctr_drbg_reseed(
    bignum_ctr_drbg_ctx *ctx, const uint8_t *entropy, size_t entropy_len,
    const uint8_t *additional_input, size_t additional_input_len)
{
    uint8_t input[BIGNUM_CTR_DRBG_MAX_INPUT_BYTES];
    uint8_t seed[48];
    bignum_ctr_drbg_status_t status;
    if (ctx == NULL) return BIGNUM_CTR_DRBG_ERROR_NULL_ARG;
    if (ctx->initialized == 0U) return BIGNUM_CTR_DRBG_ERROR_STATE;
    if (entropy == NULL || entropy_len != 32U || additional_input_len > BIGNUM_CTR_DRBG_MAX_INPUT_BYTES ||
        (additional_input_len != 0U && additional_input == NULL) || entropy_len + additional_input_len > sizeof(input)) {
        return BIGNUM_CTR_DRBG_ERROR_INPUT;
    }
    memcpy(input, entropy, entropy_len);
    if (additional_input_len != 0U) memcpy(input + entropy_len, additional_input, additional_input_len);
    status = block_cipher_df(input, entropy_len + additional_input_len, seed);
    if (status == BIGNUM_CTR_DRBG_SUCCESS) {
        ctr_drbg_update(seed, ctx->key, ctx->v);
        ctx->reseed_counter = 1U;
    }
    secure_zero(input, sizeof(input));
    secure_zero(seed, sizeof(seed));
    return status;
}

bignum_ctr_drbg_status_t bignum_ctr_drbg_generate(
    bignum_ctr_drbg_ctx *ctx, uint8_t *out, size_t out_len,
    const uint8_t *additional_input, size_t additional_input_len)
{
    bignum_ctr_drbg_ctx candidate;
    uint8_t add_data[48] = {0};
    uint8_t block[16];
    bignum_ctr_drbg_status_t status = BIGNUM_CTR_DRBG_SUCCESS;
    size_t offset;
    if (ctx == NULL || (out == NULL && out_len != 0U)) return BIGNUM_CTR_DRBG_ERROR_NULL_ARG;
    if (ctx->initialized == 0U) return BIGNUM_CTR_DRBG_ERROR_STATE;
    if (out_len > BIGNUM_CTR_DRBG_MAX_REQUEST_BYTES || additional_input_len > BIGNUM_CTR_DRBG_MAX_INPUT_BYTES ||
        (additional_input_len != 0U && additional_input == NULL)) return BIGNUM_CTR_DRBG_ERROR_INPUT;
    if (ctx->reseed_counter > DRBG_RESEED_INTERVAL) return BIGNUM_CTR_DRBG_ERROR_RESEED_REQUIRED;
    candidate = *ctx;
    if (additional_input_len != 0U) status = block_cipher_df(additional_input, additional_input_len, add_data);
    if (status != BIGNUM_CTR_DRBG_SUCCESS) return status;
    if (additional_input_len != 0U) ctr_drbg_update(add_data, candidate.key, candidate.v);
    for (offset = 0U; offset < out_len; offset += sizeof(block)) {
        size_t take = out_len - offset;
        if (take > sizeof(block)) take = sizeof(block);
        increment_v(candidate.v);
        aes_encrypt_block(candidate.key, candidate.v, block);
        memcpy(out + offset, block, take);
    }
    ctr_drbg_update(add_data, candidate.key, candidate.v);
    ++candidate.reseed_counter;
    *ctx = candidate;
    secure_zero(&candidate, sizeof(candidate));
    secure_zero(add_data, sizeof(add_data));
    secure_zero(block, sizeof(block));
    return BIGNUM_CTR_DRBG_SUCCESS;
}

void bignum_ctr_drbg_uninstantiate(bignum_ctr_drbg_ctx *ctx)
{
    if (ctx != NULL) secure_zero(ctx, sizeof(*ctx));
}
