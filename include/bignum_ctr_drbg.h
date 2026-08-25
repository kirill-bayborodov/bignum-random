/**
 * @file bignum_ctr_drbg.h
 * @brief Candidate AES-256 CTR_DRBG context API for Track B validation.
 * @details This interface is a C11 reference boundary for the AES-256
 * CTR_DRBG with the SP 800-90A block-cipher derivation function. It is not a
 * FIPS certificate or an assertion that the surrounding module is Approved.
 * The caller supplies entropy and nonce bytes at instantiation and supplies
 * additional input explicitly at generation and reseed operations.
 *
 * @version 0.1.0
 */
#ifndef BIGNUM_CTR_DRBG_H
#define BIGNUM_CTR_DRBG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BIGNUM_CTR_DRBG_KEY_BYTES 32U
#define BIGNUM_CTR_DRBG_BLOCK_BYTES 16U
#define BIGNUM_CTR_DRBG_SEED_BYTES 48U
#define BIGNUM_CTR_DRBG_EXPANDED_KEY_BYTES 240U
#define BIGNUM_CTR_DRBG_MAX_REQUEST_BYTES 65536U
#define BIGNUM_CTR_DRBG_MAX_INPUT_BYTES 1024U

typedef enum bignum_ctr_drbg_status {
    BIGNUM_CTR_DRBG_SUCCESS = 0,
    BIGNUM_CTR_DRBG_ERROR_NULL_ARG = -1,
    BIGNUM_CTR_DRBG_ERROR_INPUT = -2,
    BIGNUM_CTR_DRBG_ERROR_STATE = -3,
    BIGNUM_CTR_DRBG_ERROR_RESEED_REQUIRED = -4
} bignum_ctr_drbg_status_t;

typedef struct bignum_ctr_drbg_ctx {
    uint8_t key[BIGNUM_CTR_DRBG_KEY_BYTES];
    uint8_t v[BIGNUM_CTR_DRBG_BLOCK_BYTES];
    uint64_t reseed_counter;
    uint8_t initialized;
} bignum_ctr_drbg_ctx;

bignum_ctr_drbg_status_t bignum_ctr_drbg_instantiate(
    bignum_ctr_drbg_ctx *ctx,
    const uint8_t *entropy, size_t entropy_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *personalization, size_t personalization_len);

bignum_ctr_drbg_status_t bignum_ctr_drbg_reseed(
    bignum_ctr_drbg_ctx *ctx,
    const uint8_t *entropy, size_t entropy_len,
    const uint8_t *additional_input, size_t additional_input_len);

bignum_ctr_drbg_status_t bignum_ctr_drbg_generate(
    bignum_ctr_drbg_ctx *ctx,
    uint8_t *out, size_t out_len,
    const uint8_t *additional_input, size_t additional_input_len);

void bignum_ctr_drbg_uninstantiate(bignum_ctr_drbg_ctx *ctx);

/** Expands one AES-256 key into the FIPS 197 15-round key schedule. */
void bignum_ctr_drbg_aes256_expand_key(
    const uint8_t key[BIGNUM_CTR_DRBG_KEY_BYTES],
    uint8_t expanded_key[BIGNUM_CTR_DRBG_EXPANDED_KEY_BYTES]);

/** Encrypts one block using an expanded AES-256 key schedule. */
void bignum_ctr_drbg_aes256_encrypt_expanded(
    const uint8_t expanded_key[BIGNUM_CTR_DRBG_EXPANDED_KEY_BYTES],
    const uint8_t input[BIGNUM_CTR_DRBG_BLOCK_BYTES],
    uint8_t output[BIGNUM_CTR_DRBG_BLOCK_BYTES]);

/** Returns nonzero when the runtime CPU advertises AES-NI. */
int bignum_ctr_drbg_aes256_runtime_has_aesni(void);

/** Returns the selected backend: 0 for C11 fallback, 1 for AES-NI YASM. */
int bignum_ctr_drbg_aes256_backend(void);

/** Encrypts one block through the safe runtime-selected backend. */
void bignum_ctr_drbg_aes256_encrypt_dispatch(
    const uint8_t expanded_key[BIGNUM_CTR_DRBG_EXPANDED_KEY_BYTES],
    const uint8_t input[BIGNUM_CTR_DRBG_BLOCK_BYTES],
    uint8_t output[BIGNUM_CTR_DRBG_BLOCK_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* BIGNUM_CTR_DRBG_H */

// Candidate boundary only: CAVP vector success is required before any
// assembly port or certification claim.
