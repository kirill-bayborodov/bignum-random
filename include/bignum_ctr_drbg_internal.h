/**
 * @file bignum_ctr_drbg_internal.h
 * @brief Internal AES-256 leaf boundary for the candidate CTR_DRBG.
 * @details This header is for the DRBG implementation, assembly equivalence
 * tests, and review tools only. Callers of the public context API must not
 * depend on expanded-key representation or backend selection. The expanded
 * key is sensitive working state and remains caller-owned only for the
 * duration of the documented internal operation.
 */
#ifndef BIGNUM_CTR_DRBG_INTERNAL_H
#define BIGNUM_CTR_DRBG_INTERNAL_H

#include "bignum_ctr_drbg.h"

#define BIGNUM_CTR_DRBG_EXPANDED_KEY_BYTES 240U

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Independent AES-NI YASM key expansion leaf; requires AES-NI. */
void bignum_ctr_drbg_aes256_expand_key_asm(
    const uint8_t key[BIGNUM_CTR_DRBG_KEY_BYTES],
    uint8_t expanded_key[BIGNUM_CTR_DRBG_EXPANDED_KEY_BYTES]);

/** @brief Independent AES-NI YASM block encryption leaf; requires AES-NI. */
void bignum_ctr_drbg_aes256_encrypt_expanded_asm(
    const uint8_t expanded_key[BIGNUM_CTR_DRBG_EXPANDED_KEY_BYTES],
    const uint8_t input[BIGNUM_CTR_DRBG_BLOCK_BYTES],
    uint8_t output[BIGNUM_CTR_DRBG_BLOCK_BYTES]);

/** @brief Expands a key through the runtime-selected internal backend. */
void bignum_ctr_drbg_aes256_expand_key_dispatch(
    const uint8_t key[BIGNUM_CTR_DRBG_KEY_BYTES],
    uint8_t expanded_key[BIGNUM_CTR_DRBG_EXPANDED_KEY_BYTES]);

/** @brief Independent YASM CTR_DRBG_Update leaf; requires AES-NI. */
void bignum_ctr_drbg_update_asm(
    const uint8_t provided_data[BIGNUM_CTR_DRBG_SEED_BYTES],
    uint8_t key[BIGNUM_CTR_DRBG_KEY_BYTES],
    uint8_t v[BIGNUM_CTR_DRBG_BLOCK_BYTES]);

/** @brief Runs CTR_DRBG_Update through the complete backend or C fallback. */
void bignum_ctr_drbg_update_dispatch(
    const uint8_t provided_data[BIGNUM_CTR_DRBG_SEED_BYTES],
    uint8_t key[BIGNUM_CTR_DRBG_KEY_BYTES],
    uint8_t v[BIGNUM_CTR_DRBG_BLOCK_BYTES]);

/** @brief Independent YASM BCC leaf; requires AES-NI. */
void bignum_ctr_drbg_bcc_asm(
    const uint8_t key[BIGNUM_CTR_DRBG_KEY_BYTES],
    const uint8_t *data, size_t data_len,
    uint8_t output[BIGNUM_CTR_DRBG_BLOCK_BYTES]);

/** @brief Runs BCC through the complete backend or C fallback. */
void bignum_ctr_drbg_bcc_dispatch(
    const uint8_t key[BIGNUM_CTR_DRBG_KEY_BYTES],
    const uint8_t *data, size_t data_len,
    uint8_t output[BIGNUM_CTR_DRBG_BLOCK_BYTES]);

/** @brief Independent YASM Block_Cipher_df leaf; requires AES-NI. */
bignum_ctr_drbg_status_t bignum_ctr_drbg_block_cipher_df_asm(
    const uint8_t *input, size_t input_len,
    uint8_t output[BIGNUM_CTR_DRBG_SEED_BYTES]);

/** @brief Runs Block_Cipher_df through the complete backend or C fallback. */
bignum_ctr_drbg_status_t bignum_ctr_drbg_block_cipher_df_dispatch(
    const uint8_t *input, size_t input_len,
    uint8_t output[BIGNUM_CTR_DRBG_SEED_BYTES]);

/**
 * @brief Expands an AES-256 key into fifteen round keys.
 * @details The output contains 240 bytes in the FIPS 197 word order. The
 * caller allocates the output and must zeroize it after the final use.
 * @param key [in] Exactly 32 key bytes; borrowed for the call.
 * @param expanded_key [out] Caller-allocated 240-byte schedule.
 * @pre Both pointers are valid for their complete fixed-size ranges.
 * @post Every output byte is written; no heap ownership is transferred.
 * @warning The output is sensitive key material and must not escape the
 * implementation boundary.
 * @thread_safety Thread-safe when distinct buffers are supplied.
 */
void bignum_ctr_drbg_aes256_expand_key(
    const uint8_t key[BIGNUM_CTR_DRBG_KEY_BYTES],
    uint8_t expanded_key[BIGNUM_CTR_DRBG_EXPANDED_KEY_BYTES]);

/**
 * @brief Encrypts one AES-256 block with an expanded schedule.
 * @details This deterministic leaf is the C11 reference operation selected
 * by the runtime dispatcher when the YASM AES-NI leaf is unavailable.
 * @param expanded_key [in] Caller-owned 240-byte schedule.
 * @param input [in] Exactly one 16-byte plaintext block.
 * @param output [out] Caller-allocated 16-byte ciphertext block; written only
 * after the fixed operation completes.
 * @pre All ranges are valid and non-overlapping where required by the caller.
 * @post Exactly 16 output bytes are produced; no state is retained.
 * @thread_safety Thread-safe for independent buffers.
 */
void bignum_ctr_drbg_aes256_encrypt_expanded(
    const uint8_t expanded_key[BIGNUM_CTR_DRBG_EXPANDED_KEY_BYTES],
    const uint8_t input[BIGNUM_CTR_DRBG_BLOCK_BYTES],
    uint8_t output[BIGNUM_CTR_DRBG_BLOCK_BYTES]);

/**
 * @brief Reports whether the runtime CPU advertises AES-NI.
 * @return Nonzero when AES-NI is available; zero otherwise.
 * @thread_safety Thread-safe; no mutable module state is exposed.
 */
int bignum_ctr_drbg_aes256_runtime_has_aesni(void);

/**
 * @brief Reports the linked runtime AES backend.
 * @return `1` for the AES-NI YASM leaf and `0` for the C11 fallback.
 * @thread_safety Thread-safe; no ownership is transferred.
 */
int bignum_ctr_drbg_aes256_backend(void);

/**
 * @brief Encrypts one block through the runtime-selected internal backend.
 * @param expanded_key [in] Caller-owned 240-byte schedule.
 * @param input [in] Exactly one 16-byte plaintext block.
 * @param output [out] Caller-allocated 16-byte ciphertext block.
 * @pre The caller has validated all fixed-size ranges.
 * @post The selected backend writes exactly one ciphertext block.
 * @thread_safety Thread-safe for independent buffers.
 */
void bignum_ctr_drbg_aes256_encrypt_dispatch(
    const uint8_t expanded_key[BIGNUM_CTR_DRBG_EXPANDED_KEY_BYTES],
    const uint8_t input[BIGNUM_CTR_DRBG_BLOCK_BYTES],
    uint8_t output[BIGNUM_CTR_DRBG_BLOCK_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* BIGNUM_CTR_DRBG_INTERNAL_H */
