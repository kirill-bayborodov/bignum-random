; bignum_ctr_drbg_aes256.asm
; Candidate AES-256 encryption leaf for the Track B assembly handoff.
; ABI: void bignum_ctr_drbg_aes256_encrypt_expanded(
;          const uint8_t expanded_key[240],
;          const uint8_t input[16],
;          uint8_t output[16]);
; System V AMD64: RDI, RSI, RDX. Requires CPUID AES-NI support.
; This leaf is not reachable from the production Approved path yet.

BITS 64
DEFAULT REL

GLOBAL bignum_ctr_drbg_aes256_encrypt_expanded_asm

SECTION .text

bignum_ctr_drbg_aes256_encrypt_expanded_asm:
    movdqu      xmm0, [rsi]
    pxor        xmm0, [rdi]
    aesenc      xmm0, [rdi + 16]
    aesenc      xmm0, [rdi + 32]
    aesenc      xmm0, [rdi + 48]
    aesenc      xmm0, [rdi + 64]
    aesenc      xmm0, [rdi + 80]
    aesenc      xmm0, [rdi + 96]
    aesenc      xmm0, [rdi + 112]
    aesenc      xmm0, [rdi + 128]
    aesenc      xmm0, [rdi + 144]
    aesenc      xmm0, [rdi + 160]
    aesenc      xmm0, [rdi + 176]
    aesenc      xmm0, [rdi + 192]
    aesenc      xmm0, [rdi + 208]
    aesenclast  xmm0, [rdi + 224]
    movdqu      [rdx], xmm0
    ret

SECTION .note.GNU-stack noalloc noexec nowrite progbits
