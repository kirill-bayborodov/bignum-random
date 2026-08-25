; bignum_ctr_drbg_aes256.asm
; Independent AES-NI AES-256 key expansion and one-block encryption leaves.
; System V AMD64 ABI, no calls and no stack frame.
;
; void bignum_ctr_drbg_aes256_expand_key_asm(
;     const uint8_t key[32], uint8_t expanded_key[240]);
; void bignum_ctr_drbg_aes256_encrypt_expanded_asm(
;     const uint8_t expanded_key[240], const uint8_t input[16],
;     uint8_t output[16]);
;
; Both leaves require CPUID AES-NI support. Dispatch is responsible for
; runtime feature gating. The key schedule is written in FIPS 197 byte order.

BITS 64
DEFAULT REL

GLOBAL bignum_ctr_drbg_aes256_expand_key_asm
GLOBAL bignum_ctr_drbg_aes256_encrypt_expanded_asm

SECTION .text

bignum_ctr_drbg_aes256_expand_key_asm:
    movdqu      xmm0, [rdi]
    movdqu      xmm1, [rdi + 16]
    movdqu      [rsi], xmm0
    movdqu      [rsi + 16], xmm1

%macro AES256_EXPAND 2
    aeskeygenassist xmm2, xmm1, %2
    pshufd      xmm2, xmm2, 0xff
    movdqa      xmm3, xmm0
    pslldq      xmm3, 4
    pxor        xmm0, xmm3
    movdqa      xmm3, xmm0
    pslldq      xmm3, 4
    pxor        xmm0, xmm3
    movdqa      xmm3, xmm0
    pslldq      xmm3, 4
    pxor        xmm0, xmm3
    pxor        xmm0, xmm2
    movdqu      [rsi + %1], xmm0

    aeskeygenassist xmm2, xmm0, 0
    pshufd      xmm2, xmm2, 0xaa
    movdqa      xmm3, xmm1
    pslldq      xmm3, 4
    pxor        xmm1, xmm3
    movdqa      xmm3, xmm1
    pslldq      xmm3, 4
    pxor        xmm1, xmm3
    movdqa      xmm3, xmm1
    pslldq      xmm3, 4
    pxor        xmm1, xmm3
    pxor        xmm1, xmm2
%if %1 < 224
    movdqu      [rsi + %1 + 16], xmm1
%endif
%endmacro

    AES256_EXPAND 32, 0x01
    AES256_EXPAND 64, 0x02
    AES256_EXPAND 96, 0x04
    AES256_EXPAND 128, 0x08
    AES256_EXPAND 160, 0x10
    AES256_EXPAND 192, 0x20
    AES256_EXPAND 224, 0x40
    ret

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
