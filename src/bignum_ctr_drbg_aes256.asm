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
GLOBAL bignum_ctr_drbg_update_asm
%ifdef BIGNUM_DRBG_ZEROIZE_PROBE
EXTERN bignum_ctr_drbg_zeroization_probe
%endif

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

; void bignum_ctr_drbg_update_asm(const uint8_t provided_data[48],
;     uint8_t key[32], uint8_t v[16]);
; This leaf owns a private schedule/temp area and clears it before return.
bignum_ctr_drbg_update_asm:
    push        rbp
    mov         rbp, rsp
    push        r12
    push        r13
    push        r14
    push        r15
    sub         rsp, 304
    mov         r12, rdi
    mov         r13, rsi
    mov         r14, rdx

    mov         rdi, r13
    mov         rsi, rsp
    call        bignum_ctr_drbg_aes256_expand_key_asm

    xor         r15d, r15d
.update_block:
    lea         rax, [r14 + 15]
    mov         ecx, 16
.increment_v:
    inc         byte [rax]
    jnz         .counter_done
    dec         rax
    dec         ecx
    jnz         .increment_v
.counter_done:
    mov         rdi, rsp
    mov         rsi, r14
    lea         rdx, [rsp + 240]
    mov         rax, r15
    shl         rax, 4
    add         rdx, rax
    call        bignum_ctr_drbg_aes256_encrypt_expanded_asm
    inc         r15d
    cmp         r15d, 3
    jb          .update_block

    xor         ecx, ecx
.xor_provided:
    mov         al, [rsp + 240 + rcx]
    xor         al, [r12 + rcx]
    mov         [rsp + 240 + rcx], al
    inc         ecx
    cmp         ecx, 48
    jb          .xor_provided

    movdqu      xmm0, [rsp + 240]
    movdqu      [r13], xmm0
    movdqu      xmm0, [rsp + 256]
    movdqu      [r13 + 16], xmm0
    movdqu      xmm0, [rsp + 272]
    movdqu      [r14], xmm0

    pxor        xmm0, xmm0
    pxor        xmm1, xmm1
    pxor        xmm2, xmm2
    pxor        xmm3, xmm3
    xor         eax, eax
    lea         rdi, [rsp]
    mov         ecx, 38
    rep stosq
%ifdef BIGNUM_DRBG_ZEROIZE_PROBE
    lea         rdi, [rsp]
    mov         rsi, 304
    call        bignum_ctr_drbg_zeroization_probe
%endif
    add         rsp, 304
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    ret

SECTION .note.GNU-stack noalloc noexec nowrite progbits
