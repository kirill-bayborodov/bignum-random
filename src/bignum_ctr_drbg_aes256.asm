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
GLOBAL bignum_ctr_drbg_bcc_asm
GLOBAL bignum_ctr_drbg_bcc_expanded_asm
GLOBAL bignum_ctr_drbg_block_cipher_df_asm
%ifdef BIGNUM_DRBG_ZEROIZE_PROBE
EXTERN bignum_ctr_drbg_zeroization_probe
%endif
%ifdef BIGNUM_DRBG_DF_SNAPSHOT
EXTERN bignum_ctr_drbg_df_snapshot
%endif
%ifdef BIGNUM_DRBG_SECRET_ZEROIZE_PROBE
EXTERN bignum_ctr_drbg_secret_zeroization_probe
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

; void bignum_ctr_drbg_bcc_asm(const uint8_t key[32], const uint8_t *data,
;     size_t data_len, uint8_t output[16]);
; The C dispatcher validates that data_len is positive and block-aligned.
bignum_ctr_drbg_bcc_asm:
    push        rbp
    mov         rbp, rsp
    push        r12
    push        r13
    push        r14
    push        r15
    sub         rsp, 320
    mov         r12, rsi
    mov         r13, rdx
    mov         r14, rcx

    mov         rsi, rsp
    call        bignum_ctr_drbg_aes256_expand_key_asm

    pxor        xmm0, xmm0
    movdqu      [rsp + 240], xmm0
.bcc_block:
    test        r13, r13
    jz          .bcc_done
    movdqu      xmm0, [r12]
    pxor        xmm0, [rsp + 240]
    movdqu      [rsp + 256], xmm0
    mov         rdi, rsp
    lea         rsi, [rsp + 256]
    lea         rdx, [rsp + 240]
    call        bignum_ctr_drbg_aes256_encrypt_expanded_asm
    add         r12, 16
    sub         r13, 16
    jmp         .bcc_block
.bcc_done:
    movdqu      xmm0, [rsp + 240]
    movdqu      [r14], xmm0

    pxor        xmm0, xmm0
    pxor        xmm1, xmm1
    pxor        xmm2, xmm2
    pxor        xmm3, xmm3
    xor         eax, eax
    lea         rdi, [rsp]
    mov         ecx, 40
    rep stosq
%ifdef BIGNUM_DRBG_SECRET_ZEROIZE_PROBE
    lea         rdi, [rsp]
    mov         rsi, 320
    mov         edx, 1
    call        bignum_ctr_drbg_secret_zeroization_probe
%endif
    add         rsp, 320
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    ret

; void bignum_ctr_drbg_bcc_expanded_asm(const uint8_t expanded_key[240],
;     const uint8_t *data, size_t data_len, uint8_t output[16]);
; The expanded schedule is borrowed; only the 80-byte local workspace is wiped.
bignum_ctr_drbg_bcc_expanded_asm:
    push        rbp
    mov         rbp, rsp
    push        r12
    push        r13
    push        r14
    push        r15
    sub         rsp, 80
    mov         r15, rdi
    mov         r12, rsi
    mov         r13, rdx
    mov         r14, rcx

    pxor        xmm0, xmm0
    movdqu      [rsp], xmm0
.expanded_bcc_block:
    test        r13, r13
    jz          .expanded_bcc_done
    movdqu      xmm0, [r12]
    pxor        xmm0, [rsp]
    movdqu      [rsp + 16], xmm0
    mov         rdi, r15
    lea         rsi, [rsp + 16]
    mov         rdx, rsp
    call        bignum_ctr_drbg_aes256_encrypt_expanded_asm
    add         r12, 16
    sub         r13, 16
    jmp         .expanded_bcc_block
.expanded_bcc_done:
    movdqu      xmm0, [rsp]
    movdqu      [r14], xmm0
    pxor        xmm0, xmm0
    pxor        xmm1, xmm1
    pxor        xmm2, xmm2
    pxor        xmm3, xmm3
    xor         eax, eax
    lea         rdi, [rsp]
    mov         ecx, 10
    rep stosq
%ifdef BIGNUM_DRBG_SECRET_ZEROIZE_PROBE
    lea         rdi, [rsp]
    mov         rsi, 80
    mov         edx, 3
    call        bignum_ctr_drbg_secret_zeroization_probe
%endif
    add         rsp, 80
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    ret

; bignum_ctr_drbg_block_cipher_df_asm(const uint8_t *input, size_t input_len,
;     uint8_t output[48]);
; The C dispatcher validates 0 <= input_len <= 1024 and pointer ownership.
; The fixed workspace is 2440 bytes and is cleared before return.
bignum_ctr_drbg_block_cipher_df_asm:
    push        rbp
    mov         rbp, rsp
    push        r12
    push        r13
    push        r14
    push        r15
    push        rbx
    sub         rsp, 2440
    mov         r12, rdi
    mov         r13, rsi
    mov         r14, rdx

    mov         r15, r13
    add         r15, 9
    add         r15, 15
    and         r15, -16

    mov         eax, r13d
    bswap       eax
    mov         [rsp], eax
    mov         eax, 48
    bswap       eax
    mov         [rsp + 4], eax
    test        r13, r13
    jz          .df_no_input
    lea         rdi, [rsp + 8]
    mov         rsi, r12
    mov         rcx, r13
    rep movsb
.df_no_input:
    lea         rdi, [rsp + 8]
    add         rdi, r13
    mov         byte [rdi], 0x80
    inc         rdi
    mov         rcx, r15
    sub         rcx, r13
    sub         rcx, 9
    xor         eax, eax
    rep stosb

    lea         rdi, [rsp + 2144]
    xor         ebx, ebx
.df_init_key:
    mov         [rdi + rbx], bl
    inc         ebx
    cmp         ebx, 32
    jb          .df_init_key

    lea         rdi, [rsp + 2144]
    lea         rsi, [rsp + 2192]
    call        bignum_ctr_drbg_aes256_expand_key_asm

    xor         ebx, ebx
.df_bcc_loop:

    lea         rdi, [rsp + 1040]
    pxor        xmm0, xmm0
    movdqu      [rdi], xmm0
    mov         eax, ebx
    bswap       eax
    mov         [rdi], eax
    lea         rsi, [rsp]
    lea         rdi, [rsp + 1056]
    mov         rcx, r15
    rep movsb
    lea         rdi, [rsp + 2192]
    lea         rsi, [rsp + 1040]
    mov         rdx, r15
    add         rdx, 16
    lea         rcx, [rsp + 2096]
    mov         rax, rbx
    shl         rax, 4
    add         rcx, rax
    call        bignum_ctr_drbg_bcc_expanded_asm
%ifdef BIGNUM_DRBG_DF_SNAPSHOT
    mov         edi, ebx
    lea         rsi, [rsp + 2096]
    mov         rax, rbx
    shl         rax, 4
    add         rsi, rax
    mov         edx, 16
    call        bignum_ctr_drbg_df_snapshot
%endif
    inc         ebx
    cmp         ebx, 3
    jb          .df_bcc_loop

    ; key and x are local C arrays: copy 32-byte key and 16-byte X.
    movdqu      xmm0, [rsp + 2096]
    movdqu      [rsp + 2144], xmm0
    movdqu      xmm0, [rsp + 2112]
    movdqu      [rsp + 2160], xmm0
    movdqu      xmm0, [rsp + 2128]
    movdqu      [rsp + 2176], xmm0
%ifdef BIGNUM_DRBG_DF_SNAPSHOT
    mov         edi, 3
    lea         rsi, [rsp + 2144]
    mov         edx, 32
    call        bignum_ctr_drbg_df_snapshot
    mov         edi, 4
    lea         rsi, [rsp + 2176]
    mov         edx, 16
    call        bignum_ctr_drbg_df_snapshot
%endif

    lea         rdi, [rsp + 2144]
    lea         rsi, [rsp + 2192]
    call        bignum_ctr_drbg_aes256_expand_key_asm

    xor         ebx, ebx
.df_temp_loop:
    lea         rdi, [rsp + 2192]
    lea         rsi, [rsp + 2176]
    lea         rdx, [rsp + 2096]
    mov         rax, rbx
    shl         rax, 4
    add         rdx, rax
    call        bignum_ctr_drbg_aes256_encrypt_expanded_asm
    mov         rax, rbx
    shl         rax, 4
    movdqu      xmm0, [rsp + 2096 + rax]
    movdqu      [rsp + 2176], xmm0
%ifdef BIGNUM_DRBG_DF_SNAPSHOT
    mov         edi, ebx
    add         edi, 5
    lea         rsi, [rsp + 2096]
    mov         rax, rbx
    shl         rax, 4
    add         rsi, rax
    mov         edx, 16
    call        bignum_ctr_drbg_df_snapshot
%endif
    inc         ebx
    cmp         ebx, 3
    jb          .df_temp_loop

    movdqu      xmm0, [rsp + 2096]
    movdqu      [r14], xmm0
    movdqu      xmm0, [rsp + 2112]
    movdqu      [r14 + 16], xmm0
    movdqu      xmm0, [rsp + 2128]
    movdqu      [r14 + 32], xmm0

    pxor        xmm0, xmm0
    pxor        xmm1, xmm1
    pxor        xmm2, xmm2
    pxor        xmm3, xmm3
    xor         eax, eax
    lea         rdi, [rsp]
    mov         ecx, 305
    rep stosq
%ifdef BIGNUM_DRBG_SECRET_ZEROIZE_PROBE
    lea         rdi, [rsp]
    mov         rsi, 2440
    mov         edx, 2
    call        bignum_ctr_drbg_secret_zeroization_probe
%endif
    add         rsp, 2440
    pop         rbx
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    ret

SECTION .note.GNU-stack noalloc noexec nowrite progbits
