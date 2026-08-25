; @file bignum_random.asm
; @brief x86-64 YASM implementation of bounded cryptographic bignum sampling.
; @details This System V AMD64 implementation exports `bignum_random` with
; rdi = caller-owned `bignum_t *out` and rsi = borrowed `const bignum_t *bound`.
; `bignum_t` stores 32 little-endian uint64_t words at offset 0 and `len` at
; offset 256. The routine validates pointers, aliasing and normalized positive
; bounds before it invokes the Linux x86-64 `getrandom` syscall (number 318).
;
; The function saves rbx, r12, r13, r14 and r15, allocates an aligned stack
; candidate record (32 words plus length), and makes no ABI-level C calls. `syscall` clobbers rax, rcx
; and r11; persistent output/bound/length/mask state therefore resides only in
; callee-saved registers. It retries a syscall interrupted with -EINTR and
; fills a partial read before using the candidate. The most-significant word is
; masked to `bit_length(bound)` and candidates >= bound are rejected. Output is
; zeroed and written only after an accepted candidate is normalized, preserving
; the complete output object on every named error return.
;
; @return rax = bignum_random_status_t: 0 success; -1 null pointer; -2 empty
; range; -3 invalid length; -4 non-normalized bound; -5 entropy failure; -6
; aliased output and bound. The direction flag is cleared before `rep stosq`.
; @version 1.0.0

section .text

BIGNUM_CAPACITY      equ 32
BIGNUM_WORD_BYTES    equ 8
BIGNUM_LEN_OFFSET    equ BIGNUM_CAPACITY * BIGNUM_WORD_BYTES
BIGNUM_RECORD_QWORDS equ BIGNUM_CAPACITY + 1
BIGNUM_STACK_BYTES   equ 272
SYS_GETRANDOM        equ 318
ERRNO_EINTR          equ 4

STATUS_SUCCESS        equ 0
STATUS_NULL_ARG       equ -1
STATUS_RANGE          equ -2
STATUS_LENGTH         equ -3
STATUS_NORMALIZATION  equ -4
STATUS_ENTROPY        equ -5
STATUS_ALIAS          equ -6

; @brief Samples a uniform bignum from the valid interval [0, bound).
; @details ABI: rdi is writable output and rsi is a read-only bound. rbx, r12,
; r13, r14 and r15 are preserved. The stack allocation is private candidate
; storage and is released on every return. No condition flags survive the call.
; The Linux syscall interface receives rax = 318, rdi = byte buffer, rsi = byte
; count, rdx = flags zero; only rax/rcx/r11 are treated as syscall-clobbered.
; @param rdi [out] `bignum_t *out`, non-NULL and distinct from rsi.
; @param rsi [in] `const bignum_t *bound`, normalized, positive and in capacity.
; @return rax named bignum_random_status_t; output changes only on success.
; @warning Candidate rejection count is data-dependent by design for unbiased
; sampling. This routine requires Linux x86-64 `getrandom` syscall support.
global bignum_random
bignum_random:
    ; Null and alias checks precede stack mutation and all bound dereferences.
    test    rdi, rdi
    jz      .error_null
    test    rsi, rsi
    jz      .error_null
    cmp     rdi, rsi
    je      .error_alias

    ; Preserve System V callee-saved state used across the syscall/retry loop.
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, BIGNUM_STACK_BYTES

    mov     r12, rdi                 ; persistent output pointer
    mov     r13, rsi                 ; persistent upper-bound pointer
    mov     r14, [r13 + BIGNUM_LEN_OFFSET]

    ; Validate the core fixed-capacity and normalization invariants transactionally.
    test    r14, r14
    jz      .error_range
    cmp     r14, BIGNUM_CAPACITY
    ja      .error_length
    mov     rax, [r13 + r14 * BIGNUM_WORD_BYTES - BIGNUM_WORD_BYTES]
    test    rax, rax
    jz      .error_normalization

    ; r15 becomes (1 << top_bits) - 1, except an all-one mask for 64 bits.
    bsr     rcx, rax
    inc     rcx
    cmp     rcx, 64
    je      .full_top_mask
    mov     r15, 1
    shl     r15, cl
    dec     r15
    jmp     .candidate_attempt

.full_top_mask:
    mov     r15, -1

.candidate_attempt:
    ; Clear the complete stack record before every entropy request. The accepted
    ; record can then be committed with one fixed-size REP MOVSQ, matching the
    ; efficient C11 struct-assignment shape and guaranteeing zero inactive words.
    mov     rdi, rsp
    xor     eax, eax
    mov     ecx, BIGNUM_RECORD_QWORDS
    cld
    rep stosq

    ; Fill exactly active_words * 8 bytes. A short successful syscall advances
    ; the buffer, while -EINTR is retried before the candidate is inspected.
    mov     r8, r14
    shl     r8, 3
    mov     r9, rsp

.entropy_fill:
    mov     eax, SYS_GETRANDOM
    mov     rdi, r9
    mov     rsi, r8
    xor     edx, edx                 ; flags = 0 selects initialized urandom
    syscall
    test    rax, rax
    jg      .entropy_progress
    cmp     rax, -ERRNO_EINTR
    je      .entropy_fill
    jmp     .error_entropy

.entropy_progress:
    add     r9, rax
    sub     r8, rax
    jnz     .entropy_fill

.candidate_ready:
    ; Constrain the sample to the bound bit width before numeric comparison.
    mov     rax, [rsp + r14 * BIGNUM_WORD_BYTES - BIGNUM_WORD_BYTES]
    and     rax, r15
    mov     [rsp + r14 * BIGNUM_WORD_BYTES - BIGNUM_WORD_BYTES], rax

    ; Compare little-endian arrays from the highest word. Equality is rejected
    ; because the public interval is half-open and requires candidate < bound.
    mov     rcx, r14
.compare_candidate:
    dec     rcx
    mov     rax, [rsp + rcx * BIGNUM_WORD_BYTES]
    cmp     rax, [r13 + rcx * BIGNUM_WORD_BYTES]
    jb      .candidate_accepted
    ja      .candidate_attempt
    test    rcx, rcx
    jnz     .compare_candidate
    jmp     .candidate_attempt

.candidate_accepted:
    ; Normalize candidate length without reading inactive or uninitialized data.
    mov     rbx, r14
.normalize_candidate:
    test    rbx, rbx
    jz      .publish_candidate
    cmp     qword [rsp + rbx * BIGNUM_WORD_BYTES - BIGNUM_WORD_BYTES], 0
    jne     .publish_candidate
    dec     rbx
    jmp     .normalize_candidate

.publish_candidate:
    ; Only an accepted candidate may affect caller memory. Its zeroed tail and
    ; normalized length form a complete bignum_t record, so one fixed-size
    ; REP MOVSQ publishes words and length without a scalar copy loop.
    mov     [rsp + BIGNUM_LEN_OFFSET], rbx
    mov     rsi, rsp
    mov     rdi, r12
    mov     ecx, BIGNUM_RECORD_QWORDS
    cld
    rep movsq

.publish_length:
    mov     eax, STATUS_SUCCESS
    jmp     .finish

.error_range:
    mov     eax, STATUS_RANGE
    jmp     .finish

.error_length:
    mov     eax, STATUS_LENGTH
    jmp     .finish

.error_normalization:
    mov     eax, STATUS_NORMALIZATION
    jmp     .finish

.error_entropy:
    mov     eax, STATUS_ENTROPY

.finish:
    add     rsp, BIGNUM_STACK_BYTES
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

.error_null:
    mov     eax, STATUS_NULL_ARG
    ret

.error_alias:
    mov     eax, STATUS_ALIAS
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
