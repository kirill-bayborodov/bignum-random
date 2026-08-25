; @file bignum_random.asm
; @brief x86-64 YASM implementation of bounded cryptographic bignum sampling.
; @details This System V AMD64 implementation exports `bignum_random` with
; rdi = caller-owned `bignum_t *out` and rsi = borrowed `const bignum_t *bound`.
; `bignum_t` stores 32 little-endian uint64_t words at offset 0 and `len` at
; offset 256. The routine validates pointers, aliasing and normalized positive
; bounds before it invokes the Linux x86-64 `getrandom` syscall (number 318).
;
; The function saves rbx, r12, r13, r14 and r15, allocates an aligned stack
; candidate record (32 words plus length), and makes no ABI-level C calls.
; `syscall` clobbers rax, rcx and r11; persistent output/bound/length/mask state
; therefore resides only in callee-saved registers. A Linux `getpid` syscall
; invalidates the per-thread entropy cache after fork; cache refill retries an
; interrupted `getrandom` and completes a short read before candidate use. The
; most-significant word is masked to `bit_length(bound)` and candidates >= bound
; are rejected. A one-word fast path avoids full temporary initialization. A
; full-capacity direct-syscall path avoids cache bookkeeping because its 256-byte
; request consumes an entire cache refill. Output is written only after
; acceptance, preserving the complete output object on every named error return.
;
; @return rax = bignum_random_status_t: 0 success; -1 null pointer; -2 empty
; range; -3 invalid length; -4 non-normalized bound; -5 entropy failure; -6
; aliased output and bound. The direction flag is cleared before `rep stosq`.
; @version 0.1.1

section .text

BIGNUM_CAPACITY      equ 32
BIGNUM_WORD_BYTES    equ 8
BIGNUM_LEN_OFFSET    equ BIGNUM_CAPACITY * BIGNUM_WORD_BYTES
BIGNUM_RECORD_QWORDS equ BIGNUM_CAPACITY + 1
BIGNUM_STACK_BYTES   equ 272
SYS_GETPID           equ 39
SYS_GETRANDOM        equ 318
ERRNO_EINTR          equ 4
TLS_CACHE_WORDS      equ BIGNUM_CAPACITY
TLS_CACHE_BYTES      equ TLS_CACHE_WORDS * BIGNUM_WORD_BYTES

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
    cld                             ; System V requires DF clear on return; no path sets it.

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
    jmp     .select_candidate_path

.full_top_mask:
    mov     r15, -1

.select_candidate_path:
    ; A one-word candidate needs only its stack word until acceptance. A
    ; full-capacity candidate bypasses cache bookkeeping and receives all words
    ; directly from getrandom. Intermediate lengths keep the generic zeroed
    ; record because their inactive words are committed to public output.
    cmp     r14, 1
    je      .candidate_attempt_one
    cmp     r14, BIGNUM_CAPACITY
    je      .candidate_attempt_full
    jmp     .candidate_attempt

.candidate_attempt:
    ; Generic lengths require a zero inactive tail for the fixed-size publish.
    mov     rdi, rsp
    xor     eax, eax
    mov     ecx, BIGNUM_RECORD_QWORDS
    rep stosq
    jmp     .entropy_prepare

.candidate_attempt_one:
    ; The accepted one-word path clears caller output only after comparison.
    ; Before acceptance, the candidate stack word is the only writable state.
    jmp     .entropy_prepare

.candidate_attempt_full:
    ; A 32-word direct read overwrites the complete word region. `len` is set
    ; only after acceptance, so its prior stack contents are never read.
    mov     r8, TLS_CACHE_BYTES
    mov     r9, rsp
    jmp     .entropy_direct_fill

.entropy_prepare:
    ; Cache state is per ELF thread. A post-fork child inherits parent memory,
    ; so compare a fresh PID on every public call and discard inherited bytes.
    ; getpid cannot report an application-visible error on Linux x86-64.
    mov     eax, SYS_GETPID
    syscall
    cmp     rax, [fs:tls_cache_pid wrt ..tpoff]
    je      .entropy_consume_begin
    mov     [fs:tls_cache_pid wrt ..tpoff], rax
    mov     qword [fs:tls_cache_available wrt ..tpoff], 0

.entropy_consume_begin:
    mov     r8, r14                  ; words still required by this candidate
    xor     r9d, r9d                 ; destination word index in stack record

.entropy_consume:
    test    r8, r8
    jz      .candidate_ready
    mov     rcx, [fs:tls_cache_available wrt ..tpoff]
    test    rcx, rcx
    jz      .cache_refill_start
    mov     rax, [fs:tls_cache_index wrt ..tpoff]
    mov     rdx, [fs:tls_entropy_words + rax * BIGNUM_WORD_BYTES wrt ..tpoff]
    mov     [rsp + r9 * BIGNUM_WORD_BYTES], rdx
    inc     rax
    dec     rcx
    mov     [fs:tls_cache_index wrt ..tpoff], rax
    mov     [fs:tls_cache_available wrt ..tpoff], rcx
    inc     r9
    dec     r8
    jmp     .entropy_consume

.cache_refill_start:
    ; Local-exec TLS gives this executable a fixed negative TPOFF. FS:0 is the
    ; current thread pointer; adding the relocated offset forms a writable cache
    ; address without any C call or shared global pointer.
    mov     rdi, [fs:0]
    add     rdi, tls_entropy_words wrt ..tpoff
    mov     rsi, TLS_CACHE_BYTES

.cache_refill:
    mov     eax, SYS_GETRANDOM
    xor     edx, edx                 ; flags = 0 selects initialized urandom
    syscall
    test    rax, rax
    jg      .cache_refill_progress
    cmp     rax, -ERRNO_EINTR
    je      .cache_refill
    jmp     .error_entropy

.cache_refill_progress:
    add     rdi, rax
    sub     rsi, rax
    jnz     .cache_refill
    mov     qword [fs:tls_cache_index wrt ..tpoff], 0
    mov     qword [fs:tls_cache_available wrt ..tpoff], TLS_CACHE_WORDS
    jmp     .entropy_consume

.entropy_direct_fill:
    ; Full-capacity calls have no cache amortization opportunity. Retain the
    ; robust direct fill loop so EINTR and short reads preserve the public status
    ; contract without paying PID/TLS bookkeeping on every 256-byte request.
    mov     eax, SYS_GETRANDOM
    mov     rdi, r9
    mov     rsi, r8
    xor     edx, edx
    syscall
    test    rax, rax
    jg      .entropy_direct_progress
    cmp     rax, -ERRNO_EINTR
    je      .entropy_direct_fill
    jmp     .error_entropy

.entropy_direct_progress:
    add     r9, rax
    sub     r8, rax
    jnz     .entropy_direct_fill

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
    ; The one-word path normalizes and publishes directly; generic and full
    ; paths retain the bounded high-to-low normalization loop.
    cmp     r14, 1
    je      .publish_one_word

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
    rep movsq
    jmp     .publish_length

.publish_one_word:
    ; Commit only after an accepted one-word sample. Clearing the complete
    ; caller record establishes the zero tail; the sampled word and normalized
    ; length are then stored without a generic stack-record copy.
    mov     rdx, [rsp]
    mov     rdi, r12
    xor     eax, eax
    mov     ecx, BIGNUM_RECORD_QWORDS
    rep stosq
    mov     [r12], rdx
    test    rdx, rdx
    setne   al
    movzx   rax, al
    mov     [r12 + BIGNUM_LEN_OFFSET], rax

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

section .tbss nobits alloc write tls align=8
; @brief Per-thread raw entropy cache used only by the YASM production path.
; @details Each ELF thread owns an independent 32-word cache. `tls_cache_pid`
; invalidates inherited cache bytes after fork, while index and available count
; describe the unread suffix. The cache is refilled solely with Linux
; `getrandom(2)` output and no caller pointer or output object is retained.
tls_entropy_words:   resq TLS_CACHE_WORDS
tls_cache_index:     resq 1
tls_cache_available: resq 1
tls_cache_pid:       resq 1

section .note.GNU-stack noalloc noexec nowrite progbits
