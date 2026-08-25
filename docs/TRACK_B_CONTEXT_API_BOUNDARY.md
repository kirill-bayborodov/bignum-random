# Track B Context API and C/ASM Boundary

**Status:** Design baseline for implementation and CSTL pre-review.  
**Validation claim:** None. This document defines engineering work required before an Approved-mode claim.

## API direction

The Approved service must not use the legacy implicit TLS raw-entropy cache. It should require an explicit opaque context whose ownership and lifecycle are visible to the caller. The legacy `bignum_random(out, upper_bound)` remains a compatibility/non-Approved service until the project either removes it or formally maps it to an initialized Approved context.

The proposed public API is:

```c
bignum_random_status_t bignum_random_module_startup(void);
bignum_random_status_t bignum_random_context_create(bignum_random_context_t **context);
bignum_random_status_t bignum_random_context_generate(
    bignum_random_context_t *context,
    bignum_t *out,
    const bignum_t *upper_bound);
bignum_random_status_t bignum_random_context_reseed(
    bignum_random_context_t *context);
bignum_random_status_t bignum_random_context_uninstantiate(
    bignum_random_context_t *context);
void bignum_random_context_destroy(bignum_random_context_t *context);
```

The type is opaque to callers. `create` and `destroy` define the only ownership transfer; `destroy` must zeroize the complete context before releasing it. The candidate now uses caller-allocated storage through `bignum_ctr_drbg_context_t`. `bignum_ctr_drbg_context_size()` returns the exact allocation size; the object must be allocated with its natural alignment and must not be copied or inspected after initialization. `bignum_ctr_drbg_context_init()` zeroizes prior bytes and establishes a private initialization marker. The implementation stores the lifecycle and DRBG object inside opaque-style storage, while the public caller sees no AES expanded-key representation.

`module_startup` performs image-integrity and power-up self-tests once for the validated module image. `context_create` performs Approved DRBG instantiation only after startup is `READY`. `context_generate` obtains random words from the DRBG and applies the deterministic bounded rejection transform. `context_reseed` is allowed only in the lifecycle states where reseed is required. The entropy-provider callback is synchronous, caller-owned, and borrowed: it receives exactly 32 bytes of writable output, must either fill the complete buffer and return SUCCESS or return failure, and is never stored in the context. Provider failure zeroizes partial DRBG state and latches ERROR before returning; no provider callback is invoked from ERROR or ZEROIZED states. `context_uninstantiate` zeroizes DRBG and provider state and moves the context to `ZEROIZED`; `destroy` is idempotent only if that behavior is explicitly frozen in the final API.

## Service separation

| Service | Intended mode | Entropy source | State | Validation treatment |
|---|---|---|---|---|
| `bignum_random` legacy function | Non-Approved compatibility | Direct Linux `getrandom(2)` | No explicit DRBG context; current TLS cache must be excluded from Approved image | Must be labelled non-Approved or removed from the validated build. |
| `module_startup` | Approved lifecycle | No ordinary generation | Module startup/self-test state | Required before Approved services. |
| `context_create` | Approved | Entropy provider feeding selected DRBG | `UNINITIALIZED -> SELF_TEST/READY` | Included in module boundary and evidence. |
| `context_generate` | Approved | DRBG output only | `READY` or `RESEED_REQUIRED` | Bounded range service; no direct syscall fallback. |
| `context_reseed` | Approved | Approved entropy/reseed path | `RESEED_REQUIRED -> READY` | Input, limits, and failure behavior require KAT/fault evidence. |
| `context_init` / provider boundary | Approved | Caller-owned storage and caller-owned provider | `UNINITIALIZED` before startup; provider is transient | Size/alignment, callback completion, provider failure and zeroization require fault evidence. |
| `context_uninstantiate` | Approved lifecycle | None | `READY -> ZEROIZED` | Zeroization and post-use inhibition required. |

## C/ASM boundary

The C wrapper owns public validation, state transitions, output preservation, and provider/DRBG orchestration. The ASM kernel may implement a leaf operation only when its contract is deterministic and fully specified. The preferred first ASM boundary is a private `ctr_drbg_generate_block` or AES primitive with a fixed-size context pointer and explicit output length; the public context state machine remains in C until the C implementation and KATs are stable.

Every assembly symbol must document the following facts directly beside its declaration:

| Boundary item | Required rule |
|---|---|
| Calling convention | System V AMD64 for the first Linux x86-64 target. |
| Arguments | Explicit register and memory layout; no hidden TLS or global state. |
| Callee-saved registers | `rbx`, `rbp`, `r12`–`r15` preserved where used. |
| Stack | 16-byte alignment at every C-call boundary; no red-zone assumptions unless frozen by the platform policy. |
| Clobbers | `rax`, `rcx`, `rdx`, `rsi`, `rdi`, `r8`–`r11`, flags, and vector registers as applicable. |
| Memory | Context and output ranges validated by the C wrapper; ASM must not retain caller pointers. |
| Status | Named module status returned in `rax`; no raw errno or syscall result crosses the public boundary. |
| Sensitive state | No key, `V`, seed, entropy, or intermediate AES state is returned; cleanup is explicit. |
| Processor features | AES-NI/VAES variants are selected only under a frozen CPU policy and validated operational-environment scope. |

## DRBG context layout target

The exact layout is pending CSTL confirmation of the selected CTR_DRBG profile. At minimum, the private context must represent the AES key, internal `V`, reseed counter, instantiate/reseed state, error latch, provider state, and zeroization marker. The layout must not be ABI-stable until its versioning and endianness rules are frozen.

The bounded sampler must request enough DRBG output for the active bound, mask only the unused high bits, reject values not strictly below the bound, normalize the accepted value, and publish only after acceptance. The sampler must never read or write DRBG private fields directly. This separation allows the sampler proof to be reviewed independently from the DRBG proof.

## Migration sequence

1. Add status values and lifecycle documentation without changing the legacy function's behavior.
2. Implement a C11 context and provider interface with a deterministic test provider; do not call it Approved until it uses the selected DRBG.
3. Implement AES-256 CTR_DRBG with derivation function in C11 and verify against authoritative known-answer vectors.
4. Add startup/conditional self-tests and the error latch before porting any primitive to ASM.
5. Port only the measured AES/DRBG leaf to YASM, retaining the C state machine and range sampler initially.
6. Add ABI, fault-injection, zeroization, fork/thread, sanitization, and exact-image evidence.
7. Freeze the caller-allocated context size/alignment and entropy-provider callback protocol only after CSTL review; the current values remain candidate engineering contracts.
8. Perform CSTL pre-review before exposing an Approved mode in release documentation.

## Hard constraints

No Approved service may fall back to raw Linux `getrandom(2)` if the DRBG is unavailable. No test provider, debug hook, benchmark callback, RDRAND path, or undocumented environment variable may be reachable from an Approved build. No processor-specific ASM optimization may be accepted solely because it improves a benchmark; it must preserve the selected DRBG algorithm, KAT vectors, state machine, and operational-environment claim.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[2]: https://csrc.nist.gov/pubs/fips/140-3/final "NIST FIPS 140-3"

[3]: https://man7.org/linux/man-pages/man2/getrandom.2.html "Linux getrandom(2)"

[4]: https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-standards "NIST CMVP FIPS 140-3 Standards"
