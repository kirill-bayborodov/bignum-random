# Archived non-public headers

## Public header boundary

The installed/public API for the `bignum-random` family is intentionally limited to:

```text
include/bignum_random.h
```

All other project-specific headers formerly located directly under `include/` are non-public implementation, validation, lifecycle, entropy-provider, or benchmark headers. They were moved out of the public include directory and preserved in:

```text
docs/archives/bignum-random-extra-headers-v0.1.1.tar.gz
```

SHA-256:

```text
3af592f703801d7e908697a546939baf78daa9d7866c2f7827a10e73073c2d61
```

The archive contains the following files:

| Header | Archived role |
|---|---|
| `bignum_ctr_drbg.h` | C11 AES-256 CTR_DRBG reference API |
| `bignum_ctr_drbg_internal.h` | AES/BCC/DF/YASM internal leaf API |
| `bignum_ctr_drbg_context.h` | Caller-allocated opaque DRBG context and provider callback |
| `bignum_ctr_drbg_module.h` | Lifecycle, self-test and fail-closed state wrapper |
| `bignum_ctr_drbg_os_entropy.h` | Linux `getrandom(2)` entropy-provider adapter |
| `bignum_ctr_drbg_service.h` | Narrow production-facing DRBG service façade |
| `benchmark_framework.h` | Benchmark-only framework forwarding header |

The DRBG headers remain available in the repository under `src/internal/` for the existing validation and FIPS engineering evidence. The benchmark forwarding header is kept under `benchmarks/adapter/` because it is not part of the library API.

## YASM assembly dependency

The production bounded-random assembly implementation is `src/bignum_random.asm`. It does not include any C header and does not call the CTR_DRBG code. Its ABI contract is encoded in the assembly constants and must match the `bignum_t` layout supplied by `bignum.h` through `bignum_random.h`.

The C implementation/benchmark/test translation units include `bignum_random.h`, which in turn includes the bignum-core header defining `bignum_t` and `BIGNUM_CAPACITY`. Therefore the answer is:

> **Yes, the standalone `bignum_random` YASM implementation requires only the public `bignum_random.h` contract at the library API level; the assembly source itself includes no header.**

This does not mean the entire repository can build using only that header. The separate CTR_DRBG validation sources require their internal headers, while benchmark sources require the benchmark-only forwarding header. Those dependencies are now private to their respective source areas and are not exported through `include/`.

## Validation evidence

The reorganization was validated without changing Makefile or CI:

| Check | Result |
|---|---:|
| `include/` contains only `bignum_random.h` | PASS |
| Release template test build | PASS |
| Unit tests | PASS — `0 / 5 failed` |
| Benchmark source dry-run resolves benchmark header from adapter path | PASS |
| Makefile changed | No |
| CI changed | No |
