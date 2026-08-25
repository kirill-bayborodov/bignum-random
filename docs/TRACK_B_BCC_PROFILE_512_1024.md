# BCC AES Block-Processing Profile: DF Inputs 512–1024 Bytes

**Status:** Engineering performance analysis; measurements are directional and not certification evidence.

## Scope and Method

The DF path forms `S = L || N || input || 0x80 || zero padding`, then invokes BCC three times over `IV || S`. For DF input lengths from 512 through 1024 bytes, the BCC message lengths are 544 through 1056 bytes. The direct BCC YASM leaf was measured with a fixed AES-256 key, warmed-up calls, 10,000 iterations per size, and a checksum sink preventing dead-code elimination. Hardware `perf` counters were unavailable for the sandbox kernel, so the profile uses monotonic timing and static instruction-path analysis.

| DF input | Padded S | BCC message | AES blocks per BCC | AES blocks per DF | Median ns/call; MAD |
|---:|---:|---:|---:|---:|---:|
| 512 B | 528 B | 544 B | 34 | 102 | 682.72 ns/BCC call; MAD 0.77 ns |
| 640 B | 656 B | 672 B | 42 | 126 | 845.45 ns/BCC call; MAD 9.40 ns |
| 768 B | 784 B | 800 B | 50 | 150 | 999.93 ns/BCC call; MAD 7.36 ns |
| 896 B | 912 B | 928 B | 58 | 174 | 1160.42 ns/BCC call; MAD 7.80 ns |
| 1024 B | 1040 B | 1056 B | 66 | 198 | 1311.47 ns/BCC call; MAD 1.82 ns |

The complete DF invokes three BCC calls, so the BCC-only contribution is approximately three times the listed per-call timing. The 512-to-1024 input increase adds 32 AES blocks per BCC call, or 96 AES blocks per complete DF operation.

## Observed Profile

The current YASM BCC leaf expands the AES-256 key once per BCC call, initializes a chaining block, then loops over each 16-byte block. Each loop performs a separate call to the AES expanded-key encryption leaf. The large-buffer slope is therefore dominated by AES-NI block processing and repeated call/loop overhead, while fixed costs include stack frame setup, key expansion, and output publication.

Across seven repeated runs, the median per-call time grows from 682.72 ns at 544 BCC bytes to 1311.47 ns at 1056 BCC bytes. The increase is broadly consistent with the added 32 AES blocks. Median absolute deviation ranges from 0.77 ns to 9.40 ns. `perf stat` could not provide hardware counters on the available kernel, so exact cycles per block and branch-miss attribution require a host with PMU access or a supported Callgrind run.

## Optimization Opportunities

| Priority | Candidate | Expected benefit | Correctness/security risk | Required evidence |
|---:|---|---|---|---|
| 1 | Add an expanded-key BCC leaf or pass one expanded schedule from DF into all three BCC calls | Removes two of three AES-256 key expansions per DF and reduces fixed overhead | Medium: new ABI and sensitive schedule lifetime | C/YASM BCC equivalence, DF vectors, zeroization probe, ABI review |
| 2 | Inline the AES-NI block loop into the BCC leaf instead of calling the AES leaf for every block | Removes per-block call/return and argument setup overhead | Medium: larger assembly surface and clobber review | Full vector/fuzz suite, disassembly review, sanitizer harness around wrapper |
| 3 | Keep chaining value in an XMM register across blocks and load/XOR the next input directly | Reduces stack traffic and temporary block stores | Medium: alias/alignment and register-lifetime complexity | Misaligned/overlap contract tests, BCC differential snapshots |
| 4 | Use a DF-specific fused loop that processes the three BCC messages with one expanded schedule | Improves amortization and may reduce repeated setup | High: more complex state isolation and zeroization | Independent BCC equivalence, full DF KATs, fault and zeroization audit |
| 5 | Measure with PMU/Callgrind and paired repetitions before selecting a patch | Converts timing hypothesis into attributable evidence | Low | Median/MAD, cycles/instruction counts, fixed CPU affinity |

## Recommended Sequence

First introduce a private expanded-key BCC ABI that is not exposed through the public header. The current public-compatible BCC wrapper can retain key expansion for independent callers, while DF uses one schedule for its three BCC invocations. Next, benchmark that change in isolation. Only then consider inlining the AES block loop; this separates key-expansion savings from call-loop savings and makes regression attribution possible.

The optimization must preserve the existing fail-closed dispatcher, AES-NI feature gate, caller-owned output contract, and complete zeroization of raw key material, expanded schedule, chaining value, and temporary blocks. Every candidate must pass the 1–1024-byte, four-pattern differential fuzz suite before production activation.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[2]: https://csrc.nist.gov/pubs/fips/197/final "FIPS 197 Advanced Encryption Standard"

## Expanded-Key Optimization Checkpoint

The first optimization introduces `bignum_ctr_drbg_bcc_expanded_asm`, a private ABI leaf that borrows one 240-byte AES-256 schedule. DF now expands the initial key once for all three BCC calls, while retaining the required second expansion after the BCC-derived key is formed for final AES post-processing. The direct expanded-key BCC output was byte-equivalent to the ordinary BCC leaf.

The same C11/YASM DF benchmark harness was rerun after integration:

| DF input | C11 ns/call | Optimized YASM ns/call | Speedup |
|---:|---:|---:|---:|
| 1 B | 1808.18 | 370.07 | 4.89x |
| 16 B | 1798.87 | 437.55 | 4.11x |
| 32 B | 1796.85 | 502.28 | 3.58x |
| 64 B | 1979.68 | 622.90 | 3.18x |
| 128 B | 2213.48 | 898.98 | 2.46x |
| 256 B | 2776.85 | 1417.61 | 1.96x |
| 512 B | 3627.96 | 2378.87 | 1.53x |
| 1024 B | 5512.46 | 4282.68 | 1.29x |

These values are one post-change run and should be interpreted with the earlier repeated median/MAD profile rather than as a release-quality statistical claim. The optimization targets fixed setup cost; therefore, its relative benefit is expected to be strongest for short inputs and smaller when the BCC AES block loop dominates.

The optimization remains gated on a fresh full benchmark comparison and must not be combined with AES-loop inlining in the same attribution step.

## Inline AES-NI Loop Candidate

A second isolated candidate, `bignum_ctr_drbg_bcc_expanded_inline_asm`, embeds the AES-256 rounds in the BCC loop and is not selected by the production dispatcher. It was compared with the current expanded-key BCC leaf over every 16-byte message length from 16 through 1056 bytes; all outputs were equivalent. The candidate also passed the direct ASan/UBSan equivalence harness and the stage-4 80-byte zeroization probe.

| BCC message | Expanded-key leaf ns/call | Inline candidate ns/call | Candidate speedup |
|---:|---:|---:|---:|
| 544 B | 688.35 | 620.57 | 1.11x |
| 672 B | 836.78 | 754.30 | 1.11x |
| 800 B | 998.17 | 899.81 | 1.11x |
| 928 B | 1143.81 | 1037.94 | 1.10x |
| 1056 B | 1307.38 | 1184.75 | 1.10x |

These are single-run direct BCC timings and are hypothesis evidence, not a production performance claim. The candidate remains isolated until the complete DF path is wired through a test-only dispatcher variant and passes the 1–1024-byte differential suite, NIST vectors, fault/lifecycle tests, zeroization audit, and production symbol-isolation review.
