# Test-Only Inline DF Variant Validation

**Status:** Isolated optimization evidence; the production DF dispatcher still selects the validated expanded-key BCC leaf.

## Variant Boundary

The temporary DF variant reproduces the C11 `Block_Cipher_df` sequence but calls `bignum_ctr_drbg_bcc_expanded_inline_asm` for each of the three BCC invocations. It performs one initial AES-256 key expansion for those BCC calls and a second expansion after the BCC-derived key is formed for the final three AES blocks. The variant is compiled and linked only in a temporary test harness; `src/bignum_ctr_drbg.c` contains no reference to the inline candidate.

## Full Boundary Validation

The pure C11 reference uses the C BCC and AES helpers from `src/bignum_ctr_drbg.c`. The inline variant uses the YASM expanded-key schedule, inline BCC loop, and YASM AES post-processing. Every input length from 1 through 1024 bytes was tested with four deterministic patterns: zero, `0xff`, increasing bytes, and a mixed affine/XOR pattern.

| Validation dimension | Coverage | Result |
|---|---:|---|
| Input lengths | 1–1024 bytes | PASS |
| Patterns per length | 4 | PASS |
| C11 pure reference vs inline DF | 4096 cases | PASS |
| Direct expanded BCC vs inline BCC | 16–1056 bytes in 16-byte steps | PASS |
| NIST-style production regression, PR=false | 240 cases | PASS |
| NIST-style production regression, PR=true | 240 cases | PASS |

## Paired Median/MAD Benchmark

The benchmark interleaved C11 and inline calls on the same deterministic input for nine paired runs per size. Each run included warm-up and a checksum sink. Values are per complete DF call; medians and median absolute deviations are calculated across the nine runs.

| DF input | C11 median ns/call | C11 MAD | Inline median ns/call | Inline MAD | Speedup |
|---:|---:|---:|---:|---:|---:|
| 1 B | 2617.84 | 44.81 | 1218.14 | 21.36 | 2.15x |
| 16 B | 3273.12 | 64.15 | 1296.81 | 11.45 | 2.52x |
| 32 B | 3825.94 | 47.90 | 1379.37 | 28.82 | 2.77x |
| 64 B | 4882.60 | 28.23 | 1466.06 | 17.88 | 3.33x |
| 128 B | 7110.81 | 56.67 | 1716.50 | 39.01 | 4.14x |
| 256 B | 11784.32 | 121.37 | 2184.34 | 99.62 | 5.39x |
| 512 B | 20567.28 | 65.77 | 3002.54 | 40.93 | 6.85x |
| 1024 B | 38322.91 | 647.03 | 4723.98 | 74.48 | 8.11x |

These numbers compare a pure C11 reference against the isolated inline variant and are not directly interchangeable with earlier production-path timings that used a different C/ASM composition. They demonstrate the candidate’s full-pipeline potential, but final claims require the same machine, affinity, compiler, repetitions, and profile policy used for release benchmarking.

## Fault and Error Boundaries

The test-only variant rejects a NULL input when `input_len` is nonzero, accepts a NULL input only at length zero, rejects `input_len` above 1024, rejects a NULL output, and leaves the output canary unchanged on the rejected oversized-input case. Invalid parameters are rejected before any assembly candidate call. The candidate itself remains an internal leaf with no validation branch and is never directly reachable through the public API.

| Case | Expected result | Result |
|---|---|---|
| `input=NULL, len=0` | `SUCCESS` | PASS |
| `input=NULL, len=1` | `ERROR_INPUT` | PASS |
| `len=1024` | `SUCCESS` | PASS |
| `len=1025` | `ERROR_INPUT`, output unchanged | PASS |
| `output=NULL` | `ERROR_INPUT` in test-only variant | PASS |
| Production dispatcher references inline candidate | Must be absent | PASS |
| Production object unresolved test hooks | Must be absent | PASS |

The existing production dispatcher and public error contract are unchanged. Fault-injection seams remain in the context/service test layer and are not linked into this test-only DF variant.

## Activation Decision

The inline candidate is equivalence- and security-tested as an isolated full DF implementation, but it is not activated in production by this checkpoint. Before activation, the candidate needs a review of full-module fault transitions, production distribution contents, a repeated benchmark on the target platform, and an explicit release decision. Keeping the current dispatcher unchanged preserves the previously validated production path while retaining a reproducible optimization candidate.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[2]: https://csrc.nist.gov/pubs/fips/197/final "FIPS 197 Advanced Encryption Standard"
