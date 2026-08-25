# Track B Extended DF Verification

**Status:** Engineering verification checkpoint; not a FIPS validation claim.

## Repository Publication

The DF/BCC implementation and documentation were initially pushed to `origin/main` at commit `459d724`; subsequent NULL-output validation hardening and extended verification were published in follow-up commits. The current release preparation continues from the resulting clean main branch.

## Boundary Fuzzing with Snapshots

A temporary test-only harness exercised every input length from 1 through 1024 bytes with four deterministic byte patterns: all zero, all `0xff`, increasing bytes, and a mixed affine/XOR pattern. Each case compared the C11 `block_cipher_df_c` result with the direct YASM `bignum_ctr_drbg_block_cipher_df_asm` result. The harness completed 4096 comparisons successfully.

Snapshot logging was enabled only by assembling with `BIGNUM_DRBG_DF_SNAPSHOT`. It emitted 32,768 stage records plus the final pass record, covering three BCC outputs, post-processed key, initial X, and three AES post-processing blocks for every case. No snapshot hook is present in the ordinary production object.

| Fuzz dimension | Coverage | Result |
|---|---:|---|
| Input lengths | 1–1024 bytes, every length | PASS |
| Patterns | 4 per length | PASS |
| C11/YASM comparisons | 4096 | PASS |
| Snapshot records | 32,768 stage records | PASS |

## Benchmark

The benchmark used warmed-up calls and compared direct C11 DF orchestration against direct YASM DF using the same AES/BCC backend. Results are single-run measurements from the sandbox and are directional rather than certification evidence.

| Input bytes | C11 ns/call | YASM ns/call | Speedup |
|---:|---:|---:|---:|
| 1 | 1810.91 | 459.62 | 3.94x |
| 16 | 1823.25 | 453.12 | 4.02x |
| 32 | 1735.76 | 461.38 | 3.76x |
| 64 | 1818.67 | 552.10 | 3.29x |
| 128 | 2057.68 | 852.91 | 2.41x |
| 256 | 2549.80 | 1355.61 | 1.88x |
| 512 | 3456.57 | 2284.19 | 1.51x |
| 1024 | 5320.54 | 4245.16 | 1.25x |

The declining speedup with larger inputs is expected for this implementation shape: fixed orchestration overhead is amortized while the BCC AES block-processing cost becomes the dominant component.

## Error and Boundary Handling

The dispatcher now rejects a NULL output buffer before selecting either assembly or C fallback. A NULL input is accepted only at length zero. Length 1025 is rejected, and the output buffer remains unchanged on rejection. Length 1024 is accepted.

| Case | Expected status | Result |
|---|---:|---|
| `input=NULL, len=0` | `SUCCESS (0)` | PASS |
| `input=NULL, len=1` | `ERROR_INPUT (-2)` | PASS |
| `len=1024` | `SUCCESS (0)` | PASS |
| `len=1025` | `ERROR_INPUT (-2)` | PASS |
| `output=NULL` | `ERROR_NULL_ARG (-1)` | PASS |
| Rejected `len=1025` output unchanged | unchanged | PASS |

The active dispatcher retains the C11 fallback when AES-NI or required weak symbols are unavailable. Direct assembly leaves remain internal and require validated caller-owned buffers.

## Regression Gates

Both current NIST-style suites passed after activation: PR=false 240/240 and PR=true 240/240. The strict C11/KAT build passed, ASan/UBSan execution passed, cppcheck passed, and `git diff --check` passed before the final error-hardening change. The error-hardening change itself passed strict compilation, both vector suites, and the boundary harness.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[2]: https://csrc.nist.gov/pubs/fips/140-3/final "FIPS 140-3 Security Requirements for Cryptographic Modules"
