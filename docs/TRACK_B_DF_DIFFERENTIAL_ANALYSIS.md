# Track B DF Differential Analysis

**Status:** DF YASM activation completed after correcting the isolated leaf and passing direct snapshots and production vectors.

## Observed Difference

The isolated YASM `bignum_ctr_drbg_block_cipher_df_asm` was compared against the C11 `block_cipher_df_c` implementation in one executable using identical input bytes and the same YASM AES/BCC leaves. The first mismatch occurs at `input_len = 0`; therefore the discrepancy is not caused by maximum-input handling or a later boundary condition.

| Input length | C11 reference | YASM candidate | Result |
|---:|---|---|---|
| 0 | `9ae8601cc417bb00779a8d46a2017ca4c707a30a2912c4284bd6260dd42d005eb650d4e900c7e7e7f8443f9a9c3e0194` | `9d42170f5843cee562e7aaa2845ce8757014404c60888bed09c052ce2277c3eadca6d2a10ea8f31e2dfe2b35ca5d05db` | FAIL |

The direct BCC comparison passed on the same style of stream, so the isolated difference was in DF post-processing rather than the BCC chaining primitive. Snapshots showed that all three BCC outputs, the post-processed key, and initial X matched. The first mismatch was at AES post-processing block 0. YASM was passing the raw 32-byte key as though it were a 240-byte expanded AES schedule. The fix adds an explicit AES-256 key expansion into a private 240-byte workspace before the three post-processing encryptions. After the fix, all BCC, key/X, and AES post-processing snapshots matched.

## Activation Decision

After the key-schedule fix, runtime activation produced passing CTR_DRBG output against both vector suites. The dispatcher now selects YASM DF when AES-NI and all required symbols are available, and retains the C11 fallback otherwise. This preserves fail-closed dispatch behavior while enabling the verified optimized path.

## Required Next Diagnostic

The snapshot harness was compiled only with the `BIGNUM_DRBG_DF_SNAPSHOT` test define and was kept outside the production tree. No deterministic provider, snapshot hook, or fault seam enters the production archive. Future changes must retain the same separation and rerun the intermediate-state equivalence gate.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[2]: https://csrc.nist.gov/pubs/fips/140-3/final "FIPS 140-3 Security Requirements for Cryptographic Modules"
