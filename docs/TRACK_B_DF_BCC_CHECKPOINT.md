# Track B DF/BCC Implementation Checkpoint

**Status:** Engineering checkpoint; not a FIPS validation claim.

## Scope

This checkpoint implements independent x86-64 YASM leaves for BCC and Block_Cipher_df, adds internal ABI declarations, and introduces controlled dispatch boundaries. The BCC and DF leaves are active on the AES-NI path when their required symbols are linked. Both retain a C11 fallback when the CPU or symbols are unavailable.

## Validation Results

| Gate | Result | Evidence |
|---|---|---|
| YASM assembly | PASS | `yasm -f elf64 src/bignum_ctr_drbg_aes256.asm` |
| Strict C11 build | PASS | `gcc -std=c11 -Wall -Wextra -Werror -pedantic` |
| NIST-style CTR_DRBG PR=false | PASS | 240/240 records through the safe dispatcher |
| NIST-style CTR_DRBG PR=true | PASS | 240/240 records through the safe dispatcher |
| AES-256 C/YASM leaf KAT | PASS | Existing assembly KAT tool |
| cppcheck | PASS | Warning/style/performance/portability checks |
| `git diff --check` | PASS | No whitespace errors |
| YASM BCC direct equivalence | PASS | Direct C BCC and YASM BCC outputs matched |
| YASM DF direct equivalence | PASS | Zero-length snapshots match for all three BCC outputs, post-processed key, initial X, and all three AES post-processing blocks |

## Security and Integration Decision

The production DF dispatcher selects YASM when AES-NI and all required symbols are available, and otherwise uses the C11 fallback. The activation was gated by intermediate-state snapshots and full vector results. BCC and DF remain internal, stateless leaves with no test provider or fault hook in the production boundary.

The YASM DF leaf owns a fixed private workspace, explicitly expands the post-processing key, and clears its workspace before return. The test-only snapshot harness identified the missing AES-256 key expansion; after correction, production activation passed the current vector and sanitizer gates.

## Changed Files

The implementation changes are in `include/bignum_ctr_drbg_internal.h`, `src/bignum_ctr_drbg.c`, and `src/bignum_ctr_drbg_aes256.asm`. The internal ABI and current evidence are documented in `docs/TRACK_B_DF_BCC_ABI.md`.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[2]: https://csrc.nist.gov/pubs/fips/140-3/final "FIPS 140-3 Security Requirements for Cryptographic Modules"
