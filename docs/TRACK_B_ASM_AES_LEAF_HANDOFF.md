# Track B YASM AES-256 Leaf Handoff

**Status:** Standalone candidate leaf; not yet connected to the production Approved service. No FIPS validation claim is made.

## Boundary

`src/bignum_ctr_drbg_aes256.asm` implements independent AES-256 key expansion and one AES-256 ECB encryption operation. The encryption ABI uses an already expanded 240-byte AES-256 key schedule. The System V AMD64 ABI is:

```text
void bignum_ctr_drbg_aes256_encrypt_expanded_asm(
    const uint8_t expanded_key[240],
    const uint8_t input[16],
    uint8_t output[16]);
```

The arguments are received in `RDI`, `RSI`, and `RDX`. The leaf uses `AESENC` for rounds 1 through 13 and `AESENCLAST` for round 14. It requires the processor's AES-NI feature. The C11 exported expanded-key leaf has the same data contract and is used as the reference oracle.

The current assembly symbol deliberately has an `_asm` suffix. This prevents accidental replacement of the C11 reference while the ABI, runtime feature selection, CAVP equivalence, and protected-build packaging are reviewed.

## Evidence

| Check | Result |
|---|---|
| YASM format | `elf64` assembled successfully |
| FIPS 197 AES-256 known-answer block | **PASS** in both C11 and YASM leaves |
| C/YASM output equality | **PASS** |
| GNU stack metadata | `.note.GNU-stack` present and non-executable |
| CPU prerequisite on test host | AES-NI flag present |
| Runtime dispatcher, C-only link | Backend 0 / C11 fallback; FIPS 197 KAT **PASS** |
| Runtime dispatcher, YASM link | Backend 1 / AES-NI; FIPS 197 KAT **PASS** |
| Full DRBG vector suite, C-only link | **PASS: 240/240 records** |
| Full DRBG vector suite, YASM link | **PASS: 240/240 records** |
| Microbenchmark | End-to-end 100,000 blocks including key expansion; latest run C11 3,821,105,256 ns; YASM 7,841,957 ns; observed ratio 487.264x |

The microbenchmark is a leaf-level engineering comparison. It is not a DRBG service benchmark and it should not be used as certification evidence. The unusually large ratio is expected from this deliberately readable C11 reference, whose S-box is computed by finite-field exponentiation for clarity, versus hardware AES-NI instructions. The end-to-end comparison now includes key expansion plus block encryption. A later comparison must still measure the complete DRBG path, including counter handling, DF/BCC, state update, and dispatch overhead.

## Controls required before integration

The leaf must not be called merely because the host is x86-64. The candidate now has a C-only fallback and a weak-symbol/runtime AES-NI dispatcher. The final module still requires a validated runtime feature-selection policy, a defined behavior on processors without AES-NI, an identical C/YASM test vector suite, ABI and object-link evidence for both protected build modes, and an assembly-side review of sensitive-state lifetime and zeroization. The expanded-key argument is now defined in an internal-only header for implementation and review tools; the final Approved API must keep the AES schedule internal to the DRBG context and must not expose SSP-bearing buffers to consumers.

The protected Makefile and CI workflow remain unchanged. Standalone C harnesses are kept under `tools/` rather than `tests/`, because the protected Makefile automatically treats every `tests/*.c` file as a production test target. Consequently, this leaf is currently a handoff artifact and is not part of the family-named production object selected by the existing build rules.

## Reproduction

```sh
yasm -f elf64 src/bignum_ctr_drbg_aes256.asm -o /tmp/bignum-random-drbg-build/bignum_ctr_drbg_aes256.o
gcc -std=c11 -Wall -Wextra -Werror -pedantic -O2 -Iinclude \
  tools/test_ctr_drbg_aes_asm.c src/bignum_ctr_drbg.c \
  /tmp/bignum-random-drbg-build/bignum_ctr_drbg_aes256.o \
  -o /tmp/bignum-random-drbg-build/test_ctr_drbg_aes_asm
/tmp/bignum-random-drbg-build/test_ctr_drbg_aes_asm
```

## References

[1]: https://csrc.nist.gov/pubs/fips/197/final "NIST FIPS 197 Advanced Encryption Standard"

[2]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

## Independent YASM schedule integration evidence

The YASM leaf now implements both AES-256 key expansion using `AESKEYGENASSIST` and one-block encryption independently of the C AES implementation. The final expansion writes only the remaining 16 schedule bytes; an earlier stack-protector KAT exposed and corrected a 16-byte overrun in the last expansion macro before acceptance.

The full 240-record PR=false and full 240-record PR=true CAVP-style suites passed through a shared library linked with the independent YASM schedule and encryption leaves. The FIPS 197 schedule/ciphertext KAT passed under stack protection and ASan/UBSan. The seven-run end-to-end benchmark, including key expansion plus encryption per block, measured a median YASM speedup of **481.177x** over the scalar C11 reference on 100,000 blocks; observed runs ranged from 385.272x to 542.397x.

The result is an engineering performance/equivalence result only. AES-NI runtime dispatch remains mandatory, and the final Approved image still requires an allowlisted link, CPU feature policy, reproducible build and independent review of the assembly source.
