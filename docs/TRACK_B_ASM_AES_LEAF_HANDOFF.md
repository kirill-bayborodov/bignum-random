# Track B YASM AES-256 Leaf Handoff

**Status:** Standalone candidate leaf; not yet connected to the production Approved service. No FIPS validation claim is made.

## Boundary

`src/bignum_ctr_drbg_aes256.asm` implements one AES-256 ECB encryption operation using an already expanded 240-byte AES-256 key schedule. The System V AMD64 ABI is:

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
| Microbenchmark | 100,000 blocks; C11 3,043,505,370 ns; YASM 473,056 ns; observed ratio 6433.711x |

The microbenchmark is a leaf-level engineering comparison. It is not a DRBG service benchmark and it should not be used as certification evidence. The unusually large ratio is expected from this deliberately readable C11 reference, whose S-box is computed by finite-field exponentiation for clarity, versus hardware AES-NI instructions. A later comparison must measure the complete DRBG path, including key expansion strategy, counter handling, DF/BCC, state update, and dispatch overhead.

## Controls required before integration

The leaf must not be called merely because the host is x86-64. The final module requires a validated runtime feature-selection policy, a defined behavior on processors without AES-NI, an identical C/YASM test vector suite, ABI and object-link evidence for both protected build modes, and an assembly-side review of sensitive-state lifetime and zeroization. The expanded-key argument is currently public only to make the leaf boundary testable; the final Approved API should keep the AES schedule internal to the DRBG context and should not expose SSP-bearing buffers to consumers.

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
