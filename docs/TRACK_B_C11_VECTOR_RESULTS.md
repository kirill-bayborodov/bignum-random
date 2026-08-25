# Track B C11 DRBG Vector Results

**Status:** Candidate C11 cryptographic leaf validated against the complete AES-256 CTR_DRBG `use df` record sets for both `PredictionResistance = False` and `PredictionResistance = True` available in the downloaded NIST CAVP-style RSP archives. This is engineering evidence only; it is not a CAVP certificate, CMVP validation, or FIPS approval.

## Candidate profile

The implementation is the repository's self-contained AES-256 CTR_DRBG candidate with the SP 800-90A Rev. 1 block-cipher derivation function. It uses a 256-bit AES key, a 128-bit block and `V`, a 384-bit seed, a 32-byte entropy input, a 16-byte nonce, explicit personalization/additional input, and the documented instantiate, reseed, generate, and uninstantiate context operations.

| Item | Result |
|---|---|
| Vector source | Official NIST CAVP DRBG informal vector archives, `drbgvectors_pr_false.zip` and `drbgvectors_pr_true.zip` |
| Selected algorithm suite | `AES-256 use df` |
| Prediction resistance | False and True |
| Records exercised | 240 per mode; 480 total |
| Flow per record | Instantiate; optional reseed; two generate calls; compare 512 returned bits |
| Normal build | `-std=c11 -Wall -Wextra -Werror -pedantic` |
| Sanitizer build | AddressSanitizer and UndefinedBehaviorSanitizer with frame pointers |
| Sanitizer result | **PASS: 240/240 records per mode** |
| Negative-path harness | **PASS: strict argument/state/output-preservation/reseed-limit/zeroization checks** |
| Negative-path sanitizer | **PASS** |

## Reproduction

From the repository root, build the integrated test source in vector mode with the explicit DRBG C/YASM objects and execute:

```sh
mkdir -p /tmp/bignum-random-drbg-build
gcc -std=c11 -Wall -Wextra -Werror -pedantic -O2 -DBIGNUM_RANDOM_CTR_DRBG_VECTOR_TEST \
  -Iinclude -Isrc -Ilibs/bignum-core/include -c tests/test_bignum_random.c \
  -o /tmp/bignum-random-drbg-build/test_bignum_random.o
gcc -std=c11 -Wall -Wextra -Werror -pedantic -O2 -Iinclude -Isrc \
  -Ilibs/bignum-core/include -c src/bignum_ctr_drbg.c \
  -o /tmp/bignum-random-drbg-build/bignum_ctr_drbg.o
yasm -f elf64 src/bignum_ctr_drbg_aes256.asm \
  -o /tmp/bignum-random-drbg-build/bignum_ctr_drbg_aes256.o
yasm -f elf64 src/bignum_random.asm \
  -o /tmp/bignum-random-drbg-build/bignum_random.o
gcc /tmp/bignum-random-drbg-build/test_bignum_random.o \
  /tmp/bignum-random-drbg-build/bignum_ctr_drbg.o \
  /tmp/bignum-random-drbg-build/bignum_ctr_drbg_aes256.o \
  /tmp/bignum-random-drbg-build/bignum_random.o \
  libs/bignum-core/build/bignum_core.o \
  -o /tmp/bignum-random-drbg-build/test_bignum_random
/tmp/bignum-random-drbg-build/test_bignum_random /unused/path \
  tests/vectors/nist/ctr_drbg_pr_false.rsp
/tmp/bignum-random-drbg-build/test_bignum_random /unused/path \
  tests/vectors/nist/ctr_drbg_pr_true.rsp
```

The sanitizer command is:

```sh
gcc -std=c11 -Wall -Wextra -Werror -pedantic -fPIC -shared \
  -fsanitize=address,undefined -fno-omit-frame-pointer -Iinclude -Isrc \
  -Ilibs/bignum-core/include -DBIGNUM_RANDOM_CTR_DRBG_VECTOR_TEST \
  tests/test_bignum_random.c src/bignum_ctr_drbg.c \
  /tmp/bignum-random-drbg-build/bignum_ctr_drbg_aes256.o \
  /tmp/bignum-random-drbg-build/bignum_random.o \
  libs/bignum-core/build/bignum_core.o \
  -o /tmp/bignum-random-drbg-build/test_bignum_random_san
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
  UBSAN_OPTIONS=halt_on_error=1 \
  /tmp/bignum-random-drbg-build/test_bignum_random_san /unused/path \
  tests/vectors/nist/ctr_drbg_pr_false.rsp
```

## Interpretation and remaining gate

The result verifies the candidate AES implementation, BCC, Block_Cipher_df, counter increment, state update, non-prediction-resistant state transitions, and the prediction-resistance flow in which NIST 9.3.1 passes AdditionalInput into Reseed_function and clears it before Generate_algorithm. It does not establish the entropy-source claim, health-test behavior, fail-closed lifecycle, image-integrity mechanism, module boundary, assembly equivalence, or CAVP/CMVP status. The vector parser and executor are implemented in strict C11; no Python source or standalone runner is required by this reproduction path.

The deterministic negative-path harness is `tools/test_ctr_drbg_candidate.c`. It verifies null and malformed inputs, preservation of an existing context after rejected instantiation, blocked use of an uninitialized context, output preservation on rejected generation, oversized additional input, reseed-limit transition, integrity-gated startup, fail-closed module error behavior, transition to `RESEED_REQUIRED`, repeated blocking before reseed, and zeroization of the DRBG SSP while retaining the `ZEROIZED` lifecycle marker. Both strict and ASan/UBSan builds pass. The harness is kept under `tools/` because the protected Makefile automatically treats every `tests/*.c` file as a production test target.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[2]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators "NIST CAVP random-number-generator testing page"

[3]: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip "NIST DRBG informal vector archive"
