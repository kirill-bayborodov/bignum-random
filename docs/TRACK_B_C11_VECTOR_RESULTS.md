# Track B C11 DRBG Vector Results

**Status:** Candidate C11 cryptographic leaf validated against the complete AES-256 CTR_DRBG `use df`, `PredictionResistance = False` record set available in the downloaded NIST CAVP-style RSP archive. This is engineering evidence only; it is not a CAVP certificate, CMVP validation, or FIPS approval.

## Candidate profile

The implementation is the repository's self-contained AES-256 CTR_DRBG candidate with the SP 800-90A Rev. 1 block-cipher derivation function. It uses a 256-bit AES key, a 128-bit block and `V`, a 384-bit seed, a 32-byte entropy input, a 16-byte nonce, explicit personalization/additional input, and the documented instantiate, reseed, generate, and uninstantiate context operations.

| Item | Result |
|---|---|
| Vector source | Official NIST CAVP DRBG informal vector archive, `drbgvectors_pr_false.zip` |
| Selected algorithm suite | `AES-256 use df` |
| Prediction resistance | False |
| Records exercised | 240 |
| Flow per record | Instantiate; optional reseed; two generate calls; compare 512 returned bits |
| Normal build | `-std=c11 -Wall -Wextra -Werror -pedantic` |
| Sanitizer build | AddressSanitizer and UndefinedBehaviorSanitizer with frame pointers |
| Sanitizer result | **PASS: 240/240 records** |
| Negative-path harness | **PASS: strict argument/state/output-preservation/reseed-limit/zeroization checks** |
| Negative-path sanitizer | **PASS** |

## Reproduction

From the repository root, build the shared reference object and execute:

```sh
gcc -std=c11 -Wall -Wextra -Werror -pedantic -fPIC -shared \
  -Iinclude src/bignum_ctr_drbg.c \
  -o /tmp/bignum-random-drbg-build/libbignum_ctr_drbg.so
python3 tests/run_ctr_drbg_vectors.py \
  /tmp/bignum-random-drbg-build/libbignum_ctr_drbg.so \
  tests/vectors/nist/ctr_drbg_pr_false.rsp
```

The sanitizer command is:

```sh
gcc -std=c11 -Wall -Wextra -Werror -pedantic -fPIC -shared \
  -fsanitize=address,undefined -fno-omit-frame-pointer -Iinclude \
  src/bignum_ctr_drbg.c \
  -o /tmp/bignum-random-drbg-build/libbignum_ctr_drbg_san.so
LD_PRELOAD="$(gcc -print-file-name=libasan.so)" \
  ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
  UBSAN_OPTIONS=halt_on_error=1 \
  python3 tests/run_ctr_drbg_vectors.py \
  /tmp/bignum-random-drbg-build/libbignum_ctr_drbg_san.so \
  tests/vectors/nist/ctr_drbg_pr_false.rsp
```

## Interpretation and remaining gate

The result verifies the candidate AES implementation, BCC, Block_Cipher_df, counter increment, state update, and non-prediction-resistant CAVP-style state transitions for this suite. It does not establish the entropy-source claim, health-test behavior, fail-closed lifecycle, image-integrity mechanism, module boundary, assembly equivalence, or CAVP/CMVP status. The protected Makefile currently selects only the family-named production source, so the new context API remains a candidate reference translation unit until the packaging decision is implemented in both C11 and YASM production paths.

The deterministic negative-path harness is `tests/test_ctr_drbg_candidate.c`. It verifies null and malformed inputs, preservation of an existing context after rejected instantiation, blocked use of an uninitialized context, output preservation on rejected generation, oversized additional input, reseed-limit transition, integrity-gated startup, fail-closed module error behavior, transition to `RESEED_REQUIRED`, repeated blocking before reseed, and zeroization of the DRBG SSP while retaining the `ZEROIZED` lifecycle marker. Both strict and ASan/UBSan builds pass.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[2]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators "NIST CAVP random-number-generator testing page"

[3]: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip "NIST DRBG informal vector archive"
