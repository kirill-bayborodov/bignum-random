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

From the repository root, build the shared reference object and execute:

```sh
mkdir -p /tmp/bignum-random-drbg-build
gcc -std=c11 -Wall -Wextra -Werror -pedantic -fPIC -shared \
  -Iinclude src/bignum_ctr_drbg.c \
  -o /tmp/bignum-random-drbg-build/libbignum_ctr_drbg.so
gcc -std=c11 -Wall -Wextra -Werror -pedantic \
  -Iinclude tests/run_ctr_drbg_vectors.c -ldl \
  -o /tmp/bignum-random-drbg-build/run_ctr_drbg_vectors
/tmp/bignum-random-drbg-build/run_ctr_drbg_vectors \
  /tmp/bignum-random-drbg-build/libbignum_ctr_drbg.so \
  tests/vectors/nist/ctr_drbg_pr_false.rsp
/tmp/bignum-random-drbg-build/run_ctr_drbg_vectors \
  /tmp/bignum-random-drbg-build/libbignum_ctr_drbg.so \
  tests/vectors/nist/ctr_drbg_pr_true.rsp
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
  /tmp/bignum-random-drbg-build/run_ctr_drbg_vectors \
  /tmp/bignum-random-drbg-build/libbignum_ctr_drbg_san.so \
  tests/vectors/nist/ctr_drbg_pr_false.rsp
```

## Interpretation and remaining gate

The result verifies the candidate AES implementation, BCC, Block_Cipher_df, counter increment, state update, non-prediction-resistant state transitions, and the prediction-resistance flow in which NIST 9.3.1 passes AdditionalInput into Reseed_function and clears it before Generate_algorithm. It does not establish the entropy-source claim, health-test behavior, fail-closed lifecycle, image-integrity mechanism, module boundary, assembly equivalence, or CAVP/CMVP status. The vector runner is implemented in strict C11 and uses only the POSIX dynamic-linking interface required to load the test library; no Python source is required by this reproduction path.

The deterministic negative-path harness is `tools/test_ctr_drbg_candidate.c`. It verifies null and malformed inputs, preservation of an existing context after rejected instantiation, blocked use of an uninitialized context, output preservation on rejected generation, oversized additional input, reseed-limit transition, integrity-gated startup, fail-closed module error behavior, transition to `RESEED_REQUIRED`, repeated blocking before reseed, and zeroization of the DRBG SSP while retaining the `ZEROIZED` lifecycle marker. Both strict and ASan/UBSan builds pass. The harness is kept under `tools/` because the protected Makefile automatically treats every `tests/*.c` file as a production test target.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[2]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators "NIST CAVP random-number-generator testing page"

[3]: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip "NIST DRBG informal vector archive"
