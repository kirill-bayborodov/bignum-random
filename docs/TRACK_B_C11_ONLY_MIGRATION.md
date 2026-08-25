# Track B C11-Only Source Migration

**Status:** Completed for repository-owned source files.

## Scope

The repository contains no Python source files. The CAVP-style RSP parser and executor are integrated into `tests/test_bignum_random.c` behind the `BIGNUM_RANDOM_CTR_DRBG_VECTOR_TEST` test-only macro. The normal template build remains unchanged; vector mode is manually linked with the DRBG C/YASM objects and compares `ReturnedBits`.

| Artifact | Language | Role | Status |
|---|---|---|---|
| `tests/test_bignum_random.c` | C11 | Template tests plus conditional vector parser/executor | Active |
| `src/*.c` | C11 | Production/reference implementation | Active |
| `src/*.asm` | YASM | x86-64 cryptographic leaves | Active |
| `tests/*.c`, `tools/*.c` | C11 | Deterministic, fault, lifecycle and security tests | Active |
| Former standalone C11 vector runner | C11 | Superseded by integrated test source | Removed |

The build scripts and CI configuration were not modified. The former standalone runner was removed, and the vector logic is now maintained in the template test source. Strict compilation and both 240-case vector suites are executed through the manual vector-mode linkage described below.

## Verification

```text
gcc -std=c11 -Wall -Wextra -Werror -pedantic -O2 -DBIGNUM_RANDOM_CTR_DRBG_VECTOR_TEST \
  -Iinclude -Isrc -Ilibs/bignum-core/include -c tests/test_bignum_random.c -o test_bignum_random.o
yasm -f elf64 src/bignum_ctr_drbg_aes256.asm -o bignum_ctr_drbg_aes256.o
yasm -f elf64 src/bignum_random.asm -o bignum_random.o
gcc test_bignum_random.o src/bignum_ctr_drbg.c bignum_ctr_drbg_aes256.o \
  bignum_random.o libs/bignum-core/build/bignum_core.o -o test_bignum_random
./test_bignum_random /unused/path ctr_drbg_pr_false.rsp
./test_bignum_random /unused/path ctr_drbg_pr_true.rsp
```

Observed result target: PR=false — 240/240; PR=true — 240/240. Repository inventory must report zero `*.py` files and no references to the removed standalone runner.

Python may still be used externally by a developer or CI environment for unrelated orchestration, but no Python source is part of the repository-owned implementation or test runner set. The validated source and test evidence package must use the C11 runner and record any external framework as a separately scoped tool dependency.

## References

[1]: https://csrc.nist.gov/pubs/fips/140-3/final "NIST FIPS 140-3"

[2]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"
