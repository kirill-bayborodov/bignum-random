# Track B C11-Only Source Migration

**Status:** Completed for repository-owned source files.

## Scope

The repository contains no Python source files after replacing `tests/run_ctr_drbg_vectors.py` with `tests/run_ctr_drbg_vectors.c`. The replacement is a strict C11 test-only executable that parses the required CAVP-style RSP subset, loads the test library through POSIX `dlopen`/`dlsym`, injects instantiate/reseed/generate inputs, and compares `ReturnedBits`.

| Artifact | Language | Role | Status |
|---|---|---|---|
| `tests/run_ctr_drbg_vectors.c` | C11 | Vector parser and execution runner | Active |
| `src/*.c` | C11 | Production/reference implementation | Active |
| `src/*.asm` | YASM | x86-64 cryptographic leaves | Active |
| `tests/*.c`, `tools/*.c` | C11 | Deterministic, fault, lifecycle and security tests | Active |
| `tests/run_ctr_drbg_vectors.py` | Python | Former vector runner | Removed |

The build scripts and CI configuration were not modified. Existing documentation references to the Python runner were replaced with the C11 runner, and strict compilation plus both 240-case vector suites pass with the replacement.

## Verification

```text
gcc -std=c11 -Wall -Wextra -Werror -pedantic -O2 -Iinclude \
  tests/run_ctr_drbg_vectors.c -ldl -o run_ctr_drbg_vectors
run_ctr_drbg_vectors LIBRARY ctr_drbg_pr_false.rsp
run_ctr_drbg_vectors LIBRARY ctr_drbg_pr_true.rsp
```

Observed result: PR=false — 240/240; PR=true — 240/240. Repository inventory reports zero `*.py` files and zero stale vector-runner references.

Python may still be used externally by a developer or CI environment for unrelated orchestration, but no Python source is part of the repository-owned implementation or test runner set. The validated source and test evidence package must use the C11 runner and record any external framework as a separately scoped tool dependency.

## References

[1]: https://csrc.nist.gov/pubs/fips/140-3/final "NIST FIPS 140-3"

[2]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"
