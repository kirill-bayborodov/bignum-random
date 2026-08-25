# Assembly Test Coverage Report: `bignum_random`

**Reviewed implementation:** `src/bignum_random.asm`, final hybrid Linux x86-64 YASM path.
**Evidence date:** 25 August 2026.
**Coverage model:** executable dynamic evidence, not C source coverage.

## Scope and interpretation

YASM does not emit GCC `.gcno` and `.gcda` files, so `gcov` cannot truthfully report source-line or branch percentages for `src/bignum_random.asm`. This report therefore does **not** invent a gcov percentage for assembly. It combines the complete ASM-selected test suite, scenario-to-branch mapping, final Callgrind instruction evidence, sanitizer evidence, Helgrind evidence, ELF TLS inspection, and direct review of the two kernel-controlled error paths.

The current production code consists of validation, normalized-bound bit-width calculation, three candidate-dispatch families, masked rejection sampling, normalization, transactional publication, and named status returns. The short and medium candidate paths use a per-thread entropy cache. The full-capacity path calls `getrandom(2)` directly because a 32-word candidate consumes the entire cache refill. A process-ID comparison invalidates inherited cache bytes after `fork()`.

## Executed test suite

The following command selected the final assembly object and completed successfully:

```bash
make clean
make test CONFIG=debug USE_ASM=yes
```

It executed five independent binaries and ended with `=== Summary: 0 / 5 failed ===`.

| Binary | Dynamic scenarios | Result |
|---|---|---|
| `bin/test_bignum_random` | Deterministic status/transaction tests; singleton, representative one- and two-word ranges; fork-child sampling. | Pass |
| `bin/test_bignum_random_extra` | 20,000 property/fuzz-style bounds with independent range oracle; one-, two-, and full-capacity boundaries. | Pass |
| `bin/test_bignum_random_mt` | Eight independent pthread workers, 1,000 samples each; range and bound-preservation oracle. | Pass |
| `bin/test_bignum_random_runner` | Production static-distribution integration and singleton range. | Pass |
| `bin/test_bignum_random_benchmark_adapter` | Benchmark vocabulary, callback binding, fixture validation, production call, and checksum. | Pass |

The deterministic suite explicitly reports `test_fork_child_sampling: PASSED`. In that test the parent first fills its cache through a valid call below three, forks, and the child performs an independent valid sample. The child PID differs, so the YASM PID guard invalidates inherited cache state before cache-eligible entropy is used. The test validates the observable public behavior; it does not claim to predict cryptographic bytes.

## Assembly path map

| Assembly region / invariant | Dynamic test evidence | Coverage status |
|---|---|---|
| Null output or bound (`BIGNUM_RANDOM_ERROR_NULL_ARG`) | `test_invalid_arguments_preserve_output` passes null output and null bound; canary output is byte-compared. | Executed |
| Aliasing (`BIGNUM_RANDOM_ERROR_ALIAS`) | Same test passes `out == upper_bound`. | Executed |
| Empty interval (`BIGNUM_RANDOM_ERROR_RANGE`) | Same test passes `len == 0`. | Executed |
| Length above capacity (`BIGNUM_RANDOM_ERROR_LENGTH`) | Same test passes `len == BIGNUM_CAPACITY + 1`. | Executed |
| Non-normalized positive bound (`BIGNUM_RANDOM_ERROR_NORMALIZATION`) | Same test passes nonzero length with zero highest active word. | Executed |
| Top-word bit-length and mask | Bounds 2, 3, `2^64 + 1`, fuzz/property cases, and capacity boundaries. | Executed |
| One-word dispatch and direct publish | Singleton bound 1, bounds 2 and 3, repeated property cases, runner integration, adapter operation. | Executed |
| TLS cache initialization/refill/consume | Repeated active lengths 1–31 in deterministic, 20,000 property, MT, adapter, and benchmark tests. | Executed |
| Post-fork PID cache invalidation | `test_fork_child_sampling` warms parent cache, forks, and makes a child API call. | Executed observable scenario |
| Generic partial-length zeroed candidate and fixed-size publish | Two-word representative range, quarter/half/variable property cases, adapter fixtures. | Executed |
| Full-capacity direct entropy path | `test_capacity_boundaries` creates valid `BIGNUM_CAPACITY` bounds. | Executed |
| High-to-low compare, rejection, and equality retry | Bound 3 and generated non-power-of-two property bounds; rejection has data-dependent count. | Success and retries statistically exercised |
| Candidate normalization including sampled zero | Singleton bound 1 produces exact zero; representative and generated bounds exercise nonzero normalization. | Executed |
| Thread isolation | Eight concurrent independent workers and final Helgrind run. | Executed |
| Distribution ABI/linkage | Static archive/single-header runner. | Executed |
| `EINTR` retry loop | Linux did not inject a syscall interruption into the fixed public test interface. | Structurally reviewed; not deterministic |
| Terminal `getrandom` failure | Linux did not produce a permanent entropy error and no injectable entropy seam exists. | Structurally reviewed; not deterministic |

The rejection-loop row is deliberately not expressed as a deterministic branch percentage. Random sampling makes a specific retry count non-repeatable. Bounds 3 and generated non-power-of-two bounds exercise the rejection domain repeatedly; the correctness oracle checks every observed accepted result against strict `< upper_bound` range membership and normalization.

## Instruction-level Callgrind evidence

The final deterministic binary was profiled with:

```bash
valgrind --tool=callgrind --collect-jumps=yes --dump-instr=yes \
  --callgrind-out-file=benchmarks/reports/final_hybrid_asm_callgrind.out \
  ./bin/test_bignum_random
callgrind_annotate --inclusive=yes --auto=yes \
  benchmarks/reports/final_hybrid_asm_callgrind.out \
  > benchmarks/reports/final_hybrid_asm_callgrind.txt
```

| Callgrind metric | Final value |
|---|---:|
| Program instruction references | 721,113 |
| `bignum_random` instruction references | 175,321 |
| Share of program instruction references | 24.31% |
| Dominant caller | `test_representative_ranges` |
| Symbol presentation | Assembly source plus binary address; line-level source attribution is unavailable for generated YASM debug information. |

This evidence confirms that the final hybrid assembly symbol executed under the deterministic contract suite rather than being optimized out or bypassed by a C fallback.

## Dynamic safety evidence

| Tool | Command family | Result |
|---|---|---|
| AddressSanitizer | `make test_sanitize SAN=address CONFIG=debug USE_ASM=yes` | 5 test binaries; 0 sanitizer issues. |
| UndefinedBehaviorSanitizer | `make test_sanitize SAN=undefined CONFIG=debug USE_ASM=yes` | 5 test binaries; 0 sanitizer issues. |
| Helgrind | `make test_helgrind CONFIG=debug USE_ASM=yes` | MT test passed; 0 races detected. |
| ELF review | `readelf -SW build/bignum_random.o` and `readelf -rW build/bignum_random.o` | TLS `.tbss` section and `R_X86_64_TPOFF32` local-exec relocations present. |
| Static analysis | `make lint` | Exit status 0; only documented informational missing-include messages for adapter/vendor search paths. |

Sanitizers instrument the C test callers and allocations around assembly calls; they cannot insert memory checks into raw YASM instructions. Together with transactional canary assertions, property tests, Helgrind, and Callgrind, they provide behavioral evidence for the assembly/C boundary.

## Raw evidence retained for review

```text
benchmarks/reports/final_hybrid_asm_test_execution.log
benchmarks/reports/final_hybrid_asm_callgrind.out
benchmarks/reports/final_hybrid_asm_callgrind.txt
benchmarks/reports/final_hybrid_asm_callgrind_stdout.log
```

## Coverage conclusion

The final hybrid ASM path has dynamic evidence for all named validation statuses, all three candidate dispatch families, cache refill/consume behavior, post-fork observable behavior, rejection-domain sampling, normalization, transactionality, multithreading, and distribution linkage. It has 175,321 direct Callgrind instruction references in the final assembly symbol during deterministic testing. The only uncovered outcomes are OS-controlled `EINTR` and terminal `getrandom(2)` failure; they cannot be forced without adding an injectable entropy-provider seam to the public/internal design. This limitation is explicit, does not affect the executed success and validation evidence, and remains a documented testability follow-up.

## References

[1] [Linux `getrandom(2)` manual page](https://man7.org/linux/man-pages/man2/getrandom.2.html)
