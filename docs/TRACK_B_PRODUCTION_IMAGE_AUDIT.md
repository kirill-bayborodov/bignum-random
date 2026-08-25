# Track B Production Image Security Audit

**Audit scope:** the protected release distribution produced by `make dist CONFIG=release USE_ASM=yes`.

**Important boundary:** this distribution is the existing legacy `bignum_random` image. The candidate Track B DRBG/context sources are intentionally not selected by the protected family Makefile, so this audit verifies isolation from the legacy production image; it is not evidence that the candidate DRBG is already part of an Approved module.

## Audit checklist

| Check | Method | Result |
|---|---|---|
| Archive members | `ar t dist/libbignum_random.a` | `bignum_random.o`, `bignum_core.o` only |
| Candidate provider/test symbols | `nm -A -g --defined-only` and token scan | None found |
| Deterministic provider/fault strings | `strings -a` scan for provider, test, fault, health, DRBG, RDRAND and getrandom tokens | None found |
| Candidate source reachability | Archive member and symbol review | No `ctr_drbg`, entropy-provider or health symbols |
| ELF dynamic section | `readelf -d` on each archive object | No dynamic section; static objects only |
| Executable-stack metadata | Existing release build flags and object review | Protected build uses `-z noexecstack`; no candidate hook introduced |
| Distribution self-check | `make dist` runner | `bignum_random distribution runner: PASSED` |
| Protected files | Git status/diff review | `Makefile` and CI workflow unchanged |

The production archive contains the legacy public symbol `bignum_random` and no candidate context, health-test, deterministic provider, fault-injection, RDRAND, or direct `getrandom` string/symbol references in the archive scan. The result supports the intended packaging separation: test-only candidate artifacts remain under `tools/` and are not pulled into the protected `tests/*.c` production wildcard.

## Findings and limitations

The isolation result is **PASS for the current legacy distribution boundary**. It must not be interpreted as a certification result. The final validated image still requires a dedicated build manifest, exact-image hash, link map, symbol allowlist, dependency bill of materials, reproducible-build evidence, and a separate audit after the candidate Approved service is deliberately integrated.

The deterministic providers used by the health and lifecycle harnesses are test seams. They are not permitted to be reachable from an Approved production image. The audit therefore treats their absence from the current legacy archive as a packaging control, not as proof of future integration correctness.

## Reproduction commands

```sh
make clean
make dist CONFIG=release USE_ASM=yes
ar t dist/libbignum_random.a
nm -A -g --defined-only dist/libbignum_random.a
strings -a dist/libbignum_random.a
```

## References

[1]: https://csrc.nist.gov/pubs/fips/140-3/final "NIST FIPS 140-3"

[2]: https://csrc.nist.gov/pubs/sp/800/90/b/final "NIST SP 800-90B"
