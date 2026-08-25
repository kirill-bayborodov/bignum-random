# Track B Approved Integration Boundary

**Status:** Candidate engineering design; not a FIPS validation claim.

The controlled integration boundary separates the production-facing service from the deterministic provider test seam. Production-facing callers use `bignum_ctr_drbg_service.h` and never supply an entropy callback. The service implementation binds instantiate and reseed to `bignum_ctr_drbg_os_entropy_provider`, while the lower-level caller-context API remains available only to implementation and test harnesses.

| Layer | Public to production caller | Entropy source | Test-provider reachability |
|---|---|---|---|
| `bignum_ctr_drbg_service` | Yes, candidate Approved-facing API | Linux `getrandom(2)` adapter only | None through service API |
| `bignum_ctr_drbg_context` | Internal integration boundary | Callback supplied by caller | Available to test harnesses only |
| `bignum_ctr_drbg_os_entropy` | Linked by controlled production image | Stateless Linux adapter | No deterministic state |
| `tools/*` providers | No | Deterministic test data | Test-only |

The protected family Makefile currently builds only the legacy family-named source. Therefore, this service is delivered as an explicit integration unit and is not silently added to the legacy image. A future Approved build must list the service, context, DRBG, OS adapter and selected AES backend in a frozen manifest, while excluding `tools/` and all deterministic provider symbols.

The service does not expose provider selection, provider context, expanded AES keys, health state, direct syscall flags, or debug/fault hooks. Startup still requires the external image-integrity result and power-up KAT. Provider or health failures remain fail-closed and prevent output.

## Required integration controls

The production build must use an allowlist of source files and exported symbols rather than a broad directory wildcard. The resulting image must be audited for deterministic-provider strings and symbols, test harness objects, debug hooks, alternate entropy paths and unapproved CPU instructions. The Linux adapter must be replaced or qualified according to the selected operating-environment and entropy-source assessment before any certification submission.

## References

[1]: https://csrc.nist.gov/pubs/fips/140-3/final "NIST FIPS 140-3"

[2]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[3]: https://csrc.nist.gov/pubs/sp/800/90/b/final "NIST SP 800-90B"

## Controlled candidate-image audit evidence

An allowlisted C11 candidate archive was assembled outside the protected Makefile from exactly five source units: `bignum_ctr_drbg.c`, `bignum_ctr_drbg_module.c`, `bignum_ctr_drbg_context.c`, `bignum_ctr_drbg_os_entropy.c`, and `bignum_ctr_drbg_service.c`. The archive contained no `tools/` objects, test entry point, deterministic provider, fault hook, or RDRAND token. Objects had no dynamic sections. The C11 AES dispatcher retained only a weak unresolved YASM leaf symbol, so the archive safely resolves to the C fallback unless the separately audited AES-NI object is deliberately linked.

The audit found expected platform/runtime undefined references (`getrandom`, `getpid`, libc/compiler runtime and CPU feature helpers). These dependencies must be frozen and included in the future Approved build manifest. This candidate archive is an integration artifact, not a validated cryptographic module.
