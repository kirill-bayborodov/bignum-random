# CSTL Module Boundary and Security Policy Audit

**Scope:** Track B AES-256 CTR_DRBG candidate and bounded `bignum_random` service.

**Status:** Formal engineering pre-review; not a FIPS 140-3 validation claim.

## Proposed Boundary

| Component | Boundary classification | Rationale and required policy treatment |
|---|---|---|
| Public `bignum_random` service | Inside | Approved-facing bounded range transform only when backed by the selected DRBG service; output and error contract must be defined |
| Caller-allocated context/service lifecycle | Inside | Owns state, lifecycle, failure latch, fork ownership and zeroization |
| AES-256 CTR_DRBG C11/YASM implementation | Inside | Exact algorithm implementation and processor variants must be scoped for validation |
| BCC and Block_Cipher_df | Inside | Cryptographic support functions required by the selected DRBG profile |
| Entropy-provider adapter | Boundary decision required | Must be identified as inside-module, external validated component, or operational-environment dependency |
| Linux `getrandom(2)` kernel service | External candidate dependency | Source treatment, min-entropy rationale and failure semantics require CSTL decision |
| Compiler, YASM, linker and ELF loader | Operational environment | Exact versions, flags, ABI, CPU policy and supported image must be frozen |
| Benchmark/fuzz/fault instrumentation | Outside | Must not be linked into validated production image |
| Test-only inline DF dispatcher | Outside | Candidate evidence only; excluded from production image until activation approval |
| Release archive smoke-test source | Packaging decision required | Existing recipe includes it; final Security Policy must classify or exclude it |

## Security Policy Readiness

| Security Policy section | Current readiness | Gap |
|---|---|---|
| Module name/version and binary identity | Partial | Need final activated image hash and build manifest |
| Cryptographic services | Partial | Need Approved/non-Approved service table and exact algorithm scope |
| Roles and authentication | Open | Define operator/user roles and assumptions for software module |
| SSP inventory and lifecycle | Partial | Engineering inventory exists; formal classification and access statement require CSTL review |
| Entropy input and RBG construction | Open | Resolve SP 800-90B/90C treatment and boundary ownership |
| Self-tests and integrity | Partial | KAT/fail-closed evidence exists; trusted integrity mechanism is not implemented |
| Error states and transitions | PASS engineering | Bind exact statuses and transitions to final policy wording |
| Operational environment | Partial | Freeze OS/kernel/toolchain/ELF/CPU matrix and change policy |
| Physical security assumptions | Open | Document software-module assumptions required by the chosen validation path |
| Mitigation of other attacks | Open | Determine applicable side-channel, fault, timing and DoS claims with CSTL |
| Installation/update/rollback | Open | Define signed or trusted update process and rollback handling |

## Boundary Decisions Required from CSTL

The laboratory must decide whether the kernel-provided entropy source is part of the module boundary or an external component. It must also decide whether AES-NI and the C11 fallback are separate validated implementation variants or whether only one processor configuration is in scope. The range service must be explicitly mapped as a service transformation and must not be presented as an Approved DRBG algorithm by itself.

The final Security Policy must name every included object, generated table, configuration input, assembly leaf, and runtime capability decision that affects cryptographic behavior. It must state that benchmark, fuzzing, deterministic provider, snapshot, and fault-injection seams are excluded from the validated image.

## Audit Conclusion

The engineering boundary is sufficiently described for CSTL pre-review, but it is not certification-ready. The primary blockers are entropy-source disposition, exact Approved algorithm/capability scope, trusted software-integrity mechanism, frozen operational environment, formal roles/services/SSP policy, and update/rollback procedures.

## References

[1]: https://csrc.nist.gov/pubs/fips/140-3/final "NIST FIPS 140-3"

[2]: https://csrc.nist.gov/pubs/sp/800/140/final "NIST SP 800-140"

[3]: https://csrc.nist.gov/pubs/sp/800/90/b/final "NIST SP 800-90B"

[4]: https://csrc.nist.gov/pubs/sp/800/90/c/final "NIST SP 800-90C"
