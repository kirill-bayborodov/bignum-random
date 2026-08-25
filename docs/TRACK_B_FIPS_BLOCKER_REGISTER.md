# Track B FIPS Blocker Register

**Checkpoint:** Current `main` after commit `148cc24`.

**Status:** Engineering/CSTL preparation only; no FIPS 140-3 or CAVP claim.

## Register

| ID | Blocker | Status | Evidence or required action |
|---|---|---|---|
| B-01 | Exact module boundary and Security Policy | OPEN | CSTL must approve inside/outside boundary, services, roles, SSPs and operational environment |
| B-02 | Entropy-source treatment | OPEN | Decide `getrandom(2)` treatment; complete SP 800-90B/90C mapping and source evidence |
| B-03 | Approved algorithm scope | OPEN | Freeze CTR_DRBG capabilities, security strength, DF/PR/reseed profile and CAVP/ACVP path |
| B-04 | Trusted software integrity mechanism | OPEN | Implement or integrate trusted anchor, measured image scope, verification timing and failure response |
| B-05 | Reproducible release identity | PARTIAL | Tag and source hash recorded; exact frozen toolchain, binary manifest and final image hash remain required |
| B-06 | Inline DF production activation | NOT ACTIVATED | Test-only F-02/F-04 evidence passes; actual dispatcher switch requires approval and fresh production gates |
| B-07 | Non-AES-NI operational scope | ENGINEERING PASS | C11-only fallback passes both vector suites; claimed validation scope remains CSTL decision |
| B-08 | Lifecycle/fault/zeroization behavior | ENGINEERING PASS | F-01 closed; F-02/F-04 closed in test-only evidence; final activated image needs rerun |
| B-09 | Entropy health-test parameter justification | OPEN | Existing RCT/APT behavior is engineering evidence; thresholds require source assessment |
| B-10 | Update, rollback and change control | OPEN | Define signed/trusted update procedure, rollback policy and image-change handling |
| B-11 | Toolchain/CPU/ELF environment freeze | PARTIAL | Linux x86-64/SysV/AES-NI policy documented; exact versions and supported matrix remain open |
| B-12 | Independent CSTL assessment | OPEN | Submit complete evidence package and obtain laboratory determination |

## Evidence Scope Frozen for This Checkpoint

The current engineering evidence includes C11 CTR_DRBG, YASM AES/BCC/DF leaves, inline BCC-backed DF candidate, caller-allocated context, fail-closed lifecycle, entropy-provider boundary, RCT/APT checks, fork ownership checks, zeroization probes, NIST-style vector suites, sanitizer/Memcheck/static checks, and release-distribution smoke tests.

The following are explicitly not evidence of validation: local vector success as a substitute for CAVP, Linux `getrandom(2)` as a substitute for entropy-source validation, a source SHA-256 as a trusted integrity mechanism, benchmark results as a security-strength claim, or test-only inline dispatcher results as production activation evidence.

## Decision Boundary

No production dispatcher change is authorized by this register. The register supports formal CSTL pre-review and identifies the evidence needed for a separately approved activation change.

## References

[1]: https://csrc.nist.gov/pubs/fips/140-3/final "NIST FIPS 140-3"

[2]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[3]: https://csrc.nist.gov/pubs/sp/800/90/b/final "NIST SP 800-90B"

[4]: https://csrc.nist.gov/pubs/sp/800/90/c/final "NIST SP 800-90C"
