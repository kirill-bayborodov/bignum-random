# Inline DF Production Activation Gates

**Review status:** F-02 and F-04 test-only gates are closed. Inline DF is not activated in the production dispatcher by this checkpoint.

## Completed Gates

| Gate | Evidence | Status |
|---|---|---|
| F-01 unified cleanup path | `bignum_ctr_drbg_generate` routes all exits through cleanup; validation and vector gates pass | CLOSED |
| F-02 controlled DF failure | Temporary dispatcher failure after additional-input setup; output unchanged, context unchanged, `ERROR_STATE` returned, three cleanup calls recorded, 128 bytes cleared | CLOSED |
| F-04 full-module inline variant | Context, provider fault, fork, health, dispatch, service, and concurrency tests run with inline DF selected | CLOSED for test-only variant |
| Inline DF C11 equivalence | 4096/4096 lengths 1–1024 × four patterns | PASS |
| Inline DF NIST-style vectors | PR=false 240/240; PR=true 240/240 | PASS |
| Inline candidate zeroization | Leaf workspace probe and direct ASan/UBSan checks | PASS |
| Production dispatcher isolation | `src/bignum_ctr_drbg.c` has no inline-candidate reference | PASS |

## F-02 Evidence

The controlled failure was implemented only in a temporary copy of the C dispatcher. The forced failure occurs after `bignum_ctr_drbg_generate` has created its temporary `candidate`, `add_data`, and `block` objects. The result was `BIGNUM_CTR_DRBG_ERROR_STATE`; the caller output and DRBG context remained byte-for-byte unchanged. The temporary source recorded three cleanup calls and 128 cleared bytes, corresponding to the unified cleanup sequence.

This seam was not added to production sources and is not linked into the production archive.

## F-04 Evidence

A temporary full-module dispatcher variant routed valid DF requests to the inline BCC-backed DF orchestration. It was linked with the existing module, context, service, entropy-health, and assembly components. The following tests passed under this variant: caller/provider fault injection, fork ownership isolation, RCT/APT health testing, backend dispatch, controlled service lifecycle, concurrent context isolation, and both 240-case NIST-style vector suites.

Invalid parameter handling was preserved at the dispatcher boundary. The variant rejects NULL input for nonzero length, rejects oversized input, rejects NULL output, and does not write output for rejected oversized requests. The inline leaf remains an internal preconditioned primitive.

## Remaining Production Activation Gates

### G-01: Independent activation approval

The production dispatcher must not be changed automatically by test success. An explicit engineering/security approval is required for changing the approved-facing backend selection. The activation commit must identify the exact YASM object, compiler/linker flags, CPU feature policy, and rollback revision.

### G-02: Release-image and symbol audit after activation

A production archive must be rebuilt with no test-only source, deterministic providers, failure flags, snapshot callbacks, or diagnostic symbols. The archive audit must verify the expected inline symbol set, absence of test symbols, non-executable stack metadata, and reproducible object manifest.

### G-03: Non-AES-NI fallback validation

The runtime dispatcher must be tested on a host or CPU-feature-controlled build where AES-NI is unavailable. The C11 fallback must remain selected, produce the same vectors, preserve all error semantics, and not reference the inline candidate through an unsafe unconditional path.

### G-04: Full production-path regression after the actual switch

The test-only variant proves equivalent module behavior, but the exact production dispatcher change still requires a fresh run of strict C11/YASM build, both vector suites, context/service lifecycle tests, fault tests, health tests, fork tests, concurrency tests, ASan/UBSan, Memcheck, cppcheck, and diff hygiene.

### G-05: Final target-host performance evidence

The inline candidate shows a strong test-only speedup, but release claims require paired median/MAD measurements on the target deployment host with fixed CPU affinity, compiler flags, repetition count, and CPU frequency policy. PMU evidence should be collected where permitted; the current sandbox does not expose hardware performance counters.

### G-06: Documentation and change-control update

Before activation, update the internal ABI note, README release/backend description, security/zeroization audit, performance profile, and module traceability documents. The activation commit must include a complete artifact-level QG checklist and identify the changed production image contents.

## Recommendation

The test-only evidence supports moving to a formal activation review, but not silently changing production code. The safest next step is to prepare a narrowly scoped activation patch behind the existing runtime capability check, run the exact production-path gates listed in G-02 through G-06, and request explicit approval before publishing the activation commit.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[2]: https://csrc.nist.gov/pubs/fips/140-3/final "FIPS 140-3 Security Requirements for Cryptographic Modules"
