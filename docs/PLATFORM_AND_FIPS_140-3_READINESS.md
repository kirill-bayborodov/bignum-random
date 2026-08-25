# Platform and FIPS 140-3 Readiness Assessment

**Project:** `bignum-random`  
**Assessment baseline:** Git tag `v0.0.0`, commit `3163a6b7b44d87fe222fbeefa40e00b0268930df`  
**Scope:** current C11 reference, x86-64 YASM implementation, Linux `getrandom(2)`, independent audit readiness, and FIPS 140-3 planning.

> This document is a technical readiness assessment, not a FIPS certificate, a CMVP decision, or legal advice. Only CMVP can issue a FIPS 140-3 validation, and testing must be performed through an appropriate independent NVLAP-accredited Cryptographic and Security Testing Laboratory (CSTL).

## Executive conclusion

The current module is a **Linux x86-64 bounded-random utility**, not yet a FIPS 140-3 validated cryptographic module. It implements an unbiased integer-range transform over bytes obtained from the host Linux kernel. The transform is useful and testable, but it is not itself an Approved security function, and the project currently has no declared cryptographic module boundary, Approved mode of operation, Security Policy, CAVP certificate, entropy-source validation package, power-up self-tests, or CMVP submission package.

The recommended certification strategy is to treat the current `bignum_random` implementation as either an application utility outside a validated cryptographic boundary, or redesign the cryptographic boundary around an Approved SP 800-90A DRBG and a documented, validated entropy/RBG construction. Merely calling Linux `getrandom(2)`, adding rejection sampling, or compiling the same code with YASM does **not** establish FIPS 140-3 validation. NIST states that algorithm validation is a prerequisite for module validation and that a module must implement at least one Approved security function in an Approved mode of operation [1].

## Current implementation and platform impact

The C11 and YASM paths perform the same mathematical operation. They validate a positive normalized fixed-capacity bound, derive its significant bit width, obtain random words, mask unused high bits, reject candidates greater than or equal to the bound, normalize the accepted value, and publish output transactionally. This is a sound way to avoid modulo bias. It does not, by itself, define an Approved random-bit-generation mechanism.

### Linux and syscall assumptions

| Assumption | Current implementation | Impact |
|---|---|---|
| Operating system | Linux only | The C11 path includes `<sys/random.h>`; the YASM path invokes a Linux syscall directly. Portability requires a separate entropy-provider abstraction. |
| Kernel interface | `getrandom(2)` with flags `0` | The default source is the kernel `urandom` source. The call can block until initialization; the caller must inspect both errors and returned byte count [2]. |
| Small request size | At most 256 bytes per entropy fill | Linux documents a special guarantee for initialized `urandom` reads up to 256 bytes, while larger requests may be short or interrupted. The implementation still handles short reads and `EINTR` defensively [2]. |
| Minimum syscall availability | Linux 3.17 for `getrandom(2)` | Older kernels require an explicit unsupported-platform failure or a separately assessed provider; silent fallback to `/dev/urandom` is not currently part of the contract [2]. |
| C11 error model | libc wrapper returns `-1` and sets `errno` | The C implementation retries `EINTR` and maps other failures to `BIGNUM_RANDOM_ERROR_ENTROPY`. It does not expose the original errno. |
| YASM error model | Raw syscall returns a negative errno in `rax` | The assembly path compares the raw result with `-EINTR`, retries that case, and maps all other negative results to the named entropy error. No libc ABI or `errno` state is relied upon. |
| Maximum direct request | 256 bytes | This fits the documented Linux small-read boundary and the fixed 32-word `bignum_t` capacity. It is a design choice, not a FIPS assurance. |
| x86-64 syscall ABI | `rax=318`, buffer in `rdi`, length in `rsi`, flags in `rdx`, `syscall` clobbers `rcx` and `r11` | The number and register convention are x86-64-specific. AArch64, x86-32, and other Linux ABIs require different assembly or a C provider. |
| User-space ABI | System V AMD64 | The YASM implementation preserves `rbx`, `r12`–`r15`, maintains stack storage, and publishes no flags contract. A shared-library validation build must separately verify relocation and ABI assumptions. |
| TLS model | ELF local-exec TLS with `R_X86_64_TPOFF32` | The cache is thread-private, but the relocation model constrains how the object can be linked and loaded. A PIE/shared-library/FIPS packaging claim must explicitly include the permitted link model. |
| Fork behavior | Per-call raw `getpid` comparison invalidates inherited TLS cache | This is a defensive cache rule, not a complete fork-safety certification. Tests must cover `fork`, child sampling, cache state, failure handling, and async-signal-safe usage assumptions. |
| Entropy cache | YASM caches 32 words per thread; full-capacity calls bypass the cache | This reduces syscall overhead for short ranges but introduces mutable TLS state, cache lifetime, fork invalidation, and zeroization questions. The C11 reference retains no entropy cache. |

Linux documents that `getrandom(2)` may be used for cryptographic purposes, but that statement describes the system-call interface and does not validate this project as a FIPS module. The current implementation should therefore document the kernel as an **external operational-environment dependency**, not as an Approved algorithm owned by this library.

### Security consequences of `getrandom(2)` dependency

The default `urandom` source can block during early boot before the kernel entropy pool is initialized. The current API intentionally has no nonblocking mode and maps a terminal syscall failure to a generic entropy status. This is appropriate for a simple blocking utility, but a validated module needs a precise operational policy for startup blocking, entropy-source failure, retry limits, service denial, and zeroization.

The YASM cache changes the failure and timing surface. Once bytes have been obtained, later short-range calls can succeed without another syscall. A child process discards inherited cache state after detecting a PID change, but the implementation does not provide an explicit cache-zeroization API or a documented guarantee that every stale physical copy is erased. The audit must decide whether raw entropy bytes are Sensitive Security Parameters (SSPs), whether they are inside the logical boundary, and what zeroization evidence is required.

The rejection loop is mathematically necessary for uniformity and has data-dependent iteration count. The current public documentation warns about this. An audit must establish whether the bound is public in every intended use; if the bound or acceptance timing can reveal a secret, a constant-time or different protocol design is required. FIPS validation is not a substitute for application-level side-channel analysis.

## FIPS 140-3 applicability and gap assessment

FIPS 140-3 covers the secure design, implementation, and operation of cryptographic modules across areas including module specification, interfaces, roles and services, software/firmware security, operating environment, sensitive-security-parameter management, self-tests, lifecycle assurance, and attack mitigation [3]. CMVP uses ISO/IEC 19790 for requirements and ISO/IEC 24759 for test methods, supplemented by SP 800-140 and the related SP 800-140A–F documents [4].

| Requirement area | Current status | Required disposition |
|---|---|---|
| Module definition and boundary | **Missing** | Define the logical boundary, physical assumptions, software image, included libraries, kernel dependency, build outputs, and excluded application code. |
| Approved mode of operation | **Missing** | Define a named Approved mode and a non-Approved mode, or explicitly scope this utility outside the validated cryptographic module. |
| Approved security function | **Missing** | Add or consume a CAVP-validated Approved algorithm, normally an SP 800-90A DRBG if the module is intended to generate cryptographic random bits. CAVP lists DRBG among tested random-number-generation algorithms [1]. |
| Entropy source | **Unsubstantiated** | Identify the actual entropy source and conditioning chain. A claim involving an entropy source requires SP 800-90B justification/validation where applicable; CMVP identifies IG D.J, D.K, and D.O as relevant entropy guidance [5]. |
| RBG construction | **Not claimed** | If this is presented as an RBG, map the construction to SP 800-90C. SP 800-90C defines RBG1, RBG2, RBG3, and RBGC constructions that combine entropy sources and DRBG mechanisms [6]. |
| Interfaces and services | **Partial** | The C API and status contract exist. Add service descriptions, input/output classification, error behavior, lifecycle states, and Approved/non-Approved service mapping. |
| Roles and authentication | **Missing** | Define operator roles and authentication applicability. A small software library may document non-applicability only with supporting rationale accepted by the lab. |
| SSP management | **Missing/partial** | Classify cached raw entropy, transient buffers, process state, and any future DRBG seed/key material. Specify storage, zeroization, error handling, and exposure rules. |
| Software integrity | **Missing** | Define image integrity mechanism, trusted build, release hash, load-time/startup integrity test, and tamper/error response. |
| Self-tests | **Missing** | Define power-up/startup self-tests and conditional self-tests for every Approved algorithm and relevant entropy/RBG component. A random-range transform property test is not a cryptographic algorithm self-test. |
| Operational environment | **Partial** | Freeze supported Linux distributions, kernel range, x86-64 ABI, compiler/YASM versions, link model, CPU features, container/VM assumptions, and permitted environment changes. |
| Physical security | **Unassessed** | For a software module, determine the applicable FIPS level and document the physical-security claim or non-applicability with the lab. |
| Non-invasive attack mitigation | **Unassessed** | Analyze cache timing, syscall timing, rejection-loop timing, fault injection, speculative execution exposure, and compiler/assembler transformations. |
| Life-cycle assurance | **Missing** | Establish secure development, review, change control, release signing, vulnerability response, dependency pinning, reproducible build, and archival procedures. |
| Vendor evidence and Security Policy | **Missing** | Produce the SP 800-140A documentation package and SP 800-140B Rev. 1 Security Policy package. The CMVP standards page identifies these documents as the applicable documentation and policy supplements [4]. |
| Independent laboratory testing | **Missing** | Select an NVLAP-accredited CSTL, agree on the validation target and level, provide evidence, answer lab findings, and support the CMVP review. CMVP describes the CSTL-to-CMVP submission flow [4]. |

### Fundamental certification decision

There are two viable tracks.

**Track A — utility outside the validated boundary.** Keep `bignum_random` as a Linux utility for non-FIPS applications. Remove any wording that implies FIPS approval, make the external entropy dependency explicit, and require downstream FIPS applications to obtain random bytes from their already validated module. This is the lowest-risk track.

**Track B — validated random-generation component.** Define a complete software cryptographic module around an Approved SP 800-90A DRBG, its validated algorithm implementation, the entropy input and conditioning path, self-tests, integrity protection, Approved mode, and Security Policy. `bignum_random` then becomes a service layered on top of the module's Approved RBG output. The range-reduction function still requires its own specification and assurance, but it should not be described as the FIPS-approved random generator unless the validation scope and evidence explicitly say so.

The current direct Linux-kernel design does not provide enough evidence to choose Track B. In particular, the project has not demonstrated that the host kernel, its RNG construction, or the library's rejection sampler is a validated Approved security function. The current YASM optimization must not be allowed to silently change the validated cryptographic boundary.

## Independent audit plan

| Phase | Objective | Required outputs | Exit gate |
|---|---|---|---|
| 0. Certification scoping | Choose Track A or Track B and target FIPS security level | Certification decision, intended users, data classification, module owner, CSTL shortlist | Product owner and lab agree on scope |
| 1. Boundary and threat model | Define what is and is not the module | Boundary diagram, asset/SSP inventory, trust boundaries, attacker model, platform assumptions | No unresolved boundary ambiguity |
| 2. Algorithm and entropy architecture | Map every random-bit claim to standards | Algorithm specification, SP 800-90A/B/C mapping, entropy source/conditioning rationale, bias proof, failure policy | Lab pre-review accepts architecture |
| 3. Platform baseline | Freeze Linux x86-64 operating environments | Supported kernel/glibc/compiler/YASM matrix, syscall availability policy, ABI/TLS/link model, reproducible build recipe | Every claimed environment is buildable and testable |
| 4. Secure implementation review | Review C, YASM, TLS, fork, memory and error paths | Per-file review checklist, ABI proof, memory-safety evidence, zeroization analysis, side-channel analysis, dependency SBOM | All high/critical findings closed or accepted by lab |
| 5. Test and fault campaign | Demonstrate normal, negative, concurrency and failure behavior | Unit/property/fuzz tests, syscall fault injection, `EINTR`/short-read/error tests, fork/MT tests, sanitizers, static analysis, coverage evidence | Required tests pass with retained logs and hashes |
| 6. Self-tests and integrity | Implement FIPS lifecycle controls | Power-up and conditional self-tests, image integrity test, failure state machine, startup/conditional test vectors | Self-test failure prevents Approved services |
| 7. Evidence package | Assemble vendor and lab material | SP 800-140A evidence, SP 800-140B Rev. 1 Security Policy, configuration files, source/build hashes, test report inputs | Package is complete and traceable |
| 8. CSTL/CMVP process | Execute independent validation | Lab contract, formal test report, finding responses, CMVP submission, change-management commitments | Validation certificate or documented disposition |

## Concrete implementation requirements before Track B

1. **Define an Approved cryptographic core.** Select a CAVP-testable SP 800-90A DRBG and a validated implementation strategy. The range sampler must consume output from that core through a defined service interface; the sampler itself must not be presented as the DRBG.

2. **Define entropy ownership.** Decide whether Linux `getrandom(2)` is an external entropy input, a platform-provided RBG, or an excluded dependency. Document initialization blocking, kernel failure, short read, `EINTR`, `ENOSYS`, VM/container behavior, early boot, and live migration assumptions. Do not add an unreviewed fallback.

3. **Replace implicit TLS with an audited state model.** Document the local-exec ELF requirement or move cache state to an explicit caller/module context. Specify fork handling, thread creation/destruction, cache zeroization, crash behavior, and whether cached bytes are SSPs. Any context API change requires a compatibility and lab-scope review.

4. **Add deterministic fault injection at a test seam.** Tests must force short reads, `EINTR`, terminal errors, unavailable entropy, fork transitions, cache exhaustion, and allocation/stack boundary conditions without relying on manipulating the host kernel. The production Approved path must not retain a test backdoor.

5. **Add startup and conditional self-tests.** Include known-answer tests for every Approved algorithm, integrity verification for the image, and a state machine that inhibits Approved services after failure. Existing random-output property tests are necessary but insufficient.

6. **Freeze claims and build identity.** Record source commit, submodule commits, distribution hashes, compiler/YASM versions, linker flags, kernel/OS identity, CPU family, ELF relocation model, and generated distribution hashes. Reproduce the exact validation binary from a clean environment.

7. **Review side channels and fault behavior.** Analyze rejection-loop timing, bound-dependent memory access, syscall latency, TLS cache state, branch behavior, `fork`, signal delivery, and malformed bignum inputs. Decide whether bounds are public; if not, redesign the service.

8. **Prepare auditable documentation.** Add module specification, interface specification, roles/services/authentication applicability, Security Policy, Approved/non-Approved mode table, self-test specification, software integrity design, SSP lifecycle, operational-environment guide, secure-update process, and vulnerability disclosure process.

## Current audit readiness rating

| Dimension | Rating | Interpretation |
|---|---:|---|
| Functional correctness | Green | C11/ASM behavior, range invariants, transactional output, MT and fork scenarios have project evidence. |
| Linux x86-64 implementation assurance | Amber | ABI/TLS/syscall assumptions are documented and locally tested, but platform matrix and shared-library/link-model claims are not frozen. |
| Entropy-source assurance | Red | The module delegates entropy to the host kernel and has no SP 800-90B/90C evidence or validated entropy/RBG certificate. |
| FIPS algorithm assurance | Red | No CAVP-validated Approved security function is claimed by this repository. |
| Module boundary and Security Policy | Red | Required CMVP artifacts do not exist. |
| Independent-audit readiness | Amber/Red | Strong engineering test evidence exists, but certification evidence and formal scope are not prepared. |

## References

[1]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program "NIST Cryptographic Algorithm Validation Program (CAVP)"

[2]: https://man7.org/linux/man-pages/man2/getrandom.2.html "Linux getrandom(2) manual page"

[3]: https://csrc.nist.gov/pubs/fips/140-3/final "NIST FIPS 140-3: Security Requirements for Cryptographic Modules"

[4]: https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-standards "NIST CMVP FIPS 140-3 Standards and documentation flow"

[5]: https://csrc.nist.gov/projects/cryptographic-module-validation-program/entropy-validations "NIST CMVP Entropy Validations"

[6]: https://csrc.nist.gov/pubs/sp/800/90/c/final "NIST SP 800-90C: Recommendation for Random Bit Generator Constructions"

[7]: https://csrc.nist.gov/pubs/sp/800/90/b/final "NIST SP 800-90B: Recommendation for the Entropy Sources Used for Random Bit Generation"

[8]: https://csrc.nist.gov/pubs/sp/800/140/final "NIST SP 800-140: FIPS 140-3 Derived Test Requirements"
