# Track B BCC/DF Security and Zeroization Audit

**Status:** Engineering security audit; not a FIPS 140-3 validation claim.

## Scope

The audit covers the modified YASM BCC and Block_Cipher_df leaves, their C dispatcher, the C/ASM ABI, private workspace lifetime, register and stack behavior, error routing, test-only instrumentation, and dynamic memory checks.

## Workspace and Secret-Lifetime Review

| Component | Workspace | Secret material | Cleanup evidence | Result |
|---|---:|---|---|---|
| BCC | 320 bytes | Expanded AES-256 schedule, chaining value, current block | 40 `stosq` operations before return | PASS |
| DF | 2440 bytes | S/data stream, three BCC outputs, raw post-processed key, X, expanded AES schedule | 305 `stosq` operations before return | PASS |
| DF post-processing | DF workspace offsets 2096, 2144, 2176, 2192 | Temp, raw key, X, expanded schedule | Included in DF wipe range `[rsp, rsp+2440)` | PASS |
| Production object | No snapshot/zeroization probe symbols | No test-only callback dependency | `nm -u` contains no test-hook symbols | PASS |

The BCC and DF leaves do not retain global mutable state. Inputs are borrowed for the call duration. Outputs are published before workspace cleanup, and the assembly leaves do not expose partial output on their own error path because validation is performed by the C dispatcher before selection. The dispatcher rejects a NULL output and routes unsupported or invalid input to the C reference contract.

## ABI and Stack Review

The leaves use the System V AMD64 ABI. The BCC prologue has five pushes followed by a 320-byte subtraction; the DF prologue has six pushes followed by a 2440-byte subtraction. Both preserve callee-saved registers used by their loops. Nested calls occur with the required stack alignment. The DF post-processing explicitly expands the raw 32-byte key into a private 240-byte schedule before calling the AES-NI encryption leaf.

The production assembly object contains the expected AES, Update, BCC, and DF symbols, a non-executable `.note.GNU-stack`, and no unresolved snapshot or zeroization probe symbols. Test-only hooks are enabled only by explicit assembly defines and are not part of the normal production object.

## Dynamic Evidence

| Gate | Evidence | Result |
|---|---|---|
| BCC zeroization probe | 320-byte workspace fully zero after direct BCC return | PASS |
| DF zeroization probe | 2440-byte workspace fully zero after DF return; direct BCC plus three DF BCC calls observed | PASS |
| AES-256 leaf KAT | C/YASM leaf comparison | PASS |
| AddressSanitizer/UBSan | Strict test binary | PASS |
| Valgrind Memcheck | Non-ASan test binary, no invalid accesses or leaks | PASS |
| NIST-style DF/CTR_DRBG vectors | PR=false 240/240; PR=true 240/240 | PASS |
| Static analysis | cppcheck warning/style/performance/portability set | PASS |

The Valgrind run is intentionally performed against the non-ASan binary because Valgrind and ASan runtime preload requirements are incompatible in this execution environment. ASan/UBSan and Valgrind were therefore treated as separate dynamic gates.

## Error and Early-Return Review

The YASM leaves themselves are internal primitives with validated caller contracts and no partial-failure branch. The C DF dispatcher checks `output == NULL` before dispatch, accepts `input == NULL` only for `input_len == 0`, rejects lengths above 1024, and retains the C11 fallback when AES-NI or required symbols are unavailable. Rejected oversized input leaves the output unchanged under the C reference path.

## Findings

The audit identified and corrected one static-analysis issue: a redundant `output != NULL` condition after an explicit NULL return in the dispatcher. It also identified that the previous zeroization probe covered only CTR_DRBG_Update; conditional BCC and DF probes were added for test builds. No production test hook was introduced.

No unresolved memory-safety, secret-lifetime, stack-alignment, executable-stack, or production-isolation finding remains in the audited path. Residual review requirements are normal for future assembly optimization: every change must rerun the same direct zeroization probes, differential vectors, sanitizer/Memcheck gates, and symbol-isolation check.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[2]: https://csrc.nist.gov/pubs/fips/197/final "FIPS 197 Advanced Encryption Standard"

[3]: https://csrc.nist.gov/pubs/fips/140-3/final "FIPS 140-3 Security Requirements for Cryptographic Modules"
