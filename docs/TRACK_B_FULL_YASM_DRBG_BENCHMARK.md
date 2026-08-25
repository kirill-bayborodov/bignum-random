# Track B Full YASM DRBG Benchmark and Zeroization Evidence

**Status:** Candidate engineering evidence; not FIPS validation evidence.

## Workload

The benchmark uses the caller-allocated service boundary and performs 10,000 separate 32-byte Linux `getrandom(2)` acquisitions as an entropy-only measurement. The DRBG measurement then performs one startup and OS-backed instantiate followed by 512 iterations. Every iteration performs a 48-byte AdditionalInput operation through Block_Cipher_df/BCC, generates 2,048 bytes with CTR counter handling, executes state update, and periodically performs an OS-backed reseed every 16 iterations. The context is uninstantiated and zeroized after the measurement.

| Metric | C11 reference | Full independent YASM |
|---|---:|---:|
| Entropy calls | 10,000 | 10,000 |
| DRBG iterations | 512 | 512 |
| Output per iteration | 2,048 bytes | 2,048 bytes |
| Median DRBG time, five runs | 3,068,670,208 ns | 16,506,458 ns |
| Median time per iteration | 5,993,496.50 ns | 32,239.18 ns |
| Observed median speedup | 1.000x | **185.907x** |

The entropy-only path was measured separately because kernel scheduling and entropy-source behavior are environmental variables. The result is a performance comparison against the deliberately readable scalar C11 reference and is not certification evidence.

## Independent YASM primitives

The YASM object independently implements AES-256 key expansion, AES block encryption, and `CTR_DRBG_Update`. The update leaf increments the 128-bit `V` value in big-endian order, encrypts three successive counter blocks, XORs the 48-byte provided data, publishes the 32-byte key and 16-byte `V`, and then clears its temporary schedule and output area.

The C11 dispatcher requires AES-NI and all three YASM symbols before selecting the independent path. If any prerequisite is absent, the C11 implementation remains the fallback.

## Vector and regression evidence

The independent full YASM shared library passed both complete repository CAVP-style suites: **240/240 PR=false** and **240/240 PR=true**. The C-only fallback passed the same suites. The FIPS 197 schedule/ciphertext KAT passed under strict compilation, stack protection and ASan/UBSan. Existing protected C11 and legacy ASM targets both finished with **0/5 failures**.

## Zeroization evidence

A test-only build defines `BIGNUM_DRBG_ZEROIZE_PROBE`. After the YASM update leaf publishes the new state, it clears 304 bytes of private stack storage using `rep stosq`; the probe verifies every byte is zero. The leaf also clears all used XMM registers before the wipe. The probe passed strict C11 and ASan/UBSan runs.

The production object is assembled without the probe macro. Its symbol and string scan contains no probe symbol or test token, and the object carries a non-executable `.note.GNU-stack`. The probe is not part of the production allowlist.

## Remaining controls

The assembly leaf still requires a frozen production symbol allowlist, reproducible build and image digest, independent assembly review, runtime AES-NI policy, and target-specific entropy-source qualification. The benchmark and zeroization probe do not establish FIPS 140-3 validation.
