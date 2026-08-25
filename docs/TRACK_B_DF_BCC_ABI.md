# Track B YASM DF/BCC Internal ABI

**Status:** Candidate engineering boundary; not a FIPS validation claim. BCC and DF assembly are integrated and vector-validated through the runtime dispatcher.

The DF/BCC assembly path is internal to the CTR_DRBG implementation. It is not included in the public context or service headers. All inputs are borrowed for the duration of the call; output buffers are caller-owned and fully written only after successful completion.

| Primitive | System V AMD64 arguments | Contract |
|---|---|---|
| `bignum_ctr_drbg_bcc_asm` | `RDI=key[32]`, `RSI=data`, `RDX=data_len`, `RCX=output[16]` | `data_len` is positive and a multiple of 16; output is one BCC chaining block |
| `bignum_ctr_drbg_block_cipher_df_asm` | `RDI=input`, `RSI=input_len`, `RDX=output[48]` | Input length is validated by the C dispatcher; output is exactly 48 bytes |

The YASM BCC leaf expands the 256-bit key once, processes every 16-byte block, publishes one 16-byte result, clears its expanded key/chaining/block storage, and does not retain global state. The C dispatcher must validate pointers and lengths before calling it. The YASM DF leaf may call only the internal YASM AES/BCC leaves and must clear all private temporary state before return.

The BCC and DF dispatchers select YASM only when all required symbols and AES-NI are present. Any missing symbol or unsupported CPU selects the C reference fallback. Test-only deterministic providers and fault hooks remain outside this boundary.

The ABI is subject to assembly review, CAVP vector equivalence, sanitizer/fault testing, and production symbol allowlist review before any Approved image integration. The current checkpoint has passed strict YASM assembly, C11 compilation, both 240-case NIST-style CTR_DRBG suites through the active dispatcher, AES-256 leaf KAT, ASan/UBSan execution, cppcheck, and zero-length intermediate snapshot equivalence.

## References

[1]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final "NIST SP 800-90A Rev. 1"

[2]: https://www.felixcloutier.com/x86/aeskeygenassist "Intel AESKEYGENASSIST reference"
