# Track B Operational Environment Manifest

**Captured:** 2026-08-25

**Status:** Engineering snapshot; not a frozen FIPS operational-environment claim.

```text
Linux db71298c03d4 6.18.38+ #1 SMP PREEMPT_DYNAMIC Thu Aug  6 06:48:14 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
arch: x86_64
gcc: gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
yasm: yasm 1.3.0
ld: GNU ld (GNU Binutils for Ubuntu) 2.42
make: GNU Make 4.3
python: Python 3.12.3
cpu aes flag: present
kernel random interface: glibc 2.39
```

The snapshot records the environment used for current engineering builds and tests. It does not freeze a FIPS operational environment because the exact distribution image identity, kernel support range, compiler/linker/YASM packaging, CPU feature policy, ELF/link model, installation procedure, and change-control policy still require project-owner and CSTL approval.

The AES-NI capability is present on this host, so C11-only fallback testing is performed separately by building without the YASM object. A validation submission must state whether the AES-NI and non-AES-NI paths are both in scope or whether one is excluded.

## References

[1]: https://csrc.nist.gov/pubs/fips/140-3/final "NIST FIPS 140-3"

[2]: https://csrc.nist.gov/pubs/sp/800/140/final "NIST SP 800-140"
