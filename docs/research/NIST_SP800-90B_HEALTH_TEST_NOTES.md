# NIST SP 800-90B Health-Test Notes

The official NIST SP 800-90B material identifies the Repetition Count Test (RCT) and Adaptive Proportion Test (APT) as approved health tests for entropy sources. CMVP public-use documents describe continuous health testing as including RCT, APT, and, where applicable, a developer-defined stuck test. This repository uses those references to define an engineering boundary only; it does not claim entropy-source validation.

The candidate provider boundary must distinguish startup health tests from continuous health tests, map any health-test failure to a fail-closed module state, preserve output unchanged on failure, and retain evidence for the selected entropy source and operating environment. Thresholds and window sizes must be selected from the entropy-source assessment and must not be treated as universal defaults.

## References

[1]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90B.pdf "NIST SP 800-90B, Recommendation for the Entropy Sources Used for Random Bit Generation"

[2]: https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/cryptographic-algorithm-validation-program/Entropy-Validation-Testing.pdf "CMVP entropy validation testing materials"
