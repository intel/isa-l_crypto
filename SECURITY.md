# ISA-L Security Policy

## Report a Vulnerability

Please report security issues or vulnerabilities to the [Intel Security Center].

For more information on how Intel works to resolve security issues, see
[Vulnerability Handling Guidelines].

[Intel Security Center]:https://www.intel.com/security
[Vulnerability Handling Guidelines]:https://www.intel.com/content/www/us/en/security-center/vulnerability-handling-guidelines.html

## Security Considerations & Options for Increased Security

### Security Considerations
The security of a system that uses cryptography depends on the strength of
the cryptographic algorithms as well as the strength of the keys.
Cryptographic key strength is dependent on several factors, with some of the
most important factors including the length of the key, the entropy of the key
bits, and maintaining the secrecy of the key.

The selection of an appropriate algorithm and mode of operation critically
affects the security of a system. Appropriate selection criteria is beyond the
scope of this document and should be determined based upon usage, appropriate
standards and consultation with a cryptographic expert. This library includes some
algorithms, which are considered cryptographically weak and are included only
for legacy and interoperability reasons. See the "Recommendations" section for
more details.

Secure creation of key material is not a part of this library. This library
assumes that cryptographic keys have been created using approved methods with
an appropriate and secure entropy source. Users of this library are
referred to NIST SP800-133 Revision 1, Recommendation for Cryptographic Key
Generation, found at https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-133r1.pdf

Even with the use of strong cryptographic algorithms and robustly generated
keys, software implementations of cryptographic algorithms may be attacked
at the implementation through cache-timing attacks, buffer-over-reads, and
other software vulnerabilities. Counter-measures against these types of
attacks are possible but require additional processing cycles. Whether a
particular system should provide such counter-measures depends on the threats
to that system, and cannot be determined by a general library such as this
one. In order to provide the most flexible implementation, this library allows
certain counter-measures to be enabled or disabled at compile time. These
options are listed below as the "Options for Increased Security" and are
enabled through various build flags.

### Options for Increased Security

There are two build options that are used to increase safety in
the code and help protect external functions from incorrect input data.
The SAFE_DATA and SAFE_PARAM options are enabled by default.
Due to the potential performance impact associated to the extra code, these
can be disabled by setting the parameter equal to "n" (e.g. make -f Makefile.unx SAFE_PARAM=n).

No specific code has been added, and no specific validation or security
tests have been performed to help protect against or check for side-channel
attacks.

### SAFE_DATA

Stack and registers containing sensitive information, such as keys, are
cleared upon completion of a function call.

### SAFE_PARAM

Input parameters are checked, looking generally for NULL pointers or an incorrect input length.

### Galois Counter Mode (GCM) TAG Size

The library GCM implementation provides flexibility as to tag size selection.
As explained in [NIST Special Publication 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) section 5.2.1.2 and Appendix C, using tag sizes shorter than 96 bits can be insecure.
Please refer to the aforementioned sections to understand the details, trade offs and mitigations of using shorter tag sizes.
