Intel(R) Intelligent Storage Acceleration Library Crypto Version
================================================================

![Continuous Integration](https://github.com/intel/isa-l_crypto/actions/workflows/ci.yml/badge.svg)
[![Coverity Status](https://scan.coverity.com/projects/29481/badge.svg)](https://scan.coverity.com/projects/intel-isa-l-crypto)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/intel/isa-l_crypto/badge)](https://securityscorecards.dev/viewer/?uri=github.com/intel/isa-l_crypto)

ISA-L_crypto is a collection of optimized low-level functions targeting storage
applications.  ISA-L_crypto includes:

* Multi-buffer hashes - run multiple hash jobs together on one core for much
  better throughput than single-buffer versions.
  - SHA1, SHA256, SHA512, MD5, SM3

* Multi-hash - Get the performance of multi-buffer hashing with a single-buffer
  interface. Specification ref : [Multi-Hash white paper](https://raw.githubusercontent.com/wiki/intel/isa-l_crypto/pdf/multi-hash-paper.pdf)

* Multi-hash + murmur - run both together.

* AES - block ciphers
  - XTS, GCM, CBC

* Rolling hash - Hash input in a window which moves through the input

Also see:
* [ISA-L_crypto for updates](https://github.com/intel/isa-l_crypto).
* For non-crypto ISA-L see [isa-l on github](https://github.com/intel/isa-l).
* The [github wiki](https://github.com/intel/isa-l/wiki) covering isa-l and
  isa-l crypto.
* [Contributing](CONTRIBUTING.md).
* [Security Policy](SECURITY.md).
* [FIPS Mode](FIPS.md).

Building ISA-L
--------------

### Prerequisites

x86_64:
* Assembler: nasm v2.14.01 or later
* Compiler: gcc, clang, icc or VC compiler.
* Make: GNU 'make' or 'nmake' (Windows).
* Optional: Building with autotools requires autoconf/automake packages.

aarch64:
* Assembler: gas v2.34 or later.
* Compiler: gcc v8 or later.
* For gas v2.24~v2.34, sve2 instructions are not supported. To workaround it, sve2 optimization should be disabled by
    * ./configure --disable-sve2
    * make -f Makefile.unx DEFINES+=-DNO_SVE2=1

### Autotools
To build and install the library with autotools it is usually sufficient to run:

    ./autogen.sh
    ./configure
    make
    sudo make install

### Makefile
To use a standard makefile run:

    make -f Makefile.unx

### Windows
On Windows use nmake to build dll and static lib:

    nmake -f Makefile.nmake

### Other make targets
Other targets include:
* `make check` : create and run tests
* `make tests` : create additional unit tests
* `make perfs` : create included performance tests
* `make ex`    : build examples
* `make doc`   : build API manual

Algorithm recommendations
-------------------------

Legacy or to be avoided algorithms listed in the table below are implemented
in the library in order to support legacy applications. Please use corresponding
alternative algorithms instead.
```
+----------------------------------------------------+
| # | Algorithm      | Recommendation | Alternative  |
|---+----------------+----------------+--------------|
| 1 | MD5 integrity  | Legacy         | SHA256       |
|---+----------------+----------------+--------------|
| 2 | SHA1 integrity | Avoid          | SHA256       |
+----------------------------------------------------+
```
Intel(R) Intelligent Storage Acceleration for Crypto Library depends on C library and
it is recommended to use its latest version.

Applications using the Intel(R) Intelligent Storage Acceleration for Crypto Library rely on
Operating System to provide process isolation.
As the result, it is recommended to use latest Operating System patches and
security updates.

DLL Injection Attack
--------------------

### Problem

The Windows OS has an insecure predefined search order and set of defaults when trying to locate a resource. If the resource location is not specified by the software, an attacker need only place a malicious version in one of the locations Windows will search, and it will be loaded instead. Although this weakness can occur with any resource, it is especially common with DLL files.

### Solutions

Applications using libisal_crypto DLL library may need to apply one of the solutions to prevent from DLL injection attack.

Two solutions are available:
- Using a Fully Qualified Path is the most secure way to load a DLL
- Signature verification of the DLL

### Resources and Solution Details

- Security remarks section of LoadLibraryEx documentation by Microsoft: <https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa#security-remarks>
- Microsoft Dynamic Link Library Security article: <https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-security>
- Hijack Execution Flow: DLL Search Order Hijacking: <https://attack.mitre.org/techniques/T1574/001>
- Hijack Execution Flow: DLL Side-Loading: <https://attack.mitre.org/techniques/T1574/002>
