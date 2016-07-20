================================================================
Intel(R) Intelligent Storage Acceleration Library Crypto Version
================================================================

ISA-L_crypto is a collection of optimized low-level functions targeting storage
applications.  ISA-L_crypto includes:

* Multi-buffer hashes - run multiple hash jobs together on one core for much
  better throughput than single-buffer versions.
  - SHA1, SHA256, SHA512, MD5

* Multi-hash - Get the performance of multi-buffer hashing with a single-buffer
  interface.

* Multi-hash + murmur - run both together.

* AES - block ciphers
  - XTS, GCM, CBC

See [ISA-L_crypto for updates.](https://github.com/01org/isa-l_crypto)
For non-crypto ISA-L see [isa-l on github.](https://github.com/01org/isa-l)

Build Prerequisites
===================

ISA-L requires yasm version 1.2.0 or later or nasm v2.11.01 or later.  Building
with autotools requires autoconf/automake packages.

Building ISA-L
==============

Autotools
---------

To build and install the library with autotools it is usually sufficient to run
the following:

    ./autogen.sh
    ./configure
    make
    sudo make install

Other targets include: make check, make tests, make perfs, make ex (examples)
and make other.

Windows
-------

On Windows use nmake to build dll and static lib:

    nmake -f Makefile.nmake

Other targets include: nmake check.
