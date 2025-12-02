# CMake Build System for ISA-L Crypto

This directory contains the CMake build system for ISA-L Crypto library.

## Features

- Cross-platform support (Linux and Windows)
- Architecture detection (x86_64, aarch64, riscv64)
- Shared and static library builds
- NASM assembly support for x86 architectures
- Configurable security features (SAFE_DATA, SAFE_PARAM, FIPS_MODE)
- Package configuration files for easy integration

## Prerequisites

### Linux/Unix

- CMake 3.12 or later
- C compiler (GCC, Clang, or Intel C Compiler)
- NASM assembler (v2.14.01 or later) for x86_64 builds
- Make or Ninja build system

### Windows

- CMake 3.12 or later
- Visual Studio 2019 or later (or compatible C compiler)
- NASM assembler for x86_64 builds

## Building

### Basic Build

```bash
mkdir build
cd build
cmake ..
make -j8
```

### Build Options

- `BUILD_SHARED_LIBS`: Build shared library (default: ON)
  ```bash
  cmake .. -DBUILD_SHARED_LIBS=OFF  # Build static library
  ```

- `SAFE_DATA`: Clear memory of sensitive data (default: ON)
  ```bash
  cmake .. -DSAFE_DATA=OFF
  ```

- `SAFE_PARAM`: Enable parameter checking (default: ON)
  ```bash
  cmake .. -DSAFE_PARAM=OFF
  ```

- `FIPS_MODE`: Enable FIPS mode (default: OFF)
  ```bash
  cmake .. -DFIPS_MODE=ON
  ```

- `CMAKE_BUILD_TYPE`: Build type (default: Release)
  ```bash
  cmake .. -DCMAKE_BUILD_TYPE=Debug
  ```

- `CMAKE_INSTALL_PREFIX`: Installation prefix (default: /usr/local)
  ```bash
  cmake .. -DCMAKE_INSTALL_PREFIX=/opt/isal-crypto
  ```

### Installation

```bash
sudo make install
```

This will install:
- Library files to `${CMAKE_INSTALL_PREFIX}/lib`
- Header files to `${CMAKE_INSTALL_PREFIX}/include/isa-l_crypto`
- CMake package files to `${CMAKE_INSTALL_PREFIX}/lib/cmake/ISALCrypto`
- pkg-config file to `${CMAKE_INSTALL_PREFIX}/lib/pkgconfig`

## Using ISA-L Crypto in Your Project

### With CMake

```cmake
find_package(ISALCrypto REQUIRED)
target_link_libraries(your_target PRIVATE ISALCrypto::isal_crypto)
```

### With pkg-config

```bash
pkg-config --cflags --libs libisal_crypto
```

## Module Organization

The CMake build system is organized into modules, each defined in `cmake/*.cmake`:

- `md5_mb.cmake` - MD5 multi-buffer hashing
- `sha1_mb.cmake` - SHA1 multi-buffer hashing
- `sha256_mb.cmake` - SHA256 multi-buffer hashing
- `sha512_mb.cmake` - SHA512 multi-buffer hashing
- `sm3_mb.cmake` - SM3 multi-buffer hashing
- `mh_sha1.cmake` - Multi-hash SHA1
- `mh_sha256.cmake` - Multi-hash SHA256
- `mh_sha1_murmur3_x64_128.cmake` - Multi-hash SHA1 with Murmur3
- `rolling_hash.cmake` - Rolling hash functions
- `aes.cmake` - AES encryption/decryption (GCM, CBC, XTS)
- `fips.cmake` - FIPS self-tests
- `misc.cmake` - Miscellaneous utilities

## Architecture Support

The build system automatically detects the target architecture and builds
the appropriate optimized code:

- **x86_64**: Uses NASM-compiled assembly with SSE, AVX, AVX2, AVX512 optimizations
- **aarch64**: Uses GAS-compiled assembly with NEON, SVE optimizations
- **riscv64**: Uses portable C implementations
- **Other**: Falls back to portable base implementations

## Troubleshooting

### NASM not found

If NASM is not in your PATH, you can specify its location:
```bash
cmake .. -DCMAKE_ASM_NASM_COMPILER=/path/to/nasm
```

### Build failures

For verbose build output:
```bash
make VERBOSE=1
```

## Known Limitations

This CMake build system currently focuses on:
- x86 architecture support (x86_64)

Support for other architectures (aarch64, riscv64) is included but not extensively tested.

## Contributing

When adding new source files to the library, update the appropriate module
file in the `cmake/` directory to include the new sources.

## License

Same as ISA-L Crypto library - see LICENSE file in the root directory.
