# cmake-format: off
# Copyright (c) 2025, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of Intel Corporation nor the names of its contributors
#       may be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# cmake-format: on
cmake_minimum_required(VERSION 3.12)
cmake_policy(VERSION 3.12)

project(ISA-L-Crypto
    VERSION 2.25.0
    DESCRIPTION "Intel's ISA-L Crypto (Intelligent Storage Acceleration Library - Cryptographic Functions)"
    LANGUAGES C ASM
)

# Enable appropriate assembler based on architecture
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
    enable_language(ASM_NASM)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    # ARM uses GAS assembler (.S files)
    enable_language(ASM)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "riscv64")
    # RISC-V uses GAS assembler (.S files)
    enable_language(ASM)
endif()

# Set default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Detect processor architecture
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
    set(CPU_X86_64 ON)
    set(ARCH_DEF "x86_64")
    message(STATUS "Building for x86_64 architecture")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
    set(CPU_AARCH64 ON)
    set(ARCH_DEF "aarch64")
    message(STATUS "Building for aarch64 architecture")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "riscv64")
    set(CPU_RISCV64 ON)
    set(ARCH_DEF "riscv64")
    message(STATUS "Building for riscv64 architecture")
else()
    set(CPU_UNDEFINED ON)
    message(STATUS "Building for undefined/generic architecture")
endif()

# Options
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_TESTS "Build test applications" ON)
option(BUILD_PERF "Build performance applications" ON)
option(SAFE_DATA "Clear memory of sensitive data" ON)
option(SAFE_PARAM "Enable parameter checking" ON)
option(FIPS_MODE "Enable FIPS mode" OFF)

# Compiler and assembler setup
if(CPU_X86_64)
    # Configure NASM flags
    if(WIN32)
        set(CMAKE_ASM_NASM_FLAGS "-f win64 -D WINDOWS")
    else()
        set(CMAKE_ASM_NASM_FLAGS "-f elf64 -D LINUX")
    endif()
    set(USE_NASM ON)
elseif(CPU_AARCH64 OR CPU_RISCV64)
    # Configure ASM for ARM and RISC-V (uses GAS with .S files)
    set(CMAKE_ASM_FLAGS "${CMAKE_C_FLAGS} -D__ASSEMBLY__")
endif()

# Set include directories
set(ISAL_CRYPTO_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Initialize EXTERN_HEADERS list
set(EXTERN_HEADERS)

# Compiler flags
if(ARCH_DEF)
    add_compile_definitions(${ARCH_DEF})
endif()

# Add common compiler flags
if(NOT MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wchar-subscripts -Wformat-security -Wnested-externs -Wpointer-arith -Wshadow -Wstrict-prototypes -Wtype-limits")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector -D_FORTIFY_SOURCE=2")

    # Position independent code for shared libraries
    if(BUILD_SHARED_LIBS)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
    endif()
endif()

# Add NO_COMPAT_ISAL_CRYPTO_API_2_24 define
add_compile_definitions(NO_COMPAT_ISAL_CRYPTO_API_2_24)

# Optional features
if(SAFE_DATA)
    add_compile_definitions(SAFE_DATA)
    if(USE_NASM)
        set(CMAKE_ASM_NASM_FLAGS "${CMAKE_ASM_NASM_FLAGS} -DSAFE_DATA")
    endif()
endif()

if(SAFE_PARAM)
    add_compile_definitions(SAFE_PARAM)
    if(USE_NASM)
        set(CMAKE_ASM_NASM_FLAGS "${CMAKE_ASM_NASM_FLAGS} -DSAFE_PARAM")
    endif()
endif()

if(FIPS_MODE)
    add_compile_definitions(FIPS_MODE)
    if(USE_NASM)
        set(CMAKE_ASM_NASM_FLAGS "${CMAKE_ASM_NASM_FLAGS} -DFIPS_MODE")
    endif()
endif()

# Library version (semantic versioning)
set(LIBISAL_CRYPTO_CURRENT 2)
set(LIBISAL_CRYPTO_REVISION 25)
set(LIBISAL_CRYPTO_AGE 0)

# Include CMake modules for each library component
include(cmake/md5_mb.cmake)
include(cmake/sha1_mb.cmake)
include(cmake/sha256_mb.cmake)
include(cmake/sha512_mb.cmake)
include(cmake/sm3_mb.cmake)
include(cmake/mh_sha1.cmake)
include(cmake/mh_sha256.cmake)
include(cmake/mh_sha1_murmur3_x64_128.cmake)
include(cmake/rolling_hash.cmake)
include(cmake/misc.cmake)

# Include AES only for x86 and aarch64
if(CPU_X86_64 OR CPU_AARCH64)
    include(cmake/aes.cmake)
endif()

include(cmake/fips.cmake)

# Add common headers (only public API headers)
list(APPEND EXTERN_HEADERS include/isa-l_crypto/types.h)

# Windows .def file for symbol exports (only needed on Windows)
if(WIN32)
    set(ISAL_CRYPTO_DEF_FILE ${CMAKE_CURRENT_SOURCE_DIR}/isa-l_crypto.def)
endif()

# Create the main ISA-L Crypto library
if(WIN32)
    add_library(isal_crypto
        ${MD5_MB_SOURCES}
        ${SHA1_MB_SOURCES}
        ${SHA256_MB_SOURCES}
        ${SHA512_MB_SOURCES}
        ${SM3_MB_SOURCES}
        ${MH_SHA1_SOURCES}
        ${MH_SHA256_SOURCES}
        ${MH_SHA1_MURMUR3_SOURCES}
        ${ROLLING_HASH_SOURCES}
        ${MISC_SOURCES}
        ${AES_SOURCES}
        ${FIPS_SOURCES}
        ${ISAL_CRYPTO_DEF_FILE}
    )
else()
    add_library(isal_crypto
        ${MD5_MB_SOURCES}
        ${SHA1_MB_SOURCES}
        ${SHA256_MB_SOURCES}
        ${SHA512_MB_SOURCES}
        ${SM3_MB_SOURCES}
        ${MH_SHA1_SOURCES}
        ${MH_SHA256_SOURCES}
        ${MH_SHA1_MURMUR3_SOURCES}
        ${ROLLING_HASH_SOURCES}
        ${MISC_SOURCES}
        ${AES_SOURCES}
        ${FIPS_SOURCES}
    )
endif()

# Set library properties
set_target_properties(isal_crypto PROPERTIES
    VERSION ${LIBISAL_CRYPTO_CURRENT}.${LIBISAL_CRYPTO_REVISION}.${LIBISAL_CRYPTO_AGE}
    SOVERSION ${LIBISAL_CRYPTO_CURRENT}
    PUBLIC_HEADER "${EXTERN_HEADERS}"
)

# Configure include directories for NASM assembly files
if(USE_NASM)
    # Get all source files
    get_target_property(ALL_SOURCES isal_crypto SOURCES)

    # Filter and configure assembly files
    foreach(source IN LISTS ALL_SOURCES)
        if(source MATCHES "\\.asm$")
            get_filename_component(source_dir ${source} DIRECTORY)
            set_source_files_properties(${source} PROPERTIES
                INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR};${CMAKE_CURRENT_SOURCE_DIR}/${source_dir}")
        endif()
    endforeach()
endif()

# Include directories
target_include_directories(isal_crypto
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include/isa-l_crypto
        ${CMAKE_CURRENT_SOURCE_DIR}/internal
        ${CMAKE_CURRENT_SOURCE_DIR}/aes
        ${CMAKE_CURRENT_SOURCE_DIR}/intel-ipsec-mb/lib
        ${CMAKE_CURRENT_SOURCE_DIR}/md5_mb
        ${CMAKE_CURRENT_SOURCE_DIR}/sha1_mb
        ${CMAKE_CURRENT_SOURCE_DIR}/sha256_mb
        ${CMAKE_CURRENT_SOURCE_DIR}/sha512_mb
        ${CMAKE_CURRENT_SOURCE_DIR}/sm3_mb
        ${CMAKE_CURRENT_SOURCE_DIR}/mh_sha1
        ${CMAKE_CURRENT_SOURCE_DIR}/mh_sha256
        ${CMAKE_CURRENT_SOURCE_DIR}/mh_sha1_murmur3_x64_128
        ${CMAKE_CURRENT_SOURCE_DIR}/rolling_hash
)

# Generate isa-l_crypto.h header
set(ISAL_CRYPTO_HEADER "${CMAKE_BINARY_DIR}/isa-l_crypto.h")
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/isa-l_crypto.h.in ${ISAL_CRYPTO_HEADER} @ONLY)

# Install targets
include(GNUInstallDirs)

# Install library
install(TARGETS isal_crypto
    EXPORT ISALCryptoTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/isa-l_crypto
)

# Install generated header
install(FILES ${ISAL_CRYPTO_HEADER}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Install headers
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

# Export targets
install(EXPORT ISALCryptoTargets
    FILE ISALCryptoTargets.cmake
    NAMESPACE ISALCrypto::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ISALCrypto
)

# Generate and install package config files
include(CMakePackageConfigHelpers)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ISALCryptoConfig.cmake.in"
    "${CMAKE_BINARY_DIR}/ISALCryptoConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ISALCrypto
)

write_basic_package_version_file(
    "${CMAKE_BINARY_DIR}/ISALCryptoConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_BINARY_DIR}/ISALCryptoConfig.cmake"
    "${CMAKE_BINARY_DIR}/ISALCryptoConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ISALCrypto
)

# Optional: Create pkg-config file
set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix \${prefix})
set(libdir \${prefix}/${CMAKE_INSTALL_LIBDIR})
set(includedir \${prefix}/${CMAKE_INSTALL_INCLUDEDIR})
set(VERSION ${PROJECT_VERSION})

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/libisal_crypto.pc.in"
    "${CMAKE_BINARY_DIR}/libisal_crypto.pc"
    @ONLY
)

install(FILES "${CMAKE_BINARY_DIR}/libisal_crypto.pc"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# Enable testing if BUILD_TESTS is ON
if(BUILD_TESTS)
    enable_testing()
    include(CTest)
endif()

# Print configuration summary
message(STATUS "")
message(STATUS "ISA-L Crypto Configuration Summary:")
message(STATUS "  Version:              ${PROJECT_VERSION}")
message(STATUS "  Build type:           ${CMAKE_BUILD_TYPE}")
message(STATUS "  Architecture:         ${ARCH_DEF}")
message(STATUS "  Shared libraries:     ${BUILD_SHARED_LIBS}")
message(STATUS "  Build tests:          ${BUILD_TESTS}")
message(STATUS "  Build perf apps:      ${BUILD_PERF}")
message(STATUS "  Safe data:            ${SAFE_DATA}")
message(STATUS "  Safe param:           ${SAFE_PARAM}")
message(STATUS "  FIPS mode:            ${FIPS_MODE}")
message(STATUS "  Install prefix:       ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
