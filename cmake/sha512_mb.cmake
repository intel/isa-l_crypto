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

# SHA512 Multi-Buffer module CMake configuration

set(SHA512_MB_BASE_SOURCES
    sha512_mb/sha512_mb.c
)

set(SHA512_MB_X86_64_SOURCES
    sha512_mb/sha512_ctx_sse.c
    sha512_mb/sha512_ctx_avx.c
    sha512_mb/sha512_ctx_avx2.c
    sha512_mb/sha512_ctx_avx2_ni.c
    sha512_mb/sha512_ctx_base.c
    sha512_mb/sha512_mb_mgr_init_sse.c
    sha512_mb/sha512_mb_mgr_init_avx2.c
    sha512_mb/sha512_sb_mgr_init_sse4.c
    sha512_mb/sha512_mb_mgr_submit_sse.asm
    sha512_mb/sha512_mb_mgr_submit_avx.asm
    sha512_mb/sha512_mb_mgr_submit_avx2.asm
    sha512_mb/sha512_mb_mgr_flush_sse.asm
    sha512_mb/sha512_mb_mgr_flush_avx.asm
    sha512_mb/sha512_mb_mgr_flush_avx2.asm
    sha512_mb/sha512_mb_mgr_submit_ni_avx2.asm
    sha512_mb/sha512_mb_mgr_flush_ni_avx2.asm
    sha512_mb/sha512_x2_ni_avx2.asm
    sha512_mb/sha512_mb_x2_sse.asm
    sha512_mb/sha512_mb_x2_avx.asm
    sha512_mb/sha512_mb_x4_avx2.asm
    sha512_mb/sha512_multibinary.asm
    sha512_mb/sha512_sb_mgr_submit_sse4.c
    sha512_mb/sha512_sb_mgr_flush_sse4.c
    sha512_mb/sha512_sse4.asm
    sha512_mb/sha512_ctx_avx512.c
    sha512_mb/sha512_mb_mgr_init_avx512.c
    sha512_mb/sha512_mb_mgr_submit_avx512.asm
    sha512_mb/sha512_mb_mgr_flush_avx512.asm
    sha512_mb/sha512_mb_x8_avx512.asm
)

set(SHA512_MB_AARCH64_SOURCES
    sha512_mb/sha512_ctx_base.c
    sha512_mb/aarch64/sha512_mb_multibinary.S
    sha512_mb/aarch64/sha512_mb_aarch64_dispatcher.c
    sha512_mb/aarch64/sha512_ctx_ce.c
    sha512_mb/aarch64/sha512_mb_mgr_ce.c
    sha512_mb/aarch64/sha512_mb_x1_ce.S
    sha512_mb/aarch64/sha512_mb_x2_ce.S
)

set(SHA512_MB_RISCV64_SOURCES
    sha512_mb/sha512_ctx_base.c
    sha512_mb/sha512_ctx_base_aliases.c
)

set(SHA512_MB_BASE_ALIASES_SOURCES
    sha512_mb/sha512_ctx_base.c
    sha512_mb/sha512_ctx_base_aliases.c
)

# Build source list based on architecture
set(SHA512_MB_SOURCES ${SHA512_MB_BASE_SOURCES})

if(CPU_X86_64)
    list(APPEND SHA512_MB_SOURCES ${SHA512_MB_X86_64_SOURCES})
elseif(CPU_AARCH64)
    list(APPEND SHA512_MB_SOURCES ${SHA512_MB_AARCH64_SOURCES})
elseif(CPU_RISCV64)
    list(APPEND SHA512_MB_SOURCES ${SHA512_MB_RISCV64_SOURCES})
elseif(CPU_UNDEFINED)
    list(APPEND SHA512_MB_SOURCES ${SHA512_MB_BASE_ALIASES_SOURCES})
endif()

# Headers exported by sha512_mb module
set(SHA512_MB_HEADERS
    include/sha512_mb.h
    include/multi_buffer.h
)

# Add to main extern headers list
list(APPEND EXTERN_HEADERS ${SHA512_MB_HEADERS})

# Test and performance applications
if(BUILD_TESTS OR BUILD_PERF)
    set(SHA512_MB_CHECK_TESTS
        sha512_mb/sha512_mb_test
        sha512_mb/sha512_mb_rand_test
        sha512_mb/sha512_mb_rand_update_test
        sha512_mb/sha512_mb_param_test
    )

    set(SHA512_MB_UNIT_TESTS
        sha512_mb/sha512_mb_rand_ssl_test
    )

    set(SHA512_MB_PERF_TESTS
        sha512_mb/sha512_mb_vs_ossl_perf
    )

    if(BUILD_TESTS)
        foreach(test_name ${SHA512_MB_CHECK_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            # sha512_mb_rand_test, sha512_mb_rand_ssl_test, sha512_mb_rand_update_test need sha512_ref.c
            if(test_exec MATCHES "sha512_mb_rand.*test")
                add_executable(${test_exec} ${test_name}.c sha512_mb/sha512_ref.c)
            else()
                add_executable(${test_exec} ${test_name}.c)
            endif()
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            target_include_directories(${test_exec} PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/sha512_mb)
            add_test(NAME ${test_exec} COMMAND ${test_exec})
        endforeach()

        find_package(OpenSSL)
        foreach(test_name ${SHA512_MB_UNIT_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            # sha512_mb_rand_ssl_test needs sha512_ref.c
            add_executable(${test_exec} ${test_name}.c sha512_mb/sha512_ref.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            if(OPENSSL_FOUND)
                target_link_libraries(${test_exec} PRIVATE OpenSSL::Crypto)
            endif()
            target_include_directories(${test_exec} PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/sha512_mb)
            add_test(NAME ${test_exec} COMMAND ${test_exec})
        endforeach()
    endif()

    if(BUILD_PERF)
        find_package(OpenSSL)
        foreach(test_name ${SHA512_MB_PERF_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            add_executable(${test_exec} ${test_name}.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            if(OPENSSL_FOUND)
                target_link_libraries(${test_exec} PRIVATE OpenSSL::Crypto)
            endif()
            target_include_directories(${test_exec} PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/sha512_mb)
        endforeach()
    endif()
endif()

