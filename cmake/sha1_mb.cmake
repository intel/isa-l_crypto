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

# SHA1 Multi-Buffer module CMake configuration

set(SHA1_MB_BASE_SOURCES
    sha1_mb/sha1_mb.c
)

set(SHA1_MB_X86_64_SOURCES
    sha1_mb/sha1_ctx_sse.c
    sha1_mb/sha1_ctx_avx.c
    sha1_mb/sha1_ctx_avx2.c
    sha1_mb/sha1_ctx_base.c
    sha1_mb/sha1_mb_mgr_init_sse.c
    sha1_mb/sha1_mb_mgr_init_avx2.c
    sha1_mb/sha1_mb_mgr_submit_sse.asm
    sha1_mb/sha1_mb_mgr_submit_avx.asm
    sha1_mb/sha1_mb_mgr_submit_avx2.asm
    sha1_mb/sha1_mb_mgr_flush_sse.asm
    sha1_mb/sha1_mb_mgr_flush_avx.asm
    sha1_mb/sha1_mb_mgr_flush_avx2.asm
    sha1_mb/sha1_mb_x4_sse.asm
    sha1_mb/sha1_mb_x4_avx.asm
    sha1_mb/sha1_mb_x8_avx2.asm
    sha1_mb/sha1_multibinary.asm
    sha1_mb/sha1_ctx_avx512.c
    sha1_mb/sha1_mb_mgr_init_avx512.c
    sha1_mb/sha1_mb_mgr_submit_avx512.asm
    sha1_mb/sha1_mb_mgr_flush_avx512.asm
    sha1_mb/sha1_mb_x16_avx512.asm
    sha1_mb/sha1_opt_x1.asm
    sha1_mb/sha1_ni_x1.asm
    sha1_mb/sha1_ni_x2.asm
    sha1_mb/sha1_ctx_sse_ni.c
    sha1_mb/sha1_ctx_avx512_ni.c
    sha1_mb/sha1_mb_mgr_submit_sse_ni.asm
    sha1_mb/sha1_mb_mgr_flush_sse_ni.asm
    sha1_mb/sha1_mb_mgr_flush_avx512_ni.asm
)

set(SHA1_MB_AARCH64_SOURCES
    sha1_mb/sha1_ctx_base.c
    sha1_mb/sha1_ref.c
    sha1_mb/aarch64/sha1_mb_multibinary.S
    sha1_mb/aarch64/sha1_ctx_ce.c
    sha1_mb/aarch64/sha1_mb_x1_ce.S
    sha1_mb/aarch64/sha1_mb_x2_ce.S
    sha1_mb/aarch64/sha1_mb_mgr_ce.c
    sha1_mb/aarch64/sha1_ctx_asimd.c
    sha1_mb/aarch64/sha1_aarch64_x1.S
    sha1_mb/aarch64/sha1_mb_asimd_x4.S
    sha1_mb/aarch64/sha1_mb_mgr_asimd.c
    sha1_mb/aarch64/sha1_mb_aarch64_dispatcher.c
)

set(SHA1_MB_RISCV64_SOURCES
    sha1_mb/sha1_ctx_base_aliases.c
    sha1_mb/sha1_ctx_base.c
    sha1_mb/sha1_ref.c
)

set(SHA1_MB_BASE_ALIASES_SOURCES
    sha1_mb/sha1_ctx_base_aliases.c
    sha1_mb/sha1_ctx_base.c
    sha1_mb/sha1_ref.c
)

# Build source list based on architecture
set(SHA1_MB_SOURCES ${SHA1_MB_BASE_SOURCES})

if(CPU_X86_64)
    list(APPEND SHA1_MB_SOURCES ${SHA1_MB_X86_64_SOURCES})
elseif(CPU_AARCH64)
    list(APPEND SHA1_MB_SOURCES ${SHA1_MB_AARCH64_SOURCES})
elseif(CPU_RISCV64)
    list(APPEND SHA1_MB_SOURCES ${SHA1_MB_RISCV64_SOURCES})
elseif(CPU_UNDEFINED)
    list(APPEND SHA1_MB_SOURCES ${SHA1_MB_BASE_ALIASES_SOURCES})
endif()

# Headers exported by sha1_mb module
set(SHA1_MB_HEADERS
    include/sha1_mb.h
    include/multi_buffer.h
)

# Add to main extern headers list
list(APPEND EXTERN_HEADERS ${SHA1_MB_HEADERS})

# Test and performance applications
if(BUILD_TESTS OR BUILD_PERF)
    set(SHA1_MB_CHECK_TESTS
        sha1_mb/sha1_mb_test
        sha1_mb/sha1_mb_rand_test
        sha1_mb/sha1_mb_rand_update_test
        sha1_mb/sha1_mb_param_test
    )

    set(SHA1_MB_UNIT_TESTS
        sha1_mb/sha1_mb_rand_ssl_test
    )

    set(SHA1_MB_PERF_TESTS
        sha1_mb/sha1_mb_vs_ossl_perf
        sha1_mb/sha1_mb_vs_ossl_shortage_perf
    )

    if(BUILD_TESTS)
        foreach(test_name ${SHA1_MB_CHECK_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            # sha1_mb_rand_test, sha1_mb_rand_ssl_test, sha1_mb_rand_update_test need sha1_ref.c
            if(test_exec MATCHES "sha1_mb_rand.*test")
                add_executable(${test_exec} ${test_name}.c sha1_mb/sha1_ref.c)
            else()
                add_executable(${test_exec} ${test_name}.c)
            endif()
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            target_include_directories(${test_exec} PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/sha1_mb)
            add_test(NAME ${test_exec} COMMAND ${test_exec})
        endforeach()

        find_package(OpenSSL)
        foreach(test_name ${SHA1_MB_UNIT_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            # sha1_mb_rand_ssl_test needs sha1_ref.c
            add_executable(${test_exec} ${test_name}.c sha1_mb/sha1_ref.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            if(OPENSSL_FOUND)
                target_link_libraries(${test_exec} PRIVATE OpenSSL::Crypto)
            endif()
            target_include_directories(${test_exec} PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/sha1_mb)
            add_test(NAME ${test_exec} COMMAND ${test_exec})
        endforeach()
    endif()

    if(BUILD_PERF)
        find_package(OpenSSL)
        foreach(test_name ${SHA1_MB_PERF_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            add_executable(${test_exec} ${test_name}.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            if(OPENSSL_FOUND)
                target_link_libraries(${test_exec} PRIVATE OpenSSL::Crypto)
            endif()
            target_include_directories(${test_exec} PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/sha1_mb)
        endforeach()
    endif()
endif()

