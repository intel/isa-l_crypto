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

# MD5 Multi-Buffer module CMake configuration

set(MD5_MB_BASE_SOURCES
    md5_mb/md5_mb.c
)

set(MD5_MB_X86_64_SOURCES
    md5_mb/md5_ctx_sse.c
    md5_mb/md5_ctx_avx.c
    md5_mb/md5_ctx_avx2.c
    md5_mb/md5_ctx_base.c
    md5_mb/md5_mb_mgr_init_sse.c
    md5_mb/md5_mb_mgr_init_avx2.c
    md5_mb/md5_mb_mgr_init_avx512.c
    md5_mb/md5_mb_mgr_submit_sse.asm
    md5_mb/md5_mb_mgr_submit_avx.asm
    md5_mb/md5_mb_mgr_submit_avx2.asm
    md5_mb/md5_mb_mgr_flush_sse.asm
    md5_mb/md5_mb_mgr_flush_avx.asm
    md5_mb/md5_mb_mgr_flush_avx2.asm
    md5_mb/md5_mb_x4x2_sse.asm
    md5_mb/md5_mb_x4x2_avx.asm
    md5_mb/md5_mb_x8x2_avx2.asm
    md5_mb/md5_multibinary.asm
    md5_mb/md5_mb_mgr_submit_avx512.asm
    md5_mb/md5_mb_mgr_flush_avx512.asm
    md5_mb/md5_mb_x16x2_avx512.asm
    md5_mb/md5_ctx_avx512.c
)

set(MD5_MB_AARCH64_SOURCES
    md5_mb/md5_ctx_base.c
    md5_mb/aarch64/md5_ctx_aarch64_asimd.c
    md5_mb/aarch64/md5_mb_aarch64_dispatcher.c
    md5_mb/aarch64/md5_mb_mgr_aarch64_asimd.c
    md5_mb/aarch64/md5_mb_asimd_x4.S
    md5_mb/aarch64/md5_mb_asimd_x1.S
    md5_mb/aarch64/md5_ctx_aarch64_sve.c
    md5_mb/aarch64/md5_mb_mgr_aarch64_sve.c
    md5_mb/aarch64/md5_ctx_aarch64_sve2.c
    md5_mb/aarch64/md5_mb_mgr_aarch64_sve2.c
    md5_mb/aarch64/md5_mb_sve.S
    md5_mb/aarch64/md5_mb_multibinary.S
)

set(MD5_MB_RISCV64_SOURCES
    md5_mb/md5_ctx_base.c
    md5_mb/md5_ctx_base_aliases.c
)

set(MD5_MB_BASE_ALIASES_SOURCES
    md5_mb/md5_ctx_base.c
    md5_mb/md5_ctx_base_aliases.c
)

# Build source list based on architecture
set(MD5_MB_SOURCES ${MD5_MB_BASE_SOURCES})

if(CPU_X86_64)
    list(APPEND MD5_MB_SOURCES ${MD5_MB_X86_64_SOURCES})
elseif(CPU_AARCH64)
    list(APPEND MD5_MB_SOURCES ${MD5_MB_AARCH64_SOURCES})
elseif(CPU_RISCV64)
    list(APPEND MD5_MB_SOURCES ${MD5_MB_RISCV64_SOURCES})
elseif(CPU_UNDEFINED)
    list(APPEND MD5_MB_SOURCES ${MD5_MB_BASE_ALIASES_SOURCES})
endif()

# Headers exported by md5_mb module
set(MD5_MB_HEADERS
    include/isa-l_crypto/md5_mb.h
    include/isa-l_crypto/multi_buffer.h
)

# Add to main extern headers list
list(APPEND EXTERN_HEADERS ${MD5_MB_HEADERS})

# Test and performance applications
if(BUILD_TESTS OR BUILD_PERF)
    set(MD5_MB_CHECK_TESTS
        md5_mb/md5_mb_test
        md5_mb/md5_mb_rand_test
        md5_mb/md5_mb_rand_update_test
        md5_mb/md5_mb_param_test
    )

    set(MD5_MB_UNIT_TESTS
        md5_mb/md5_mb_rand_ssl_test
    )

    set(MD5_MB_PERF_TESTS
        md5_mb/md5_mb_vs_ossl_perf
    )

    if(BUILD_TESTS)
        foreach(test_name ${MD5_MB_CHECK_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            # md5_mb_rand_test and md5_mb_rand_update_test need md5_ref.c
            if(test_exec MATCHES "md5_mb_rand.*test")
                add_executable(${test_exec} ${test_name}.c md5_mb/md5_ref.c)
            else()
                add_executable(${test_exec} ${test_name}.c)
            endif()
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            target_include_directories(${test_exec} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/isa-l_crypto ${CMAKE_CURRENT_SOURCE_DIR}/include/internal ${CMAKE_CURRENT_SOURCE_DIR}/md5_mb)
            add_test(NAME ${test_exec} COMMAND ${test_exec})
        endforeach()

        find_package(OpenSSL)
        foreach(test_name ${MD5_MB_UNIT_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            add_executable(${test_exec} ${test_name}.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            if(OPENSSL_FOUND)
                target_link_libraries(${test_exec} PRIVATE OpenSSL::Crypto)
            endif()
            target_include_directories(${test_exec} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/isa-l_crypto ${CMAKE_CURRENT_SOURCE_DIR}/include/internal ${CMAKE_CURRENT_SOURCE_DIR}/md5_mb)
        endforeach()
    endif()

    if(BUILD_PERF)
        find_package(OpenSSL)
        foreach(test_name ${MD5_MB_PERF_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            add_executable(${test_exec} ${test_name}.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            if(OPENSSL_FOUND)
                target_link_libraries(${test_exec} PRIVATE OpenSSL::Crypto)
            endif()
            target_include_directories(${test_exec} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/isa-l_crypto ${CMAKE_CURRENT_SOURCE_DIR}/include/internal ${CMAKE_CURRENT_SOURCE_DIR}/md5_mb)
        endforeach()
    endif()
endif()

