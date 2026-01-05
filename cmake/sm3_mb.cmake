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

# SM3 Multi-Buffer module CMake configuration

set(SM3_MB_BASE_SOURCES
    sm3_mb/sm3_mb.c
)

set(SM3_MB_X86_64_SOURCES
    sm3_mb/sm3_ctx_base.c
    sm3_mb/sm3_multibinary.asm
    sm3_mb/sm3_ctx_avx512.c
    sm3_mb/sm3_mb_mgr_submit_avx512.asm
    sm3_mb/sm3_mb_mgr_flush_avx512.asm
    sm3_mb/sm3_mb_x16_avx512.asm
    sm3_mb/sm3_ctx_avx2.c
    sm3_mb/sm3_mb_mgr_submit_avx2.asm
    sm3_mb/sm3_mb_mgr_flush_avx2.asm
    sm3_mb/sm3_mb_x8_avx2.asm
    sm3_mb/sm3_ctx_avx2_ni.c
    sm3_mb/sm3_mb_mgr_submit_avx2_ni.asm
    sm3_mb/sm3_mb_mgr_flush_avx2_ni.asm
    sm3_mb/sm3_mb_x1_avx2_ni.asm
)

set(SM3_MB_AARCH64_SOURCES
    sm3_mb/sm3_ctx_base.c
    sm3_mb/aarch64/sm3_mb_aarch64_dispatcher.c
    sm3_mb/aarch64/sm3_mb_multibinary_aarch64.S
    sm3_mb/aarch64/sm3_mb_mgr_sm_aarch64.c
    sm3_mb/aarch64/sm3_mb_ctx_sm_aarch64.c
    sm3_mb/aarch64/sm3_mb_sm_x1.S
    sm3_mb/aarch64/sm3_mb_sm_x2.S
    sm3_mb/aarch64/sm3_mb_sm_x3.S
    sm3_mb/aarch64/sm3_mb_sm_x4.S
    sm3_mb/aarch64/sm3_mb_mgr_sve.c
    sm3_mb/aarch64/sm3_mb_ctx_sve.c
    sm3_mb/aarch64/sm3_mb_mgr_sve2.c
    sm3_mb/aarch64/sm3_mb_ctx_sve2.c
    sm3_mb/aarch64/sm3_mb_sve.S
    sm3_mb/aarch64/sm3_mb_mgr_asimd_aarch64.c
    sm3_mb/aarch64/sm3_mb_ctx_asimd_aarch64.c
    sm3_mb/aarch64/sm3_mb_asimd_x1.S
    sm3_mb/aarch64/sm3_mb_asimd_x4.S
)

set(SM3_MB_RISCV64_SOURCES
    sm3_mb/sm3_ctx_base.c
    sm3_mb/sm3_ctx_base_aliases.c
)

set(SM3_MB_BASE_ALIASES_SOURCES
    sm3_mb/sm3_ctx_base.c
    sm3_mb/sm3_ctx_base_aliases.c
)

# Build source list based on architecture
set(SM3_MB_SOURCES ${SM3_MB_BASE_SOURCES})

if(CPU_X86_64)
    list(APPEND SM3_MB_SOURCES ${SM3_MB_X86_64_SOURCES})
elseif(CPU_AARCH64)
    list(APPEND SM3_MB_SOURCES ${SM3_MB_AARCH64_SOURCES})
elseif(CPU_RISCV64)
    list(APPEND SM3_MB_SOURCES ${SM3_MB_RISCV64_SOURCES})
elseif(CPU_UNDEFINED)
    list(APPEND SM3_MB_SOURCES ${SM3_MB_BASE_ALIASES_SOURCES})
endif()

# Headers exported by sm3_mb module
set(SM3_MB_HEADERS
    include/isa-l_crypto/sm3_mb.h
    include/isa-l_crypto/multi_buffer.h
)

# Add to main extern headers list
list(APPEND EXTERN_HEADERS ${SM3_MB_HEADERS})

# Test and performance applications
if(BUILD_TESTS OR BUILD_PERF)
    set(SM3_MB_CHECK_TESTS
        sm3_mb/sm3_ref_test
        sm3_mb/sm3_mb_test
        sm3_mb/sm3_mb_param_test
    )

    set(SM3_MB_UNIT_TESTS
        sm3_mb/sm3_mb_rand_ssl_test
        sm3_mb/sm3_mb_rand_update_test
        sm3_mb/sm3_mb_rand_test
    )

    set(SM3_MB_PERF_TESTS
        sm3_mb/sm3_mb_vs_ossl_perf
        sm3_mb/sm3_mb_vs_ossl_shortage_perf
    )

    if(BUILD_TESTS)
        find_package(OpenSSL)
        foreach(test_name ${SM3_MB_CHECK_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            # All sm3_mb tests need sm3_test_helper.c
            add_executable(${test_exec} ${test_name}.c sm3_mb/sm3_test_helper.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            if(OPENSSL_FOUND)
                target_link_libraries(${test_exec} PRIVATE OpenSSL::Crypto)
            endif()
            target_include_directories(${test_exec} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/isa-l_crypto ${CMAKE_CURRENT_SOURCE_DIR}/include/internal ${CMAKE_CURRENT_SOURCE_DIR}/sm3_mb)
            add_test(NAME ${test_exec} COMMAND ${test_exec})
        endforeach()

        # sm3_mb tests need helper object
        foreach(test_name ${SM3_MB_UNIT_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            add_executable(${test_exec} ${test_name}.c sm3_mb/sm3_test_helper.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            if(OPENSSL_FOUND)
                target_link_libraries(${test_exec} PRIVATE OpenSSL::Crypto)
            endif()
            target_include_directories(${test_exec} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/isa-l_crypto ${CMAKE_CURRENT_SOURCE_DIR}/include/internal ${CMAKE_CURRENT_SOURCE_DIR}/sm3_mb)
            add_test(NAME ${test_exec} COMMAND ${test_exec})
        endforeach()
    endif()

    if(BUILD_PERF)
        find_package(OpenSSL)
        foreach(test_name ${SM3_MB_PERF_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            add_executable(${test_exec} ${test_name}.c sm3_mb/sm3_test_helper.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            if(OPENSSL_FOUND)
                target_link_libraries(${test_exec} PRIVATE OpenSSL::Crypto)
            endif()
            target_include_directories(${test_exec} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/isa-l_crypto ${CMAKE_CURRENT_SOURCE_DIR}/include/internal ${CMAKE_CURRENT_SOURCE_DIR}/sm3_mb)
        endforeach()
    endif()
endif()

