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

# AES module CMake configuration

set(AES_BASE_SOURCES
    aes/gcm_pre.c
    aes/cbc_pre.c
    aes/aes_keyexp.c
    aes/aes_cbc.c
    aes/aes_xts.c
    aes/aes_gcm.c
)

set(AES_X86_64_SOURCES
    aes/gcm_multibinary.asm
    aes/gcm128_avx_gen2.asm
    aes/gcm128_avx_gen4.asm
    aes/gcm128_sse.asm
    aes/gcm256_avx_gen2.asm
    aes/gcm256_avx_gen4.asm
    aes/gcm256_sse.asm
    aes/gcm128_vaes_avx512.asm
    aes/gcm256_vaes_avx512.asm
    aes/gcm128_avx_gen2_nt.asm
    aes/gcm128_avx_gen4_nt.asm
    aes/gcm128_sse_nt.asm
    aes/gcm256_avx_gen2_nt.asm
    aes/gcm256_avx_gen4_nt.asm
    aes/gcm256_sse_nt.asm
    aes/gcm128_vaes_avx512_nt.asm
    aes/gcm256_vaes_avx512_nt.asm
    aes/gcm_multibinary_nt.asm
    aes/keyexp_multibinary.asm
    aes/keyexp_128.asm
    aes/keyexp_192.asm
    aes/keyexp_256.asm
    aes/cbc_multibinary.asm
    aes/cbc_dec_128_x8_sse.asm
    aes/cbc_dec_128_x8_avx.asm
    aes/cbc_dec_192_x8_sse.asm
    aes/cbc_dec_192_x8_avx.asm
    aes/cbc_dec_256_x8_sse.asm
    aes/cbc_dec_256_x8_avx.asm
    aes/cbc_enc_128_x4_sb.asm
    aes/cbc_enc_128_x8_sb.asm
    aes/cbc_enc_192_x4_sb.asm
    aes/cbc_enc_192_x8_sb.asm
    aes/cbc_enc_256_x4_sb.asm
    aes/cbc_enc_256_x8_sb.asm
    aes/cbc_dec_vaes_avx512.asm
    aes/xts_aes_128_multibinary.asm
    aes/XTS_AES_128_dec_sse.asm
    aes/XTS_AES_128_dec_expanded_key_sse.asm
    aes/XTS_AES_128_enc_sse.asm
    aes/XTS_AES_128_enc_expanded_key_sse.asm
    aes/XTS_AES_128_dec_avx.asm
    aes/XTS_AES_128_dec_expanded_key_avx.asm
    aes/XTS_AES_128_enc_avx.asm
    aes/XTS_AES_128_enc_expanded_key_avx.asm
    aes/xts_aes_256_multibinary.asm
    aes/XTS_AES_256_dec_avx.asm
    aes/XTS_AES_256_dec_expanded_key_avx.asm
    aes/XTS_AES_256_enc_avx.asm
    aes/XTS_AES_256_enc_expanded_key_avx.asm
    aes/XTS_AES_256_dec_sse.asm
    aes/XTS_AES_256_dec_expanded_key_sse.asm
    aes/XTS_AES_256_enc_sse.asm
    aes/XTS_AES_256_enc_expanded_key_sse.asm
    aes/XTS_AES_256_enc_vaes.asm
    aes/XTS_AES_128_enc_vaes.asm
    aes/XTS_AES_256_enc_expanded_key_vaes.asm
    aes/XTS_AES_128_enc_expanded_key_vaes.asm
    aes/XTS_AES_256_dec_vaes.asm
    aes/XTS_AES_128_dec_vaes.asm
    aes/XTS_AES_256_dec_expanded_key_vaes.asm
    aes/XTS_AES_128_dec_expanded_key_vaes.asm
)

set(AES_AARCH64_SOURCES
    aes/aarch64/gcm_multibinary_aarch64.S
    aes/aarch64/keyexp_multibinary_aarch64.S
    aes/aarch64/gcm_aarch64_dispatcher.c
    aes/aarch64/keyexp_aarch64_dispatcher.c
    aes/aarch64/keyexp_128_aarch64_aes.S
    aes/aarch64/keyexp_192_aarch64_aes.S
    aes/aarch64/keyexp_256_aarch64_aes.S
    aes/aarch64/aes_gcm_aes_finalize_128.S
    aes/aarch64/aes_gcm_aes_init.S
    aes/aarch64/aes_gcm_enc_dec_128.S
    aes/aarch64/aes_gcm_precomp_128.S
    aes/aarch64/aes_gcm_update_128.S
    aes/aarch64/aes_gcm_aes_finalize_256.S
    aes/aarch64/aes_gcm_consts.S
    aes/aarch64/aes_gcm_enc_dec_256.S
    aes/aarch64/aes_gcm_precomp_256.S
    aes/aarch64/aes_gcm_update_256.S
    aes/aarch64/xts_aarch64_dispatcher.c
    aes/aarch64/xts_aes_128_dec.S
    aes/aarch64/xts_aes_128_enc.S
    aes/aarch64/xts_keyexp_aes_128_dec.S
    aes/aarch64/xts_keyexp_aes_128_enc.S
    aes/aarch64/xts_aes_256_dec.S
    aes/aarch64/xts_aes_256_enc.S
    aes/aarch64/xts_keyexp_aes_256_dec.S
    aes/aarch64/xts_keyexp_aes_256_enc.S
    aes/aarch64/xts_multibinary_aarch64.S
    aes/aarch64/cbc_multibinary_aarch64.S
    aes/aarch64/cbc_aarch64_dispatcher.c
    aes/aarch64/cbc_enc_aes.S
    aes/aarch64/cbc_dec_aes.S
)

# Build source list based on architecture
set(AES_SOURCES ${AES_BASE_SOURCES})

if(CPU_X86_64)
    list(APPEND AES_SOURCES ${AES_X86_64_SOURCES})
elseif(CPU_AARCH64)
    list(APPEND AES_SOURCES ${AES_AARCH64_SOURCES})
endif()

# Headers exported by aes module
set(AES_HEADERS
    include/isa-l_crypto/aes_gcm.h
    include/isa-l_crypto/aes_cbc.h
    include/isa-l_crypto/aes_xts.h
    include/isa-l_crypto/aes_keyexp.h
    include/isa-l_crypto/isal_crypto_api.h
)

# Add to main extern headers list
list(APPEND EXTERN_HEADERS ${AES_HEADERS})

# Test and performance applications
if(BUILD_TESTS OR BUILD_PERF)
    set(AES_CHECK_TESTS
        aes/cbc_std_vectors_test
        aes/gcm_std_vectors_test
        aes/gcm_nt_std_vectors_test
        aes/xts_128_test
        aes/xts_256_test
        aes/xts_128_expanded_key_test
        aes/xts_256_expanded_key_test
        aes/aes_param_test
    )

    set(AES_UNIT_TESTS
        aes/cbc_std_vectors_random_test
        aes/gcm_std_vectors_random_test
        aes/gcm_nt_rand_test
        aes/xts_128_rand
        aes/xts_128_rand_ossl_test
        aes/xts_256_rand
        aes/xts_256_rand_ossl_test
    )

    set(AES_PERF_TESTS
        aes/cbc_ossl_perf
        aes/gcm_ossl_perf
        aes/xts_128_enc_ossl_perf
        aes/xts_256_enc_ossl_perf
        aes/xts_128_dec_ossl_perf
        aes/xts_128_enc_perf
        aes/xts_128_dec_perf
        aes/xts_256_enc_perf
        aes/xts_256_dec_perf
        aes/xts_256_dec_ossl_perf
        aes/aes_perf
    )

    set(AES_EXAMPLES
        aes/gcm_simple_example
    )

    if(BUILD_TESTS)
        foreach(test_name ${AES_CHECK_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            add_executable(${test_exec} ${test_name}.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            target_include_directories(${test_exec} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include/isa-l_crypto ${CMAKE_CURRENT_SOURCE_DIR}/include/internal ${CMAKE_CURRENT_SOURCE_DIR}/aes)
            add_test(NAME ${test_exec} COMMAND ${test_exec})
        endforeach()

        find_package(OpenSSL)
        foreach(test_name ${AES_UNIT_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            add_executable(${test_exec} ${test_name}.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            if(OPENSSL_FOUND)
                target_link_libraries(${test_exec} PRIVATE OpenSSL::Crypto)
            endif()
            target_include_directories(${test_exec} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/isa-l_crypto ${CMAKE_CURRENT_SOURCE_DIR}/include/internal ${CMAKE_CURRENT_SOURCE_DIR}/aes)
        endforeach()

        # Build examples
        foreach(example_name ${AES_EXAMPLES})
            get_filename_component(example_exec ${example_name} NAME)
            add_executable(${example_exec} ${example_name}.c)
            target_link_libraries(${example_exec} PRIVATE isal_crypto)
            target_include_directories(${example_exec} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/isa-l_crypto ${CMAKE_CURRENT_SOURCE_DIR}/include/internal ${CMAKE_CURRENT_SOURCE_DIR}/aes)
        endforeach()
    endif()

    if(BUILD_PERF)
        find_package(OpenSSL)
        foreach(test_name ${AES_PERF_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            add_executable(${test_exec} ${test_name}.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            if(OPENSSL_FOUND)
                target_link_libraries(${test_exec} PRIVATE OpenSSL::Crypto)
            endif()
            target_include_directories(${test_exec} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/isa-l_crypto ${CMAKE_CURRENT_SOURCE_DIR}/include/internal ${CMAKE_CURRENT_SOURCE_DIR}/aes)
        endforeach()
    endif()
endif()

