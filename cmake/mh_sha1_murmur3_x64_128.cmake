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

# MH-SHA1-Murmur3-x64-128 module CMake configuration

set(MH_SHA1_MURMUR3_BASE_SOURCES
    mh_sha1_murmur3_x64_128/murmur3_x64_128_internal.c
    mh_sha1_murmur3_x64_128/mh_sha1_murmur3_x64_128.c
    mh_sha1_murmur3_x64_128/mh_sha1_murmur3_x64_128_finalize_base.c
    mh_sha1_murmur3_x64_128/mh_sha1_murmur3_x64_128_update_base.c
)

set(MH_SHA1_MURMUR3_X86_64_SOURCES
    mh_sha1_murmur3_x64_128/mh_sha1_murmur3_x64_128_block_sse.asm
    mh_sha1_murmur3_x64_128/mh_sha1_murmur3_x64_128_block_avx.asm
    mh_sha1_murmur3_x64_128/mh_sha1_murmur3_x64_128_block_avx2.asm
    mh_sha1_murmur3_x64_128/mh_sha1_murmur3_x64_128_multibinary.asm
    mh_sha1_murmur3_x64_128/mh_sha1_murmur3_x64_128_avx512.c
    mh_sha1_murmur3_x64_128/mh_sha1_murmur3_x64_128_block_avx512.asm
)

set(MH_SHA1_MURMUR3_AARCH64_SOURCES
    mh_sha1_murmur3_x64_128/aarch64/mh_sha1_murmur3_aarch64_dispatcher.c
    mh_sha1_murmur3_x64_128/aarch64/mh_sha1_murmur3_ce.c
    mh_sha1_murmur3_x64_128/aarch64/mh_sha1_murmur3_block_ce.S
    mh_sha1_murmur3_x64_128/aarch64/mh_sha1_murmur3_asimd.c
    mh_sha1_murmur3_x64_128/aarch64/mh_sha1_murmur3_block_asimd.S
    mh_sha1_murmur3_x64_128/aarch64/mh_sha1_murmur3_multibinary.S
)

set(MH_SHA1_MURMUR3_RISCV64_SOURCES
    mh_sha1_murmur3_x64_128/mh_sha1_murmur3_x64_128_base_aliases.c
)

set(MH_SHA1_MURMUR3_BASE_ALIASES_SOURCES
    mh_sha1_murmur3_x64_128/mh_sha1_murmur3_x64_128_base_aliases.c
)

# Build source list based on architecture
set(MH_SHA1_MURMUR3_SOURCES ${MH_SHA1_MURMUR3_BASE_SOURCES})

if(CPU_X86_64)
    list(APPEND MH_SHA1_MURMUR3_SOURCES ${MH_SHA1_MURMUR3_X86_64_SOURCES})
elseif(CPU_AARCH64)
    list(APPEND MH_SHA1_MURMUR3_SOURCES ${MH_SHA1_MURMUR3_AARCH64_SOURCES})
elseif(CPU_RISCV64)
    list(APPEND MH_SHA1_MURMUR3_SOURCES ${MH_SHA1_MURMUR3_RISCV64_SOURCES})
elseif(CPU_UNDEFINED)
    list(APPEND MH_SHA1_MURMUR3_SOURCES ${MH_SHA1_MURMUR3_BASE_ALIASES_SOURCES})
endif()

# Headers exported by mh_sha1_murmur3_x64_128 module
set(MH_SHA1_MURMUR3_HEADERS
    include/isa-l_crypto/mh_sha1_murmur3_x64_128.h
)

# Add to main extern headers list
list(APPEND EXTERN_HEADERS ${MH_SHA1_MURMUR3_HEADERS})

# Test and performance applications
if(BUILD_TESTS OR BUILD_PERF)
    set(MH_SHA1_MURMUR3_CHECK_TESTS
        mh_sha1_murmur3_x64_128/mh_sha1_murmur3_x64_128_param_test
    )

    set(MH_SHA1_MURMUR3_UNIT_TESTS
        mh_sha1_murmur3_x64_128/mh_sha1_murmur3_x64_128_test
        mh_sha1_murmur3_x64_128/mh_sha1_murmur3_x64_128_update_test
    )

    set(MH_SHA1_MURMUR3_PERF_TESTS
        mh_sha1_murmur3_x64_128/mh_sha1_murmur3_x64_128_perf
    )

    if(BUILD_TESTS)
        foreach(test_name ${MH_SHA1_MURMUR3_CHECK_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            # Tests need both mh_sha1_ref.c and murmur3_x64_128.c
            add_executable(${test_exec} ${test_name}.c mh_sha1/mh_sha1_ref.c mh_sha1_murmur3_x64_128/murmur3_x64_128.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            target_include_directories(${test_exec} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/isa-l_crypto ${CMAKE_CURRENT_SOURCE_DIR}/mh_sha1 ${CMAKE_CURRENT_SOURCE_DIR}/mh_sha1_murmur3_x64_128)
            add_test(NAME ${test_exec} COMMAND ${test_exec})
        endforeach()

        foreach(test_name ${MH_SHA1_MURMUR3_UNIT_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            # Unit tests also need both helper files
            add_executable(${test_exec} ${test_name}.c mh_sha1/mh_sha1_ref.c mh_sha1_murmur3_x64_128/murmur3_x64_128.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            target_include_directories(${test_exec} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/isa-l_crypto ${CMAKE_CURRENT_SOURCE_DIR}/mh_sha1 ${CMAKE_CURRENT_SOURCE_DIR}/mh_sha1_murmur3_x64_128)
            add_test(NAME ${test_exec} COMMAND ${test_exec})
        endforeach()
    endif()

    if(BUILD_PERF)
        foreach(test_name ${MH_SHA1_MURMUR3_PERF_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            add_executable(${test_exec} ${test_name}.c mh_sha1/mh_sha1_ref.c mh_sha1_murmur3_x64_128/murmur3_x64_128.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            target_include_directories(${test_exec} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/isa-l_crypto ${CMAKE_CURRENT_SOURCE_DIR}/mh_sha1 ${CMAKE_CURRENT_SOURCE_DIR}/mh_sha1_murmur3_x64_128)
        endforeach()
    endif()
endif()

