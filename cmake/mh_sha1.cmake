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

# MH-SHA1 module CMake configuration

set(MH_SHA1_BASE_SOURCES
    mh_sha1/mh_sha1_block_base.c
    mh_sha1/mh_sha1_finalize_base.c
    mh_sha1/mh_sha1_update_base.c
    mh_sha1/sha1_for_mh_sha1.c
    mh_sha1/mh_sha1.c
)

set(MH_SHA1_X86_64_SOURCES
    mh_sha1/mh_sha1_multibinary.asm
    mh_sha1/mh_sha1_block_sse.asm
    mh_sha1/mh_sha1_block_avx.asm
    mh_sha1/mh_sha1_block_avx2.asm
    mh_sha1/mh_sha1_block_avx512.asm
    mh_sha1/mh_sha1_avx512.c
)

set(MH_SHA1_AARCH64_SOURCES
    mh_sha1/aarch64/mh_sha1_multibinary.S
    mh_sha1/aarch64/mh_sha1_aarch64_dispatcher.c
    mh_sha1/aarch64/mh_sha1_block_sve.S
    mh_sha1/aarch64/mh_sha1_sve.c
    mh_sha1/aarch64/mh_sha1_sve2.c
    mh_sha1/aarch64/mh_sha1_block_asimd.S
    mh_sha1/aarch64/mh_sha1_asimd.c
    mh_sha1/aarch64/mh_sha1_block_ce.S
    mh_sha1/aarch64/mh_sha1_ce.c
)

set(MH_SHA1_RISCV64_SOURCES
    mh_sha1/mh_sha1_base_aliases.c
)

set(MH_SHA1_BASE_ALIASES_SOURCES
    mh_sha1/mh_sha1_base_aliases.c
)

# Build source list based on architecture
set(MH_SHA1_SOURCES ${MH_SHA1_BASE_SOURCES})

if(CPU_X86_64)
    list(APPEND MH_SHA1_SOURCES ${MH_SHA1_X86_64_SOURCES})
elseif(CPU_AARCH64)
    list(APPEND MH_SHA1_SOURCES ${MH_SHA1_AARCH64_SOURCES})
elseif(CPU_RISCV64)
    list(APPEND MH_SHA1_SOURCES ${MH_SHA1_RISCV64_SOURCES})
elseif(CPU_UNDEFINED)
    list(APPEND MH_SHA1_SOURCES ${MH_SHA1_BASE_ALIASES_SOURCES})
endif()

# Headers exported by mh_sha1 module
set(MH_SHA1_HEADERS
    include/isa-l_crypto/mh_sha1.h
)

# Add to main extern headers list
list(APPEND EXTERN_HEADERS ${MH_SHA1_HEADERS})

# Test and performance applications
if(BUILD_TESTS OR BUILD_PERF)
    set(MH_SHA1_CHECK_TESTS
        mh_sha1/mh_sha1_test
        mh_sha1/mh_sha1_param_test
    )

    set(MH_SHA1_UNIT_TESTS
        mh_sha1/mh_sha1_update_test
    )

    set(MH_SHA1_PERF_TESTS
        mh_sha1/mh_sha1_perf
    )

    if(BUILD_TESTS)
        foreach(test_name ${MH_SHA1_CHECK_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            # These tests need mh_sha1_ref.c
            if(test_exec STREQUAL "mh_sha1_test" OR test_exec STREQUAL "mh_sha1_update_test")
                add_executable(${test_exec} ${test_name}.c mh_sha1/mh_sha1_ref.c)
            else()
                add_executable(${test_exec} ${test_name}.c)
            endif()
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            target_include_directories(${test_exec} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/isa-l_crypto ${CMAKE_CURRENT_SOURCE_DIR}/mh_sha1)
            add_test(NAME ${test_exec} COMMAND ${test_exec})
        endforeach()

        foreach(test_name ${MH_SHA1_UNIT_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            # mh_sha1_update_test also needs mh_sha1_ref.c
            add_executable(${test_exec} ${test_name}.c mh_sha1/mh_sha1_ref.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            target_include_directories(${test_exec} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/isa-l_crypto ${CMAKE_CURRENT_SOURCE_DIR}/mh_sha1)
            add_test(NAME ${test_exec} COMMAND ${test_exec})
        endforeach()
    endif()

    if(BUILD_PERF)
        foreach(test_name ${MH_SHA1_PERF_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            add_executable(${test_exec} ${test_name}.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            target_include_directories(${test_exec} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/isa-l_crypto ${CMAKE_CURRENT_SOURCE_DIR}/mh_sha1)
        endforeach()
    endif()
endif()

