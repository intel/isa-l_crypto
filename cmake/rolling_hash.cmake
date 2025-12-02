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

# Rolling Hash module CMake configuration

set(ROLLING_HASH_BASE_SOURCES
    rolling_hash/rolling_hashx_base.c
    rolling_hash/rolling_hash2.c
)

set(ROLLING_HASH_X86_64_SOURCES
    rolling_hash/rolling_hash2_until_04.asm
    rolling_hash/rolling_hash2_until_00.asm
    rolling_hash/rolling_hash2_multibinary.asm
)

set(ROLLING_HASH_AARCH64_SOURCES
    rolling_hash/aarch64/rolling_hash2_aarch64_multibinary.S
    rolling_hash/aarch64/rolling_hash2_aarch64_dispatcher.c
    rolling_hash/aarch64/rolling_hash2_run_until_unroll.S
)

set(ROLLING_HASH_RISCV64_SOURCES
    rolling_hash/rolling_hash2_base_aliases.c
)

set(ROLLING_HASH_BASE_ALIASES_SOURCES
    rolling_hash/rolling_hash2_base_aliases.c
)

# Build source list based on architecture
set(ROLLING_HASH_SOURCES ${ROLLING_HASH_BASE_SOURCES})

if(CPU_X86_64)
    list(APPEND ROLLING_HASH_SOURCES ${ROLLING_HASH_X86_64_SOURCES})
elseif(CPU_AARCH64)
    list(APPEND ROLLING_HASH_SOURCES ${ROLLING_HASH_AARCH64_SOURCES})
elseif(CPU_RISCV64)
    list(APPEND ROLLING_HASH_SOURCES ${ROLLING_HASH_RISCV64_SOURCES})
elseif(CPU_UNDEFINED)
    list(APPEND ROLLING_HASH_SOURCES ${ROLLING_HASH_BASE_ALIASES_SOURCES})
endif()

# Headers exported by rolling_hash module
set(ROLLING_HASH_HEADERS
    include/rolling_hashx.h
)

# Add to main extern headers list
list(APPEND EXTERN_HEADERS ${ROLLING_HASH_HEADERS})

# Test and performance applications
if(BUILD_TESTS OR BUILD_PERF)
    set(ROLLING_HASH_CHECK_TESTS
        rolling_hash/rolling_hash2_test
        rolling_hash/rolling_hash2_param_test
    )

    set(ROLLING_HASH_PERF_TESTS
        rolling_hash/rolling_hash2_perf
    )

    if(BUILD_TESTS)
        foreach(test_name ${ROLLING_HASH_CHECK_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            add_executable(${test_exec} ${test_name}.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            target_include_directories(${test_exec} PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/rolling_hash)
            add_test(NAME ${test_exec} COMMAND ${test_exec})
        endforeach()
    endif()

    if(BUILD_PERF)
        foreach(test_name ${ROLLING_HASH_PERF_TESTS})
            get_filename_component(test_exec ${test_name} NAME)
            add_executable(${test_exec} ${test_name}.c)
            target_link_libraries(${test_exec} PRIVATE isal_crypto)
            target_include_directories(${test_exec} PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/rolling_hash)
        endforeach()
    endif()
endif()

