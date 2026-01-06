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

# FIPS module CMake configuration

set(FIPS_BASE_SOURCES
    fips/sha_self_tests.c
)

set(FIPS_X86_64_SOURCES
    fips/self_tests.c
    fips/aes_self_tests.c
    fips/asm_self_tests.asm
)

set(FIPS_AARCH64_SOURCES
    fips/self_tests_generic.c
    fips/aes_self_tests.c
)

set(FIPS_RISCV64_SOURCES
    fips/self_tests_generic.c
)

set(FIPS_BASE_ALIASES_SOURCES
    fips/self_tests_generic.c
)

# Build source list based on architecture
set(FIPS_SOURCES ${FIPS_BASE_SOURCES})

if(CPU_X86_64)
    list(APPEND FIPS_SOURCES ${FIPS_X86_64_SOURCES})
elseif(CPU_AARCH64)
    list(APPEND FIPS_SOURCES ${FIPS_AARCH64_SOURCES})
elseif(CPU_RISCV64)
    list(APPEND FIPS_SOURCES ${FIPS_RISCV64_SOURCES})
elseif(CPU_UNDEFINED)
    list(APPEND FIPS_SOURCES ${FIPS_BASE_ALIASES_SOURCES})
endif()

# FIPS module doesn't export additional headers beyond what's already exported

# Test applications
if(BUILD_TESTS)
    set(FIPS_CHECK_TESTS
        fips/self_tests_test
    )

    foreach(test_name ${FIPS_CHECK_TESTS})
        get_filename_component(test_exec ${test_name} NAME)
        add_executable(${test_exec} ${test_name}.c)
        target_link_libraries(${test_exec} PRIVATE isal_crypto)
        target_include_directories(${test_exec} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/isa-l_crypto ${CMAKE_CURRENT_SOURCE_DIR}/internal ${CMAKE_CURRENT_SOURCE_DIR}/fips)
        add_test(NAME ${test_exec} COMMAND ${test_exec})
    endforeach()
endif()

