# This file is part of the openHiTLS project.
#
# openHiTLS is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#     http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

cmake_minimum_required(VERSION 3.10)
project(pqcp_provider C)

include(CheckCCompilerFlag)

# 新增：自定义库路径变量
set(PQCP_LIB_DIR "" CACHE PATH "Custom library search path")
set(PQCP_LIB_TYPE "SHARED" CACHE STRING "Library type (SHARED or STATIC)")
set(HITLS_ROOT_PATH "" CACHE PATH "Custom HiTLS root directory")
if(NOT HITLS_ROOT_PATH)
    set(HITLS_ROOT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/platform/openhitls")
endif()
set(HITLS_LIB_DIR "" CACHE PATH "Directory holding the built openHiTLS libraries (defaults to ${HITLS_ROOT_PATH}/build)")
if(NOT HITLS_LIB_DIR)
    set(HITLS_LIB_DIR "${HITLS_ROOT_PATH}/build")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(PQCP_ENABLE_NEV "Compile the NEV implementations" ON)
option(PQCP_NEV_ENABLE_NEON "Enable the ARMv8 assembly path in the NEV NEON implementation" OFF)
option(PQCP_NEV_ENABLE_SVE2 "Select the 256-bit SVE2 NEV and SHA3 assembly implementation" OFF)
option(PQCP_NEV_ENABLE_SVE2_SHA3 "Enable the FEAT_SHA3/FEAT_SVE_SHA3 hybrid SHA3 backend" OFF)
option(PQCP_BUILD_NEV_BENCHMARK "Build the NEV provider benchmark" OFF)
option(PQCP_BUILD_NEV_UNIT_TESTS "Build the NEV white-box unit tests" OFF)
set(PQCP_NEV_HASH_BACKEND "SHA3" CACHE STRING "NEV Hash/KDF backend: SHA3, SM3 or CUSTOM")
set_property(CACHE PQCP_NEV_HASH_BACKEND PROPERTY STRINGS SHA3 SM3 CUSTOM)
set(PQCP_NEV_CUSTOM_HASH_SOURCES "" CACHE STRING "Semicolon-separated CUSTOM NEV Hash/KDF source files")
set(PQCP_NEV_CUSTOM_HASH_INCLUDE_DIRS "" CACHE STRING "Semicolon-separated CUSTOM NEV Hash/KDF include directories")

# 调试选项设置
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3 -O0")

# ASAN配置
if(ENABLE_ASAN)
    message(STATUS "Enabling asan flags")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
endif()
if(ENABLE_GCOV)
    message(STATUS "Enabling gcov code coverage flags")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lgcov --coverage")
endif()
file(GLOB_RECURSE PROVIDER_SOURCES
    src/provider/*.c
    src/scloudplus/src/*.c
    src/polarlac/src/*.c
    src/composite_sign/src/*.c
)

option(PQCP_ENABLE_AIGIS_SIG "Build the Aigis-Sig provider implementation" ON)
option(PQCP_AIGIS_SIG_ARMV8 "Use the AArch64 assembly backend for Aigis-Sig" OFF)

set(PQCP_AIGIS_SIG_SOURCES)
set(PQCP_AIGIS_SIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/Aigis-sig")
if(PQCP_ENABLE_AIGIS_SIG)
    list(APPEND PQCP_AIGIS_SIG_SOURCES
        ${PQCP_AIGIS_SIG_DIR}/src/aigis_sig_sign.c
        ${PQCP_AIGIS_SIG_DIR}/src/aigis_sig_poly.c
        ${PQCP_AIGIS_SIG_DIR}/src/aigis_sig_sample.c
        ${PQCP_AIGIS_SIG_DIR}/src/aigis_sig_pack.c
        ${PQCP_AIGIS_SIG_DIR}/src/portable/aigis_sig_arith.c
        ${PQCP_AIGIS_SIG_DIR}/src/aigis_sig_sm3_kdf.c
        ${PQCP_AIGIS_SIG_DIR}/src/aigis_sig_sha3_kdf.c
        ${PQCP_AIGIS_SIG_DIR}/src/crypt_aigis_sig.c
        ${PQCP_AIGIS_SIG_DIR}/src/aigis_sig_hashkdf.c
        ${PQCP_AIGIS_SIG_DIR}/src/aigis_sig_params.c
    )
    if(PQCP_AIGIS_SIG_ARMV8)
        if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
            message(FATAL_ERROR "PQCP_AIGIS_SIG_ARMV8 requires an AArch64 target")
        endif()
        if(NOT CMAKE_EXECUTABLE_FORMAT STREQUAL "ELF")
            message(FATAL_ERROR "PQCP_AIGIS_SIG_ARMV8 requires an ELF AArch64 target")
        endif()
        enable_language(ASM)
        list(APPEND PQCP_AIGIS_SIG_SOURCES
            ${PQCP_AIGIS_SIG_DIR}/src/armv8/aigis_sig_ntt.S
            ${PQCP_AIGIS_SIG_DIR}/src/armv8/aigis_sig_pointwise.S
            ${PQCP_AIGIS_SIG_DIR}/src/armv8/aigis_sig_poly.S
            ${PQCP_AIGIS_SIG_DIR}/src/armv8/aigis_sig_sample.S
            ${PQCP_AIGIS_SIG_DIR}/src/armv8/aigis_sig_pack.S
            ${PQCP_AIGIS_SIG_DIR}/src/armv8/aigis_sig_keccak_scalar.S
            ${PQCP_AIGIS_SIG_DIR}/src/armv8/aigis_sig_keccak_x2.S
            ${PQCP_AIGIS_SIG_DIR}/src/armv8/aigis_sig_pspm.S
        )
        message(STATUS "Aigis-Sig backend: ARMv8 assembly")
    else()
        list(APPEND PQCP_AIGIS_SIG_SOURCES
            ${PQCP_AIGIS_SIG_DIR}/src/portable/aigis_sig_ntt.c
            ${PQCP_AIGIS_SIG_DIR}/src/portable/aigis_sig_challenge.c
        )
        message(STATUS "Aigis-Sig backend: portable C")
    endif()
    list(APPEND PROVIDER_SOURCES ${PQCP_AIGIS_SIG_SOURCES})
else()
    message(STATUS "Aigis-Sig disabled by algorithm selection")
endif()
file(GLOB_RECURSE HIAE_SOURCES
    src/hiae/src/*.c
)

set(PQCP_HIAE_SUPPORTED FALSE)
set(PQCP_HIAE_COMPILE_OPTIONS)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    check_c_compiler_flag("-maes" PQCP_COMPILER_SUPPORTS_MAES)
    if(PQCP_COMPILER_SUPPORTS_MAES)
        set(PQCP_HIAE_SUPPORTED TRUE)
        list(APPEND PQCP_HIAE_COMPILE_OPTIONS "-maes")
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
    check_c_compiler_flag("-march=armv8-a+crypto+aes+sha2" PQCP_COMPILER_SUPPORTS_ARMV8_CRYPTO)
    if(PQCP_COMPILER_SUPPORTS_ARMV8_CRYPTO)
        set(PQCP_HIAE_SUPPORTED TRUE)
        list(APPEND PQCP_HIAE_COMPILE_OPTIONS "-march=armv8-a+crypto+aes+sha2")
    endif()
endif()

if(PQCP_HIAE_SUPPORTED)
    list(APPEND PROVIDER_SOURCES ${HIAE_SOURCES})
else()
    message(STATUS "HiAE disabled: unsupported target platform or compiler flags for ${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(NEV_OBJECTS)
set(PQCP_NEV_DISPATCH_DEFINITION)
set(PQCP_NEV_PROVIDER_DEFINITION)
if(PQCP_ENABLE_NEV)
    list(APPEND PROVIDER_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/src/nev/src/crypt_nev.c
    )
    set(PQCP_NEV_PROVIDER_DEFINITION PQCP_NEV)
    set(NEV_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/src/nev)
    set(NEV_SRC_ROOT ${NEV_ROOT}/src)
    set(NEV_ASM_ROOT ${NEV_SRC_ROOT}/asm)
    set(NEV_C_NAMESPACE_HEADER ${NEV_SRC_ROOT}/nev_c_namespace.h)
    set(NEV_ASM_NAMESPACE_HEADER ${NEV_ASM_ROOT}/nev_asm_namespace.h)
    string(TOUPPER "${PQCP_NEV_HASH_BACKEND}" PQCP_NEV_HASH_BACKEND_EFFECTIVE)
    set(NEV_COMMON_SOURCES)
    set(PQCP_NEV_BACKEND_DEFINITIONS)
    set(PQCP_NEV_PROVIDER_SVE2_DEFINITION)
    set(PQCP_NEV_SAMPLE_DEFINITIONS)
    set(PQCP_NEV_BACKEND_INCLUDE_DIRS)

    if(PQCP_NEV_HASH_BACKEND_EFFECTIVE STREQUAL "SHA3")
        list(APPEND NEV_COMMON_SOURCES ${NEV_SRC_ROOT}/nev_symmetric_sha3.c)
        list(APPEND PQCP_NEV_BACKEND_DEFINITIONS PQCP_NEV_HASH_SHA3 HITLS_CRYPTO_SHA3)
        list(APPEND PQCP_NEV_BACKEND_INCLUDE_DIRS
            ${HITLS_ROOT_PATH}/crypto/sha3/src
            ${HITLS_ROOT_PATH}/crypto/sha3/include
        )
    elseif(PQCP_NEV_HASH_BACKEND_EFFECTIVE STREQUAL "SM3")
        list(APPEND NEV_COMMON_SOURCES
            ${NEV_SRC_ROOT}/auxfunc.c
            ${NEV_SRC_ROOT}/hashkdf.c
            ${NEV_SRC_ROOT}/nev_symmetric_iccs.c
        )
        list(APPEND PQCP_NEV_BACKEND_DEFINITIONS
            PQCP_NEV_HASH_SM3
            USE_ICCS
            HITLS_CRYPTO_SM3
        )
        list(APPEND PQCP_NEV_BACKEND_INCLUDE_DIRS
            ${HITLS_ROOT_PATH}/include/bsl
            ${HITLS_ROOT_PATH}/include/crypto
            ${HITLS_ROOT_PATH}/crypto/include
            ${HITLS_ROOT_PATH}/crypto/sm3/include
        )
        list(APPEND PQCP_NEV_SAMPLE_DEFINITIONS PQCP_NEV_DISABLE_KECCAK_X2)
    elseif(PQCP_NEV_HASH_BACKEND_EFFECTIVE STREQUAL "CUSTOM")
        if(NOT PQCP_NEV_CUSTOM_HASH_SOURCES)
            message(FATAL_ERROR "PQCP_NEV_HASH_BACKEND=CUSTOM requires PQCP_NEV_CUSTOM_HASH_SOURCES")
        endif()
        foreach(NEV_CUSTOM_SOURCE IN LISTS PQCP_NEV_CUSTOM_HASH_SOURCES)
            if(NOT IS_ABSOLUTE "${NEV_CUSTOM_SOURCE}")
                set(NEV_CUSTOM_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/${NEV_CUSTOM_SOURCE}")
            endif()
            if(NOT EXISTS "${NEV_CUSTOM_SOURCE}")
                message(FATAL_ERROR "NEV custom Hash/KDF source does not exist: ${NEV_CUSTOM_SOURCE}")
            endif()
            list(APPEND NEV_COMMON_SOURCES "${NEV_CUSTOM_SOURCE}")
        endforeach()
        list(APPEND PQCP_NEV_BACKEND_INCLUDE_DIRS ${PQCP_NEV_CUSTOM_HASH_INCLUDE_DIRS})
        list(APPEND PQCP_NEV_BACKEND_DEFINITIONS PQCP_NEV_HASH_CUSTOM)
        list(APPEND PQCP_NEV_SAMPLE_DEFINITIONS PQCP_NEV_DISABLE_KECCAK_X2)
    else()
        message(FATAL_ERROR "Unsupported PQCP_NEV_HASH_BACKEND=${PQCP_NEV_HASH_BACKEND}; use SHA3, SM3 or CUSTOM")
    endif()

    if(PQCP_NEV_ENABLE_SVE2)
        if(NOT PQCP_NEV_ENABLE_NEON)
            message(FATAL_ERROR "PQCP_NEV_ENABLE_SVE2=ON requires PQCP_NEV_ENABLE_NEON=ON")
        endif()
        if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
            message(FATAL_ERROR "PQCP_NEV_ENABLE_SVE2=ON requires an AArch64 target with a 256-bit SVE vector length")
        endif()
        if(NOT PQCP_NEV_HASH_BACKEND_EFFECTIVE STREQUAL "SHA3")
            message(FATAL_ERROR "PQCP_NEV_ENABLE_SVE2=ON requires PQCP_NEV_HASH_BACKEND=SHA3")
        endif()
        check_c_compiler_flag("-march=armv8-a+sve2" PQCP_NEV_COMPILER_SUPPORTS_SVE2)
        if(NOT PQCP_NEV_COMPILER_SUPPORTS_SVE2)
            message(FATAL_ERROR "The C compiler does not support -march=armv8-a+sve2")
        endif()
        list(APPEND PQCP_NEV_BACKEND_DEFINITIONS
            HITLS_CRYPTO_NEV_SVE2
        )
        set(PQCP_NEV_PROVIDER_SVE2_DEFINITION HITLS_CRYPTO_NEV_SVE2)
        if(PQCP_NEV_ENABLE_SVE2_SHA3)
            check_c_compiler_flag("-march=armv8-a+sve2-sha3" PQCP_NEV_COMPILER_SUPPORTS_SVE2_SHA3)
            if(NOT PQCP_NEV_COMPILER_SUPPORTS_SVE2_SHA3)
                message(FATAL_ERROR "The C compiler does not support -march=armv8-a+sve2-sha3")
            endif()
            list(APPEND PQCP_NEV_BACKEND_DEFINITIONS HITLS_CRYPTO_NEV_SVE2_SHA3)
        endif()
    elseif(PQCP_NEV_ENABLE_SVE2_SHA3)
        message(FATAL_ERROR "PQCP_NEV_ENABLE_SVE2_SHA3=ON requires PQCP_NEV_ENABLE_SVE2=ON")
    endif()

    add_library(pqcp_nev_common OBJECT ${NEV_COMMON_SOURCES})
    target_include_directories(pqcp_nev_common PRIVATE
        ${NEV_SRC_ROOT}
        ${HITLS_ROOT_PATH}/config/macro_config
        ${HITLS_ROOT_PATH}/conf/macro_config
        ${PQCP_NEV_BACKEND_INCLUDE_DIRS}
    )
    target_compile_definitions(pqcp_nev_common PRIVATE
        HITLS_CRYPTO_NEV
        ${PQCP_NEV_BACKEND_DEFINITIONS}
    )
    set_target_properties(pqcp_nev_common PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        C_VISIBILITY_PRESET hidden
    )
    list(APPEND NEV_OBJECTS $<TARGET_OBJECTS:pqcp_nev_common>)

    set(NEV_NEON_C_SOURCES
        ${NEV_SRC_ROOT}/nev_engine.c
        ${NEV_SRC_ROOT}/nev_ntt.c
        ${NEV_SRC_ROOT}/nev_pack.c
        ${NEV_SRC_ROOT}/nev_poly.c
        ${NEV_SRC_ROOT}/nev_poly_q769.c
        ${NEV_SRC_ROOT}/nev_poly_q1409.c
        ${NEV_SRC_ROOT}/nev_poly_q3329.c
        ${NEV_SRC_ROOT}/nev_sample.c
    )
    add_library(pqcp_nev_neon_c OBJECT ${NEV_NEON_C_SOURCES})
    target_include_directories(pqcp_nev_neon_c PRIVATE
        ${NEV_SRC_ROOT}
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${HITLS_ROOT_PATH}/include/bsl
        ${HITLS_ROOT_PATH}/config/macro_config
        ${HITLS_ROOT_PATH}/conf/macro_config
        ${PQCP_NEV_BACKEND_INCLUDE_DIRS}
    )
    target_compile_definitions(pqcp_nev_neon_c PRIVATE
        HITLS_CRYPTO_NEV
        ${PQCP_NEV_BACKEND_DEFINITIONS}
        ${PQCP_NEV_SAMPLE_DEFINITIONS}
    )
    target_compile_options(pqcp_nev_neon_c PRIVATE
        -include ${NEV_C_NAMESPACE_HEADER}
        $<$<CONFIG:Release>:-O3>
        $<$<AND:$<CONFIG:Release>,$<NOT:$<BOOL:${ENABLE_ASAN}>>>:-fomit-frame-pointer>
    )
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        set_source_files_properties(
            ${NEV_SRC_ROOT}/nev_poly_q769.c
            ${NEV_SRC_ROOT}/nev_poly_q1409.c
            ${NEV_SRC_ROOT}/nev_poly_q3329.c
            PROPERTIES COMPILE_OPTIONS "-Wno-maybe-uninitialized")
    endif()
    set_target_properties(pqcp_nev_neon_c PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        C_VISIBILITY_PRESET hidden
    )
    list(APPEND NEV_OBJECTS $<TARGET_OBJECTS:pqcp_nev_neon_c>)
    set(PQCP_NEV_DISPATCH_DEFINITION PQCP_NEV_NEON_C)
    set(PQCP_NEV_IMPL_EFFECTIVE "NEON portable C core")

    if(PQCP_NEV_ENABLE_NEON)
        if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
            message(FATAL_ERROR "PQCP_NEV_ENABLE_NEON=ON requires an AArch64 target")
        endif()
        enable_language(ASM)
        check_c_compiler_flag("-march=armv8-a+simd" PQCP_NEV_COMPILER_SUPPORTS_NEON)
        if(NOT PQCP_NEV_COMPILER_SUPPORTS_NEON)
            message(FATAL_ERROR "The C compiler does not support -march=armv8-a+simd")
        endif()
        set(NEV_NEON_ASM_SOURCES
            ${NEV_SRC_ROOT}/nev_engine.c
            ${NEV_SRC_ROOT}/nev_sample.c
            ${NEV_ASM_ROOT}/asm_nev_ntt.c
            ${NEV_ASM_ROOT}/asm_nev_pack.c
            ${NEV_ASM_ROOT}/asm_nev_poly.c
            ${NEV_ASM_ROOT}/asm_nev_sample.c
            ${NEV_ASM_ROOT}/nev_ntt_armv8.S
            ${NEV_ASM_ROOT}/nev_pack_armv8.S
            ${NEV_ASM_ROOT}/nev_poly_armv8.S
            ${NEV_ASM_ROOT}/nev_sample_armv8.S
        )
        if(PQCP_NEV_ENABLE_SVE2)
            list(APPEND NEV_NEON_ASM_SOURCES
                ${NEV_ASM_ROOT}/asm_nev_sha3_sve2.c
                ${NEV_ASM_ROOT}/nev_ntt_sve2_256.S
                ${NEV_ASM_ROOT}/nev_pack_sve2.S
                ${NEV_ASM_ROOT}/nev_poly_sve2_256.S
                ${NEV_ASM_ROOT}/nev_poly_sve2_extra.S
                ${NEV_ASM_ROOT}/nev_sample_sve2.S
                ${NEV_ASM_ROOT}/nev_sha3_sve2.S
            )
            if(PQCP_NEV_ENABLE_SVE2_SHA3)
                list(APPEND NEV_NEON_ASM_SOURCES ${NEV_ASM_ROOT}/nev_sha3_neon.S)
            endif()
            set_source_files_properties(
                ${NEV_ASM_ROOT}/nev_ntt_sve2_256.S
                ${NEV_ASM_ROOT}/nev_pack_sve2.S
                ${NEV_ASM_ROOT}/nev_poly_sve2_256.S
                ${NEV_ASM_ROOT}/nev_poly_sve2_extra.S
                ${NEV_ASM_ROOT}/nev_sample_sve2.S
                PROPERTIES COMPILE_OPTIONS "-march=armv8-a+sve2")
            if(PQCP_NEV_ENABLE_SVE2_SHA3)
                set_source_files_properties(
                    ${NEV_ASM_ROOT}/nev_sha3_sve2.S
                    ${NEV_ASM_ROOT}/nev_sha3_neon.S
                    PROPERTIES COMPILE_OPTIONS "-march=armv8-a+sve2-sha3")
            else()
                set_source_files_properties(${NEV_ASM_ROOT}/nev_sha3_sve2.S
                    PROPERTIES COMPILE_OPTIONS "-march=armv8-a+sve2")
            endif()
        endif()
        add_library(pqcp_nev_neon_asm OBJECT ${NEV_NEON_ASM_SOURCES})
        target_include_directories(pqcp_nev_neon_asm PRIVATE
            ${NEV_SRC_ROOT}
            ${NEV_ASM_ROOT}
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${HITLS_ROOT_PATH}/include/bsl
            ${HITLS_ROOT_PATH}/include/crypto
            ${HITLS_ROOT_PATH}/crypto/include
            ${HITLS_ROOT_PATH}/config/macro_config
            ${HITLS_ROOT_PATH}/conf/macro_config
            ${PQCP_NEV_BACKEND_INCLUDE_DIRS}
        )
        target_compile_definitions(pqcp_nev_neon_asm PRIVATE
            HITLS_CRYPTO_NEV
            HITLS_CRYPTO_NEV_ARMV8
            ${PQCP_NEV_BACKEND_DEFINITIONS}
            ${PQCP_NEV_SAMPLE_DEFINITIONS}
        )
        target_compile_options(pqcp_nev_neon_asm PRIVATE
            -include ${NEV_ASM_NAMESPACE_HEADER}
            $<$<CONFIG:Release>:-O3>
            $<$<AND:$<CONFIG:Release>,$<NOT:$<BOOL:${ENABLE_ASAN}>>>:-fomit-frame-pointer>
            -march=armv8-a+simd
        )
        set_target_properties(pqcp_nev_neon_asm PROPERTIES
            POSITION_INDEPENDENT_CODE ON
            C_VISIBILITY_PRESET hidden
        )
        list(APPEND NEV_OBJECTS $<TARGET_OBJECTS:pqcp_nev_neon_asm>)
        set(PQCP_NEV_DISPATCH_DEFINITION PQCP_NEV_NEON_DISPATCH_ASM)
        set(PQCP_NEV_IMPL_EFFECTIVE "NEON high-performance core + ARMv8 assembly runtime dispatch")
        if(PQCP_NEV_ENABLE_SVE2)
            set(PQCP_NEV_IMPL_EFFECTIVE
                "NEON high-performance core + compile-time SVE2 assembly selection")
            if(PQCP_NEV_ENABLE_SVE2_SHA3)
                set(PQCP_NEV_IMPL_EFFECTIVE
                    "NEON high-performance core + compile-time SVE2 and hybrid SHA3 assembly selection")
            endif()
        endif()
    endif()
    message(STATUS "NEV implementation: ${PQCP_NEV_IMPL_EFFECTIVE}")
    message(STATUS "NEV Hash/KDF backend: ${PQCP_NEV_HASH_BACKEND_EFFECTIVE}")
    file(WRITE "${CMAKE_BINARY_DIR}/nev_hash_backend.txt"
        "${PQCP_NEV_HASH_BACKEND_EFFECTIVE}\n")

    if(PQCP_BUILD_NEV_UNIT_TESTS)
        if(NOT PQCP_NEV_ENABLE_NEON)
            message(FATAL_ERROR "PQCP_BUILD_NEV_UNIT_TESTS=ON requires PQCP_NEV_ENABLE_NEON=ON")
        endif()
        enable_testing()
        add_subdirectory(testcode/nev_asm_compact)
    endif()
else()
    file(WRITE "${CMAKE_BINARY_DIR}/nev_hash_backend.txt" "DISABLED\n")
endif()

# 添加链接目录
if(PQCP_LIB_DIR)
    link_directories(${PQCP_LIB_DIR})
endif()

# Create shared library
add_library(pqcp_provider ${PQCP_LIB_TYPE} ${PROVIDER_SOURCES} ${NEV_OBJECTS})

target_include_directories(pqcp_provider PRIVATE
    "${PQCP_AIGIS_SIG_DIR}/include"
    "${PQCP_AIGIS_SIG_DIR}/src"
)

if(USER_BUILD_ARGS)
    separate_arguments(USER_BUILD_ARGS)
    foreach(PQCP_USER_BUILD_TARGET IN ITEMS
        pqcp_provider
        pqcp_nev_common
        pqcp_nev_neon_c
        pqcp_nev_neon_asm)
        if(TARGET ${PQCP_USER_BUILD_TARGET})
            target_compile_options(${PQCP_USER_BUILD_TARGET} PRIVATE ${USER_BUILD_ARGS})
        endif()
    endforeach()
endif()
target_compile_options(pqcp_provider PRIVATE -Wall -Wextra -Werror)
target_include_directories(pqcp_provider
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/provider
        ${CMAKE_CURRENT_SOURCE_DIR}/src/scloudplus/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/polarlac/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/composite_sign/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/nev/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/nev/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/hiae/include
        ${OPENHITLS_INCLUDE_DIRS}
        ${HITLS_ROOT_PATH}/include/crypto
        ${HITLS_ROOT_PATH}/include/bsl
        ${HITLS_ROOT_PATH}/bsl/err/include
        ${HITLS_ROOT_PATH}/config/macro_config
        ${HITLS_ROOT_PATH}/conf/macro_config
        ${HITLS_ROOT_PATH}/crypto/eal/src
        ${HITLS_ROOT_PATH}/crypto/include
        ${HITLS_ROOT_PATH}/crypto/sm3/include
        ${HITLS_ROOT_PATH}/bsl/sal/include
        ${HITLS_ROOT_PATH}/bsl/include
)

foreach(src ${PROVIDER_SOURCES})
    get_filename_component(filename ${src} NAME)
    set_source_files_properties(${src} PROPERTIES
        COMPILE_DEFINITIONS "__FILENAME__=\"${filename}\""
    )
endforeach()

target_compile_definitions(pqcp_provider PRIVATE
    HITLS_CRYPTO_EAL
    HITLS_CRYPTO_PKEY
    HITLS_CRYPTO_MD
    HITLS_CRYPTO_SM3
    HITLS_CRYPTO_CIPHER
    HITLS_CRYPTO_MAC
    HITLS_NO_CONFIG_CHECK
    ${PQCP_NEV_PROVIDER_DEFINITION}
    ${PQCP_NEV_DISPATCH_DEFINITION}
    ${PQCP_NEV_PROVIDER_SVE2_DEFINITION}
)

if(PQCP_ENABLE_AIGIS_SIG)
    target_compile_definitions(pqcp_provider PRIVATE PQCP_AIGIS_SIG)
    if(PQCP_AIGIS_SIG_ARMV8)
        target_compile_definitions(pqcp_provider PRIVATE PQCP_AIGIS_SIG_ARMV8_BACKEND)
    else()
        target_compile_definitions(pqcp_provider PRIVATE PQCP_AIGIS_SIG_PORTABLE_BACKEND)
    endif()
else()
    target_compile_options(pqcp_provider PRIVATE -UPQCP_AIGIS_SIG)
endif()

if(NOT PQCP_HIAE_SUPPORTED)
    target_compile_options(pqcp_provider PRIVATE -UPQCP_HIAE)
endif()

foreach(src ${HIAE_SOURCES})
    if(PQCP_HIAE_SUPPORTED)
        set_source_files_properties(${src} PROPERTIES COMPILE_OPTIONS "${PQCP_HIAE_COMPILE_OPTIONS}")
    endif()
endforeach()

foreach(src ${PQCP_AIGIS_SIG_SOURCES})
    set_property(SOURCE ${src} APPEND PROPERTY COMPILE_OPTIONS "-fvisibility=hidden")
endforeach()

# 新增：目标链接目录
target_link_directories(pqcp_provider PRIVATE
    ${HITLS_LIB_DIR}
)

message(STATUS "hitls_crypto: ${HITLS_CRYPTO_LIB}")
message(STATUS "hitls_bsl: ${HITLS_BSL_LIB}")
message(STATUS "HITLS_ROOT_PATH: ${HITLS_ROOT_PATH}")

target_link_libraries(pqcp_provider
    hitls_bsl
    hitls_crypto
)

if(PQCP_BUILD_NEV_BENCHMARK)
    if(NOT PQCP_ENABLE_NEV)
        message(FATAL_ERROR "PQCP_BUILD_NEV_BENCHMARK=ON requires PQCP_ENABLE_NEV=ON")
    endif()
    if(NOT PQCP_LIB_TYPE STREQUAL "SHARED")
        message(FATAL_ERROR "PQCP_BUILD_NEV_BENCHMARK=ON requires PQCP_LIB_TYPE=SHARED")
    endif()
    add_subdirectory(testcode/benchmark)
endif()

# 在文件末尾添加以下内容
add_custom_target(clean-all
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E remove
        *.log
        *.tmp
        *.bak
    COMMENT "Cleaning all build artifacts and temporary files"
)
set_target_properties(pqcp_provider PROPERTIES POSITION_INDEPENDENT_CODE ON)
# 可选：添加文档说明
set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_CLEAN_FILES
    "*.log"
    "*.tmp"
    "*.bak"
)
