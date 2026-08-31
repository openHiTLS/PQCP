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

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)

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

# 添加链接目录
if(PQCP_LIB_DIR)
    link_directories(${PQCP_LIB_DIR})
endif()

# Create shared library
add_library(pqcp_provider ${PQCP_LIB_TYPE} ${PROVIDER_SOURCES})

target_include_directories(pqcp_provider PRIVATE
    "${PQCP_AIGIS_SIG_DIR}/include"
    "${PQCP_AIGIS_SIG_DIR}/src"
)

if(USER_BUILD_ARGS)
    separate_arguments(USER_BUILD_ARGS)
    target_compile_options(pqcp_provider PRIVATE ${USER_BUILD_ARGS})
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
    ${HITLS_ROOT_PATH}/build
)

message(STATUS "hitls_crypto: ${HITLS_CRYPTO_LIB}")
message(STATUS "hitls_bsl: ${HITLS_BSL_LIB}")
message(STATUS "HITLS_ROOT_PATH: ${HITLS_ROOT_PATH}")

target_link_libraries(pqcp_provider
    hitls_bsl
    hitls_crypto
)

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
