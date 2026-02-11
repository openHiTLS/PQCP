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

# 新增：自定义库路径变量
set(PQCP_LIB_DIR "" CACHE PATH "Custom library search path")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)

# 调试选项设置
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3 -O0")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -march=native")

# ASAN配置
if(ENABLE_ASAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
endif()

set(POLAR_LAC_SRC
    src/polarlac/src/polarlac.c
    src/polarlac/src/polarlac_poly.c
    src/polarlac/src/polarlac_pke.c
    src/polarlac/src/polarlac_kem.c
    src/polarlac/src/polarlac_ntt1024.c
    src/polarlac/src/polarlac_ntt.c
    src/polarlac/src/polarlac_polar.c
    src/polarlac/src/polarlac_rand.c
)

set(COMPOSITE_SIGN_SRC
    src/composite_sign/src/crypt_composite_sign_encdec.c
    src/composite_sign/src/crypt_composite_sign.c
)
# Set source files
set(PROVIDER_SOURCES
    src/provider/pqcp_provider.c
    src/provider/pqcp_pkey.c
    src/scloudplus/src/scloudplus.c
    src/scloudplus/src/scloudplus_util.c
    ${POLAR_LAC_SRC}
    ${COMPOSITE_SIGN_SRC}
)


# 添加链接目录
if(PQCP_LIB_DIR)
    link_directories(${PQCP_LIB_DIR})
endif()

# Create shared library
add_library(pqcp_provider SHARED ${PROVIDER_SOURCES})

target_include_directories(pqcp_provider
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/provider
        ${CMAKE_CURRENT_SOURCE_DIR}/src/scloudplus/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/polarlac/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/composite_sign/include
        ${OPENHITLS_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/openhitls/include/crypto
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/openhitls/include/bsl
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/openhitls/platform/Secure_C/include
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/openhitls/bsl/err/include
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/openhitls/config/macro_config
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/openhitls/crypto/eal/src
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/openhitls/crypto/include
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/openhitls/bsl/sal/include
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
)

# 新增：目标链接目录
target_link_directories(pqcp_provider PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/openhitls/build
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/openhitls/platform/Secure_C/lib
)

message(STATUS "hitls_crypto: ${HITLS_CRYPTO_LIB}")
message(STATUS "hitls_bsl: ${HITLS_BSL_LIB}")
message(STATUS "boundscheck: ${SECUREC_LIB}")

target_link_libraries(pqcp_provider
    hitls_bsl
    hitls_crypto
    boundscheck
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
