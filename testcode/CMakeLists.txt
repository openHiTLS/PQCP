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
project(pqcp_test C)


set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(PQCP_ROOT "${PROJECT_SOURCE_DIR}/..")
set(HITLS_ROOT_DIR "${PQCP_ROOT}/platform/openhitls")
# 设置输出目录
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

find_package(Threads REQUIRED)

# 设置编译选项
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g3 -O0 -Wall -Wextra")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wextra")
endif()

# 启用AddressSanitizer（如果需要）
if(ENABLE_ASAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
endif()

# 启用代码覆盖率分析（如果需要）
if(ENABLE_GCOV)
    message(STATUS "Enabling gcov code coverage flags")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lgcov --coverage")
endif()

# 设置依赖库搜索路径
set(PQCP_DEPENDENCY_DIRS
        ${CMAKE_SOURCE_DIR}/../platform/openhitls/build
        ${CMAKE_SOURCE_DIR}/../platform/openhitls/platform/Secure_C/lib
        ${CMAKE_SOURCE_DIR}/../build
    CACHE STRING "PQCP dependency library paths")

# 查找依赖库
find_library(HITLS_CRYPTO_LIB hitls_crypto 
    PATHS ${PQCP_DEPENDENCY_DIRS}
    NO_DEFAULT_PATH)
find_library(HITLS_BSL_LIB hitls_bsl 
    PATHS ${PQCP_DEPENDENCY_DIRS}
    NO_DEFAULT_PATH)
find_library(SECUREC_LIB boundscheck
    PATHS ${PQCP_DEPENDENCY_DIRS}
    NO_DEFAULT_PATH)
find_library(PQCP_PROVIDER_LIB pqcp_provider
    PATHS ${PQCP_DEPENDENCY_DIRS}
    NO_DEFAULT_PATH)

# 验证库是否存在
foreach(LIB IN ITEMS 
    HITLS_CRYPTO_LIB 
    HITLS_BSL_LIB 
    SECUREC_LIB
    PQCP_PROVIDER_LIB)
    if(NOT ${LIB})
        message(FATAL_ERROR "Required library ${LIB} not found in: ${PQCP_DEPENDENCY_DIRS}")
    endif()
endforeach()
add_compile_options(-Wall -Wextra -Werror)
# 包含目录
include_directories(
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/../include
    ${CMAKE_SOURCE_DIR}/../src/scloudplus/include
    ${CMAKE_SOURCE_DIR}/../src/scloudplus/src
    ${CMAKE_SOURCE_DIR}/../src/classic_mceliece/include
    ${CMAKE_SOURCE_DIR}/../src/classic_mceliece/src
    ${CMAKE_SOURCE_DIR}/../src/frodokem/include
    ${CMAKE_SOURCE_DIR}/../src/frodokem/src
    ${CMAKE_SOURCE_DIR}/../platform/openhitls/include/bsl
    ${CMAKE_SOURCE_DIR}/../platform/openhitls/include/crypto
    ${CMAKE_SOURCE_DIR}/../platform/openhitls/platform/Secure_C/include
    ${CMAKE_SOURCE_DIR}/../src/hybrid_env/include
    ${CMAKE_SOURCE_DIR}/../src/hybrid_env/src
    ${CMAKE_SOURCE_DIR}/../src/composite_sign/include
    ${CMAKE_SOURCE_DIR}/../src/composite_sign/src
)

# 构建Demo
if(BUILD_DEMO)
    set(DEMO_OUTPUT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/output)
    file(GLOB DEMO_FILES "demo/*.c")
    foreach(DEMO_FILE ${DEMO_FILES})
        get_filename_component(DEMO_NAME ${DEMO_FILE} NAME_WE)
        add_executable(${DEMO_NAME} ${DEMO_FILE} ${COMMON_SOURCES})
        set_target_properties(${DEMO_NAME} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${DEMO_OUTPUT_DIR}/demo
        )
        target_link_libraries(${DEMO_NAME} 
            ${PQCP_LIBRARY}
            ${HITLS_CRYPTO_LIB}
            ${HITLS_BSL_LIB}
            ${PQCP_PROVIDER_LIB}
            Threads::Threads
            ${SECUREC_LIB})
        install(TARGETS ${DEMO_NAME} DESTINATION ../output)
    endforeach()
endif()

include(ExternalProject)

ExternalProject_Add(gen_testcase
    SOURCE_DIR            ${PQCP_ROOT}
    PREFIX                ""
    BINARY_DIR            ${PQCP_ROOT}/testcode/framework/gen_test/build/
    INSTALL_DIR           ""
    UPDATE_COMMAND        ""
    CONFIGURE_COMMAND     cmake -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS} -DPRINT_TO_TERMINAL=${ENABLE_PRINT} ..
    BUILD_COMMAND         make
    INSTALL_COMMAND       ""
    BUILD_ALWAYS          FALSE
    LOG_BUILD             TRUE
    LOG_DOWNLOAD          TRUE
    EXCLUDE_FROM_ALL      TRUE
    LOG_OUTPUT_ON_FAILURE TRUE
)

add_subdirectory(sdv)
