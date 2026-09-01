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

add_executable(pqcp_nev_benchmark nev_bench.c)
add_dependencies(pqcp_nev_benchmark pqcp_provider)

target_include_directories(pqcp_nev_benchmark PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${HITLS_ROOT_PATH}/include/crypto
    ${HITLS_ROOT_PATH}/include/bsl
)

target_compile_definitions(pqcp_nev_benchmark PRIVATE
    PQCP_BENCH_PROVIDER_PATH="${CMAKE_BINARY_DIR}"
)
target_compile_options(pqcp_nev_benchmark PRIVATE -Wall -Wextra -Werror)

target_link_directories(pqcp_nev_benchmark PRIVATE
    ${HITLS_LIB_DIR}
)
target_link_libraries(pqcp_nev_benchmark PRIVATE
    hitls_crypto
    hitls_bsl
)

if(UNIX AND NOT APPLE)
    target_link_libraries(pqcp_nev_benchmark PRIVATE dl pthread)
    target_link_options(pqcp_nev_benchmark PRIVATE -Wl,-z,noexecstack)
endif()

set_target_properties(pqcp_nev_benchmark PROPERTIES
    BUILD_RPATH "${HITLS_LIB_DIR}"
)
