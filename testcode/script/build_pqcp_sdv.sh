#!/bin/bash

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
set -e

# PQCP SDV测试构建脚本 - 复用OpenHiTLS测试框架
# 该脚本将PQCP测试文件集成到OpenHiTLS测试框架中构建

usage()
{
    printf "\n"
    printf "%-05s %-30s\n" "* Script :"                                        "${BASH_SOURCE[0]}"
    printf "%-50s %-30s\n" "* Usage Option :"                                  ""
    printf "%-50s %-30s\n" "* --help|-h    : Help information."                ""
    printf "%-50s %-30s\n" "* asan         : Enable AddressSanitizer."         "bash ${BASH_SOURCE[0]} asan"
    printf "%-50s %-30s\n" "* gcov         : Enable coverage capability."      "bash ${BASH_SOURCE[0]} gcov"
    printf "%-50s %-30s\n" "* verbose      : Show details."                    "bash ${BASH_SOURCE[0]} verbose"
    printf "%-50s %-30s\n" "* run-tests    : Run specific test suites."        "bash ${BASH_SOURCE[0]} run-tests=suite1|suite2"
    printf "%-50s %-30s\n" "* list-suites  : List available PQCP test suites." "bash ${BASH_SOURCE[0]} list-suites"
    printf "%-50s %-30s\n" "* clean        : Clean build artifacts."           "bash ${BASH_SOURCE[0]} clean"
}

# 设置环境变量
export_env()
{
    # PQCP根目录
    PQCP_ROOT_DIR=$(cd $(dirname ${BASH_SOURCE[0]})/../.. && pwd)
    export PQCP_ROOT_DIR

    # OpenHiTLS根目录
    if [ -f ${PQCP_ROOT_DIR}/build/base_path.txt ];then
        HITLS_ROOT_DIR=$(cat ${PQCP_ROOT_DIR}/build/base_path.txt)
    else
        HITLS_ROOT_DIR=${PQCP_ROOT_DIR}/platform/openhitls
    fi
    export HITLS_ROOT_DIR

    # PQCP测试目录
    PQCP_TEST_DIR="${PQCP_ROOT_DIR}/testcode/sdv"
    export PQCP_TEST_DIR

    # PQCP provider目录
    PQCP_PROVIDER_DIR="${PQCP_ROOT_DIR}/build"
    export PQCP_PROVIDER_DIR

    # 构建选项
    ENABLE_ASAN="OFF"
    ENABLE_GCOV="OFF"
    ENABLE_VERBOSE=""
    BUILD_DEMO="ON"
    RUN_TESTS=""
    BUILD_OPTIONS=""
}

# 检查依赖
check_dependencies()
{
    # 检查HiTLS是否存在
    if [ ! -d "${HITLS_ROOT_DIR}" ]; then
        echo "[ERROR] HiTLS directory not found: ${HITLS_ROOT_DIR}"
        exit 1
    fi

    # 检查PQCP provider是否存在
    if [ ! -f "${PQCP_PROVIDER_DIR}/libpqcp_provider.so" ]; then
        echo "[WARNING] PQCP provider not found: ${PQCP_PROVIDER_DIR}/libpqcp_provider.so"
        echo "[INFO] Please build PQCP first: ./build_pqcp.sh"
        exit 1
    fi
}

# 查找PQCP测试套件
find_pqcp_test_suites()
{
    local test_suites=""
    if [ -d "${PQCP_TEST_DIR}" ]; then
        # 查找所有.data文件
        local data_files=$(find "${PQCP_TEST_DIR}" -name "*.data" 2>/dev/null)
        for file in $data_files; do
            local suite_name=$(basename "$file" .data)
            local dir_name=$(basename $(dirname "$file"))
            test_suites="${test_suites}${dir_name}/${suite_name} "
        done
    fi
    echo "${test_suites}"
}

# 查找PQCP测试源文件
find_pqcp_test_sources()
{
    local test_sources=""
    if [ -d "${PQCP_TEST_DIR}" ]; then
        while IFS= read -r -d '' file; do
            test_sources="${test_sources}${file} "
        done < <(find "${PQCP_TEST_DIR}" -name "*.c" -print0 2>/dev/null)
    fi
    echo "${test_sources}"
}

# 列出可用的测试套件
list_test_suites()
{
    echo "======================================================================"
    echo "Available PQCP Test Suites:"
    echo "======================================================================"

    local suites=$(find_pqcp_test_suites)
    if [ -z "$suites" ]; then
        echo "[INFO] No test suites found in ${PQCP_TEST_DIR}"
        echo "[INFO] Please create .data files in test/sdv subdirectories"
        return 0
    fi

    for suite in $suites; do
        echo "  - ${suite}"
    done
    echo ""
    echo "[INFO] Total: $(echo $suites | wc -w) test suite(s)"
}

# 构建PQCP SDV测试
build_pqcp_sdv()
{
    local all_suites=""
    # 指定测试套件
    if [ -n "${RUN_TESTS}" ]; then
        local tmp=($(echo "${RUN_TESTS}" | tr -s "|" " "))
        for i in ${!tmp[@]}
        do
            local suite=$(find ${PQCP_ROOT_DIR}/testcode/sdv -name "${tmp[i]}.data" | sed -e "s/.data//")
            [[ -z "${suite}" ]] && echo "not found testsuite:${tmp[i]}" && exit 1
            [[ -n "${suite}" ]] && all_suites="${suite} ${all_suites}"
        done
    else
        # 自动发现所有PQCP测试套件
        local data_files=$(find "${PQCP_TEST_DIR}" -name "*.data" 2>/dev/null)
        echo "data_files: ${data_files}"
        for file in $data_files; do
            local suite_path=$(realpath "${file}" | sed 's/\.data$//')
            if [ -z "$all_suites" ]; then
                all_suites="${suite_path}"
            else
                all_suites="${all_suites} ${suite_path}"
            fi
        done
    fi
    echo "HILTS_ROOT_DIR: ${HITLS_ROOT_DIR}"
    if [ -f "${HITLS_ROOT_DIR}/build/macro.txt" ]; then
        echo "[INFO] Found macro.txt, loading macros..."
        MACROS="$(cat ${HITLS_ROOT_DIR}/build/macro.txt)"
    else
        echo "[WARNING] macro.txt not found, proceeding without additional macros."
    fi
    echo "======================================================================"
    echo "Building PQCP SDV Tests with OpenHiTLS Framework"
    echo "======================================================================"
    cd ${PQCP_ROOT_DIR}/testcode && rm -rf ./build && mkdir build && cd build
    echo "Find test suites: ${all_suites}"
    cmake -DGEN_TEST_FILES="${all_suites}" -DCMAKE_C_FLAGS="${CMAKE_C_FLAGS} \
          -DPRINT_TO_TERMINAL=ON -g -O0" -DBUILD_DEMO=${BUILD_DEMO} -DENABLE_ASAN=${ENABLE_ASAN} \
          -DENABLE_GCOV=${ENABLE_GCOV} -DHITLS_ROOT_DIR=${HITLS_ROOT_DIR} -DMACROS="${MACROS}" \
          ..
    make -j$(nproc)
}

# 清理构建产物
clean()
{
    rm -rf ${PQCP_ROOT_DIR}/testcode/output/log
    rm -rf ${PQCP_ROOT_DIR}/testcode/output/test_suite*
    rm -rf ${PQCP_ROOT_DIR}/testcode/output/asan.*
    rm -rf ${PQCP_ROOT_DIR}/testcode/output/*.log
    rm -rf ${PQCP_ROOT_DIR}/testcode/output/*.xml
    rm -rf ${PQCP_ROOT_DIR}/testcode/output/demo/
    rm -rf ${PQCP_ROOT_DIR}/testcode/output/gen_testcase
    rm -rf ${PQCP_ROOT_DIR}/testcode/build
    rm -rf ${PQCP_ROOT_DIR}/testcode/sdv/build
    rm -rf ${PQCP_ROOT_DIR}/testcode/framework/gen_test/build
    mkdir -p ${PQCP_ROOT_DIR}/testcode/output/log
}

# 解析命令行参数
parse_options()
{
    while [[ -n $1 ]]; do
        key=${1%%=*}
        value=${1#*=}
        case ${key} in
            asan)
                ENABLE_ASAN="ON"
                ;;
            gcov)
                ENABLE_GCOV="ON"
                ;;
            verbose)
                ENABLE_VERBOSE="verbose"
                ;;
            no-demo)
                BUILD_DEMO="OFF"
                ;;
            run-tests)
                RUN_TESTS=${value}
                ;;
            list-suites)
                list_test_suites
                exit 0
                ;;
            clean)
                export_env
                clean
                exit 0
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: ${key}"
                usage
                exit 1
                ;;
        esac
        shift
    done
}

# 主函数
main()
{
    export_env
    parse_options "$@"
    clean
    check_dependencies
    build_pqcp_sdv
}

main "$@"
