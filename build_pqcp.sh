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

# 添加项目根目录定义
PQCP_ROOT_DIR=$(cd $(dirname $0)/; pwd)
echo $PQCP_ROOT_DIR

# 配置选项
OPTIONS=""
BUILD_TYPE="Release"
ENABLE_ASAN="OFF"
ENABLE_GCOV="OFF"
OPENHITLS_DIR="platform/openhitls"
OPENHITLS_REF="openhitls-0.4.0-alpha2"
OPENHITLS_REPO="${OPENHITLS_REPO:-https://gitcode.com/openHiTLS/openhitls.git}"
LIB_TYPE="SHARED"
CUSTOM_HITLS_DIR=""

ENABLED_ALGORITHMS=""    # --enable 指定的算法列表
DISABLED_ALGORITHMS=""   # --disable 指定的算法列表
ALGO_FLAGS=""            # 生成的算法宏定义编译选项
BUILD_ARGS=""
DEL_ARGS=""
PQCP_ENABLE_NEV="ON"
PQCP_NEV_ENABLE_NEON="OFF"
PQCP_NEV_ENABLE_SVE2="OFF"
PQCP_NEV_ENABLE_SVE2_SHA3="OFF"
PQCP_NEV_HASH_BACKEND="SHA3"
PQCP_NEV_CUSTOM_HASH_SOURCES=""
PQCP_NEV_CUSTOM_HASH_INCLUDE_DIRS=""

get_build_jobs()
{
    if command -v nproc >/dev/null 2>&1; then
        nproc
    elif command -v sysctl >/dev/null 2>&1; then
        sysctl -n hw.logicalcpu
    else
        getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1
    fi
}

normalize_algorithm_name()
{
    echo "$1" | tr '[:upper:]-' '[:lower:]_'
}

list_available_algorithms()
{
    local algorithms=""
    for algo_dir in "${PQCP_ROOT_DIR}"/src/*; do
        if [ -d "${algo_dir}/src" ]; then
            algorithms="${algorithms} $(normalize_algorithm_name "$(basename "${algo_dir}")")"
        fi
    done
    echo "${algorithms}"
}

algo_to_macro()
{
    local algo=$(normalize_algorithm_name "$1")
    local upper=$(echo "${algo}" | tr '[:lower:]' '[:upper:]')
    echo "PQCP_${upper}"
}

is_algorithm_enabled()
{
    local target=$(normalize_algorithm_name "$1")
    if [ -n "${ENABLED_ALGORITHMS}" ]; then
        for algo in ${ENABLED_ALGORITHMS}; do
            if [ "${algo}" = "${target}" ]; then
                return 0
            fi
        done
        return 1
    fi
    for algo in ${DISABLED_ALGORITHMS}; do
        if [ "${algo}" = "${target}" ]; then
            return 1
        fi
    done
    return 0
}

generate_algo_flags()
{
    local flags=""
    local all_algos=$(list_available_algorithms)
    for algo in ${all_algos}; do
            local macro=$(algo_to_macro "${algo}")
            flags="${flags} -D${macro}"
    done
    if [ -n "${ENABLED_ALGORITHMS}" ]; then
        # --enable 模式：只启用指定的算法
        # 先禁用所有算法
        for algo in ${all_algos}; do
            local macro=$(algo_to_macro "${algo}")
            flags="${flags} -U${macro}"
        done
        # 再启用指定的算法
        for algo in ${ENABLED_ALGORITHMS}; do
            local macro=$(algo_to_macro "${algo}")
            flags="${flags} -D${macro}"
        done
    elif [ -n "${DISABLED_ALGORITHMS}" ]; then
        # --disable 模式：禁用指定的算法
        for algo in ${DISABLED_ALGORITHMS}; do
            local macro=$(algo_to_macro "${algo}")
            flags="${flags} -U${macro}"
        done
    fi
    echo "${flags}"
}

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        debug)
            BUILD_TYPE="Debug"
            OPTIONS+="debug "
            shift
            ;;
        asan)
            ENABLE_ASAN="ON"
            OPTIONS+="asan "
            shift
            ;;
        gcov)
            ENABLE_GCOV="ON"
            shift
            ;;
        static)
            LIB_TYPE="STATIC"
            shift
            ;;
        --hitls_dir)
            if [[ -z "$2" || "$2" == -* ]]; then
                echo "错误: --hitls_dir 选项需要一个参数"
                exit 1
            fi
            if [ ! -d "$2" ]; then
                echo "错误: OpenHiTLS目录不存在: $2"
                exit 1
            fi
            CUSTOM_HITLS_DIR=$(realpath "$2")
            shift 2
            ;;
        --enable)
            shift
            while [[ -n $1 && ! $1 =~ ^-- ]]; do
                ENABLED_ALGORITHMS="${ENABLED_ALGORITHMS} $(normalize_algorithm_name "$1")"
                shift
            done
            ;;
        --disable)
            shift
            while [[ -n $1 && ! $1 =~ ^-- ]]; do
                DISABLED_ALGORITHMS="${DISABLED_ALGORITHMS} $(normalize_algorithm_name "$1")"
                shift
            done
            ;;
        --build_args)
           shift
           while [[ -n $1 && ! $1 =~ ^-- ]]; do
               BUILD_ARGS="${BUILD_ARGS} $1"
               shift
           done
           ;;
        --nev-neon)
            PQCP_NEV_ENABLE_NEON="ON"
            shift
            ;;
        --nev-sve2)
            PQCP_NEV_ENABLE_NEON="ON"
            PQCP_NEV_ENABLE_SVE2="ON"
            shift
            ;;
        --nev-sve2-sha3)
            PQCP_NEV_ENABLE_NEON="ON"
            PQCP_NEV_ENABLE_SVE2="ON"
            PQCP_NEV_ENABLE_SVE2_SHA3="ON"
            shift
            ;;
        --nev-hash-backend)
            if [[ -z "$2" || "$2" == -* ]]; then
                echo "错误: --nev-hash-backend 选项需要一个参数"
                exit 1
            fi
            PQCP_NEV_HASH_BACKEND=$(echo "$2" | tr '[:lower:]' '[:upper:]')
            if [[ "${PQCP_NEV_HASH_BACKEND}" != "SHA3" &&
                  "${PQCP_NEV_HASH_BACKEND}" != "SM3" &&
                  "${PQCP_NEV_HASH_BACKEND}" != "CUSTOM" ]]; then
                echo "错误: NEV Hash/KDF后端仅支持 sha3、sm3 或 custom"
                exit 1
            fi
            shift 2
            ;;
        --nev-custom-hash-source)
            if [[ -z "$2" || "$2" == -* || ! -f "$2" ]]; then
                echo "错误: --nev-custom-hash-source 需要一个存在的源文件"
                exit 1
            fi
            CUSTOM_SOURCE=$(realpath "$2")
            if [ -n "${PQCP_NEV_CUSTOM_HASH_SOURCES}" ]; then
                PQCP_NEV_CUSTOM_HASH_SOURCES="${PQCP_NEV_CUSTOM_HASH_SOURCES};${CUSTOM_SOURCE}"
            else
                PQCP_NEV_CUSTOM_HASH_SOURCES="${CUSTOM_SOURCE}"
            fi
            shift 2
            ;;
        --nev-custom-hash-include)
            if [[ -z "$2" || "$2" == -* || ! -d "$2" ]]; then
                echo "错误: --nev-custom-hash-include 需要一个存在的目录"
                exit 1
            fi
            CUSTOM_INCLUDE=$(realpath "$2")
            if [ -n "${PQCP_NEV_CUSTOM_HASH_INCLUDE_DIRS}" ]; then
                PQCP_NEV_CUSTOM_HASH_INCLUDE_DIRS="${PQCP_NEV_CUSTOM_HASH_INCLUDE_DIRS};${CUSTOM_INCLUDE}"
            else
                PQCP_NEV_CUSTOM_HASH_INCLUDE_DIRS="${CUSTOM_INCLUDE}"
            fi
            shift 2
            ;;
        --help|-h)
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  debug              构建Debug版本"
            echo "  asan               启用AddressSanitizer"
            echo "  static             构建静态库"
            echo "  --hitls_dir PATH   指定OpenHiTLS目录"
            echo "  --enable algo...   只启用指定的算法（如: polarlac scloudplus）"
            echo "  --disable algo...  禁用指定的算法"
            echo "  --build_args ARGS  传递额外的编译参数（如: --build_args "-g -O0"）"
            echo "  --nev-neon         编译NEV的可选ARMv8汇编实现（仅AArch64，兼容选项名）"
            echo "  --nev-sve2         编译时选择256-bit SVE2 NEV和SHA3实现（仅AArch64）"
            echo "  --nev-sve2-sha3    启用NEON x1/x2与SVE2 x4混合SHA3优化（仅AArch64）"
            echo "  --nev-hash-backend BACKEND  选择NEV Hash/KDF后端: sha3(默认)、sm3、custom"
            echo "  --nev-custom-hash-source FILE  添加CUSTOM后端源文件，可重复指定"
            echo "  --nev-custom-hash-include DIR  添加CUSTOM后端头文件目录，可重复指定"
            echo "  --help, -h         显示帮助信息"
            echo ""
            echo "可用的算法: $(list_available_algorithms)"
            echo ""
            echo "示例:"
            echo "  $0                                 # 构建所有算法"
            echo "  $0 --enable polarlac scloudplus   # 只启用polarlac和scloudplus"
            echo "  $0 --disable polarlac             # 禁用polarlac"
            echo "  $0 --nev-hash-backend sm3         # 构建可用ICCS KAT验证的SM3配置"
            exit 0
            ;;
        *)
            echo "未知参数: $1"
            echo "使用 --help 查看帮助"
            exit 1
            ;;
    esac
done

# 生成算法宏定义编译选项
ALGO_FLAGS=$(generate_algo_flags)
if is_algorithm_enabled "aigis_sig"; then
    PQCP_ENABLE_AIGIS_SIG="ON"
else
    PQCP_ENABLE_AIGIS_SIG="OFF"
fi

if is_algorithm_enabled "nev"; then
    PQCP_ENABLE_NEV="ON"
else
    PQCP_ENABLE_NEV="OFF"
fi
if [ -n "${ALGO_FLAGS}" ]; then
    echo "======================================================================"
    echo "算法裁剪选项:"
    if [ -n "${ENABLED_ALGORITHMS}" ]; then
        echo "  启用算法: ${ENABLED_ALGORITHMS}"
    fi
    if [ -n "${DISABLED_ALGORITHMS}" ]; then
        echo "  禁用算法: ${DISABLED_ALGORITHMS}"
    fi
    echo "  编译标志: ${ALGO_FLAGS}"
    echo "======================================================================"
fi

# 创建全新构建目录
echo "准备全新构建环境..."
rm -rf "${PQCP_ROOT_DIR}/build"
mkdir -p "${PQCP_ROOT_DIR}/build"
if [ -n "${ALGO_FLAGS}" ]; then
    echo "${ALGO_FLAGS}" > "${PQCP_ROOT_DIR}/build/macro.txt"
fi
cd "${PQCP_ROOT_DIR}/build" || exit

build_depend_code()
{
    if [ ! -d "${PQCP_ROOT_DIR}/${OPENHITLS_DIR}" ]; then
        echo "下载OpenHiTLS..."
        mkdir -p "${PQCP_ROOT_DIR}/platform"  # 确保父目录存在
        git clone --depth 1 --branch "${OPENHITLS_REF}" "${OPENHITLS_REPO}" "${PQCP_ROOT_DIR}/${OPENHITLS_DIR}"
    fi
    # 构建OpenHiTLS
    echo "构建OpenHiTLS..."
    if [ ! -d "${PQCP_ROOT_DIR}/platform/openhitls/build" ]; then
        mkdir -p ${PQCP_ROOT_DIR}/platform/openhitls/build
        cd ${PQCP_ROOT_DIR}/platform/openhitls/testcode/script
        bash build_hitls.sh ${OPTIONS} shared
        cd -
    fi
}

if [ -n "$CUSTOM_HITLS_DIR" ]; then
    HITLS_ROOT_PATH="$CUSTOM_HITLS_DIR"
else
    build_depend_code
    HITLS_ROOT_PATH="${PQCP_ROOT_DIR}/${OPENHITLS_DIR}"
fi

if [ -f "${HITLS_ROOT_PATH}/build/macro.txt" ]; then
    echo "[INFO] Found macro.txt, loading macros..."
    BUILD_ARGS="$(cat ${HITLS_ROOT_PATH}/build/macro.txt) ${BUILD_ARGS}"
fi
# 运行CMake配置
echo "生成构建系统..."
echo "BUILD ARGS: ${BUILD_ARGS}"
cmake .. \
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
    -DENABLE_ASAN=${ENABLE_ASAN} \
    -DENABLE_GCOV=${ENABLE_GCOV} \
    -DPQCP_ENABLE_NEV=${PQCP_ENABLE_NEV} \
    -DPQCP_NEV_ENABLE_NEON=${PQCP_NEV_ENABLE_NEON} \
    -DPQCP_NEV_ENABLE_SVE2=${PQCP_NEV_ENABLE_SVE2} \
    -DPQCP_NEV_ENABLE_SVE2_SHA3=${PQCP_NEV_ENABLE_SVE2_SHA3} \
    -DPQCP_NEV_HASH_BACKEND=${PQCP_NEV_HASH_BACKEND} \
    -DPQCP_NEV_CUSTOM_HASH_SOURCES="${PQCP_NEV_CUSTOM_HASH_SOURCES}" \
    -DPQCP_NEV_CUSTOM_HASH_INCLUDE_DIRS="${PQCP_NEV_CUSTOM_HASH_INCLUDE_DIRS}" \
    -DCMAKE_C_FLAGS="${ALGO_FLAGS}" \
    -DPQCP_ENABLE_AIGIS_SIG="${PQCP_ENABLE_AIGIS_SIG}" \
    -DUSER_BUILD_ARGS="${BUILD_ARGS}" \
    -DHITLS_ROOT_PATH="${HITLS_ROOT_PATH}" \
    -DPQCP_LIB_TYPE=${LIB_TYPE}

# 编译项目
echo "开始编译..."
make -j"$(get_build_jobs)"
echo $HITLS_ROOT_PATH > base_path.txt
echo "构建完成！"
