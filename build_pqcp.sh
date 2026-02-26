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
OPENHITLS_DIR="platform/openhitls"
LIB_TYPE="SHARED"
CUSTOM_HITLS_DIR=""
SECURE_C_DIR="platform/openhitls/platform/Secure_C"

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
        static)
            LIB_TYPE="STATIC"
            shift
            ;;
        --hitls_dir)
            if [[ -z "$2" || "$2" == -* ]]; then
                echo "错误: --hitls_dir 选项需要一个参数"
                exit 1
            fi
            CUSTOM_HITLS_DIR="$2"
            shift 2
            ;;
        *)
            echo "未知参数: $1"
            exit 1
            ;;
    esac
done

# 创建全新构建目录
echo "准备全新构建环境..."
rm -rf "${PQCP_ROOT_DIR}/build"
mkdir -p "${PQCP_ROOT_DIR}/build"
cd "${PQCP_ROOT_DIR}/build" || exit

build_depend_code()
{
    # 构建Secure_C
    echo "构建Secure_C..."
    if [ ! -f "${PQCP_ROOT_DIR}/${SECURE_C_DIR}/libboundscheck.a" ]; then
        cd "${PQCP_ROOT_DIR}/${SECURE_C_DIR}"
        make -j$(nproc)
        cd -
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

# 下载依赖
echo "检查依赖项..."
if [ ! -d "${PQCP_ROOT_DIR}/${OPENHITLS_DIR}" ]; then
    echo "下载OpenHiTLS..."
    mkdir -p "${PQCP_ROOT_DIR}/platform"  # 确保父目录存在
    git clone --recurse-submodules https://gitcode.com/openhitls/openhitls.git "${PQCP_ROOT_DIR}/${OPENHITLS_DIR}"
fi

build_depend_code
if [ -n "$CUSTOM_HITLS_DIR" ]; then
    HITLS_ROOT_PATH="$CUSTOM_HITLS_DIR"
else
    HITLS_ROOT_PATH="${PQCP_ROOT_DIR}/${OPENHITLS_DIR}"
fi

# 运行CMake配置
echo "生成构建系统..."
cmake .. \
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
    -DENABLE_ASAN=${ENABLE_ASAN} \
    -DCMAKE_PREFIX_PATH="${PQCP_ROOT_DIR}/${OPENHITLS_DIR};${PQCP_ROOT_DIR}/${SECURE_C_DIR}" \
    -DHITLS_ROOT_PATH="${HITLS_ROOT_PATH}" \
    -DPQCP_LIB_TYPE=${LIB_TYPE}

# 编译项目
echo "开始编译..."
make -j$(nproc)

echo "构建完成！"
