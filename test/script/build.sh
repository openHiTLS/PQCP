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

# PQCP测试构建脚本

# 默认参数
BUILD_TYPE="Debug"
ENABLE_ASAN=0
ENABLE_GCOV=0
BUILD_DIR="build"
INSTALL_DIR="install"
VERBOSE=0
BUILD_TARGETS="all"

# 添加项目根目录定义
PQCP_ROOT_DIR=$(cd $(dirname $0)/../; pwd)
BUILD_DIR="${PQCP_ROOT_DIR}/build"

# 强制清理旧构建
echo "▌清理旧构建文件..."
rm -rf "${BUILD_DIR}/CMakeCache.txt"
rm -rf "${BUILD_DIR}/CMakeFiles"
rm -rf "${BUILD_DIR}/bin"
rm -rf "${BUILD_DIR}/lib"

# 创建新构建目录
echo "▌准备全新构建环境..."
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}" || exit 1

# 显示帮助信息
show_help() {
    echo "PQCP测试构建脚本"
    echo "用法: $0 [选项]"
    echo "选项:"
    echo "  --help, -h              显示帮助信息"
    echo "  --release               构建发布版本（默认为Debug）"
    echo "  --asan                  启用AddressSanitizer"
    echo "  --gcov                  启用代码覆盖率分析"
    echo "  --build-dir=<dir>       指定构建目录（默认为build）"
    echo "  --install-dir=<dir>     指定安装目录（默认为install）"
    echo "  --verbose               显示详细构建信息"
    echo "  --targets=<targets>     指定构建目标（默认为all）"
    echo "                          可选值: all, sdv, perf, fuzz, demo"
}

# 解析命令行参数
for arg in "$@"; do
    case $arg in
        --help|-h)
            show_help
            exit 0
            ;;
        --release)
            BUILD_TYPE="Release"
            shift
            ;;
        --asan)
            ENABLE_ASAN=1
            shift
            ;;
        --gcov)
            ENABLE_GCOV=1
            shift
            ;;
        --build-dir=*)
            BUILD_DIR="${arg#*=}"
            shift
            ;;
        --install-dir=*)
            INSTALL_DIR="${arg#*=}"
            shift
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
        --targets=*)
            BUILD_TARGETS="${arg#*=}"
            shift
            ;;
        *)
            echo "未知选项: $arg"
            show_help
            exit 1
            ;;
    esac
done

# 创建构建目录
cd ..
mkdir -p $BUILD_DIR
cd $BUILD_DIR || exit 1
echo "当前目录: $PWD"

# 构建CMake命令
CMAKE_ARGS="-DCMAKE_BUILD_TYPE=$BUILD_TYPE"
CMAKE_ARGS="$CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=../$INSTALL_DIR"

if [ $ENABLE_ASAN -eq 1 ]; then
    CMAKE_ARGS="$CMAKE_ARGS -DENABLE_ASAN=ON"
fi

if [ $ENABLE_GCOV -eq 1 ]; then
    CMAKE_ARGS="$CMAKE_ARGS -DENABLE_GCOV=ON"
fi

if [ "$BUILD_TARGETS" != "all" ]; then
    CMAKE_ARGS="$CMAKE_ARGS -DBUILD_TARGETS=$BUILD_TARGETS"
fi

# 构建项目
echo "构建PQCP测试项目..."
if [ $VERBOSE -eq 1 ]; then
    cmake .. $CMAKE_ARGS
else
    cmake .. $CMAKE_ARGS > /dev/null
fi

make -j$(nproc)

echo "PQCP测试构建完成！"
echo "构建类型: $BUILD_TYPE"
echo "构建目录: $BUILD_DIR"
echo "安装目录: $INSTALL_DIR"
echo "构建目标: $BUILD_TARGETS"
if [ $ENABLE_ASAN -eq 1 ]; then
    echo "已启用AddressSanitizer"
fi
if [ $ENABLE_GCOV -eq 1 ]; then
    echo "已启用代码覆盖率分析"
fi 