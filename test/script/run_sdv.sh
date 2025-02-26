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
# PQCP SDV测试执行脚本

# 默认参数
OUTPUT_DIR="output"
VERBOSE=0
TEST_SUITES=""
TEST_CASES=""

# 显示帮助信息
show_help() {
    echo "PQCP SDV测试执行脚本"
    echo "用法: $0 [选项] [测试套件...] [测试用例...]"
    echo "选项:"
    echo "  --help, -h              显示帮助信息"
    echo "  --output-dir=<dir>      指定输出目录（默认为output）"
    echo "  --verbose               显示详细测试信息"
    echo "  --list                  列出所有可用的测试套件和测试用例"
    echo ""
    echo "示例:"
    echo "  $0                      运行所有测试"
    echo "  $0 kem                  运行KEM测试套件"
    echo "  $0 kem sign             运行KEM和Sign测试套件"
    echo "  $0 kem::kyber512        运行KEM测试套件中的kyber512测试用例"
}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            show_help
            exit 0
            ;;
        --output-dir=*)
            OUTPUT_DIR="${1#*=}"
            shift
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
        --list)
            LIST_TESTS=1
            shift
            ;;
        *)
            # 检查是否是测试套件::测试用例格式
            if [[ $1 == *::* ]]; then
                SUITE=$(echo $1 | cut -d':' -f1)
                CASE=$(echo $1 | cut -d':' -f3)
                
                if [[ -z "$TEST_SUITES" ]]; then
                    TEST_SUITES="$SUITE"
                else
                    # 检查套件是否已经在列表中
                    if [[ ! "$TEST_SUITES" =~ (^|[[:space:]])$SUITE($|[[:space:]]) ]]; then
                        TEST_SUITES="$TEST_SUITES $SUITE"
                    fi
                fi
                
                if [[ -z "$TEST_CASES" ]]; then
                    TEST_CASES="$SUITE::$CASE"
                else
                    TEST_CASES="$TEST_CASES $SUITE::$CASE"
                fi
            else
                # 假设是测试套件
                if [[ -z "$TEST_SUITES" ]]; then
                    TEST_SUITES="$1"
                else
                    TEST_SUITES="$TEST_SUITES $1"
                fi
            fi
            shift
            ;;
    esac
done

# 创建输出目录
mkdir -p $OUTPUT_DIR

# 设置可执行文件路径
EXECUTABLE="./build/bin/pqcp_sdv_test"

# 检查可执行文件是否存在
if [ ! -f "$EXECUTABLE" ]; then
    echo "错误: 找不到测试可执行文件 $EXECUTABLE"
    echo "请先运行 build.sh 构建测试项目"
    exit 1
fi

# 列出所有测试
if [ ! -z ${LIST_TESTS+x} ]; then
    echo "列出所有可用的测试套件和测试用例:"
    $EXECUTABLE --list
    exit 0
fi

# 构建命令行参数
ARGS="--output-dir=$OUTPUT_DIR"

if [ $VERBOSE -eq 1 ]; then
    ARGS="$ARGS --verbose"
fi

# 运行测试
echo "运行PQCP SDV测试..."

if [ -z "$TEST_SUITES" ]; then
    # 运行所有测试
    echo "运行所有测试套件"
    $EXECUTABLE $ARGS
else
    if [ -z "$TEST_CASES" ]; then
        # 运行指定的测试套件
        echo "运行测试套件: $TEST_SUITES"
        for suite in $TEST_SUITES; do
            echo "运行测试套件: $suite"
            $EXECUTABLE $ARGS --suite=$suite
        done
    else
        # 运行指定的测试用例
        for test_case in $TEST_CASES; do
            suite=$(echo $test_case | cut -d':' -f1)
            case=$(echo $test_case | cut -d':' -f3)
            echo "运行测试用例: $suite::$case"
            $EXECUTABLE $ARGS --suite=$suite --case=$case
        done
    fi
fi

# 检查测试结果
if [ $? -eq 0 ]; then
    echo "所有测试通过！"
    exit 0
else
    echo "测试失败！"
    exit 1
fi 