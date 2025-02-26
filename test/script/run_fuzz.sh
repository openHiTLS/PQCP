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
# PQCP模糊测试执行脚本

# 默认参数
OUTPUT_DIR="output/fuzz"
ITERATIONS=1000
SEED=0
VERBOSE=0
TEST_TARGETS=""

# 显示帮助信息
show_help() {
    echo "PQCP模糊测试执行脚本"
    echo "用法: $0 [选项] [测试目标...]"
    echo "选项:"
    echo "  --help, -h              显示帮助信息"
    echo "  --output-dir=<dir>      指定输出目录（默认为output/fuzz）"
    echo "  --iterations=<num>      指定迭代次数（默认为1000）"
    echo "  --seed=<num>            指定随机种子（默认为0，使用时间作为种子）"
    echo "  --verbose               显示详细测试信息"
    echo "  --list                  列出所有可用的模糊测试目标"
    echo ""
    echo "示例:"
    echo "  $0                      运行所有模糊测试"
    echo "  $0 kem                  运行KEM模糊测试"
    echo "  $0 kem sign             运行KEM和Sign模糊测试"
    echo "  $0 --iterations=10000 kem 运行KEM模糊测试，迭代10000次"
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
        --iterations=*)
            ITERATIONS="${1#*=}"
            shift
            ;;
        --seed=*)
            SEED="${1#*=}"
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
            # 假设是测试目标
            if [[ -z "$TEST_TARGETS" ]]; then
                TEST_TARGETS="$1"
            else
                TEST_TARGETS="$TEST_TARGETS $1"
            fi
            shift
            ;;
    esac
done

# 创建输出目录
mkdir -p $OUTPUT_DIR

# 设置可执行文件路径
EXECUTABLE="./build/bin/pqcp_fuzz_test"

# 检查可执行文件是否存在
if [ ! -f "$EXECUTABLE" ]; then
    echo "错误: 找不到模糊测试可执行文件 $EXECUTABLE"
    echo "请先运行 build.sh 构建测试项目"
    exit 1
fi

# 列出所有测试
if [ ! -z ${LIST_TESTS+x} ]; then
    echo "列出所有可用的模糊测试目标:"
    $EXECUTABLE --list
    exit 0
fi

# 构建命令行参数
ARGS="--output-dir=$OUTPUT_DIR --iterations=$ITERATIONS --seed=$SEED"

if [ $VERBOSE -eq 1 ]; then
    ARGS="$ARGS --verbose"
fi

# 运行测试
echo "运行PQCP模糊测试..."

if [ -z "$TEST_TARGETS" ]; then
    # 运行所有测试
    echo "运行所有模糊测试目标"
    $EXECUTABLE $ARGS
else
    # 运行指定的测试目标
    for target in $TEST_TARGETS; do
        echo "运行模糊测试目标: $target"
        $EXECUTABLE $ARGS --target=$target
    done
fi

# 检查测试结果
if [ $? -eq 0 ]; then
    echo "模糊测试完成！"
    echo "结果保存在: $OUTPUT_DIR"
    exit 0
else
    echo "模糊测试失败！"
    echo "失败的测试用例保存在: $OUTPUT_DIR"
    exit 1
fi 