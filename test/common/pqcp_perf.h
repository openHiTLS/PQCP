/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

/**
 * @file pqcp_perf.h
 * @brief PQCP性能测试框架头文件
 */

#ifndef PQCP_PERF_H
#define PQCP_PERF_H

#include "pqcp_test.h"
#include <stdint.h>
#include <time.h>

/* 性能测试结果结构 */
typedef struct {
    const char *name;
    double elapsedTime;  /* 单位：毫秒 */
    uint64_t iterations;
    double opsPerSec;
    double avgTimePerOp;  /* 单位：微秒 */
} PqcpPerfResult;

/* 性能测试配置 */
typedef struct {
    uint64_t minIterations;  /* 最小迭代次数 */
    uint64_t maxIterations;  /* 最大迭代次数 */
    double minTime;          /* 最小测试时间（秒） */
    int32_t warmupIterations;     /* 预热迭代次数 */
} PqcpPerfConfig;

/* 默认性能测试配置 */
extern const PqcpPerfConfig PQCP_DEFAULT_PERF_CONFIG;

/**
 * 运行性能测试
 * 
 * @param name 测试名称
 * @param setupFunc 测试前的准备函数，可以为NULL
 * @param testFunc 测试函数
 * @param teardownFunc 测试后的清理函数，可以为NULL
 * @param config 性能测试配置，如果为NULL则使用默认配置
 * @param userData 用户数据，会传递给setupFunc、testFunc和teardownFunc
 * @param result 输出的性能测试结果
 * 
 * @return 0表示成功，其他值表示失败
 */
int32_t PQCP_PerfRun(
    const char *name,
    int32_t (*setupFunc)(void **userData),
    int32_t (*testFunc)(void *userData),
    void (*teardownFunc)(void *userData),
    const PqcpPerfConfig *config,
    void *userData,
    PqcpPerfResult *result
);

/**
 * 打印性能测试结果
 * 
 * @param result 性能测试结果
 */
void PQCP_PerfPrintResult(const PqcpPerfResult *result);

/**
 * 将性能测试结果写入CSV文件
 * 
 * @param result 性能测试结果
 * @param csvFile CSV文件路径
 * @param append 是否追加到文件末尾
 * 
 * @return 0表示成功，其他值表示失败
 */
int32_t PQCP_PerfWriteCSV(const PqcpPerfResult *result, const char *csvFile, int32_t append);

/**
 * 获取高精度时间戳（纳秒）
 * 
 * @return 当前时间戳（纳秒）
 */
uint64_t PQCP_PerfGetTimeNs(void);

#endif /* PQCP_PERF_H */ 