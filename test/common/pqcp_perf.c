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

#include "pqcp_perf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 默认性能测试配置 */
const PqcpPerfConfig PQCP_DEFAULT_PERF_CONFIG = {
    .minIterations = 10,
    .maxIterations = 1000000,
    .minTime = 1.0,  /* 至少运行1秒 */
    .warmupIterations = 3
};

/**
 * 获取高精度时间戳（纳秒）
 */
uint64_t PQCP_PerfGetTimeNs(void) {
    struct timespec ts;
    
#ifdef _WIN32
    /* Windows实现 */
    timespec_get(&ts, TIME_UTC);
#else
    /* POSIX实现 */
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/**
 * 运行性能测试
 */
int PQCP_PerfRun(
    const char *name,
    int (*setupFunc)(void **userData),
    int (*testFunc)(void *userData),
    void (*teardownFunc)(void *userData),
    const PqcpPerfConfig *config,
    void *userData,
    PqcpPerfResult *result
) {
    if (testFunc == NULL || result == NULL) {
        return -1;
    }
    
    /* 使用默认配置（如果未提供） */
    PqcpPerfConfig cfg = (config != NULL) ? *config : PQCP_DEFAULT_PERF_CONFIG;
    
    /* 初始化结果 */
    memset(result, 0, sizeof(PqcpPerfResult));
    result->name = name;
    
    /* 调用setup函数（如果提供） */
    if (setupFunc != NULL) {
        int ret = setupFunc(&userData);
        if (ret != 0) {
            return ret;
        }
    }
    
    /* 预热运行 */
    for (int i = 0; i < cfg.warmupIterations; i++) {
        testFunc(userData);
    }
    
    /* 开始计时 */
    uint64_t startTime = PQCP_PerfGetTimeNs();
    uint64_t elapsedNs = 0;
    uint64_t iterations = 0;
    
    /* 运行测试，直到达到最小时间或最大迭代次数 */
    while (iterations < cfg.maxIterations) {
        /* 运行一批次的测试 */
        uint64_t batchSize = (iterations < cfg.minIterations) ? 
                             (cfg.minIterations - iterations) : 
                             cfg.minIterations;
        
        for (uint64_t i = 0; i < batchSize; i++) {
            testFunc(userData);
        }
        
        iterations += batchSize;
        
        /* 检查是否达到最小时间 */
        elapsedNs = PQCP_PerfGetTimeNs() - startTime;
        double elapsed_sec = (double)elapsedNs / 1000000000.0;
        
        if (iterations >= cfg.minIterations && elapsed_sec >= cfg.minTime) {
            break;
        }
    }
    
    /* 计算结果 */
    result->elapsedTime = (double)elapsedNs / 1000000.0;  /* 转换为毫秒 */
    result->iterations = iterations;
    
    double elapsed_sec = result->elapsedTime / 1000.0;  /* 转换为秒 */
    result->opsPerSec = (double)iterations / elapsed_sec;
    result->avgTimePerOp = (result->elapsedTime * 1000.0) / (double)iterations;  /* 转换为微秒 */
    
    /* 调用teardown函数（如果提供） */
    if (teardownFunc != NULL) {
        teardownFunc(userData);
    }
    
    return 0;
}

/**
 * 打印性能测试结果
 */
void PQCP_PerfPrintResult(const PqcpPerfResult *result) {
    if (result == NULL) {
        return;
    }
    
    printf("Performance Test: %s\n", result->name);
    printf("  Iterations:     %llu\n", (unsigned long long)result->iterations);
    printf("  Elapsed Time:   %.3f ms\n", result->elapsedTime);
    printf("  Throughput:     %.2f ops/sec\n", result->opsPerSec);
    printf("  Average Time:   %.3f µs/op\n", result->avgTimePerOp);
}

/**
 * 将性能测试结果写入CSV文件
 */
int PQCP_PerfWriteCSV(const PqcpPerfResult *result, const char *csvFile, int append) {
    if (result == NULL || csvFile == NULL) {
        return -1;
    }
    
    FILE *file = fopen(csvFile, append ? "a" : "w");
    if (file == NULL) {
        return -1;
    }
    
    /* 如果是新文件，写入CSV头 */
    if (!append || ftell(file) == 0) {
        fprintf(file, "Test Name,Iterations,Elapsed Time (ms),Throughput (ops/sec),Average Time (µs/op)\n");
    }
    
    /* 写入测试结果 */
    fprintf(file, "%s,%llu,%.3f,%.2f,%.3f\n",
            result->name,
            (unsigned long long)result->iterations,
            result->elapsedTime,
            result->opsPerSec,
            result->avgTimePerOp);
    
    fclose(file);
    return 0;
} 