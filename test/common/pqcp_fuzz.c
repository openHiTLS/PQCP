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

#include "pqcp_fuzz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* 默认模糊测试配置 */
const PqcpFuzzConfig PQCP_DEFAULT_FUZZ_CONFIG = {
    .minSize = 1,
    .maxSize = 4096,
    .seed = 0,  /* 0表示使用当前时间作为种子 */
    .iterations = 1000
};

/**
 * 初始化模糊测试数据
 */
int32_t PQCP_FuzzInit(PqcpFuzzData *fuzzData, size_t size)
{
    if (fuzzData == NULL || size == 0) {
        return -1;
    }
    
    fuzzData->data = (uint8_t *)malloc(size);
    if (fuzzData->data == NULL) {
        return -1;
    }
    
    fuzzData->size = size;
    memset(fuzzData->data, 0, size);
    
    return 0;
}

/**
 * 释放模糊测试数据
 */
void PQCP_FuzzFree(PqcpFuzzData *fuzzData)
{
    if (fuzzData != NULL && fuzzData->data != NULL) {
        free(fuzzData->data);
        fuzzData->data = NULL;
        fuzzData->size = 0;
    }
}

/**
 * 生成随机模糊测试数据
 */
int32_t PQCP_FuzzGenerate(PqcpFuzzData *fuzzData, const PqcpFuzzConfig *config)
{
    if (fuzzData == NULL) {
        return -1;
    }
    
    /* 使用默认配置（如果未提供） */
    PqcpFuzzConfig cfg = (config != NULL) ? *config : PQCP_DEFAULT_FUZZ_CONFIG;
    
    /* 初始化随机数生成器 */
    uint32_t seed = cfg.seed;
    if (seed == 0) {
        seed = (uint32_t)time(NULL);
    }
    srand(seed);
    
    /* 生成随机大小（如果需要） */
    if (fuzzData->data == NULL) {
        size_t size = cfg.minSize;
        if (cfg.maxSize > cfg.minSize) {
            size += rand() % (cfg.maxSize - cfg.minSize + 1);
        }
        
        if (PQCP_FuzzInit(fuzzData, size) != 0) {
            return -1;
        }
    }
    
    /* 填充随机数据 */
    for (size_t i = 0; i < fuzzData->size; i++) {
        fuzzData->data[i] = (uint8_t)(rand() & 0xFF);
    }
    
    return 0;
}

/**
 * 变异模糊测试数据
 */
int32_t PQCP_FuzzMutate(PqcpFuzzData *fuzzData, float mutationRate)
{
    if (fuzzData == NULL || fuzzData->data == NULL || fuzzData->size == 0) {
        return -1;
    }
    
    if (mutationRate <= 0.0f || mutationRate > 1.0f) {
        mutationRate = 0.01f;  /* 默认变异率为1% */
    }
    
    /* 计算要变异的字节数 */
    size_t numBytesToMutate = (size_t)(fuzzData->size * mutationRate);
    if (numBytesToMutate == 0) {
        numBytesToMutate = 1;  /* 至少变异一个字节 */
    }
    
    /* 随机选择字节进行变异 */
    for (size_t i = 0; i < numBytesToMutate; i++) {
        size_t idx = rand() % fuzzData->size;
        uint8_t mutationType = rand() % 3;
        
        switch (mutationType) {
            case 0:  /* 随机替换 */
                fuzzData->data[idx] = (uint8_t)(rand() & 0xFF);
                break;
            case 1:  /* 位翻转 */
                fuzzData->data[idx] ^= (1 << (rand() % 8));
                break;
            case 2:  /* 加/减一个小值 */
                {
                    int8_t delta = (rand() % 10) - 5;  /* -5到+4 */
                    fuzzData->data[idx] = (uint8_t)(fuzzData->data[idx] + delta);
                }
                break;
        }
    }
    
    return 0;
}

/**
 * 运行模糊测试
 */
int32_t PQCP_FuzzRun(int32_t (*testFunc)(const PqcpFuzzData *fuzzData, void *userData),
    const PqcpFuzzConfig *config, void *userData)
{
    if (testFunc == NULL) {
        return -1;
    }
    
    /* 使用默认配置（如果未提供） */
    PqcpFuzzConfig cfg = (config != NULL) ? *config : PQCP_DEFAULT_FUZZ_CONFIG;
    
    /* 初始化随机数生成器 */
    uint32_t seed = cfg.seed;
    if (seed == 0) {
        seed = (uint32_t)time(NULL);
    }
    srand(seed);
    
    printf("Starting fuzzing with seed: %u, iterations: %u\n", seed, cfg.iterations);
    
    /* 创建初始模糊测试数据 */
    PqcpFuzzData fuzzData = {0};
    size_t initialSize = cfg.minSize;
    if (cfg.maxSize > cfg.minSize) {
        initialSize += rand() % (cfg.maxSize - cfg.minSize + 1);
    }
    
    if (PQCP_FuzzInit(&fuzzData, initialSize) != 0) {
        return -1;
    }
    
    if (PQCP_FuzzGenerate(&fuzzData, &cfg) != 0) {
        PQCP_FuzzFree(&fuzzData);
        return -1;
    }
    
    /* 运行模糊测试 */
    int32_t failures = 0;
    for (uint32_t i = 0; i < cfg.iterations; i++) {
        /* 运行测试 */
        int32_t result = testFunc(&fuzzData, userData);
        
        if (result != 0) {
            printf("Fuzzing failed at iteration %u\n", i);
            
            /* 保存失败的测试数据 */
            char failureFile[256];
            snprintf(failureFile, sizeof(failureFile), "fuzz_failure_%u.bin", i);
            PQCP_FuzzSaveToFile(&fuzzData, failureFile);
            printf("Saved failure data to: %s\n", failureFile);
            
            failures++;
        }
        
        /* 变异数据用于下一次迭代 */
        if (i < cfg.iterations - 1) {
            PQCP_FuzzMutate(&fuzzData, 0.05f);  /* 5%的变异率 */
        }
    }
    
    PQCP_FuzzFree(&fuzzData);
    
    printf("Fuzzing completed. Total failures: %d/%u\n", failures, cfg.iterations);
    
    return (failures > 0) ? -1 : 0;
}

/**
 * 从文件加载模糊测试数据
 */
int32_t PQCP_FuzzLoadFromFile(PqcpFuzzData *fuzzData, const char *filePath)
{
    if (fuzzData == NULL || filePath == NULL) {
        return -1;
    }
    
    FILE *file = fopen(filePath, "rb");
    if (file == NULL) {
        return -1;
    }
    
    /* 获取文件大小 */
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (fileSize <= 0) {
        fclose(file);
        return -1;
    }
    
    /* 释放现有数据（如果有） */
    PQCP_FuzzFree(fuzzData);
    
    /* 分配内存并读取文件 */
    if (PQCP_FuzzInit(fuzzData, (size_t)fileSize) != 0) {
        fclose(file);
        return -1;
    }
    
    size_t bytesRead = fread(fuzzData->data, 1, fuzzData->size, file);
    fclose(file);
    
    if (bytesRead != fuzzData->size) {
        PQCP_FuzzFree(fuzzData);
        return -1;
    }
    
    return 0;
}

/**
 * 将模糊测试数据保存到文件
 */
int32_t PQCP_FuzzSaveToFile(const PqcpFuzzData *fuzzData, const char *filePath)
{
    if (fuzzData == NULL || fuzzData->data == NULL || filePath == NULL) {
        return -1;
    }
    
    FILE *file = fopen(filePath, "wb");
    if (file == NULL) {
        return -1;
    }
    
    size_t bytesWritten = fwrite(fuzzData->data, 1, fuzzData->size, file);
    fclose(file);
    
    if (bytesWritten != fuzzData->size) {
        return -1;
    }
    
    return 0;
} 