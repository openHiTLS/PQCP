/**
 * @file pqcp_fuzz.h
 * @brief PQCP模糊测试框架头文件
 */

#ifndef PQCP_FUZZ_H
#define PQCP_FUZZ_H

#include <stdint.h>
#include <stddef.h>

/* 模糊测试输入数据 */
typedef struct {
    uint8_t *data;
    size_t size;
} PqcpFuzzData;

/* 模糊测试配置 */
typedef struct {
    size_t minSize;
    size_t maxSize;
    uint32_t seed;
    uint32_t iterations;
} PqcpFuzzConfig;

/* 默认模糊测试配置 */
extern const PqcpFuzzConfig PQCP_DEFAULT_FUZZ_CONFIG;

/**
 * 初始化模糊测试数据
 * 
 * @param fuzzData 模糊测试数据
 * @param size 数据大小
 * 
 * @return 0表示成功，其他值表示失败
 */
int PQCP_FuzzInit(PqcpFuzzData *fuzzData, size_t size);

/**
 * 释放模糊测试数据
 * 
 * @param fuzzData 模糊测试数据
 */
void PQCP_FuzzFree(PqcpFuzzData *fuzzData);

/**
 * 生成随机模糊测试数据
 * 
 * @param fuzzData 模糊测试数据
 * @param config 模糊测试配置，如果为NULL则使用默认配置
 * 
 * @return 0表示成功，其他值表示失败
 */
int PQCP_FuzzGenerate(PqcpFuzzData *fuzzData, const PqcpFuzzConfig *config);

/**
 * 变异模糊测试数据
 * 
 * @param fuzzData 模糊测试数据
 * @param mutationRate 变异率（0.0-1.0）
 * 
 * @return 0表示成功，其他值表示失败
 */
int PQCP_FuzzMutate(PqcpFuzzData *fuzzData, float mutationRate);

/**
 * 运行模糊测试
 * 
 * @param testFunc 测试函数，返回0表示测试通过，其他值表示测试失败
 * @param config 模糊测试配置，如果为NULL则使用默认配置
 * @param userData 用户数据，会传递给testFunc
 * 
 * @return 0表示成功，其他值表示失败
 */
int PQCP_FuzzRun(
    int (*testFunc)(const PqcpFuzzData *fuzzData, void *userData),
    const PqcpFuzzConfig *config,
    void *userData
);

/**
 * 从文件加载模糊测试数据
 * 
 * @param fuzzData 模糊测试数据
 * @param filePath 文件路径
 * 
 * @return 0表示成功，其他值表示失败
 */
int PQCP_FuzzLoadFromFile(PqcpFuzzData *fuzzData, const char *filePath);

/**
 * 将模糊测试数据保存到文件
 * 
 * @param fuzzData 模糊测试数据
 * @param filePath 文件路径
 * 
 * @return 0表示成功，其他值表示失败
 */
int PQCP_FuzzSaveToFile(const PqcpFuzzData *fuzzData, const char *filePath);

#endif /* PQCP_FUZZ_H */ 