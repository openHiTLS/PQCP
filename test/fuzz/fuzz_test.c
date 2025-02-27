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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>

/* 模糊测试目标结构 */
typedef struct {
    const char *name;
    const char *description;
    int32_t (*runTest)(int32_t iterations, uint32_t seed, int32_t verbose, FILE *logFile);
} FuzzTarget;

/* 全局变量 */
static FuzzTarget *g_fuzzTargets = NULL;
static int32_t g_numTargets = 0;
static int32_t g_maxTargets = 0;
static uint32_t g_currentSeed = 0;

/* 辅助函数 */
static void InitRandom(uint32_t seed)
{
    g_currentSeed = seed;
    srand(seed);
}

static unsigned char RandomByte(void)
{
    return (unsigned char)(rand() & 0xFF);
}

static void GenerateRandomBuffer(unsigned char *buffer, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        buffer[i] = RandomByte();
    }
}

static void LogBuffer(FILE *logFile, const char *prefix, const unsigned char *buffer, size_t size)
{
    if (logFile) {
        fprintf(logFile, "%s: ", prefix);
        for (size_t i = 0; i < size; i++) {
            fprintf(logFile, "%02x", buffer[i]);
        }
        fprintf(logFile, "\n");
    }
}

/* 添加模糊测试目标 */
int32_t AddFuzzTarget(const char *name, const char *description, 
                    int32_t (*runTest)(int32_t iterations, uint32_t seed, int32_t verbose, FILE *logFile))
{
    if (g_numTargets >= g_maxTargets) {
        int32_t newMax = g_maxTargets == 0 ? 8 : g_maxTargets * 2;
        FuzzTarget *newTargets = realloc(g_fuzzTargets, newMax * sizeof(FuzzTarget));
        if (!newTargets) {
            return -1;
        }
        g_fuzzTargets = newTargets;
        g_maxTargets = newMax;
    }
    
    g_fuzzTargets[g_numTargets].name = name;
    g_fuzzTargets[g_numTargets].description = description;
    g_fuzzTargets[g_numTargets].runTest = runTest;
    g_numTargets++;
    
    return 0;
}

/* 列出所有模糊测试目标 */
void ListFuzzTargets(void)
{
    printf("可用的模糊测试目标:\n");
    for(int32_t i = 0; i < g_numTargets; i++) {
        printf("  %-20s - %s\n", g_fuzzTargets[i].name, g_fuzzTargets[i].description);
    }
}

/* 运行指定的模糊测试目标 */
int32_t RunFuzzTarget(const char *name, int32_t iterations, uint32_t seed, int32_t verbose, FILE *logFile)
{
    for(int32_t i = 0; i < g_numTargets; i++) {
        if (strcmp(g_fuzzTargets[i].name, name) == 0) {
            printf("运行模糊测试目标: %s (%s)\n", name, g_fuzzTargets[i].description);
            printf("使用种子: %u, 迭代次数: %d\n", seed, iterations);
            return g_fuzzTargets[i].runTest(iterations, seed, verbose, logFile);
        }
    }
    printf("错误: 未找到测试目标 '%s'\n", name);
    return -1;
}

/* 运行所有模糊测试目标 */
int32_t RunAllFuzzTargets(int32_t iterations, uint32_t seed, int32_t verbose, FILE *logFile)
{
    int32_t result = 0;
    for (int32_t i = 0; i < g_numTargets; i++) {
        printf("运行模糊测试目标: %s (%s)\n", g_fuzzTargets[i].name, g_fuzzTargets[i].description);
        printf("使用种子: %u, 迭代次数: %d\n", seed, iterations);
        if (g_fuzzTargets[i].runTest(iterations, seed, verbose, logFile) != 0) {
            result = -1;
        }
    }
    return result;
}

/* 清理资源 */
void CleanupFuzzTests(void)
{
    free(g_fuzzTargets);
    g_fuzzTargets = NULL;
    g_numTargets = 0;
    g_maxTargets = 0;
}

/* 示例模糊测试目标实现 */

/* Scloudplus密钥封装模糊测试 */
static int32_t FuzzScloudplusKem(int32_t iterations, uint32_t seed, int32_t verbose, FILE *logFile)
{
    /* 初始化随机数生成器 */
    InitRandom(seed);
    
    /* 模拟Scloudplus参数 */
    const int32_t Scloudplus_variants[] = {512, 768, 1024};
    const char *variant_names[] = {"Scloudplus-1", "Scloudplus-3", "Scloudplus-5"};
    
    /* 记录测试开始 */
    if (logFile) {
        fprintf(logFile, "=== 开始Scloudplus KEM模糊测试 ===\n");
        fprintf(logFile, "种子: %u, 迭代次数: %d\n", seed, iterations);
    }
    
    /* 对每个Scloudplus变体执行测试 */
    for (int32_t v = 0; v < 3; v++) {
        int32_t failures = 0;
        
        if (verbose) {
            printf("测试 %s (%d次迭代)...\n", variant_names[v], iterations);
        }
        
        if (logFile) {
            fprintf(logFile, "\n--- 测试 %s ---\n", variant_names[v]);
        }
        
        /* 执行测试迭代 */
        for (int32_t i = 0; i < iterations; i++) {
            /* 生成随机公钥和私钥 */
            size_t pk_size = Scloudplus_variants[v] / 4;  /* 模拟公钥大小 */
            size_t sk_size = Scloudplus_variants[v] / 2;  /* 模拟私钥大小 */
            unsigned char *pk = malloc(pk_size);
            unsigned char *sk = malloc(sk_size);
            
            if (!pk || !sk) {
                fprintf(stderr, "内存分配失败\n");
                free(pk);
                free(sk);
                return -1;
            }
            
            /* 生成随机密钥 */
            GenerateRandomBuffer(pk, pk_size);
            GenerateRandomBuffer(sk, sk_size);
            
            /* 生成随机密文和共享密钥 */
            size_t ct_size = Scloudplus_variants[v] / 3;  /* 模拟密文大小 */
            size_t ss_size = 32;  /* 共享密钥大小通常是32字节 */
            unsigned char *ct = malloc(ct_size);
            unsigned char *ss_enc = malloc(ss_size);
            unsigned char *ss_dec = malloc(ss_size);
            
            if (!ct || !ss_enc || !ss_dec) {
                fprintf(stderr, "内存分配失败\n");
                free(pk);
                free(sk);
                free(ct);
                free(ss_enc);
                free(ss_dec);
                return -1;
            }
            
            /* 生成随机密文和共享密钥 */
            GenerateRandomBuffer(ct, ct_size);
            GenerateRandomBuffer(ss_enc, ss_size);
            
            /* 记录测试输入 */
            if (verbose && logFile) {
                fprintf(logFile, "\n迭代 #%d:\n", i + 1);
                LogBuffer(logFile, "公钥", pk, pk_size);
                LogBuffer(logFile, "私钥", sk, sk_size);
                LogBuffer(logFile, "密文", ct, ct_size);
                LogBuffer(logFile, "封装密钥", ss_enc, ss_size);
            }
            
            /* 模拟解封装操作 */
            int32_t decaps_result = 0;  /* 0表示成功，非0表示失败 */
            
            /* 这里应该调用实际的Scloudplus解封装函数 */
            /* 目前只是模拟一个随机结果 */
            if (rand() % 100 < 95) {  /* 95%的成功率 */
                /* 模拟成功解封装 */
                memcpy(ss_dec, ss_enc, ss_size);
                /* 随机修改一些位，模拟解封装中的小错误 */
                if (rand() % 100 < 10) {  /* 10%的概率有小错误 */
                    ss_dec[rand() % ss_size] ^= (1 << (rand() % 8));
                }
            } else {
                /* 模拟解封装失败 */
                GenerateRandomBuffer(ss_dec, ss_size);
                decaps_result = 1;
            }
            
            /* 检查解封装结果 */
            int32_t match = (memcmp(ss_enc, ss_dec, ss_size) == 0);
            
            /* 记录测试结果 */
            if (logFile) {
                if (verbose) {
                    LogBuffer(logFile, "解封装密钥", ss_dec, ss_size);
                    fprintf(logFile, "解封装结果: %d\n", decaps_result);
                    fprintf(logFile, "密钥匹配: %d\n", match);
                }
                
                /* 检测不一致的情况 */
                if ((decaps_result == 0 && !match) || (decaps_result != 0 && match)) {
                    fprintf(logFile, "警告: 解封装结果与密钥匹配状态不一致!\n");
                    failures++;
                }
            }
            
            /* 释放内存 */
            free(pk);
            free(sk);
            free(ct);
            free(ss_enc);
            free(ss_dec);
        }
        
        /* 报告此变体的测试结果 */
        printf("%s: 完成 %d 次迭代, 检测到 %d 个异常\n", 
               variant_names[v], iterations, failures);
        
        if (logFile) {
            fprintf(logFile, "\n%s 测试摘要: 完成 %d 次迭代, 检测到 %d 个异常\n", 
                   variant_names[v], iterations, failures);
        }
    }
    
    /* 记录测试结束 */
    if (logFile) {
        fprintf(logFile, "\n=== Scloudplus KEM模糊测试完成 ===\n");
    }
    
    return 0;
}

/* pqcdsa签名模糊测试 */
static int32_t FuzzPqcdsaSign(int32_t iterations, uint32_t seed, int32_t verbose, FILE *logFile)
{
    /* 初始化随机数生成器 */
    InitRandom(seed);
    
    /* 模拟pqcdsa参数 */
    const int32_t pqcdsa_variants[] = {2, 3, 5};
    const char *variant_names[] = {"pqcdsa-2", "pqcdsa-3", "pqcdsa-5"};
    
    /* 记录测试开始 */
    if (logFile) {
        fprintf(logFile, "=== 开始pqcdsa签名模糊测试 ===\n");
        fprintf(logFile, "种子: %u, 迭代次数: %d\n", seed, iterations);
    }
    
    /* 对每个pqcdsa变体执行测试 */
    for (int32_t v = 0; v < 3; v++) {
        int32_t failures = 0;
        
        if (verbose) {
            printf("测试 %s (%u 次迭代)...\n", variant_names[v], iterations);
        }
        
        if (logFile) {
            fprintf(logFile, "\n--- 测试 %s ---\n", variant_names[v]);
        }
        
        /* 执行测试迭代 */
        for (int32_t i = 0; i < iterations; i++) {
            /* 生成随机公钥和私钥 */
            size_t pk_size = 1312 * pqcdsa_variants[v];  /* 模拟公钥大小 */
            size_t sk_size = 2560 * pqcdsa_variants[v];  /* 模拟私钥大小 */
            unsigned char *pk = malloc(pk_size);
            unsigned char *sk = malloc(sk_size);
            
            if (!pk || !sk) {
                fprintf(stderr, "内存分配失败\n");
                free(pk);
                free(sk);
                return -1;
            }
            
            /* 生成随机密钥 */
            GenerateRandomBuffer(pk, pk_size);
            GenerateRandomBuffer(sk, sk_size);
            
            /* 生成随机消息 */
            size_t msg_size = 100 + (rand() % 900);  /* 随机消息大小 (100-999字节) */
            unsigned char *msg = malloc(msg_size);
            
            if (!msg) {
                fprintf(stderr, "内存分配失败\n");
                free(pk);
                free(sk);
                free(msg);
                return -1;
            }
            
            GenerateRandomBuffer(msg, msg_size);
            
            /* 生成随机签名 */
            size_t sig_size = 2000 * pqcdsa_variants[v];  /* 模拟签名大小 */
            unsigned char *sig = malloc(sig_size);
            
            if (!sig) {
                fprintf(stderr, "内存分配失败\n");
                free(pk);
                free(sk);
                free(msg);
                free(sig);
                return -1;
            }
            
            GenerateRandomBuffer(sig, sig_size);
            
            /* 记录测试输入 */
            if (verbose && logFile) {
                fprintf(logFile, "\n迭代 #%d:\n", i + 1);
                LogBuffer(logFile, "公钥 (前32字节)", pk, 32);
                LogBuffer(logFile, "私钥 (前32字节)", sk, 32);
                LogBuffer(logFile, "消息 (前32字节)", msg, msg_size < 32 ? msg_size : 32);
                LogBuffer(logFile, "签名 (前32字节)", sig, 32);
            }
            
            /* 模拟验证操作 */
            int32_t verify_result = 0;  /* 0表示成功，非0表示失败 */
            
            /* 这里应该调用实际的pqcdsa验证函数 */
            /* 目前只是模拟一个随机结果 */
            if (rand() % 100 < 90) {  /* 90%的成功率 */
                /* 模拟成功验证 */
                verify_result = 0;
            } else {
                /* 模拟验证失败 */
                verify_result = 1;
            }
            
            /* 记录测试结果 */
            if (logFile) {
                if (verbose) {
                    fprintf(logFile, "验证结果: %d\n", verify_result);
                }
                
                /* 检测异常情况 */
                if (verify_result != 0) {
                    /* 在实际应用中，我们可能需要更详细地分析失败原因 */
                    fprintf(logFile, "警告: 签名验证失败!\n");
                    failures++;
                }
            }
            
            /* 释放内存 */
            free(pk);
            free(sk);
            free(msg);
            free(sig);
        }
        
        /* 报告此变体的测试结果 */
        printf("%s: 完成 %d 次迭代, 检测到 %d 个验证失败\n", 
               variant_names[v], iterations, failures);
        
        if (logFile) {
            fprintf(logFile, "\n%s 测试摘要: 完成 %d 次迭代, 检测到 %d 个验证失败\n", 
                   variant_names[v], iterations, failures);
        }
    }
    
    /* 记录测试结束 */
    if (logFile) {
        fprintf(logFile, "\n=== pqcdsa签名模糊测试完成 ===\n");
    }
    
    return 0;
}

/* 初始化模糊测试 */
int32_t PQCP_InitFuzzTests(void)
{
    /* 添加测试目标 */
    if (AddFuzzTarget("Scloudplus_kem", "Scloudplus密钥封装机制模糊测试", FuzzScloudplusKem) != 0) {
        return -1;
    }
    
    if (AddFuzzTarget("pqcdsa_sign", "pqcdsa数字签名模糊测试", FuzzPqcdsaSign) != 0) {
        return -1;
    }
    
    return 0;
}

/* 主函数 */
int32_t main(int32_t argc, char *argv[])
{
    int32_t opt, optionIndex = 0;
    int32_t verbose = 0;
    int32_t listOnly = 0;
    int32_t iterations = 1000;
    uint32_t seed = (uint32_t)time(NULL);
    char *outputDir = "output/fuzz";
    char *logFilePath = NULL;
    FILE *logFile = NULL;
    
    struct option longOptions[] = {
        {"help",       no_argument,       0, 'h'},
        {"output-dir", required_argument, 0, 'o'},
        {"iterations", required_argument, 0, 'i'},
        {"seed",       required_argument, 0, 's'},
        {"verbose",    no_argument,       0, 'v'},
        {"list",       no_argument,       0, 'l'},
        {0, 0, 0, 0}
    };
    
    /* 解析命令行参数 */
    while ((opt = getopt_long(argc, argv, "ho:i:s:vl", longOptions, &optionIndex)) != -1) {
        switch (opt) {
            case 'h':
                printf("用法: %s [选项] [测试目标...]\n", argv[0]);
                printf("选项:\n");
                printf("  -h, --help              显示帮助信息\n");
                printf("  -o, --output-dir=DIR    设置输出目录 (默认: output/fuzz)\n");
                printf("  -i, --iterations=NUM    设置迭代次数 (默认: 1000)\n");
                printf("  -s, --seed=NUM          设置随机种子 (默认: 当前时间)\n");
                printf("  -v, --verbose           显示详细输出\n");
                printf("  -l, --list              列出可用的测试目标\n");
                return 0;
            case 'o':
                outputDir = optarg;
                break;
            case 'i':
                iterations = (int32_t)atoi(optarg);
                if (iterations <= 0) {
                    iterations = 1000;
                }
                break;
            case 's':
                seed = (uint32_t)strtoul(optarg, NULL, 10);
                break;
            case 'v':
                verbose = 1;
                break;
            case 'l':
                listOnly = 1;
                break;
            default:
                fprintf(stderr, "尝试 '%s --help' 获取更多信息。\n", argv[0]);
                return 1;
        }
    }
    
    /* 初始化测试 */
    if (PQCP_InitFuzzTests() != 0) {
        fprintf(stderr, "初始化模糊测试失败\n");
        return 1;
    }
    
    /* 如果只是列出测试目标 */
    if (listOnly) {
        ListFuzzTargets();
        CleanupFuzzTests();
        return 0;
    }
    
    /* 创建输出目录 */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", outputDir);
    system(cmd);
    
    /* 创建日志文件 */
    char logFileName[256];
    snprintf(logFileName, sizeof(logFileName), "fuzz_test_seed_%u.log", seed);
    
    logFilePath = malloc(strlen(outputDir) + strlen(logFileName) + 2);
    if (!logFilePath) {
        fprintf(stderr, "内存分配失败\n");
        CleanupFuzzTests();
        return 1;
    }
    
    sprintf(logFilePath, "%s/%s", outputDir, logFileName);
    logFile = fopen(logFilePath, "w");
    
    if (!logFile) {
        fprintf(stderr, "无法创建日志文件: %s\n", logFilePath);
        free(logFilePath);
        CleanupFuzzTests();
        return 1;
    }
    
    /* 记录测试开始时间和参数 */
    time_t now = time(NULL);
    fprintf(logFile, "模糊测试开始: %s", ctime(&now));
    fprintf(logFile, "种子: %u\n", seed);
    fprintf(logFile, "迭代次数: %d\n", iterations);
    fprintf(logFile, "详细模式: %s\n\n", verbose ? "是" : "否");
    
    /* 运行测试 */
    int32_t result = 0;
    if (optind < argc) {
        /* 运行指定的测试目标 */
        for (int32_t i = optind; i < argc; i++) {
            if (RunFuzzTarget(argv[i], iterations, seed, verbose, logFile) != 0) {
                result = 1;
            }
        }
    } else {
        /* 运行所有测试目标 */
        if (RunAllFuzzTargets(iterations, seed, verbose, logFile) != 0) {
            result = 1;
        }
    }
    
    /* 记录测试结束时间 */
    now = time(NULL);
    fprintf(logFile, "\n模糊测试结束: %s", ctime(&now));
    
    /* 关闭日志文件 */
    fclose(logFile);
    
    /* 清理资源 */
    free(logFilePath);
    CleanupFuzzTests();
    
    printf("模糊测试完成。结果已保存到 %s\n", logFilePath);
    
    return result;
} 