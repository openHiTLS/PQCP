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

/* 性能测试结果结构 */
typedef struct {
    const char *algorithm;
    const char *operation;
    double avgTimeMs;
    double minTimeMs;
    double maxTimeMs;
    int32_t iterations;
    size_t dataSize;
} PerfResult;

/* 性能测试组结构 */
typedef struct {
    const char *name;
    const char *description;
    int32_t (*runTest)(int32_t iterations, int32_t verbose, FILE *csvFile);
} PerfTestGroup;

/* 全局变量 */
static PerfTestGroup *g_testGroups = NULL;
static int32_t g_numGroups = 0;
static int32_t g_maxGroups = 0;

/* 辅助函数 */
static double GetTimeMs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

static void WriteCsvHeader(FILE *csvFile)
{
    if (csvFile) {
        fprintf(csvFile, "Algorithm,Operation,AvgTime(ms),MinTime(ms),MaxTime(ms),Iterations,DataSize(bytes)\n");
    }
}

static void WriteCsvResult(FILE *csvFile, const PerfResult *result)
{
    if (csvFile && result) {
        fprintf(csvFile, "%s,%s,%.4f,%.4f,%.4f,%u,%zu\n",
                result->algorithm, result->operation,
                result->avgTimeMs, result->minTimeMs, result->maxTimeMs,
                result->iterations, result->dataSize);
    }
}

static void PrintResult(const PerfResult *result, int32_t verbose)
{
    printf("%-15s %-15s Avg: %.4f ms, Min: %.4f ms, Max: %.4f ms, Iterations: %u, Data: %zu bytes\n",
           result->algorithm, result->operation,
           result->avgTimeMs, result->minTimeMs, result->maxTimeMs,
           result->iterations, result->dataSize);
}

/* 添加测试组 */
int32_t PQCP_AddPerfTestGroup(const char *name, const char *description, 
                             int32_t (*runTest)(int32_t iterations, int32_t verbose, FILE *csvFile))
{
    if (g_numGroups >= g_maxGroups) {
        int32_t newMax = g_maxGroups == 0 ? 8 : g_maxGroups * 2;
        PerfTestGroup *newGroups = realloc(g_testGroups, newMax * sizeof(PerfTestGroup));
        if (!newGroups) return -1;
        g_testGroups = newGroups;
        g_maxGroups = newMax;
    }
    
    g_testGroups[g_numGroups].name = name;
    g_testGroups[g_numGroups].description = description;
    g_testGroups[g_numGroups].runTest = runTest;
    g_numGroups++;
    
    return 0;
}

/* 列出所有测试组 */
void PQCP_ListPerfTestGroups(void)
{
    printf("可用的性能测试组:\n");
    for (int32_t i = 0; i < g_numGroups; i++) {
        printf("  %-20s - %s\n", g_testGroups[i].name, g_testGroups[i].description);
    }
}

/* 运行指定的测试组 */
int32_t PQCP_RunPerfTestGroup(const char *name, int32_t iterations, int32_t verbose, FILE *csvFile)
{
    for (int32_t i = 0; i < g_numGroups; i++) {
        if (strcmp(g_testGroups[i].name, name) == 0) {
            printf("运行性能测试组: %s (%s)\n", name, g_testGroups[i].description);
            return g_testGroups[i].runTest(iterations, verbose, csvFile);
        }
    }
    printf("错误: 未找到测试组 '%s'\n", name);
    return -1;
}

/* 运行所有测试组 */
int32_t PQCP_RunAllPerfTests(int32_t iterations, int32_t verbose, const char *csvPath) {
    FILE *csvFile = fopen(csvPath, "w");
    if (!csvFile) {
        fprintf(stderr, "无法创建CSV文件: %s\n", csvPath);
        return -1;
    }
    
    WriteCsvHeader(csvFile);
    
    int32_t result = 0;
    for (int32_t i = 0; i < g_numGroups; i++) {
        if (g_testGroups[i].runTest(iterations, verbose, csvFile) != 0) {
            result = -1;
        }
    }
    
    fclose(csvFile);
    return result;
}

/* 示例测试组实现 */

/* Scloudplus性能测试 */
static int32_t RunScloudplusPerfTest(int32_t iterations, int32_t verbose, FILE *csvFile)
{
    PerfResult results[3][3] = {0};
    const char *variants[] = {"Scloudplus-512", "Scloudplus-768", "Scloudplus-1024"};
    const char *operations[] = {"KeyGen", "Encaps", "Decaps"};
    
    /* 设置默认迭代次数 */
    if (iterations <= 0) {
        iterations = 1000;
    }
    
    /* 为每个变体和操作执行测试 */
    for (int32_t v = 0; v < 3; v++) {
        for (int32_t op = 0; op < 3; op++) {
            double start, end, total = 0, min_time = 1e9, max_time = 0;
            
            /* 初始化结果结构 */
            results[v][op].algorithm = variants[v];
            results[v][op].operation = operations[op];
            results[v][op].iterations = iterations;
            
            /* 根据变体设置数据大小（示例值） */
            switch (v) {
                case 0: results[v][op].dataSize = 1632; break;  /* Scloudplus-512 */
                case 1: results[v][op].dataSize = 2400; break;  /* Scloudplus-768 */
                case 2: results[v][op].dataSize = 3168; break;  /* Scloudplus-1024 */
            }
            
            if (verbose) {
                printf("测试 %s %s (%d 次迭代)...\n", variants[v], operations[op], iterations);
            }
            
            /* 执行测试迭代 */
            for (int32_t i = 0; i < iterations; i++) {
                start = GetTimeMs();
                
                /* 这里应该调用实际的Scloudplus函数 */
                /* 目前只是模拟延迟 */
                struct timespec ts;
                ts.tv_sec = 0;
                ts.tv_nsec = (v + 1) * (op + 1) * 100000; /* 模拟不同操作的不同延迟 */
                nanosleep(&ts, NULL);
                
                end = GetTimeMs();
                double elapsed = end - start;
                
                total += elapsed;
                if (elapsed < min_time) min_time = elapsed;
                if (elapsed > max_time) max_time = elapsed;
            }
            
            /* 计算平均时间 */
            results[v][op].avgTimeMs = total / iterations;
            results[v][op].minTimeMs = min_time;
            results[v][op].maxTimeMs = max_time;
            
            /* 输出结果 */
            PrintResult(&results[v][op], verbose);
            WriteCsvResult(csvFile, &results[v][op]);
        }
    }
    
    return 0;
}

/* pqcdsa性能测试 */
static int32_t RunPqcdsaPerfTest(int32_t iterations, int32_t verbose, FILE *csvFile)
{
    PerfResult results[3][3] = {0};
    const char *variants[] = {"pqcdsa-2", "pqcdsa-3", "pqcdsa-5"};
    const char *operations[] = {"KeyGen", "Sign", "Verify"};
    
    /* 设置默认迭代次数 */
    if (iterations <= 0) {
        iterations = 1000;
    }
    
    /* 为每个变体和操作执行测试 */
    for (int32_t v = 0; v < 3; v++) {
        for (int32_t op = 0; op < 3; op++) {
            double start, end, total = 0, min_time = 1e9, max_time = 0;
            
            /* 初始化结果结构 */
            results[v][op].algorithm = variants[v];
            results[v][op].operation = operations[op];
            results[v][op].iterations = iterations;
            
            /* 根据变体设置数据大小（示例值） */
            switch (v) {
                case 0: results[v][op].dataSize = 2528; break;  /* pqcdsa-2 */
                case 1: results[v][op].dataSize = 3504; break;  /* pqcdsa-3 */
                case 2: results[v][op].dataSize = 4595; break;  /* pqcdsa-5 */
            }
            
            if (verbose) {
                printf("测试 %s %s (%d 次迭代)...\n", variants[v], operations[op], iterations);
            }
            
            /* 执行测试迭代 */
            for (int32_t i = 0; i < iterations; i++) {
                start = GetTimeMs();
                
                /* 这里应该调用实际的pqcdsa函数 */
                /* 目前只是模拟延迟 */
                struct timespec ts;
                ts.tv_sec = 0;
                ts.tv_nsec = (v + 1) * (op + 1) * 200000; /* 模拟不同操作的不同延迟 */
                nanosleep(&ts, NULL);
                
                end = GetTimeMs();
                double elapsed = end - start;
                
                total += elapsed;
                if (elapsed < min_time) min_time = elapsed;
                if (elapsed > max_time) max_time = elapsed;
            }
            
            /* 计算平均时间 */
            results[v][op].avgTimeMs = total / iterations;
            results[v][op].minTimeMs = min_time;
            results[v][op].maxTimeMs = max_time;
            
            /* 输出结果 */
            PrintResult(&results[v][op], verbose);
            WriteCsvResult(csvFile, &results[v][op]);
        }
    }
    
    return 0;
}

/* 初始化性能测试 */
int32_t InitPerfTests(void)
{
    /* 添加测试组 */
    if (PQCP_AddPerfTestGroup("Scloudplus", "Scloudplus密钥封装机制性能测试", RunScloudplusPerfTest) != 0) {
        return -1;
    }
    
    if (PQCP_AddPerfTestGroup("pqcdsa", "pqcdsa数字签名性能测试", RunPqcdsaPerfTest) != 0) {
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
    int32_t iterations = 0;
    char *outputDir = "output/perf";
    char *csvFilePath = "perf_results.csv";
    char *testGroup = NULL;
    FILE *csvFile = NULL;
    
    struct option long_options[] = {
        {"help",       no_argument,       0, 'h'},
        {"output-dir", required_argument, 0, 'o'},
        {"csv",        required_argument, 0, 'c'},
        {"iterations", required_argument, 0, 'i'},
        {"verbose",    no_argument,       0, 'v'},
        {"list",       no_argument,       0, 'l'},
        {0, 0, 0, 0}
    };
    
    /* 解析命令行参数 */
    while ((opt = getopt_long(argc, argv, "ho:c:i:vl", long_options, &optionIndex)) != -1) {
        switch (opt) {
            case 'h':
                printf("用法: %s [选项] [测试组...]\n", argv[0]);
                printf("选项:\n");
                printf("  -h, --help              显示帮助信息\n");
                printf("  -o, --output-dir=DIR    设置输出目录 (默认: output/perf)\n");
                printf("  -c, --csv=FILE          设置CSV输出文件 (默认: perf_results.csv)\n");
                printf("  -i, --iterations=NUM    设置迭代次数 (默认: 算法特定)\n");
                printf("  -v, --verbose           显示详细输出\n");
                printf("  -l, --list              列出可用的测试组\n");
                return 0;
            case 'o':
                outputDir = optarg;
                break;
            case 'c':
                csvFilePath = optarg;
                break;
            case 'i':
                iterations = atoi(optarg);
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
    if (InitPerfTests() != 0) {
        fprintf(stderr, "初始化性能测试失败\n");
        return 1;
    }
    
    /* 如果只是列出测试组 */
    if (listOnly) {
        PQCP_ListPerfTestGroups();
        PQCP_RunAllPerfTests(iterations, verbose, csvFilePath);
        return 0;
    }
    
    /* 创建输出目录 */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", outputDir);
    system(cmd);
    
    /* 打开CSV文件 */
    char full_csv_path[512];
    snprintf(full_csv_path, sizeof(full_csv_path), "%s/%s", outputDir, csvFilePath);
    csvFile = fopen(full_csv_path, "w");
    if (!csvFile) {
        fprintf(stderr, "无法创建CSV文件: %s\n", full_csv_path);
        return 1;
    }
    
    /* 写入CSV头 */
    WriteCsvHeader(csvFile);
    
    /* 运行测试 */
    int32_t result = 0;
    if (optind < argc) {
        /* 运行指定的测试组 */
        for (int32_t i = optind; i < argc; i++) {
            if (PQCP_RunPerfTestGroup(argv[i], iterations, verbose, csvFile) != 0) {
                result = 1;
            }
        }
    } else {
        /* 运行所有测试组 */
        if (PQCP_RunAllPerfTests(iterations, verbose, full_csv_path) != 0) {
            result = 1;
        }
    }
    
    /* 关闭CSV文件 */
    fclose(csvFile);
    
    return result;
} 