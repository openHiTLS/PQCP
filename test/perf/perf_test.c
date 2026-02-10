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
#include <linux/limits.h>

#include "perf_kem.h"
#include "crypt_eal_pkey.h"
#include "pqcp_types.h"
#include "pqcp_test.h"
#include "pqcp_provider.h"
#include "pqcp_err.h"
#include "crypt_errno.h"

extern uint32_t g_duration;
extern PerfResult g_perfRes;

typedef struct {
    char *algName;
    int32_t algId;
    int32_t setParaCmd;
    int32_t algParaId;
    int32_t getCipherLenCmd;
} BenchTestSuite;

BenchTestSuite g_benchmark[] = {
};

static void SetDuration(uint32_t time) {
    if (time >= 100) {
        printf("Duration is too long");
        return;
    }
    g_duration = time;
}

static int32_t RunKemPerfTest(int32_t iterations, int32_t verbose, FILE *csvFile)
{
    int32_t ret = 0;
    uint32_t testSuiteCnt = sizeof(g_benchmark) / sizeof(g_benchmark[0]);
    for (int i = 0; i < testSuiteCnt; ++i) {
        PQCP_BENCHMARK_KEM_KeyGen(g_benchmark[i].algName, g_benchmark[i].algId, g_benchmark[i].setParaCmd, g_benchmark[i].algParaId, g_duration);
        PQCP_BENCHMARK_KEM_Encaps(g_benchmark[i].algName, g_benchmark[i].algId, g_benchmark[i].setParaCmd, g_benchmark[i].algParaId, g_benchmark[i].getCipherLenCmd, g_duration);
        PQCP_BENCHMARK_KEM_Decaps(g_benchmark[i].algName, g_benchmark[i].algId, g_benchmark[i].setParaCmd, g_benchmark[i].algParaId, g_benchmark[i].getCipherLenCmd, g_duration);
    }
    
}

int32_t InitDefaultProvider()
{
    char basePath[PATH_MAX] = {0};
    char fullPath[PATH_MAX] = {0};

    if (readlink("/proc/self/exe", basePath, sizeof(basePath) - 1) == -1)
    {
        perror("get realpath failed.\n");
        return PQCP_TEST_FAILURE;
    }
    printf("basePath: %s\n", basePath);

    dirname(basePath);
    snprintf(fullPath, sizeof(fullPath), "%s/../../../build", basePath);
    printf("fullPath: %s\n", fullPath);

    int32_t ret = CRYPT_EAL_ProviderSetLoadPath(NULL, fullPath);
    if (ret != 0)
    {
        printf("set provider path failed.\n");
        return PQCP_TEST_FAILURE;
    }

    ret = CRYPT_EAL_ProviderLoad(NULL, BSL_SAL_LIB_FMT_LIBSO, "pqcp_provider", NULL, NULL);
    if (ret != 0)
    {
        printf("load provider failed: 0x%x.\n", ret);
        return PQCP_TEST_FAILURE;
    }

    return PQCP_TEST_SUCCESS;
}
/* 初始化性能测试 */
int32_t InitPerfTests(void)
{
    if (InitDefaultProvider() != PQCP_TEST_SUCCESS) {
        printf("Load Provider failed\n");
        return -1;
    }
    int32_t ret = CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
    if (ret != PQCP_SUCCESS) {
        printf("RandInit failed: %x", ret);
        return ret;
    }
    if (PQCP_AddPerfTestGroup("PQCP", "PQCP密钥封装机制性能测试", RunKemPerfTest) != 0) {
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
    FILE *csvFile = NULL;
    char *full_csv_path = NULL;

    struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"output-dir", required_argument, 0, 'o'},
        {"csv", required_argument, 0, 'c'},
        {"iterations", required_argument, 0, 'i'},
        {"verbose", no_argument, 0, 'v'},
        {"list", no_argument, 0, 'l'},
        {"time", required_argument, 0, 't'},
        {0, 0, 0, 0}};

    /* 解析命令行参数 */
    while ((opt = getopt_long(argc, argv, "ho:c:i:vlt:", long_options, &optionIndex)) != -1) {
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
                printf("  -t, --time              设置单个用例运行时间\n");
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
            case 't':
                SetDuration(atoi(optarg));
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
    (void)system(cmd);

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
    if (csvFile) {
        fclose(csvFile);
        csvFile = NULL;
    }
    return result;
} 