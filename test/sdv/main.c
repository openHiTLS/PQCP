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

#include "pqcp_test.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

/* 命令行选项 */
static struct option g_longOptions[] = {
    {"help", no_argument, 0, 'h'},
    {"output-dir", required_argument, 0, 'o'},
    {"verbose", no_argument, 0, 'v'},
    {"list", no_argument, 0, 'l'},
    {"suite", required_argument, 0, 's'},
    {"case", required_argument, 0, 'c'},
    {"report", required_argument, 0, 'r'},
    {0, 0, 0, 0}
};

/* 显示帮助信息 */
static void ShowHelp(const char *programName)
{
    printf("PQCP SDV测试程序\n");
    printf("用法: %s [选项]\n", programName);
    printf("选项:\n");
    printf("  -h, --help              显示帮助信息\n");
    printf("  -o, --output-dir=DIR    指定输出目录（默认为output/sdv）\n");
    printf("  -v, --verbose           显示详细测试信息\n");
    printf("  -l, --list              列出所有可用的测试套件和测试用例\n");
    printf("  -s, --suite=SUITE       运行指定的测试套件\n");
    printf("  -c, --case=CASE         运行指定的测试用例（需要与--suite一起使用）\n");
    printf("  -r, --report=FILE       指定测试报告文件名（默认为sdv_test_report.html）\n");
}

/* 声明测试套件初始化函数 */
extern int32_t PQCP_InitKemTestSuite(void);
extern int32_t PQCP_InitSignTestSuite(void);
extern int32_t PQCP_InitIntegrationTestSuite(void);

int32_t main(int32_t argc, char *argv[])
{
    int32_t opt;
    int32_t optionIndex = 0;
    int32_t verbose = 0;
    int32_t listFlag = 0;
    const char *outputDir = "output/sdv";
    const char *suiteName = NULL;
    const char *caseName = NULL;
    const char *reportFile = "sdv_test_report.html";
    
    /* 解析命令行参数 */
    while ((opt = getopt_long(argc, argv, "ho:vls:c:r:", g_longOptions, &optionIndex)) != -1) {
        switch (opt) {
            case 'h':
                ShowHelp(argv[0]);
                return 0;
            case 'o':
                outputDir = optarg;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'l':
                listFlag = 1;
                break;
            case 's':
                suiteName = optarg;
                break;
            case 'c':
                caseName = optarg;
                break;
            case 'r':
                reportFile = optarg;
                break;
            default:
                ShowHelp(argv[0]);
                return 1;
        }
    }
    
    /* 初始化测试框架 */
    if (PQCP_TestInit() != 0) {
        fprintf(stderr, "初始化测试框架失败\n");
        return 1;
    }
    
    /* 设置输出目录和详细模式 */
    PQCP_TestSetOutputDir(outputDir);
    
    /* 初始化测试套件 */
    PQCP_InitKemTestSuite();
    // PQCP_InitSignTestSuite();
    // PQCP_InitIntegrationTestSuite();
    
    /* 列出所有测试 */
    if (listFlag) {
        printf("可用的测试套件:\n");
        PQCP_TestListSuites();
        
        if (suiteName != NULL) {
            PqcpTestSuite *suite = PQCP_TestFindSuite(suiteName);
            if (suite != NULL) {
                PQCP_TestListCases(suite);
            } else {
                printf("找不到测试套件: %s\n", suiteName);
            }
        }
        
        PQCP_TestCleanup();
        return 0;
    }
    
    PqcpTestReport report = {0};
    
    /* 运行测试 */
    if (suiteName != NULL) {
        if (caseName != NULL) {
            /* 运行指定的测试用例 */
            report = PQCP_TestRunCaseByName(suiteName, caseName, verbose);
        } else {
            /* 运行指定的测试套件 */
            report = PQCP_TestRunSuiteByName(suiteName, verbose);
        }
    } else {
        /* 运行所有测试 */
        report = PQCP_TestRunAll(verbose);
    }
    
    /* 打印测试报告 */
    PQCP_TestPrintReport(&report);
    
    /* 保存测试报告 */
    PQCP_TestSaveReport(&report, reportFile);
    
    /* 清理测试框架 */
    PQCP_TestCleanup();
    
    /* 根据测试结果返回状态码 */
    return (report.failureCount > 0 || report.errorCount > 0) ? 1 : 0;
} 