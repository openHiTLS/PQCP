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
#include <time.h>
#include <stdarg.h>

/* 测试框架上下文 */
typedef struct {
    PqcpTestSuite *suites;    /* 测试套件链表 */
    int suiteCount;          /* 测试套件数量 */
    const char *outputDir;   /* 输出目录 */
    FILE *logFile;           /* 日志文件 */
    int verbose;              /* 详细模式 */
} PqcpTestContext;

/* 全局测试上下文 */
static PqcpTestContext g_testCtx = {0};

/**
 * 获取当前时间（毫秒）
 */
double PQCP_TestGetTimeMs(void) {
    struct timespec ts;
    
#ifdef _WIN32
    /* Windows实现 */
    timespec_get(&ts, TIME_UTC);
#else
    /* POSIX实现 */
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

/**
 * 设置输出目录
 */
void PQCP_TestSetOutputDir(const char *dir) {
    g_testCtx.outputDir = dir;
}

/**
 * 获取输出目录
 */
const char *PQCP_TestGetOutputDir(void) {
    return g_testCtx.outputDir;
}

/**
 * 写入日志
 */
static void PQCP_TestLog(const char *format, ...) {
    if (g_testCtx.logFile == NULL) {
        return;
    }
    
    va_list args;
    va_start(args, format);
    vfprintf(g_testCtx.logFile, format, args);
    va_end(args);
    
    /* 如果是详细模式，也输出到控制台 */
    if (g_testCtx.verbose) {
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
    }
    
    /* 刷新日志文件 */
    fflush(g_testCtx.logFile);
}

/**
 * 初始化测试框架
 */
int PQCP_TestInit(void) {
    /* 清理现有上下文（如果有） */
    PQCP_TestCleanup();
    
    /* 初始化上下文 */
    memset(&g_testCtx, 0, sizeof(PqcpTestContext));
    g_testCtx.outputDir = "output";
    g_testCtx.verbose = 0;
    
    /* 创建输出目录 */
    char cmd[256];
#ifdef _WIN32
    snprintf(cmd, sizeof(cmd), "if not exist \"%s\" mkdir \"%s\"", g_testCtx.outputDir, g_testCtx.outputDir);
#else
    snprintf(cmd, sizeof(cmd), "mkdir -p \"%s\"", g_testCtx.outputDir);
#endif
    system(cmd);
    
    /* 打开日志文件 */
    char logPath[256];
    snprintf(logPath, sizeof(logPath), "%s/test_log.txt", g_testCtx.outputDir);
    g_testCtx.logFile = fopen(logPath, "w");
    if (g_testCtx.logFile == NULL) {
        fprintf(stderr, "无法创建日志文件: %s\n", logPath);
        return -1;
    }
    
    /* 记录测试开始时间 */
    time_t now = time(NULL);
    PQCP_TestLog("测试开始: %s", ctime(&now));
    
    return 0;
}

/**
 * 清理测试框架
 */
void PQCP_TestCleanup(void) {
    /* 关闭日志文件 */
    if (g_testCtx.logFile != NULL) {
        fclose(g_testCtx.logFile);
        g_testCtx.logFile = NULL;
    }
    
    /* 释放测试套件 */
    PqcpTestSuite *suite = g_testCtx.suites;
    while(suite != NULL) {
        /* 释放测试用例 */
        PqcpTestCase *testCase = suite->cases;
        while (testCase != NULL) {
            PqcpTestCase *next_case = testCase->next;
            free(testCase->name);
            free(testCase->description);
            free(testCase);
            testCase = next_case;
        }
        
        PqcpTestSuite *next_suite = suite->next;
        free(suite->name);
        free(suite->description);
        free(suite);
        suite = next_suite;
    }
    
    g_testCtx.suites = NULL;
    g_testCtx.suiteCount = 0;
}

/**
 * 创建测试套件
 */
PqcpTestSuite *PQCP_TestCreateSuite(const char *name, const char *description) {
    if (name == NULL) {
        return NULL;
    }
    
    /* 分配内存 */
    PqcpTestSuite *suite = (PqcpTestSuite *)malloc(sizeof(PqcpTestSuite));
    if (suite == NULL) {
        return NULL;
    }
    
    /* 初始化套件 */
    memset(suite, 0, sizeof(PqcpTestSuite));
    
    /* 复制名称和描述 */
    suite->name = strdup(name);
    if (suite->name == NULL) {
        free(suite);
        return NULL;
    }
    
    if (description != NULL) {
        suite->description = strdup(description);
        if (suite->description == NULL) {
            free(suite->name);
            free(suite);
            return NULL;
        }
    }
    
    return suite;
}

/**
 * 添加测试套件
 */
int PQCP_TestAddSuite(PqcpTestSuite *suite) {
    if (suite == NULL) {
        return -1;
    }
    
    /* 检查是否已存在同名套件 */
    PqcpTestSuite *existing = PQCP_TestFindSuite(suite->name);
    if (existing != NULL) {
        return -1;
    }
    
    /* 添加到链表头部 */
    suite->next = g_testCtx.suites;
    g_testCtx.suites = suite;
    g_testCtx.suiteCount++;
    
    return 0;
}

/**
 * 查找测试套件
 */
PqcpTestSuite *PQCP_TestFindSuite(const char *name) {
    if (name == NULL) {
        return NULL;
    }
    
    PqcpTestSuite *suite = g_testCtx.suites;
    while (suite != NULL) {
        if (strcmp(suite->name, name) == 0) {
            return suite;
        }
        suite = suite->next;
    }
    
    return NULL;
}

/**
 * 列出所有测试套件
 */
void PQCP_TestListSuites(void) {
    printf("可用的测试套件:\n");
    
    PqcpTestSuite *suite = g_testCtx.suites;
    while (suite != NULL) {
        printf("  %s", suite->name);
        if (suite->description != NULL) {
            printf(" - %s", suite->description);
        }
        printf("\n");
        suite = suite->next;
    }
}

/**
 * 添加测试用例
 */
int PQCP_TestAddCase(PqcpTestSuite *suite, const char *name, const char *description, 
                      PqcpTestResult (*run)(void)) {
    if (suite == NULL || name == NULL || run == NULL) {
        return -1;
    }
    
    /* 检查是否已存在同名测试用例 */
    PqcpTestCase *existing = PQCP_TestFindCase(suite, name);
    if (existing != NULL) {
        return -1;
    }
    
    /* 分配内存 */
    PqcpTestCase *testCase = (PqcpTestCase *)malloc(sizeof(PqcpTestCase));
    if (testCase == NULL) {
        return -1;
    }
    
    /* 初始化测试用例 */
    memset(testCase, 0, sizeof(PqcpTestCase));
    
    /* 复制名称和描述 */
    testCase->name = strdup(name);
    if (testCase->name == NULL) {
        free(testCase);
        return -1;
    }
    
    if (description != NULL) {
        testCase->description = strdup(description);
        if (testCase->description == NULL) {
            free(testCase->name);
            free(testCase);
            return -1;
        }
    }
    
    testCase->run = run;
    
    /* 添加到链表头部 */
    testCase->next = suite->cases;
    suite->cases = testCase;
    suite->caseCount++;
    
    return 0;
}

/**
 * 查找测试用例
 */
PqcpTestCase *PQCP_TestFindCase(PqcpTestSuite *suite, const char *name) {
    if (suite == NULL || name == NULL) {
        return NULL;
    }
    
    PqcpTestCase *testCase = suite->cases;
    while (testCase != NULL) {
        if (strcmp(testCase->name, name) == 0) {
            return testCase;
        }
        testCase = testCase->next;
    }
    
    return NULL;
}

/**
 * 列出测试套件中的所有测试用例
 */
void PQCP_TestListCases(PqcpTestSuite *suite) {
    if (suite == NULL) {
        return;
    }
    
    printf("测试套件 '%s' 中的测试用例:\n", suite->name);
    
    PqcpTestCase *testCase = suite->cases;
    while (testCase != NULL) {
        printf("  %s", testCase->name);
        if (testCase->description != NULL) {
            printf(" - %s", testCase->description);
        }
        printf("\n");
        testCase = testCase->next;
    }
}

/**
 * 运行单个测试用例
 */
PqcpTestReport PQCP_TestRunCase(PqcpTestSuite *suite, PqcpTestCase *testCase, int verbose) {
    PqcpTestReport report = {0};
    
    if (suite == NULL || testCase == NULL) {
        report.errorCount = 1;
        return report;
    }
    
    /* 初始化报告 */
    report.totalSuites = 1;
    report.totalCases = 1;
    
    /* 记录测试开始 */
    PQCP_TestLog("\n运行测试: %s::%s\n", suite->name, testCase->name);
    if (testCase->description != NULL) {
        PQCP_TestLog("描述: %s\n", testCase->description);
    }
    
    /* 记录开始时间 */
    double start_time = PQCP_TestGetTimeMs();
    
    /* 运行测试 */
    PqcpTestResult result = testCase->run();
    
    /* 记录结束时间 */
    double end_time = PQCP_TestGetTimeMs();
    double elapsed_time = end_time - start_time;
    report.totalTime = elapsed_time;
    
    /* 更新报告 */
    switch (result) {
        case PQCP_TEST_SUCCESS:
            report.successCount = 1;
            PQCP_TestLog("结果: 成功 (%.2f ms)\n", elapsed_time);
            break;
        case PQCP_TEST_FAILURE:
            report.failureCount = 1;
            PQCP_TestLog("结果: 失败 (%.2f ms)\n", elapsed_time);
            break;
        case PQCP_TEST_SKIP:
            report.skipCount = 1;
            PQCP_TestLog("结果: 跳过 (%.2f ms)\n", elapsed_time);
            break;
        default:
            report.errorCount = 1;
            PQCP_TestLog("结果: 错误 (%.2f ms)\n", elapsed_time);
            break;
    }
    
    return report;
}

/**
 * 运行测试套件
 */
PqcpTestReport PQCP_TestRunSuite(PqcpTestSuite *suite, int verbose) {
    PqcpTestReport report = {0};
    
    if (suite == NULL) {
        report.errorCount = 1;
        return report;
    }
    
    /* 初始化报告 */
    report.totalSuites = 1;
    report.totalCases = suite->caseCount;
    
    /* 记录测试开始 */
    PQCP_TestLog("\n运行测试套件: %s\n", suite->name);
    if (suite->description != NULL) {
        PQCP_TestLog("描述: %s\n", suite->description);
    }
    PQCP_TestLog("测试用例数: %d\n\n", suite->caseCount);
    
    /* 记录开始时间 */
    double start_time = PQCP_TestGetTimeMs();
    
    /* 运行所有测试用例 */
    PqcpTestCase *testCase = suite->cases;
    while (testCase != NULL) {
        PqcpTestReport case_report = PQCP_TestRunCase(suite, testCase, verbose);
        
        /* 更新报告 */
        report.successCount += case_report.successCount;
        report.failureCount += case_report.failureCount;
        report.skipCount += case_report.skipCount;
        report.errorCount += case_report.errorCount;
        report.totalTime += case_report.totalTime;
        
        testCase = testCase->next;
    }
    
    /* 记录结束时间 */
    double end_time = PQCP_TestGetTimeMs();
    double total_elapsed_time = end_time - start_time;
    
    /* 打印套件摘要 */
    PQCP_TestLog("\n测试套件 '%s' 摘要:\n", suite->name);
    PQCP_TestLog("  总用例数: %d\n", suite->caseCount);
    PQCP_TestLog("  成功: %d\n", report.successCount);
    PQCP_TestLog("  失败: %d\n", report.failureCount);
    PQCP_TestLog("  跳过: %d\n", report.skipCount);
    PQCP_TestLog("  错误: %d\n", report.errorCount);
    PQCP_TestLog("  总时间: %.2f ms\n", total_elapsed_time);
    
    return report;
}

/**
 * 运行所有测试
 */
PqcpTestReport PQCP_TestRunAll(int verbose) {
    PqcpTestReport report = {0};
    
    /* 初始化报告 */
    report.totalSuites = g_testCtx.suiteCount;
    
    /* 记录测试开始 */
    PQCP_TestLog("\n运行所有测试\n");
    PQCP_TestLog("测试套件数: %d\n\n", g_testCtx.suiteCount);
    
    /* 记录开始时间 */
    double start_time = PQCP_TestGetTimeMs();
    
    /* 运行所有测试套件 */
    PqcpTestSuite *suite = g_testCtx.suites;
    while (suite != NULL) {
        PqcpTestReport suite_report = PQCP_TestRunSuite(suite, verbose);
        
        /* 更新报告 */
        report.totalCases += suite_report.totalCases;
        report.successCount += suite_report.successCount;
        report.failureCount += suite_report.failureCount;
        report.skipCount += suite_report.skipCount;
        report.errorCount += suite_report.errorCount;
        report.totalTime += suite_report.totalTime;
        
        suite = suite->next;
    }
    
    /* 记录结束时间 */
    double end_time = PQCP_TestGetTimeMs();
    double total_elapsed_time = end_time - start_time;
    
    /* 打印总摘要 */
    PQCP_TestLog("\n测试总摘要:\n");
    PQCP_TestLog("  总套件数: %d\n", report.totalSuites);
    PQCP_TestLog("  总用例数: %d\n", report.totalCases);
    PQCP_TestLog("  成功: %d\n", report.successCount);
    PQCP_TestLog("  失败: %d\n", report.failureCount);
    PQCP_TestLog("  跳过: %d\n", report.skipCount);
    PQCP_TestLog("  错误: %d\n", report.errorCount);
    PQCP_TestLog("  总时间: %.2f ms\n", total_elapsed_time);
    
    return report;
}

/**
 * 按名称运行测试套件
 */
PqcpTestReport PQCP_TestRunSuiteByName(const char *suiteName, int verbose) {
    PqcpTestReport report = {0};
    
    if (suiteName == NULL) {
        report.errorCount = 1;
        return report;
    }
    
    /* 查找测试套件 */
    PqcpTestSuite *suite = PQCP_TestFindSuite(suiteName);
    if (suite == NULL) {
        PQCP_TestLog("错误: 找不到测试套件 '%s'\n", suiteName);
        report.errorCount = 1;
        return report;
    }
    
    /* 运行测试套件 */
    return PQCP_TestRunSuite(suite, verbose);
}

/**
 * 按名称运行测试用例
 */
PqcpTestReport PQCP_TestRunCaseByName(const char *suiteName, const char *caseName, int verbose) {
    PqcpTestReport report = {0};
    
    if (suiteName == NULL || caseName == NULL) {
        report.errorCount = 1;
        return report;
    }
    
    /* 查找测试套件 */
    PqcpTestSuite *suite = PQCP_TestFindSuite(suiteName);
    if (suite == NULL) {
        PQCP_TestLog("错误: 找不到测试套件 '%s'\n", suiteName);
        report.errorCount = 1;
        return report;
    }
    
    /* 查找测试用例 */
    PqcpTestCase *testCase = PQCP_TestFindCase(suite, caseName);
    if (testCase == NULL) {
        PQCP_TestLog("错误: 在测试套件 '%s' 中找不到测试用例 '%s'\n", suiteName, caseName);
        report.errorCount = 1;
        return report;
    }
    
    /* 运行测试用例 */
    return PQCP_TestRunCase(suite, testCase, verbose);
}

/**
 * 打印测试报告
 */
void PQCP_TestPrintReport(const PqcpTestReport *report) {
    if (report == NULL) {
        return;
    }
    
    printf("\n测试报告摘要:\n");
    printf("  总套件数: %d\n", report->totalSuites);
    printf("  总用例数: %d\n", report->totalCases);
    printf("  成功率: %.2f%%\n", 
        (double)report->successCount / report->totalCases * 100);
    printf("  失败: %d\n", report->failureCount);
    printf("  跳过: %d\n", report->skipCount);
    printf("  错误: %d\n", report->errorCount);
    printf("  总时间: %.2f ms\n", report->totalTime);
    
    /* 打印测试结果状态 */
    if (report->failureCount == 0 && report->errorCount == 0) {
        printf("\n测试结果: 通过 ✓\n");
    } else {
        printf("\n测试结果: 失败 ✗\n");
    }
}

/**
 * 保存测试报告到文件
 */
int PQCP_TestSaveReport(const PqcpTestReport *report, const char *filename) {
    if (report == NULL || filename == NULL) {
        return -1;
    }
    
    /* 构建完整的文件路径 */
    char file_path[256];
    snprintf(file_path, sizeof(file_path), "%s/%s", g_testCtx.outputDir, filename);
    
    /* 打开文件 */
    FILE *file = fopen(file_path, "w");
    if (file == NULL) {
        PQCP_TestLog("错误: 无法创建报告文件 '%s'\n", file_path);
        return -1;
    }
    
    /* 写入HTML报告头部 */
    fprintf(file, "<!DOCTYPE html>\n");
    fprintf(file, "<html>\n");
    fprintf(file, "<head>\n");
    fprintf(file, "  <meta charset=\"UTF-8\">\n");
    fprintf(file, "  <title>PQCP测试报告</title>\n");
    fprintf(file, "  <style>\n");
    fprintf(file, "    body { font-family: Arial, sans-serif; margin: 20px; }\n");
    fprintf(file, "    h1 { color: #333; }\n");
    fprintf(file, "    .summary { margin: 20px 0; }\n");
    fprintf(file, "    .success { color: green; }\n");
    fprintf(file, "    .failure { color: red; }\n");
    fprintf(file, "    .skip { color: orange; }\n");
    fprintf(file, "    .error { color: darkred; }\n");
    fprintf(file, "    table { border-collapse: collapse; width: 100%%; }\n");
    fprintf(file, "    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
    fprintf(file, "    th { background-color: #f2f2f2; }\n");
    fprintf(file, "    tr:nth-child(even) { background-color: #f9f9f9; }\n");
    fprintf(file, "  </style>\n");
    fprintf(file, "</head>\n");
    fprintf(file, "<body>\n");
    
    /* 写入报告标题 */
    fprintf(file, "  <h1>PQCP测试报告</h1>\n");
    
    /* 写入生成时间 */
    time_t now = time(NULL);
    fprintf(file, "  <p>生成时间: %s</p>\n", ctime(&now));
    
    /* 写入摘要 */
    fprintf(file, "  <div class=\"summary\">\n");
    fprintf(file, "    <h2>测试摘要</h2>\n");
    fprintf(file, "    <p>总套件数: %d</p>\n", report->totalSuites);
    fprintf(file, "    <p>总用例数: %d</p>\n", report->totalCases);
    fprintf(file, "    <p class=\"success\">成功率: %.2f%%</p>\n", 
        (double)report->successCount / report->totalCases * 100);
    fprintf(file, "    <p class=\"failure\">失败: %d</p>\n", report->failureCount);
    fprintf(file, "    <p class=\"skip\">跳过: %d</p>\n", report->skipCount);
    fprintf(file, "    <p class=\"error\">错误: %d</p>\n", report->errorCount);
    fprintf(file, "    <p>总时间: %.2f ms</p>\n", report->totalTime);
    
    /* 写入测试结果状态 */
    if (report->failureCount == 0 && report->errorCount == 0) {
        fprintf(file, "    <h2 class=\"success\">测试结果: 通过 ✓</h2>\n");
    } else {
        fprintf(file, "    <h2 class=\"failure\">测试结果: 失败 ✗</h2>\n");
    }
    fprintf(file, "  </div>\n");
    
    /* 写入HTML报告尾部 */
    fprintf(file, "</body>\n");
    fprintf(file, "</html>\n");
    
    /* 关闭文件 */
    fclose(file);
    
    PQCP_TestLog("测试报告已保存到: %s\n", file_path);
    
    return 0;
} 