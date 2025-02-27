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
 * @file pqcp_test.h
 * @brief PQCP测试框架主头文件
 */

#ifndef PQCP_TEST_H
#define PQCP_TEST_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 测试结果枚举 */
typedef enum {
    PQCP_TEST_SUCCESS = 0,    /* 测试成功 */
    PQCP_TEST_FAILURE = 1,    /* 测试失败 */
    PQCP_TEST_SKIP = 2,       /* 测试跳过 */
    PQCP_TEST_ERROR = -1      /* 测试错误 */
} PqcpTestResult;

/* 测试用例结构 */
typedef struct PqcpTestCase {
    char *name;               /* 测试用例名称 */
    char *description;        /* 测试用例描述 */
    PqcpTestResult (*run)(void); /* 测试用例执行函数 */
    struct PqcpTestCase *next;   /* 链表中的下一个测试用例 */
} PqcpTestCase;

/* 测试套件结构 */
typedef struct PqcpTestSuite {
    char *name;               /* 测试套件名称 */
    char *description;        /* 测试套件描述 */
    PqcpTestCase *cases;      /* 测试用例链表 */
    int32_t caseCount;            /* 测试用例数量 */
    struct PqcpTestSuite *next; /* 链表中的下一个测试套件 */
} PqcpTestSuite;

/* 测试报告结构 */
typedef struct {
    int32_t totalSuites;          /* 总测试套件数 */
    int32_t totalCases;           /* 总测试用例数 */
    int32_t successCount;         /* 成功的测试用例数 */
    int32_t failureCount;         /* 失败的测试用例数 */
    int32_t skipCount;            /* 跳过的测试用例数 */
    int32_t errorCount;           /* 错误的测试用例数 */
    double totalTime;          /* 总执行时间（毫秒） */
} PqcpTestReport;

/* 测试框架初始化和清理 */
int32_t PQCP_TestInit(void);
void PQCP_TestCleanup(void);

/* 测试套件管理 */
PqcpTestSuite* PQCP_TestCreateSuite(const char *name, const char *description);
int32_t PQCP_TestAddSuite(PqcpTestSuite *suite);
PqcpTestSuite* PQCP_TestFindSuite(const char *name);
void PQCP_TestListSuites(void);

/* 测试用例管理 */
int32_t PQCP_TestAddCase(PqcpTestSuite *suite, const char *name, const char *description, PqcpTestResult (*Run)(void));
PqcpTestCase* PQCP_TestFindCase(PqcpTestSuite *suite, const char *name);
void PQCP_TestListCases(PqcpTestSuite *suite);

/* 测试执行 */
PqcpTestReport PQCP_TestRunCase(PqcpTestSuite *suite, PqcpTestCase *testCase, int32_t verbose);
PqcpTestReport PQCP_TestRunSuite(PqcpTestSuite *suite, int32_t verbose);
PqcpTestReport PQCP_TestRunAll(int32_t verbose);
PqcpTestReport PQCP_TestRunSuiteByName(const char *suiteName, int32_t verbose);
PqcpTestReport PQCP_TestRunCaseByName(const char *suiteName, const char *caseName, int32_t verbose);

/* 测试报告 */
void PQCP_TestPrintReport(const PqcpTestReport *report);
int32_t PQCP_TestSaveReport(const PqcpTestReport *report, const char *filename);

/* 辅助函数 */
double PQCP_TestGetTimeMs(void);
void PQCP_TestSetOutputDir(const char *dir);
const char* PQCP_TestGetOutputDir(void);

#endif /* PQCP_TEST_H */ 