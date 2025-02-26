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
#include "pqcp_test.h"
#include "pqcp_types.h"
#include "pqcp_provider.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"

/* KEM测试用例 */

static int32_t PQCP_TestLoadProvider(void)
{
    int32_t ret = CRYPT_EAL_ProviderSetLoadPath(NULL, "/path/to/pqcp/build");
    if (ret != CRYPT_SUCCESS) {
        printf("设置PQCP提供者路径失败\n");
        return PQCP_TEST_FAILURE;
    }
    ret = CRYPT_EAL_ProviderLoad(NULL, BSL_SAL_LIB_FMT_LIBSO, "pqcp_provider", NULL, NULL);
    if (ret != CRYPT_SUCCESS) {
        printf("加载PQCP提供者失败\n");
        return PQCP_TEST_FAILURE;
    }
    /* 模拟测试通过 */
    return PQCP_TEST_SUCCESS;
}

/* scloud+测试用例 */
static PqcpTestResult TestScloudPlusKeygen(void)
{    
    /* 示例实现 */
    printf("执行scloud+密钥生成测试...\n");
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    if (ctx == NULL) {
        printf("创建scloud+密钥生成上下文失败\n");
        return PQCP_TEST_FAILURE;
    }
    int32_t val = 256;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, PQCP_SCLOUDPLUS_KEY_BITS, &val, sizeof(val));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        printf("设置scloud+密钥生成上下文密钥位数失败\n");
        return PQCP_TEST_FAILURE;
    }
    ret = CRYPT_EAL_PkeyGen(ctx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        printf("生成scloud+密钥失败\n");
        return PQCP_TEST_FAILURE;
    }
    CRYPT_EAL_PkeyPub pub = {CRYPT_PKEY_SCLOUDPLUS, {NULL, 0}};
    ret = CRYPT_EAL_PkeyGetPub(ctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        printf("获取scloud+公钥失败\n");
        return PQCP_TEST_FAILURE;
    }
    CRYPT_EAL_PkeyPrv prv = {CRYPT_PKEY_SCLOUDPLUS, {NULL, 0}};
    ret = CRYPT_EAL_PkeyGetPrv(ctx, &prv);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        printf("获取scloud+私钥失败\n");
        return PQCP_TEST_FAILURE;
    }
    /* 模拟测试通过 */
    return PQCP_TEST_SUCCESS;
}

static PqcpTestResult TestScloudPlusEncaps(void)
{
    
    /* 示例实现 */
    printf("执行scloud+密钥封装测试...\n");
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    if (ctx == NULL) {
        printf("创建scloud+密钥生成上下文失败\n");
        return PQCP_TEST_FAILURE;
    }
    int32_t val = 256;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, PQCP_SCLOUDPLUS_KEY_BITS, &val, sizeof(val));
    if (ret != CRYPT_SUCCESS) {
        printf("设置scloud+密钥生成上下文密钥位数失败\n");
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return PQCP_TEST_FAILURE;
    }
    ret = CRYPT_EAL_PkeyGen(ctx);
    if (ret != CRYPT_SUCCESS) {
        printf("生成scloud+密钥失败\n");
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return PQCP_TEST_FAILURE;
    }
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    if (ret != CRYPT_SUCCESS) {
        printf("初始化scloud+密钥封装失败\n");
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return PQCP_TEST_FAILURE;
    }
    uint8_t cipher[1024];
    uint32_t cipherLen = sizeof(cipher);
    uint8_t sharekey[1024];
    uint32_t sharekeyLen = sizeof(sharekey);
    ret = CRYPT_EAL_PkeyEncaps(ctx, cipher, &cipherLen, sharekey, &sharekeyLen);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        printf("scloud+密钥封装失败\n");
        return PQCP_TEST_FAILURE;
    }
    /* 模拟测试通过 */
    return PQCP_TEST_SUCCESS;
}

static PqcpTestResult TestScloudPlusDecaps(void)
{
    /* 这里是scloud+密钥解封装测试的实现 */
    /* 在实际实现中，应该调用PQCP库的scloud+密钥解封装函数 */
    
    /* 示例实现 */
    printf("执行scloud+密钥解封装测试...\n");
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    if (ctx == NULL) {
        printf("创建scloud+密钥生成上下文失败\n");
        return PQCP_TEST_FAILURE;
    }
    int32_t val = 256;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, PQCP_SCLOUDPLUS_KEY_BITS, &val, sizeof(val));
    if (ret != CRYPT_SUCCESS) {
        printf("设置scloud+密钥生成上下文密钥位数失败\n");
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return PQCP_TEST_FAILURE;
    }
    ret = CRYPT_EAL_PkeyGen(ctx);
    if (ret != CRYPT_SUCCESS) {
        printf("生成scloud+密钥失败\n");
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return PQCP_TEST_FAILURE;
    }
    ret = CRYPT_EAL_PkeyDecapsInit(ctx, NULL);
    if (ret != CRYPT_SUCCESS) {
        printf("初始化scloud+密钥解封装失败\n");
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return PQCP_TEST_FAILURE;
    }
    uint8_t cipher[1024];
    uint32_t cipherLen = sizeof(cipher);
    uint8_t sharekey[1024];
    uint32_t sharekeyLen = sizeof(sharekey);
    ret = CRYPT_EAL_PkeyDecaps(ctx, cipher, cipherLen, sharekey, &sharekeyLen);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        printf("scloud+密钥解封装失败\n");
        return PQCP_TEST_FAILURE;
    }

    /* 模拟测试通过 */
    return PQCP_TEST_SUCCESS;
}

/* 初始化KEM测试套件 */
int32_t PQCP_InitKemTestSuite(void)
{
    /* 创建KEM测试套件 */
    PqcpTestSuite *suite = PQCP_TestCreateSuite("kem", "后量子密钥封装机制测试");
    if (suite == NULL) {
        return -1;
    }
    if (PQCP_TestLoadProvider() != PQCP_TEST_SUCCESS) {
        return -1;
    }
    /* 添加scloud+测试用例 */
    PQCP_TestAddCase(suite, "scloudplus_keygen", "scloud+密钥生成测试", TestScloudPlusKeygen);
    PQCP_TestAddCase(suite, "scloudplus_encaps", "scloud+密钥封装测试", TestScloudPlusEncaps);
    PQCP_TestAddCase(suite, "scloudplus_decaps", "scloud+密钥解封装测试", TestScloudPlusDecaps);
    
    /* 添加测试套件到测试框架 */
    return PQCP_TestAddSuite(suite);
}