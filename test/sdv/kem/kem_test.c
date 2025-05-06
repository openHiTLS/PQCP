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
#include "kem_test.h"
#include "pqcp_types.h"
#include "pqcp_provider.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "crypt_eal_rand.h"

/* scloud+测试用例 */
static PqcpTestResult TestScloudPlusKeygen(void)
{
    /* 示例实现 */
    printf("执行scloud+密钥生成测试...\n");
    CRYPT_EAL_PkeyCtx* ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE,
                                                          "provider=pqcp");
    if (ctx == NULL)
    {
        printf("创建scloud+密钥生成上下文失败\n");
        return PQCP_TEST_FAILURE;
    }
    int32_t val = 256;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, PQCP_SCLOUDPLUS_KEY_BITS, &val, sizeof(val));
    if (ret != CRYPT_SUCCESS)
    {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        printf("设置scloud+密钥生成上下文密钥位数失败\n");
        return PQCP_TEST_FAILURE;
    }
    ret = CRYPT_EAL_PkeyGen(ctx);
    if (ret != CRYPT_SUCCESS)
    {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        printf("生成scloud+密钥失败\n");
        return PQCP_TEST_FAILURE;
    }
    CRYPT_EAL_PkeyPub pub = {CRYPT_PKEY_SCLOUDPLUS, {NULL, 0}};
    ret = CRYPT_EAL_PkeyGetPub(ctx, &pub);
    if (ret != CRYPT_SUCCESS)
    {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        printf("获取scloud+公钥失败\n");
        return PQCP_TEST_FAILURE;
    }
    CRYPT_EAL_PkeyPrv prv = {CRYPT_PKEY_SCLOUDPLUS, {NULL, 0}};
    ret = CRYPT_EAL_PkeyGetPrv(ctx, &prv);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS)
    {
        printf("获取scloud+私钥失败\n");
        return PQCP_TEST_FAILURE;
    }
    /* 模拟测试通过 */
    return PQCP_TEST_SUCCESS;
}

static PqcpTestResult TestScloudPlus(void)
{
    int32_t ret = -1;
    CRYPT_EAL_PkeyCtx *deCtx = NULL;
    int32_t cipherLen = 33832/2;
    int8_t cipher[33832/2] = {0};
    int32_t sharekeyLen = 32;
    int8_t sharekey[32] = {0};
    int8_t sharekey2[32] = {0};
    int32_t val = 256;
    uint8_t pubdata[37520/2];
    BSL_Param pub[2] = {
        {CRYPT_PARAM_SCLOUDPLUS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubdata, sizeof(pubdata), 0},
        BSL_PARAM_END
    };
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE,
        "provider=pqcp");
    ASSERT_TRUE(ctx != NULL, "create ctx failed.");
    deCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE,
        "provider=pqcp");
    ASSERT_TRUE(deCtx != NULL, "create ctx failed.");
    ret = CRYPT_EAL_PkeyCtrl(ctx, PQCP_SCLOUDPLUS_KEY_BITS, &val, sizeof(val));
    ASSERT_EQ(ret, 0, "ctrl param failed.");
    ret = CRYPT_EAL_PkeyCtrl(deCtx, PQCP_SCLOUDPLUS_KEY_BITS, &val, sizeof(val));
    ASSERT_EQ(ret, 0, "ctrl param failed.");
    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, 0, "gen key failed.");
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, 0, "encaps init failed.");
    ret = CRYPT_EAL_PkeyEncaps(ctx, cipher, &cipherLen, sharekey, &sharekeyLen);
    ASSERT_EQ(ret, 0, "encaps failed.");
    ret = CRYPT_EAL_PkeyGetPubEx(ctx, &pub);
    ASSERT_EQ(ret, 0, "get encaps key failed.");
    ret = CRYPT_EAL_PkeySetPubEx(deCtx, &pub);
    ASSERT_EQ(ret, 0, "set encaps key failed.");
    ret = CRYPT_EAL_PkeyDecapsInit(ctx, NULL);
    ASSERT_EQ(ret, 0, "decaps init failed.");
    ret = CRYPT_EAL_PkeyDecaps(ctx, cipher, cipherLen, sharekey2, &sharekeyLen);
    ASSERT_EQ(ret, 0, "decaps failed.");
    ret = memcmp(sharekey, sharekey2, sharekeyLen);
    ASSERT_EQ(ret, 0, "memcmp failed.");
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(deCtx);
    /* 模拟测试通过 */
    return (ret == 0) ? PQCP_TEST_SUCCESS : PQCP_TEST_FAILURE;
}


int32_t TestScloudPlus128_1(void)
{
    return TestScloudPlusEncapsDecaps("../../testdata/scloudplus/scloudplus_testvector/test_vector_128_1.data");
}

int32_t TestScloudPlus128_2(void)
{
    return TestScloudPlusEncapsDecaps("../../testdata/scloudplus/scloudplus_testvector/test_vector_128_2.data");
}

int32_t TestScloudPlus128_3(void)
{
    return TestScloudPlusEncapsDecaps("../../testdata/scloudplus/scloudplus_testvector/test_vector_128_3.data");
}

int32_t TestScloudPlus192_1(void)
{
    return TestScloudPlusEncapsDecaps("../../testdata/scloudplus/scloudplus_testvector/test_vector_192_1.data");
}

int32_t TestScloudPlus192_2(void)
{
    return TestScloudPlusEncapsDecaps("../../testdata/scloudplus/scloudplus_testvector/test_vector_192_2.data");
}

int32_t TestScloudPlus192_3(void)
{
    return TestScloudPlusEncapsDecaps("../../testdata/scloudplus/scloudplus_testvector/test_vector_192_3.data");
}

int32_t TestScloudPlus256_1(void)
{
    return TestScloudPlusEncapsDecaps("../../testdata/scloudplus/scloudplus_testvector/test_vector_256_1.data");
}

int32_t TestScloudPlus256_2(void)
{
    return TestScloudPlusEncapsDecaps("../../testdata/scloudplus/scloudplus_testvector/test_vector_256_2.data");
}

int32_t TestScloudPlus256_3(void)
{
    return TestScloudPlusEncapsDecaps("../../testdata/scloudplus/scloudplus_testvector/test_vector_256_3.data");
}

/* 初始化KEM测试套件 */
int32_t PQCP_InitKemTestSuite(void)
{
    /* 创建KEM测试套件 */
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    PqcpTestSuite* suite = PQCP_TestCreateSuite("kem", "后量子密钥封装机制测试");
    if (suite == NULL)
    {
        return -1;
    }

    PQCP_TestAddCase(suite, "scloudplus base test1", "scloud+ encaps and decaps", TestScloudPlusKeygen);
    PQCP_TestAddCase(suite, "scloudplus base test2", "scloud+ encaps and decaps", TestScloudPlus);
    
    PQCP_TestAddCase(suite, "scloudplus KAT test128_1", "scloud+ vector test 128-1", TestScloudPlus128_1);
    PQCP_TestAddCase(suite, "scloudplus KAT test128_2", "scloud+ vector test 128-2", TestScloudPlus128_2);
    PQCP_TestAddCase(suite, "scloudplus KAT test128_3", "scloud+ vector test 128-3", TestScloudPlus128_3);
    PQCP_TestAddCase(suite, "scloudplus KAT test192_1", "scloud+ vector test 192-1", TestScloudPlus192_1);
    PQCP_TestAddCase(suite, "scloudplus KAT test192_2", "scloud+ vector test 192-2", TestScloudPlus192_2);
    PQCP_TestAddCase(suite, "scloudplus KAT test192_3", "scloud+ vector test 192-3", TestScloudPlus192_3);
    PQCP_TestAddCase(suite, "scloudplus KAT test256_1", "scloud+ vector test 256-1", TestScloudPlus256_1);
    PQCP_TestAddCase(suite, "scloudplus KAT test256_2", "scloud+ vector test 256-2", TestScloudPlus256_2);
    PQCP_TestAddCase(suite, "scloudplus KAT test256_3", "scloud+ vector test 256-3", TestScloudPlus256_3);

    /* 添加测试套件到测试框架 */
    return PQCP_TestAddSuite(suite);
}
