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
#include "scloudplus_local.h"
#include "pqcp_err.h"

/* scloud+测试用例 */
static PqcpTestResult TestScloudPlusKeygen(void)
{
    /* 示例实现 */
    printf("执行scloud+密钥生成测试...\n");
    CRYPT_EAL_PkeyCtx* ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE,
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
    uint8_t pubdata[37520/2];
    uint8_t prvdata[43808/2];
    BSL_Param pub[2] = {
        {PQCP_PARAM_SCLOUDPLUS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubdata, sizeof(pubdata), 0},
        BSL_PARAM_END
    };
    BSL_Param prv[2] = {
        {PQCP_PARAM_SCLOUDPLUS_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvdata, sizeof(prvdata), 0},
        BSL_PARAM_END
    };
    ret = CRYPT_EAL_PkeyGetPubEx(ctx, &pub);
    if (ret != CRYPT_SUCCESS)
    {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        printf("获取scloud+公钥失败\n");
        return PQCP_TEST_FAILURE;
    }
    ret = CRYPT_EAL_PkeyGetPrvEx(ctx, &prv);
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
    SCLOUDPLUS_Para tmpParm = {0};
    BSL_Param pub[2] = {
        {PQCP_PARAM_SCLOUDPLUS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubdata, sizeof(pubdata), 0},
        BSL_PARAM_END
    };
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE,
        "provider=pqcp");
    ASSERT_TRUE(ctx != NULL, "create ctx failed.");
    deCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE,
        "provider=pqcp");
    ASSERT_TRUE(deCtx != NULL, "create ctx failed.");
    ret = CRYPT_EAL_PkeyCtrl(ctx, PQCP_SCLOUDPLUS_KEY_BITS, &val, sizeof(val));
    ASSERT_EQ(ret, 0, "ctrl set key failed.");
    ret = CRYPT_EAL_PkeyCtrl(deCtx, PQCP_SCLOUDPLUS_KEY_BITS, &val, sizeof(val));
    ASSERT_EQ(ret, 0, "ctrl set key failed.");
    ret = CRYPT_EAL_PkeyCtrl(deCtx, PQCP_SCLOUDPLUS_GET_PARA, &tmpParm, sizeof(tmpParm));
    ASSERT_EQ(ret, 0, "ctrl get param failed.");
    ASSERT_EQ(tmpParm.kemSkSize, 21904, "ctrl get param param failed."); // due to key bits = 256.

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
    printf("Testing [ScloudPlus128_1] with [../../testdata/scloudplus/scloudplus_testvector/test_vector_128_1.data\n");
    return TestScloudPlusEncapsDecaps("../../testdata/scloudplus/scloudplus_testvector/test_vector_128_1.data");
}

int32_t TestScloudPlus128_2(void)
{
    printf("Testing [ScloudPlus128_2] with [../../testdata/scloudplus/scloudplus_testvector/test_vector_128_2.data\n");
    return TestScloudPlusEncapsDecaps("../../testdata/scloudplus/scloudplus_testvector/test_vector_128_2.data");
}

int32_t TestScloudPlus128_3(void)
{
    printf("Testing [ScloudPlus128_3] with [../../testdata/scloudplus/scloudplus_testvector/test_vector_128_3.data\n");
    return TestScloudPlusEncapsDecaps("../../testdata/scloudplus/scloudplus_testvector/test_vector_128_3.data");
}

int32_t TestScloudPlus192_1(void)
{
    printf("Testing [ScloudPlus192_1] with [../../testdata/scloudplus/scloudplus_testvector/test_vector_192_1.data\n");
    return TestScloudPlusEncapsDecaps("../../testdata/scloudplus/scloudplus_testvector/test_vector_192_1.data");
}

int32_t TestScloudPlus192_2(void)
{
    printf("Testing [ScloudPlus192_2] with [../../testdata/scloudplus/scloudplus_testvector/test_vector_192_2.data\n");
    return TestScloudPlusEncapsDecaps("../../testdata/scloudplus/scloudplus_testvector/test_vector_192_2.data");
}

int32_t TestScloudPlus192_3(void)
{
    printf("Testing [ScloudPlus192_3] with [../../testdata/scloudplus/scloudplus_testvector/test_vector_192_3.data\n");
    return TestScloudPlusEncapsDecaps("../../testdata/scloudplus/scloudplus_testvector/test_vector_192_3.data");
}

int32_t TestScloudPlus256_1(void)
{
    printf("Testing [ScloudPlus256_1] with [../../testdata/scloudplus/scloudplus_testvector/test_vector_256_1.data\n");
    return TestScloudPlusEncapsDecaps("../../testdata/scloudplus/scloudplus_testvector/test_vector_256_1.data");
}

int32_t TestScloudPlus256_2(void)
{
    printf("Testing [ScloudPlus256_2] with [../../testdata/scloudplus/scloudplus_testvector/test_vector_256_2.data\n");
    return TestScloudPlusEncapsDecaps("../../testdata/scloudplus/scloudplus_testvector/test_vector_256_2.data");
}

int32_t TestScloudPlus256_3(void)
{
    printf("Testing [ScloudPlus256_3] with [../../testdata/scloudplus/scloudplus_testvector/test_vector_256_3.data\n");
    return TestScloudPlusEncapsDecaps("../../testdata/scloudplus/scloudplus_testvector/test_vector_256_3.data");
}


int32_t TestRand(uint8_t *rand, uint32_t randLen) {
    for (uint i = 0; i < randLen; ++i) {
        rand[i] = i;
    }
    return 0;
}

static PqcpTestResult TestPolarlac(void)
{
    CRYPT_EAL_SetRandCallBack(TestRand);
    int32_t ret = -1;
    CRYPT_EAL_PkeyCtx *deCtx = NULL;
    
    // Polarlac算法参数 - 需要根据实际算法调整这些值
    int32_t cipherLen = 4096;  // 假设的密文长度，请根据实际调整
    int8_t cipher[4096] = {0};
    int32_t sharekeyLen = 32;  // 共享密钥长度
    int8_t sharekey[32] = {0};
    int8_t sharekey2[32] = {0};
    int32_t val = PQCP_POLAR_LAC_LIGHT;         // 密钥位数
    
    // 公钥数据缓冲区 - 大小需要根据实际算法调整
    uint8_t pubdata[8192];
    uint8_t prvdata[8192];
    // Polarlac参数结构 - 需要根据实际定义调整
    
    BSL_Param pub[2] = {
        {PQCP_PARAM_POLAR_LAC_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubdata, sizeof(pubdata), 0},
        BSL_PARAM_END
    };
    BSL_Param prv[2] = {
        {PQCP_PARAM_POLAR_LAC_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvdata, sizeof(prvdata), 0},
        BSL_PARAM_END
    };
    // 创建加密封装上下文
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_POLAR_LAC, CRYPT_EAL_PKEY_KEM_OPERATE,
        "provider=pqcp");
    ASSERT_TRUE(ctx != NULL, "create ctx failed.");
    
    // 创建解封装上下文
    deCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_POLAR_LAC, CRYPT_EAL_PKEY_KEM_OPERATE,
        "provider=pqcp");
    ASSERT_TRUE(deCtx != NULL, "create ctx failed.");
    
    ret = CRYPT_EAL_PkeyGetPubEx(ctx, pub);
    ASSERT_EQ(ret, PQCP_NULL_INPUT, "get pub key error code incorrect");
    
    ret = CRYPT_EAL_PkeyGetPrvEx(ctx, prv);
    ASSERT_EQ(ret, PQCP_NULL_INPUT, "get prv key error code incorrect");
    // 设置密钥位数
    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_POLAR_LAC_KEYINFO_NOT_SET, "gen key error code incorrect");

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, 0, "ctrl set key failed.");
    ret = CRYPT_EAL_PkeyCtrl(deCtx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, 0, "ctrl set key failed.");


    // 生成密钥对
    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, 0, "gen key failed.");

    // 初始化封装操作
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, 0, "encaps init failed.");

    uint32_t realCipherLen = cipherLen;
    // 执行封装
    ret = CRYPT_EAL_PkeyEncaps(ctx, cipher, &realCipherLen, sharekey, &sharekeyLen);
    ASSERT_EQ(ret, 0, "encaps failed.");

    // 获取公钥
    ret = CRYPT_EAL_PkeyGetPrvEx(ctx, prv);
    ASSERT_EQ(ret, 0, "get decaps key failed.");

    ret = CRYPT_EAL_PkeyGetPubEx(ctx, pub);
    ASSERT_EQ(ret, 0, "get encaps key failed.");
    // 设置公钥到解封装上下文
    ret = CRYPT_EAL_PkeySetPrvEx(deCtx, prv);
    ASSERT_EQ(ret, 0, "set encaps key failed.");

    // 初始化解封装操作
    ret = CRYPT_EAL_PkeyDecapsInit(deCtx, NULL);  // 注意：这里应该是deCtx而不是ctx
    ASSERT_EQ(ret, 0, "decaps init failed.");

    // 执行解封装
    ret = CRYPT_EAL_PkeyDecaps(deCtx, cipher, realCipherLen, sharekey2, &sharekeyLen);
    ASSERT_EQ(ret, 0, "decaps failed.");

    // 验证共享密钥是否匹配
    ret = memcmp(sharekey, sharekey2, sharekeyLen);
    ASSERT_EQ(ret, 0, "memcmp failed.");

    int8_t cipher2[4096] = {0};
    uint8_t ss2[32] = {0};
    CRYPT_EAL_PkeyCtx *dumpCtx = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(dumpCtx != NULL, "create ctx failed.");

    ret = CRYPT_EAL_PkeyEncaps(dumpCtx, cipher2, &realCipherLen, ss2, &sharekeyLen);
    ASSERT_EQ(ret, 0, "encaps failed.");
    
    ret = memcmp(sharekey, ss2, sharekeyLen);
    ASSERT_EQ(ret, 0, "memcmp ss2 and sharekey failed.");

    ret = memcmp(cipher, cipher2, realCipherLen);
    ASSERT_EQ(ret, 0, "memcmp ss2 and sharekey failed.");
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(deCtx);
    return (ret == 0) ? PQCP_TEST_SUCCESS : PQCP_TEST_FAILURE;
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
    PQCP_TestAddCase(suite, "Polarlac Api test", "all kat", TestPolarlac);
    /* 添加测试套件到测试框架 */
    return PQCP_TestAddSuite(suite);
}
