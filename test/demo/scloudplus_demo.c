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
#include <linux/limits.h>
#include <unistd.h>
#include <libgen.h>
#include "pqcp_types.h"
#include "pqcp_provider.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "crypt_eal_rand.h"

/* 这里应该包含PQCP库的头文件 */
/* 在实际使用中，应该替换为正确的头文件路径 */
#include "pqcp_test.h"

/* 演示用的消息 */
const char *demo_message = "这是一条使用后量子密码算法保护的消息";

/**
 * 打印缓冲区内容（十六进制）
 */
static void PrintHex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i < len - 1) {
            printf("\n     ");
        }
    }
    printf("\n");
}

/**
 * scloud+密钥封装机制（KEM）演示
 */
static int32_t ScloudplusDemo(void)
{
    printf("\n=== Scloud+密钥封装机制(KEM)演示 ===\n\n");
    int32_t ret = -1;
    CRYPT_EAL_PkeyCtx *deCtx = NULL;
    int32_t cipherLen = 33832/2;
    int8_t cipher[33832/2] = {0};
    int32_t sharekeyLen = 32;
    int8_t sharekey[32] = {0};
    int32_t sharekey2Len = 32;
    int8_t sharekey2[32] = {0};
    int32_t val = 256;
    uint8_t pubdata[37520/2];
    BSL_Param pub[2] = {
        {CRYPT_PARAM_SCLOUDPLUS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubdata, sizeof(pubdata), 0},
        BSL_PARAM_END
    };
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE,
        "provider=pqcp");
    if (ctx == NULL) {
        printf("create ctx failed.\n");
        goto EXIT;
    }
    deCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE,
        "provider=pqcp");
    if (deCtx == NULL) {
        printf("create ctx failed.\n");
        goto EXIT;
    }
    ret = CRYPT_EAL_PkeyCtrl(ctx, PQCP_SCLOUDPLUS_KEY_BITS, &val, sizeof(val));
    if (ret != CRYPT_SUCCESS) {
        printf("ctrl param failed.\n");
        goto EXIT;
    }
    ret = CRYPT_EAL_PkeyCtrl(deCtx, PQCP_SCLOUDPLUS_KEY_BITS, &val, sizeof(val));
    if (ret != CRYPT_SUCCESS) {
        printf("ctrl param failed.\n");
        goto EXIT;
    }
    ret = CRYPT_EAL_PkeyGen(ctx);
    if (ret != CRYPT_SUCCESS) {
        printf("gen key failed.\n");
        goto EXIT;
    }
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    if (ret != CRYPT_SUCCESS) {
        printf("encaps init failed.\n");
        goto EXIT;
    }
    ret = CRYPT_EAL_PkeyEncaps(ctx, cipher, &cipherLen, sharekey, &sharekeyLen);
    if (ret != CRYPT_SUCCESS) {
        printf("encaps failed.\n");
        goto EXIT;
    }
    ret = CRYPT_EAL_PkeyGetPubEx(ctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        printf("get encaps key failed.\n");
        goto EXIT;
    }
    ret = CRYPT_EAL_PkeySetPubEx(deCtx, &pub);
    if (ret != CRYPT_SUCCESS) {
        printf("set encaps key failed.\n");
        goto EXIT;
    }
    ret = CRYPT_EAL_PkeyDecapsInit(ctx, NULL);
    if (ret != CRYPT_SUCCESS) {
        printf("decaps init failed.\n");
        goto EXIT;
    }
    ret = CRYPT_EAL_PkeyDecaps(ctx, cipher, cipherLen, sharekey2, &sharekeyLen);
    if (ret != CRYPT_SUCCESS) {
        printf("decaps failed.\n");
        goto EXIT;
    }
    if (sharekeyLen != sharekey2Len || memcmp(sharekey, sharekey2, sharekeyLen) != 0) {
        printf("\nerror：encaps or decaps failed！sharekey not match.\n");
        ret = -1;
    } else {
        printf("\nencaps and decaps success！sharekey match\n");
    }
    
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(deCtx);
    return ret;
}

static int32_t PQCP_TestLoadProvider(void)
{
    char basePath[PATH_MAX] = {0};
    char fullPath[PATH_MAX] = {0};
    
    // 获取当前可执行文件路径作为根路径
    if (readlink("/proc/self/exe", basePath, sizeof(basePath)-1) == -1) {
        perror("get realpath failed.\n");
        return PQCP_TEST_FAILURE;
    }
    printf("basePath：%s\n", basePath);
    // 提取目录路径并拼接相对路径
    dirname(basePath);  // 获取可执行文件所在目录
    snprintf(fullPath, sizeof(fullPath), "%s/../../../build", basePath);
    printf("fullPath： %s\n", fullPath);
    
    int32_t ret = CRYPT_EAL_ProviderSetLoadPath(NULL, fullPath);
    if (ret != 0) {
        printf("set provider path failed.\n");
        return PQCP_TEST_FAILURE;
    }
    
    ret = CRYPT_EAL_ProviderLoad(NULL, BSL_SAL_LIB_FMT_LIBSO, "pqcp_provider", NULL, NULL);
    if (ret != 0) {
        printf("load provider failed.\n");
        return PQCP_TEST_FAILURE;
    }
    
    return PQCP_TEST_SUCCESS;
}

/**
 * 主函数
 */
int32_t main(void)
{
    printf("PQCP库Scloud+使用示例\n");
    printf("====================================\n");

    int32_t result = 0;
    if (PQCP_TestLoadProvider() != CRYPT_SUCCESS) {
        printf("\nload provider failed！\n");
    }
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
    /* 运行scloud+演示 */
    if (ScloudplusDemo() != 0) {
        result = -1;
    }

    if (result == 0) {
        printf("\nScloud+演示成功完成！\n");
    } else {
        printf("\nScloud+演示过程中出现错误！\n");
    }
    CRYPT_EAL_RandDeinit();
    (void)CRYPT_EAL_ProviderUnload(NULL, BSL_SAL_LIB_FMT_LIBSO, "pqcp_provider");
    return result;
}