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
#include "pqcp_err.h"
#include "crypt_eal_rand.h"

#define PQCP_TEST_SUCCESS 0
#define PQCP_TEST_FAILURE 1

static int32_t CompositeSignDemo(void)
{
    printf("\n=== Composite Sign ===\n\n");
    int32_t ret = -1;
    CRYPT_EAL_PkeyCtx *signCtx = NULL;
    CRYPT_EAL_PkeyCtx *verifyCtx = NULL;
    int32_t val = PQCP_COMPOSITE_MLDSA44_SM2;
    uint8_t msg[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t pubdata[4096];
    uint8_t signData[4096];
    BSL_Param pub[2] = {
        {PQCP_PARAM_COMPOSITE_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubdata, sizeof(pubdata), 0},
        BSL_PARAM_END
    };

    signCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE,
        "provider=pqcp");
    if (signCtx == NULL) {
        printf("create signCtx failed.\n");
        goto EXIT;
    }
    verifyCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE,
        "provider=pqcp");
    if (verifyCtx == NULL) {
        printf("create verifyCtx failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyCtrl(signCtx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    if (ret != PQCP_SUCCESS) {
        printf("ctrl param failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyCtrl(verifyCtx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    if (ret != PQCP_SUCCESS) {
        printf("ctrl param failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyGen(signCtx);
    if (ret != PQCP_SUCCESS) {
        printf("gen key failed.\n");
        goto EXIT;
    }
    ret = CRYPT_EAL_PkeyGetPubEx(signCtx, pub);
    if (ret != PQCP_SUCCESS) {
        printf("get pubkey failed.\n");
        goto EXIT;
    }
    pub->valueLen = pub->useLen;
    ret = CRYPT_EAL_PkeySetPubEx(verifyCtx, pub);
    if (ret != PQCP_SUCCESS) {
        printf("set pubkey failed : %d.\n", ret);
        goto EXIT;
    }
    uint32_t signBufLen = sizeof(signData);
    ret = CRYPT_EAL_PkeySign(signCtx, 0, msg, sizeof(msg), signData, &signBufLen);
    if (ret != PQCP_SUCCESS) {
        printf("sign failed.\n");
        goto EXIT;
    }
    ret = CRYPT_EAL_PkeyVerify(verifyCtx, 0, msg, sizeof(msg), signData, signBufLen);
    if (ret != PQCP_SUCCESS) {
        printf("verify failed.\n");
        goto EXIT;
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(signCtx);
    CRYPT_EAL_PkeyFreeCtx(verifyCtx);
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
        printf("load provider failed: %d.\n", ret);
        return PQCP_TEST_FAILURE;
    }
    
    return PQCP_TEST_SUCCESS;
}
/**
 * 主函数
 */
int32_t main(void)
{
    printf("PQCP库CompositeSign使用示例\n");
    printf("====================================\n");

    int32_t result = 0;
    if (PQCP_TestLoadProvider() != PQCP_SUCCESS) {
        printf("\nload provider failed！\n");
    } else {
        printf("\nLoad provider successfully.\n");
    }
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    /* 运行FrodoKEM演示 */
    if (CompositeSignDemo() != 0) {
        result = -1;
    }

    if (result == 0) {
        printf("\nCompositeSign演示成功完成！\n");
    } else {
        printf("\nCompositeSign演示过程中出现错误！\n");
    }
    CRYPT_EAL_RandDeinit();
    (void)CRYPT_EAL_ProviderUnload(NULL, BSL_SAL_LIB_FMT_LIBSO, "pqcp_provider");
    return result;
}