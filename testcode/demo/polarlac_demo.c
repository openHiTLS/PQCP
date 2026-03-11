#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <time.h>
#include <linux/limits.h>
#include <unistd.h>
#include "pqcp_types.h"
#include "pqcp_provider.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_init.h"
#include "pqcp_err.h"

#define PQCP_TEST_SUCCESS 0
#define PQCP_TEST_FAILURE 1

static int32_t PolarLacDemo(void)
{
    int32_t val = PQCP_POLAR_LAC_LIGHT;
    int32_t ret = -1;
    uint32_t cipherLen = 0;;
    uint8_t *cipher = NULL;
    uint32_t sharekeyLen = 32;
    uint8_t sharekey[32] = {0};
    uint32_t sharekey2Len = 32;
    uint8_t sharekey2[32] = {0};
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;
    uint32_t pkLen = 0;
    uint32_t skLen = 0;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *deCtx = NULL;
    CRYPT_EAL_PkeyCtx *copyCtx = NULL;
    // rand init
    if (CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL) != PQCP_SUCCESS)
    {
        printf("rand init failed.\n");
        return -1;
    }

    // new ctx
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_POLAR_LAC, CRYPT_EAL_PKEY_KEM_OPERATE,
                                                          "provider=pqcp");
    if (ctx == NULL)
    {
        printf("create ctx failed.\n");
        goto EXIT;
    }
    deCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_POLAR_LAC, CRYPT_EAL_PKEY_KEM_OPERATE,
                                                            "provider=pqcp");
    if (deCtx == NULL)
    {
        printf("create deCtx failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    if (ret != PQCP_SUCCESS)
    {
        printf("ctrl set parr by id failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));

    if (ret != PQCP_SUCCESS)
    {
        printf("ctrl get cipher len failed.\n");
        goto EXIT;
    }
    
    cipher = (uint8_t *)malloc(cipherLen);
    
    if (cipher == NULL) {
        printf("Malloc cipher failed \n");
        goto EXIT;
    }
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &pkLen, sizeof(pkLen));
    if (ret != PQCP_SUCCESS)
    {
        printf("ctrl get pk len failed.\n");
        goto EXIT;
    }
    pk = (uint8_t *)malloc(pkLen);
    if (pk == NULL) {
        printf("Malloc pk failed \n");
        goto EXIT;
    }
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &skLen, sizeof(skLen));
    if (ret != PQCP_SUCCESS)
    {
        printf("ctrl get sk len failed.\n");
        goto EXIT;
    }
    sk = (uint8_t *)malloc(skLen);
    if (sk == NULL) {
        printf("Malloc sk failed \n");
        goto EXIT;
    }

    BSL_Param pub[2] = {
        {PQCP_PARAM_POLAR_LAC_PUBKEY, BSL_PARAM_TYPE_OCTETS, pk, pkLen, 0},
        BSL_PARAM_END};
    BSL_Param prv[2] = {
        {PQCP_PARAM_POLAR_LAC_PRVKEY, BSL_PARAM_TYPE_OCTETS, sk, skLen, 0},
        BSL_PARAM_END};

    ret = CRYPT_EAL_PkeySetParaById(deCtx, val);
    if (ret != PQCP_SUCCESS)
    {
        printf("ctrl param failed.\n");
        goto EXIT;
    }

    // keygen
    ret = CRYPT_EAL_PkeyGen(ctx);
    if (ret != PQCP_SUCCESS)
    {
        printf("gen key failed.\n");
        goto EXIT;
    }

    //get & set pk
    ret = CRYPT_EAL_PkeyGetPubEx(ctx, pub);
    if (ret != PQCP_SUCCESS)
    {
        printf("get pk failed\n");
        goto EXIT;
    }

    // get & set sk
    ret = CRYPT_EAL_PkeyGetPrvEx(ctx, prv);
    if (ret != PQCP_SUCCESS)
    {
        printf("get sk failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeySetPrvEx(deCtx, prv);
    if (ret != PQCP_SUCCESS)
    {
        printf("set sk failed.\n");
        goto EXIT;
    }

    // encaps
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    if (ret != PQCP_SUCCESS)
    {
        printf("encaps init failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyEncaps(ctx, cipher, &cipherLen, sharekey, &sharekeyLen);
    if (ret != PQCP_SUCCESS)
    {
        printf("encaps failed.\n");
        goto EXIT;
    }

    // decaps
    ret = CRYPT_EAL_PkeyDecapsInit(ctx, NULL);
    if (ret != PQCP_SUCCESS)
    {
        printf("decaps init failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyDecaps(deCtx, cipher, cipherLen, sharekey2, &sharekeyLen);
    if (ret != PQCP_SUCCESS)
    {
        printf("decaps failed.\n");
        goto EXIT;
    }

    if (sharekeyLen == sharekey2Len && memcmp(sharekey, sharekey2, sharekeyLen) == 0)
    {
        printf("\nPolar lac encaps and decaps finished; sharedkey matching succeeded.\n");
    }
    else
    {
        printf("\nError: encaps or decaps failed; sharekey mismatch.\n");
        ret = -1;
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(copyCtx);
    CRYPT_EAL_PkeyFreeCtx(deCtx);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return ret;
}

static int32_t PQCP_TestLoadProvider(void)
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

int32_t main(void)
{
    printf("PQCP_PolarLac\n");
    printf("====================================\n");

    int32_t result = 0;
    if (PQCP_TestLoadProvider() != PQCP_SUCCESS)
    {
        printf("\nLoad provider failed!\n");
    }
    else
    {
        printf("\nLoad provider successfully.\n");
    }

    if (PolarLacDemo() != 0)
    {
        result = -1;
    }

    if (result == 0)
    {
        printf("\nPolarLac success\n");
    }
    else
    {
        printf("\nPolarLac error\n");
    }

    (void)CRYPT_EAL_ProviderUnload(NULL, BSL_SAL_LIB_FMT_LIBSO, "pqcp_provider");
    return result;
}