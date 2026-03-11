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
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>

#include "hitls_build.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_eal_md.h"
#include "eal_md_local.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_init.h"
#include "crypt_params_key.h"
#include "crypt_eal_provider.h"

#include "test.h"
#include "helper.h"
#include "crypto_test_util.h"

#include "securec.h"
#include "crypt_util_rand.h"
#include "bsl_err_internal.h"

char PROVIDER_PATH[] = "../../build";

#ifndef HITLS_BSL_SAL_MEM
void *TestMalloc(uint32_t len)
{
    return malloc((size_t)len);
}
#endif

int32_t TestPqcpProviderLoad(void)
{
    int32_t ret = CRYPT_EAL_ProviderSetLoadPath(NULL, PROVIDER_PATH);
    if (ret != 0) {
        printf("set provider path failed.\n");
        return 1;
    }
    
    ret = CRYPT_EAL_ProviderLoad(NULL, BSL_SAL_LIB_FMT_LIBSO, "pqcp_provider", NULL, NULL);
    if (ret != 0) {
        printf("load provider failed: %d.\n", ret);
        return 1;
    }
    
    return 0;
}
int32_t TestPqcpProviderUnload(void)
{
    int32_t ret = CRYPT_EAL_ProviderUnload(NULL, BSL_SAL_LIB_FMT_LIBSO, "pqcp_provider");
    if (ret != 0) {
        printf("unload provider failed: %d.\n", ret);
        return 1;
    }
    return 0;
}

void TestMemInit(void)
{
#ifdef HITLS_BSL_SAL_MEM
    return;
#else
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, TestMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);
#endif
}

typedef struct {
    CRYPT_Data *entropy;
    CRYPT_Data *nonce;
    CRYPT_Data *pers;

    CRYPT_Data *addin1;
    CRYPT_Data *entropyPR1;

    CRYPT_Data *addin2;
    CRYPT_Data *entropyPR2;

    CRYPT_Data *retBits;
} DRBG_Vec_t;

#ifndef HITLS_CRYPTO_ENTROPY
static int32_t GetEntropy(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    if (lenRange == NULL) {
        Print("getEntropy Error lenRange NULL\n");
        return CRYPT_NULL_INPUT;
    }
    if (ctx == NULL || entropy == NULL) {
        Print("getEntropy Error\n");
        lenRange->max = strength;
        return CRYPT_NULL_INPUT;
    }

    DRBG_Vec_t *seedCtx = (DRBG_Vec_t *)ctx;

    entropy->data = seedCtx->entropy->data;
    entropy->len = seedCtx->entropy->len;

    return CRYPT_SUCCESS;
}

static void CleanEntropy(void *ctx, CRYPT_Data *entropy)
{
    (void)ctx;
    (void)entropy;
    return;
}
#endif

int32_t TestSimpleRand(uint8_t *buff, uint32_t len)
{
    int rand = open("/dev/urandom", O_RDONLY);
    if (rand < 0) {
        printf("open /dev/urandom failed.\n");
        return -1;
    }
    int l = read(rand, buff, len);
    if (l < 0) {
        printf("read from /dev/urandom failed. errno: %d.\n", errno);
        close(rand);
        return -1;
    }
    close(rand);
    return 0;
}

int32_t TestSimpleRandEx(void *libCtx, uint8_t *buff, uint32_t len)
{
    (void)libCtx;
    return TestSimpleRand(buff, len);
}

int32_t TestSimpleRandExSelfCheck(void *libCtx, uint8_t *buff, uint32_t len)
{
    if (libCtx == NULL) {
        return CRYPT_PROVIDER_INVALID_LIB_CTX;
    }
    return TestSimpleRand(buff, len);
}

int TestRandInitEx(void *libCtx)
{
    (void)libCtx;
    int drbgAlgId = GetAvailableRandAlgId();
    int32_t ret;
    if (drbgAlgId == -1) {
        Print("Drbg algs are disabled.");
        return CRYPT_NOT_SUPPORT;
    }

#ifndef HITLS_CRYPTO_ENTROPY
    CRYPT_RandSeedMethod seedMeth = {GetEntropy, CleanEntropy, NULL, NULL};
    uint8_t entropy[64] = {0};
    CRYPT_Data tempEntropy = {entropy, sizeof(entropy)};
    DRBG_Vec_t seedCtx = {0};
    seedCtx.entropy = &tempEntropy;
#endif

    BSL_ERR_SET_MARK();

#ifdef HITLS_CRYPTO_PROVIDER
#ifndef HITLS_CRYPTO_ENTROPY
    BSL_Param param[4] = {0};
    (void)BSL_PARAM_InitValue(&param[0], CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, &seedCtx, 0);
    (void)BSL_PARAM_InitValue(&param[1], CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR,
        seedMeth.getEntropy, 0);
    (void)BSL_PARAM_InitValue(&param[2], CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR,
        seedMeth.cleanEntropy, 0);
    ret = CRYPT_EAL_ProviderRandInitCtx(libCtx, (CRYPT_RAND_AlgId)drbgAlgId, "provider=default", NULL, 0, param);
#else
    ret = CRYPT_EAL_ProviderRandInitCtx(libCtx, (CRYPT_RAND_AlgId)drbgAlgId, "provider=default", NULL, 0, NULL);
#endif
#else
#ifndef HITLS_CRYPTO_ENTROPY
    ret = CRYPT_EAL_RandInit(drbgAlgId, &seedMeth, (void *)&seedCtx, NULL, 0);
#else
    ret = CRYPT_EAL_RandInit(drbgAlgId, NULL, NULL, NULL, 0);
#endif
#endif
    if (ret == CRYPT_EAL_ERR_DRBG_REPEAT_INIT) {
        BSL_ERR_POP_TO_MARK();
        ret = CRYPT_SUCCESS;
    }
    return ret;
}

int TestRandInit(void)
{
    int32_t ret = TestRandInitEx(NULL);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_EAL_SetRandCallBack(TestSimpleRand);
    CRYPT_RandRegistEx(TestSimpleRandEx);
    return CRYPT_SUCCESS;
}

int TestRandInitSelfCheck(void)
{
    int32_t ret = TestRandInitEx(NULL);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_RandRegistEx(TestSimpleRandExSelfCheck);
    return CRYPT_SUCCESS;
}

void TestRandDeInit(void)
{
    CRYPT_RandRegistEx(NULL);
    CRYPT_EAL_RandDeinitEx(NULL);
}
