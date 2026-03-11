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

#include "pqcp_provider.h"
#include "pqcp_provider_impl.h"
#include "crypt_eal_implprovider.h"
#include "crypt_types.h"
#include "pqcp_err.h"
#include "bsl_sal.h"

/* Provider name */
#define PQCP_PROVIDER_NAME "provider=pqcp"
/* Provider context structure */
typedef struct {
    void *handle;
} PQCP_ProvCtx;


static CRYPT_EAL_AlgInfo g_pqcpKeyMgmt[] = {
#ifdef PQCP_SCLOUDPLUS
    {PQCP_PKEY_SCLOUDPLUS, g_pqcpKeyMgmtScloudPlus, PQCP_PROVIDER_NAME},
#endif
#ifdef PQCP_POLARLAC
    {PQCP_PKEY_POLAR_LAC, g_pqcpKeyMgmtPolarLac, PQCP_PROVIDER_NAME},
#endif
#ifdef PQCP_COMPOSITE_SIGN
    {PQCP_PKEY_COMPOSITE_SIGN, g_pqcpKeyMgmtCompositeSign, PQCP_PROVIDER_NAME},
#endif
    CRYPT_EAL_ALGINFO_END
};

static CRYPT_EAL_AlgInfo g_pqcpKeyKem[] = {
#ifdef PQCP_SCLOUDPLUS
    {PQCP_PKEY_SCLOUDPLUS, g_pqcpKemScloudPlus, PQCP_PROVIDER_NAME},
#endif
#ifdef PQCP_POLARLAC
    {PQCP_PKEY_POLAR_LAC, g_pqcpKemPolarLac, PQCP_PROVIDER_NAME},
#endif
    CRYPT_EAL_ALGINFO_END
};

static CRYPT_EAL_AlgInfo g_pqcpKeySign[] = {
#ifdef PQCP_COMPOSITE_SIGN
    {PQCP_PKEY_COMPOSITE_SIGN, g_pqcpCompositeSign, PQCP_PROVIDER_NAME},
#endif
    CRYPT_EAL_ALGINFO_END
};

/* Provider function implementations */
static int32_t PQCP_ProviderQuery(void *provCtx, int32_t operaId, CRYPT_EAL_AlgInfo **algInfos)
{
    if (provCtx == NULL || algInfos == NULL) {
        return PQCP_NULL_INPUT;
    }
    switch (operaId) {
        case CRYPT_EAL_OPERAID_KEYMGMT:
            *algInfos = g_pqcpKeyMgmt;
            break;
        case CRYPT_EAL_OPERAID_KEM:
            *algInfos = g_pqcpKeyKem;
            break;
        case CRYPT_EAL_OPERAID_SIGN:
            *algInfos = g_pqcpKeySign;
            break;
        default:
            return PQCP_NOT_SUPPORT;
    }
    return PQCP_SUCCESS;
}

static void PQCP_ProvideFree(void *provCtx)
{
    PQCP_ProvCtx *ctx = (PQCP_ProvCtx *)provCtx;
    if (ctx != NULL) {
        BSL_SAL_Free(ctx);
    }
}

static int32_t PQCP_ProviderCtrl(void *provCtx, int32_t cmd, void *val, uint32_t valLen)
{
    (void) provCtx;
    (void) cmd;
    (void) val;
    (void) valLen;
    /* Add provider control operations if needed */
    return PQCP_SUCCESS;
}

/* Provider output functions */
static CRYPT_EAL_Func g_pqcpProviderFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, PQCP_ProviderQuery},
    {CRYPT_EAL_PROVCB_FREE, PQCP_ProvideFree},
    {CRYPT_EAL_PROVCB_CTRL, PQCP_ProviderCtrl},
    CRYPT_EAL_FUNC_END
};

/* Provider initialization */
int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx,
                              BSL_Param *param,
                              CRYPT_EAL_Func *capFuncs,
                              CRYPT_EAL_Func **outFuncs,
                              void **provCtx)
{
    PQCP_ProvCtx *ctx = NULL;
    (void)param;
    (void)capFuncs;
    /* Create provider context */
    ctx = (PQCP_ProvCtx *)BSL_SAL_Malloc(sizeof(PQCP_ProvCtx));
    if (ctx == NULL) {
        return PQCP_MEM_ALLOC_FAIL;
    }

    ctx->handle = mgrCtx;
    *outFuncs = g_pqcpProviderFuncs;
    *provCtx = ctx;
    return PQCP_SUCCESS;
}