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

#include "scloudplus.h"
#include "crypt_polarlac.h"
#include "pqcp_provider.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_errno.h"

void *CRYPT_PQCP_PkeyMgmtNewCtx(void *provCtx, int32_t algId)
{
    (void) provCtx;
    void *pkeyCtx = NULL;
    switch (algId) {
        case CRYPT_PKEY_SCLOUDPLUS:
            pkeyCtx = PQCP_SCLOUDPLUS_NewCtx();
            break;
        case CRYPT_PKEY_POLAR_LAC:
            pkeyCtx = PQCP_LAC2_NewCtx();
            break;
        default:
            break;
    }
    if (pkeyCtx == NULL) {
        // BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
        return NULL;
    }
    return pkeyCtx;
};

const CRYPT_EAL_Func g_pqcpKeyMgmtScloudPlus[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_PQCP_PkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)PQCP_SCLOUDPLUS_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)PQCP_SCLOUDPLUS_SetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)PQCP_SCLOUDPLUS_SetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)PQCP_SCLOUDPLUS_GetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)PQCP_SCLOUDPLUS_GetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)PQCP_SCLOUDPLUS_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)PQCP_SCLOUDPLUS_Cmp},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)PQCP_SCLOUDPLUS_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)PQCP_SCLOUDPLUS_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_pqcpKemScloudPlus[] = {
    {CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE_INIT, (CRYPT_EAL_ImplPkeyEncapsInit)PQCP_SCLOUDPLUS_EncapsInit},
    {CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE_INIT, (CRYPT_EAL_ImplPkeyDecapsInit)PQCP_SCLOUDPLUS_DecapsInit},
    {CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE, (CRYPT_EAL_ImplPkeyKemEncapsulate)PQCP_SCLOUDPLUS_Encaps},
    {CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE, (CRYPT_EAL_ImplPkeyKemDecapsulate)PQCP_SCLOUDPLUS_Decaps},
    CRYPT_EAL_FUNC_END,
};



const CRYPT_EAL_Func g_pqcpKeyMgmtPolarLac[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_PQCP_PkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)PQCP_LAC2_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)PQCP_LAC2_SetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)PQCP_LAC2_SetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)PQCP_LAC2_GetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)PQCP_LAC2_GetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)PQCP_LAC2_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)PQCP_LAC2_Cmp},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)PQCP_LAC2_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)PQCP_LAC2_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_pqcpKemPolarLac[] = {
    {CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE_INIT, (CRYPT_EAL_ImplPkeyEncapsInit)PQCP_LAC2_EncapsInit},
    {CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE_INIT, (CRYPT_EAL_ImplPkeyDecapsInit)PQCP_LAC2_DecapsInit},
    {CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE, (CRYPT_EAL_ImplPkeyKemEncapsulate)PQCP_LAC2_Encaps},
    {CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE, (CRYPT_EAL_ImplPkeyKemDecapsulate)PQCP_LAC2_Decaps},
    CRYPT_EAL_FUNC_END,
};