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
#include "crypt_composite_sign.h"
#include "pqcp_provider.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "pqcp_err.h"

void *CRYPT_PQCP_PkeyMgmtNewCtx(void *provCtx, int32_t algId)
{
    (void)provCtx;
    void *pkeyCtx = NULL;
    switch (algId)
    {
#ifdef PQCP_SCLOUDPLUS
    case PQCP_PKEY_SCLOUDPLUS:
        pkeyCtx = PQCP_SCLOUDPLUS_NewCtx();
        break;
#endif
#ifdef PQCP_POLARLAC
    case PQCP_PKEY_POLAR_LAC:
        pkeyCtx = PQCP_LAC2_NewCtx();
        break;
#endif
#ifdef PQCP_COMPOSITE_SIGN
    case PQCP_PKEY_COMPOSITE_SIGN:
        pkeyCtx = CRYPT_COMPOSITE_NewCtx();
        break;
#endif
    default:
        break;
    }
    return pkeyCtx;
};

#ifdef PQCP_SCLOUDPLUS
const CRYPT_EAL_Func g_pqcpKeyMgmtScloudPlus[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_PQCP_PkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)PQCP_SCLOUDPLUS_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)PQCP_SCLOUDPLUS_SetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)PQCP_SCLOUDPLUS_SetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)PQCP_SCLOUDPLUS_GetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)PQCP_SCLOUDPLUS_GetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)PQCP_SCLOUDPLUS_DupCtx},
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
#endif

#ifdef PQCP_POLARLAC
const CRYPT_EAL_Func g_pqcpKeyMgmtPolarLac[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_PQCP_PkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)PQCP_LAC2_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)PQCP_LAC2_SetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)PQCP_LAC2_SetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)PQCP_LAC2_GetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)PQCP_LAC2_GetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)PQCP_LAC2_DupCtx},
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
#endif

#ifdef PQCP_COMPOSITE_SIGN
const CRYPT_EAL_Func g_pqcpKeyMgmtCompositeSign[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_PQCP_PkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)CRYPT_COMPOSITE_GenKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)CRYPT_COMPOSITE_SetPrvKeyEx},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)CRYPT_COMPOSITE_SetPubKeyEx},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)CRYPT_COMPOSITE_GetPrvKeyEx},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)CRYPT_COMPOSITE_GetPubKeyEx},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)CRYPT_COMPOSITE_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_COMPOSITE_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)CRYPT_COMPOSITE_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_pqcpCompositeSign[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_COMPOSITE_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_COMPOSITE_Verify},
    CRYPT_EAL_FUNC_END,
};
#endif