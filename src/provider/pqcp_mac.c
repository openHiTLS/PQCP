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

#ifdef PQCP_HIAE

#include "pqcp_provider.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_hiae.h"

const CRYPT_EAL_Func g_pqcpMacHiae[] = {
    {CRYPT_EAL_IMPLMAC_NEWCTX, (CRYPT_EAL_ImplMacNewCtx)PQCP_HIAE_MacNewCtx},
    {CRYPT_EAL_IMPLMAC_INIT, (CRYPT_EAL_ImplMacInit)PQCP_HIAE_MacInit},
    {CRYPT_EAL_IMPLMAC_UPDATE, (CRYPT_EAL_ImplMacUpdate)PQCP_HIAE_MacUpdate},
    {CRYPT_EAL_IMPLMAC_FINAL, (CRYPT_EAL_ImplMacFinal)PQCP_HIAE_MacFinal},
    {CRYPT_EAL_IMPLMAC_DEINITCTX, (CRYPT_EAL_ImplMacDeInitCtx)PQCP_HIAE_MacDeInitCtx},
    {CRYPT_EAL_IMPLMAC_REINITCTX, (CRYPT_EAL_ImplMacReInitCtx)PQCP_HIAE_MacReInitCtx},
    {CRYPT_EAL_IMPLMAC_CTRL, (CRYPT_EAL_ImplMacCtrl)PQCP_HIAE_MacCtrl},
    {CRYPT_EAL_IMPLMAC_FREECTX, (CRYPT_EAL_ImplMacFreeCtx)PQCP_HIAE_MacFreeCtx},
    {CRYPT_EAL_IMPLMAC_DUPCTX, (CRYPT_EAL_ImplMacDupCtx)PQCP_HIAE_MacDupCtx},
    CRYPT_EAL_FUNC_END,
};

#endif /* PQCP_HIAE */
