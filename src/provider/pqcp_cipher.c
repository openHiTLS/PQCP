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

const CRYPT_EAL_Func g_pqcpCipherHiae[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)PQCP_HIAE_CipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)PQCP_HIAE_CipherInitCtx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)PQCP_HIAE_CipherUpdate},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)PQCP_HIAE_CipherFinal},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)PQCP_HIAE_CipherDeinitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)PQCP_HIAE_CipherCtrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)PQCP_HIAE_CipherFreeCtx},
    {CRYPT_EAL_IMPLCIPHER_DUPCTX, (CRYPT_EAL_ImplCipherDupCtx)PQCP_HIAE_CipherDupCtx},
    CRYPT_EAL_FUNC_END,
};

#endif /* PQCP_HIAE */
