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

#ifndef CRYPT_LAC2_H
#define CRYPT_LAC2_H
#include "bsl_params.h"
typedef struct CryptPolarLacCtx CRYPT_POLAR_LAC_Ctx;

void* PQCP_LAC2_NewCtx(void);
int32_t PQCP_LAC2_Gen(CRYPT_POLAR_LAC_Ctx* ctx);
int32_t PQCP_LAC2_SetPrvKey(CRYPT_POLAR_LAC_Ctx* ctx, BSL_Param* param);
int32_t PQCP_LAC2_SetPubKey(CRYPT_POLAR_LAC_Ctx* ctx, BSL_Param* param);
int32_t PQCP_LAC2_GetPrvKey(CRYPT_POLAR_LAC_Ctx* ctx, BSL_Param* param);
int32_t PQCP_LAC2_GetPubKey(CRYPT_POLAR_LAC_Ctx* ctx, BSL_Param* param);
CRYPT_POLAR_LAC_Ctx* PQCP_LAC2_DupCtx(CRYPT_POLAR_LAC_Ctx* src_ctx);
int32_t PQCP_LAC2_Ctrl(CRYPT_POLAR_LAC_Ctx* ctx, int32_t cmd, void* val, uint32_t valLen);
void PQCP_LAC2_FreeCtx(CRYPT_POLAR_LAC_Ctx* ctx);

int32_t PQCP_LAC2_EncapsInit(CRYPT_POLAR_LAC_Ctx* ctx, const BSL_Param* params);
int32_t PQCP_LAC2_DecapsInit(CRYPT_POLAR_LAC_Ctx* ctx, const BSL_Param* params);
int32_t PQCP_LAC2_Encaps(CRYPT_POLAR_LAC_Ctx* ctx,
                             uint8_t* ciphertext, uint32_t* ctLen,
                             uint8_t* sharedSecret, uint32_t* ssLen);
int32_t PQCP_LAC2_Decaps(CRYPT_POLAR_LAC_Ctx* ctx,
                             const uint8_t* ciphertext, uint32_t ctLen,
                             uint8_t* sharedSecret, uint32_t* ssLen);
#endif