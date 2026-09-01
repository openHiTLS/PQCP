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

#ifndef CRYPT_NEV_H
#define CRYPT_NEV_H

#include <stdint.h>
#include "bsl_params.h"

typedef struct CryptNevCtx CRYPT_NEV_Ctx;

void *PQCP_NEV_NewCtx(void);
int32_t PQCP_NEV_Gen(CRYPT_NEV_Ctx *ctx);
int32_t PQCP_NEV_SetPrvKey(CRYPT_NEV_Ctx *ctx, BSL_Param *param);
int32_t PQCP_NEV_SetPubKey(CRYPT_NEV_Ctx *ctx, BSL_Param *param);
int32_t PQCP_NEV_GetPrvKey(CRYPT_NEV_Ctx *ctx, BSL_Param *param);
int32_t PQCP_NEV_GetPubKey(CRYPT_NEV_Ctx *ctx, BSL_Param *param);
CRYPT_NEV_Ctx *PQCP_NEV_DupCtx(CRYPT_NEV_Ctx *srcCtx);
int32_t PQCP_NEV_Ctrl(CRYPT_NEV_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen);
void PQCP_NEV_FreeCtx(CRYPT_NEV_Ctx *ctx);

int32_t PQCP_NEV_EncapsInit(CRYPT_NEV_Ctx *ctx, const BSL_Param *params);
int32_t PQCP_NEV_DecapsInit(CRYPT_NEV_Ctx *ctx, const BSL_Param *params);
int32_t PQCP_NEV_Encaps(CRYPT_NEV_Ctx *ctx, uint8_t *ciphertext, uint32_t *ctLen,
    uint8_t *sharedSecret, uint32_t *ssLen);
int32_t PQCP_NEV_Decaps(CRYPT_NEV_Ctx *ctx, const uint8_t *ciphertext, uint32_t ctLen,
    uint8_t *sharedSecret, uint32_t *ssLen);

#endif
