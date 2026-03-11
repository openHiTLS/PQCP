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

#ifndef CRYPT_COMPOSITE_SIGN_H
#define CRYPT_COMPOSITE_SIGN_H

#include <stdint.h>
#include "crypt_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct CompositeCtx CRYPT_CompositeCtx;
typedef CRYPT_Data CRYPT_CompositePub;
typedef CRYPT_Data CRYPT_CompositePrv;

CRYPT_CompositeCtx *CRYPT_COMPOSITE_NewCtx(void);

void CRYPT_COMPOSITE_FreeCtx(CRYPT_CompositeCtx *ctx);

CRYPT_CompositeCtx *CRYPT_COMPOSITE_DupCtx(CRYPT_CompositeCtx *ctx);

int32_t CRYPT_COMPOSITE_Ctrl(CRYPT_CompositeCtx *ctx, int32_t opt, void *val, uint32_t len);

int32_t CRYPT_COMPOSITE_GenKey(CRYPT_CompositeCtx *ctx);

int32_t CRYPT_COMPOSITE_SetPubKey(CRYPT_CompositeCtx *ctx, const CRYPT_CompositePub *pub);
int32_t CRYPT_COMPOSITE_SetPrvKey(CRYPT_CompositeCtx *ctx, const CRYPT_CompositePrv *prv);
int32_t CRYPT_COMPOSITE_GetPubKey(const CRYPT_CompositeCtx *ctx, CRYPT_CompositePub *pub);
int32_t CRYPT_COMPOSITE_GetPrvKey(const CRYPT_CompositeCtx *ctx, CRYPT_CompositePrv *prv);

int32_t CRYPT_COMPOSITE_SetPubKeyEx(CRYPT_CompositeCtx *ctx, const BSL_Param *para);
int32_t CRYPT_COMPOSITE_SetPrvKeyEx(CRYPT_CompositeCtx *ctx, const BSL_Param *para);
int32_t CRYPT_COMPOSITE_GetPubKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para);
int32_t CRYPT_COMPOSITE_GetPrvKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para);

int32_t CRYPT_COMPOSITE_Sign(CRYPT_CompositeCtx *ctx, int32_t hashId, const uint8_t *data,
    uint32_t dataLen, uint8_t *sign, uint32_t *signLen);

int32_t CRYPT_COMPOSITE_Verify(CRYPT_CompositeCtx *ctx, int32_t hashId, const uint8_t *data,
    uint32_t dataLen, uint8_t *sign, uint32_t signLen);

#ifdef __cplusplus
}
#endif

#endif// CRYPT_COMPOSITE_SIGN_H
