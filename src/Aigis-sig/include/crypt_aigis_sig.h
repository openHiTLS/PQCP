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

#ifndef CRYPT_AIGIS_SIG_H
#define CRYPT_AIGIS_SIG_H

#include <stdint.h>
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CryptAigisSigCtx CRYPT_AIGIS_SIG_Ctx;

/** Create an Aigis-Sig provider context. The caller owns the returned context. */
CRYPT_AIGIS_SIG_Ctx *PQCP_AIGIS_SIG_NewCtx(void *libCtx);

/** Release an Aigis-Sig provider context. A NULL context is accepted. */
void PQCP_AIGIS_SIG_FreeCtx(CRYPT_AIGIS_SIG_Ctx *ctx);

/** Duplicate a configured context, including its key material. */
CRYPT_AIGIS_SIG_Ctx *PQCP_AIGIS_SIG_DupCtx(const CRYPT_AIGIS_SIG_Ctx *ctx);

/** Generate a key pair after selecting an algorithm variant with Ctrl. */
int32_t PQCP_AIGIS_SIG_GenKey(CRYPT_AIGIS_SIG_Ctx *ctx);

/** Import or export private/public key material through BSL_Param. */
int32_t PQCP_AIGIS_SIG_SetPrvKey(CRYPT_AIGIS_SIG_Ctx *ctx, const BSL_Param *param);
int32_t PQCP_AIGIS_SIG_SetPubKey(CRYPT_AIGIS_SIG_Ctx *ctx, const BSL_Param *param);
int32_t PQCP_AIGIS_SIG_GetPrvKey(const CRYPT_AIGIS_SIG_Ctx *ctx, BSL_Param *param);
int32_t PQCP_AIGIS_SIG_GetPubKey(const CRYPT_AIGIS_SIG_Ctx *ctx, BSL_Param *param);

/** Select the algorithm variant or query provider attributes. */
int32_t PQCP_AIGIS_SIG_Ctrl(CRYPT_AIGIS_SIG_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen);

/** Sign data. signLen is the available size on input and the actual size on success. */
int32_t PQCP_AIGIS_SIG_Sign(CRYPT_AIGIS_SIG_Ctx *ctx, int32_t mdId, const uint8_t *data, uint32_t dataLen,
                            uint8_t *sign, uint32_t *signLen);

/** Verify a signature. sign is read-only but follows the openHiTLS provider callback ABI. */
int32_t PQCP_AIGIS_SIG_Verify(const CRYPT_AIGIS_SIG_Ctx *ctx, int32_t mdId, const uint8_t *data, uint32_t dataLen,
                              uint8_t *sign, uint32_t signLen);

#ifdef __cplusplus
}
#endif

#endif
