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

#ifndef CRYPT_HIAE_H
#define CRYPT_HIAE_H

#include <stdint.h>
#include <stdbool.h>
#include "bsl_params.h"

/**
 * @defgroup crypt_hiae HiAE provider interfaces
 * @brief HiAE AEAD and HiAE-MAC provider entry points.
 *
 * HiAE profile used in PQCP:
 * - key length: 32 bytes
 * - nonce/iv length: 16 bytes
 * - tag length: fixed 16 bytes
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct PQCP_HiaeCipherCtx PQCP_HIAE_CipherCtx;
typedef struct PQCP_HiaeMacCtx PQCP_HIAE_MacCtx;

/**
 * @ingroup crypt_hiae
 * @brief Create HiAE AEAD context.
 *
 * @param provCtx [IN] Provider context.
 * @param algId [IN] Algorithm identifier, must match HiAE AEAD.
 * @retval Success: context pointer.
 * @retval Failure: NULL.
 */
PQCP_HIAE_CipherCtx *PQCP_HIAE_CipherNewCtx(void *provCtx, int32_t algId);

/**
 * @ingroup crypt_hiae
 * @brief Initialize HiAE AEAD context for encryption or decryption.
 *
 * @attention For a fixed key, nonce reuse is forbidden.
 * @param ctx [IN/OUT] HiAE AEAD context.
 * @param key [IN] Key buffer.
 * @param keyLen [IN] Key length in bytes, must be 32.
 * @param iv [IN] Nonce/IV buffer.
 * @param ivLen [IN] Nonce length in bytes, must be 16.
 * @param param [IN] Reserved provider parameters.
 * @param enc [IN] true for encrypt, false for decrypt.
 * @retval #PQCP_SUCCESS, success.
 * @retval Other error codes, see crypt_errno.h and pqcp_err.h.
 */
int32_t PQCP_HIAE_CipherInitCtx(PQCP_HIAE_CipherCtx *ctx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, BSL_Param *param, bool enc);

/**
 * @ingroup crypt_hiae
 * @brief Process HiAE payload bytes.
 *
 * @param ctx [IN/OUT] HiAE AEAD context.
 * @param in [IN] Input payload.
 * @param inLen [IN] Input length in bytes.
 * @param out [OUT] Output payload.
 * @param outLen [IN/OUT] Input as output buffer capacity; output as produced bytes.
 * @retval #PQCP_SUCCESS, success.
 * @retval Other error codes, see crypt_errno.h and pqcp_err.h.
 */
int32_t PQCP_HIAE_CipherUpdate(PQCP_HIAE_CipherCtx *ctx, const uint8_t *in, uint32_t inLen, uint8_t *out,
    uint32_t *outLen);

/**
 * @ingroup crypt_hiae
 * @brief Finalize AEAD stream stage.
 *
 * @note HiAE tag is obtained via #PQCP_HIAE_CipherCtrl with CRYPT_CTRL_GET_TAG.
 *       Current provider behavior: payload bytes are fully produced by
 *       #PQCP_HIAE_CipherUpdate, and this function only finalizes internal
 *       state (output length is 0).
 * @param ctx [IN/OUT] HiAE AEAD context.
 * @param out [OUT] Reserved output buffer, not used for payload output.
 * @param outLen [IN/OUT] Output as produced bytes, fixed to 0 on success.
 * @retval #PQCP_SUCCESS, success.
 * @retval Other error codes, see crypt_errno.h and pqcp_err.h.
 */
int32_t PQCP_HIAE_CipherFinal(PQCP_HIAE_CipherCtx *ctx, uint8_t *out, uint32_t *outLen);

/**
 * @ingroup crypt_hiae
 * @brief Deinitialize and cleanse HiAE AEAD context.
 *
 * @param ctx [IN/OUT] HiAE AEAD context.
 * @retval #PQCP_SUCCESS, success.
 * @retval Other error codes, see crypt_errno.h and pqcp_err.h.
 */
int32_t PQCP_HIAE_CipherDeinitCtx(PQCP_HIAE_CipherCtx *ctx);

/**
 * @ingroup crypt_hiae
 * @brief Control HiAE AEAD context parameters.
 *
 * Supported control types:
 * - CRYPT_CTRL_SET_IV / CRYPT_CTRL_REINIT_STATUS
 * - CRYPT_CTRL_SET_AAD
 * - CRYPT_CTRL_GET_TAG
 * - CRYPT_CTRL_GET_BLOCKSIZE
 *
 * @note CRYPT_CTRL_SET_AAD may be called multiple times before the first
 *       payload update. Arbitrary byte-length chunks are accepted and are
 *       processed as one continuous AD stream. Once
 *       #PQCP_HIAE_CipherUpdate starts processing payload bytes, further
 *       CRYPT_CTRL_SET_AAD calls are rejected. NOTE that CRYPT_EAL_CipherCtrl
 *       currently does not support calling CRYPT_CTRL_SET_AAD MULTIPLE TIMES.
 * @attention HiAE uses a fixed 16-byte tag, SET_TAGLEN is not supported.
 * @param ctx [IN/OUT] HiAE AEAD context.
 * @param cmd [IN] Control command.
 * @param val [IN/OUT] Command input/output data.
 * @param valLen [IN] Data length in bytes.
 * @retval #PQCP_SUCCESS, success.
 * @retval Other error codes, see crypt_errno.h and pqcp_err.h.
 */
int32_t PQCP_HIAE_CipherCtrl(PQCP_HIAE_CipherCtx *ctx, int32_t cmd, void *val, uint32_t valLen);

/**
 * @ingroup crypt_hiae
 * @brief Free HiAE AEAD context.
 *
 * @param ctx [IN/OUT] HiAE AEAD context.
 */
void PQCP_HIAE_CipherFreeCtx(PQCP_HIAE_CipherCtx *ctx);

/**
 * @ingroup crypt_hiae
 * @brief Duplicate HiAE AEAD context.
 *
 * @param ctx [IN] Source HiAE AEAD context.
 * @retval Success: duplicated context pointer.
 * @retval Failure: NULL.
 */
PQCP_HIAE_CipherCtx *PQCP_HIAE_CipherDupCtx(const PQCP_HIAE_CipherCtx *ctx);

/**
 * @ingroup crypt_hiae
 * @brief Create HiAE-MAC context.
 *
 * @param provCtx [IN] Provider context.
 * @param algId [IN] Algorithm identifier, must match HiAE MAC.
 * @retval Success: context pointer.
 * @retval Failure: NULL.
 */
PQCP_HIAE_MacCtx *PQCP_HIAE_MacNewCtx(void *provCtx, int32_t algId);

/**
 * @ingroup crypt_hiae
 * @brief Initialize HiAE-MAC context with key material.
 *
 * @param ctx [IN/OUT] HiAE-MAC context.
 * @param key [IN] Input key material, key only.
 * @param len [IN] Input length in bytes, must be 32.
 * @param param [IN] Reserved provider parameters.
 * @retval #PQCP_SUCCESS, success.
 * @retval Other error codes, see crypt_errno.h and pqcp_err.h.
 */
int32_t PQCP_HIAE_MacInit(PQCP_HIAE_MacCtx *ctx, const uint8_t *key, uint32_t len, BSL_Param *param);

/**
 * @ingroup crypt_hiae
 * @brief Update HiAE-MAC with message bytes.
 *
 * @attention #PQCP_HIAE_MacCtrl with CRYPT_CTRL_SET_IV must be called after
 *            init and before this API.
 *
 * @param ctx [IN/OUT] HiAE-MAC context.
 * @param input [IN] MAC input data.
 * @param len [IN] Input length in bytes.
 * @retval #PQCP_SUCCESS, success.
 * @retval Other error codes, see crypt_errno.h and pqcp_err.h.
 */
int32_t PQCP_HIAE_MacUpdate(PQCP_HIAE_MacCtx *ctx, const uint8_t *input, uint32_t len);

/**
 * @ingroup crypt_hiae
 * @brief Finalize HiAE-MAC and output 16-byte tag.
 *
 * @attention #PQCP_HIAE_MacCtrl with CRYPT_CTRL_SET_IV must be called after
 *            init and before this API.
 *
 * @param ctx [IN/OUT] HiAE-MAC context.
 * @param out [OUT] Tag output buffer.
 * @param outLen [IN/OUT] Input as output capacity; output as tag length.
 * @retval #PQCP_SUCCESS, success.
 * @retval Other error codes, see crypt_errno.h and pqcp_err.h.
 */
int32_t PQCP_HIAE_MacFinal(PQCP_HIAE_MacCtx *ctx, uint8_t *out, uint32_t *outLen);

/**
 * @ingroup crypt_hiae
 * @brief Deinitialize and cleanse HiAE-MAC context.
 *
 * @param ctx [IN/OUT] HiAE-MAC context.
 * @retval #PQCP_SUCCESS, success.
 * @retval Other error codes, see crypt_errno.h and pqcp_err.h.
 */
int32_t PQCP_HIAE_MacDeInitCtx(PQCP_HIAE_MacCtx *ctx);

/**
 * @ingroup crypt_hiae
 * @brief Reinitialize HiAE-MAC state with existing key/IV.
 *
 * @param ctx [IN/OUT] HiAE-MAC context.
 * @retval #PQCP_SUCCESS, success.
 * @retval Other error codes, see crypt_errno.h and pqcp_err.h.
 */
int32_t PQCP_HIAE_MacReInitCtx(PQCP_HIAE_MacCtx *ctx);

/**
 * @ingroup crypt_hiae
 * @brief Control HiAE-MAC parameters.
 *
 * Supported control types:
 * - CRYPT_CTRL_SET_IV
 * - CRYPT_CTRL_GET_MACLEN
 *
 * @note HiAE-MAC requires CRYPT_CTRL_SET_IV after #PQCP_HIAE_MacInit and
 *       before update/final operations.
 * @param ctx [IN/OUT] HiAE-MAC context.
 * @param cmd [IN] Control command.
 * @param val [IN/OUT] Command input/output data.
 * @param valLen [IN] Data length in bytes.
 * @retval #PQCP_SUCCESS, success.
 * @retval Other error codes, see crypt_errno.h and pqcp_err.h.
 */
int32_t PQCP_HIAE_MacCtrl(PQCP_HIAE_MacCtx *ctx, int32_t cmd, void *val, uint32_t valLen);

/**
 * @ingroup crypt_hiae
 * @brief Free HiAE-MAC context.
 *
 * @param ctx [IN/OUT] HiAE-MAC context.
 */
void PQCP_HIAE_MacFreeCtx(PQCP_HIAE_MacCtx *ctx);

/**
 * @ingroup crypt_hiae
 * @brief Duplicate HiAE-MAC context.
 *
 * @param ctx [IN] Source HiAE-MAC context.
 * @retval Success: duplicated context pointer.
 * @retval Failure: NULL.
 */
PQCP_HIAE_MacCtx *PQCP_HIAE_MacDupCtx(const PQCP_HIAE_MacCtx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CRYPT_HIAE_H */
