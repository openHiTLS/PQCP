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

#ifdef PQCP_AIGIS_SIG

#include <limits.h>
#include <stdbool.h>
#include <string.h>

#include "crypt_aigis_sig.h"
#include "crypt_eal_pkey.h"
#include "pqcp_err.h"
#include "pqcp_types.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "aigis_sig_local.h"
#include "aigis_sig_sha3_cache.h"

enum { PQCP_AIGIS_SIG_PARAM_I = 1, PQCP_AIGIS_SIG_PARAM_II = 2, PQCP_AIGIS_SIG_PARAM_III = 3 };

typedef struct {
    int32_t paramId;
    int32_t coreParamId;
    int32_t hashId;
    uint32_t pubKeyLen;
    uint32_t prvKeyLen;
    uint32_t signLen;
    uint32_t minSignLen;
} PQCP_AIGIS_SIG_AlgInfo;

struct CryptAigisSigCtx {
    PQCP_AIGIS_SIG_CoreCtx opCtx;
    const PQCP_AIGIS_SIG_AlgInfo *info;
    uint8_t *pubKey;
    uint8_t *prvKey;
};

static int32_t AigisSigRunKeyGenSha3(const CRYPT_AIGIS_SIG_Ctx *ctx, uint8_t *pubKey, uint8_t *prvKey)
{
    PQCP_AIGIS_SIG_Sha3Cache cache = {0};
    PQCP_AIGIS_SIG_CoreCtx opCtx = ctx->opCtx;
    opCtx.sha3Cache = &cache;
    int32_t ret = PQCP_AIGIS_SIG_KeyGenInternal(&opCtx, pubKey, prvKey);
    PQCP_AIGIS_SIG_Sha3CacheFree(&cache);
    return ret;
}

static int32_t AigisSigRunSignSha3(const CRYPT_AIGIS_SIG_Ctx *ctx, const uint8_t *msg, uint32_t msgLen, uint8_t *sig,
                                   uint32_t *sigLen)
{
    PQCP_AIGIS_SIG_Sha3Cache cache = {0};
    PQCP_AIGIS_SIG_CoreCtx opCtx = ctx->opCtx;
    opCtx.sha3Cache = &cache;
    int32_t ret = PQCP_AIGIS_SIG_SignInternal(&opCtx, ctx->prvKey, msg, msgLen, sig, sigLen);
    PQCP_AIGIS_SIG_Sha3CacheFree(&cache);
    return ret;
}

static int32_t AigisSigRunVerifySha3(const CRYPT_AIGIS_SIG_Ctx *ctx, const uint8_t *msg, uint32_t msgLen,
                                     const uint8_t *sig, uint32_t sigLen)
{
    PQCP_AIGIS_SIG_Sha3Cache cache = {0};
    PQCP_AIGIS_SIG_CoreCtx opCtx = ctx->opCtx;
    opCtx.sha3Cache = &cache;
    int32_t ret = PQCP_AIGIS_SIG_VerifyInternal(&opCtx, ctx->pubKey, sig, sigLen, msg, msgLen);
    PQCP_AIGIS_SIG_Sha3CacheFree(&cache);
    return ret;
}

static const PQCP_AIGIS_SIG_AlgInfo g_aigisSigInfo[] = {
    {PQCP_AIGIS_SIG_SM3_I, PQCP_AIGIS_SIG_PARAM_I, PQCP_AIGIS_SIG_HASH_SM3, AIGIS_SIG_PARAM_I_PUBLIC_KEY_BYTES,
     AIGIS_SIG_PARAM_I_PRIVATE_KEY_BYTES, AIGIS_SIG_PARAM_I_SIGNATURE_MAX_BYTES, AIGIS_SIG_PARAM_I_SIGNATURE_MIN_BYTES},
    {PQCP_AIGIS_SIG_SM3_II, PQCP_AIGIS_SIG_PARAM_II, PQCP_AIGIS_SIG_HASH_SM3, AIGIS_SIG_PARAM_II_PUBLIC_KEY_BYTES,
     AIGIS_SIG_PARAM_II_PRIVATE_KEY_BYTES, AIGIS_SIG_PARAM_II_SIGNATURE_MAX_BYTES,
     AIGIS_SIG_PARAM_II_SIGNATURE_MIN_BYTES},
    {PQCP_AIGIS_SIG_SHA3_I, PQCP_AIGIS_SIG_PARAM_I, PQCP_AIGIS_SIG_HASH_SHA3, AIGIS_SIG_PARAM_I_PUBLIC_KEY_BYTES,
     AIGIS_SIG_PARAM_I_PRIVATE_KEY_BYTES, AIGIS_SIG_PARAM_I_SIGNATURE_MAX_BYTES, AIGIS_SIG_PARAM_I_SIGNATURE_MIN_BYTES},
    {PQCP_AIGIS_SIG_SHA3_II, PQCP_AIGIS_SIG_PARAM_II, PQCP_AIGIS_SIG_HASH_SHA3, AIGIS_SIG_PARAM_II_PUBLIC_KEY_BYTES,
     AIGIS_SIG_PARAM_II_PRIVATE_KEY_BYTES, AIGIS_SIG_PARAM_II_SIGNATURE_MAX_BYTES,
     AIGIS_SIG_PARAM_II_SIGNATURE_MIN_BYTES},
    {PQCP_AIGIS_SIG_SM3_III, PQCP_AIGIS_SIG_PARAM_III, PQCP_AIGIS_SIG_HASH_SM3, AIGIS_SIG_PARAM_III_PUBLIC_KEY_BYTES,
     AIGIS_SIG_PARAM_III_PRIVATE_KEY_BYTES, AIGIS_SIG_PARAM_III_SIGNATURE_MAX_BYTES,
     AIGIS_SIG_PARAM_III_SIGNATURE_MIN_BYTES},
    {PQCP_AIGIS_SIG_SHA3_III, PQCP_AIGIS_SIG_PARAM_III, PQCP_AIGIS_SIG_HASH_SHA3, AIGIS_SIG_PARAM_III_PUBLIC_KEY_BYTES,
     AIGIS_SIG_PARAM_III_PRIVATE_KEY_BYTES, AIGIS_SIG_PARAM_III_SIGNATURE_MAX_BYTES,
     AIGIS_SIG_PARAM_III_SIGNATURE_MIN_BYTES},
};

static const PQCP_AIGIS_SIG_AlgInfo *AigisSigGetInfo(int32_t paramId)
{
    for (uint32_t i = 0; i < sizeof(g_aigisSigInfo) / sizeof(g_aigisSigInfo[0]); i++) {
        if (g_aigisSigInfo[i].paramId == paramId) {
            return &g_aigisSigInfo[i];
        }
    }
    return NULL;
}

static int32_t AigisSigPushError(int32_t error)
{
    BSL_ERR_PUSH_ERROR(error);
    return error;
}

CRYPT_AIGIS_SIG_Ctx *PQCP_AIGIS_SIG_NewCtx(void *libCtx)
{
    CRYPT_AIGIS_SIG_Ctx *ctx = BSL_SAL_Calloc(1U, sizeof(CRYPT_AIGIS_SIG_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->opCtx.libCtx = libCtx;
    return ctx;
}

void PQCP_AIGIS_SIG_FreeCtx(CRYPT_AIGIS_SIG_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->prvKey != NULL && ctx->info != NULL) {
        BSL_SAL_ClearFree(ctx->prvKey, ctx->info->prvKeyLen);
    } else {
        BSL_SAL_FREE(ctx->prvKey);
    }
    BSL_SAL_FREE(ctx->pubKey);
    BSL_SAL_Free(ctx);
}

static int32_t AigisSigCopyKey(uint8_t **dst, uint32_t expectedLen, const BSL_Param *params, int32_t key, bool secret)
{
    BSL_Param *param = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)params, key);
    if (param == NULL || param->value == NULL) {
        return AigisSigPushError(PQCP_NULL_INPUT);
    }
    if (param->valueLen != expectedLen) {
        return AigisSigPushError(PQCP_AIGIS_SIG_KEYLEN_ERROR);
    }
    uint8_t *copy = BSL_SAL_Malloc(expectedLen);
    if (copy == NULL) {
        return AigisSigPushError(PQCP_MEM_ALLOC_FAIL);
    }
    (void)memcpy(copy, param->value, expectedLen);
    if (secret) {
        BSL_SAL_ClearFree(*dst, expectedLen);
    } else {
        BSL_SAL_FREE(*dst);
    }
    *dst = copy;
    return PQCP_SUCCESS;
}

static int32_t AigisSigGetKey(const uint8_t *src, uint32_t expectedLen, BSL_Param *params, int32_t key)
{
    BSL_Param *param = BSL_PARAM_FindParam(params, key);
    if (param == NULL || param->value == NULL) {
        return AigisSigPushError(PQCP_NULL_INPUT);
    }
    if (src == NULL) {
        return AigisSigPushError(PQCP_AIGIS_SIG_KEY_NOT_SET);
    }
    if (param->valueLen < expectedLen) {
        return AigisSigPushError(PQCP_AIGIS_SIG_KEYLEN_ERROR);
    }
    (void)memcpy(param->value, src, expectedLen);
    param->useLen = expectedLen;
    return PQCP_SUCCESS;
}

int32_t PQCP_AIGIS_SIG_SetPrvKey(CRYPT_AIGIS_SIG_Ctx *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return AigisSigPushError(PQCP_NULL_INPUT);
    }
    if (ctx->info == NULL) {
        return AigisSigPushError(PQCP_AIGIS_SIG_PARAM_NOT_SET);
    }
    return AigisSigCopyKey(&ctx->prvKey, ctx->info->prvKeyLen, param, PQCP_PARAM_AIGIS_SIG_PRVKEY, true);
}

int32_t PQCP_AIGIS_SIG_SetPubKey(CRYPT_AIGIS_SIG_Ctx *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return AigisSigPushError(PQCP_NULL_INPUT);
    }
    if (ctx->info == NULL) {
        return AigisSigPushError(PQCP_AIGIS_SIG_PARAM_NOT_SET);
    }
    return AigisSigCopyKey(&ctx->pubKey, ctx->info->pubKeyLen, param, PQCP_PARAM_AIGIS_SIG_PUBKEY, false);
}

int32_t PQCP_AIGIS_SIG_GetPrvKey(const CRYPT_AIGIS_SIG_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return AigisSigPushError(PQCP_NULL_INPUT);
    }
    if (ctx->info == NULL) {
        return AigisSigPushError(PQCP_AIGIS_SIG_PARAM_NOT_SET);
    }
    return AigisSigGetKey(ctx->prvKey, ctx->info->prvKeyLen, param, PQCP_PARAM_AIGIS_SIG_PRVKEY);
}

int32_t PQCP_AIGIS_SIG_GetPubKey(const CRYPT_AIGIS_SIG_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return AigisSigPushError(PQCP_NULL_INPUT);
    }
    if (ctx->info == NULL) {
        return AigisSigPushError(PQCP_AIGIS_SIG_PARAM_NOT_SET);
    }
    return AigisSigGetKey(ctx->pubKey, ctx->info->pubKeyLen, param, PQCP_PARAM_AIGIS_SIG_PUBKEY);
}

int32_t PQCP_AIGIS_SIG_Ctrl(CRYPT_AIGIS_SIG_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL || val == NULL) {
        return AigisSigPushError(PQCP_NULL_INPUT);
    }
    if (valLen != sizeof(int32_t)) {
        return AigisSigPushError(PQCP_INVALID_ARG);
    }
    if (cmd == CRYPT_CTRL_SET_PARA_BY_ID) {
        if (ctx->info != NULL) {
            return AigisSigPushError(PQCP_AIGIS_SIG_PARAM_REPEATED_SET);
        }
        ctx->info = AigisSigGetInfo(*(int32_t *)val);
        if (ctx->info == NULL) {
            return AigisSigPushError(PQCP_INVALID_ARG);
        }
        ctx->opCtx.paramId = ctx->info->coreParamId;
        ctx->opCtx.hashId = ctx->info->hashId;
        ctx->opCtx.params = PQCP_AIGIS_SIG_GetParams(ctx->info->coreParamId);
        if (ctx->opCtx.params == NULL) {
            ctx->info = NULL;
            return AigisSigPushError(PQCP_INVALID_ARG);
        }
        return PQCP_SUCCESS;
    }
    if (ctx->info == NULL) {
        return AigisSigPushError(PQCP_AIGIS_SIG_PARAM_NOT_SET);
    }
    switch (cmd) {
        case CRYPT_CTRL_GET_SIGNLEN:
            *(int32_t *)val = (int32_t)ctx->info->signLen;
            return PQCP_SUCCESS;
        case CRYPT_CTRL_GET_PUBKEY_LEN:
            *(int32_t *)val = (int32_t)ctx->info->pubKeyLen;
            return PQCP_SUCCESS;
        case CRYPT_CTRL_GET_PRVKEY_LEN:
            *(int32_t *)val = (int32_t)ctx->info->prvKeyLen;
            return PQCP_SUCCESS;
        default:
            return AigisSigPushError(PQCP_INVALID_ARG);
    }
}

int32_t PQCP_AIGIS_SIG_GenKey(CRYPT_AIGIS_SIG_Ctx *ctx)
{
    if (ctx == NULL) {
        return AigisSigPushError(PQCP_NULL_INPUT);
    }
    if (ctx->info == NULL) {
        return AigisSigPushError(PQCP_AIGIS_SIG_PARAM_NOT_SET);
    }
    uint8_t *pubKey = BSL_SAL_Malloc(ctx->info->pubKeyLen);
    uint8_t *prvKey = BSL_SAL_Malloc(ctx->info->prvKeyLen);
    if (pubKey == NULL || prvKey == NULL) {
        BSL_SAL_FREE(pubKey);
        BSL_SAL_ClearFree(prvKey, ctx->info->prvKeyLen);
        return AigisSigPushError(PQCP_MEM_ALLOC_FAIL);
    }
    int32_t ret = ctx->opCtx.hashId == PQCP_AIGIS_SIG_HASH_SHA3 ?
                      AigisSigRunKeyGenSha3(ctx, pubKey, prvKey) :
                      PQCP_AIGIS_SIG_KeyGenInternal(&ctx->opCtx, pubKey, prvKey);
    if (ret != 0) {
        BSL_SAL_FREE(pubKey);
        BSL_SAL_ClearFree(prvKey, ctx->info->prvKeyLen);
        return AigisSigPushError(PQCP_AIGIS_SIG_OPERATION_FAIL);
    }
    BSL_SAL_FREE(ctx->pubKey);
    BSL_SAL_ClearFree(ctx->prvKey, ctx->info->prvKeyLen);
    ctx->pubKey = pubKey;
    ctx->prvKey = prvKey;
    return PQCP_SUCCESS;
}

CRYPT_AIGIS_SIG_Ctx *PQCP_AIGIS_SIG_DupCtx(const CRYPT_AIGIS_SIG_Ctx *src)
{
    if (src == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return NULL;
    }
    CRYPT_AIGIS_SIG_Ctx *dst = PQCP_AIGIS_SIG_NewCtx(src->opCtx.libCtx);
    if (dst == NULL) {
        return NULL;
    }
    dst->info = src->info;
    dst->opCtx.paramId = src->opCtx.paramId;
    dst->opCtx.hashId = src->opCtx.hashId;
    dst->opCtx.params = src->opCtx.params;
    if (src->pubKey != NULL) {
        dst->pubKey = BSL_SAL_Malloc(src->info->pubKeyLen);
    }
    if (src->prvKey != NULL) {
        dst->prvKey = BSL_SAL_Malloc(src->info->prvKeyLen);
    }
    if ((src->pubKey != NULL && dst->pubKey == NULL) || (src->prvKey != NULL && dst->prvKey == NULL)) {
        PQCP_AIGIS_SIG_FreeCtx(dst);
        BSL_ERR_PUSH_ERROR(PQCP_MEM_ALLOC_FAIL);
        return NULL;
    }
    if (src->pubKey != NULL) {
        (void)memcpy(dst->pubKey, src->pubKey, src->info->pubKeyLen);
    }
    if (src->prvKey != NULL) {
        (void)memcpy(dst->prvKey, src->prvKey, src->info->prvKeyLen);
    }
    return dst;
}

int32_t PQCP_AIGIS_SIG_Sign(CRYPT_AIGIS_SIG_Ctx *ctx, int32_t mdId, const uint8_t *data, uint32_t dataLen,
                            uint8_t *sign, uint32_t *signLen)
{
    (void)mdId;
    if (ctx == NULL || (data == NULL && dataLen != 0U) || sign == NULL || signLen == NULL) {
        return AigisSigPushError(PQCP_NULL_INPUT);
    }
    if (ctx->info == NULL) {
        return AigisSigPushError(PQCP_AIGIS_SIG_PARAM_NOT_SET);
    }
    if (ctx->prvKey == NULL) {
        return AigisSigPushError(PQCP_AIGIS_SIG_KEY_NOT_SET);
    }
    if (*signLen < ctx->info->signLen || *signLen > INT32_MAX || dataLen > INT32_MAX) {
        return AigisSigPushError(PQCP_AIGIS_SIG_INVALID_SIG_LEN);
    }
    uint32_t coreSignLen = *signLen;
    int32_t ret = ctx->opCtx.hashId == PQCP_AIGIS_SIG_HASH_SHA3 ?
                      AigisSigRunSignSha3(ctx, data, dataLen, sign, &coreSignLen) :
                      PQCP_AIGIS_SIG_SignInternal(&ctx->opCtx, ctx->prvKey, data, dataLen, sign, &coreSignLen);
    if (ret == 0) {
        *signLen = coreSignLen;
    }
    return ret == 0 ? PQCP_SUCCESS : AigisSigPushError(PQCP_AIGIS_SIG_OPERATION_FAIL);
}

int32_t PQCP_AIGIS_SIG_Verify(const CRYPT_AIGIS_SIG_Ctx *ctx, int32_t mdId, const uint8_t *data, uint32_t dataLen,
                              uint8_t *sign, uint32_t signLen)
{
    (void)mdId;
    if (ctx == NULL || (data == NULL && dataLen != 0U) || sign == NULL) {
        return AigisSigPushError(PQCP_NULL_INPUT);
    }
    if (ctx->info == NULL) {
        return AigisSigPushError(PQCP_AIGIS_SIG_PARAM_NOT_SET);
    }
    if (ctx->pubKey == NULL) {
        return AigisSigPushError(PQCP_AIGIS_SIG_KEY_NOT_SET);
    }
    if (signLen < ctx->info->minSignLen || signLen > ctx->info->signLen || dataLen > INT32_MAX || signLen > INT32_MAX) {
        return AigisSigPushError(PQCP_AIGIS_SIG_INVALID_SIG_LEN);
    }
    int32_t ret = ctx->opCtx.hashId == PQCP_AIGIS_SIG_HASH_SHA3 ?
                      AigisSigRunVerifySha3(ctx, data, dataLen, sign, signLen) :
                      PQCP_AIGIS_SIG_VerifyInternal(&ctx->opCtx, ctx->pubKey, sign, signLen, data, dataLen);
    return ret == 0 ? PQCP_SUCCESS : AigisSigPushError(PQCP_AIGIS_SIG_VERIFY_FAIL);
}

#endif /* PQCP_AIGIS_SIG */
