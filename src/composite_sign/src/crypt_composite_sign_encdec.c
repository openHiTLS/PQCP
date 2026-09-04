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
#ifdef PQCP_COMPOSITE_SIGN

#include "crypt_utils.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "crypt_composite_sign_local.h"
#ifdef PQCP_AIGIS_SIG
#include "crypt_aigis_sig.h"
#endif
#include "pqcp_err.h"
#include "pqcp_types.h"

int32_t PQCP_CompositeGetMldsaPrvKey(const PQCP_CompositeCtx *ctx, BSL_Buffer *encode)
{
    /*  https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-14
        draft-ietf-lamps-pq-composite-sigs-14: sk = SerializePrivateKey(mldsaSeed, tradSK)
    */
    int32_t ret;
    uint32_t prvLen = ctx->info->pqcPrvkeyLen;
    uint8_t *prv = (uint8_t *)BSL_SAL_Malloc(prvLen);
    RETURN_RET_IF(prv == NULL, PQCP_MEM_ALLOC_FAIL);
    GOTO_ERR_IF(CRYPT_EAL_PkeyCtrl(ctx->pqcCtx, CRYPT_CTRL_GET_MLDSA_SEED, prv, prvLen), ret);
    encode->data = prv;
    encode->dataLen = prvLen;
    return PQCP_SUCCESS;
ERR:
    BSL_SAL_Free(prv);
    return ret;
}

int32_t PQCP_CompositeGetMldsaPubKey(const PQCP_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t pubLen = ctx->info->pqcPubkeyLen;
    uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
    RETURN_RET_IF(pub == NULL, PQCP_MEM_ALLOC_FAIL);
    BSL_Param param[2] = {{CRYPT_PARAM_ML_DSA_PUBKEY, BSL_PARAM_TYPE_OCTETS, pub, pubLen, 0}, BSL_PARAM_END};
    GOTO_ERR_IF(CRYPT_EAL_PkeyGetPubEx(ctx->pqcCtx, param), ret);
    encode->data = pub;
    encode->dataLen = pubLen;
    return PQCP_SUCCESS;
ERR:
    BSL_SAL_FREE(pub);
    return ret;
}

#ifdef PQCP_AIGIS_SIG
int32_t PQCP_CompositeGetAigisPrvKey(const PQCP_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t prvLen = ctx->info->pqcPrvkeyLen;
    uint8_t *prv = (uint8_t *)BSL_SAL_Malloc(prvLen);
    RETURN_RET_IF(prv == NULL, PQCP_MEM_ALLOC_FAIL);
    BSL_Param param[2] = {{PQCP_PARAM_AIGIS_SIG_PRVKEY, BSL_PARAM_TYPE_OCTETS, prv, prvLen, 0}, BSL_PARAM_END};
    GOTO_ERR_IF(PQCP_AIGIS_SIG_GetPrvKey(ctx->pqcCtx, param), ret);
    encode->data = prv;
    encode->dataLen = param[0].useLen;
    return PQCP_SUCCESS;
ERR:
    BSL_SAL_ClearFree(prv, prvLen);
    return ret;
}

int32_t PQCP_CompositeGetAigisPubKey(const PQCP_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t pubLen = ctx->info->pqcPubkeyLen;
    uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
    RETURN_RET_IF(pub == NULL, PQCP_MEM_ALLOC_FAIL);
    BSL_Param param[2] = {{PQCP_PARAM_AIGIS_SIG_PUBKEY, BSL_PARAM_TYPE_OCTETS, pub, pubLen, 0}, BSL_PARAM_END};
    GOTO_ERR_IF(PQCP_AIGIS_SIG_GetPubKey(ctx->pqcCtx, param), ret);
    encode->data = pub;
    encode->dataLen = param[0].useLen;
    return PQCP_SUCCESS;
ERR:
    BSL_SAL_FREE(pub);
    return ret;
}
#endif

static int32_t GetSm2PubKey(const PQCP_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t pubLen = 0;
    RETURN_RET_IF_ERR(CRYPT_EAL_PkeyCtrl(ctx->tradCtx, CRYPT_CTRL_GET_PUBKEY_LEN, &pubLen, sizeof(pubLen)), ret);
    uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
    RETURN_RET_IF(pub == NULL, PQCP_MEM_ALLOC_FAIL);
    BSL_Param param[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, pub, pubLen, 0}, BSL_PARAM_END};
    ret = CRYPT_EAL_PkeyGetPubEx(ctx->tradCtx, param);
    if (ret != PQCP_SUCCESS) {
        BSL_SAL_FREE(pub);
        return ret;
    }
    encode->data = pub;
    encode->dataLen = param[0].useLen;
    return PQCP_SUCCESS;
}

static int32_t GetSm2PrvKey(const PQCP_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t prvLen = 0;
    RETURN_RET_IF_ERR(CRYPT_EAL_PkeyCtrl(ctx->tradCtx, CRYPT_CTRL_GET_PRVKEY_LEN, &prvLen, sizeof(prvLen)), ret);
    uint8_t *prv = (uint8_t *)BSL_SAL_Malloc(prvLen);
    RETURN_RET_IF(prv == NULL, PQCP_MEM_ALLOC_FAIL);
    BSL_Param param[2] = {{CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS, prv, prvLen, 0}, BSL_PARAM_END};
    ret = CRYPT_EAL_PkeyGetPrvEx(ctx->tradCtx, param);
    if (ret != PQCP_SUCCESS) {
        BSL_SAL_FREE(prv);
        return ret;
    }
    encode->data = prv;
    encode->dataLen = param[0].useLen;
    return PQCP_SUCCESS;
}

int32_t PQCP_CompositeGetTradPrvKey(const PQCP_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->tradAlg) {
        case CRYPT_PKEY_SM2:
            return GetSm2PrvKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(PQCP_NOT_SUPPORT);
            return PQCP_NOT_SUPPORT;
    }
}

int32_t PQCP_CompositeGetTradPubKey(const PQCP_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->tradAlg) {
        case CRYPT_PKEY_SM2:
            return GetSm2PubKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(PQCP_NOT_SUPPORT);
            return PQCP_NOT_SUPPORT;
    }
}

int32_t PQCP_CompositeSetMldsaPrvKey(PQCP_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_Param param[2] = {
        {CRYPT_PARAM_ML_DSA_PRVKEY_SEED, BSL_PARAM_TYPE_OCTETS, encode->data, encode->dataLen, 0},
        BSL_PARAM_END};
    RETURN_RET_IF_ERR(CRYPT_EAL_PkeySetPrvEx(ctx->pqcCtx, param), ret);
    return PQCP_SUCCESS;
}

int32_t PQCP_CompositeSetMldsaPubKey(PQCP_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_Param param[2] = {
        {CRYPT_PARAM_ML_DSA_PUBKEY, BSL_PARAM_TYPE_OCTETS, encode->data, encode->dataLen, 0},
        BSL_PARAM_END};
    RETURN_RET_IF_ERR(CRYPT_EAL_PkeySetPubEx(ctx->pqcCtx, param), ret);
    return PQCP_SUCCESS;
}

#ifdef PQCP_AIGIS_SIG
int32_t PQCP_CompositeSetAigisPrvKey(PQCP_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_Param param[2] = {
        {PQCP_PARAM_AIGIS_SIG_PRVKEY, BSL_PARAM_TYPE_OCTETS, encode->data, encode->dataLen, 0},
        BSL_PARAM_END};
    RETURN_RET_IF_ERR(PQCP_AIGIS_SIG_SetPrvKey(ctx->pqcCtx, param), ret);
    return PQCP_SUCCESS;
}

int32_t PQCP_CompositeSetAigisPubKey(PQCP_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_Param param[2] = {
        {PQCP_PARAM_AIGIS_SIG_PUBKEY, BSL_PARAM_TYPE_OCTETS, encode->data, encode->dataLen, 0},
        BSL_PARAM_END};
    RETURN_RET_IF_ERR(PQCP_AIGIS_SIG_SetPubKey(ctx->pqcCtx, param), ret);
    return PQCP_SUCCESS;
}
#endif

static int32_t SetSm2PubKey(PQCP_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_Param param[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, encode->data, encode->dataLen, 0},
                          BSL_PARAM_END};
    RETURN_RET_IF_ERR(CRYPT_EAL_PkeySetPubEx(ctx->tradCtx, param), ret);
    return PQCP_SUCCESS;
}

static int32_t SetSm2PrvKey(PQCP_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_Param para[2] = {{CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS, encode->data, encode->dataLen, 0},
                         BSL_PARAM_END};
    RETURN_RET_IF_ERR(CRYPT_EAL_PkeySetPrvEx(ctx->tradCtx, para), ret);
    return PQCP_SUCCESS;
}

int32_t PQCP_CompositeSetTradPrvKey(PQCP_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->tradAlg) {
        case CRYPT_PKEY_SM2:
            return SetSm2PrvKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(PQCP_NOT_SUPPORT);
            return PQCP_NOT_SUPPORT;
    }
}

int32_t PQCP_CompositeSetTradPubKey(PQCP_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->tradAlg) {
        case CRYPT_PKEY_SM2:
            return SetSm2PubKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(PQCP_NOT_SUPPORT);
            return PQCP_NOT_SUPPORT;
    }
}
#endif // PQCP_COMPOSITE_SIGN
