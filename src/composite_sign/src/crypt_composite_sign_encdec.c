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
#include "crypt_composite_sign_local.h"
#include "pqcp_err.h"

static int32_t CRYPT_CompositeGetMldsaPrvKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    /*  https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-14
        draft-ietf-lamps-pq-composite-sigs-14: sk = SerializePrivateKey(mldsaSeed, tradSK)
    */
    int32_t ret;
    uint32_t prvLen = ctx->info->pqcPrvkeyLen;
    uint8_t *prv = (uint8_t *)BSL_SAL_Malloc(prvLen);
    RETURN_RET_IF(prv == NULL, PQCP_MEM_ALLOC_FAIL);
    GOTO_ERR_IF(ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_GET_MLDSA_SEED, prv, prvLen), ret);
    encode->data = prv;
    encode->dataLen = prvLen;
    return PQCP_SUCCESS;
ERR:
    BSL_SAL_Free(prv);
    return ret;
}

static int32_t CRYPT_CompositeGetMldsaPubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t pubLen = ctx->info->pqcPubkeyLen;
    uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
    RETURN_RET_IF(pub == NULL, PQCP_MEM_ALLOC_FAIL);
    BSL_Param param[2] = {{CRYPT_PARAM_ML_DSA_PUBKEY, BSL_PARAM_TYPE_OCTETS, pub, pubLen, 0}, BSL_PARAM_END};
    GOTO_ERR_IF(ctx->pqcMethod->getPub(ctx->pqcCtx, &param), ret);
    encode->data = pub;
    encode->dataLen = pubLen;
    return PQCP_SUCCESS;
ERR:
    BSL_SAL_FREE(pub);
    return ret;
}

int32_t CRYPT_CompositeGetPqcPrvKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->pqcAlg) {
        case CRYPT_PKEY_ML_DSA:
            return CRYPT_CompositeGetMldsaPrvKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(PQCP_NOT_SUPPORT);
            return PQCP_NOT_SUPPORT;
    }
}

int32_t CRYPT_CompositeGetPqcPubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->pqcAlg) {
        case CRYPT_PKEY_ML_DSA:
            return CRYPT_CompositeGetMldsaPubKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(PQCP_NOT_SUPPORT);
            return PQCP_NOT_SUPPORT;
    }
}


static int32_t CRYPT_CompositeGetSm2PubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t pubLen = 0;
    RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_PUBKEY_LEN, &pubLen, sizeof(pubLen)),ret);
    uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
    RETURN_RET_IF(pub == NULL, PQCP_MEM_ALLOC_FAIL);
    BSL_Param param[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, pub, pubLen, 0}, BSL_PARAM_END};
    ret = ctx->tradMethod->getPub(ctx->tradCtx, &param);
    if (ret != PQCP_SUCCESS) {
        BSL_SAL_FREE(pub);
        return ret;
    }
    encode->data = pub;
    encode->dataLen = pubLen;
    return PQCP_SUCCESS;
}

static int32_t CRYPT_CompositeGetSm2PrvKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t prvLen = 0;
    RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_PRVKEY_LEN, &prvLen, sizeof(prvLen)),ret);
    uint8_t *prv = (uint8_t *)BSL_SAL_Malloc(prvLen);
    RETURN_RET_IF(prv == NULL, PQCP_MEM_ALLOC_FAIL);
    BSL_Param param[2] = {{CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS, prv, prvLen, 0}, BSL_PARAM_END};
    ret = ctx->tradMethod->getPrv(ctx->tradCtx, &param);
    if (ret != PQCP_SUCCESS) {
        BSL_SAL_FREE(prv);
        return ret;
    }
    encode->data = prv;
    encode->dataLen = prvLen;
    return PQCP_SUCCESS;
}

int32_t CRYPT_CompositeGetTradPrvKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->tradAlg) {
        case CRYPT_PKEY_SM2:
            return CRYPT_CompositeGetSm2PrvKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(PQCP_NOT_SUPPORT);
            return PQCP_NOT_SUPPORT;
    }
}

int32_t CRYPT_CompositeGetTradPubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->tradAlg) {
        case CRYPT_PKEY_SM2:
            return CRYPT_CompositeGetSm2PubKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(PQCP_NOT_SUPPORT);
            return PQCP_NOT_SUPPORT;
    }
}

static int32_t CRYPT_CompositeSetMldsaPrvKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_Param param[2] = {
        {CRYPT_PARAM_ML_DSA_PRVKEY_SEED, BSL_PARAM_TYPE_OCTETS, encode->data, encode->dataLen, 0},
        BSL_PARAM_END};
    RETURN_RET_IF_ERR(ctx->pqcMethod->setPrv(ctx->pqcCtx, &param), ret);
    return PQCP_SUCCESS;
}

static int32_t CRYPT_CompositeSetMldsaPubKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_Param param[2] = {
        {CRYPT_PARAM_ML_DSA_PUBKEY, BSL_PARAM_TYPE_OCTETS, encode->data, encode->dataLen, 0},
        BSL_PARAM_END};
    RETURN_RET_IF_ERR(ctx->pqcMethod->setPub(ctx->pqcCtx, &param), ret);
    return PQCP_SUCCESS;
}

int32_t CRYPT_CompositeSetPqcPrvKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->pqcAlg) {
        case CRYPT_PKEY_ML_DSA:
            return CRYPT_CompositeSetMldsaPrvKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(PQCP_NOT_SUPPORT);
            return PQCP_NOT_SUPPORT;
    }
}
int32_t CRYPT_CompositeSetPqcPubKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->pqcAlg) {
        case CRYPT_PKEY_ML_DSA:
            return CRYPT_CompositeSetMldsaPubKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(PQCP_NOT_SUPPORT);
            return PQCP_NOT_SUPPORT;
    }
}

static int32_t CRYPT_CompositeSetSm2PubKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_Param param[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, encode->data, encode->dataLen, 0},
                          BSL_PARAM_END};
    RETURN_RET_IF_ERR(ctx->tradMethod->setPub(ctx->tradCtx, &param), ret);
    return PQCP_SUCCESS;
}

static int32_t CRYPT_CompositeSetSm2PrvKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_Param para[2] = {{CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS, encode->data, encode->dataLen, 0},
                         BSL_PARAM_END};
    RETURN_RET_IF_ERR(ctx->tradMethod->setPrv(ctx->tradCtx, &para), ret);
    return PQCP_SUCCESS;
}

int32_t CRYPT_CompositeSetTradPrvKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->tradAlg) {
        case CRYPT_PKEY_SM2:
            return CRYPT_CompositeSetSm2PrvKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(PQCP_NOT_SUPPORT);
            return PQCP_NOT_SUPPORT;
    }
}

int32_t CRYPT_CompositeSetTradPubKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->tradAlg) {
        case CRYPT_PKEY_SM2:
            return CRYPT_CompositeSetSm2PubKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(PQCP_NOT_SUPPORT);
            return PQCP_NOT_SUPPORT;
    }
}
#endif // PQCP_COMPOSITE_SIGN
