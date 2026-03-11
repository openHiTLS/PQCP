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
#include "securec.h"

#include "crypt_composite_sign_local.h"
#include "crypt_utils.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "eal_pkey_local.h"
#include "eal_md_local.h"

#include "pqcp_types.h"
#include "pqcp_err.h"

#define MLDSA_SEED_LEN 32
#define CHECK_UINT32_LEN_AND_INFO(ctx, val, len)                \
    do                                                          \
    {                                                           \
        if (val == NULL)                                        \
        {                                                       \
            BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);               \
            return PQCP_NULL_INPUT;                            \
        }                                                       \
        if (len != sizeof(uint32_t))                            \
        {                                                       \
            BSL_ERR_PUSH_ERROR(PQCP_INVALID_ARG);              \
            return PQCP_INVALID_ARG;                           \
        }                                                       \
        if (ctx->info == NULL)                                  \
        {                                                       \
            BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_KEYINFO_NOT_SET); \
            return PQCP_COMPOSITE_KEYINFO_NOT_SET;              \
        }                                                       \
    } while (0)

/*
This part of codes references the composite sign IEFT DRAFT: https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/
*/
static const uint8_t PREFIX[] = {0x43, 0x6F, 0x6D, 0x70, 0x6F, 0x73, 0x69, 0x74, 0x65, 0x41, 0x6C,
                                 0x67, 0x6F, 0x72, 0x69, 0x74, 0x68, 0x6D, 0x53, 0x69, 0x67, 0x6E,
                                 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x32, 0x30, 0x32, 0x35};

static const COMPOSITE_ALG_INFO g_composite_info[] = {
    {
        PQCP_COMPOSITE_MLDSA44_SM2, // Composite algId
        "COMPSIG-MLDSA44-SM2", // label
        CRYPT_PKEY_ML_DSA, // pqc algId
        CRYPT_MLDSA_TYPE_MLDSA_44, // pqc paraId
        CRYPT_PKEY_SM2, // trad algId
        0, // trad paraId
        CRYPT_MD_SM3, // composite hash Id
        CRYPT_MD_SM3, // trad hash Id
        0, // bits
        1377, // composite public key len
        64, // composite private key len
        1312, // pqc public key len
        32, // pqc private key len
        2420, // pqc sig len
    },
    {   PQCP_COMPOSITE_MLDSA65_SM2, // Composite algId
        "COMPSIG-MLDSA65-SM2", // label
        CRYPT_PKEY_ML_DSA, // pqc algId
        CRYPT_MLDSA_TYPE_MLDSA_65, // pqc paraId
        CRYPT_PKEY_SM2, // trad algId
        0, // trad paraId
        CRYPT_MD_SM3, // composite hash Id
        CRYPT_MD_SM3, // trad hash Id
        0, // bits
        2017, // composite public key len
        64, // composite private key len
        1952, // pqc public key len
        32, // pqc private key len
        3309, // pqc sig len
    },
    {
        PQCP_COMPOSITE_MLDSA87_SM2, // Composite algId
        "COMPSIG-MLDSA87-SM2", // label
        CRYPT_PKEY_ML_DSA, // pqc algId
        CRYPT_MLDSA_TYPE_MLDSA_87, // pqc paraId
        CRYPT_PKEY_SM2, // trad algId
        0, // trad paraId
        CRYPT_MD_SM3, // composite hash Id
        CRYPT_MD_SM3, // trad hash Id
        0, // bits
        2657, // composite public key len
        64, // composite private key len
        2592, // pqc public key len
        32, // pqc private key len
        4627, // pqc sig len
    }
};

const COMPOSITE_ALG_INFO *CRYPT_COMPOSITE_GetInfo(int32_t paramId)
{
    const COMPOSITE_ALG_INFO *info = NULL;
    for (size_t i = 0; i < sizeof(g_composite_info) / sizeof(g_composite_info[0]); i++) {
        if (g_composite_info[i].paramId == paramId) {
            info = &g_composite_info[i];
            return info;
        }
    }
    return NULL;
}

CRYPT_CompositeCtx *CRYPT_COMPOSITE_NewCtx(void)
{
    CRYPT_CompositeCtx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_CompositeCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_MEM_ALLOC_FAIL);
        return NULL;
    }
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}

void CRYPT_COMPOSITE_FreeCtx(CRYPT_CompositeCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    int ref = 0;
    BSL_SAL_AtomicDownReferences(&(ctx->references), &ref);
    if (ref > 0) {
        return;
    }
    if (ctx->pqcMethod != NULL && ctx->pqcMethod->freeCtx != NULL) {
        ctx->pqcMethod->freeCtx(ctx->pqcCtx);
    }
    if (ctx->tradMethod != NULL && ctx->tradMethod->freeCtx != NULL) {
        ctx->tradMethod->freeCtx(ctx->tradCtx);
    }
    BSL_SAL_FREE(ctx->ctxInfo);
    BSL_SAL_ReferencesFree(&(ctx->references));
    BSL_SAL_FREE(ctx);
}

CRYPT_CompositeCtx *CRYPT_COMPOSITE_DupCtx(CRYPT_CompositeCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return NULL;
    }
    CRYPT_CompositeCtx *newCtx = CRYPT_COMPOSITE_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_MEM_ALLOC_FAIL);
        return NULL;
    }
    newCtx->info = ctx->info;
    newCtx->pqcMethod = ctx->pqcMethod;
    newCtx->tradMethod = ctx->tradMethod;
    if (newCtx->pqcMethod != NULL && newCtx->tradMethod != NULL) {
        newCtx->pqcCtx = newCtx->pqcMethod->dupCtx(ctx->pqcCtx);
        if (newCtx->pqcCtx == NULL) {
            BSL_ERR_PUSH_ERROR(PQCP_MEM_ALLOC_FAIL);
            goto ERR;
        }
        newCtx->tradCtx = newCtx->tradMethod->dupCtx(ctx->tradCtx);
        if (newCtx->tradCtx == NULL) {
            BSL_ERR_PUSH_ERROR(PQCP_MEM_ALLOC_FAIL);
            goto ERR;
        }
    }
    if (ctx->ctxLen > 0 && ctx->ctxInfo != NULL) {
        newCtx->ctxInfo = BSL_SAL_Dump(ctx->ctxInfo, ctx->ctxLen);
        if (newCtx->ctxInfo == NULL) {
            BSL_ERR_PUSH_ERROR(PQCP_MEM_ALLOC_FAIL);
            goto ERR;
        }
    }
    newCtx->ctxLen = ctx->ctxLen;
    newCtx->libCtx = ctx->libCtx;
    return newCtx;
ERR:
    CRYPT_COMPOSITE_FreeCtx(newCtx);
    return NULL;
}

static int32_t CRYPT_CompositeGetSignLen(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    if (len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(PQCP_INVALID_ARG);
        return PQCP_INVALID_ARG;
    }
    if (ctx->info == NULL ||ctx->pqcCtx == NULL || ctx->tradCtx == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_KEYINFO_NOT_SET);
        return PQCP_COMPOSITE_KEYINFO_NOT_SET;
    }
    uint32_t pqcSigLen = ctx->info->pqcSigLen;
    uint32_t tradSigLen = 0;
    int32_t ret = ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_SIGNLEN, &tradSigLen, sizeof(tradSigLen));
    if (ret != PQCP_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *(int32_t *)val = pqcSigLen + tradSigLen;
    return PQCP_SUCCESS;
}

static int32_t CRYPT_CompositeSetAlgInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    int32_t ret = PQCP_MEM_ALLOC_FAIL;
    if (len != sizeof(int32_t) || val == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_INVALID_ARG);
        return PQCP_INVALID_ARG;
    }
    if (ctx->info != NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_KEY_INFO_ALREADY_SET);
        return PQCP_COMPOSITE_KEY_INFO_ALREADY_SET;
    }
    ctx->info = CRYPT_COMPOSITE_GetInfo(*(int32_t *)val);
    if (ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_INVALID_ARG);
        return PQCP_INVALID_ARG;
    }
    const EAL_PkeyMethod *pqcMethod = CRYPT_EAL_PkeyFindMethod(ctx->info->pqcAlg);
    const EAL_PkeyMethod *tradMethod = CRYPT_EAL_PkeyFindMethod(ctx->info->tradAlg);
    if (pqcMethod == NULL || tradMethod == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NOT_SUPPORT);
        return PQCP_NOT_SUPPORT;
    }
    ctx->pqcCtx = pqcMethod->newCtx();
    GOTO_ERR_IF_TRUE((ctx->pqcCtx == NULL), PQCP_MEM_ALLOC_FAIL);
    ctx->tradCtx = tradMethod->newCtx();
    GOTO_ERR_IF_TRUE((ctx->tradCtx == NULL), PQCP_MEM_ALLOC_FAIL);
    int32_t pqcParam = ctx->info->pqcParam;
    GOTO_ERR_IF(pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_SET_PARA_BY_ID, &(pqcParam), sizeof(pqcParam)), ret);
    ctx->pqcMethod = pqcMethod;
    ctx->tradMethod = tradMethod;
    return PQCP_SUCCESS;
ERR:
    pqcMethod->freeCtx(ctx->pqcCtx);
    ctx->pqcCtx = NULL;
    tradMethod->freeCtx(ctx->tradCtx);
    ctx->tradCtx = NULL;
    ctx->info = NULL;
    return ret;
}

static int32_t CRYPT_CompositeSetctxInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    if (len > 0 && val == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    if (len > COMPOSITE_MAX_CTX_BYTES) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_KEYLEN_ERROR);
        return PQCP_COMPOSITE_KEYLEN_ERROR;
    }
    if (ctx->ctxInfo != NULL) {
        BSL_SAL_FREE(ctx->ctxInfo);
        ctx->ctxLen = 0;
    }
    if (val == NULL && len == 0) {
        return PQCP_SUCCESS;
    }
    ctx->ctxInfo = BSL_SAL_Dump((uint8_t *)val, len);
    if (ctx->ctxInfo == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_MEM_ALLOC_FAIL);
        return PQCP_MEM_ALLOC_FAIL;
    }
    ctx->ctxLen = len;
    return PQCP_SUCCESS;
}

static int32_t CRYPT_CompositeGetPubKeyLen(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(val == NULL || len != sizeof(uint32_t), PQCP_INVALID_ARG);
    RETURN_RET_IF(ctx->info == NULL, PQCP_COMPOSITE_KEYINFO_NOT_SET);
    *(uint32_t *)val = ctx->info->compPubKeyLen;
    return PQCP_SUCCESS;
}

static int32_t CRYPT_CompositeGetPrvKeyLen(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(val == NULL || len != sizeof(uint32_t), PQCP_INVALID_ARG);
    RETURN_RET_IF(ctx->info == NULL, PQCP_COMPOSITE_KEYINFO_NOT_SET);
    *(uint32_t *)val = ctx->info->compPrvKeyLen;
    return PQCP_SUCCESS;
}

int32_t CRYPT_COMPOSITE_Ctrl(CRYPT_CompositeCtx *ctx, int32_t opt, void *val, uint32_t len)
{
    RETURN_RET_IF(ctx == NULL, PQCP_NULL_INPUT);
    switch (opt) {
        case CRYPT_CTRL_SET_PARA_BY_ID:
            return CRYPT_CompositeSetAlgInfo(ctx, val, len);
        case CRYPT_CTRL_GET_SIGNLEN:
            return CRYPT_CompositeGetSignLen(ctx, val, len);
        case CRYPT_CTRL_GET_PUBKEY_LEN:
            return CRYPT_CompositeGetPubKeyLen(ctx, val, len);
        case CRYPT_CTRL_GET_PRVKEY_LEN:
            return CRYPT_CompositeGetPrvKeyLen(ctx, val, len);
        case CRYPT_CTRL_SET_CTX_INFO:
            return CRYPT_CompositeSetctxInfo(ctx, val, len);
        case PQCP_CTRL_HYBRID_GET_PQC_PRVKEY_LEN:
            CHECK_UINT32_LEN_AND_INFO(ctx, val, len);
            *(uint32_t *)val = MLDSA_SEED_LEN;
            return PQCP_SUCCESS;
        case PQCP_CTRL_HYBRID_GET_PQC_PUBKEY_LEN:
            CHECK_UINT32_LEN_AND_INFO(ctx, val, len);
            return ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_GET_PUBKEY_LEN, val, len);
        case PQCP_CTRL_HYBRID_GET_TRAD_PRVKEY_LEN:
            CHECK_UINT32_LEN_AND_INFO(ctx, val, len);
            return ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_PRVKEY_LEN, val, len);
        case PQCP_CTRL_HYBRID_GET_TRAD_PUBKEY_LEN:
            CHECK_UINT32_LEN_AND_INFO(ctx, val, len);
            return ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_PUBKEY_LEN, val, len);
        case PQCP_CTRL_HYBRID_GET_PQC_SIGNLEN:
            CHECK_UINT32_LEN_AND_INFO(ctx, val, len);
            return ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_GET_SIGNLEN, val, len);
        case PQCP_CTRL_HYBRID_GET_TRAD_SIGNLEN:
            CHECK_UINT32_LEN_AND_INFO(ctx, val, len);
            return ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_SIGNLEN, val, len);
        default:
            BSL_ERR_PUSH_ERROR(PQCP_NOT_SUPPORT);
            return PQCP_NOT_SUPPORT;
    }
}

int32_t CRYPT_COMPOSITE_GenKey(CRYPT_CompositeCtx *ctx)
{
    int32_t ret;
    RETURN_RET_IF(ctx == NULL, PQCP_NULL_INPUT);
    RETURN_RET_IF((ctx->pqcCtx == NULL || ctx->tradCtx == NULL), PQCP_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF_ERR(ctx->pqcMethod->gen(ctx->pqcCtx), ret);
    RETURN_RET_IF_ERR(ctx->tradMethod->gen(ctx->tradCtx), ret);
    return ret;
}

int32_t CRYPT_COMPOSITE_GetPrvKey(const CRYPT_CompositeCtx *ctx, CRYPT_CompositePrv *prv)
{
    RETURN_RET_IF((ctx == NULL || prv == NULL || prv->data == NULL), PQCP_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, PQCP_COMPOSITE_KEYINFO_NOT_SET);
    int32_t ret;
    BSL_Buffer pqcPrv = { 0 };
    BSL_Buffer tradPrv = { 0 };
    GOTO_ERR_IF(CRYPT_CompositeGetPqcPrvKey(ctx, &pqcPrv), ret);
    GOTO_ERR_IF(CRYPT_CompositeGetTradPrvKey(ctx, &tradPrv), ret);
    if (prv->len < pqcPrv.dataLen + tradPrv.dataLen) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_LEN_NOT_ENOUGH);
        ret = PQCP_COMPOSITE_LEN_NOT_ENOUGH;
        goto ERR;
    }
    (void)memcpy_s(prv->data, prv->len, pqcPrv.data, pqcPrv.dataLen);
    (void)memcpy_s(prv->data + pqcPrv.dataLen, prv->len - pqcPrv.dataLen, tradPrv.data, tradPrv.dataLen);
    prv->len = pqcPrv.dataLen + tradPrv.dataLen;
ERR:
    BSL_SAL_ClearFree(pqcPrv.data, pqcPrv.dataLen);
    BSL_SAL_ClearFree(tradPrv.data, tradPrv.dataLen);
    return ret;
}

int32_t CRYPT_COMPOSITE_GetPubKey(const CRYPT_CompositeCtx *ctx, CRYPT_CompositePub *pub)
{
    RETURN_RET_IF((ctx == NULL || pub == NULL || pub->data == NULL), PQCP_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, PQCP_COMPOSITE_KEYINFO_NOT_SET);
    int32_t ret;
    BSL_Buffer pqcPub = { 0 };
    BSL_Buffer tradPub = { 0 };
    GOTO_ERR_IF(CRYPT_CompositeGetPqcPubKey(ctx, &pqcPub), ret);
    GOTO_ERR_IF(CRYPT_CompositeGetTradPubKey(ctx, &tradPub), ret);
    if (pub->len < pqcPub.dataLen + tradPub.dataLen) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_LEN_NOT_ENOUGH);
        ret = PQCP_COMPOSITE_LEN_NOT_ENOUGH;
        goto ERR;
    }
    (void)memcpy_s(pub->data, pub->len, pqcPub.data, pqcPub.dataLen);
    (void)memcpy_s(pub->data + pqcPub.dataLen, pub->len - pqcPub.dataLen, tradPub.data, tradPub.dataLen);
    pub->len = pqcPub.dataLen + tradPub.dataLen;
ERR:
    BSL_SAL_FREE(pqcPub.data);
    BSL_SAL_FREE(tradPub.data);
    return ret;
}

int32_t CRYPT_COMPOSITE_SetPrvKey(CRYPT_CompositeCtx *ctx, const CRYPT_CompositePrv *prv)
{
    int32_t ret;
    RETURN_RET_IF((ctx == NULL || prv == NULL || prv->data == NULL), PQCP_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, PQCP_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(prv->len < ctx->info->compPrvKeyLen, PQCP_COMPOSITE_KEYLEN_ERROR);
    BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
    BSL_Buffer tradPrv = {prv->data + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen};
    RETURN_RET_IF_ERR(CRYPT_CompositeSetPqcPrvKey(ctx, &pqcPrv), ret);
    RETURN_RET_IF_ERR(CRYPT_CompositeSetTradPrvKey(ctx, &tradPrv), ret);
    return PQCP_SUCCESS;
}

int32_t CRYPT_COMPOSITE_SetPubKey(CRYPT_CompositeCtx *ctx, const CRYPT_CompositePub *pub)
{
    int32_t ret;
    RETURN_RET_IF((ctx == NULL || pub == NULL || pub->data == NULL), PQCP_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, PQCP_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(pub->len < ctx->info->compPubKeyLen, PQCP_COMPOSITE_KEYLEN_ERROR);

    BSL_Buffer pqcPub = {pub->data, ctx->info->pqcPubkeyLen};
    BSL_Buffer tradPub = {pub->data + ctx->info->pqcPubkeyLen, pub->len - ctx->info->pqcPubkeyLen};
    RETURN_RET_IF_ERR(CRYPT_CompositeSetPqcPubKey(ctx, &pqcPub), ret);
    RETURN_RET_IF_ERR(CRYPT_CompositeSetTradPubKey(ctx, &tradPub), ret);
    return PQCP_SUCCESS;
}

int32_t CRYPT_COMPOSITE_GetPrvKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    CRYPT_CompositePrv prv = {0};
    BSL_Param *paramPrv = GetParamValue(para, PQCP_PARAM_COMPOSITE_PRVKEY, &prv.data, &(prv.len));
    int32_t ret = CRYPT_COMPOSITE_GetPrvKey(ctx, &prv);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    paramPrv->useLen = prv.len;
    return PQCP_SUCCESS;
}

int32_t CRYPT_COMPOSITE_GetPubKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    CRYPT_CompositePub pub = {0};
    BSL_Param *paramPub = GetParamValue(para, PQCP_PARAM_COMPOSITE_PUBKEY, &pub.data, &(pub.len));
    int32_t ret = CRYPT_COMPOSITE_GetPubKey(ctx, &pub);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    paramPub->useLen = pub.len;
    return PQCP_SUCCESS;
}

int32_t CRYPT_COMPOSITE_SetPrvKeyEx(CRYPT_CompositeCtx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    CRYPT_CompositePrv prv = {0};
    (void)GetConstParamValue(para, PQCP_PARAM_COMPOSITE_PRVKEY, &prv.data, &prv.len);
    return CRYPT_COMPOSITE_SetPrvKey(ctx, &prv);
}

int32_t CRYPT_COMPOSITE_SetPubKeyEx(CRYPT_CompositeCtx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    CRYPT_CompositePub pub = {0};
    (void)GetConstParamValue(para, PQCP_PARAM_COMPOSITE_PUBKEY, &pub.data, &pub.len);
    return CRYPT_COMPOSITE_SetPubKey(ctx, &pub);
}

static int32_t CompositePreHash(int32_t hashId, const uint8_t *data, uint32_t dataLen,
                                uint8_t *digest, uint32_t *digestLen)
{
    int32_t ret;
    const EAL_MdMethod *hashMethod = EAL_MdFindDefaultMethod(hashId);
    RETURN_RET_IF(hashMethod == NULL, CRYPT_EAL_ALG_NOT_SUPPORT);
    void *mdCtx = hashMethod->newCtx(NULL, hashMethod->id);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_MEM_ALLOC_FAIL);
        return PQCP_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF(hashMethod->init(mdCtx, NULL), ret);
    GOTO_ERR_IF(hashMethod->update(mdCtx, data, dataLen), ret);
    GOTO_ERR_IF(hashMethod->final(mdCtx, digest, digestLen), ret);
ERR:
    hashMethod->freeCtx(mdCtx);
    return ret;
}

static int32_t CompositeMsgEncode(CRYPT_CompositeCtx *ctx, int32_t hashId, const uint8_t *data, uint32_t dataLen,
                                  CRYPT_Data *msg)
{
    int32_t ret;
    uint8_t digest[64];
    uint32_t digestLen = sizeof(digest);
    RETURN_RET_IF_ERR(CompositePreHash(hashId, data, dataLen, digest, &digestLen), ret);
    const char *label = ctx->info->label;
    uint32_t prefixLen = COMPOSITE_SIGNATURE_PREFIX_LEN;
    uint32_t labelLen = (uint32_t)strlen(label);
    msg->len = prefixLen + labelLen + 1 + ctx->ctxLen + digestLen;
    msg->data = (uint8_t *)BSL_SAL_Malloc(msg->len);
    RETURN_RET_IF(msg->data == NULL, PQCP_MEM_ALLOC_FAIL);
    uint8_t *ptr = msg->data;
    (void)memcpy_s(ptr, msg->len, PREFIX, prefixLen);
    ptr += prefixLen;
    (void)memcpy_s(ptr, msg->len - prefixLen, label, labelLen);
    ptr += labelLen;
    *ptr = ctx->ctxLen;
    ptr++;
    if (ctx->ctxInfo != NULL && ctx->ctxLen > 0) {
        (void)memcpy_s(ptr, msg->len - (prefixLen + labelLen + 1), ctx->ctxInfo, ctx->ctxLen);
        ptr += ctx->ctxLen;
    }
    (void)memcpy_s(ptr, digestLen, digest, digestLen);
    return PQCP_SUCCESS;
}

int32_t CRYPT_COMPOSITE_Sign(CRYPT_CompositeCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                             uint8_t *sign, uint32_t *signLen)
{
    (void)algId;
    if (ctx == NULL || data == NULL || sign == NULL || signLen == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    if (ctx->pqcCtx == NULL || ctx->tradCtx == NULL || ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_KEYINFO_NOT_SET);
        return PQCP_COMPOSITE_KEYINFO_NOT_SET;
    }
    if (*signLen < ctx->info->pqcSigLen) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_INVALID_SIG_LEN);
        return PQCP_COMPOSITE_INVALID_SIG_LEN;
    }
    int32_t ret;
    uint32_t pqcSigLen = ctx->info->pqcSigLen;
    uint32_t tradSigLen = *signLen - pqcSigLen;
    CRYPT_Data msg = {0};
    RETURN_RET_IF_ERR(CompositeMsgEncode(ctx, ctx->info->hashId, data, dataLen, &msg), ret);
    GOTO_ERR_IF(ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctx->info->label,
        (uint32_t)strlen(ctx->info->label)), ret);
    int32_t pqcRet = ctx->pqcMethod->sign(ctx->pqcCtx, CRYPT_MD_MAX, msg.data, msg.len, sign, &pqcSigLen);
    int32_t tradRet = ctx->tradMethod->sign(ctx->tradCtx, ctx->info->tradHashId, msg.data, msg.len, sign + pqcSigLen,
                                           &tradSigLen);
    if (pqcRet != PQCP_SUCCESS || tradRet != PQCP_SUCCESS) {
        ret = (pqcRet != PQCP_SUCCESS) ? pqcRet : tradRet;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    *signLen = pqcSigLen + tradSigLen;
ERR:
    BSL_SAL_FREE(msg.data);
    return ret;
}

int32_t CRYPT_COMPOSITE_Verify(CRYPT_CompositeCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                               uint8_t *sign, uint32_t signLen)
{
    (void)algId;
    if (ctx == NULL || data == NULL || sign == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    if (ctx->pqcCtx == NULL || ctx->tradCtx == NULL || ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_KEYINFO_NOT_SET);
        return PQCP_COMPOSITE_KEYINFO_NOT_SET;
    }
    if (signLen < ctx->info->pqcSigLen) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_INVALID_SIG_LEN);
        return PQCP_COMPOSITE_INVALID_SIG_LEN;
    }
    int32_t ret;
    uint32_t pqcSigLen = ctx->info->pqcSigLen;
    uint32_t tradSigLen = signLen - pqcSigLen;
    CRYPT_Data msg = {0};
    RETURN_RET_IF_ERR(CompositeMsgEncode(ctx, ctx->info->hashId, data, dataLen, &msg), ret);
    GOTO_ERR_IF(ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctx->info->label,
        (uint32_t)strlen(ctx->info->label)), ret);
    GOTO_ERR_IF(ctx->pqcMethod->verify(ctx->pqcCtx, CRYPT_MD_MAX, msg.data, msg.len, sign, pqcSigLen), ret);
    GOTO_ERR_IF(ctx->tradMethod->verify(ctx->tradCtx, ctx->info->tradHashId, msg.data, msg.len, sign + pqcSigLen,
                                              tradSigLen), ret);
ERR:
    BSL_SAL_FREE(msg.data);
    return ret;
}
#endif // PQCP_COMPOSITE_SIGN
