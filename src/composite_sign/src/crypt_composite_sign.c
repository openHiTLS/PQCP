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
#include <string.h>

#include "crypt_composite_sign_local.h"
#ifdef PQCP_AIGIS_SIG
#include "crypt_aigis_sig.h"
#endif
#include "crypt_utils.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "eal_md_local.h"

#include "pqcp_types.h"
#include "pqcp_provider.h"
#include "pqcp_err.h"

#ifdef PQCP_AIGIS_SIG
#define AIGIS_SIG_PARAM_I_PUBLIC_KEY_LEN 928
#define AIGIS_SIG_PARAM_I_PRIVATE_KEY_LEN 2800
#define AIGIS_SIG_PARAM_I_SIGNATURE_LEN 2015
#define AIGIS_SIG_PARAM_II_PUBLIC_KEY_LEN 1824
#define AIGIS_SIG_PARAM_II_PRIVATE_KEY_LEN 4976
#define AIGIS_SIG_PARAM_II_SIGNATURE_LEN 4533
#define AIGIS_SIG_PARAM_III_PUBLIC_KEY_LEN 4672
#define AIGIS_SIG_PARAM_III_PRIVATE_KEY_LEN 8800
#define AIGIS_SIG_PARAM_III_SIGNATURE_LEN 9134
#define SM2_PUBLIC_KEY_LEN 65
#define SM2_PRIVATE_KEY_LEN 32
#endif
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

#define PQC_METHOD_FREE(func) ((void (*)(void *))(func))
#define PQC_METHOD_DUP(func) ((void *(*)(const void *))(func))
#define PQC_METHOD_CTRL(func) ((int32_t(*)(void *, int32_t, void *, uint32_t))(func))
#define PQC_METHOD_GEN(func) ((int32_t(*)(void *))(func))
#define PQC_METHOD_SIGN(func)                                                                                   \
    ((int32_t(*)(void *, int32_t, const uint8_t *, uint32_t, uint8_t *, uint32_t *))(func))
#define PQC_METHOD_VERIFY(func)                                                                                 \
    ((int32_t(*)(const void *, int32_t, const uint8_t *, uint32_t, uint8_t *, uint32_t))(func))

/*
This part of codes references the composite sign IEFT DRAFT:
https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/
*/
static const uint8_t PREFIX[] = {0x43, 0x6F, 0x6D, 0x70, 0x6F, 0x73, 0x69, 0x74, 0x65, 0x41, 0x6C,
                                 0x67, 0x6F, 0x72, 0x69, 0x74, 0x68, 0x6D, 0x53, 0x69, 0x67, 0x6E,
                                 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x32, 0x30, 0x32, 0x35};

static int32_t EalPqcNewCtx(PQCP_CompositeCtx *ctx)
{
    int32_t ret;
    ctx->pqcCtx = CRYPT_EAL_PkeyNewCtx(ctx->info->pqcAlg);
    RETURN_RET_IF(ctx->pqcCtx == NULL, PQCP_MEM_ALLOC_FAIL);
    int32_t pqcParam = ctx->info->pqcParam;
    RETURN_RET_IF_ERR(CRYPT_EAL_PkeyCtrl(ctx->pqcCtx, CRYPT_CTRL_SET_PARA_BY_ID, &pqcParam, sizeof(pqcParam)), ret);
    return PQCP_SUCCESS;
}

static int32_t FixedPqcGetSigLen(PQCP_CompositeCtx *ctx, const uint8_t *sign, uint32_t signLen, uint32_t *pqcSigLen)
{
    (void)sign;
    if (signLen < ctx->info->pqcSigLen) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_INVALID_SIG_LEN);
        return PQCP_COMPOSITE_INVALID_SIG_LEN;
    }
    *pqcSigLen = ctx->info->pqcSigLen;
    return PQCP_SUCCESS;
}

const PQCP_COMPOSITE_PQC_METHOD g_compositeMldsaPqcMethod = {
    EalPqcNewCtx, PQC_METHOD_FREE(CRYPT_EAL_PkeyFreeCtx), PQC_METHOD_DUP(CRYPT_EAL_PkeyDupCtx),
    PQC_METHOD_CTRL(CRYPT_EAL_PkeyCtrl), PQC_METHOD_GEN(CRYPT_EAL_PkeyGen),
    PQC_METHOD_SIGN(CRYPT_EAL_PkeySign), PQC_METHOD_VERIFY(CRYPT_EAL_PkeyVerify), FixedPqcGetSigLen,
    PQCP_CompositeGetMldsaPrvKey, PQCP_CompositeGetMldsaPubKey, PQCP_CompositeSetMldsaPrvKey,
    PQCP_CompositeSetMldsaPubKey};

#ifdef PQCP_AIGIS_SIG
static int32_t AigisPqcNewCtx(PQCP_CompositeCtx *ctx)
{
    int32_t ret;
    ctx->pqcCtx = PQCP_AIGIS_SIG_NewCtx(ctx->libCtx);
    RETURN_RET_IF(ctx->pqcCtx == NULL, PQCP_MEM_ALLOC_FAIL);
    int32_t pqcParam = ctx->info->pqcParam;
    RETURN_RET_IF_ERR(PQCP_AIGIS_SIG_Ctrl(ctx->pqcCtx, CRYPT_CTRL_SET_PARA_BY_ID, &pqcParam, sizeof(pqcParam)), ret);
    return PQCP_SUCCESS;
}
const PQCP_COMPOSITE_PQC_METHOD g_compositeAigisPqcMethod = {
    AigisPqcNewCtx, PQC_METHOD_FREE(PQCP_AIGIS_SIG_FreeCtx), PQC_METHOD_DUP(PQCP_AIGIS_SIG_DupCtx),
    PQC_METHOD_CTRL(PQCP_AIGIS_SIG_Ctrl), PQC_METHOD_GEN(PQCP_AIGIS_SIG_GenKey),
    PQC_METHOD_SIGN(PQCP_AIGIS_SIG_Sign), PQC_METHOD_VERIFY(PQCP_AIGIS_SIG_Verify), FixedPqcGetSigLen,
    PQCP_CompositeGetAigisPrvKey, PQCP_CompositeGetAigisPubKey, PQCP_CompositeSetAigisPrvKey,
    PQCP_CompositeSetAigisPubKey};
#endif

static const PQCP_COMPOSITE_ALG_INFO g_composite_info[] = {
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
        1, // set pqc ctx info
        &g_compositeMldsaPqcMethod, // pqc method
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
        1, // set pqc ctx info
        &g_compositeMldsaPqcMethod, // pqc method
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
        1, // set pqc ctx info
        &g_compositeMldsaPqcMethod, // pqc method
    },
#ifdef PQCP_AIGIS_SIG
    {
        PQCP_COMPOSITE_AIGIS_SIG_SM3_I_SM2, // Composite algId
        "COMPSIG-AIGIS-SIG-SM3-I-SM2", // label
        PQCP_PKEY_AIGIS_SIG, // pqc algId
        PQCP_AIGIS_SIG_SM3_I, // pqc paraId
        CRYPT_PKEY_SM2, // trad algId
        0, // trad paraId
        CRYPT_MD_SM3, // composite hash Id
        CRYPT_MD_SM3, // trad hash Id
        0, // bits
        AIGIS_SIG_PARAM_I_PUBLIC_KEY_LEN + SM2_PUBLIC_KEY_LEN, // composite public key len
        AIGIS_SIG_PARAM_I_PRIVATE_KEY_LEN + SM2_PRIVATE_KEY_LEN, // composite private key len
        AIGIS_SIG_PARAM_I_PUBLIC_KEY_LEN, // pqc public key len
        AIGIS_SIG_PARAM_I_PRIVATE_KEY_LEN, // pqc private key len
        AIGIS_SIG_PARAM_I_SIGNATURE_LEN, // pqc sig len
        0, // set pqc ctx info
        &g_compositeAigisPqcMethod, // pqc method
    },
    {
        PQCP_COMPOSITE_AIGIS_SIG_SM3_II_SM2, // Composite algId
        "COMPSIG-AIGIS-SIG-SM3-II-SM2", // label
        PQCP_PKEY_AIGIS_SIG, // pqc algId
        PQCP_AIGIS_SIG_SM3_II, // pqc paraId
        CRYPT_PKEY_SM2, // trad algId
        0, // trad paraId
        CRYPT_MD_SM3, // composite hash Id
        CRYPT_MD_SM3, // trad hash Id
        0, // bits
        AIGIS_SIG_PARAM_II_PUBLIC_KEY_LEN + SM2_PUBLIC_KEY_LEN, // composite public key len
        AIGIS_SIG_PARAM_II_PRIVATE_KEY_LEN + SM2_PRIVATE_KEY_LEN, // composite private key len
        AIGIS_SIG_PARAM_II_PUBLIC_KEY_LEN, // pqc public key len
        AIGIS_SIG_PARAM_II_PRIVATE_KEY_LEN, // pqc private key len
        AIGIS_SIG_PARAM_II_SIGNATURE_LEN, // pqc sig len
        0, // set pqc ctx info
        &g_compositeAigisPqcMethod, // pqc method
    },
    {
        PQCP_COMPOSITE_AIGIS_SIG_SM3_III_SM2, // Composite algId
        "COMPSIG-AIGIS-SIG-SM3-III-SM2", // label
        PQCP_PKEY_AIGIS_SIG, // pqc algId
        PQCP_AIGIS_SIG_SM3_III, // pqc paraId
        CRYPT_PKEY_SM2, // trad algId
        0, // trad paraId
        CRYPT_MD_SM3, // composite hash Id
        CRYPT_MD_SM3, // trad hash Id
        0, // bits
        AIGIS_SIG_PARAM_III_PUBLIC_KEY_LEN + SM2_PUBLIC_KEY_LEN, // composite public key len
        AIGIS_SIG_PARAM_III_PRIVATE_KEY_LEN + SM2_PRIVATE_KEY_LEN, // composite private key len
        AIGIS_SIG_PARAM_III_PUBLIC_KEY_LEN, // pqc public key len
        AIGIS_SIG_PARAM_III_PRIVATE_KEY_LEN, // pqc private key len
        AIGIS_SIG_PARAM_III_SIGNATURE_LEN, // pqc sig len
        0, // set pqc ctx info
        &g_compositeAigisPqcMethod, // pqc method
    },
    {
        PQCP_COMPOSITE_AIGIS_SIG_SHA3_I_SM2, // Composite algId
        "COMPSIG-AIGIS-SIG-SHA3-I-SM2", // label
        PQCP_PKEY_AIGIS_SIG, // pqc algId
        PQCP_AIGIS_SIG_SHA3_I, // pqc paraId
        CRYPT_PKEY_SM2, // trad algId
        0, // trad paraId
        CRYPT_MD_SHA3_256, // composite hash Id
        CRYPT_MD_SM3, // trad hash Id
        0, // bits
        AIGIS_SIG_PARAM_I_PUBLIC_KEY_LEN + SM2_PUBLIC_KEY_LEN, // composite public key len
        AIGIS_SIG_PARAM_I_PRIVATE_KEY_LEN + SM2_PRIVATE_KEY_LEN, // composite private key len
        AIGIS_SIG_PARAM_I_PUBLIC_KEY_LEN, // pqc public key len
        AIGIS_SIG_PARAM_I_PRIVATE_KEY_LEN, // pqc private key len
        AIGIS_SIG_PARAM_I_SIGNATURE_LEN, // pqc sig len
        0, // set pqc ctx info
        &g_compositeAigisPqcMethod, // pqc method
    },
    {
        PQCP_COMPOSITE_AIGIS_SIG_SHA3_II_SM2, // Composite algId
        "COMPSIG-AIGIS-SIG-SHA3-II-SM2", // label
        PQCP_PKEY_AIGIS_SIG, // pqc algId
        PQCP_AIGIS_SIG_SHA3_II, // pqc paraId
        CRYPT_PKEY_SM2, // trad algId
        0, // trad paraId
        CRYPT_MD_SHA3_256, // composite hash Id
        CRYPT_MD_SM3, // trad hash Id
        0, // bits
        AIGIS_SIG_PARAM_II_PUBLIC_KEY_LEN + SM2_PUBLIC_KEY_LEN, // composite public key len
        AIGIS_SIG_PARAM_II_PRIVATE_KEY_LEN + SM2_PRIVATE_KEY_LEN, // composite private key len
        AIGIS_SIG_PARAM_II_PUBLIC_KEY_LEN, // pqc public key len
        AIGIS_SIG_PARAM_II_PRIVATE_KEY_LEN, // pqc private key len
        AIGIS_SIG_PARAM_II_SIGNATURE_LEN, // pqc sig len
        0, // set pqc ctx info
        &g_compositeAigisPqcMethod, // pqc method
    },
    {
        PQCP_COMPOSITE_AIGIS_SIG_SHA3_III_SM2, // Composite algId
        "COMPSIG-AIGIS-SIG-SHA3-III-SM2", // label
        PQCP_PKEY_AIGIS_SIG, // pqc algId
        PQCP_AIGIS_SIG_SHA3_III, // pqc paraId
        CRYPT_PKEY_SM2, // trad algId
        0, // trad paraId
        CRYPT_MD_SHA3_512, // composite hash Id
        CRYPT_MD_SM3, // trad hash Id
        0, // bits
        AIGIS_SIG_PARAM_III_PUBLIC_KEY_LEN + SM2_PUBLIC_KEY_LEN, // composite public key len
        AIGIS_SIG_PARAM_III_PRIVATE_KEY_LEN + SM2_PRIVATE_KEY_LEN, // composite private key len
        AIGIS_SIG_PARAM_III_PUBLIC_KEY_LEN, // pqc public key len
        AIGIS_SIG_PARAM_III_PRIVATE_KEY_LEN, // pqc private key len
        AIGIS_SIG_PARAM_III_SIGNATURE_LEN, // pqc sig len
        0, // set pqc ctx info
        &g_compositeAigisPqcMethod, // pqc method
    }
#endif
};

const PQCP_COMPOSITE_ALG_INFO *PQCP_COMPOSITE_GetInfo(int32_t paramId)
{
    const PQCP_COMPOSITE_ALG_INFO *info = NULL;
    for (size_t i = 0; i < sizeof(g_composite_info) / sizeof(g_composite_info[0]); i++) {
        if (g_composite_info[i].paramId == paramId) {
            info = &g_composite_info[i];
            return info;
        }
    }
    return NULL;
}

static int32_t CompositeSetPqcCtxInfo(PQCP_CompositeCtx *ctx)
{
    if (!ctx->info->isSetPqcCtxInfo) {
        return PQCP_SUCCESS;
    }
    return ctx->info->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctx->info->label,
        (uint32_t)strlen(ctx->info->label));
}

PQCP_CompositeCtx *PQCP_COMPOSITE_NewCtx(void *libCtx)
{
    PQCP_CompositeCtx *ctx = BSL_SAL_Calloc(1, sizeof(PQCP_CompositeCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_MEM_ALLOC_FAIL);
        return NULL;
    }
    BSL_SAL_ReferencesInit(&(ctx->references));
    ctx->libCtx = libCtx;
    return ctx;
}

void PQCP_COMPOSITE_FreeCtx(PQCP_CompositeCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    int ref = 0;
    BSL_SAL_AtomicDownReferences(&(ctx->references), &ref);
    if (ref > 0) {
        return;
    }
    if (ctx->info != NULL && ctx->info->pqcMethod != NULL) {
        ctx->info->pqcMethod->freeCtx(ctx->pqcCtx);
        ctx->pqcCtx = NULL;
    }
    CRYPT_EAL_PkeyFreeCtx(ctx->tradCtx);
    BSL_SAL_FREE(ctx->ctxInfo);
    BSL_SAL_ReferencesFree(&(ctx->references));
    BSL_SAL_FREE(ctx);
}

PQCP_CompositeCtx *PQCP_COMPOSITE_DupCtx(PQCP_CompositeCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return NULL;
    }
    PQCP_CompositeCtx *newCtx = PQCP_COMPOSITE_NewCtx(ctx->libCtx);
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_MEM_ALLOC_FAIL);
        return NULL;
    }
    newCtx->info = ctx->info;
    if (ctx->pqcCtx != NULL || ctx->tradCtx != NULL) {
        if (newCtx->info == NULL || newCtx->info->pqcMethod == NULL) {
            BSL_ERR_PUSH_ERROR(PQCP_NOT_SUPPORT);
            goto ERR;
        }
        newCtx->pqcCtx = newCtx->info->pqcMethod->dupCtx(ctx->pqcCtx);
        if (newCtx->pqcCtx == NULL) {
            BSL_ERR_PUSH_ERROR(PQCP_MEM_ALLOC_FAIL);
            goto ERR;
        }
        newCtx->tradCtx = CRYPT_EAL_PkeyDupCtx(ctx->tradCtx);
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
    return newCtx;
ERR:
    PQCP_COMPOSITE_FreeCtx(newCtx);
    return NULL;
}

static int32_t GetSignLen(PQCP_CompositeCtx *ctx, void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    if (len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(PQCP_INVALID_ARG);
        return PQCP_INVALID_ARG;
    }
    if (ctx->info == NULL || ctx->pqcCtx == NULL || ctx->tradCtx == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_KEYINFO_NOT_SET);
        return PQCP_COMPOSITE_KEYINFO_NOT_SET;
    }
    uint32_t pqcSigLen = ctx->info->pqcSigLen;
    uint32_t tradSigLen = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx->tradCtx, CRYPT_CTRL_GET_SIGNLEN, &tradSigLen, sizeof(tradSigLen));
    if (ret != PQCP_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *(int32_t *)val = pqcSigLen + tradSigLen;
    return PQCP_SUCCESS;
}

static int32_t SetAlgInfo(PQCP_CompositeCtx *ctx, void *val, uint32_t len)
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
    ctx->info = PQCP_COMPOSITE_GetInfo(*(int32_t *)val);
    if (ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_INVALID_ARG);
        return PQCP_INVALID_ARG;
    }
    GOTO_ERR_IF(ctx->info->pqcMethod->newCtx(ctx), ret);
    ctx->tradCtx = CRYPT_EAL_PkeyNewCtx(ctx->info->tradAlg);
    GOTO_ERR_IF_TRUE((ctx->tradCtx == NULL), PQCP_MEM_ALLOC_FAIL);
    if (ctx->info->tradParam != 0) {
        int32_t tradParam = ctx->info->tradParam;
        GOTO_ERR_IF(CRYPT_EAL_PkeyCtrl(ctx->tradCtx, CRYPT_CTRL_SET_PARA_BY_ID, &tradParam, sizeof(tradParam)), ret);
    }
    return PQCP_SUCCESS;
ERR:
    if (ctx->info != NULL && ctx->info->pqcMethod != NULL) {
        ctx->info->pqcMethod->freeCtx(ctx->pqcCtx);
        ctx->pqcCtx = NULL;
    }
    if (ctx->tradCtx != NULL) {
        CRYPT_EAL_PkeyFreeCtx(ctx->tradCtx);
        ctx->tradCtx = NULL;
    }
    ctx->info = NULL;
    return ret;
}

static int32_t SetCtxInfo(PQCP_CompositeCtx *ctx, void *val, uint32_t len)
{
    if (len > 0 && val == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    if (len > COMPOSITE_MAX_CTX_BYTES) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_KEYLEN_ERROR);
        return PQCP_COMPOSITE_KEYLEN_ERROR;
    }
    if (val == NULL && len == 0) {
        if (ctx->ctxInfo != NULL) {
            BSL_SAL_FREE(ctx->ctxInfo);
            ctx->ctxInfo = NULL;
            ctx->ctxLen = 0;
        }
        return PQCP_SUCCESS;
    }
    uint8_t *newCtxInfo = BSL_SAL_Dump((uint8_t *)val, len);
    if (newCtxInfo == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_MEM_ALLOC_FAIL);
        return PQCP_MEM_ALLOC_FAIL;
    }
    BSL_SAL_FREE(ctx->ctxInfo);
    ctx->ctxInfo = newCtxInfo;
    ctx->ctxLen = len;
    return PQCP_SUCCESS;
}

static int32_t GetPubKeyLen(PQCP_CompositeCtx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(val == NULL || len != sizeof(uint32_t), PQCP_INVALID_ARG);
    RETURN_RET_IF(ctx->info == NULL, PQCP_COMPOSITE_KEYINFO_NOT_SET);
    *(uint32_t *)val = ctx->info->compPubKeyLen;
    return PQCP_SUCCESS;
}

static int32_t GetPrvKeyLen(PQCP_CompositeCtx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(val == NULL || len != sizeof(uint32_t), PQCP_INVALID_ARG);
    RETURN_RET_IF(ctx->info == NULL, PQCP_COMPOSITE_KEYINFO_NOT_SET);
    *(uint32_t *)val = ctx->info->compPrvKeyLen;
    return PQCP_SUCCESS;
}

static int32_t GetPqcSignLen(PQCP_CompositeCtx *ctx, void *val, uint32_t len)
{
    CHECK_UINT32_LEN_AND_INFO(ctx, val, len);
    *(uint32_t *)val = ctx->info->pqcSigLen;
    return PQCP_SUCCESS;
}

int32_t PQCP_COMPOSITE_Ctrl(PQCP_CompositeCtx *ctx, int32_t opt, void *val, uint32_t len)
{
    RETURN_RET_IF(ctx == NULL, PQCP_NULL_INPUT);
    switch (opt) {
        case CRYPT_CTRL_SET_PARA_BY_ID:
            return SetAlgInfo(ctx, val, len);
        case CRYPT_CTRL_GET_SIGNLEN:
            return GetSignLen(ctx, val, len);
        case CRYPT_CTRL_GET_PUBKEY_LEN:
            return GetPubKeyLen(ctx, val, len);
        case CRYPT_CTRL_GET_PRVKEY_LEN:
            return GetPrvKeyLen(ctx, val, len);
        case CRYPT_CTRL_SET_CTX_INFO:
            return SetCtxInfo(ctx, val, len);
        case PQCP_CTRL_HYBRID_GET_PQC_PRVKEY_LEN:
            CHECK_UINT32_LEN_AND_INFO(ctx, val, len);
            *(uint32_t *)val = ctx->info->pqcPrvkeyLen;
            return PQCP_SUCCESS;
        case PQCP_CTRL_HYBRID_GET_PQC_PUBKEY_LEN:
            CHECK_UINT32_LEN_AND_INFO(ctx, val, len);
            return ctx->info->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_GET_PUBKEY_LEN, val, len);
        case PQCP_CTRL_HYBRID_GET_TRAD_PRVKEY_LEN:
            CHECK_UINT32_LEN_AND_INFO(ctx, val, len);
            return CRYPT_EAL_PkeyCtrl(ctx->tradCtx, CRYPT_CTRL_GET_PRVKEY_LEN, val, len);
        case PQCP_CTRL_HYBRID_GET_TRAD_PUBKEY_LEN:
            CHECK_UINT32_LEN_AND_INFO(ctx, val, len);
            return CRYPT_EAL_PkeyCtrl(ctx->tradCtx, CRYPT_CTRL_GET_PUBKEY_LEN, val, len);
        case PQCP_CTRL_HYBRID_GET_PQC_SIGNLEN:
            return GetPqcSignLen(ctx, val, len);
        case PQCP_CTRL_HYBRID_GET_TRAD_SIGNLEN:
            CHECK_UINT32_LEN_AND_INFO(ctx, val, len);
            return CRYPT_EAL_PkeyCtrl(ctx->tradCtx, CRYPT_CTRL_GET_SIGNLEN, val, len);
        default:
            BSL_ERR_PUSH_ERROR(PQCP_NOT_SUPPORT);
            return PQCP_NOT_SUPPORT;
    }
}

int32_t PQCP_COMPOSITE_GenKey(PQCP_CompositeCtx *ctx)
{
    int32_t ret;
    RETURN_RET_IF(ctx == NULL, PQCP_NULL_INPUT);
    RETURN_RET_IF((ctx->pqcCtx == NULL || ctx->tradCtx == NULL), PQCP_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF_ERR(ctx->info->pqcMethod->gen(ctx->pqcCtx), ret);
    RETURN_RET_IF_ERR(CRYPT_EAL_PkeyGen(ctx->tradCtx), ret);
    return ret;
}

int32_t PQCP_COMPOSITE_GetPrvKey(const PQCP_CompositeCtx *ctx, CRYPT_CompositePrv *prv)
{
    RETURN_RET_IF((ctx == NULL || prv == NULL || prv->data == NULL), PQCP_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, PQCP_COMPOSITE_KEYINFO_NOT_SET);
    int32_t ret;
    BSL_Buffer pqcPrv = { 0 };
    BSL_Buffer tradPrv = { 0 };
    GOTO_ERR_IF(ctx->info->pqcMethod->getPrv(ctx, &pqcPrv), ret);
    GOTO_ERR_IF(PQCP_CompositeGetTradPrvKey(ctx, &tradPrv), ret);
    if (prv->len < pqcPrv.dataLen + tradPrv.dataLen) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_LEN_NOT_ENOUGH);
        ret = PQCP_COMPOSITE_LEN_NOT_ENOUGH;
        goto ERR;
    }
    memcpy(prv->data, pqcPrv.data, pqcPrv.dataLen);
    memcpy(prv->data + pqcPrv.dataLen, tradPrv.data, tradPrv.dataLen);
    prv->len = pqcPrv.dataLen + tradPrv.dataLen;
ERR:
    BSL_SAL_ClearFree(pqcPrv.data, pqcPrv.dataLen);
    BSL_SAL_ClearFree(tradPrv.data, tradPrv.dataLen);
    return ret;
}

int32_t PQCP_COMPOSITE_GetPubKey(const PQCP_CompositeCtx *ctx, CRYPT_CompositePub *pub)
{
    RETURN_RET_IF((ctx == NULL || pub == NULL || pub->data == NULL), PQCP_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, PQCP_COMPOSITE_KEYINFO_NOT_SET);
    int32_t ret;
    BSL_Buffer pqcPub = { 0 };
    BSL_Buffer tradPub = { 0 };
    GOTO_ERR_IF(ctx->info->pqcMethod->getPub(ctx, &pqcPub), ret);
    GOTO_ERR_IF(PQCP_CompositeGetTradPubKey(ctx, &tradPub), ret);
    if (pub->len < pqcPub.dataLen + tradPub.dataLen) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_LEN_NOT_ENOUGH);
        ret = PQCP_COMPOSITE_LEN_NOT_ENOUGH;
        goto ERR;
    }
    memcpy(pub->data, pqcPub.data, pqcPub.dataLen);
    memcpy(pub->data + pqcPub.dataLen, tradPub.data, tradPub.dataLen);
    pub->len = pqcPub.dataLen + tradPub.dataLen;
ERR:
    BSL_SAL_FREE(pqcPub.data);
    BSL_SAL_FREE(tradPub.data);
    return ret;
}

int32_t PQCP_COMPOSITE_SetPrvKey(PQCP_CompositeCtx *ctx, const CRYPT_CompositePrv *prv)
{
    int32_t ret;
    RETURN_RET_IF((ctx == NULL || prv == NULL || prv->data == NULL), PQCP_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, PQCP_COMPOSITE_KEYINFO_NOT_SET);
    // The prvkey len of trad is not determined, so only verify it is longer than the PQC private key part.
    RETURN_RET_IF(prv->len <= ctx->info->pqcPrvkeyLen, PQCP_COMPOSITE_KEYLEN_ERROR);
    BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
    BSL_Buffer tradPrv = {prv->data + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen};
    RETURN_RET_IF_ERR(ctx->info->pqcMethod->setPrv(ctx, &pqcPrv), ret);
    RETURN_RET_IF_ERR(PQCP_CompositeSetTradPrvKey(ctx, &tradPrv), ret);
    return PQCP_SUCCESS;
}

int32_t PQCP_COMPOSITE_SetPubKey(PQCP_CompositeCtx *ctx, const CRYPT_CompositePub *pub)
{
    int32_t ret;
    RETURN_RET_IF((ctx == NULL || pub == NULL || pub->data == NULL), PQCP_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, PQCP_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(pub->len < ctx->info->compPubKeyLen, PQCP_COMPOSITE_KEYLEN_ERROR);

    BSL_Buffer pqcPub = {pub->data, ctx->info->pqcPubkeyLen};
    BSL_Buffer tradPub = {pub->data + ctx->info->pqcPubkeyLen, pub->len - ctx->info->pqcPubkeyLen};
    RETURN_RET_IF_ERR(ctx->info->pqcMethod->setPub(ctx, &pqcPub), ret);
    RETURN_RET_IF_ERR(PQCP_CompositeSetTradPubKey(ctx, &tradPub), ret);
    return PQCP_SUCCESS;
}

int32_t PQCP_COMPOSITE_GetPrvKeyEx(const PQCP_CompositeCtx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    CRYPT_CompositePrv prv = {0};
    BSL_Param *paramPrv = GetParamValue(para, PQCP_PARAM_COMPOSITE_PRVKEY, &prv.data, &(prv.len));
    int32_t ret = PQCP_COMPOSITE_GetPrvKey(ctx, &prv);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    paramPrv->useLen = prv.len;
    return PQCP_SUCCESS;
}

int32_t PQCP_COMPOSITE_GetPubKeyEx(const PQCP_CompositeCtx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    CRYPT_CompositePub pub = {0};
    BSL_Param *paramPub = GetParamValue(para, PQCP_PARAM_COMPOSITE_PUBKEY, &pub.data, &(pub.len));
    int32_t ret = PQCP_COMPOSITE_GetPubKey(ctx, &pub);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    paramPub->useLen = pub.len;
    return PQCP_SUCCESS;
}

int32_t PQCP_COMPOSITE_SetPrvKeyEx(PQCP_CompositeCtx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    CRYPT_CompositePrv prv = {0};
    (void)GetConstParamValue(para, PQCP_PARAM_COMPOSITE_PRVKEY, &prv.data, &prv.len);
    return PQCP_COMPOSITE_SetPrvKey(ctx, &prv);
}

int32_t PQCP_COMPOSITE_SetPubKeyEx(PQCP_CompositeCtx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    CRYPT_CompositePub pub = {0};
    (void)GetConstParamValue(para, PQCP_PARAM_COMPOSITE_PUBKEY, &pub.data, &pub.len);
    return PQCP_COMPOSITE_SetPubKey(ctx, &pub);
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

static int32_t CompositeMsgEncode(PQCP_CompositeCtx *ctx, int32_t hashId, const uint8_t *data, uint32_t dataLen,
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
    memcpy(ptr, PREFIX, prefixLen);
    ptr += prefixLen;
    memcpy(ptr, label, labelLen);
    ptr += labelLen;
    *ptr = ctx->ctxLen;
    ptr++;
    if (ctx->ctxInfo != NULL && ctx->ctxLen > 0) {
        memcpy(ptr, ctx->ctxInfo, ctx->ctxLen);
        ptr += ctx->ctxLen;
    }
    memcpy(ptr, digest, digestLen);
    return PQCP_SUCCESS;
}

int32_t PQCP_COMPOSITE_Sign(PQCP_CompositeCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
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
    CRYPT_Data msg = {0};
    RETURN_RET_IF_ERR(CompositeMsgEncode(ctx, ctx->info->hashId, data, dataLen, &msg), ret);
    GOTO_ERR_IF(CompositeSetPqcCtxInfo(ctx), ret);
    uint8_t *pqcSig = sign;
    int32_t pqcRet = ctx->info->pqcMethod->sign(ctx->pqcCtx, CRYPT_MD_MAX, msg.data, msg.len, pqcSig, &pqcSigLen);
    uint32_t tradSigLen = *signLen - pqcSigLen;
    uint8_t *tradSig = pqcSig + pqcSigLen;
    int32_t tradRet = CRYPT_EAL_PkeySign(ctx->tradCtx, ctx->info->tradHashId, msg.data, msg.len, tradSig,
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

int32_t PQCP_COMPOSITE_Verify(PQCP_CompositeCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
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
    int32_t ret;
    uint32_t pqcSigLen = 0;
    CRYPT_Data msg = {0};
    GOTO_ERR_IF(ctx->info->pqcMethod->getSigLen(ctx, sign, signLen, &pqcSigLen), ret);
    uint8_t *pqcSig = sign;
    uint32_t tradSigLen = signLen - pqcSigLen;
    uint8_t *tradSig = pqcSig + pqcSigLen;
    RETURN_RET_IF_ERR(CompositeMsgEncode(ctx, ctx->info->hashId, data, dataLen, &msg), ret);
    GOTO_ERR_IF(CompositeSetPqcCtxInfo(ctx), ret);
    GOTO_ERR_IF(ctx->info->pqcMethod->verify(ctx->pqcCtx, CRYPT_MD_MAX, msg.data, msg.len, pqcSig, pqcSigLen), ret);
    GOTO_ERR_IF(CRYPT_EAL_PkeyVerify(ctx->tradCtx, ctx->info->tradHashId, msg.data, msg.len, tradSig, tradSigLen), ret);
ERR:
    BSL_SAL_FREE(msg.data);
    return ret;
}
#endif // PQCP_COMPOSITE_SIGN
