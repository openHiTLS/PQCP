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
#ifdef PQCP_POLARLAC
#include "polarlac_local.h"
#include "bsl_sal.h"
#include "securec.h"
#include "pqcp_err.h"
#include "crypt_polarlac.h"
#include "crypt_types.h"


#define CHECK_CTX_INFO_AND_UINT32_LEN(ctx, len)    \
    do                                             \
    {                                              \
        if (ctx->info == NULL)                     \
        {                                          \
            return PQCP_POLAR_LAC_KEYINFO_NOT_SET; \
        }                                          \
        if (len != sizeof(int32_t))                \
        {                                          \
            return PQCP_INVALID_ARG;               \
        }                                          \
    } while (0)

static const CRYPT_Lac2Info g_polarLacParams[] = {
    // LAC_LIGHT
    {.dimN = 512,
     .seedLen = 32,
     .msgLen = 16,
     .c2VecNum = 256,
     .numOne = 128,
     .sampleLen = 590,
     .skLen = 512 + 544,
     .pkLen = 544,
     .ctLen = 576,
     .sharedLen = 32,
     .bits = 8,
     .secBits = 128},

    // LAC128
    {.dimN = 512,
     .seedLen = 32,
     .msgLen = 16,
     .c2VecNum = 512,
     .numOne = 128,
     .sampleLen = 590,
     .skLen = 512 + 544,
     .pkLen = 544,
     .ctLen = 640,
     .sharedLen = 32,
     .bits = 8,
     .secBits = 128},

    // LAC256
    {.dimN = 1024,
     .seedLen = 32,
     .msgLen = 32,
     .c2VecNum = 512,
     .numOne = 192,
     .sampleLen = 815,
     .skLen = 1024 + 1056,
     .pkLen = 1056,
     .ctLen = 1280,
     .sharedLen = 32,
     .bits = 8,
     .secBits = 256}};

static const CRYPT_Lac2Info *PolarLacGetInfo(uint32_t algId)
{
    uint32_t offset = algId - PQCP_POLAR_LAC_LIGHT;
    if (offset >= sizeof(g_polarLacParams) / sizeof(g_polarLacParams[0])) {
        return NULL;
    }
    return &g_polarLacParams[offset];
}

void *PQCP_LAC2_NewCtx()
{
    CRYPT_POLAR_LAC_Ctx *ctx = BSL_SAL_Malloc(sizeof(CRYPT_POLAR_LAC_Ctx));
    if (ctx == NULL) {
        return NULL;
    }
    (void)memset_s(ctx, sizeof(CRYPT_POLAR_LAC_Ctx), 0, sizeof(CRYPT_POLAR_LAC_Ctx));
    return ctx;
}

void PQCP_LAC2_FreeCtx(CRYPT_POLAR_LAC_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->info != NULL) {
        BSL_SAL_CleanseData(ctx->sk, ctx->info->skLen);
        BSL_SAL_FREE(ctx->sk);
        BSL_SAL_FREE(ctx->pk);
    }
    BSL_SAL_FREE(ctx);
}

static int32_t PolarLacSetAlgInfo(CRYPT_POLAR_LAC_Ctx *ctx, void *val, uint32_t len)
{
    if (len != sizeof(int32_t)) {
        return PQCP_INVALID_ARG;
    }
    if (ctx->info != NULL) {
        return PQCP_POLAR_LAC_PARA_REPEATED_SET;
    }
    int32_t algId = *(int32_t *)val;
    const CRYPT_Lac2Info *info = PolarLacGetInfo(algId);
    if (info == NULL) {
        return PQCP_INVALID_ARG;
    }
    ctx->algId = algId;
    ctx->info = info;
    return PQCP_SUCCESS;
}

int32_t PQCP_LAC2_SetPrvKey(CRYPT_POLAR_LAC_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || ctx->info == NULL || param == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->sk != NULL || ctx->pk != NULL) {
        return PQCP_POLAR_LAC_KEY_REPEATED_SET;
    }
    const BSL_Param *prv = BSL_PARAM_FindConstParam(param, PQCP_PARAM_POLAR_LAC_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->info->skLen > prv->valueLen) {
        return PQCP_INVALID_ARG;
    }
    ctx->sk = BSL_SAL_Malloc(ctx->info->skLen);
    ctx->pk = BSL_SAL_Malloc(ctx->info->pkLen);
    if (ctx->sk == NULL || ctx->pk == NULL) {
        BSL_SAL_FREE(ctx->sk);
        BSL_SAL_FREE(ctx->pk);
        return PQCP_MEM_ALLOC_FAIL;
    }
    uint32_t useLen = ctx->info->skLen;
    (void)memcpy_s(ctx->sk, useLen, prv->value, useLen);
    (void)memcpy_s(ctx->pk, ctx->info->pkLen, ctx->sk + ctx->info->skLen - ctx->info->pkLen, ctx->info->pkLen);
    return PQCP_SUCCESS;
}

int32_t PQCP_LAC2_SetPubKey(CRYPT_POLAR_LAC_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || ctx->info == NULL || param == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->sk != NULL || ctx->pk != NULL) {
        return PQCP_POLAR_LAC_KEY_REPEATED_SET;
    }
    const BSL_Param *pub = BSL_PARAM_FindConstParam(param, PQCP_PARAM_POLAR_LAC_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->info->pkLen > pub->valueLen) {
        return PQCP_INVALID_ARG;
    }
    ctx->pk = BSL_SAL_Malloc(ctx->info->pkLen);
    if (ctx->pk == NULL) {
        return PQCP_MEM_ALLOC_FAIL;
    }
    uint32_t useLen = ctx->info->pkLen;
    (void)memcpy_s(ctx->pk, useLen, pub->value, useLen);
    return PQCP_SUCCESS;
}

int32_t PQCP_LAC2_EncapsInit(CRYPT_POLAR_LAC_Ctx *ctx, const BSL_Param *params)
{
    (void)ctx;
    (void)params;
    return 0;
}

int32_t PQCP_LAC2_DecapsInit(CRYPT_POLAR_LAC_Ctx *ctx, const BSL_Param *params)
{
    (void)ctx;
    (void)params;
    return 0;
}
static int32_t EncapsInputCheck(CRYPT_POLAR_LAC_Ctx *ctx, uint8_t *ciphertext, uint32_t *ctLen, uint8_t *sharedSecret,
                                uint32_t *ssLen)
{
    bool nullInput =
        ctx == NULL || ctx->pk == NULL || ciphertext == NULL || ctLen == NULL || sharedSecret == NULL || ssLen == NULL;
    if (nullInput == true) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        return PQCP_POLAR_LAC_KEYINFO_NOT_SET;
    }
    if (*ctLen < ctx->info->ctLen || *ssLen < ctx->info->sharedLen) {
        return PQCP_POLAR_LAC_LEN_NOT_ENOUGH;
    }
    return PQCP_SUCCESS;
}
int32_t PQCP_LAC2_Encaps(CRYPT_POLAR_LAC_Ctx *ctx, uint8_t *ciphertext, uint32_t *ctLen, uint8_t *sharedSecret,
                         uint32_t *ssLen)
{
    int32_t ret = EncapsInputCheck(ctx, ciphertext, ctLen, sharedSecret, ssLen);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    *ssLen = ctx->info->sharedLen;
    *ctLen = ctx->info->ctLen;
    return PQCP_POLAR_LAC_EncapsInternal(ctx, ciphertext, sharedSecret);
}
static int32_t DecapsInputCheck(CRYPT_POLAR_LAC_Ctx *ctx, const uint8_t *ciphertext, uint32_t ctLen,
                                uint8_t *sharedSecret, uint32_t *ssLen)
{
    bool nullInput = ctx == NULL || ctx->sk == NULL || ciphertext == NULL || sharedSecret == NULL || ssLen == NULL;
    if (nullInput == true) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        return PQCP_POLAR_LAC_KEYINFO_NOT_SET;
    }
    if (ctLen != ctx->info->ctLen || *ssLen < ctx->info->sharedLen) {
        return PQCP_POLAR_LAC_LEN_NOT_ENOUGH;
    }
    return PQCP_SUCCESS;
}

int32_t PQCP_LAC2_Decaps(CRYPT_POLAR_LAC_Ctx *ctx, const uint8_t *ciphertext, uint32_t ctLen, uint8_t *sharedSecret,
                         uint32_t *ssLen)
{
    int32_t ret = DecapsInputCheck(ctx, ciphertext, ctLen, sharedSecret, ssLen);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    if (ctLen != ctx->info->ctLen) {
        return PQCP_INVALID_ARG;
    }
    *ssLen = ctx->info->sharedLen;
    return PQCP_POLAR_LAC_DeapsInternal(ctx, sharedSecret, ciphertext);
}

int32_t PQCP_LAC2_Gen(CRYPT_POLAR_LAC_Ctx *ctx)
{
    if (ctx == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        return PQCP_POLAR_LAC_KEYINFO_NOT_SET;
    }
    if (ctx->pk == NULL) {
        ctx->pk = BSL_SAL_Malloc(ctx->info->pkLen);
    }
    if (ctx->sk == NULL) {
        ctx->sk = BSL_SAL_Malloc(ctx->info->skLen);
    }
    if (ctx->pk == NULL || ctx->sk == NULL) {
        BSL_SAL_FREE(ctx->pk);
        BSL_SAL_FREE(ctx->sk);
        return PQCP_MEM_ALLOC_FAIL;
    }
    return PQCP_POLAR_LAC_KeyGenInternal(ctx);
}

int32_t PQCP_LAC2_Ctrl(CRYPT_POLAR_LAC_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL || val == NULL) {
        return PQCP_NULL_INPUT;
    }
    switch (cmd) {
        case CRYPT_CTRL_SET_PARA_BY_ID:
            return PolarLacSetAlgInfo(ctx, val, valLen);
        case CRYPT_CTRL_GET_CIPHERTEXT_LEN:
            CHECK_CTX_INFO_AND_UINT32_LEN(ctx, valLen);
            *(int32_t *)val = ctx->info->ctLen;
            break;
        case CRYPT_CTRL_GET_PRVKEY_LEN:
            CHECK_CTX_INFO_AND_UINT32_LEN(ctx, valLen);
            *(int32_t *)val = ctx->info->skLen;
            break;
        case CRYPT_CTRL_GET_PUBKEY_LEN:
            CHECK_CTX_INFO_AND_UINT32_LEN(ctx, valLen);
            *(int32_t *)val = ctx->info->pkLen;
            break;
        default:
            return PQCP_INVALID_ARG;
            break;
    }
    return PQCP_SUCCESS;
}

CRYPT_POLAR_LAC_Ctx *PQCP_LAC2_DupCtx(CRYPT_POLAR_LAC_Ctx *srcCtx)
{
    if (srcCtx == NULL) {
        return NULL;
    }
    CRYPT_POLAR_LAC_Ctx *ctx = PQCP_LAC2_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    if (srcCtx->info != NULL) {
        ctx->algId = srcCtx->algId;
        ctx->info = srcCtx->info;
    }
    if (srcCtx->sk != NULL) {
        ctx->sk = BSL_SAL_Malloc(ctx->info->skLen);
        if (ctx->sk == NULL) {
            PQCP_LAC2_FreeCtx(ctx);
            return NULL;
        }
        memcpy_s(ctx->sk, ctx->info->skLen, srcCtx->sk, srcCtx->info->skLen);
    }
    if (srcCtx->pk != NULL) {
        ctx->pk = BSL_SAL_Malloc(ctx->info->pkLen);
        if (ctx->pk == NULL) {
            BSL_SAL_FREE(ctx->sk);
            PQCP_LAC2_FreeCtx(ctx);
            return NULL;
        }
        memcpy_s(ctx->pk, ctx->info->pkLen, srcCtx->pk, srcCtx->info->pkLen);
    }
    return ctx;
}

int32_t PQCP_LAC2_GetPrvKey(CRYPT_POLAR_LAC_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || ctx->info == NULL || param == NULL || ctx->sk == NULL) {
        return PQCP_NULL_INPUT;
    }
    BSL_Param *prv = BSL_PARAM_FindParam(param, PQCP_PARAM_POLAR_LAC_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->info->skLen > prv->valueLen) {
        return PQCP_POLAR_LAC_LEN_NOT_ENOUGH;
    }
    memcpy_s(prv->value, prv->valueLen, ctx->sk, ctx->info->skLen);
    prv->useLen = ctx->info->skLen;
    return PQCP_SUCCESS;
}

int32_t PQCP_LAC2_GetPubKey(CRYPT_POLAR_LAC_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || ctx->info == NULL || param == NULL || ctx->pk == NULL) {
        return PQCP_NULL_INPUT;
    }
    BSL_Param *pub = BSL_PARAM_FindParam(param, PQCP_PARAM_POLAR_LAC_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->info->pkLen > pub->valueLen) {
        return PQCP_POLAR_LAC_LEN_NOT_ENOUGH;
    }
    memcpy_s(pub->value, pub->valueLen, ctx->pk, ctx->info->pkLen);
    pub->useLen = ctx->info->pkLen;
    return PQCP_SUCCESS;
}
#endif // PQCP_POLARLAC
