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

#ifdef PQCP_NEV

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(PQCP_NEV_NEON_DISPATCH_ASM) && !defined(HITLS_CRYPTO_NEV_SVE2) && defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif

#include "bsl_sal.h"
#include "crypt_eal_rand.h"
#include "crypt_nev.h"
#include "crypt_types.h"
#include "nev_local.h"
#include "pqcp_err.h"
#include "pqcp_types.h"

struct CryptNevCtx {
    int32_t algId;
    const CRYPT_NevInfo *info;
    uint8_t *sk;
    uint8_t *pk;
    uint8_t pkHash[NEV_SEED_MAX];
    uint8_t pkHashSet;
    NEV_Poly hPoly;
    NEV_Poly sPoly;
    uint8_t hPolySet;
    uint8_t sPolySet;
};

int32_t pqcp_nev_c_engine_keygen(const CRYPT_NevInfo *info, uint8_t *pk, uint8_t *sk,
    const uint8_t *entropy, NEV_Poly *hCache, NEV_Poly *sCache);
int32_t pqcp_nev_c_engine_encaps(const CRYPT_NevInfo *info, uint8_t *ct, uint8_t *ss,
    const uint8_t *pk, const uint8_t *pkHash, const NEV_Poly *hCache,
    const uint8_t *message);
int32_t pqcp_nev_c_engine_decaps(const CRYPT_NevInfo *info, uint8_t *ss, const uint8_t *ct,
    const uint8_t *sk, const NEV_Poly *hCache, const NEV_Poly *sCache);
void pqcp_nev_c_poly_from_bytes(NEV_Poly *r, const uint8_t *a, const CRYPT_NevInfo *info);

#if defined(PQCP_NEV_NEON_DISPATCH_ASM)
int32_t pqcp_nev_asm_engine_keygen(const CRYPT_NevInfo *info, uint8_t *pk, uint8_t *sk,
    const uint8_t *entropy, NEV_Poly *hCache, NEV_Poly *sCache);
int32_t pqcp_nev_asm_engine_encaps(const CRYPT_NevInfo *info, uint8_t *ct, uint8_t *ss,
    const uint8_t *pk, const uint8_t *pkHash, const NEV_Poly *hCache,
    const uint8_t *message);
int32_t pqcp_nev_asm_engine_decaps(const CRYPT_NevInfo *info, uint8_t *ss, const uint8_t *ct,
    const uint8_t *sk, const NEV_Poly *hCache, const NEV_Poly *sCache);

static int NevCanUseNeon(void)
{
#if defined(HITLS_CRYPTO_NEV_SVE2)
    return 1;
#elif defined(__linux__) && defined(HWCAP_ASIMD)
    return (getauxval(AT_HWCAP) & HWCAP_ASIMD) != 0;
#elif defined(__aarch64__) || defined(_M_ARM64)
    return 1;
#else
    return 0;
#endif
}
#endif

static const CRYPT_NevInfo g_nevParams[] = {
    {PQCP_NEV_512_769_C,   512,  769, 64769, 21817, 24, 128, 1, 2, 0, 2, 1, 16,  615,  615, 1246,  512, 128},
    {PQCP_NEV_1024_769_C, 1024,  769, 64769, 21817, 24, 128, 1, 8, 0, 2, 1, 32, 1229, 1229, 2490, 1024, 256},
    {PQCP_NEV_2048_769_C, 2048,  769, 64769, 21817, 24, 128, 8, 8, 0, 1, 1, 64, 2458, 2458, 4980, 2048, 512},
    {PQCP_NEV_512_1409,    512, 1409, 14977, 23814, 25,  64, 3, 3, 3, 3, 0, 16,  672,  672, 1360,  672, 128},
    {PQCP_NEV_1024_1409,  1024, 1409, 14977, 23814, 25,  64, 2, 2, 2, 2, 0, 32, 1344, 1344, 2720, 1344, 256},
    {PQCP_NEV_2048_1409,  2048, 1409, 14977, 23814, 25,  64, 9, 9, 9, 2, 0, 64, 2688, 2688, 5440, 2688, 512},
    {PQCP_NEV_512_3329,    512, 3329, 62209, 20159, 26, 128, 7, 7, 7, 7, 0, 16,  768,  768, 1552,  768, 128},
    {PQCP_NEV_1024_3329,  1024, 3329, 62209, 20159, 26, 128, 4, 4, 4, 4, 0, 32, 1536, 1536, 3104, 1536, 256},
    {PQCP_NEV_2048_3329,  2048, 3329, 62209, 20159, 26, 128, 2, 3, 2, 3, 0, 64, 3072, 3072, 6208, 3072, 512},
    {PQCP_NEV_512_769,     512,  769, 64769, 21817, 24, 128, 1, 2, 9, 2, 0, 16,  615,  615, 1246,  615, 128},
    {PQCP_NEV_1024_769,   1024,  769, 64769, 21817, 24, 128, 1, 8, 9, 2, 0, 32, 1229, 1229, 2490, 1229, 256},
    {PQCP_NEV_2048_769,   2048,  769, 64769, 21817, 24, 128, 8, 8, 9, 1, 0, 64, 2458, 2458, 4980, 2458, 512}
};

static const CRYPT_NevInfo *NevGetInfo(int32_t algId)
{
    for (size_t i = 0; i < sizeof(g_nevParams) / sizeof(g_nevParams[0]); i++) {
        if (g_nevParams[i].paraId == algId) {
            return &g_nevParams[i];
        }
    }
    return NULL;
}

static void NevFreeKeys(CRYPT_NEV_Ctx *ctx)
{
    if (ctx->sk != NULL && ctx->info != NULL) {
        BSL_SAL_CleanseData(ctx->sk, ctx->info->skLen);
    }
    BSL_SAL_FREE(ctx->sk);
    BSL_SAL_FREE(ctx->pk);
    BSL_SAL_CleanseData(ctx->pkHash, sizeof(ctx->pkHash));
    ctx->pkHashSet = 0;
    BSL_SAL_CleanseData(&ctx->hPoly, sizeof(ctx->hPoly));
    BSL_SAL_CleanseData(&ctx->sPoly, sizeof(ctx->sPoly));
    ctx->hPolySet = 0;
    ctx->sPolySet = 0;
}

void *PQCP_NEV_NewCtx(void)
{
    CRYPT_NEV_Ctx *ctx = BSL_SAL_Malloc(sizeof(CRYPT_NEV_Ctx));
    if (ctx == NULL) {
        return NULL;
    }
    (void)memset(ctx, 0, sizeof(CRYPT_NEV_Ctx));
    return ctx;
}

void PQCP_NEV_FreeCtx(CRYPT_NEV_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    NevFreeKeys(ctx);
    BSL_SAL_FREE(ctx);
}

static int32_t NevSetAlgInfo(CRYPT_NEV_Ctx *ctx, const void *val, uint32_t valLen)
{
    if (valLen != sizeof(int32_t)) {
        return PQCP_INVALID_ARG;
    }
    if (ctx->info != NULL) {
        return PQCP_NEV_PARA_REPEATED_SET;
    }
    int32_t algId = *(const int32_t *)val;
    const CRYPT_NevInfo *info = NevGetInfo(algId);
    if (info == NULL) {
        return PQCP_INVALID_ARG;
    }
    ctx->algId = algId;
    ctx->info = info;
    return PQCP_SUCCESS;
}

int32_t PQCP_NEV_SetPrvKey(CRYPT_NEV_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        return PQCP_NEV_KEYINFO_NOT_SET;
    }
    if (ctx->sk != NULL || ctx->pk != NULL) {
        return PQCP_NEV_KEY_REPEATED_SET;
    }
    const BSL_Param *prv = BSL_PARAM_FindConstParam(param, PQCP_PARAM_NEV_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (prv->valueLen < ctx->info->skLen) {
        return PQCP_INVALID_ARG;
    }

    ctx->sk = BSL_SAL_Malloc(ctx->info->skLen);
    ctx->pk = BSL_SAL_Malloc(ctx->info->pkLen);
    if (ctx->sk == NULL || ctx->pk == NULL) {
        NevFreeKeys(ctx);
        return PQCP_MEM_ALLOC_FAIL;
    }
    (void)memcpy(ctx->sk, prv->value, ctx->info->skLen);
    (void)memcpy(ctx->pk, ctx->sk + ctx->info->polyBytes, ctx->info->pkLen);
    pqcp_nev_c_poly_from_bytes(&ctx->sPoly, ctx->sk, ctx->info);
    pqcp_nev_c_poly_from_bytes(&ctx->hPoly, ctx->pk, ctx->info);
    ctx->sPolySet = 1;
    ctx->hPolySet = 1;
    NEV_Hash(ctx->pkHash, ctx->pk, ctx->info->pkLen, ctx->info->seedLen);
    ctx->pkHashSet = 1;
    return PQCP_SUCCESS;
}

int32_t PQCP_NEV_SetPubKey(CRYPT_NEV_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        return PQCP_NEV_KEYINFO_NOT_SET;
    }
    if (ctx->sk != NULL || ctx->pk != NULL) {
        return PQCP_NEV_KEY_REPEATED_SET;
    }
    const BSL_Param *pub = BSL_PARAM_FindConstParam(param, PQCP_PARAM_NEV_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (pub->valueLen < ctx->info->pkLen) {
        return PQCP_INVALID_ARG;
    }

    ctx->pk = BSL_SAL_Malloc(ctx->info->pkLen);
    if (ctx->pk == NULL) {
        return PQCP_MEM_ALLOC_FAIL;
    }
    (void)memcpy(ctx->pk, pub->value, ctx->info->pkLen);
    pqcp_nev_c_poly_from_bytes(&ctx->hPoly, ctx->pk, ctx->info);
    ctx->hPolySet = 1;
    NEV_Hash(ctx->pkHash, ctx->pk, ctx->info->pkLen, ctx->info->seedLen);
    ctx->pkHashSet = 1;
    return PQCP_SUCCESS;
}

int32_t PQCP_NEV_GetPrvKey(CRYPT_NEV_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        return PQCP_NEV_KEYINFO_NOT_SET;
    }
    if (ctx->sk == NULL) {
        return PQCP_NULL_INPUT;
    }
    BSL_Param *prv = BSL_PARAM_FindParam(param, PQCP_PARAM_NEV_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (prv->valueLen < ctx->info->skLen) {
        return PQCP_NEV_LEN_NOT_ENOUGH;
    }
    (void)memcpy(prv->value, ctx->sk, ctx->info->skLen);
    prv->useLen = ctx->info->skLen;
    return PQCP_SUCCESS;
}

int32_t PQCP_NEV_GetPubKey(CRYPT_NEV_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        return PQCP_NEV_KEYINFO_NOT_SET;
    }
    if (ctx->pk == NULL) {
        return PQCP_NULL_INPUT;
    }
    BSL_Param *pub = BSL_PARAM_FindParam(param, PQCP_PARAM_NEV_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (pub->valueLen < ctx->info->pkLen) {
        return PQCP_NEV_LEN_NOT_ENOUGH;
    }
    (void)memcpy(pub->value, ctx->pk, ctx->info->pkLen);
    pub->useLen = ctx->info->pkLen;
    return PQCP_SUCCESS;
}

CRYPT_NEV_Ctx *PQCP_NEV_DupCtx(CRYPT_NEV_Ctx *srcCtx)
{
    if (srcCtx == NULL) {
        return NULL;
    }
    CRYPT_NEV_Ctx *dstCtx = PQCP_NEV_NewCtx();
    if (dstCtx == NULL) {
        return NULL;
    }
    dstCtx->algId = srcCtx->algId;
    dstCtx->info = srcCtx->info;

    if (srcCtx->sk != NULL) {
        dstCtx->sk = BSL_SAL_Malloc(srcCtx->info->skLen);
        if (dstCtx->sk == NULL) {
            PQCP_NEV_FreeCtx(dstCtx);
            return NULL;
        }
        (void)memcpy(dstCtx->sk, srcCtx->sk, srcCtx->info->skLen);
    }
    if (srcCtx->pk != NULL) {
        dstCtx->pk = BSL_SAL_Malloc(srcCtx->info->pkLen);
        if (dstCtx->pk == NULL) {
            PQCP_NEV_FreeCtx(dstCtx);
            return NULL;
        }
        (void)memcpy(dstCtx->pk, srcCtx->pk, srcCtx->info->pkLen);
    }
    if (srcCtx->pkHashSet != 0) {
        (void)memcpy(dstCtx->pkHash, srcCtx->pkHash, sizeof(dstCtx->pkHash));
        dstCtx->pkHashSet = 1;
    }
    if (srcCtx->hPolySet != 0) {
        (void)memcpy(&dstCtx->hPoly, &srcCtx->hPoly, sizeof(dstCtx->hPoly));
        dstCtx->hPolySet = 1;
    }
    if (srcCtx->sPolySet != 0) {
        (void)memcpy(&dstCtx->sPoly, &srcCtx->sPoly, sizeof(dstCtx->sPoly));
        dstCtx->sPolySet = 1;
    }
    return dstCtx;
}

int32_t PQCP_NEV_Gen(CRYPT_NEV_Ctx *ctx)
{
    if (ctx == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        return PQCP_NEV_KEYINFO_NOT_SET;
    }
    if (ctx->sk != NULL || ctx->pk != NULL) {
        return PQCP_NEV_KEY_REPEATED_SET;
    }

    ctx->sk = BSL_SAL_Malloc(ctx->info->skLen);
    ctx->pk = BSL_SAL_Malloc(ctx->info->pkLen);
    if (ctx->sk == NULL || ctx->pk == NULL) {
        NevFreeKeys(ctx);
        return PQCP_MEM_ALLOC_FAIL;
    }
    uint8_t entropy[NEV_SEED_MAX] = {0};
    int32_t ret = CRYPT_EAL_Randbytes(entropy, ctx->info->seedLen);
    if (ret == PQCP_SUCCESS) {
#if defined(PQCP_NEV_NEON_DISPATCH_ASM)
        if (NevCanUseNeon()) {
            ret = pqcp_nev_asm_engine_keygen(ctx->info, ctx->pk, ctx->sk, entropy,
                &ctx->hPoly, &ctx->sPoly);
        } else {
            ret = pqcp_nev_c_engine_keygen(ctx->info, ctx->pk, ctx->sk, entropy,
                &ctx->hPoly, &ctx->sPoly);
        }
#else
        ret = pqcp_nev_c_engine_keygen(ctx->info, ctx->pk, ctx->sk, entropy,
            &ctx->hPoly, &ctx->sPoly);
#endif
    }
    BSL_SAL_CleanseData(entropy, sizeof(entropy));
    if (ret != PQCP_SUCCESS) {
        NevFreeKeys(ctx);
        return ret;
    }
    (void)memcpy(ctx->pkHash, ctx->sk + ctx->info->skLen - ctx->info->seedLen,
        ctx->info->seedLen);
    ctx->pkHashSet = 1;
    ctx->hPolySet = 1;
    ctx->sPolySet = 1;
    return PQCP_SUCCESS;
}

int32_t PQCP_NEV_EncapsInit(CRYPT_NEV_Ctx *ctx, const BSL_Param *params)
{
    (void)params;
    return ctx == NULL ? PQCP_NULL_INPUT : PQCP_SUCCESS;
}

int32_t PQCP_NEV_DecapsInit(CRYPT_NEV_Ctx *ctx, const BSL_Param *params)
{
    (void)params;
    return ctx == NULL ? PQCP_NULL_INPUT : PQCP_SUCCESS;
}

int32_t PQCP_NEV_Encaps(CRYPT_NEV_Ctx *ctx, uint8_t *ciphertext, uint32_t *ctLen,
    uint8_t *sharedSecret, uint32_t *ssLen)
{
    if (ctx == NULL || ciphertext == NULL || ctLen == NULL || sharedSecret == NULL || ssLen == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        return PQCP_NEV_KEYINFO_NOT_SET;
    }
    if (ctx->pk == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (*ctLen < ctx->info->ctLen || *ssLen < ctx->info->seedLen) {
        return PQCP_NEV_LEN_NOT_ENOUGH;
    }

    uint8_t message[NEV_SEED_MAX] = {0};
    int32_t ret = CRYPT_EAL_Randbytes(message, ctx->info->seedLen);
    if (ret == PQCP_SUCCESS) {
#if defined(PQCP_NEV_NEON_DISPATCH_ASM)
        if (NevCanUseNeon()) {
            ret = pqcp_nev_asm_engine_encaps(ctx->info, ciphertext, sharedSecret, ctx->pk,
                ctx->pkHashSet != 0 ? ctx->pkHash : NULL,
                ctx->hPolySet != 0 ? &ctx->hPoly : NULL, message);
        } else {
            ret = pqcp_nev_c_engine_encaps(ctx->info, ciphertext, sharedSecret, ctx->pk,
                ctx->pkHashSet != 0 ? ctx->pkHash : NULL,
                ctx->hPolySet != 0 ? &ctx->hPoly : NULL, message);
        }
#else
        ret = pqcp_nev_c_engine_encaps(ctx->info, ciphertext, sharedSecret, ctx->pk,
            ctx->pkHashSet != 0 ? ctx->pkHash : NULL,
            ctx->hPolySet != 0 ? &ctx->hPoly : NULL, message);
#endif
    }
    BSL_SAL_CleanseData(message, sizeof(message));
    if (ret != PQCP_SUCCESS) {
        (void)memset(ciphertext, 0, ctx->info->ctLen);
        (void)memset(sharedSecret, 0, ctx->info->seedLen);
        return ret;
    }
    *ctLen = ctx->info->ctLen;
    *ssLen = ctx->info->seedLen;
    return PQCP_SUCCESS;
}

int32_t PQCP_NEV_Decaps(CRYPT_NEV_Ctx *ctx, const uint8_t *ciphertext, uint32_t ctLen,
    uint8_t *sharedSecret, uint32_t *ssLen)
{
    if (ctx == NULL || ciphertext == NULL || sharedSecret == NULL || ssLen == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        return PQCP_NEV_KEYINFO_NOT_SET;
    }
    if (ctx->sk == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctLen != ctx->info->ctLen || *ssLen < ctx->info->seedLen) {
        return PQCP_NEV_LEN_NOT_ENOUGH;
    }

    int32_t ret;
#if defined(PQCP_NEV_NEON_DISPATCH_ASM)
    if (NevCanUseNeon()) {
        ret = pqcp_nev_asm_engine_decaps(ctx->info, sharedSecret, ciphertext, ctx->sk,
            ctx->hPolySet != 0 ? &ctx->hPoly : NULL,
            ctx->sPolySet != 0 ? &ctx->sPoly : NULL);
    } else {
        ret = pqcp_nev_c_engine_decaps(ctx->info, sharedSecret, ciphertext, ctx->sk,
            ctx->hPolySet != 0 ? &ctx->hPoly : NULL,
            ctx->sPolySet != 0 ? &ctx->sPoly : NULL);
    }
#else
    ret = pqcp_nev_c_engine_decaps(ctx->info, sharedSecret, ciphertext, ctx->sk,
        ctx->hPolySet != 0 ? &ctx->hPoly : NULL,
        ctx->sPolySet != 0 ? &ctx->sPoly : NULL);
#endif
    if (ret != PQCP_SUCCESS) {
        (void)memset(sharedSecret, 0, ctx->info->seedLen);
        return PQCP_NEV_DECAP_FAIL;
    }
    *ssLen = ctx->info->seedLen;
    return PQCP_SUCCESS;
}

int32_t PQCP_NEV_Ctrl(CRYPT_NEV_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL || val == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (cmd == CRYPT_CTRL_SET_PARA_BY_ID) {
        return NevSetAlgInfo(ctx, val, valLen);
    }
    if (ctx->info == NULL) {
        return PQCP_NEV_KEYINFO_NOT_SET;
    }
    if (valLen != sizeof(uint32_t)) {
        return PQCP_INVALID_ARG;
    }

    switch (cmd) {
        case CRYPT_CTRL_GET_PUBKEY_LEN:
            *(uint32_t *)val = ctx->info->pkLen;
            break;
        case CRYPT_CTRL_GET_PRVKEY_LEN:
            *(uint32_t *)val = ctx->info->skLen;
            break;
        case CRYPT_CTRL_GET_CIPHERTEXT_LEN:
            *(uint32_t *)val = ctx->info->ctLen;
            break;
        case CRYPT_CTRL_GET_SHARED_KEY_LEN:
            *(uint32_t *)val = ctx->info->seedLen;
            break;
        default:
            return PQCP_INVALID_ARG;
    }
    return PQCP_SUCCESS;
}

#endif
