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

#include <stdio.h> // 新增头文件
#include "scloudplus.h"
#include "bsl_sal.h"
#include "crypt_eal_md.h"
#include "crypt_eal_rand.h" // 随机数头文件
#include "../../../platform/Secure_C/include/securec.h"
#include "pqcp_err.h"
#include "pqcp_types.h"
#include "scloudplus_local.h"

// 预定义三组参数配置
static const SCLOUDPLUS_Para PRESET_PARAS[] = {
    {.ss = 16,
     .mbar = 8,
     .nbar = 8,
     .m = 600,
     .n = 600,
     .logq = 12,
     .logq1 = 9,
     .logq2 = 7,
     .h1 = 150,
     .h2 = 150,
     .eta1 = 7,
     .eta2 = 7,
     .mu = 64,
     .mu_count = 2,
     .tau = 3,
     .mnin = 679,
     .mnout = 582,
     .c1_size = 5400,
     .c2_size = 56,
     .ctx_size = 5456,
     .pk_size = 7216,
     .pke_sk_size = 1200,
     .kem_sk_size = 8480},
    {.ss = 24,
     .mbar = 8,
     .nbar = 8,
     .m = 928,
     .n = 896,
     .logq = 12,
     .logq1 = 12,
     .logq2 = 10,
     .h1 = 224,
     .h2 = 232,
     .eta1 = 2,
     .eta2 = 1,
     .mu = 96,
     .mu_count = 2,
     .tau = 4,
     .mnin = 671,
     .mnout = 488,
     .c1_size = 10752,
     .c2_size = 80,
     .ctx_size = 10832,
     .pk_size = 11152,
     .pke_sk_size = 1792,
     .kem_sk_size = 13008},
    {.ss = 32,
     .mbar = 12,
     .nbar = 11,
     .m = 1136,
     .n = 1120,
     .logq = 12,
     .logq1 = 10,
     .logq2 = 7,
     .h1 = 280,
     .h2 = 284,
     .eta1 = 3,
     .eta2 = 2,
     .mu = 64,
     .mu_count = 4,
     .tau = 3,
     .mnin = 680,
     .mnout = 530,
     .c1_size = 16800,
     .c2_size = 116,
     .ctx_size = 16916,
     .pk_size = 18760,
     .pke_sk_size = 3080,
     .kem_sk_size = 21904}};

int32_t SCLOUDPLUS_PKEKeygen(const SCLOUDPLUS_Para *para, uint8_t *pk, uint8_t *sk)
{
    if (para->ss == 0 || pk == NULL || sk == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    int32_t ret = PQCP_SUCCESS;
    uint16_t *MemoryPool = NULL;
    MemoryPool =
        BSL_SAL_Malloc(sizeof(uint16_t) * ((para->n + 2 * para->m) * para->nbar));
    if (MemoryPool == NULL)
    {
        return PQCP_MALLOC_FAIL;
    }
    uint16_t *S = MemoryPool;
    uint16_t *E = MemoryPool + (para->n * para->nbar);
    uint16_t *B = MemoryPool + (para->n * para->nbar) + (para->m * para->nbar);
    
    uint32_t seedLen = seedALen + seedr1Len + seedr2Len;
    uint8_t alpha[alphaLen], seed[seedLen];
    const uint8_t *seedA = seed;
    const uint8_t *r1 = seed + seedALen;
    const uint8_t *r2 = seed + seedALen + seedr1Len;
    ret = CRYPT_EAL_Randbytes(alpha, alphaLen);
    if (ret != PQCP_SUCCESS)
    {
        goto EXIT;
    }
    ret = SCLOUDPLUS_MdFunc(CRYPT_MD_SHAKE256, alpha, alphaLen, NULL, 0, seed, &seedLen);
    if (ret != PQCP_SUCCESS)
    {
        goto EXIT;
    }
    ret = SCLOUDPLUS_SamplePsi(r1, para, S);
    if (ret != PQCP_SUCCESS)
    {
        goto EXIT;
    }
    ret = SCLOUDPLUS_SampleEta1(r2, para, E);
    if (ret != PQCP_SUCCESS)
    {
        goto EXIT;
    }
    ret = SCLOUDPLUS_AS_E(seedA, S, E, para, B);
    if (ret != PQCP_SUCCESS)
    {
        goto EXIT;
    }
    SCLOUDPLUS_PackPK(B, para, pk);
    memcpy_s(pk + para->pk_size - seedALen, seedALen, seedA, seedALen);
    SCLOUDPLUS_PackSK(S, para, sk);
EXIT:
    BSL_SAL_FREE(MemoryPool);
    return ret;
}

int32_t SCLOUDPLUS_PKEEncrypt(const uint8_t *pk, const uint8_t *m, const uint8_t *r, const SCLOUDPLUS_Para *para,
                              uint8_t *ctx)
{
    if (para->ss == 0 || pk == NULL || m == NULL || ctx == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    int32_t ret = PQCP_SUCCESS;
    uint16_t *MemoryPool = NULL;
    MemoryPool =
        BSL_SAL_Malloc(
            sizeof(uint16_t) * ((para->mbar * (para->m + 2 * para->n + 3 * para->nbar)) + (para->m * para->nbar)));
    if (MemoryPool == NULL)
    {
        return PQCP_MALLOC_FAIL;
    }
    uint16_t *S1 = MemoryPool;
    uint16_t *E1 = MemoryPool + para->mbar * para->m;
    uint16_t *E2 = MemoryPool + para->mbar * (para->m + para->n);
    uint16_t *mu0 = MemoryPool + para->mbar * (para->m + para->n + para->nbar);
    uint16_t *C1 = MemoryPool + para->mbar * (para->m + para->n + 2 * para->nbar);
    uint16_t *C2 = MemoryPool + para->mbar * (para->m + 2 * para->n + 2 * para->nbar);
    uint16_t *B = MemoryPool + para->mbar * (para->m + 2 * para->n + 3 * para->nbar);
    uint32_t seedLen = seedr1Len + seedr2Len;
    uint8_t seed[seedLen];
    const uint8_t *seedA = pk + para->pk_size - seedALen;
    const uint8_t *r1 = seed;
    const uint8_t *r2 = seed + seedr1Len;
    ret = SCLOUDPLUS_MdFunc(CRYPT_MD_SHAKE256, r, randrLen, NULL, 0, seed, &seedLen);
    if (ret != PQCP_SUCCESS)
    {
        goto EXIT;
    }
    ret = SCLOUDPLUS_SamplePhi(r1, para, S1);
    if (ret != PQCP_SUCCESS)
    {
        goto EXIT;
    }
    ret = SCLOUDPLUS_SampleEta2(r2, para, E1, E2);
    if (ret != PQCP_SUCCESS)
    {
        goto EXIT;
    }
    SCLOUDPLUS_MsgEncode(m, para, mu0);
    SCLOUDPLUS_UnPackPK(pk, para, B);
    ret = SCLOUDPLUS_SA_E(seedA, S1, E1, para, C1);
    if (ret != PQCP_SUCCESS)
    {
        goto EXIT;
    }
    SCLOUDPLUS_SB_E(S1, B, E2, para, C2);
    SCLOUDPLUS_Add(C2, mu0, para->mbar * para->nbar, C2);
    SCLOUDPLUS_CompressC1(C1, para, C1);
    SCLOUDPLUS_CompressC2(C2, para, C2);
    SCLOUDPLUS_PackC1(C1, para, ctx);
    SCLOUDPLUS_PackC2(C2, para, ctx + para->c1_size);
EXIT:
    BSL_SAL_FREE(MemoryPool);
    return ret;
}

int32_t SCLOUDPLUS_PKEDecrypt(const uint8_t *sk, const uint8_t *ctx, const SCLOUDPLUS_Para *para, uint8_t *m)
{
    if (para->ss == 0 || sk == NULL || ctx == NULL || m == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    uint16_t *MemoryPool = NULL;
    MemoryPool =
        BSL_SAL_Malloc(sizeof(uint16_t) * ((para->mbar * (para->n + 2 * para->nbar)) + (para->n * para->nbar)));
    if (MemoryPool == NULL)
    {
        return PQCP_MALLOC_FAIL;
    }
    uint16_t *S = MemoryPool;
    uint16_t *C1 = MemoryPool + para->n * para->nbar;
    uint16_t *C2 = MemoryPool + para->mbar * para->n + para->n * para->nbar;
    uint16_t *D = MemoryPool + para->mbar * (para->n + para->nbar) + para->n * para->nbar;
    SCLOUDPLUS_UnPackSK(sk, para, S);
    SCLOUDPLUS_UnPackC1(ctx, para, C1);
    SCLOUDPLUS_UnPackC2(ctx + para->c1_size, para, C2);
    SCLOUDPLUS_DeCompressC1(C1, para, C1);
    SCLOUDPLUS_DeCompressC2(C2, para, C2);
    SCLOUDPLUS_CS(C1, S, para, D);
    SCLOUDPLUS_Sub(C2, D, para->mbar * para->nbar, D);
    SCLOUDPLUS_MsgDecode(D, para, m);
EXIT:
    BSL_SAL_FREE(MemoryPool);
    return PQCP_SUCCESS;
}

void *PQCP_SCLOUDPLUS_NewCtx(void)
{
    SCLOUDPLUS_Ctx *ctx = BSL_SAL_Malloc(sizeof(SCLOUDPLUS_Ctx));
    if (ctx == NULL)
    {
        return NULL;
    }
    (void)memset_s(ctx, sizeof(SCLOUDPLUS_Ctx), 0, sizeof(SCLOUDPLUS_Ctx));

    return ctx;
}

int32_t PQCP_SCLOUDPLUS_Gen(SCLOUDPLUS_Ctx *ctx)
{
    if (ctx == NULL || ctx->para == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    int32_t ret = PQCP_SUCCESS;
    if (ctx->public_key != NULL)
    {
        memset_s(ctx->public_key, ctx->para->pk_size, 0, ctx->para->pk_size);
        BSL_SAL_FREE(ctx->public_key);
    }
    if (ctx->private_key != NULL)
    {
        memset_s(ctx->private_key, ctx->para->kem_sk_size, 0, ctx->para->kem_sk_size);
        BSL_SAL_FREE(ctx->private_key);
    }
    ctx->public_key = BSL_SAL_Calloc(ctx->para->pk_size, sizeof(uint8_t));
    if (ctx->public_key == NULL)
    {
        ret = PQCP_MALLOC_FAIL;
        goto EXIT;
    }
    ctx->private_key = BSL_SAL_Calloc(ctx->para->kem_sk_size, sizeof(uint8_t));
    if (ctx->private_key == NULL)
    {
        ret = PQCP_MALLOC_FAIL;
        goto EXIT;
    }
    uint32_t outLen = hpkLen;
    uint8_t z[randzLen];
    ret = CRYPT_EAL_Randbytes(z, randzLen);
    if (ret != PQCP_SUCCESS)
    {
        goto EXIT;
    }
    ret = SCLOUDPLUS_PKEKeygen(ctx->para, ctx->public_key, ctx->private_key);
    if (ret != PQCP_SUCCESS)
    {
        goto EXIT;
    }
    memcpy_s(ctx->private_key + ctx->para->pke_sk_size, ctx->para->pk_size, ctx->public_key, ctx->para->pk_size);
    ret = SCLOUDPLUS_MdFunc(CRYPT_MD_SHA3_256, ctx->public_key, ctx->para->pk_size, NULL, 0,
                            ctx->private_key + ctx->para->pke_sk_size + ctx->para->pk_size, &outLen);
    if (ret != PQCP_SUCCESS)
    {
        goto EXIT;
    }
    memcpy_s(ctx->private_key + ctx->para->kem_sk_size - randzLen, randzLen, z, randzLen);

    return PQCP_SUCCESS;
EXIT:
    if (ctx->public_key != NULL)
    {
        memset_s(ctx->public_key, ctx->para->pk_size, 0, ctx->para->pk_size);
        BSL_SAL_FREE(ctx->public_key);
    }
    if (ctx->private_key != NULL)
    {
        memset_s(ctx->private_key, ctx->para->kem_sk_size, 0, ctx->para->kem_sk_size);
        BSL_SAL_FREE(ctx->private_key);
    }
    return ret;
}

int32_t PQCP_SCLOUDPLUS_SetPrvKey(SCLOUDPLUS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || ctx->para == NULL || param == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    const BSL_Param *prv = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_SCLOUDPLUS_PRVKEY);
    if (prv == NULL || prv->value == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    if (ctx->para->kem_sk_size > prv->valueLen)
    {
        return PQCP_SCLOUDPLUS_INVALID_ARG;
    }
    if (ctx->private_key == NULL)
    {
        ctx->private_key = BSL_SAL_Calloc(ctx->para->kem_sk_size, sizeof(uint8_t));
        if (ctx->private_key == NULL)
        {
            return PQCP_MEM_ALLOC_FAIL;
        }
    }

    uint32_t useLen = ctx->para->kem_sk_size;
    memcpy_s(ctx->private_key, useLen, prv->value, useLen);
    return PQCP_SUCCESS;
}

int32_t PQCP_SCLOUDPLUS_SetPubKey(SCLOUDPLUS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || ctx->para == NULL || param == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    const BSL_Param *pub = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_SCLOUDPLUS_PUBKEY);
    if (pub == NULL || pub->value == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    if (ctx->para->pk_size > pub->valueLen)
    {
        return PQCP_SCLOUDPLUS_INVALID_ARG;
    }
    if (ctx->public_key == NULL)
    {
        ctx->public_key = BSL_SAL_Calloc(ctx->para->pk_size, sizeof(uint8_t));
        if (ctx->public_key == NULL)
        {
            return PQCP_MEM_ALLOC_FAIL;
        }
    }

    uint32_t useLen = ctx->para->pk_size;
    memcpy_s(ctx->public_key, useLen, pub->value, useLen);
    return PQCP_SUCCESS;
}

int32_t PQCP_SCLOUDPLUS_GetPrvKey(SCLOUDPLUS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || ctx->para == NULL || param == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    BSL_Param *prv = BSL_PARAM_FindParam(param, CRYPT_PARAM_SCLOUDPLUS_PRVKEY);
    if (prv == NULL || prv->value == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    if (ctx->private_key == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    if (ctx->para->kem_sk_size > prv->valueLen)
    {
        return PQCP_SCLOUDPLUS_INVALID_ARG;
    }
    uint32_t useLen = ctx->para->kem_sk_size;
    memcpy_s(prv->value, useLen, ctx->private_key, useLen);
    prv->useLen = useLen;
    return PQCP_SUCCESS;
}

int32_t PQCP_SCLOUDPLUS_GetPubKey(SCLOUDPLUS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || ctx->para == NULL || param == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    BSL_Param *pub = BSL_PARAM_FindParam(param, CRYPT_PARAM_SCLOUDPLUS_PUBKEY);
    if (pub == NULL || pub->value == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    if (ctx->public_key == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    if (ctx->para->pk_size > pub->valueLen)
    {
        return PQCP_SCLOUDPLUS_INVALID_ARG;
    }
    uint32_t useLen = ctx->para->pk_size;
    memcpy_s(pub->value, useLen, ctx->public_key, useLen);
    pub->useLen = useLen;
    return PQCP_SUCCESS;
}

SCLOUDPLUS_Ctx *PQCP_SCLOUDPLUS_DupCtx(SCLOUDPLUS_Ctx *src)
{
    if (src == NULL)
    {
        return NULL;
    }
    SCLOUDPLUS_Ctx *ctx = PQCP_SCLOUDPLUS_NewCtx();
    if (ctx == NULL)
    {
        return NULL;
    }
    if (src->para != NULL)
    {
        ctx->para = BSL_SAL_Malloc(sizeof(SCLOUDPLUS_Para));
        if (ctx->para == NULL)
        {
            PQCP_SCLOUDPLUS_FreeCtx(ctx);
            return NULL;
        }
        memcpy_s(ctx->para, sizeof(SCLOUDPLUS_Para), src->para, sizeof(SCLOUDPLUS_Para));
    }
    if (src->public_key != NULL)
    {
        ctx->public_key = BSL_SAL_Calloc(src->para->pk_size, sizeof(uint8_t));
        if (ctx->public_key == NULL)
        {
            PQCP_SCLOUDPLUS_FreeCtx(ctx);
            return NULL;
        }
        memcpy_s(ctx->public_key, ctx->para->pk_size, src->public_key, ctx->para->pk_size);
    }
    if (src->private_key != NULL)
    {
        ctx->private_key = BSL_SAL_Calloc(src->para->kem_sk_size, sizeof(uint8_t));
        if (ctx->private_key == NULL)
        {
            PQCP_SCLOUDPLUS_FreeCtx(ctx);
            return NULL;
        }
        memcpy_s(ctx->private_key, ctx->para->kem_sk_size, src->private_key, ctx->para->kem_sk_size);
    }
    return ctx;
}

int32_t PQCP_SCLOUDPLUS_Cmp(SCLOUDPLUS_Ctx *ctx1, SCLOUDPLUS_Ctx *ctx2)
{
    if (ctx1 == NULL || ctx2 == NULL || ctx1->para == NULL || ctx2->para == NULL)
    {
        return PQCP_NULL_INPUT;
    };
    int32_t ret = memcmp(ctx1->para, ctx2->para, sizeof(SCLOUDPLUS_Ctx));
    if (ret != PQCP_SUCCESS)
    {
        return PQCP_SCLOUDPLUS_CMP_FALSE;
    }
    if (ctx1->public_key != NULL && ctx2->public_key != NULL)
    {
        ret = memcmp(ctx1->public_key, ctx2->public_key, ctx1->para->pk_size);
        if (ret != PQCP_SUCCESS)
        {
            return PQCP_SCLOUDPLUS_CMP_FALSE;
        }
    }
    if (ctx1->private_key != NULL && ctx2->private_key != NULL)
    {
        ret = memcmp(ctx1->private_key, ctx2->private_key, ctx1->para->kem_sk_size);
        if (ret != PQCP_SUCCESS)
        {
            return PQCP_SCLOUDPLUS_CMP_FALSE;
        }
    }
    return PQCP_SUCCESS;
}

int32_t PQCP_SCLOUDPLUS_Ctrl(SCLOUDPLUS_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    switch (cmd)
    {
    case PQCP_SCLOUDPLUS_KEY_BITS:
    {
        if (val == NULL || valLen != sizeof(uint32_t))
        {
            return PQCP_NULL_INPUT;
        }
        int32_t ssLen = *(int32_t *)val;
        ctx->para = BSL_SAL_Malloc(sizeof(SCLOUDPLUS_Para));
        if (ctx->para == NULL)
        {
            return PQCP_MALLOC_FAIL;
        }
        if (ssLen == secBits1)
        {
            memcpy_s(ctx->para, sizeof(SCLOUDPLUS_Para), &PRESET_PARAS[0], sizeof(SCLOUDPLUS_Para));
            return PQCP_SUCCESS;
        }
        else if (ssLen == secBits2)
        {
            memcpy_s(ctx->para, sizeof(SCLOUDPLUS_Para), &PRESET_PARAS[1], sizeof(SCLOUDPLUS_Para));
            return PQCP_SUCCESS;
        }
        else if (ssLen == secBits3)
        {
            memcpy_s(ctx->para, sizeof(SCLOUDPLUS_Para), &PRESET_PARAS[2], sizeof(SCLOUDPLUS_Para));
            return PQCP_SUCCESS;
        }
        else
        {
            BSL_SAL_FREE(ctx->para);
            return PQCP_SCLOUDPLUS_INVALID_ARG;
        }
    }
    case PQCP_SCLOUDPLUS_GET_PARA:
    {
        if (ctx->para == NULL || val == NULL || valLen != sizeof(SCLOUDPLUS_Para))
        {
            return PQCP_NULL_INPUT;
        }
        memcpy_s(val, sizeof(SCLOUDPLUS_Para), &ctx->para, sizeof(SCLOUDPLUS_Para));
        return PQCP_SUCCESS;
    }
    case PQCP_SCLOUDPLUS_GET_CIPHERLEN:
    {
        if (ctx->para == NULL || val == NULL || valLen != sizeof(uint32_t))
        {
            return PQCP_NULL_INPUT;
        }
        *(uint32_t *)val = ctx->para->ctx_size;
        return PQCP_SUCCESS;
    }
    case PQCP_SCLOUDPLUS_GET_SECBITS:
    {
        if (ctx->para == NULL || val == NULL || valLen != sizeof(uint32_t))
        {
            return PQCP_NULL_INPUT;
        }
        *(uint32_t *)val = ctx->para->ss * 8;
        return PQCP_SUCCESS;
    }
    default:
        return PQCP_SCLOUDPLUS_INVALID_ARG;
    }
}

void PQCP_SCLOUDPLUS_FreeCtx(SCLOUDPLUS_Ctx *ctx)
{
    if (ctx == NULL)
    {
        return;
    }
    if (ctx->para != NULL)
    {
        BSL_SAL_FREE(ctx->para);
    }
    if (ctx->public_key != NULL)
    {
        BSL_SAL_FREE(ctx->public_key);
    }
    if (ctx->private_key != NULL)
    {
        BSL_SAL_FREE(ctx->private_key);
    }
    BSL_SAL_FREE(ctx);
}

int32_t PQCP_SCLOUDPLUS_EncapsInit(SCLOUDPLUS_Ctx *ctx, const BSL_Param *params)
{
    printf("PQCP_SCLOUDPLUS_EncapsInit\n");
    // TODO: 封装初始化
    return 0;
}

int32_t PQCP_SCLOUDPLUS_DecapsInit(SCLOUDPLUS_Ctx *ctx, const BSL_Param *params)
{
    printf("PQCP_SCLOUDPLUS_DecapsInit\n");
    // TODO: 解封装初始化
    return 0;
}

int32_t PQCP_SCLOUDPLUS_Encaps(SCLOUDPLUS_Ctx *ctx,
                               uint8_t *ciphertext, uint32_t *ctLen,
                               uint8_t *sharedSecret, uint32_t *ssLen)
{
    if (ctx == NULL || ctx->para == NULL || ctx->public_key == NULL || ciphertext == NULL || sharedSecret == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    uint8_t in[ctx->para->ss + hpkLen + randrLen + seedkLen];
    uint8_t *C = ciphertext;
    uint8_t *m = in;
    uint8_t *hpk = in + ctx->para->ss;
    uint8_t *r = in + ctx->para->ss + hpkLen;
    uint8_t *k = in + ctx->para->ss + hpkLen + randrLen;
    uint32_t outLen = hpkLen;
    int32_t ret = CRYPT_EAL_Randbytes(m, ctx->para->ss);
    if (ret != PQCP_SUCCESS)
    {
        return ret;
    }
    ret = SCLOUDPLUS_MdFunc(CRYPT_MD_SHA3_256, ctx->public_key, ctx->para->pk_size, NULL, 0, hpk, &outLen);
    if (ret != PQCP_SUCCESS)
    {
        return ret;
    }
    outLen = randrLen + seedkLen;
    ret = SCLOUDPLUS_MdFunc(CRYPT_MD_SHA3_512, m, ctx->para->ss, hpk, hpkLen, r, &outLen);
    if (ret != PQCP_SUCCESS)
    {
        return ret;
    }
    ret = SCLOUDPLUS_PKEEncrypt(ctx->public_key, m, r, ctx->para, C);
    if (ret != PQCP_SUCCESS)
    {
        return ret;
    }
    *ssLen = ctx->para->ss;
    ret = SCLOUDPLUS_MdFunc(CRYPT_MD_SHAKE256, k, seedkLen, C, ctx->para->ctx_size, sharedSecret, ssLen);
    if (ret != PQCP_SUCCESS)
    {
        return ret;
    }
    *ctLen = ctx->para->ctx_size;
    return PQCP_SUCCESS;
}

int32_t PQCP_SCLOUDPLUS_Decaps(SCLOUDPLUS_Ctx *ctx,
                               const uint8_t *ciphertext, uint32_t ctLen,
                               uint8_t *sharedSecret, uint32_t *ssLen)
{
    if (ctx == NULL || ctx->para == NULL || ctx->private_key == NULL || ciphertext == NULL || sharedSecret == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    if (ctLen != ctx->para->ctx_size)
    {
        return PQCP_SCLOUDPLUS_INVALID_ARG;
    }
    uint8_t *C1 = BSL_SAL_Malloc(ctx->para->ctx_size);
    if (C1 == NULL)
    {
        return PQCP_MALLOC_FAIL;
    }
    uint8_t in[ctx->para->ss + randrLen + seedkLen];
    const uint8_t *C = ciphertext;
    uint8_t *m1 = in;
    uint8_t *hpk = ctx->private_key + ctx->para->pke_sk_size + ctx->para->pk_size;
    uint8_t *r1 = in + ctx->para->ss;
    uint8_t *k1 = in + ctx->para->ss + randrLen;

    uint32_t outLen = randrLen + seedkLen;
    int32_t ret = SCLOUDPLUS_PKEDecrypt(ctx->private_key, C, ctx->para, m1);
    if (ret != PQCP_SUCCESS)
    {
        goto EXIT;
    }
    ret = SCLOUDPLUS_MdFunc(CRYPT_MD_SHA3_512, m1, ctx->para->ss, hpk, hpkLen, r1, &outLen);
    if (ret != PQCP_SUCCESS)
    {
        goto EXIT;
    }
    ret = SCLOUDPLUS_PKEEncrypt(ctx->private_key + ctx->para->pke_sk_size, m1, r1, ctx->para, C1);
    if (ret != PQCP_SUCCESS)
    {
        goto EXIT;
    }
    int8_t bl = SCLOUDPLUS_Verify(C, C1, ctx->para->ctx_size);
    *ssLen = ctx->para->ss;
    if (bl == 0)
    {
        ret = SCLOUDPLUS_MdFunc(CRYPT_MD_SHAKE256, k1, seedkLen, C, ctx->para->ctx_size, sharedSecret, ssLen);
    }
    else
    {
        ret = SCLOUDPLUS_MdFunc(CRYPT_MD_SHAKE256, ctx->private_key + ctx->para->kem_sk_size - randzLen, randzLen, C,
                                ctx->para->ctx_size, sharedSecret, ssLen);
    }
EXIT:
    BSL_SAL_FREE(C1);
    return ret;
}
