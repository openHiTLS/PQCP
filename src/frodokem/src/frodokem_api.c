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

#include <stdio.h>
#include "scloudplus.h"
#include "bsl_sal.h"
#include "crypt_eal_md.h"
#include "crypt_eal_rand.h"
#include "securec.h"
#include "pqcp_err.h"
#include "pqcp_types.h"
#include "frodo_local.h"
#include "frodokem.h"

void* PQCP_FRODOKEM_NewCtx(void)
{
    FrodoKEM_Ctx* ctx = BSL_SAL_Malloc(sizeof(FrodoKEM_Ctx));
    if (ctx == NULL) {
        return NULL;
    }
    (void)memset_s(ctx, sizeof(FrodoKEM_Ctx), 0, sizeof(FrodoKEM_Ctx));

    return ctx;
}

int32_t PQCP_FRODOKEM_Gen(FrodoKEM_Ctx* ctx)
{
    if (ctx == NULL || ctx->para == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->publicKey != NULL) {
        (void)memset_s(ctx->publicKey, ctx->para->pkSize, 0, ctx->para->pkSize);
        BSL_SAL_FREE(ctx->publicKey);
    }
    if (ctx->privateKey != NULL) {
        (void)memset_s(ctx->privateKey, ctx->para->kemSkSize, 0, ctx->para->kemSkSize);
        BSL_SAL_FREE(ctx->privateKey);
    }
    ctx->publicKey = BSL_SAL_Calloc(ctx->para->pkSize, sizeof(uint8_t));
    if (ctx->publicKey == NULL) {
        return PQCP_MALLOC_FAIL;
    }
    ctx->privateKey = BSL_SAL_Calloc(ctx->para->kemSkSize, sizeof(uint8_t));
    if (ctx->privateKey == NULL) {
        return PQCP_MALLOC_FAIL;
    }
    int32_t ret = FrodoKemKeypair(ctx->para, ctx->publicKey, ctx->privateKey);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }

    return PQCP_SUCCESS;
EXIT:
    if (ctx->publicKey != NULL) {
        (void)memset_s(ctx->publicKey, ctx->para->pkSize, 0, ctx->para->pkSize);
        BSL_SAL_FREE(ctx->publicKey);
    }
    if (ctx->privateKey != NULL) {
        (void)memset_s(ctx->privateKey, ctx->para->kemSkSize, 0, ctx->para->kemSkSize);
        BSL_SAL_FREE(ctx->privateKey);
    }
    return ret;
}

int32_t PQCP_FRODOKEM_SetPrvKey(FrodoKEM_Ctx* ctx, BSL_Param* param)
{
    if (ctx == NULL || ctx->para == NULL || param == NULL) {
        return PQCP_NULL_INPUT;
    }
    const BSL_Param* prv = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_FRODOKEM_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->para->kemSkSize > prv->valueLen) {
        return PQCP_FRODOKEM_INVALID_ARG;
    }
    if (ctx->privateKey == NULL) {
        ctx->privateKey = BSL_SAL_Calloc(ctx->para->kemSkSize, sizeof(uint8_t));
        if (ctx->privateKey == NULL) {
            return PQCP_MEM_ALLOC_FAIL;
        }
    }

    uint32_t useLen = ctx->para->kemSkSize;
    (void)memcpy_s(ctx->privateKey, useLen, prv->value, useLen);
    return PQCP_SUCCESS;
}

int32_t PQCP_FRODOKEM_SetPubKey(FrodoKEM_Ctx* ctx, BSL_Param* param)
{
    if (ctx == NULL || ctx->para == NULL || param == NULL) {
        return PQCP_NULL_INPUT;
    }
    const BSL_Param* pub = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_FRODOKEM_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->para->pkSize > pub->valueLen) {
        return PQCP_FRODOKEM_INVALID_ARG;
    }
    if (ctx->publicKey == NULL) {
        ctx->publicKey = BSL_SAL_Calloc(ctx->para->pkSize, sizeof(uint8_t));
        if (ctx->publicKey == NULL) {
            return PQCP_MEM_ALLOC_FAIL;
        }
    }

    uint32_t useLen = ctx->para->pkSize;
    (void)memcpy_s(ctx->publicKey, useLen, pub->value, useLen);
    return PQCP_SUCCESS;
}

int32_t PQCP_FRODOKEM_GetPrvKey(FrodoKEM_Ctx* ctx, BSL_Param* param)
{
    if (ctx == NULL || ctx->para == NULL || param == NULL) {
        return PQCP_NULL_INPUT;
    }
    BSL_Param* prv = BSL_PARAM_FindParam(param, CRYPT_PARAM_FRODOKEM_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->privateKey == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->para->kemSkSize > prv->valueLen) {
        return PQCP_FRODOKEM_INVALID_ARG;
    }
    uint32_t useLen = ctx->para->kemSkSize;
    (void)memcpy_s(prv->value, useLen, ctx->privateKey, useLen);
    prv->useLen = useLen;
    return PQCP_SUCCESS;
}

int32_t PQCP_FRODOKEM_GetPubKey(FrodoKEM_Ctx* ctx, BSL_Param* param)
{
    if (ctx == NULL || ctx->para == NULL || param == NULL) {
        return PQCP_NULL_INPUT;
    }
    BSL_Param* pub = BSL_PARAM_FindParam(param, CRYPT_PARAM_FRODOKEM_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->publicKey == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->para->pkSize > pub->valueLen) {
        return PQCP_FRODOKEM_INVALID_ARG;
    }
    uint32_t useLen = ctx->para->pkSize;
    (void)memcpy_s(pub->value, useLen, ctx->publicKey, useLen);
    pub->useLen = useLen;
    return PQCP_SUCCESS;
}

FrodoKEM_Ctx* PQCP_FRODOKEM_DupCtx(FrodoKEM_Ctx* src)
{
    if (src == NULL) {
        return NULL;
    }
    FrodoKEM_Ctx* ctx = PQCP_FRODOKEM_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    if (src->para != NULL) {
        ctx->para = BSL_SAL_Malloc(sizeof(FrodoKemParams));
        if (ctx->para == NULL) {
            PQCP_FRODOKEM_FreeCtx(ctx);
            return NULL;
        }
        (void)memcpy_s(ctx->para, sizeof(FrodoKemParams), src->para, sizeof(FrodoKemParams));
    }
    if (src->publicKey != NULL) {
        ctx->publicKey = BSL_SAL_Calloc(src->para->pkSize, sizeof(uint8_t));
        if (ctx->publicKey == NULL) {
            PQCP_FRODOKEM_FreeCtx(ctx);
            return NULL;
        }
        (void)memcpy_s(ctx->publicKey, ctx->para->pkSize, src->publicKey, ctx->para->pkSize);
    }
    if (src->privateKey != NULL) {
        ctx->privateKey = BSL_SAL_Calloc(src->para->kemSkSize, sizeof(uint8_t));
        if (ctx->privateKey == NULL) {
            PQCP_FRODOKEM_FreeCtx(ctx);
            return NULL;
        }
        (void)memcpy_s(ctx->privateKey, ctx->para->kemSkSize, src->privateKey, ctx->para->kemSkSize);
    }
    return ctx;
}

int32_t PQCP_FRODOKEM_Cmp(FrodoKEM_Ctx* ctx1, FrodoKEM_Ctx* ctx2)
{
    if (ctx1 == NULL || ctx2 == NULL || ctx1->para == NULL || ctx2->para == NULL) {
        return PQCP_NULL_INPUT;
    };
    if (memcmp(ctx1->para, ctx2->para, sizeof(FrodoKEM_Ctx)) != 0) {
        return PQCP_FRODOKEM_CMP_FALSE;
    }
    if (ctx1->publicKey != NULL && ctx2->publicKey != NULL) {
        if (memcmp(ctx1->publicKey, ctx2->publicKey, ctx1->para->pkSize) != 0) {
            return PQCP_FRODOKEM_CMP_FALSE;
        }
    }
    if (ctx1->privateKey != NULL && ctx2->privateKey != NULL) {
        if (memcmp(ctx1->privateKey, ctx2->privateKey, ctx1->para->kemSkSize) != 0) {
            return PQCP_FRODOKEM_CMP_FALSE;
        }
    }
    return PQCP_SUCCESS;
}

int32_t PQCP_FRODOKEM_Ctrl(FrodoKEM_Ctx* ctx, int32_t cmd, void* val, uint32_t valLen)
{
    if (ctx == NULL) {
        return PQCP_NULL_INPUT;
    }
    switch (cmd) {
        case PQCP_FRODOKEM_ALG_PARAMS:
            {
                if (val == NULL || valLen != sizeof(uint32_t)) {
                    return PQCP_NULL_INPUT;
                }
                int32_t algId = *(int32_t*)val;
                ctx->para = FrodoGetParamsById(algId);
                if (ctx->para == NULL) {
                    return PQCP_FRODOKEM_INVALID_ARG;
                }
                return PQCP_SUCCESS;
            }
        case PQCP_FRODOKEM_GET_PARA:
            {
                if (ctx->para == NULL || val == NULL || valLen != sizeof(FrodoKemParams)) {
                    return PQCP_NULL_INPUT;
                }
                (void)memcpy_s(val, sizeof(FrodoKemParams), ctx->para, sizeof(FrodoKemParams));
                return PQCP_SUCCESS;
            }
        case PQCP_FRODOKEM_GET_CIPHERLEN:
            {
                if (ctx->para == NULL || val == NULL || valLen != sizeof(uint32_t)) {
                    return PQCP_NULL_INPUT;
                }
                *(uint32_t*)val = ctx->para->ctxSize;
                return PQCP_SUCCESS;
            }
        case PQCP_FRODOKEM_GET_SECBITS:
            {
                if (ctx->para == NULL || val == NULL || valLen != sizeof(uint32_t)) {
                    return PQCP_NULL_INPUT;
                }
                *(uint32_t*)val = ctx->para->ss * 8;
                return PQCP_SUCCESS;
            }
        default:
            return PQCP_FRODOKEM_INVALID_ARG;
    }
}

void PQCP_FRODOKEM_FreeCtx(FrodoKEM_Ctx* ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->publicKey != NULL) {
        BSL_SAL_FREE(ctx->publicKey);
    }
    if (ctx->privateKey != NULL) {
        BSL_SAL_FREE(ctx->privateKey);
    }
    BSL_SAL_FREE(ctx);
}

int32_t PQCP_FRODOKEM_EncapsInit(FrodoKEM_Ctx* ctx, const BSL_Param* params)
{
    (void)ctx;
    (void)params;
    return 0;
}

int32_t PQCP_FRODOKEM_DecapsInit(FrodoKEM_Ctx* ctx, const BSL_Param* params)
{
    (void)ctx;
    (void)params;
    return 0;
}

int32_t PQCP_FRODOKEM_Encaps(FrodoKEM_Ctx* ctx, uint8_t* ciphertext, uint32_t* ctLen, uint8_t* sharedSecret,
                             uint32_t* ssLen)
{
    if (ctx == NULL || ctx->para == NULL || ctx->publicKey == NULL || ciphertext == NULL || sharedSecret == NULL) {
        return PQCP_NULL_INPUT;
    }
    *ssLen = ctx->para->ss;
    *ctLen = ctx->para->ctxSize;
    return FrodoKemEncaps(ctx->para, ciphertext, sharedSecret, ctx->publicKey);
}

int32_t PQCP_FRODOKEM_Decaps(FrodoKEM_Ctx* ctx, const uint8_t* ciphertext, uint32_t ctLen, uint8_t* sharedSecret,
                             uint32_t* ssLen)
{
    if (ctx == NULL || ctx->para == NULL || ctx->privateKey == NULL || ciphertext == NULL || sharedSecret == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctLen != ctx->para->ctxSize) {
        return PQCP_FRODOKEM_INVALID_ARG;
    }

    *ssLen = ctx->para->ss;
    return FrodoKemDecaps(ctx->para, sharedSecret, ciphertext, ctx->privateKey);
}
