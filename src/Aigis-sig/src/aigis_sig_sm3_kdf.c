/* Copyright (c) 2025 LiuRuikang
 * School Of Cyber Engineering, Xidian University
 *
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

#include <string.h>

#include "aigis_sig_sm3_kdf.h"
#include "bsl_sal.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_md.h"
#include "crypt_sm3.h"
#include "crypt_types.h"
#include "pqcp_err.h"

static const uint8_t g_aigisSigSm3Key[64] = {
    0x53, 0x07, 0xf6, 0xd5, 0xeb, 0x6a, 0x3c, 0xed, 0x3d, 0x24, 0xc5, 0x3c, 0xc9, 0xc8, 0x2c, 0xce,
    0x2f, 0x89, 0x36, 0x39, 0x70, 0x23, 0xf0, 0x69, 0x5c, 0x26, 0xc8, 0x0c, 0x1a, 0xb1, 0x82, 0xa7,
    0x1d, 0xb0, 0x2b, 0xa9, 0x2f, 0x54, 0x40, 0x18, 0x11, 0x5a, 0x96, 0xe7, 0x19, 0x66, 0x2c, 0xa3,
    0x2b, 0x7c, 0x7e, 0xfc, 0x0a, 0x6d, 0x24, 0x82, 0x15, 0x07, 0x66, 0xba, 0x6f, 0x65, 0x5b, 0x8e};

static int32_t Sm3Digest(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t out[32])
{
    if ((in == NULL && inLen != 0U) || out == NULL) {
        return PQCP_NULL_INPUT;
    }
    uint32_t outLen = 32U;
    return CRYPT_EAL_ProviderMd(libCtx, CRYPT_MD_SM3, NULL, in, inLen, out, &outLen);
}

static int32_t Sm3DigestCtx(CRYPT_EAL_MdCtx *mdCtx, const uint8_t *in, uint32_t inLen, uint8_t out[32])
{
    if (mdCtx == NULL || (in == NULL && inLen != 0U) || out == NULL) {
        return PQCP_NULL_INPUT;
    }
    uint32_t outLen = 32U;
    int32_t ret = CRYPT_EAL_MdInit(mdCtx);
    if (ret == PQCP_SUCCESS && inLen != 0U) {
        ret = CRYPT_EAL_MdUpdate(mdCtx, in, inLen);
    }
    if (ret == PQCP_SUCCESS) {
        ret = CRYPT_EAL_MdFinal(mdCtx, out, &outLen);
    }
    int32_t deinitRet = CRYPT_EAL_MdDeinit(mdCtx);
    if (ret == PQCP_SUCCESS) {
        ret = deinitRet;
    }
    if (ret == PQCP_SUCCESS && outLen != 32U) {
        ret = PQCP_INVALID_ARG;
    }
    return ret;
}

static int32_t Sm3DirectDigestCtx(CRYPT_SM3_Ctx *mdCtx, const uint8_t *in, uint32_t inLen, uint8_t out[32])
{
    uint32_t outLen = 32U;
    int32_t ret = CRYPT_SM3_Init(mdCtx);
    if (ret == PQCP_SUCCESS && inLen != 0U) {
        ret = CRYPT_SM3_Update(mdCtx, in, inLen);
    }
    if (ret == PQCP_SUCCESS) {
        ret = CRYPT_SM3_Final(mdCtx, out, &outLen);
    }
    const int32_t deinitRet = CRYPT_SM3_Deinit(mdCtx);
    if (ret == PQCP_SUCCESS) {
        ret = deinitRet;
    }
    if (ret == PQCP_SUCCESS && outLen != 32U) {
        ret = PQCP_INVALID_ARG;
    }
    return ret;
}

int32_t PQCP_AIGIS_SIG_Sm3Hash256(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t out[32])
{
    return Sm3Digest(libCtx, in, inLen, out);
}

static int32_t Sm3Hmac(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t out[32])
{
    if ((in == NULL && inLen != 0U) || out == NULL) {
        return PQCP_NULL_INPUT;
    }

    CRYPT_EAL_MacCtx *macCtx = CRYPT_EAL_ProviderMacNewCtx(libCtx, CRYPT_MAC_HMAC_SM3, NULL);
    if (macCtx == NULL) {
        return PQCP_MEM_ALLOC_FAIL;
    }

    int32_t ret = CRYPT_EAL_MacInit(macCtx, g_aigisSigSm3Key, sizeof(g_aigisSigSm3Key));
    if (ret == PQCP_SUCCESS && inLen != 0U) {
        ret = CRYPT_EAL_MacUpdate(macCtx, in, inLen);
    }
    uint32_t outLen = 32U;
    if (ret == PQCP_SUCCESS) {
        ret = CRYPT_EAL_MacFinal(macCtx, out, &outLen);
    }
    if (ret == PQCP_SUCCESS && outLen != 32U) {
        ret = PQCP_INVALID_ARG;
    }
    CRYPT_EAL_MacFreeCtx(macCtx);
    return ret;
}

int32_t PQCP_AIGIS_SIG_Sm3PseudoHash512(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t out[64])
{
    if ((in == NULL && inLen != 0U) || out == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (inLen > UINT32_MAX - 2U) {
        return PQCP_INVALID_ARG;
    }
    uint8_t *prefixed = BSL_SAL_Malloc(inLen + 2U);
    uint8_t *suffixed = BSL_SAL_Malloc(inLen + 2U);
    if (prefixed == NULL || suffixed == NULL) {
        BSL_SAL_FREE(prefixed);
        BSL_SAL_FREE(suffixed);
        return PQCP_MEM_ALLOC_FAIL;
    }
    prefixed[0] = 0x02U;
    prefixed[1] = 0x00U;
    if (inLen != 0U) {
        (void)memcpy(prefixed + 2U, in, inLen);
        (void)memcpy(suffixed, in, inLen);
    }
    suffixed[inLen] = 0x02U;
    suffixed[inLen + 1U] = 0x00U;
    CRYPT_EAL_MdCtx *mdCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_SM3, NULL);
    if (mdCtx == NULL) {
        BSL_SAL_CleanseData(prefixed, inLen + 2U);
        BSL_SAL_CleanseData(suffixed, inLen + 2U);
        BSL_SAL_FREE(prefixed);
        BSL_SAL_FREE(suffixed);
        return PQCP_MEM_ALLOC_FAIL;
    }
    uint8_t k1[32];
    uint8_t h1[32];
    uint8_t chain[64];
    int32_t ret = Sm3Hmac(libCtx, prefixed, inLen + 2U, k1);
    if (ret == PQCP_SUCCESS) {
        ret = Sm3DigestCtx(mdCtx, suffixed, inLen + 2U, h1);
    }
    if (ret == PQCP_SUCCESS) {
        (void)memcpy(chain, k1, 32U);
        (void)memcpy(chain + 32U, h1, 32U);
        (void)memcpy(out, h1, 32U);
        ret = Sm3DigestCtx(mdCtx, chain, sizeof(chain), out + 32U);
    }
    CRYPT_EAL_MdFreeCtx(mdCtx);
    BSL_SAL_CleanseData(k1, sizeof(k1));
    BSL_SAL_CleanseData(h1, sizeof(h1));
    BSL_SAL_CleanseData(chain, sizeof(chain));
    BSL_SAL_CleanseData(prefixed, inLen + 2U);
    BSL_SAL_CleanseData(suffixed, inLen + 2U);
    BSL_SAL_FREE(prefixed);
    BSL_SAL_FREE(suffixed);
    return ret;
}

static int32_t Sm3PseudoXofCtx(CRYPT_SM3_Ctx *mdCtx, CRYPT_SM3_Ctx *prefixCtx, uint8_t *blockInput,
                               const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen)
{
    if (inLen != 0U) {
        (void)memcpy(blockInput, in, inLen);
    }
    const uint32_t prefixLen = inLen & ~63U;
    if (prefixLen == 0U) {
        uint32_t counter = 1U;
        uint32_t offset = 0U;
        uint8_t digest[32];
        int32_t ret = PQCP_SUCCESS;
        while (offset < outLen) {
            blockInput[inLen] = (uint8_t)(counter >> 24);
            blockInput[inLen + 1U] = (uint8_t)(counter >> 16);
            blockInput[inLen + 2U] = (uint8_t)(counter >> 8);
            blockInput[inLen + 3U] = (uint8_t)counter;
            ret = Sm3DirectDigestCtx(mdCtx, blockInput, inLen + 4U, digest);
            if (ret != PQCP_SUCCESS) {
                break;
            }
            const uint32_t take = outLen - offset < sizeof(digest) ? outLen - offset : sizeof(digest);
            (void)memcpy(out + offset, digest, take);
            offset += take;
            counter++;
        }
        BSL_SAL_CleanseData(digest, sizeof(digest));
        return ret;
    }

    int32_t ret = CRYPT_SM3_Init(prefixCtx);
    if (ret == PQCP_SUCCESS) {
        ret = CRYPT_SM3_Update(prefixCtx, blockInput, prefixLen);
    }
    uint32_t counter = 1U;
    uint32_t offset = 0U;
    uint8_t digest[32];
    while (ret == PQCP_SUCCESS && offset < outLen) {
        blockInput[inLen] = (uint8_t)(counter >> 24);
        blockInput[inLen + 1U] = (uint8_t)(counter >> 16);
        blockInput[inLen + 2U] = (uint8_t)(counter >> 8);
        blockInput[inLen + 3U] = (uint8_t)counter;
        ret = CRYPT_SM3_CopyCtx(mdCtx, prefixCtx);
        if (ret == PQCP_SUCCESS) {
            ret = CRYPT_SM3_Update(mdCtx, blockInput + prefixLen, inLen + 4U - prefixLen);
        }
        uint32_t digestLen = sizeof(digest);
        if (ret == PQCP_SUCCESS) {
            ret = CRYPT_SM3_Final(mdCtx, digest, &digestLen);
        }
        if (ret == PQCP_SUCCESS && digestLen != sizeof(digest)) {
            ret = PQCP_INVALID_ARG;
        }
        if (ret != PQCP_SUCCESS) {
            break;
        }
        const uint32_t take = outLen - offset < sizeof(digest) ? outLen - offset : sizeof(digest);
        (void)memcpy(out + offset, digest, take);
        offset += take;
        counter++;
    }
    const int32_t deinitRet = CRYPT_SM3_Deinit(prefixCtx);
    if (ret == PQCP_SUCCESS) {
        ret = deinitRet;
    }
    BSL_SAL_CleanseData(digest, sizeof(digest));
    return ret;
}

int32_t PQCP_AIGIS_SIG_Sm3PseudoXof(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen)
{
    if ((in == NULL && inLen != 0U) || (out == NULL && outLen != 0U)) {
        return PQCP_NULL_INPUT;
    }
    if (inLen > UINT32_MAX - 4U) {
        return PQCP_INVALID_ARG;
    }
    if (outLen == 0U) {
        return PQCP_SUCCESS;
    }
    uint8_t *blockInput = BSL_SAL_Malloc(inLen + 4U);
    if (blockInput == NULL) {
        return PQCP_MEM_ALLOC_FAIL;
    }
    CRYPT_EAL_MdCtx *mdCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_SM3, NULL);
    if (mdCtx == NULL) {
        BSL_SAL_CleanseData(blockInput, inLen + 4U);
        BSL_SAL_FREE(blockInput);
        return PQCP_MEM_ALLOC_FAIL;
    }
    if (inLen != 0U) {
        (void)memcpy(blockInput, in, inLen);
    }
    uint32_t counter = 1U;
    uint32_t offset = 0U;
    uint8_t digest[32];
    int32_t ret = PQCP_SUCCESS;
    while (offset < outLen) {
        blockInput[inLen] = (uint8_t)(counter >> 24);
        blockInput[inLen + 1U] = (uint8_t)(counter >> 16);
        blockInput[inLen + 2U] = (uint8_t)(counter >> 8);
        blockInput[inLen + 3U] = (uint8_t)counter;
        ret = Sm3DigestCtx(mdCtx, blockInput, inLen + 4U, digest);
        if (ret != PQCP_SUCCESS) {
            break;
        }
        uint32_t take = outLen - offset < sizeof(digest) ? outLen - offset : sizeof(digest);
        (void)memcpy(out + offset, digest, take);
        offset += take;
        counter++;
    }
    BSL_SAL_CleanseData(digest, sizeof(digest));
    BSL_SAL_CleanseData(blockInput, inLen + 4U);
    BSL_SAL_FREE(blockInput);
    CRYPT_EAL_MdFreeCtx(mdCtx);
    return ret;
}

int32_t PQCP_AIGIS_SIG_Sm3PseudoXofBatchInit(PQCP_AIGIS_SIG_Sm3PseudoXofBatchCtx *ctx, void *libCtx, uint32_t inputLen)
{
    if (ctx == NULL) {
        return PQCP_NULL_INPUT;
    }
    (void)memset(ctx, 0, sizeof(*ctx));
    if (inputLen > UINT32_MAX - 4U) {
        return PQCP_INVALID_ARG;
    }
    ctx->blockInput = BSL_SAL_Malloc(inputLen + 4U);
    if (ctx->blockInput == NULL) {
        return PQCP_MEM_ALLOC_FAIL;
    }
    (void)libCtx;
    ctx->mdCtx = CRYPT_SM3_NewCtx();
    ctx->prefixCtx = CRYPT_SM3_NewCtx();
    if (ctx->mdCtx == NULL || ctx->prefixCtx == NULL) {
        BSL_SAL_CleanseData(ctx->blockInput, inputLen + 4U);
        BSL_SAL_FREE(ctx->blockInput);
        ctx->blockInput = NULL;
        CRYPT_SM3_FreeCtx(ctx->mdCtx);
        CRYPT_SM3_FreeCtx(ctx->prefixCtx);
        ctx->mdCtx = NULL;
        ctx->prefixCtx = NULL;
        return PQCP_MEM_ALLOC_FAIL;
    }
    ctx->inputLen = inputLen;
    return PQCP_SUCCESS;
}

int32_t PQCP_AIGIS_SIG_Sm3PseudoXofBatchGenerate(PQCP_AIGIS_SIG_Sm3PseudoXofBatchCtx *ctx, const uint8_t *in,
                                                 uint8_t *out, uint32_t outLen)
{
    if (ctx == NULL || ctx->mdCtx == NULL || ctx->prefixCtx == NULL || ctx->blockInput == NULL ||
        (in == NULL && ctx->inputLen != 0U) || (out == NULL && outLen != 0U)) {
        return PQCP_NULL_INPUT;
    }
    return Sm3PseudoXofCtx(ctx->mdCtx, ctx->prefixCtx, ctx->blockInput, in, ctx->inputLen, out, outLen);
}

void PQCP_AIGIS_SIG_Sm3PseudoXofBatchFree(PQCP_AIGIS_SIG_Sm3PseudoXofBatchCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->blockInput != NULL) {
        BSL_SAL_CleanseData(ctx->blockInput, ctx->inputLen + 4U);
        BSL_SAL_FREE(ctx->blockInput);
        ctx->blockInput = NULL;
    }
    CRYPT_SM3_FreeCtx(ctx->mdCtx);
    CRYPT_SM3_FreeCtx(ctx->prefixCtx);
    ctx->mdCtx = NULL;
    ctx->prefixCtx = NULL;
    ctx->inputLen = 0U;
}

int32_t PQCP_AIGIS_SIG_Sm3PseudoXofTwoSegment(void *libCtx, const uint8_t *in1, uint32_t in1Len, const uint8_t *in2,
                                              uint32_t in2Len, uint8_t *out, uint32_t outLen)
{
    if ((in1 == NULL && in1Len != 0U) || (in2 == NULL && in2Len != 0U) || (out == NULL && outLen != 0U)) {
        return PQCP_NULL_INPUT;
    }
    if (in1Len > UINT32_MAX - in2Len || in1Len + in2Len > UINT32_MAX - 4U) {
        return PQCP_INVALID_ARG;
    }
    if (outLen == 0U) {
        return PQCP_SUCCESS;
    }
    CRYPT_EAL_MdCtx *mdCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_SM3, NULL);
    if (mdCtx == NULL) {
        return PQCP_MEM_ALLOC_FAIL;
    }
    uint32_t counter = 1U;
    uint32_t offset = 0U;
    uint8_t counterBytes[4];
    uint8_t digest[32];
    int32_t ret = PQCP_SUCCESS;
    while (offset < outLen) {
        counterBytes[0] = (uint8_t)(counter >> 24);
        counterBytes[1] = (uint8_t)(counter >> 16);
        counterBytes[2] = (uint8_t)(counter >> 8);
        counterBytes[3] = (uint8_t)counter;
        uint32_t digestLen = sizeof(digest);
        ret = CRYPT_EAL_MdInit(mdCtx);
        if (ret == PQCP_SUCCESS && in1Len != 0U) {
            ret = CRYPT_EAL_MdUpdate(mdCtx, in1, in1Len);
        }
        if (ret == PQCP_SUCCESS && in2Len != 0U) {
            ret = CRYPT_EAL_MdUpdate(mdCtx, in2, in2Len);
        }
        if (ret == PQCP_SUCCESS) {
            ret = CRYPT_EAL_MdUpdate(mdCtx, counterBytes, sizeof(counterBytes));
        }
        if (ret == PQCP_SUCCESS) {
            ret = CRYPT_EAL_MdFinal(mdCtx, digest, &digestLen);
        }
        int32_t deinitRet = CRYPT_EAL_MdDeinit(mdCtx);
        if (ret == PQCP_SUCCESS) {
            ret = deinitRet;
        }
        if (ret == PQCP_SUCCESS && digestLen != sizeof(digest)) {
            ret = PQCP_INVALID_ARG;
        }
        if (ret != PQCP_SUCCESS) {
            break;
        }
        uint32_t take = outLen - offset < sizeof(digest) ? outLen - offset : sizeof(digest);
        (void)memcpy(out + offset, digest, take);
        offset += take;
        counter++;
    }
    BSL_SAL_CleanseData(digest, sizeof(digest));
    CRYPT_EAL_MdFreeCtx(mdCtx);
    return ret;
}

static void IncrementBigEndian(uint8_t *value, uint32_t len)
{
    while (len != 0U) {
        len--;
        value[len]++;
        if (value[len] != 0U) {
            break;
        }
    }
}

static void AddFourBigEndian(uint8_t *dst, const uint8_t *a, const uint8_t *b, const uint8_t *c, uint32_t len)
{
    uint32_t carry = 0U;
    while (len != 0U) {
        len--;
        uint32_t sum = (uint32_t)dst[len] + a[len] + b[len] + c[len] + carry;
        dst[len] = (uint8_t)sum;
        carry = sum >> 8;
    }
}

static int32_t Sm3Df(CRYPT_SM3_Ctx *mdCtx, const uint8_t *in, uint32_t inLen,
                     uint8_t out[PQCP_AIGIS_SIG_SM3_SEED_LEN])
{
    if ((in == NULL && inLen != 0U) || inLen > UINT32_MAX - 5U) {
        return PQCP_INVALID_ARG;
    }
    uint8_t prefix[5] = {0U, 0U, 0U, 0x01U, 0xb8U}; /* 55 * 8, big endian. */
    uint8_t digest[32];
    uint32_t offset = 0U;
    int32_t ret = PQCP_SUCCESS;
    for (uint8_t counter = 1U; offset < PQCP_AIGIS_SIG_SM3_SEED_LEN; counter++) {
        prefix[0] = counter;
        uint32_t digestLen = sizeof(digest);
        ret = CRYPT_SM3_Init(mdCtx);
        if (ret == PQCP_SUCCESS) {
            ret = CRYPT_SM3_Update(mdCtx, prefix, sizeof(prefix));
        }
        if (ret == PQCP_SUCCESS && inLen != 0U) {
            ret = CRYPT_SM3_Update(mdCtx, in, inLen);
        }
        if (ret == PQCP_SUCCESS) {
            ret = CRYPT_SM3_Final(mdCtx, digest, &digestLen);
        }
        int32_t deinitRet = CRYPT_SM3_Deinit(mdCtx);
        if (ret == PQCP_SUCCESS) {
            ret = deinitRet;
        }
        if (ret == PQCP_SUCCESS && digestLen != sizeof(digest)) {
            ret = PQCP_INVALID_ARG;
        }
        if (ret != PQCP_SUCCESS) {
            break;
        }
        uint32_t take = PQCP_AIGIS_SIG_SM3_SEED_LEN - offset;
        if (take > sizeof(digest)) {
            take = sizeof(digest);
        }
        (void)memcpy(out + offset, digest, take);
        offset += take;
    }
    BSL_SAL_CleanseData(digest, sizeof(digest));
    return ret;
}

int32_t PQCP_AIGIS_SIG_Sm3DrngInit(PQCP_AIGIS_SIG_Sm3DrngCtx *ctx, void *libCtx, const uint8_t *seed, uint32_t seedLen)
{
    if (ctx == NULL || (seed == NULL && seedLen != 0U)) {
        return PQCP_NULL_INPUT;
    }
    (void)memset(ctx, 0, sizeof(*ctx));
    ctx->libCtx = libCtx;
    ctx->mdCtx = CRYPT_SM3_NewCtx();
    if (ctx->mdCtx == NULL) {
        return PQCP_MEM_ALLOC_FAIL;
    }
    int32_t ret = Sm3Df(ctx->mdCtx, seed, seedLen, ctx->v);
    uint8_t padded[1U + PQCP_AIGIS_SIG_SM3_SEED_LEN] = {0};
    if (ret == PQCP_SUCCESS) {
        (void)memcpy(padded + 1U, ctx->v, sizeof(ctx->v));
        ret = Sm3Df(ctx->mdCtx, padded, sizeof(padded), ctx->c);
    }
    if (ret == PQCP_SUCCESS) {
        IncrementBigEndian(ctx->reseedCounter, sizeof(ctx->reseedCounter));
        ctx->initialized = 1U;
    } else {
        PQCP_AIGIS_SIG_Sm3DrngFree(ctx);
    }
    BSL_SAL_CleanseData(padded, sizeof(padded));
    return ret;
}

int32_t PQCP_AIGIS_SIG_Sm3DrngGenerate(PQCP_AIGIS_SIG_Sm3DrngCtx *ctx, uint8_t *out, uint32_t outLen)
{
    if (ctx == NULL || ctx->initialized == 0U || (out == NULL && outLen != 0U)) {
        return PQCP_NULL_INPUT;
    }
    uint8_t data[PQCP_AIGIS_SIG_SM3_SEED_LEN];
    uint8_t digest[32];
    (void)memcpy(data, ctx->v, sizeof(data));
    uint32_t offset = 0U;
    int32_t ret = PQCP_SUCCESS;
    while (offset < outLen) {
        ret = Sm3DirectDigestCtx(ctx->mdCtx, data, sizeof(data), digest);
        if (ret != PQCP_SUCCESS) {
            break;
        }
        uint32_t take = outLen - offset < sizeof(digest) ? outLen - offset : sizeof(digest);
        (void)memcpy(out + offset, digest, take);
        offset += take;
        IncrementBigEndian(data, sizeof(data));
    }
    if (ret == PQCP_SUCCESS) {
        uint8_t padded[1U + PQCP_AIGIS_SIG_SM3_SEED_LEN] = {0};
        uint8_t h[PQCP_AIGIS_SIG_SM3_SEED_LEN] = {0};
        padded[0] = 0x03U;
        (void)memcpy(padded + 1U, ctx->v, sizeof(ctx->v));
        ret = Sm3DirectDigestCtx(ctx->mdCtx, padded, sizeof(padded), h + PQCP_AIGIS_SIG_SM3_SEED_LEN - 32U);
        if (ret == PQCP_SUCCESS) {
            AddFourBigEndian(ctx->v, h, ctx->c, ctx->reseedCounter, sizeof(ctx->v));
            IncrementBigEndian(ctx->reseedCounter, sizeof(ctx->reseedCounter));
        }
        BSL_SAL_CleanseData(padded, sizeof(padded));
        BSL_SAL_CleanseData(h, sizeof(h));
    }
    BSL_SAL_CleanseData(data, sizeof(data));
    BSL_SAL_CleanseData(digest, sizeof(digest));
    return ret;
}

void PQCP_AIGIS_SIG_Sm3DrngFree(PQCP_AIGIS_SIG_Sm3DrngCtx *ctx)
{
    if (ctx != NULL) {
        CRYPT_SM3_FreeCtx(ctx->mdCtx);
        ctx->mdCtx = NULL;
        BSL_SAL_CleanseData(ctx, sizeof(*ctx));
    }
}

#endif
