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

#include <string.h>

#include "aigis_sig_sha3_kdf.h"
#include "aigis_sig_sha3_cache.h"
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_eal_md.h"
#include "pqcp_err.h"

static uint64_t Load64Le(const uint8_t input[8])
{
    uint64_t value;
    (void)memcpy(&value, input, sizeof(value));
#ifdef HITLS_BIG_ENDIAN
    value = __builtin_bswap64(value);
#endif
    return value;
}

static void Store64Le(uint8_t output[8], uint64_t value)
{
#ifdef HITLS_BIG_ENDIAN
    value = __builtin_bswap64(value);
#endif
    (void)memcpy(output, &value, sizeof(value));
}

#ifndef PQCP_AIGIS_SIG_ARMV8_BACKEND
static uint64_t RotateLeft64(uint64_t value, uint32_t shift)
{
    return shift == 0U ? value : (value << shift) | (value >> (64U - shift));
}

/* Keccak-f[1600] expressed directly from the FIPS 202 theta, rho, pi,
 * chi and iota mappings.  The fixed lane map avoids division/modulo in
 * the permutation hot path and keeps the implementation PQCP-private.
 * The row-local Rho/Pi/Chi schedule follows the portable implementation
 * in openHiTLS commit 6482a94f8ff930fec9950f0c4eb86a40cac4f8ff,
 * crypto/sha3/src/public_sha3.c; no openHiTLS private ABI is used. */
static const uint64_t AIGIS_KECCAK_ROUND_CONSTANTS[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082), UINT64_C(0x800000000000808a),
    UINT64_C(0x8000000080008000), UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009), UINT64_C(0x000000000000008a),
    UINT64_C(0x0000000000000088), UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
    UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b), UINT64_C(0x8000000000008089),
    UINT64_C(0x8000000000008003), UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a), UINT64_C(0x8000000080008081),
    UINT64_C(0x8000000000008080), UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008),
};

__attribute__((always_inline)) static inline void AigisKeccakRound(const uint64_t input[25], uint64_t output[25],
                                                                   uint64_t roundConstant)
{
    const uint64_t c0 = input[0] ^ input[5] ^ input[10] ^ input[15] ^ input[20];
    const uint64_t c1 = input[1] ^ input[6] ^ input[11] ^ input[16] ^ input[21];
    const uint64_t c2 = input[2] ^ input[7] ^ input[12] ^ input[17] ^ input[22];
    const uint64_t c3 = input[3] ^ input[8] ^ input[13] ^ input[18] ^ input[23];
    const uint64_t c4 = input[4] ^ input[9] ^ input[14] ^ input[19] ^ input[24];
    const uint64_t d0 = c4 ^ RotateLeft64(c1, 1U);
    const uint64_t d1 = c0 ^ RotateLeft64(c2, 1U);
    const uint64_t d2 = c1 ^ RotateLeft64(c3, 1U);
    const uint64_t d3 = c2 ^ RotateLeft64(c4, 1U);
    const uint64_t d4 = c3 ^ RotateLeft64(c0, 1U);
    uint64_t b0 = input[0] ^ d0;
    uint64_t b1 = RotateLeft64(input[6] ^ d1, 44U);
    uint64_t b2 = RotateLeft64(input[12] ^ d2, 43U);
    uint64_t b3 = RotateLeft64(input[18] ^ d3, 21U);
    uint64_t b4 = RotateLeft64(input[24] ^ d4, 14U);

    output[0] = b0 ^ ((~b1) & b2) ^ roundConstant;
    output[1] = b1 ^ ((~b2) & b3);
    output[2] = b2 ^ ((~b3) & b4);
    output[3] = b3 ^ ((~b4) & b0);
    output[4] = b4 ^ ((~b0) & b1);

    b0 = RotateLeft64(input[3] ^ d3, 28U);
    b1 = RotateLeft64(input[9] ^ d4, 20U);
    b2 = RotateLeft64(input[10] ^ d0, 3U);
    b3 = RotateLeft64(input[16] ^ d1, 45U);
    b4 = RotateLeft64(input[22] ^ d2, 61U);
    output[5] = b0 ^ ((~b1) & b2);
    output[6] = b1 ^ ((~b2) & b3);
    output[7] = b2 ^ ((~b3) & b4);
    output[8] = b3 ^ ((~b4) & b0);
    output[9] = b4 ^ ((~b0) & b1);

    b0 = RotateLeft64(input[1] ^ d1, 1U);
    b1 = RotateLeft64(input[7] ^ d2, 6U);
    b2 = RotateLeft64(input[13] ^ d3, 25U);
    b3 = RotateLeft64(input[19] ^ d4, 8U);
    b4 = RotateLeft64(input[20] ^ d0, 18U);
    output[10] = b0 ^ ((~b1) & b2);
    output[11] = b1 ^ ((~b2) & b3);
    output[12] = b2 ^ ((~b3) & b4);
    output[13] = b3 ^ ((~b4) & b0);
    output[14] = b4 ^ ((~b0) & b1);

    b0 = RotateLeft64(input[4] ^ d4, 27U);
    b1 = RotateLeft64(input[5] ^ d0, 36U);
    b2 = RotateLeft64(input[11] ^ d1, 10U);
    b3 = RotateLeft64(input[17] ^ d2, 15U);
    b4 = RotateLeft64(input[23] ^ d3, 56U);
    output[15] = b0 ^ ((~b1) & b2);
    output[16] = b1 ^ ((~b2) & b3);
    output[17] = b2 ^ ((~b3) & b4);
    output[18] = b3 ^ ((~b4) & b0);
    output[19] = b4 ^ ((~b0) & b1);

    b0 = RotateLeft64(input[2] ^ d2, 62U);
    b1 = RotateLeft64(input[8] ^ d3, 55U);
    b2 = RotateLeft64(input[14] ^ d4, 39U);
    b3 = RotateLeft64(input[15] ^ d0, 41U);
    b4 = RotateLeft64(input[21] ^ d1, 2U);
    output[20] = b0 ^ ((~b1) & b2);
    output[21] = b1 ^ ((~b2) & b3);
    output[22] = b2 ^ ((~b3) & b4);
    output[23] = b3 ^ ((~b4) & b0);
    output[24] = b4 ^ ((~b0) & b1);
}
#endif

static void AigisKeccakF1600(uint64_t state[25])
{
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
    PQCP_AIGIS_SIG_KeccakF1600Armv8(state);
#else
    uint64_t temporary[25];
    for (uint32_t round = 0U; round < 24U; round += 2U) {
        AigisKeccakRound(state, temporary, AIGIS_KECCAK_ROUND_CONSTANTS[round]);
        AigisKeccakRound(temporary, state, AIGIS_KECCAK_ROUND_CONSTANTS[round + 1U]);
    }
    BSL_SAL_CleanseData(temporary, sizeof(temporary));
#endif
}

static void AigisKeccakRate72AbsorbBlock(uint64_t state[25], const uint8_t block[PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72])
{
    for (uint32_t i = 0U; i < PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72 / 8U; i++) {
        state[i] ^= Load64Le(block + 8U * i);
    }
}

static int32_t AigisKeccakRate72InitTwoSegment(PQCP_AIGIS_SIG_AigisKeccakXofRate72Ctx *ctx, const uint8_t *in1,
                                               uint32_t in1Len, const uint8_t *in2, uint32_t in2Len)
{
    if (ctx == NULL || (in1 == NULL && in1Len != 0U) || (in2 == NULL && in2Len != 0U)) {
        return PQCP_NULL_INPUT;
    }
    (void)memset(ctx, 0, sizeof(*ctx));
    uint8_t block[PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72] = {0};
    uint32_t blockLen = 0U;
    const uint8_t *segments[2] = {in1, in2};
    const uint32_t lengths[2] = {in1Len, in2Len};

    for (uint32_t segment = 0U; segment < 2U; segment++) {
        const uint8_t *input = segments[segment];
        uint32_t remaining = lengths[segment];
        while (remaining != 0U) {
            if (blockLen == 0U && remaining >= PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72) {
                AigisKeccakRate72AbsorbBlock(ctx->state, input);
                AigisKeccakF1600(ctx->state);
                input += PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72;
                remaining -= PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72;
                continue;
            }
            uint32_t take = PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72 - blockLen;
            if (take > remaining) {
                take = remaining;
            }
            (void)memcpy(block + blockLen, input, take);
            blockLen += take;
            input += take;
            remaining -= take;
            if (blockLen == PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72) {
                AigisKeccakRate72AbsorbBlock(ctx->state, block);
                AigisKeccakF1600(ctx->state);
                (void)memset(block, 0, sizeof(block));
                blockLen = 0U;
            }
        }
    }
    block[blockLen] = 0x1fU;
    block[PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72 - 1U] |= 0x80U;
    AigisKeccakRate72AbsorbBlock(ctx->state, block);
    ctx->offset = PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72;
    ctx->initialized = 1U;
    BSL_SAL_CleanseData(block, sizeof(block));
    return PQCP_SUCCESS;
}

static int32_t Sha3Digest(void *libCtx, uint32_t digestLen, const uint8_t *in, uint32_t inLen, uint8_t *out)
{
    if ((in == NULL && inLen != 0U) || out == NULL) {
        return PQCP_NULL_INPUT;
    }
    uint32_t outLen = digestLen;
    CRYPT_MD_AlgId algId = digestLen == 32U ? CRYPT_MD_SHA3_256 : CRYPT_MD_SHA3_512;
    int32_t ret = CRYPT_EAL_ProviderMd(libCtx, algId, NULL, in, inLen, out, &outLen);
    return ret == PQCP_SUCCESS && outLen != digestLen ? PQCP_INVALID_ARG : ret;
}

int32_t PQCP_AIGIS_SIG_Sha3Hash256(void *libCtx, PQCP_AIGIS_SIG_Sha3Cache *cache, const uint8_t *in, uint32_t inLen,
                                   uint8_t out[32])
{
    (void)cache;
    return Sha3Digest(libCtx, 32U, in, inLen, out);
}

int32_t PQCP_AIGIS_SIG_Sha3Hash512(void *libCtx, PQCP_AIGIS_SIG_Sha3Cache *cache, const uint8_t *in, uint32_t inLen,
                                   uint8_t out[64])
{
    (void)cache;
    return Sha3Digest(libCtx, 64U, in, inLen, out);
}

void PQCP_AIGIS_SIG_Sha3CacheFree(PQCP_AIGIS_SIG_Sha3Cache *cache)
{
    if (cache == NULL) {
        return;
    }
    CRYPT_EAL_MdFreeCtx(cache->shake128);
    CRYPT_EAL_MdFreeCtx(cache->shake256);
    BSL_SAL_CleanseData(cache, sizeof(*cache));
}

static void ShakeFree(PQCP_AIGIS_SIG_Shake256Ctx *ctx)
{
    if (ctx != NULL) {
        if (ctx->cached != 0U) {
            (void)CRYPT_EAL_MdDeinit(ctx->mdCtx);
        } else {
            CRYPT_EAL_MdFreeCtx(ctx->mdCtx);
        }
        ctx->mdCtx = NULL;
        ctx->cached = 0U;
    }
}

static int32_t ShakeInit(PQCP_AIGIS_SIG_Shake256Ctx *ctx, void *libCtx, PQCP_AIGIS_SIG_Sha3Cache *cache, uint32_t rate,
                         const uint8_t *in, uint32_t inLen)
{
    if (ctx == NULL || (in == NULL && inLen != 0U)) {
        return PQCP_NULL_INPUT;
    }
    ctx->mdCtx = NULL;
    ctx->cached = 0U;
    CRYPT_MD_AlgId algId = rate == PQCP_AIGIS_SIG_SHAKE128_RATE ? CRYPT_MD_SHAKE128 : CRYPT_MD_SHAKE256;
    if (cache != NULL) {
        CRYPT_EAL_MdCtx **cachedCtx = rate == PQCP_AIGIS_SIG_SHAKE128_RATE ? &cache->shake128 : &cache->shake256;
        if (*cachedCtx == NULL) {
            *cachedCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, algId, NULL);
        }
        if (*cachedCtx != NULL) {
            ctx->mdCtx = *cachedCtx;
            ctx->cached = 1U;
        }
    }
    if (ctx->mdCtx == NULL) {
        ctx->mdCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, algId, NULL);
    }
    if (ctx->mdCtx == NULL) {
        return PQCP_MEM_ALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_MdInit(ctx->mdCtx);
    if (ret == PQCP_SUCCESS && inLen != 0U) {
        ret = CRYPT_EAL_MdUpdate(ctx->mdCtx, in, inLen);
    }
    if (ret != PQCP_SUCCESS) {
        ShakeFree(ctx);
    }
    return ret;
}

static int32_t ShakeSqueeze(PQCP_AIGIS_SIG_Shake256Ctx *ctx, uint8_t *out, uint32_t outLen)
{
    if (ctx == NULL || ctx->mdCtx == NULL || (out == NULL && outLen != 0U)) {
        return PQCP_NULL_INPUT;
    }
    if (outLen == 0U) {
        return PQCP_SUCCESS;
    }
    return CRYPT_EAL_MdSqueeze(ctx->mdCtx, out, outLen);
}

int32_t PQCP_AIGIS_SIG_Shake128Init(PQCP_AIGIS_SIG_Shake128Ctx *ctx, void *libCtx, PQCP_AIGIS_SIG_Sha3Cache *cache,
                                    const uint8_t *in, uint32_t inLen)
{
    return ShakeInit(ctx, libCtx, cache, PQCP_AIGIS_SIG_SHAKE128_RATE, in, inLen);
}

int32_t PQCP_AIGIS_SIG_Shake256Init(PQCP_AIGIS_SIG_Shake256Ctx *ctx, void *libCtx, PQCP_AIGIS_SIG_Sha3Cache *cache,
                                    const uint8_t *in, uint32_t inLen)
{
    return ShakeInit(ctx, libCtx, cache, PQCP_AIGIS_SIG_SHAKE256_RATE, in, inLen);
}

int32_t PQCP_AIGIS_SIG_Shake256Squeeze(PQCP_AIGIS_SIG_Shake256Ctx *ctx, uint8_t *out, uint32_t outLen)
{
    return ShakeSqueeze(ctx, out, outLen);
}

void PQCP_AIGIS_SIG_Shake256Free(PQCP_AIGIS_SIG_Shake256Ctx *ctx)
{
    ShakeFree(ctx);
}

int32_t PQCP_AIGIS_SIG_Shake256(void *libCtx, PQCP_AIGIS_SIG_Sha3Cache *cache, const uint8_t *in, uint32_t inLen,
                                uint8_t *out, uint32_t outLen)
{
    if ((in == NULL && inLen != 0U) || (out == NULL && outLen != 0U)) {
        return PQCP_NULL_INPUT;
    }
    PQCP_AIGIS_SIG_Shake256Ctx ctx = {0};
    int32_t ret = PQCP_AIGIS_SIG_Shake256Init(&ctx, libCtx, cache, in, inLen);
    if (ret == PQCP_SUCCESS) {
        ret = PQCP_AIGIS_SIG_Shake256Squeeze(&ctx, out, outLen);
    }
    PQCP_AIGIS_SIG_Shake256Free(&ctx);
    return ret;
}

int32_t PQCP_AIGIS_SIG_Shake256TwoSegment(void *libCtx, PQCP_AIGIS_SIG_Sha3Cache *cache, const uint8_t *in1,
                                          uint32_t in1Len, const uint8_t *in2, uint32_t in2Len, uint8_t *out,
                                          uint32_t outLen)
{
    if ((in1 == NULL && in1Len != 0U) || (in2 == NULL && in2Len != 0U) || (out == NULL && outLen != 0U)) {
        return PQCP_NULL_INPUT;
    }
    PQCP_AIGIS_SIG_Shake256Ctx ctx = {0};
    int32_t ret = PQCP_AIGIS_SIG_Shake256Init(&ctx, libCtx, cache, in1, in1Len);
    if (ret == PQCP_SUCCESS && in2Len != 0U) {
        ret = CRYPT_EAL_MdUpdate(ctx.mdCtx, in2, in2Len);
    }
    if (ret == PQCP_SUCCESS) {
        ret = PQCP_AIGIS_SIG_Shake256Squeeze(&ctx, out, outLen);
    }
    PQCP_AIGIS_SIG_Shake256Free(&ctx);
    return ret;
}

int32_t PQCP_AIGIS_SIG_AigisKeccakXofRate72Init(PQCP_AIGIS_SIG_AigisKeccakXofRate72Ctx *ctx, const uint8_t *in,
                                                uint32_t inLen)
{
    return AigisKeccakRate72InitTwoSegment(ctx, in, inLen, NULL, 0U);
}

int32_t PQCP_AIGIS_SIG_AigisKeccakXofRate72Squeeze(PQCP_AIGIS_SIG_AigisKeccakXofRate72Ctx *ctx, uint8_t *out,
                                                   uint32_t outLen)
{
    if (ctx == NULL || ctx->initialized == 0U || (out == NULL && outLen != 0U)) {
        return PQCP_NULL_INPUT;
    }
    uint8_t block[PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72];
    uint32_t outputOffset = 0U;
    while (outputOffset < outLen) {
        if (ctx->offset == PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72) {
            AigisKeccakF1600(ctx->state);
            for (uint32_t i = 0U; i < PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72 / 8U; i++) {
                Store64Le(block + 8U * i, ctx->state[i]);
            }
            ctx->offset = 0U;
        }
        uint32_t take = PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72 - ctx->offset;
        if (take > outLen - outputOffset) {
            take = outLen - outputOffset;
        }
        if (take != 0U) {
            if (ctx->offset != 0U) {
                for (uint32_t i = 0U; i < PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72 / 8U; i++) {
                    Store64Le(block + 8U * i, ctx->state[i]);
                }
            }
            (void)memcpy(out + outputOffset, block + ctx->offset, take);
            ctx->offset += take;
            outputOffset += take;
        }
    }
    BSL_SAL_CleanseData(block, sizeof(block));
    return PQCP_SUCCESS;
}

void PQCP_AIGIS_SIG_AigisKeccakXofRate72Free(PQCP_AIGIS_SIG_AigisKeccakXofRate72Ctx *ctx)
{
    if (ctx != NULL) {
        BSL_SAL_CleanseData(ctx, sizeof(*ctx));
    }
}

int32_t PQCP_AIGIS_SIG_AigisKeccakXofRate72(const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen)
{
    if ((in == NULL && inLen != 0U) || (out == NULL && outLen != 0U)) {
        return PQCP_NULL_INPUT;
    }
    PQCP_AIGIS_SIG_AigisKeccakXofRate72Ctx ctx = {0};
    int32_t ret = PQCP_AIGIS_SIG_AigisKeccakXofRate72Init(&ctx, in, inLen);
    if (ret == PQCP_SUCCESS) {
        ret = PQCP_AIGIS_SIG_AigisKeccakXofRate72Squeeze(&ctx, out, outLen);
    }
    PQCP_AIGIS_SIG_AigisKeccakXofRate72Free(&ctx);
    return ret;
}

int32_t PQCP_AIGIS_SIG_AigisKeccakXofRate72TwoSegment(const uint8_t *in1, uint32_t in1Len, const uint8_t *in2,
                                                      uint32_t in2Len, uint8_t *out, uint32_t outLen)
{
    if ((in1 == NULL && in1Len != 0U) || (in2 == NULL && in2Len != 0U) || (out == NULL && outLen != 0U)) {
        return PQCP_NULL_INPUT;
    }
    PQCP_AIGIS_SIG_AigisKeccakXofRate72Ctx ctx = {0};
    int32_t ret = AigisKeccakRate72InitTwoSegment(&ctx, in1, in1Len, in2, in2Len);
    if (ret == PQCP_SUCCESS) {
        ret = PQCP_AIGIS_SIG_AigisKeccakXofRate72Squeeze(&ctx, out, outLen);
    }
    PQCP_AIGIS_SIG_AigisKeccakXofRate72Free(&ctx);
    return ret;
}

#endif
