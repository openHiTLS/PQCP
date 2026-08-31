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
#include "aigis_sig_local.h"

#include <stddef.h>
#include "aigis_sig_sha3_kdf.h"
#include "aigis_sig_sm3_kdf.h"
#include "pqcp_err.h"

static int32_t CheckCtx(const PQCP_AIGIS_SIG_CoreCtx *ctx)
{
    if (ctx == NULL || ctx->params == NULL) {
        return PQCP_NULL_INPUT;
    }
    if ((ctx->paramId < 1 || ctx->paramId > 3) || ctx->params->id != ctx->paramId) {
        return PQCP_NOT_SUPPORT;
    }
    if (ctx->hashId != PQCP_AIGIS_SIG_HASH_SM3 && ctx->hashId != PQCP_AIGIS_SIG_HASH_SHA3) {
        return PQCP_NOT_SUPPORT;
    }
    return PQCP_SUCCESS;
}

int32_t PQCP_AIGIS_SIG_Kdf(const PQCP_AIGIS_SIG_CoreCtx *ctx, uint8_t *out, uint32_t outLen, const uint8_t *in,
                           uint32_t inLen)
{
    int32_t ret = CheckCtx(ctx);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    if (ctx->hashId == PQCP_AIGIS_SIG_HASH_SHA3) {
        if (ctx->paramId == 3) {
            return PQCP_AIGIS_SIG_AigisKeccakXofRate72(in, inLen, out, outLen);
        }
        return PQCP_AIGIS_SIG_Shake256(ctx->libCtx, ctx->sha3Cache, in, inLen, out, outLen);
    }
    return PQCP_AIGIS_SIG_Sm3PseudoXof(ctx->libCtx, in, inLen, out, outLen);
}

int32_t PQCP_AIGIS_SIG_KdfTwoSegment(const PQCP_AIGIS_SIG_CoreCtx *ctx, uint8_t *out, uint32_t outLen,
                                     const uint8_t *in1, uint32_t in1Len, const uint8_t *in2, uint32_t in2Len)
{
    int32_t ret = CheckCtx(ctx);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    if (ctx->hashId == PQCP_AIGIS_SIG_HASH_SHA3) {
        if (ctx->paramId == 3) {
            return PQCP_AIGIS_SIG_AigisKeccakXofRate72TwoSegment(in1, in1Len, in2, in2Len, out, outLen);
        }
        return PQCP_AIGIS_SIG_Shake256TwoSegment(ctx->libCtx, ctx->sha3Cache, in1, in1Len, in2, in2Len, out, outLen);
    }
    return PQCP_AIGIS_SIG_Sm3PseudoXofTwoSegment(ctx->libCtx, in1, in1Len, in2, in2Len, out, outLen);
}

int32_t PQCP_AIGIS_SIG_Hash(const PQCP_AIGIS_SIG_CoreCtx *ctx, uint8_t *out, uint32_t outLen, const uint8_t *in,
                            uint32_t inLen)
{
    int32_t ret = CheckCtx(ctx);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    if (outLen == 32U) {
        if (ctx->hashId == PQCP_AIGIS_SIG_HASH_SHA3) {
            return PQCP_AIGIS_SIG_Sha3Hash256(ctx->libCtx, ctx->sha3Cache, in, inLen, out);
        }
        return PQCP_AIGIS_SIG_Sm3Hash256(ctx->libCtx, in, inLen, out);
    }
    if (outLen == 64U) {
        if (ctx->hashId == PQCP_AIGIS_SIG_HASH_SHA3) {
            return PQCP_AIGIS_SIG_Sha3Hash512(ctx->libCtx, ctx->sha3Cache, in, inLen, out);
        }
        return PQCP_AIGIS_SIG_Sm3PseudoHash512(ctx->libCtx, in, inLen, out);
    }
    return PQCP_NOT_SUPPORT;
}

int32_t PQCP_AIGIS_SIG_KdfAbsorb(const PQCP_AIGIS_SIG_CoreCtx *ctx, PQCP_AIGIS_SIG_KdfCtx *state, const uint8_t *input,
                                 uint32_t inputLen)
{
    if (state == NULL) {
        return PQCP_NULL_INPUT;
    }
    int32_t ret = CheckCtx(ctx);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    state->hashId = ctx->hashId;
    state->rate = ctx->hashId == PQCP_AIGIS_SIG_HASH_SHA3 ?
                      (ctx->paramId == 3 ? PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72 : PQCP_AIGIS_SIG_SHAKE256_RATE) :
                      PQCP_AIGIS_SIG_SM3_RATE;
    if (ctx->hashId == PQCP_AIGIS_SIG_HASH_SHA3) {
        if (ctx->paramId == 3) {
            return PQCP_AIGIS_SIG_AigisKeccakXofRate72Init(&state->state.aigisKeccakRate72, input, inputLen);
        }
        return PQCP_AIGIS_SIG_Shake256Init(&state->state.shake256, ctx->libCtx, ctx->sha3Cache, input, inputLen);
    }
    return PQCP_AIGIS_SIG_Sm3DrngInit(&state->state.sm3, ctx->libCtx, input, inputLen);
}

int32_t PQCP_AIGIS_SIG_Kdf128Absorb(const PQCP_AIGIS_SIG_CoreCtx *ctx, PQCP_AIGIS_SIG_KdfCtx *state,
                                    const uint8_t *input, uint32_t inputLen)
{
    if (state == NULL) {
        return PQCP_NULL_INPUT;
    }
    int32_t ret = CheckCtx(ctx);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    state->hashId = ctx->hashId;
    state->rate = ctx->hashId == PQCP_AIGIS_SIG_HASH_SHA3 ? PQCP_AIGIS_SIG_SHAKE128_RATE : PQCP_AIGIS_SIG_SM3_RATE;
    if (ctx->hashId == PQCP_AIGIS_SIG_HASH_SHA3) {
        return PQCP_AIGIS_SIG_Shake128Init(&state->state.shake256, ctx->libCtx, ctx->sha3Cache, input, inputLen);
    }
    return PQCP_AIGIS_SIG_Sm3DrngInit(&state->state.sm3, ctx->libCtx, input, inputLen);
}

int32_t PQCP_AIGIS_SIG_KdfSqueezeBlocks(uint8_t *output, uint32_t blockNum, PQCP_AIGIS_SIG_KdfCtx *state)
{
    if (state == NULL) {
        return PQCP_INVALID_ARG;
    }
    if (state->hashId == PQCP_AIGIS_SIG_HASH_SHA3) {
        if ((state->rate != PQCP_AIGIS_SIG_SHAKE128_RATE && state->rate != PQCP_AIGIS_SIG_SHAKE256_RATE &&
             state->rate != PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72) ||
            blockNum > UINT32_MAX / state->rate) {
            return PQCP_INVALID_ARG;
        }
        if (state->rate == PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72) {
            return PQCP_AIGIS_SIG_AigisKeccakXofRate72Squeeze(&state->state.aigisKeccakRate72, output,
                                                              blockNum * state->rate);
        }
        return PQCP_AIGIS_SIG_Shake256Squeeze(&state->state.shake256, output, blockNum * state->rate);
    }
    if (state->hashId != PQCP_AIGIS_SIG_HASH_SM3 || blockNum > UINT32_MAX / PQCP_AIGIS_SIG_SM3_RATE) {
        return PQCP_INVALID_ARG;
    }
    return PQCP_AIGIS_SIG_Sm3DrngGenerate(&state->state.sm3, output, blockNum * PQCP_AIGIS_SIG_SM3_RATE);
}

void PQCP_AIGIS_SIG_KdfFree(PQCP_AIGIS_SIG_KdfCtx *state)
{
    if (state == NULL) {
        return;
    }
    if (state->hashId == PQCP_AIGIS_SIG_HASH_SHA3) {
        if (state->rate == PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72) {
            PQCP_AIGIS_SIG_AigisKeccakXofRate72Free(&state->state.aigisKeccakRate72);
        } else {
            PQCP_AIGIS_SIG_Shake256Free(&state->state.shake256);
        }
    } else if (state->hashId == PQCP_AIGIS_SIG_HASH_SM3) {
        PQCP_AIGIS_SIG_Sm3DrngFree(&state->state.sm3);
    }
    state->rate = 0U;
    state->hashId = -1;
}
