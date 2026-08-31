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
#include <string.h>

#include "aigis_sig_local.h"
#include "bsl_sal.h"
#include "pqcp_err.h"
#include "portable/aigis_sig_portable.h"

static int RejectUniformScalarImpl(int32_t *a, int32_t *cur, int32_t n, const uint8_t *buf, int32_t bufLen)
{
    int ctr, pos, group;
    uint32_t t;

    ctr = *cur;
    pos = 0;
    const int32_t fastGroups = (n - ctr) / 4 < bufLen / 11 ? (n - ctr) / 4 : bufLen / 11;
    for (group = 0; group < fastGroups; ++group) {
        t = buf[pos];
        t |= (uint32_t)buf[pos + 1] << 8;
        t |= (uint32_t)buf[pos + 2] << 16;
        t &= 0x3FFFFF;
        a[ctr] = (int32_t)t;
        ctr += (int32_t)(t < PARAM_Q);

        t = buf[pos + 2] >> 6;
        t |= (uint32_t)buf[pos + 3] << 2;
        t |= (uint32_t)buf[pos + 4] << 10;
        t |= (uint32_t)buf[pos + 5] << 18;
        t &= 0x3FFFFF;
        a[ctr] = (int32_t)t;
        ctr += (int32_t)(t < PARAM_Q);

        t = buf[pos + 5] >> 4;
        t |= (uint32_t)buf[pos + 6] << 4;
        t |= (uint32_t)buf[pos + 7] << 12;
        t |= (uint32_t)buf[pos + 8] << 20;
        t &= 0x3FFFFF;
        a[ctr] = (int32_t)t;
        ctr += (int32_t)(t < PARAM_Q);

        t = buf[pos + 8] >> 2;
        t |= (uint32_t)buf[pos + 9] << 6;
        t |= (uint32_t)buf[pos + 10] << 14;
        t &= 0x3FFFFF;
        a[ctr] = (int32_t)t;
        ctr += (int32_t)(t < PARAM_Q);
        pos += 11;
    }

    while (ctr < n && pos + 3 <= bufLen) {
        t = buf[pos++];
        t |= (uint32_t)buf[pos++] << 8;
        t |= (uint32_t)buf[pos] << 16;
        t &= 0x3FFFFF;
        if (t < PARAM_Q) {
            a[ctr++] = t;
        }

        if (ctr == n || pos + 4 > bufLen) {
            *cur = ctr;
            return pos + 1;
        }

        t = buf[pos++] >> 6;
        t |= (uint32_t)buf[pos++] << 2;
        t |= (uint32_t)buf[pos++] << 10;
        t |= (uint32_t)buf[pos] << 18;
        t &= 0x3FFFFF;
        if (t < PARAM_Q) {
            a[ctr++] = t;
        }

        if (ctr == n || pos + 4 > bufLen) {
            *cur = ctr;
            return pos + 1;
        }

        t = buf[pos++] >> 4;
        t |= (uint32_t)buf[pos++] << 4;
        t |= (uint32_t)buf[pos++] << 12;
        t |= (uint32_t)buf[pos] << 20;
        t &= 0x3FFFFF;
        if (t < PARAM_Q) {
            a[ctr++] = t;
        }

        if (ctr == n || pos + 3 > bufLen) {
            *cur = ctr;
            return pos + 1;
        }

        t = buf[pos++] >> 2;
        t |= (uint32_t)buf[pos++] << 6;
        t |= (uint32_t)buf[pos++] << 14;
        t &= 0x3FFFFF;
        if (t < PARAM_Q) {
            a[ctr++] = t;
        }
    }
    *cur = ctr;
    return pos;
}

int32_t PQCP_AIGIS_SIG_RejectUniformScalar(int32_t *a, int32_t *cur, const uint8_t *buf, int32_t bufLen)
{
    return RejectUniformScalarImpl(a, cur, PARAM_N, buf, bufLen);
}

#ifndef PQCP_AIGIS_SIG_ARMV8_BACKEND
int32_t PQCP_AIGIS_SIG_RejectUniform(int32_t *a, int32_t *cur, const uint8_t *buf, int32_t bufLen)
{
    return RejectUniformScalarImpl(a, cur, PARAM_N, buf, bufLen);
}
#endif

#define REJ_UNIFORM_GROUP_BYTES 11

static int32_t RejectUniformCompleteGroups(int32_t *a, int32_t *cur, const uint8_t *buf, int32_t bufLen)
{
    const int32_t completeLen = bufLen - bufLen % REJ_UNIFORM_GROUP_BYTES;
    return PQCP_AIGIS_SIG_RejectUniform(a, cur, buf, completeLen);
}

int32_t PQCP_AIGIS_SIG_PolyUniformSeed(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPoly *a, const uint8_t *seed,
                                       int32_t seedLen)
{
    ALIGN(32) uint8_t buf[REJ_UNIFORM_BYTES + PQCP_AIGIS_SIG_SHAKE128_RATE];
    PQCP_AIGIS_SIG_KdfCtx state = {0};
    int32_t cur = 0, pos = 0;
    int32_t ret = PQCP_AIGIS_SIG_Kdf128Absorb(opCtx, &state, seed, (uint32_t)seedLen);
    if (ret != 0) {
        goto cleanup;
    }
    if (opCtx->hashId == PQCP_AIGIS_SIG_HASH_SM3) {
        /* Each SM3 DRBG Generate request updates its state; these four request boundaries are KAT-visible. */
        const uint32_t initialBlocks = 11U;
        const uint32_t initialRequests = 4U;
        const uint32_t requestBytes = initialBlocks * state.rate;
        int32_t len = (int32_t)(initialRequests * requestBytes);
        for (uint32_t i = 0; i < initialRequests; ++i) {
            ret = KDF_SQUEEZEBLOCK(buf + i * requestBytes, initialBlocks, &state);
            if (ret != 0) {
                goto cleanup;
            }
        }
        /* The first 1408 bytes contain exactly 512 candidates, so any rejection
         * otherwise triggers this same one-block request after parsing.  Prefetch
         * it while the DRBG state is live and parse the contiguous buffer once. */
        ret = KDF_SQUEEZEBLOCK(buf + len, 1, &state);
        if (ret != 0) {
            goto cleanup;
        }
        len += (int32_t)state.rate;
        pos = RejectUniformCompleteGroups(a->coeffs, &cur, buf, len);
        while (cur < PARAM_N) {
            len -= pos;
            memmove(buf, buf + pos, (size_t)len);
            ret = KDF_SQUEEZEBLOCK(buf + len, 1, &state);
            if (ret != 0) {
                goto cleanup;
            }
            len += (int32_t)state.rate;
            pos = RejectUniformCompleteGroups(a->coeffs, &cur, buf, len);
        }
        goto cleanup;
    }
    const uint32_t initialBlocks = (REJ_UNIFORM_BYTES + state.rate - 1U) / state.rate;
    int32_t len = (int32_t)(initialBlocks * state.rate);
    ret = KDF_SQUEEZEBLOCK(buf, initialBlocks, &state);
    if (ret != 0) {
        goto cleanup;
    }
    pos = RejectUniformCompleteGroups(a->coeffs, &cur, buf, len);
    while (cur < PARAM_N) {
        len -= pos;
        memmove(buf, buf + pos, (size_t)len);
        ret = KDF_SQUEEZEBLOCK(buf + len, 1, &state);
        if (ret != 0) {
            goto cleanup;
        }
        len += (int32_t)state.rate;
        pos = RejectUniformCompleteGroups(a->coeffs, &cur, buf, len);
    }
cleanup:
    PQCP_AIGIS_SIG_XOF_FREE(&state);
    return ret;
}

#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
int32_t PQCP_AIGIS_SIG_PolyUniformSeedPairSha3Armv8(AigisSigPoly *a0, AigisSigPoly *a1, const uint8_t *seed0,
                                                    const uint8_t *seed1, uint32_t seedLen)
{
    enum { INITIAL_BLOCKS = (REJ_UNIFORM_BYTES + PQCP_AIGIS_SIG_SHAKE128_RATE - 1U) / PQCP_AIGIS_SIG_SHAKE128_RATE };
    ALIGN(32) uint8_t buf0[REJ_UNIFORM_BYTES + PQCP_AIGIS_SIG_SHAKE128_RATE];
    ALIGN(32) uint8_t buf1[REJ_UNIFORM_BYTES + PQCP_AIGIS_SIG_SHAKE128_RATE];
    ALIGN(32) uint8_t discard[PQCP_AIGIS_SIG_SHAKE128_RATE];
    AigisSigKeccakX2State state;
    int32_t cur0 = 0;
    int32_t cur1 = 0;
    int32_t len0 = INITIAL_BLOCKS * PQCP_AIGIS_SIG_SHAKE128_RATE;
    int32_t len1 = len0;
    int32_t pos0;
    int32_t pos1;

    if (a0 == NULL || a1 == NULL || seed0 == NULL || seed1 == NULL || a0 == a1) {
        return PQCP_NULL_INPUT;
    }
    if (seedLen == SEEDBYTES + 1U) {
        PQCP_AIGIS_SIG_Keccakx2Absorb33Shake128Armv8(state, seed0, seed1);
    } else if (seedLen == AIGIS_SIG_MAX_SEED_BYTES + 1U) {
        PQCP_AIGIS_SIG_Keccakx2Absorb65Shake128Armv8(state, seed0, seed1);
    } else {
        PQCP_AIGIS_SIG_Keccakx2AbsorbArmv8(state, PQCP_AIGIS_SIG_SHAKE128_RATE, seed0, seed1, seedLen, 0x1FU);
    }
    PQCP_AIGIS_SIG_Keccakx2SqueezeArmv8(buf0, buf1, INITIAL_BLOCKS, PQCP_AIGIS_SIG_SHAKE128_RATE, state);
    uint64_t pairCursors = PQCP_AIGIS_SIG_RejectUniformPairInitialArmv8(a0->coeffs, a1->coeffs, buf0, buf1);
    cur0 = (int32_t)(uint32_t)pairCursors;
    cur1 = (int32_t)(uint32_t)(pairCursors >> 32);
    pos0 = 128 * 11;
    pos1 = pos0;
    pos0 += RejectUniformCompleteGroups(a0->coeffs, &cur0, buf0 + pos0, len0 - pos0);
    pos1 += RejectUniformCompleteGroups(a1->coeffs, &cur1, buf1 + pos1, len1 - pos1);

    while (cur0 < PARAM_N || cur1 < PARAM_N) {
        if (cur0 < PARAM_N) {
            len0 -= pos0;
            (void)memmove(buf0, buf0 + pos0, (size_t)len0);
        }
        if (cur1 < PARAM_N) {
            len1 -= pos1;
            (void)memmove(buf1, buf1 + pos1, (size_t)len1);
        }
        uint8_t *out0 = cur0 < PARAM_N ? buf0 + len0 : discard;
        uint8_t *out1 = cur1 < PARAM_N ? buf1 + len1 : discard;
        PQCP_AIGIS_SIG_Keccakx2SqueezeArmv8(out0, out1, 1U, PQCP_AIGIS_SIG_SHAKE128_RATE, state);
        if (cur0 < PARAM_N) {
            len0 += PQCP_AIGIS_SIG_SHAKE128_RATE;
            pos0 = RejectUniformCompleteGroups(a0->coeffs, &cur0, buf0, len0);
        }
        if (cur1 < PARAM_N) {
            len1 += PQCP_AIGIS_SIG_SHAKE128_RATE;
            pos1 = RejectUniformCompleteGroups(a1->coeffs, &cur1, buf1, len1);
        }
    }
    BSL_SAL_CleanseData(buf0, sizeof(buf0));
    BSL_SAL_CleanseData(buf1, sizeof(buf1));
    BSL_SAL_CleanseData(discard, sizeof(discard));
    BSL_SAL_CleanseData(state, sizeof(state));
    return PQCP_SUCCESS;
}
#endif

int32_t PQCP_AIGIS_SIG_ExpandMatrixRow(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecL *row,
                                       const uint8_t rho[AIGIS_SIG_MAX_SEED_BYTES], uint32_t rowIndex)
{
    const uint32_t seedBytes = opCtx->params->seedBytes;
    ALIGN(32) uint8_t inbuf[AIGIS_SIG_MAX_SEED_BYTES + 1U];
    const uint32_t count = opCtx->params->l;
    (void)memcpy(inbuf, rho, seedBytes);
    for (uint32_t column = 0; column < count; column++) {
        inbuf[seedBytes] = (uint8_t)((rowIndex << 4) | column);
        int32_t ret = PQCP_AIGIS_SIG_PolyUniformSeed(opCtx, &row->vec[column], inbuf, (int32_t)(seedBytes + 1U));
        if (ret != 0) {
            return ret;
        }
    }
    return 0;
}

int32_t PQCP_AIGIS_SIG_ExpandMatrix(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecL mat[AIGIS_SIG_MAX_K],
                                    const uint8_t rho[AIGIS_SIG_MAX_SEED_BYTES])
{
    uint32_t i, j;
    const uint32_t rows = opCtx->params->k;
    const uint32_t columns = opCtx->params->l;
    const uint32_t seedBytes = opCtx->params->seedBytes;
    ALIGN(32) uint8_t inbuf[AIGIS_SIG_MAX_SEED_BYTES + 1U];
    (void)memcpy(inbuf, rho, seedBytes);

#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
    if (opCtx->paramId == 3 && opCtx->hashId == PQCP_AIGIS_SIG_HASH_SHA3) {
        ALIGN(32) uint8_t inbuf1[AIGIS_SIG_MAX_SEED_BYTES + 1U];
        (void)memcpy(inbuf1, rho, seedBytes);
        const uint32_t total = rows * columns;
        for (uint32_t index = 0U; index < total; index += 2U) {
            const uint32_t row0 = index / columns;
            const uint32_t column0 = index - row0 * columns;
            const uint32_t row1 = (index + 1U) / columns;
            const uint32_t column1 = index + 1U - row1 * columns;
            inbuf[seedBytes] = (uint8_t)((row0 << 4U) | column0);
            inbuf1[seedBytes] = (uint8_t)((row1 << 4U) | column1);
            const int32_t ret = PQCP_AIGIS_SIG_PolyUniformSeedPairSha3Armv8(
                &mat[row0].vec[column0], &mat[row1].vec[column1], inbuf, inbuf1, seedBytes + 1U);
            if (ret != PQCP_SUCCESS) {
                BSL_SAL_CleanseData(inbuf1, sizeof(inbuf1));
                return ret;
            }
        }
        BSL_SAL_CleanseData(inbuf1, sizeof(inbuf1));
        return PQCP_SUCCESS;
    }
#endif

    for (i = 0; i < rows; i++) {
        for (j = 0; j < columns; j++) {
            inbuf[seedBytes] = (i << 4) | j;
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
            if (opCtx->hashId == PQCP_AIGIS_SIG_HASH_SHA3 && j + 1U < columns) {
                ALIGN(32) uint8_t inbuf1[AIGIS_SIG_MAX_SEED_BYTES + 1U];
                (void)memcpy(inbuf1, inbuf, seedBytes + 1U);
                inbuf1[seedBytes] = (uint8_t)((i << 4) | (j + 1U));
                int32_t ret = PQCP_AIGIS_SIG_PolyUniformSeedPairSha3Armv8(&mat[i].vec[j], &mat[i].vec[j + 1U], inbuf,
                                                                          inbuf1, seedBytes + 1U);
                BSL_SAL_CleanseData(inbuf1, sizeof(inbuf1));
                if (ret != 0) {
                    return ret;
                }
                ++j;
                continue;
            }
#endif
            int32_t ret =
                PQCP_AIGIS_SIG_PolyUniformSeed(opCtx, &mat[i].vec[j], inbuf, (int32_t)(seedBytes + 1U));
            if (ret != 0) {
                return ret;
            }
        }
    }
    return 0;
}

static void PackW1(uint8_t *out, const AigisSigPoly *a, uint32_t maxHigh)
{
    const int32_t *coeffs = a->coeffs;
    if (maxHigh == 3U) {
        for (uint32_t i = 0, j = 0; i < PARAM_N; i += 4U, ++j) {
            out[j] = (uint8_t)(coeffs[i] | coeffs[i + 1U] << 2U | coeffs[i + 2U] << 4U |
                               coeffs[i + 3U] << 6U);
        }
        return;
    }
    for (uint32_t i = 0, j = 0; i < PARAM_N; i += 8U, j += 3U) {
        out[j] = (uint8_t)(coeffs[i] | coeffs[i + 1U] << 3 | coeffs[i + 2U] << 6);
        out[j + 1U] = (uint8_t)(coeffs[i + 2U] >> 2 | coeffs[i + 3U] << 1 | coeffs[i + 4U] << 4 | coeffs[i + 5U] << 7);
        out[j + 2U] = (uint8_t)(coeffs[i + 5U] >> 1 | coeffs[i + 6U] << 2 | coeffs[i + 7U] << 5);
    }
}

/* generate the PQCP_AIGIS_SIG_Challenge c */
int32_t PQCP_AIGIS_SIG_Challenge(const PQCP_AIGIS_SIG_CoreCtx *opCtx, uint8_t *seed,
                                 const uint8_t mu[AIGIS_SIG_MAX_CRH_BYTES],
                                 const AigisSigPolyVecK *w1)
{
    uint32_t i;
    int32_t ret;
    const AigisSigParams *params = opCtx->params;
    const uint32_t count = params->k;
    ALIGN(32) uint8_t buf[AIGIS_SIG_MAX_CRH_BYTES + AIGIS_SIG_MAX_K * AIGIS_SIG_POLY_W1_PACKED_BYTES];
    const uint32_t inputLen = params->crhBytes + count * params->polyW1PackedBytes;
    (void)memcpy(buf, mu, params->crhBytes);
    for (i = 0; i < count; ++i) {
        PackW1(buf + params->crhBytes + i * params->polyW1PackedBytes, w1->vec + i, params->maxHigh);
    }
    ret = Hash(opCtx, seed, buf, inputLen);
    BSL_SAL_CleanseData(buf, inputLen);
    return ret;
}

int32_t PQCP_AIGIS_SIG_SampleInBall(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPoly *c,
                                    const uint8_t seed[AIGIS_SIG_MAX_SEED_BYTES])
{
    uint8_t outbuf[4U * PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72];
    uint8_t signs[15U];
    uint32_t i, pos;
    PQCP_AIGIS_SIG_KdfCtx state = {0};
    uint32_t bitBuffer = 0;
    uint32_t bitCount = 0;
    uint32_t cleanseLen = 0;
    const uint32_t weight = opCtx->params->challengeWeight;
    const uint32_t signBytes = (weight + 7U) >> 3;
    const uint32_t candidateBytes = (2U * weight * 9U + 7U) >> 3;
    /* Preserve the accepted compact I/II request boundary. Parameter III's
     * reference fixes the first SM3-DRNG request at 256 bytes. */
    const uint32_t initialBytes = weight > 64U ? 256U : signBytes + candidateBytes;

    int32_t ret = KDF_ABSORB(opCtx, &state, seed, opCtx->params->seedBytes);
    if (ret != 0) {
        goto cleanup;
    }
    const uint32_t initialBlocks = (initialBytes + state.rate - 1U) / state.rate;
    cleanseLen = initialBlocks * state.rate;
    ret = KDF_SQUEEZEBLOCK(outbuf, initialBlocks, &state);
    if (ret != 0) {
        goto cleanup;
    }

    (void)memcpy(signs, outbuf, signBytes);

    pos = signBytes;
    uint32_t bufLen = initialBlocks * state.rate;

    for (i = 0; i < PARAM_N; ++i) {
        c->coeffs[i] = 0;
    }

    for (i = PARAM_N - weight; i < PARAM_N; ++i) {
        uint32_t b;
        do {
            while (bitCount < 9U) {
                if (pos == bufLen) {
                    ret = KDF_SQUEEZEBLOCK(outbuf, 1, &state);
                    if (ret != 0) {
                        goto cleanup;
                    }
                    pos = 0;
                    bufLen = state.rate;
                }
                bitBuffer |= (uint32_t)outbuf[pos++] << bitCount;
                bitCount += 8U;
            }
            b = bitBuffer & 0x1ffU;
            bitBuffer >>= 9;
            bitCount -= 9U;
        } while (b > i);

        c->coeffs[i] = c->coeffs[b];
        const uint32_t signIndex = i - (PARAM_N - weight);
        c->coeffs[b] = 1 - 2 * (int32_t)((signs[signIndex >> 3U] >> (signIndex & 7U)) & 1U);
    }
    ret = 0;
cleanup:
    PQCP_AIGIS_SIG_XOF_FREE(&state);
    BSL_SAL_CleanseData(outbuf, cleanseLen);
    BSL_SAL_CleanseData(signs, sizeof(signs));
    return ret;
}
