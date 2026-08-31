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
#include <stdint.h>
#include "aigis_sig_local.h"
#include "portable/aigis_sig_portable.h"

#include <string.h>

#include "bsl_sal.h"
#include "pqcp_err.h"

static int32_t Power2RoundParam(int32_t value, int32_t *low, uint32_t d)
{
    const uint32_t high = ((uint32_t)value + (UINT32_C(1) << (d - 1U)) - 1U) >> d;
    *low = value - (int32_t)(high << d);
    return (int32_t)high;
}

static int32_t DecomposeParam(int32_t value, int32_t *low, const AigisSigParams *params)
{
    int32_t high = (value + 127) >> 7;
    if (params->alpha == 695296U) {
        high = (high * 6177 + (1 << 24)) >> 25;
    } else {
        /* Parameter III: alpha = 1042944 = 128 * 8148. */
        high = (high * 2059 + (1 << 23)) >> 24;
    }
    high ^= (((int32_t)params->maxHigh - high) >> 31) & high;
    *low = value - high * (int32_t)params->alpha;
    *low -= (((PARAM_Q - 1) / 2 - *low) >> 31) & PARAM_Q;
    return high;
}

static int32_t MakeHintParam(int32_t low, int32_t high, const AigisSigParams *params)
{
    return (low <= (int32_t)params->gamma2 || low > PARAM_Q - (int32_t)params->gamma2 ||
            (low == PARAM_Q - (int32_t)params->gamma2 && high == 0))
               ? 0
               : 1;
}

#ifndef PQCP_AIGIS_SIG_ARMV8_BACKEND
void PQCP_AIGIS_SIG_PolyGReduce(AigisSigPoly *a)
{
    int i;
    for (i = 0; i < PARAM_N; ++i) {
        a->coeffs[i] = PQCP_AIGIS_SIG_GeneralReduce(a->coeffs[i]);
    }
}
#endif

#ifndef PQCP_AIGIS_SIG_ARMV8_BACKEND
void PQCP_AIGIS_SIG_PolyAModQ(AigisSigPoly *a)
{
    int i;
    for (i = 0; i < PARAM_N; ++i) {
        a->coeffs[i] = PQCP_AIGIS_SIG_PositiveReduce(a->coeffs[i]);
    }
}
#endif

#ifndef PQCP_AIGIS_SIG_ARMV8_BACKEND
void PQCP_AIGIS_SIG_PolyCModQ(AigisSigPoly *a)
{
    int i;
    for (i = 0; i < PARAM_N; ++i) {
        a->coeffs[i] = PQCP_AIGIS_SIG_CenteredReduce(a->coeffs[i]);
    }
}
#endif

#ifndef PQCP_AIGIS_SIG_ARMV8_BACKEND
void PQCP_AIGIS_SIG_PolyDecompose(AigisSigPoly *r1, AigisSigPoly *r0, const AigisSigPoly *a)
{
    int i;
    for (i = 0; i < PARAM_N; ++i) {
        r1->coeffs[i] = PQCP_AIGIS_SIG_Decompose(a->coeffs[i], &r0->coeffs[i]);
    }
}
#endif
#ifndef PQCP_AIGIS_SIG_ARMV8_BACKEND
void PQCP_AIGIS_SIG_PolyPower2Round(AigisSigPoly *r1, AigisSigPoly *r0, const AigisSigPoly *a)
{
    int i;
    for (i = 0; i < PARAM_N; ++i) {
        r1->coeffs[i] = PQCP_AIGIS_SIG_Power2Round(a->coeffs[i], &r0->coeffs[i]);
    }
}
#endif

#ifndef PQCP_AIGIS_SIG_ARMV8_BACKEND
void PQCP_AIGIS_SIG_PolyAdd(AigisSigPoly *c, const AigisSigPoly *a, const AigisSigPoly *b)
{
    int i;

    for (i = 0; i < PARAM_N; ++i) {
        c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}
#endif

#ifndef PQCP_AIGIS_SIG_ARMV8_BACKEND
void PQCP_AIGIS_SIG_PolySub(AigisSigPoly *c, const AigisSigPoly *a, const AigisSigPoly *b)
{
    int i;

    for (i = 0; i < PARAM_N; ++i) {
        c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}
#endif

void PQCP_AIGIS_SIG_PolyShiftLeft(AigisSigPoly *a, int k)
{
    int i;

    for (i = 0; i < PARAM_N; ++i) {
        a->coeffs[i] = (int32_t)((int64_t)a->coeffs[i] * ((int64_t)1 << k));
    }
}

#ifndef PQCP_AIGIS_SIG_ARMV8_BACKEND
void PQCP_AIGIS_SIG_PolyPointwise(AigisSigPoly *c, const AigisSigPoly *a, const AigisSigPoly *b)
{
    int i;
    for (i = 0; i < PARAM_N; ++i) {
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
        c->coeffs[i] = PQCP_AIGIS_SIG_MontgomeryReduce((int64_t)a->coeffs[i] * b->coeffs[i]);
#else
        c->coeffs[i] = PQCP_AIGIS_SIG_PlantardMulReduce((int64_t)a->coeffs[i] * b->coeffs[i]);
#endif
    }
}
#endif

#ifndef PQCP_AIGIS_SIG_ARMV8_BACKEND
int32_t PQCP_AIGIS_SIG_PolyCheckNorm(const AigisSigPoly *a, uint32_t bound)
{
    int i;
    uint32_t r = 0;

    for (i = 0; i < PARAM_N; ++i) {
        const int64_t value = a->coeffs[i];
        r |= (uint32_t)(value > (int64_t)bound);
        r |= (uint32_t)(value < 1 - (int64_t)bound);
    }

    return (int32_t)r;
}
#endif

static int RejectEta1(int32_t *a, int32_t *cur, int32_t n, const uint8_t *buf, int32_t bufLen)
{
    int ctr, pos, group;
    int32_t t[4];

    ctr = *cur;
    pos = 0;

    const int32_t fastGroups = (n - ctr) / 4 < bufLen ? (n - ctr) / 4 : bufLen;
    for (group = 0; group < fastGroups; ++group) {
        const uint32_t packed = buf[pos++];
        t[0] = (int32_t)(packed & 0x03U);
        t[1] = (int32_t)(packed >> 2 & 0x03U);
        t[2] = (int32_t)(packed >> 4 & 0x03U);
        t[3] = (int32_t)(packed >> 6);
        a[ctr] = 1 - t[0];
        ctr += t[0] <= 2;
        a[ctr] = 1 - t[1];
        ctr += t[1] <= 2;
        a[ctr] = 1 - t[2];
        ctr += t[2] <= 2;
        a[ctr] = 1 - t[3];
        ctr += t[3] <= 2;
    }

    while (ctr < n && pos < bufLen) {
        t[0] = buf[pos] & 0x03;
        t[1] = (buf[pos] >> 2) & 0x03;
        t[2] = (buf[pos] >> 4) & 0x03;
        t[3] = (buf[pos++] >> 6) & 0x03;

        a[ctr] = 1 - t[0];
        ctr += t[0] <= 2;
        if (ctr < n) {
            a[ctr] = 1 - t[1];
            ctr += t[1] <= 2;
        }
        if (ctr < n) {
            a[ctr] = 1 - t[2];
            ctr += t[2] <= 2;
        }
        if (ctr < n) {
            a[ctr] = 1 - t[3];
            ctr += t[3] <= 2;
        }
    }
    *cur = ctr;
    return pos;
}

static int RejectEta2(const AigisSigParams *params, int32_t *a, int32_t *cur, int32_t n, const uint8_t *buf,
                      int32_t bufLen)
{
    int32_t ctr = *cur;
    int32_t pos = 0;

    if (params->eta2Bits == 2U) {
        const int32_t fastGroups = (n - ctr) / 4 < bufLen ? (n - ctr) / 4 : bufLen;
        for (int32_t group = 0; group < fastGroups; ++group) {
            const uint32_t packed = buf[pos++];
            const uint32_t t0 = packed & 0x03U;
            const uint32_t t1 = packed >> 2 & 0x03U;
            const uint32_t t2 = packed >> 4 & 0x03U;
            const uint32_t t3 = packed >> 6;
            a[ctr] = 1 - (int32_t)t0;
            ctr += (int32_t)(t0 <= 2U);
            a[ctr] = 1 - (int32_t)t1;
            ctr += (int32_t)(t1 <= 2U);
            a[ctr] = 1 - (int32_t)t2;
            ctr += (int32_t)(t2 <= 2U);
            a[ctr] = 1 - (int32_t)t3;
            ctr += (int32_t)(t3 <= 2U);
        }
        while (ctr < n && pos < bufLen) {
            const uint32_t packed = buf[pos];
            const uint32_t t0 = packed & 0x03U;
            const uint32_t t1 = packed >> 2 & 0x03U;
            const uint32_t t2 = packed >> 4 & 0x03U;
            const uint32_t t3 = packed >> 6;
            a[ctr] = 1 - (int32_t)t0;
            ctr += (int32_t)(t0 <= 2U);
            if (ctr >= n) {
                break;
            }
            a[ctr] = 1 - (int32_t)t1;
            ctr += (int32_t)(t1 <= 2U);
            if (ctr >= n) {
                break;
            }
            a[ctr] = 1 - (int32_t)t2;
            ctr += (int32_t)(t2 <= 2U);
            if (ctr >= n) {
                break;
            }
            a[ctr] = 1 - (int32_t)t3;
            ctr += (int32_t)(t3 <= 2U);
            ++pos;
        }
    } else {
        const int32_t fastGroups = (n - ctr) / 2 < bufLen ? (n - ctr) / 2 : bufLen;
        for (int32_t group = 0; group < fastGroups; ++group) {
            const uint32_t packed = buf[pos++];
            const uint32_t t0 = packed & 0x0fU;
            const uint32_t t1 = packed >> 4;
            a[ctr] = 5 - (int32_t)t0;
            ctr += (int32_t)(t0 <= 10U);
            a[ctr] = 5 - (int32_t)t1;
            ctr += (int32_t)(t1 <= 10U);
        }
        while (ctr < n && pos < bufLen) {
            const uint32_t packed = buf[pos];
            const uint32_t t0 = packed & 0x0fU;
            const uint32_t t1 = packed >> 4;
            a[ctr] = 5 - (int32_t)t0;
            ctr += (int32_t)(t0 <= 10U);
            if (ctr >= n) {
                break;
            }
            a[ctr] = 5 - (int32_t)t1;
            ctr += (int32_t)(t1 <= 10U);
            ++pos;
        }
    }
    *cur = ctr;
    return pos;
}

static int32_t UniformEtaSeed(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPoly *a, const uint8_t *seed,
                              int32_t seedLen, int32_t etaIndex)
{
    ALIGN(32) uint8_t buf[384U + PQCP_AIGIS_SIG_SHAKE128_RATE];
    PQCP_AIGIS_SIG_KdfCtx state = {0};
    int32_t cur = 0;
    int32_t ret = KDF_ABSORB(opCtx, &state, seed, seedLen);
    if (ret != 0) {
        return ret;
    }
    const uint32_t rejectBytes = etaIndex == 1 ? opCtx->params->rejEta1Bytes : opCtx->params->rejEta2Bytes;
    const uint32_t initialBlocks = (rejectBytes + state.rate - 1U) / state.rate;
    const uint32_t bufferLen = initialBlocks * state.rate;
    ret = KDF_SQUEEZEBLOCK(buf, initialBlocks, &state);
    if (ret != 0) {
        goto cleanup;
    }
    if (etaIndex == 1) {
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
        cur = PQCP_AIGIS_SIG_RejectEta1InitialArmv8(a->coeffs, buf, bufferLen);
#else
        RejectEta1(a->coeffs, &cur, PARAM_N, buf, (int32_t)bufferLen);
#endif
    } else {
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
        if (opCtx->params->eta2Bits == 4U) {
            cur = PQCP_AIGIS_SIG_RejectEta5InitialArmv8(a->coeffs, buf, bufferLen);
        } else {
            cur = PQCP_AIGIS_SIG_RejectEta1InitialArmv8(a->coeffs, buf, bufferLen);
        }
#else
        RejectEta2(opCtx->params, a->coeffs, &cur, PARAM_N, buf, (int32_t)bufferLen);
#endif
    }
    while (cur < PARAM_N) {
        ret = KDF_SQUEEZEBLOCK(buf, 1, &state);
        if (ret != 0) {
            goto cleanup;
        }
        if (etaIndex == 1) {
            RejectEta1(a->coeffs, &cur, PARAM_N, buf, (int32_t)state.rate);
        } else {
            RejectEta2(opCtx->params, a->coeffs, &cur, PARAM_N, buf, (int32_t)state.rate);
        }
    }
cleanup:
    PQCP_AIGIS_SIG_XOF_FREE(&state);
    BSL_SAL_CleanseData(buf, bufferLen);
    return ret;
}

#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
int32_t PQCP_AIGIS_SIG_PolyUniformEtaPairSha3Armv8(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPoly *a0,
                                                   AigisSigPoly *a1, const uint8_t *seed0, const uint8_t *seed1,
                                                   uint32_t seedLen, uint32_t etaIndex)
{
    ALIGN(32) uint8_t buf0[384U + PQCP_AIGIS_SIG_SHAKE256_RATE];
    ALIGN(32) uint8_t buf1[384U + PQCP_AIGIS_SIG_SHAKE256_RATE];
    ALIGN(32) uint8_t discard[PQCP_AIGIS_SIG_SHAKE256_RATE];
    AigisSigKeccakX2State state;
    int32_t cur0;
    int32_t cur1;

    if (opCtx == NULL || a0 == NULL || a1 == NULL || seed0 == NULL || seed1 == NULL || a0 == a1 ||
        (etaIndex != 1U && etaIndex != 2U)) {
        return PQCP_NULL_INPUT;
    }
    const uint32_t rate = opCtx->paramId == 3 ? PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72 : PQCP_AIGIS_SIG_SHAKE256_RATE;
    const uint32_t rejectBytes = etaIndex == 1U ? opCtx->params->rejEta1Bytes : opCtx->params->rejEta2Bytes;
    const uint32_t initialBlocks = (rejectBytes + rate - 1U) / rate;
    const uint32_t bufferLen = initialBlocks * rate;
    PQCP_AIGIS_SIG_Keccakx2AbsorbArmv8(state, rate, seed0, seed1, seedLen, 0x1FU);
    PQCP_AIGIS_SIG_Keccakx2SqueezeArmv8(buf0, buf1, initialBlocks, rate, state);
    if (etaIndex == 1U || opCtx->params->eta2Bits == 2U) {
        cur0 = PQCP_AIGIS_SIG_RejectEta1InitialArmv8(a0->coeffs, buf0, bufferLen);
        cur1 = PQCP_AIGIS_SIG_RejectEta1InitialArmv8(a1->coeffs, buf1, bufferLen);
    } else {
        cur0 = PQCP_AIGIS_SIG_RejectEta5InitialArmv8(a0->coeffs, buf0, bufferLen);
        cur1 = PQCP_AIGIS_SIG_RejectEta5InitialArmv8(a1->coeffs, buf1, bufferLen);
    }
    while (cur0 < PARAM_N || cur1 < PARAM_N) {
        uint8_t *out0 = cur0 < PARAM_N ? buf0 : discard;
        uint8_t *out1 = cur1 < PARAM_N ? buf1 : discard;
        PQCP_AIGIS_SIG_Keccakx2SqueezeArmv8(out0, out1, 1U, rate, state);
        if (cur0 < PARAM_N) {
            if (etaIndex == 1U) {
                RejectEta1(a0->coeffs, &cur0, PARAM_N, buf0, (int32_t)rate);
            } else {
                RejectEta2(opCtx->params, a0->coeffs, &cur0, PARAM_N, buf0, (int32_t)rate);
            }
        }
        if (cur1 < PARAM_N) {
            if (etaIndex == 1U) {
                RejectEta1(a1->coeffs, &cur1, PARAM_N, buf1, (int32_t)rate);
            } else {
                RejectEta2(opCtx->params, a1->coeffs, &cur1, PARAM_N, buf1, (int32_t)rate);
            }
        }
    }
    BSL_SAL_CleanseData(buf0, sizeof(buf0));
    BSL_SAL_CleanseData(buf1, sizeof(buf1));
    BSL_SAL_CleanseData(discard, sizeof(discard));
    BSL_SAL_CleanseData(state, sizeof(state));
    return PQCP_SUCCESS;
}
#endif

static void PackZ15(uint8_t out[960], const AigisSigPoly *a, uint32_t center)
{
    const int32_t *coeffs = a->coeffs;
    for (uint32_t i = 0, j = 0; i < PARAM_N; i += 8U, j += 15U) {
        uint32_t t[8];
        for (uint32_t k = 0; k < 8U; ++k) {
            t[k] = center - (uint32_t)coeffs[i + k];
        }
        out[j] = (uint8_t)t[0];
        out[j + 1U] = (uint8_t)((t[0] >> 8) | (t[1] << 7));
        out[j + 2U] = (uint8_t)(t[1] >> 1);
        out[j + 3U] = (uint8_t)((t[1] >> 9) | (t[2] << 6));
        out[j + 4U] = (uint8_t)(t[2] >> 2);
        out[j + 5U] = (uint8_t)((t[2] >> 10) | (t[3] << 5));
        out[j + 6U] = (uint8_t)(t[3] >> 3);
        out[j + 7U] = (uint8_t)((t[3] >> 11) | (t[4] << 4));
        out[j + 8U] = (uint8_t)(t[4] >> 4);
        out[j + 9U] = (uint8_t)((t[4] >> 12) | (t[5] << 3));
        out[j + 10U] = (uint8_t)(t[5] >> 5);
        out[j + 11U] = (uint8_t)((t[5] >> 13) | (t[6] << 2));
        out[j + 12U] = (uint8_t)(t[6] >> 6);
        out[j + 13U] = (uint8_t)((t[6] >> 14) | (t[7] << 1));
        out[j + 14U] = (uint8_t)(t[7] >> 7);
    }
}

static void PackZ17(uint8_t out[1088], const AigisSigPoly *a, uint32_t center)
{
    const int32_t *coeffs = a->coeffs;
    for (uint32_t i = 0, j = 0; i < PARAM_N; i += 8U, j += 17U) {
        uint32_t t[8];
        for (uint32_t k = 0; k < 8U; ++k) {
            t[k] = center - (uint32_t)coeffs[i + k];
        }
        out[j] = (uint8_t)t[0];
        out[j + 1U] = (uint8_t)(t[0] >> 8);
        out[j + 2U] = (uint8_t)((t[0] >> 16) | (t[1] << 1));
        out[j + 3U] = (uint8_t)(t[1] >> 7);
        out[j + 4U] = (uint8_t)((t[1] >> 15) | (t[2] << 2));
        out[j + 5U] = (uint8_t)(t[2] >> 6);
        out[j + 6U] = (uint8_t)((t[2] >> 14) | (t[3] << 3));
        out[j + 7U] = (uint8_t)(t[3] >> 5);
        out[j + 8U] = (uint8_t)((t[3] >> 13) | (t[4] << 4));
        out[j + 9U] = (uint8_t)(t[4] >> 4);
        out[j + 10U] = (uint8_t)((t[4] >> 12) | (t[5] << 5));
        out[j + 11U] = (uint8_t)(t[5] >> 3);
        out[j + 12U] = (uint8_t)((t[5] >> 11) | (t[6] << 6));
        out[j + 13U] = (uint8_t)(t[6] >> 2);
        out[j + 14U] = (uint8_t)((t[6] >> 10) | (t[7] << 7));
        out[j + 15U] = (uint8_t)(t[7] >> 1);
        out[j + 16U] = (uint8_t)(t[7] >> 9);
    }
}

#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
void PQCP_AIGIS_SIG_UnpackCenteredArmv8(AigisSigPoly *r, const uint8_t *in, uint32_t center, uint32_t bits);
#else
static void UnpackZ15(AigisSigPoly *r, const uint8_t in[960], uint32_t center)
{
    int32_t *coeffs = r->coeffs;
    for (uint32_t i = 0, j = 0; i < PARAM_N; i += 8U, j += 15U) {
        const uint32_t t0 = (uint32_t)in[j] | ((uint32_t)in[j + 1U] & 0x7FU) << 8;
        const uint32_t t1 = (uint32_t)in[j + 1U] >> 7 | (uint32_t)in[j + 2U] << 1 | ((uint32_t)in[j + 3U] & 0x3FU) << 9;
        const uint32_t t2 =
            (uint32_t)in[j + 3U] >> 6 | (uint32_t)in[j + 4U] << 2 | ((uint32_t)in[j + 5U] & 0x1FU) << 10;
        const uint32_t t3 =
            (uint32_t)in[j + 5U] >> 5 | (uint32_t)in[j + 6U] << 3 | ((uint32_t)in[j + 7U] & 0x0FU) << 11;
        const uint32_t t4 =
            (uint32_t)in[j + 7U] >> 4 | (uint32_t)in[j + 8U] << 4 | ((uint32_t)in[j + 9U] & 0x07U) << 12;
        const uint32_t t5 =
            (uint32_t)in[j + 9U] >> 3 | (uint32_t)in[j + 10U] << 5 | ((uint32_t)in[j + 11U] & 0x03U) << 13;
        const uint32_t t6 =
            (uint32_t)in[j + 11U] >> 2 | (uint32_t)in[j + 12U] << 6 | ((uint32_t)in[j + 13U] & 0x01U) << 14;
        const uint32_t t7 = (uint32_t)in[j + 13U] >> 1 | (uint32_t)in[j + 14U] << 7;
        coeffs[i] = (int32_t)center - (int32_t)t0;
        coeffs[i + 1U] = (int32_t)center - (int32_t)t1;
        coeffs[i + 2U] = (int32_t)center - (int32_t)t2;
        coeffs[i + 3U] = (int32_t)center - (int32_t)t3;
        coeffs[i + 4U] = (int32_t)center - (int32_t)t4;
        coeffs[i + 5U] = (int32_t)center - (int32_t)t5;
        coeffs[i + 6U] = (int32_t)center - (int32_t)t6;
        coeffs[i + 7U] = (int32_t)center - (int32_t)t7;
    }
}

static void UnpackZ17(AigisSigPoly *r, const uint8_t in[1088], uint32_t center)
{
    int32_t *coeffs = r->coeffs;
    for (uint32_t i = 0, j = 0; i < PARAM_N; i += 8U, j += 17U) {
        const uint32_t t0 = (uint32_t)in[j] | (uint32_t)in[j + 1U] << 8 | ((uint32_t)in[j + 2U] & 0x01U) << 16;
        const uint32_t t1 =
            (uint32_t)in[j + 2U] >> 1 | (uint32_t)in[j + 3U] << 7 | ((uint32_t)in[j + 4U] & 0x03U) << 15;
        const uint32_t t2 =
            (uint32_t)in[j + 4U] >> 2 | (uint32_t)in[j + 5U] << 6 | ((uint32_t)in[j + 6U] & 0x07U) << 14;
        const uint32_t t3 =
            (uint32_t)in[j + 6U] >> 3 | (uint32_t)in[j + 7U] << 5 | ((uint32_t)in[j + 8U] & 0x0FU) << 13;
        const uint32_t t4 =
            (uint32_t)in[j + 8U] >> 4 | (uint32_t)in[j + 9U] << 4 | ((uint32_t)in[j + 10U] & 0x1FU) << 12;
        const uint32_t t5 =
            (uint32_t)in[j + 10U] >> 5 | (uint32_t)in[j + 11U] << 3 | ((uint32_t)in[j + 12U] & 0x3FU) << 11;
        const uint32_t t6 =
            (uint32_t)in[j + 12U] >> 6 | (uint32_t)in[j + 13U] << 2 | ((uint32_t)in[j + 14U] & 0x7FU) << 10;
        const uint32_t t7 = (uint32_t)in[j + 14U] >> 7 | (uint32_t)in[j + 15U] << 1 | (uint32_t)in[j + 16U] << 9;
        coeffs[i] = (int32_t)center - (int32_t)t0;
        coeffs[i + 1U] = (int32_t)center - (int32_t)t1;
        coeffs[i + 2U] = (int32_t)center - (int32_t)t2;
        coeffs[i + 3U] = (int32_t)center - (int32_t)t3;
        coeffs[i + 4U] = (int32_t)center - (int32_t)t4;
        coeffs[i + 5U] = (int32_t)center - (int32_t)t5;
        coeffs[i + 6U] = (int32_t)center - (int32_t)t6;
        coeffs[i + 7U] = (int32_t)center - (int32_t)t7;
    }
}

#endif

void PQCP_AIGIS_SIG_PolyZPack(const PQCP_AIGIS_SIG_CoreCtx *opCtx, uint8_t *r, const AigisSigPoly *a)
{
    if (opCtx->params->szBits == 15U) {
        PackZ15(r, a, opCtx->params->gamma1);
    } else if (opCtx->params->szBits == 17U) {
        PackZ17(r, a, opCtx->params->gamma1);
    } else {
        for (uint32_t i = 0, j = 0; i < PARAM_N; i += 2U, j += 5U) {
            const uint32_t t0 = opCtx->params->gamma1 - (uint32_t)a->coeffs[i];
            const uint32_t t1 = opCtx->params->gamma1 - (uint32_t)a->coeffs[i + 1U];
            r[j] = (uint8_t)t0;
            r[j + 1U] = (uint8_t)(t0 >> 8U);
            r[j + 2U] = (uint8_t)((t0 >> 16U) | (t1 << 4U));
            r[j + 3U] = (uint8_t)(t1 >> 4U);
            r[j + 4U] = (uint8_t)(t1 >> 12U);
        }
    }
}

void PQCP_AIGIS_SIG_PolyZUnpack(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPoly *r, const uint8_t *a)
{
#ifdef PQCP_AIGIS_SIG_PORTABLE_BACKEND
    if (opCtx->params->szBits == 15U) {
        UnpackZ15(r, a, opCtx->params->gamma1);
    } else if (opCtx->params->szBits == 17U) {
        UnpackZ17(r, a, opCtx->params->gamma1);
    } else {
        for (uint32_t i = 0, j = 0; i < PARAM_N; i += 2U, j += 5U) {
            const uint32_t t0 = (uint32_t)a[j] | (uint32_t)a[j + 1U] << 8U |
                                ((uint32_t)a[j + 2U] & 0x0fU) << 16U;
            const uint32_t t1 = (uint32_t)a[j + 2U] >> 4U | (uint32_t)a[j + 3U] << 4U |
                                (uint32_t)a[j + 4U] << 12U;
            r->coeffs[i] = (int32_t)opCtx->params->gamma1 - (int32_t)t0;
            r->coeffs[i + 1U] = (int32_t)opCtx->params->gamma1 - (int32_t)t1;
        }
    }
#else
    PQCP_AIGIS_SIG_UnpackCenteredArmv8(r, a, opCtx->params->gamma1, opCtx->params->szBits);
#endif
}

void PQCP_AIGIS_SIG_PolyVecLNtt(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecL *v)
{
    uint32_t i;
    const uint32_t l = opCtx->params->l;

    for (i = 0; i < l; ++i) {
        PQCP_AIGIS_SIG_Ntt(v->vec[i].coeffs);
    }
}

void PQCP_AIGIS_SIG_PolyVecLNttCopy(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecL *dst,
                                    const AigisSigPolyVecL *src)
{
    const uint32_t l = opCtx->params->l;
    for (uint32_t i = 0; i < l; ++i) {
        PQCP_AIGIS_SIG_NttCopy(dst->vec[i].coeffs, src->vec[i].coeffs);
    }
}
int32_t PQCP_AIGIS_SIG_PolyVecLUniformGamma1(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecL *v,
                                             const uint8_t *seed, uint32_t nonce)
{
    int32_t ret = 0;
    uint32_t i;
    const uint32_t count = opCtx->params->l;
    const uint32_t outLen = opCtx->params->polyZPackedBytes;
    if (opCtx->hashId == PQCP_AIGIS_SIG_HASH_SM3) {
        uint8_t inbuf[AIGIS_SIG_MAX_SEED_BYTES + AIGIS_SIG_MAX_CRH_BYTES + 2U];
        uint8_t outbuf[(AIGIS_SIG_N * 20U) >> 3];
        const uint32_t seedLen = opCtx->params->seedBytes + opCtx->params->crhBytes;
        (void)memcpy(inbuf, seed, seedLen);
        PQCP_AIGIS_SIG_Sm3PseudoXofBatchCtx batch = {0};
        ret = PQCP_AIGIS_SIG_Sm3PseudoXofBatchInit(&batch, opCtx->libCtx, seedLen + 2U);
        for (i = 0; i < count && ret == 0; i++) {
            inbuf[seedLen] = (uint8_t)nonce;
            inbuf[seedLen + 1U] = (uint8_t)(nonce >> 8);
            ret = PQCP_AIGIS_SIG_Sm3PseudoXofBatchGenerate(&batch, inbuf, outbuf, outLen);
            if (ret == 0) {
                PQCP_AIGIS_SIG_PolyZUnpack(opCtx, v->vec + i, outbuf);
            }
            nonce++;
        }
        PQCP_AIGIS_SIG_Sm3PseudoXofBatchFree(&batch);
        BSL_SAL_CleanseData(inbuf, sizeof(inbuf));
        BSL_SAL_CleanseData(outbuf, outLen);
        return ret;
    }
    uint8_t inbuf[AIGIS_SIG_MAX_SEED_BYTES + AIGIS_SIG_MAX_CRH_BYTES + 2U];
    uint8_t outbuf[(AIGIS_SIG_N * 20U) >> 3];
    const uint32_t seedLen = opCtx->params->seedBytes + opCtx->params->crhBytes;
    for (i = 0; i < seedLen; ++i) {
        inbuf[i] = seed[i];
    }
    for (i = 0; i < count; i++) {
        inbuf[seedLen] = nonce & 0xFF;
        inbuf[seedLen + 1U] = nonce >> 8;
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
        if (opCtx->paramId == 3 && i + 1U < count) {
            enum { RATE72_BLOCKS = (1280U + PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72 - 1U) /
                                        PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72 };
            ALIGN(32) uint8_t inbuf1[AIGIS_SIG_MAX_SEED_BYTES + AIGIS_SIG_MAX_CRH_BYTES + 2U];
            ALIGN(32) uint8_t outbuf1[RATE72_BLOCKS * PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72];
            ALIGN(32) uint8_t pairOut[RATE72_BLOCKS * PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72];
            AigisSigKeccakX2State state;
            (void)memcpy(inbuf1, inbuf, seedLen + 2U);
            inbuf1[seedLen] = (uint8_t)(nonce + 1U);
            inbuf1[seedLen + 1U] = (uint8_t)((nonce + 1U) >> 8U);
            PQCP_AIGIS_SIG_Keccakx2AbsorbArmv8(state, PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72, inbuf, inbuf1,
                                               seedLen + 2U, 0x1fU);
            PQCP_AIGIS_SIG_Keccakx2SqueezeArmv8(pairOut, outbuf1, RATE72_BLOCKS,
                                                PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72, state);
            PQCP_AIGIS_SIG_PolyZUnpack(opCtx, v->vec + i, pairOut);
            PQCP_AIGIS_SIG_PolyZUnpack(opCtx, v->vec + i + 1U, outbuf1);
            BSL_SAL_CleanseData(state, sizeof(state));
            BSL_SAL_CleanseData(inbuf1, sizeof(inbuf1));
            BSL_SAL_CleanseData(pairOut, sizeof(pairOut));
            BSL_SAL_CleanseData(outbuf1, sizeof(outbuf1));
            ++i;
            nonce += 2U;
            continue;
        }
#endif
        ret = KDF(opCtx, outbuf, outLen, inbuf, seedLen + 2U);
        if (ret != 0) {
            goto gamma1_cleanup;
        }
        PQCP_AIGIS_SIG_PolyZUnpack(opCtx, v->vec + i, outbuf);
        nonce++;
    }
gamma1_cleanup:
    BSL_SAL_CleanseData(inbuf, sizeof(inbuf));
    BSL_SAL_CleanseData(outbuf, outLen);
    return ret;
}

int32_t PQCP_AIGIS_SIG_PolyVecLUniformEta1(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecL *v,
                                           const uint8_t *seed, uint32_t nonce)
{
    int32_t ret = 0;
    uint32_t i;
    const uint32_t count = opCtx->params->l;
    const uint32_t seedBytes = opCtx->params->seedBytes;
    ALIGN(32) uint8_t inbuf[AIGIS_SIG_MAX_SEED_BYTES + 1U];
    for (i = 0; i < seedBytes; ++i) {
        inbuf[i] = seed[i];
    }
    for (i = 0; i < count; i++) {
        inbuf[seedBytes] = nonce;
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
        if (opCtx->hashId == PQCP_AIGIS_SIG_HASH_SHA3 && i + 1U < count) {
            ALIGN(32) uint8_t inbuf1[AIGIS_SIG_MAX_SEED_BYTES + 1U];
            (void)memcpy(inbuf1, inbuf, seedBytes + 1U);
            inbuf1[seedBytes] = (uint8_t)(nonce + 1U);
            ret = PQCP_AIGIS_SIG_PolyUniformEtaPairSha3Armv8(opCtx, v->vec + i, v->vec + i + 1U, inbuf, inbuf1,
                                                             seedBytes + 1U, 1U);
            BSL_SAL_CleanseData(inbuf1, sizeof(inbuf1));
            if (ret != 0) {
                break;
            }
            ++i;
            nonce += 2U;
            continue;
        }
#endif
        ret = UniformEtaSeed(opCtx, v->vec + i, inbuf, (int32_t)(seedBytes + 1U), 1);
        if (ret != 0) {
            break;
        }
        nonce++;
    }
    BSL_SAL_CleanseData(inbuf, sizeof(inbuf));
    return ret;
}
void PQCP_AIGIS_SIG_PolyVecLPointwiseAcc(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPoly *w,
                                         const AigisSigPolyVecL *u, const AigisSigPolyVecL *v)
{
    const uint32_t count = opCtx->params->l;
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
    if (count == 2U) {
        PQCP_AIGIS_SIG_PolyVecLPointwiseAccL2Vec(w, u, v);
        return;
    }
    if (count == 4U) {
        PQCP_AIGIS_SIG_PolyVecLPointwiseAccL4Vec(w, u, v);
        return;
    }
    if (count == 7U) {
        PQCP_AIGIS_SIG_PolyVecLPointwiseAccL7Vec(w, u, v);
        return;
    }
#endif
    if (count == 2U) {
        int32_t *result = w->coeffs;
        const int32_t *u0 = u->vec[0].coeffs;
        const int32_t *u1 = u->vec[1].coeffs;
        const int32_t *v0 = v->vec[0].coeffs;
        const int32_t *v1 = v->vec[1].coeffs;
        for (uint32_t coefficient = 0; coefficient < PARAM_N; ++coefficient) {
            int64_t sum = (int64_t)u0[coefficient] * v0[coefficient];
            sum += (int64_t)u1[coefficient] * v1[coefficient];
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
            result[coefficient] = PQCP_AIGIS_SIG_GeneralReduce(PQCP_AIGIS_SIG_MontgomeryReduce(sum));
#else
            result[coefficient] = PQCP_AIGIS_SIG_PlantardMulReduce(sum);
#endif
        }
        return;
    }

    int32_t *result = w->coeffs;
    if (count != 4U) {
        for (uint32_t coefficient = 0; coefficient < PARAM_N; ++coefficient) {
            int64_t sum = 0;
            for (uint32_t i = 0; i < count; ++i) {
                sum += (int64_t)u->vec[i].coeffs[coefficient] * v->vec[i].coeffs[coefficient];
            }
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
            result[coefficient] = PQCP_AIGIS_SIG_GeneralReduce(PQCP_AIGIS_SIG_MontgomeryReduce(sum));
#else
            result[coefficient] = PQCP_AIGIS_SIG_PlantardMulReduce(sum);
#endif
        }
        return;
    }

    const int32_t *u0 = u->vec[0].coeffs;
    const int32_t *u1 = u->vec[1].coeffs;
    const int32_t *u2 = u->vec[2].coeffs;
    const int32_t *u3 = u->vec[3].coeffs;
    const int32_t *v0 = v->vec[0].coeffs;
    const int32_t *v1 = v->vec[1].coeffs;
    const int32_t *v2 = v->vec[2].coeffs;
    const int32_t *v3 = v->vec[3].coeffs;
    for (uint32_t coefficient = 0; coefficient < PARAM_N; ++coefficient) {
        int64_t sum = (int64_t)u0[coefficient] * v0[coefficient];
        sum += (int64_t)u1[coefficient] * v1[coefficient];
        sum += (int64_t)u2[coefficient] * v2[coefficient];
        sum += (int64_t)u3[coefficient] * v3[coefficient];
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
        result[coefficient] = PQCP_AIGIS_SIG_GeneralReduce(PQCP_AIGIS_SIG_MontgomeryReduce(sum));
#else
        result[coefficient] = PQCP_AIGIS_SIG_PlantardMulReduce(sum);
#endif
    }
}

int32_t PQCP_AIGIS_SIG_PolyVecLCheckNorm(const PQCP_AIGIS_SIG_CoreCtx *opCtx, const AigisSigPolyVecL *v, uint32_t bound)
{
    uint32_t i;
    int ret = 0;
    const uint32_t count = opCtx->params->l;

    for (i = 0; i < count; ++i) {
        ret |= PQCP_AIGIS_SIG_PolyCheckNorm(v->vec + i, bound);
    }

    return ret;
}
void PQCP_AIGIS_SIG_PolyVecKAModQ(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecK *v)
{
    uint32_t i;
    const uint32_t count = opCtx->params->k;
    for (i = 0; i < count; ++i) {
        PQCP_AIGIS_SIG_PolyAModQ(v->vec + i);
    }
}
void PQCP_AIGIS_SIG_PolyVecKCModQ(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecK *v)
{
    uint32_t i;
    const uint32_t count = opCtx->params->k;
    for (i = 0; i < count; ++i) {
        PQCP_AIGIS_SIG_PolyCModQ(v->vec + i);
    }
}
void PQCP_AIGIS_SIG_PolyVecKGReduce(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecK *v)
{
    uint32_t i;
    const uint32_t count = opCtx->params->k;
    for (i = 0; i < count; ++i) {
        PQCP_AIGIS_SIG_PolyGReduce(v->vec + i);
    }
}
void PQCP_AIGIS_SIG_PolyVecKAddPower2Round(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecK *high,
                                           AigisSigPolyVecK *low, const AigisSigPolyVecK *u, const AigisSigPolyVecK *v)
{
    const uint32_t count = opCtx->params->k;
    for (uint32_t i = 0; i < count; ++i) {
        int32_t *highCoeffs = high->vec[i].coeffs;
        int32_t *lowCoeffs = low->vec[i].coeffs;
        const int32_t *left = u->vec[i].coeffs;
        const int32_t *right = v->vec[i].coeffs;
        for (uint32_t coefficient = 0; coefficient < PARAM_N; ++coefficient) {
            const int32_t sum = left[coefficient] + right[coefficient];
            const int32_t canonical = PQCP_AIGIS_SIG_PositiveReduce(sum);
            highCoeffs[coefficient] = Power2RoundParam(canonical, &lowCoeffs[coefficient], opCtx->params->d);
        }
    }
}

#ifdef PQCP_AIGIS_SIG_PORTABLE_BACKEND
void PQCP_AIGIS_SIG_PolyVecKAModQDecompose(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecK *high,
                                           AigisSigPolyVecK *low, const AigisSigPolyVecK *v)
{
    const uint32_t count = opCtx->params->k;
    for (uint32_t i = 0; i < count; ++i) {
        int32_t *highCoeffs = high->vec[i].coeffs;
        int32_t *lowCoeffs = low->vec[i].coeffs;
        const int32_t *input = v->vec[i].coeffs;
        for (uint32_t coefficient = 0; coefficient < PARAM_N; ++coefficient) {
            /* The signing caller supplies the inverse-NTT result in
             * (-0.6q, 0.6q), within PositiveReduce's one-add domain. */
            const int32_t canonical = PQCP_AIGIS_SIG_PositiveReduce(input[coefficient]);
            highCoeffs[coefficient] = DecomposeParam(canonical, &lowCoeffs[coefficient], opCtx->params);
        }
    }
}

int32_t PQCP_AIGIS_SIG_PolyVecKSubWCModQCheckNorm(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecK *v,
                                                  const AigisSigPolyVecK *u, const AigisSigPolyVecK *w, uint32_t bound)
{
    uint32_t outOfRange = 0;
    const uint32_t count = opCtx->params->k;
    for (uint32_t i = 0; i < count; ++i) {
        int32_t *result = v->vec[i].coeffs;
        const int32_t *input = u->vec[i].coeffs;
        const int32_t *high = w->vec[i].coeffs;
        for (uint32_t coefficient = 0; coefficient < PARAM_N; ++coefficient) {
            /* GeneralReduce supplies u in the centered q range and UseHint
             * supplies w in [0, AIGIS_SIG_MAX_HIGH].  Therefore difference is
             * representable as int32_t before CenteredReduce. */
            const int64_t difference =
                (int64_t)input[coefficient] - (int64_t)high[coefficient] * opCtx->params->alpha;
            const int32_t centered = PQCP_AIGIS_SIG_CenteredReduce((int32_t)difference);
            result[coefficient] = centered;
            outOfRange |= (uint32_t)((int64_t)centered > (int64_t)bound);
            outOfRange |= (uint32_t)((int64_t)centered < 1 - (int64_t)bound);
        }
    }
    return (int32_t)outOfRange;
}
#endif

void PQCP_AIGIS_SIG_PolyVecKSubW(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecK *v, const AigisSigPolyVecK *u,
                                 const AigisSigPolyVecK *w)
{
    const uint32_t count = opCtx->params->k;
    for (uint32_t i = 0; i < count; ++i) {
        int32_t *result = v->vec[i].coeffs;
        const int32_t *input = u->vec[i].coeffs;
        const int32_t *high = w->vec[i].coeffs;
        for (uint32_t coefficient = 0; coefficient < PARAM_N; ++coefficient) {
            result[coefficient] =
                (int32_t)((int64_t)input[coefficient] - (int64_t)high[coefficient] * opCtx->params->alpha);
        }
    }
}

void PQCP_AIGIS_SIG_PolyVecKShiftLeft(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecK *v, uint32_t k)
{
    uint32_t i;
    const uint32_t count = opCtx->params->k;

    for (i = 0; i < count; ++i) {
        PQCP_AIGIS_SIG_PolyShiftLeft(v->vec + i, k);
    }
}
int32_t PQCP_AIGIS_SIG_PolyVecKUniformEta2(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecK *v,
                                           const uint8_t *seed, uint32_t nonce)
{
    int32_t ret = 0;
    uint32_t i;
    const uint32_t count = opCtx->params->k;
    const uint32_t seedBytes = opCtx->params->seedBytes;
    ALIGN(32) uint8_t inbuf[AIGIS_SIG_MAX_SEED_BYTES + 1U];
    for (i = 0; i < seedBytes; ++i) {
        inbuf[i] = seed[i];
    }
    for (i = 0; i < count; i++) {
        inbuf[seedBytes] = nonce;
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
        if (opCtx->hashId == PQCP_AIGIS_SIG_HASH_SHA3 && i + 1U < count) {
            ALIGN(32) uint8_t inbuf1[AIGIS_SIG_MAX_SEED_BYTES + 1U];
            (void)memcpy(inbuf1, inbuf, seedBytes + 1U);
            inbuf1[seedBytes] = (uint8_t)(nonce + 1U);
            ret = PQCP_AIGIS_SIG_PolyUniformEtaPairSha3Armv8(opCtx, v->vec + i, v->vec + i + 1U, inbuf, inbuf1,
                                                             seedBytes + 1U, 2U);
            BSL_SAL_CleanseData(inbuf1, sizeof(inbuf1));
            if (ret != 0) {
                break;
            }
            ++i;
            nonce += 2U;
            continue;
        }
#endif
        ret = UniformEtaSeed(opCtx, v->vec + i, inbuf, (int32_t)(seedBytes + 1U), 2);
        if (ret != 0) {
            break;
        }
        nonce++;
    }
    BSL_SAL_CleanseData(inbuf, sizeof(inbuf));
    return ret;
}
void PQCP_AIGIS_SIG_PolyVecKNtt(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecK *v)
{
    uint32_t i;
    const uint32_t k = opCtx->params->k;

    for (i = 0; i < k; ++i) {
        PQCP_AIGIS_SIG_Ntt(v->vec[i].coeffs);
    }
}

void PQCP_AIGIS_SIG_PolyVecKInvNtt(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecK *v)
{
    uint32_t i;
    const uint32_t k = opCtx->params->k;

    for (i = 0; i < k; ++i) {
        PQCP_AIGIS_SIG_InvNtt(v->vec[i].coeffs);
    }
}

int32_t PQCP_AIGIS_SIG_PolyVecKCheckNorm(const PQCP_AIGIS_SIG_CoreCtx *opCtx, const AigisSigPolyVecK *v, uint32_t bound)
{
    uint32_t i;
    int ret = 0;
    const uint32_t count = opCtx->params->k;

    for (i = 0; i < count; ++i) {
        ret |= PQCP_AIGIS_SIG_PolyCheckNorm(v->vec + i, bound);
    }

    return ret;
}

void PQCP_AIGIS_SIG_PolyVecKDecompose(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecK *v1, AigisSigPolyVecK *v0,
                                      const AigisSigPolyVecK *v)
{
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
    if (opCtx->paramId == 3) {
        PQCP_AIGIS_SIG_PolyVecKDecomposeD13Armv8(v1, v0, v, opCtx->params->k);
        return;
    }
#endif
    uint32_t i;
    const uint32_t count = opCtx->params->k;
    for (i = 0; i < count; ++i) {
        for (uint32_t j = 0; j < PARAM_N; ++j) {
            v1->vec[i].coeffs[j] = DecomposeParam(v->vec[i].coeffs[j], &v0->vec[i].coeffs[j], opCtx->params);
        }
    }
}

int32_t PQCP_AIGIS_SIG_PolyVecKMakeHint(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecK *h,
                                        const AigisSigPolyVecK *u, const AigisSigPolyVecK *v)
{
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
    if (opCtx->paramId == 3) {
        return PQCP_AIGIS_SIG_PolyVecKMakeHintD13Armv8(h, u, v, opCtx->params->k);
    }
#endif
    uint32_t i, j, k, s = 0, t = 0;
    const uint32_t count = opCtx->params->k;

    for (i = 0; i < count; ++i) {
        int32_t *hint = h->vec[i].coeffs;
        const int32_t *low = u->vec[i].coeffs;
        const int32_t *high = v->vec[i].coeffs;
        for (j = 0; j < PARAM_N / SEC; ++j) {
            s = 0;
            for (k = 0; k < SEC; ++k) {
                const uint32_t coefficient = SEC * j + k;
                hint[coefficient] = MakeHintParam(low[coefficient], high[coefficient], opCtx->params);
                s += hint[coefficient];
            }
            if (s > NHW) {
                return -1;
            }
            t += s;
        }
    }
    return (int32_t)t;
}

void PQCP_AIGIS_SIG_PolyVecKUseHint(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecK *w, const AigisSigPolyVecK *u,
                                    const AigisSigPolyVecK *h)
{
    const uint32_t count = opCtx->params->k;
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
    if (opCtx->paramId == 3) {
        PQCP_AIGIS_SIG_PolyVecKDecomposeUseHintD13Armv8(w, u, h, count);
        return;
    } else {
        for (uint32_t i = 0; i < count; ++i) {
            PQCP_AIGIS_SIG_PolyDecomposeUseHint(w->vec[i].coeffs, u->vec[i].coeffs, h->vec[i].coeffs);
        }
        return;
    }
#endif
    for (uint32_t i = 0; i < count; ++i) {
        int32_t *result = w->vec[i].coeffs;
        const int32_t *input = u->vec[i].coeffs;
        const int32_t *hint = h->vec[i].coeffs;
        for (uint32_t j = 0; j < PARAM_N; ++j) {
            int32_t low;
            const int32_t high = DecomposeParam(input[j], &low, opCtx->params);
            if (hint[j] == 0) {
                result[j] = high;
            } else if (low > 0) {
                result[j] = (high == (int32_t)opCtx->params->maxHigh) ? 0 : high + 1;
            } else {
                result[j] = (high == 0) ? (int32_t)opCtx->params->maxHigh : high - 1;
            }
        }
    }
}
