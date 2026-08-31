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

#include <string.h>

#define HINT_SECTION_SHIFT      3
#define HINT_SECTIONS_PER_POLY  (1 << HINT_SECTION_SHIFT)
#define HINT_SECTION_INDEX_MASK (HINT_SECTIONS_PER_POLY - 1)

#if PARAM_N != SEC * HINT_SECTIONS_PER_POLY
#error "hint section indexing requires eight sections per polynomial"
#endif
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
void PQCP_AIGIS_SIG_UnpackCenteredArmv8(AigisSigPoly *r, const uint8_t *in, uint32_t center, uint32_t bits);
int32_t PQCP_AIGIS_SIG_PolyVecLUnpackZCheckNormArmv8(AigisSigPolyVecL *r, const uint8_t *in, uint32_t count,
                                                     uint32_t center, uint32_t bits, uint32_t bound);
#endif

static void UnpackUnsigned(int32_t *coeffs, const uint8_t *in, uint32_t bits)
{
    uint64_t bitBuffer = 0;
    uint32_t bitCount = 0;
    uint32_t inPos = 0;
    const uint32_t mask = (UINT32_C(1) << bits) - 1U;
    for (uint32_t i = 0; i < PARAM_N; ++i) {
        while (bitCount < bits) {
            bitBuffer |= (uint64_t)in[inPos++] << bitCount;
            bitCount += 8U;
        }
        coeffs[i] = (int32_t)((uint32_t)bitBuffer & mask);
        bitBuffer >>= bits;
        bitCount -= bits;
    }
}

static void PackT0(uint8_t *out, const AigisSigPoly *a, uint32_t d);

static void PackEta1(uint8_t *out, const AigisSigPoly *a)
{
    const int32_t *coeffs = a->coeffs;
    for (uint32_t i = 0, j = 0; i < PARAM_N; i += 4U, ++j) {
        out[j] = (uint8_t)((1U - (uint32_t)coeffs[i]) | ((1U - (uint32_t)coeffs[i + 1U]) << 2U) |
                           ((1U - (uint32_t)coeffs[i + 2U]) << 4U) | ((1U - (uint32_t)coeffs[i + 3U]) << 6U));
    }
}

static void PackEta5(uint8_t *out, const AigisSigPoly *a)
{
    const int32_t *coeffs = a->coeffs;
    for (uint32_t i = 0, j = 0; i < PARAM_N; i += 2U, ++j) {
        out[j] = (uint8_t)((5U - (uint32_t)coeffs[i]) | ((5U - (uint32_t)coeffs[i + 1U]) << 4U));
    }
}

static void UnpackEta1(AigisSigPoly *r, const uint8_t *in)
{
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
    PQCP_AIGIS_SIG_UnpackCenteredArmv8(r, in, 1U, 2U);
#else
    int32_t *coeffs = r->coeffs;
    for (uint32_t i = 0, j = 0; i < PARAM_N; i += 4U, ++j) {
        const uint8_t packed = in[j];
        coeffs[i] = 1 - (int32_t)(packed & 0x03U);
        coeffs[i + 1U] = 1 - (int32_t)(packed >> 2U & 0x03U);
        coeffs[i + 2U] = 1 - (int32_t)(packed >> 4U & 0x03U);
        coeffs[i + 3U] = 1 - (int32_t)(packed >> 6U);
    }
#endif
}

static void UnpackEta5(AigisSigPoly *r, const uint8_t *in)
{
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
    PQCP_AIGIS_SIG_UnpackCenteredArmv8(r, in, 5U, 4U);
#else
    int32_t *coeffs = r->coeffs;
    for (uint32_t i = 0, j = 0; i < PARAM_N; i += 2U, ++j) {
        const uint8_t packed = in[j];
        coeffs[i] = 5 - (int32_t)(packed & 0x0fU);
        coeffs[i + 1U] = 5 - (int32_t)(packed >> 4U);
    }
#endif
}

static void PackT1(uint8_t *out, const AigisSigPoly *a, uint32_t bits)
{
    if (bits == 9U) {
        const int32_t *coeffs = a->coeffs;
        for (uint32_t i = 0, j = 0; i < PARAM_N; i += 8U, j += 9U) {
            const uint32_t t0 = (uint32_t)coeffs[i];
            const uint32_t t1 = (uint32_t)coeffs[i + 1U];
            const uint32_t t2 = (uint32_t)coeffs[i + 2U];
            const uint32_t t3 = (uint32_t)coeffs[i + 3U];
            const uint32_t t4 = (uint32_t)coeffs[i + 4U];
            const uint32_t t5 = (uint32_t)coeffs[i + 5U];
            const uint32_t t6 = (uint32_t)coeffs[i + 6U];
            const uint32_t t7 = (uint32_t)coeffs[i + 7U];
            uint64_t low = (uint64_t)t0 | ((uint64_t)t1 << 9U) | ((uint64_t)t2 << 18U) |
                           ((uint64_t)t3 << 27U) | ((uint64_t)t4 << 36U) | ((uint64_t)t5 << 45U) |
                           ((uint64_t)t6 << 54U) | ((uint64_t)t7 << 63U);
#ifdef HITLS_BIG_ENDIAN
            low = __builtin_bswap64(low);
#endif
            (void)memcpy(out + j, &low, sizeof(low));
            out[j + 8U] = (uint8_t)(t7 >> 1U);
        }
        return;
    }
    const int32_t *coeffs = a->coeffs;
    for (uint32_t i = 0, j = 0; i < PARAM_N; i += 8U, j += 7U) {
        out[j] = (uint8_t)(coeffs[i] | coeffs[i + 1U] << 7);
        out[j + 1U] = (uint8_t)(coeffs[i + 1U] >> 1 | coeffs[i + 2U] << 6);
        out[j + 2U] = (uint8_t)(coeffs[i + 2U] >> 2 | coeffs[i + 3U] << 5);
        out[j + 3U] = (uint8_t)(coeffs[i + 3U] >> 3 | coeffs[i + 4U] << 4);
        out[j + 4U] = (uint8_t)(coeffs[i + 4U] >> 4 | coeffs[i + 5U] << 3);
        out[j + 5U] = (uint8_t)(coeffs[i + 5U] >> 5 | coeffs[i + 6U] << 2);
        out[j + 6U] = (uint8_t)(coeffs[i + 6U] >> 6 | coeffs[i + 7U] << 1);
    }
}

static void UnpackT1(AigisSigPoly *r, const uint8_t *in, uint32_t bits)
{
    if (bits == 9U) {
        int32_t *coeffs = r->coeffs;
        for (uint32_t i = 0, j = 0; i < PARAM_N; i += 8U, j += 9U) {
            coeffs[i] = (int32_t)((uint32_t)in[j] | ((uint32_t)in[j + 1U] & 0x01U) << 8U);
            coeffs[i + 1U] = (int32_t)((uint32_t)in[j + 1U] >> 1U |
                                               ((uint32_t)in[j + 2U] & 0x03U) << 7U);
            coeffs[i + 2U] = (int32_t)((uint32_t)in[j + 2U] >> 2U |
                                               ((uint32_t)in[j + 3U] & 0x07U) << 6U);
            coeffs[i + 3U] = (int32_t)((uint32_t)in[j + 3U] >> 3U |
                                               ((uint32_t)in[j + 4U] & 0x0fU) << 5U);
            coeffs[i + 4U] = (int32_t)((uint32_t)in[j + 4U] >> 4U |
                                               ((uint32_t)in[j + 5U] & 0x1fU) << 4U);
            coeffs[i + 5U] = (int32_t)((uint32_t)in[j + 5U] >> 5U |
                                               ((uint32_t)in[j + 6U] & 0x3fU) << 3U);
            coeffs[i + 6U] = (int32_t)((uint32_t)in[j + 6U] >> 6U |
                                               ((uint32_t)in[j + 7U] & 0x7fU) << 2U);
            coeffs[i + 7U] = (int32_t)((uint32_t)in[j + 7U] >> 7U | (uint32_t)in[j + 8U] << 1U);
        }
        return;
    }
    int32_t *coeffs = r->coeffs;
    for (uint32_t i = 0, j = 0; i < PARAM_N; i += 8U, j += 7U) {
        coeffs[i] = in[j] & 0x7fU;
        coeffs[i + 1U] = ((in[j + 1U] & 0x3fU) << 1) | (in[j] >> 7);
        coeffs[i + 2U] = ((in[j + 2U] & 0x1fU) << 2) | (in[j + 1U] >> 6);
        coeffs[i + 3U] = ((in[j + 3U] & 0x0fU) << 3) | (in[j + 2U] >> 5);
        coeffs[i + 4U] = ((in[j + 4U] & 0x07U) << 4) | (in[j + 3U] >> 4);
        coeffs[i + 5U] = ((in[j + 5U] & 0x03U) << 5) | (in[j + 4U] >> 3);
        coeffs[i + 6U] = ((in[j + 6U] & 0x01U) << 6) | (in[j + 5U] >> 2);
        coeffs[i + 7U] = in[j + 6U] >> 1;
    }
}

/*************************************************
 * pack the public key pk,
 * where pk = rho|t1
 **************************************************/
void PQCP_AIGIS_SIG_PackPublicKey(const PQCP_AIGIS_SIG_CoreCtx *opCtx, uint8_t *pk,
                                  const uint8_t rho[AIGIS_SIG_MAX_SEED_BYTES],
                                  const AigisSigPolyVecK *t1)
{
    uint32_t i;
    const AigisSigParams *params = opCtx->params;
    const uint32_t count = params->k;
    const uint32_t t1Bits = QBITS - params->d;

    (void)memcpy(pk, rho, params->seedBytes);
    pk += params->seedBytes;

    for (i = 0; i < count; ++i) {
        PackT1(pk + i * params->polyT1PackedBytes, t1->vec + i, t1Bits);
    }
}
void PQCP_AIGIS_SIG_UnpackPublicKey(const PQCP_AIGIS_SIG_CoreCtx *opCtx,
                                    uint8_t rho[AIGIS_SIG_MAX_SEED_BYTES], AigisSigPolyVecK *t1,
                                    const uint8_t *pk)
{
    uint32_t i;
    const AigisSigParams *params = opCtx->params;
    const uint32_t count = params->k;
    const uint32_t t1Bits = QBITS - params->d;

    (void)memcpy(rho, pk, params->seedBytes);
    pk += params->seedBytes;

    for (i = 0; i < count; ++i) {
        UnpackT1(t1->vec + i, pk + i * params->polyT1PackedBytes, t1Bits);
    }
}

/*************************************************
 * pack the secret key sk,
 * where sk = rho|key|hash(pk)|s1|s2|t0
 **************************************************/
void PQCP_AIGIS_SIG_PackPrivateKey(const PQCP_AIGIS_SIG_CoreCtx *opCtx, uint8_t *sk,
                                   const uint8_t rho[AIGIS_SIG_MAX_SEED_BYTES],
                                   const uint8_t key[AIGIS_SIG_MAX_SEED_BYTES],
                                   const uint8_t hashpk[AIGIS_SIG_MAX_CRH_BYTES],
                                   const AigisSigPolyVecL *s1, const AigisSigPolyVecK *s2, const AigisSigPolyVecK *t0)
{
    uint32_t i;
    const AigisSigParams *params = opCtx->params;
    const uint32_t k = params->k;
    const uint32_t l = params->l;
    const uint32_t eta2Bytes = params->polyEta2PackedBytes;

    (void)memcpy(sk, rho, params->seedBytes);
    sk += params->seedBytes;
    (void)memcpy(sk, key, params->seedBytes);
    sk += params->seedBytes;
    (void)memcpy(sk, hashpk, params->crhBytes);
    sk += params->crhBytes;

    for (i = 0; i < l; ++i) {
        PackEta1(sk + i * params->polyEta1PackedBytes, s1->vec + i);
    }
    sk += l * params->polyEta1PackedBytes;

    if (params->eta2Bits == 2U) {
        for (i = 0; i < k; ++i) {
            PackEta1(sk + i * eta2Bytes, s2->vec + i);
        }
    } else {
        for (i = 0; i < k; ++i) {
            PackEta5(sk + i * eta2Bytes, s2->vec + i);
        }
    }
    sk += k * eta2Bytes;

    for (i = 0; i < k; ++i) {
        PackT0(sk + i * params->polyT0PackedBytes, t0->vec + i, params->d);
    }
}

static void PackT0(uint8_t *out, const AigisSigPoly *a, uint32_t d)
{
    if (d == 13U) {
        const int32_t *coeffs = a->coeffs;
        const uint32_t center = UINT32_C(1) << 12U;
        for (uint32_t i = 0, j = 0; i < PARAM_N; i += 8U, j += 13U) {
            const uint64_t t0 = center - (uint32_t)coeffs[i];
            const uint64_t t1 = center - (uint32_t)coeffs[i + 1U];
            const uint64_t t2 = center - (uint32_t)coeffs[i + 2U];
            const uint64_t t3 = center - (uint32_t)coeffs[i + 3U];
            const uint64_t t4 = center - (uint32_t)coeffs[i + 4U];
            const uint64_t t5 = center - (uint32_t)coeffs[i + 5U];
            const uint64_t t6 = center - (uint32_t)coeffs[i + 6U];
            const uint64_t t7 = center - (uint32_t)coeffs[i + 7U];
            uint64_t low = t0 | (t1 << 13U) | (t2 << 26U) | (t3 << 39U) | (t4 << 52U);
            uint64_t high = (t4 >> 12U) | (t5 << 1U) | (t6 << 14U) | (t7 << 27U);
#ifdef HITLS_BIG_ENDIAN
            low = __builtin_bswap64(low);
            uint32_t highLow = __builtin_bswap32((uint32_t)high);
#else
            uint32_t highLow = (uint32_t)high;
#endif
            (void)memcpy(out + j, &low, sizeof(low));
            (void)memcpy(out + j + sizeof(low), &highLow, sizeof(highLow));
            out[j + 12U] = (uint8_t)(high >> 32U);
        }
        return;
    }
    const int32_t *coeffs = a->coeffs;
    const int32_t center = 1 << (PARAM_D - 1);
    for (uint32_t i = 0, j = 0; i < PARAM_N; i += 8U, j += 15U) {
        const int32_t t0 = center - coeffs[i];
        const int32_t t1 = center - coeffs[i + 1U];
        const int32_t t2 = center - coeffs[i + 2U];
        const int32_t t3 = center - coeffs[i + 3U];
        const int32_t t4 = center - coeffs[i + 4U];
        const int32_t t5 = center - coeffs[i + 5U];
        const int32_t t6 = center - coeffs[i + 6U];
        const int32_t t7 = center - coeffs[i + 7U];
        out[j] = (uint8_t)t0;
        out[j + 1U] = (uint8_t)((t0 >> 8) | (t1 << 7));
        out[j + 2U] = (uint8_t)(t1 >> 1);
        out[j + 3U] = (uint8_t)((t1 >> 9) | (t2 << 6));
        out[j + 4U] = (uint8_t)(t2 >> 2);
        out[j + 5U] = (uint8_t)((t2 >> 10) | (t3 << 5));
        out[j + 6U] = (uint8_t)(t3 >> 3);
        out[j + 7U] = (uint8_t)((t3 >> 11) | (t4 << 4));
        out[j + 8U] = (uint8_t)(t4 >> 4);
        out[j + 9U] = (uint8_t)((t4 >> 12) | (t5 << 3));
        out[j + 10U] = (uint8_t)(t5 >> 5);
        out[j + 11U] = (uint8_t)((t5 >> 13) | (t6 << 2));
        out[j + 12U] = (uint8_t)(t6 >> 6);
        out[j + 13U] = (uint8_t)((t6 >> 14) | (t7 << 1));
        out[j + 14U] = (uint8_t)(t7 >> 7);
    }
}

static void UnpackT0(AigisSigPoly *r, const uint8_t *in, uint32_t d)
{
    if (d == 13U) {
        const int32_t center = (int32_t)(UINT32_C(1) << (d - 1U));
        UnpackUnsigned(r->coeffs, in, d);
        for (uint32_t i = 0; i < PARAM_N; ++i) {
            r->coeffs[i] = center - r->coeffs[i];
        }
        return;
    }
    int32_t *coeffs = r->coeffs;
    const int32_t center = 1 << (PARAM_D - 1);
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
        coeffs[i] = center - (int32_t)t0;
        coeffs[i + 1U] = center - (int32_t)t1;
        coeffs[i + 2U] = center - (int32_t)t2;
        coeffs[i + 3U] = center - (int32_t)t3;
        coeffs[i + 4U] = center - (int32_t)t4;
        coeffs[i + 5U] = center - (int32_t)t5;
        coeffs[i + 6U] = center - (int32_t)t6;
        coeffs[i + 7U] = center - (int32_t)t7;
    }
}

void PQCP_AIGIS_SIG_UnpackPrivateKey(const PQCP_AIGIS_SIG_CoreCtx *opCtx,
                                     uint8_t rho[AIGIS_SIG_MAX_SEED_BYTES],
                                     uint8_t key[AIGIS_SIG_MAX_SEED_BYTES],
                                     uint8_t hashpk[AIGIS_SIG_MAX_CRH_BYTES], AigisSigPolyVecL *s1,
                                     AigisSigPolyVecK *s2, AigisSigPolyVecK *t0, const uint8_t *sk)
{
    uint32_t i;
    const AigisSigParams *params = opCtx->params;
    const uint32_t k = params->k;
    const uint32_t l = params->l;
    const uint32_t eta2Bytes = params->polyEta2PackedBytes;
    (void)memcpy(rho, sk, params->seedBytes);
    sk += params->seedBytes;
    (void)memcpy(key, sk, params->seedBytes);
    sk += params->seedBytes;
    (void)memcpy(hashpk, sk, params->crhBytes);

    sk += params->crhBytes;

    for (uint32_t j = 0; j < l; j++) {
        UnpackEta1(&s1->vec[j], sk + j * params->polyEta1PackedBytes);
    }
    sk += l * params->polyEta1PackedBytes;

    if (params->eta2Bits == 2U) {
        for (i = 0; i < k; ++i) {
            UnpackEta1(&s2->vec[i], sk + i * eta2Bytes);
        }
    } else {
        for (i = 0; i < k; ++i) {
            UnpackEta5(&s2->vec[i], sk + i * eta2Bytes);
        }
    }
    sk += k * eta2Bytes;

    for (i = 0; i < k; ++i) {
        UnpackT0(t0->vec + i, sk + i * params->polyT0PackedBytes, params->d);
    }
}
/*************************************************
 * pack the signature sig,
 * where sig = z|h|challengeSeed
 **************************************************/
static uint8_t Pack4Bits(uint8_t *sig, const uint8_t *t, int k)
{
    int i;
    int len = (k + 1) >> 1;

    memset(sig, 0, (size_t)len);
    for (i = 0; i < k; ++i) {
        sig[i >> 1] |= (uint8_t)((t[i] & 0x0fU) << ((i & 1) * 4));
    }
    return (uint8_t)len;
}
static int32_t Unpack4Bits(uint8_t *t, const uint8_t *sig, int k)
{
    int i;
    int len = (k + 1) >> 1;

    for (i = 0; i < k; ++i) {
        t[i] = (uint8_t)((sig[i >> 1] >> ((i & 1) * 4)) & 0x0fU);
    }
    return len;
}
static int Pack6Bits(uint8_t *sig, const uint8_t *t, int k)
{
    int i = 0;
    int len = (k * 6 + 7) >> 3;

    for (; i + 4 <= k; i += 4, sig += 3) {
        sig[0] = (uint8_t)((t[i] & 0x3fU) | (t[i + 1] & 0x03U) << 6);
        sig[1] = (uint8_t)(((t[i + 1] & 0x3fU) >> 2) | (t[i + 2] & 0x0fU) << 4);
        sig[2] = (uint8_t)(((t[i + 2] & 0x3fU) >> 4) | (t[i + 3] & 0x3fU) << 2);
    }
    if (i < k) {
        sig[0] = (uint8_t)(t[i] & 0x3fU);
        if (++i < k) {
            sig[0] |= (uint8_t)((t[i] & 0x03U) << 6);
            sig[1] = (uint8_t)((t[i] & 0x3fU) >> 2);
            if (++i < k) {
                sig[1] |= (uint8_t)((t[i] & 0x0fU) << 4);
                sig[2] = (uint8_t)((t[i] & 0x3fU) >> 4);
            }
        }
    }
    return len;
}
static int32_t Unpack6Bits(uint32_t *t, const uint8_t *sig, int k)
{
    int i = 0;

    for (; i + 4 <= k; i += 4, sig += 3) {
        t[i] = sig[0] & 0x3fU;
        t[i + 1] = ((uint32_t)sig[0] >> 6 | (uint32_t)sig[1] << 2) & 0x3fU;
        t[i + 2] = ((uint32_t)sig[1] >> 4 | (uint32_t)sig[2] << 4) & 0x3fU;
        t[i + 3] = (uint32_t)sig[2] >> 2;
    }
    if (i < k) {
        t[i] = sig[0] & 0x3fU;
        if (++i < k) {
            t[i] = ((uint32_t)sig[0] >> 6 | (uint32_t)sig[1] << 2) & 0x3fU;
            if (++i < k) {
                t[i] = ((uint32_t)sig[1] >> 4 | (uint32_t)sig[2] << 4) & 0x3fU;
            }
        }
    }
    return (k * 6 + 7) >> 3;
}
static int PackHint(const AigisSigParams *params, uint8_t *sig, const AigisSigPolyVecK *h)
{
    uint32_t i;
    const uint32_t count = params->k;
    int j, k, r;
    int len;
    ALIGN(32) uint8_t pos[176]; // maximum OMEGA of the supported sets
    const int secs = HINT_SECTIONS_PER_POLY; // num of secs per AigisSigPoly
    ALIGN(32) uint8_t t[HINT_SECTIONS_PER_POLY * AIGIS_SIG_MAX_K]; // num of 1s per sec
    int start;
    k = 0;
    uint8_t max = 0;
    for (i = 0; i < count; ++i) {
        const int32_t *hint = h->vec[i].coeffs;
        for (j = 0; j < HINT_SECTIONS_PER_POLY; j++) {
            start = k;
            for (r = 0; r < SEC; r++) {
                if (hint[SEC * j + r]) {
                    pos[k++] = r;
                }
            }
            t[secs * i + j] = k - start;
            if (t[secs * i + j] != 0) {
                max = secs * i + j + 1;
            }
        }
    }
    sig[0] = max;
    sig += 1;
    len = Pack4Bits(sig, t, max);
    sig += len;
    len += Pack6Bits(sig, pos, k) + 1;
    return len;
}

static int UnpackHint(const AigisSigParams *params, AigisSigPolyVecK *h, const uint8_t *sig, uint32_t sigLen)
{
    int i, j, k, r;
    const uint32_t count = params->k;
    const uint32_t omega = params->omega;
    ALIGN(32) uint32_t pos[176];
    ALIGN(32) uint8_t t[64] = {0};
    size_t countLen, posLen;
    int max;

    if (sigLen < 1) {
        return -1;
    }
    max = sig[0];
    if ((uint32_t)max > count * HINT_SECTIONS_PER_POLY) {
        return -1;
    }
    countLen = ((size_t)max + 1) >> 1;
    if (sigLen < 1 + countLen) {
        return -1;
    }
    if ((max & 1) != 0 && (sig[countLen] & 0xf0) != 0) {
        return -1;
    }
    if (max != 0) {
        const uint32_t shift = ((uint32_t)(max - 1) & 1U) << 2;
        if (((sig[countLen] >> shift) & 0x0fU) == 0) {
            return -1;
        }
    }

    for (uint32_t i = 0; i < count; i++) {
        int32_t *hint = h->vec[i].coeffs;
        for (int j = 0; j < PARAM_N; j++) {
            hint[j] = 0;
        }
    }

    sig += 1;
    sig += Unpack4Bits(t, sig, max);

    k = 0;
    for (i = 0; i < max; i++) {
        k += t[i];
    }
    if ((uint32_t)k > omega) {
        return -1;
    }
    posLen = ((size_t)k * 6 + 7) >> 3;
    if (sigLen != 1 + countLen + posLen) {
        return -1;
    }
    if (posLen != 0 && ((size_t)k * 6 & 7) != 0 && (sig[posLen - 1] >> ((size_t)k * 6 & 7)) != 0) {
        return -1;
    }

    Unpack6Bits(pos, sig, k);

    r = 0;
    for (k = 0; k < max; k++) {
        int previous = -1;
        i = k >> HINT_SECTION_SHIFT;
        j = k & HINT_SECTION_INDEX_MASK;
        int32_t *hint = h->vec[i].coeffs;
        for (int start = 0; start < t[k]; start++) {
            if (pos[r] >= SEC || (int)pos[r] <= previous) {
                return -1;
            }
            previous = (int)pos[r];
            hint[SEC * j + pos[r++]] = 1;
        }
    }

    return 0;
}

int32_t PQCP_AIGIS_SIG_PackSignature(const PQCP_AIGIS_SIG_CoreCtx *opCtx, uint8_t *sig, const AigisSigPolyVecL *z,
                                     const uint8_t *challengeSeed, const AigisSigPolyVecK *h)
{
    uint32_t i;
    int sigLen;
    const AigisSigParams *params = opCtx->params;
    const uint32_t count = params->l;
    const uint32_t packedBytes = params->polyZPackedBytes;
    const uint32_t prefixLen = count * packedBytes + params->seedBytes;

    for (i = 0; i < count; ++i) {
        PQCP_AIGIS_SIG_PolyZPack(opCtx, sig + i * packedBytes, z->vec + i);
    }
    sig += count * packedBytes;

    /* Encode challengeSeed */
    (void)memcpy(sig, challengeSeed, params->seedBytes);
    sig += params->seedBytes;

    // pack h
    sigLen = PackHint(params, sig, h);
    sigLen += (int)prefixLen;

    return sigLen;
}

int32_t PQCP_AIGIS_SIG_UnpackSignature(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecL *z, AigisSigPolyVecK *h,
                                       uint8_t *challengeSeed, const uint8_t *sig, uint32_t sigLen)
{
    uint32_t i;
    const AigisSigParams *params = opCtx->params;
    const uint32_t count = params->l;
    const uint32_t packedBytes = params->polyZPackedBytes;
    const size_t prefixLen = (size_t)count * packedBytes + params->seedBytes;

    if (sig == NULL || sigLen < prefixLen + 1 || sigLen > params->signatureMaxBytes) {
        return -1;
    }

    for (i = 0; i < count; ++i) {
        PQCP_AIGIS_SIG_PolyZUnpack(opCtx, z->vec + i, sig + i * packedBytes);
    }
    sig += count * packedBytes;

    /* Decode challengeSeed */
    (void)memcpy(challengeSeed, sig, params->seedBytes);
    sig += params->seedBytes;

    return UnpackHint(params, h, sig, sigLen - prefixLen);
}

#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
int32_t PQCP_AIGIS_SIG_UnpackSignatureCheckZ(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecL *z,
                                             AigisSigPolyVecK *h, uint8_t *challengeSeed, const uint8_t *sig,
                                             uint32_t sigLen, uint32_t bound)
{
    const AigisSigParams *params = opCtx->params;
    const uint32_t count = params->l;
    const uint32_t packedBytes = params->polyZPackedBytes;
    const size_t prefixLen = (size_t)count * packedBytes + params->seedBytes;
    int32_t normFailed;
    int32_t hintFailed;

    if (sig == NULL || sigLen < prefixLen + 1 || sigLen > params->signatureMaxBytes) {
        return -1;
    }

    /* The fused assembly decoder has fixed 15- and 17-bit shuffle tables.
     * Parameter III uses 20-bit responses, so use the generic bit-width
     * decoder and preserve the same strict norm predicate. */
    if (params->szBits == 20U) {
        return PQCP_AIGIS_SIG_UnpackSignature(opCtx, z, h, challengeSeed, sig, sigLen) != 0 ||
                       PQCP_AIGIS_SIG_PolyVecLCheckNorm(opCtx, z, bound) != 0
                   ? -1
                   : 0;
    }

    normFailed = PQCP_AIGIS_SIG_PolyVecLUnpackZCheckNormArmv8(z, sig, count, params->gamma1, params->szBits, bound);
    sig += count * packedBytes;

    /* Decode all remaining fields even when the decoded response is out of range. */
    (void)memcpy(challengeSeed, sig, params->seedBytes);
    sig += params->seedBytes;
    hintFailed = UnpackHint(params, h, sig, sigLen - prefixLen);

    return (normFailed != 0 || hintFailed != 0) ? -1 : 0;
}
#endif
