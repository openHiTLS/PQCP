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

#include "bsl_sal.h"
#include "pqcp_err.h"
#include "nev_local.h"

#define NEV_KEYGEN_MAX_ATTEMPTS 256U
#define NEV_WORKSPACE_POLY_CNT 4U

/* Cleanse only the LIVE coefficients (info->n) of each workspace poly, not the
 * unused [n, NEV_N_MAX) tail of the fixed-size NEV_Poly array. For n < 2048
 * this avoids zeroing dead bytes (4x less work at n=512). */
static inline void NevCleansePolys(NEV_Poly *polys, uint32_t count, uint32_t n)
{
    uint32_t bytes = n * (uint32_t)sizeof(int16_t);
    for (uint32_t i = 0; i < count; i++) {
        BSL_SAL_CleanseData(&polys[i], bytes);
    }
}

static uint32_t NevConstTimeDifferent(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    uint32_t diff = 0;
    for (uint32_t i = 0; i < len; i++) {
        diff |= (uint32_t)(a[i] ^ b[i]);
    }
    return (diff | (0U - diff)) >> 31;
}

static int32_t NevOwPkeEncDet(const CRYPT_NevInfo *info, uint8_t *ct, const uint8_t *message,
    const uint8_t *pk, const uint8_t *rho, NEV_Poly *polys, const NEV_Poly *hCache)
{
    NEV_Poly *r = &polys[0];
    NEV_Poly *e = info->compress != 0 ? &polys[0] : &polys[1];
    NEV_Poly *v = info->compress != 0 ? &polys[1] : &polys[2];
    const NEV_Poly *h = hCache;

    if (h == NULL) {
        NEV_PolyFromBytes(&polys[3], pk, info);
        h = &polys[3];
    }
    if (info->compress != 0) {
        NEV_PolyGetNoiseM(e, message, rho, 1, info);
        NEV_PolyNtt(e, info);
        NEV_PolyMontMul(v, h, e, info);
        NEV_PolyReduceInvNtt(v, info);
        NEV_PolyMontCompress(ct, v, info);
    } else {
#if defined(HITLS_CRYPTO_NEV_ARMV8) && !defined(PQCP_NEV_DISABLE_KECCAK_X2)
        /* SHA3 can expand the two independent streams in one Keccakx2 pass. */
        NEV_PolySampleRAndNoiseM(r, e, message, rho, info);
#else
        NEV_PolySampleEta(r, rho, 0, info->etaR, info);
        NEV_PolyGetNoiseM(e, message, rho, 1, info);
#endif
        NEV_PolyNtt(r, info);
        NEV_PolyNtt(e, info);
        NEV_PolyMontMul(v, h, r, info);
        NEV_PolyAddReduceCaddq(v, v, e, info);
        NEV_PolyToBytes(ct, v, info);
    }

    return PQCP_SUCCESS;
}

static int32_t NevOwPkeDec(const CRYPT_NevInfo *info, uint8_t *message, const uint8_t *ct,
    const uint8_t *skOw, NEV_Poly *polys, const NEV_Poly *sCache)
{
    NEV_Poly *v = &polys[0];
    NEV_Poly *t = &polys[1];
    const NEV_Poly *s = sCache;

    if (s == NULL) {
        NEV_PolyFromBytes(&polys[2], skOw, info);
        s = &polys[2];
    }
    if (info->compress != 0) {
        NEV_PolyDecompress(v, ct, info);
        NEV_PolyNtt(v, info);
    } else {
        NEV_PolyFromBytes(v, ct, info);
    }
    NEV_PolyMontMul(t, s, v, info);
    NEV_PolyReduceInvNttToMsg(message, t, info);

    return PQCP_SUCCESS;
}

int32_t PQCP_NEV_EngineKeyGen(const CRYPT_NevInfo *info, uint8_t *pk, uint8_t *sk,
    const uint8_t *entropy, NEV_Poly *hCache, NEV_Poly *sCache)
{
    if (info == NULL || pk == NULL || sk == NULL || entropy == NULL) {
        return PQCP_NULL_INPUT;
    }

    NEV_Poly polys[NEV_WORKSPACE_POLY_CNT] __attribute__((aligned(64)));
    NEV_Poly *f = &polys[0];
    NEV_Poly *g = &polys[1];
    NEV_Poly *inv = &polys[2];
    NEV_Poly *h = &polys[3];
    uint8_t seed[NEV_SEED_MAX];
    uint8_t nonce = 0;
    uint32_t attempts = 0;
    int32_t ret = PQCP_INVALID_ARG;
    int32_t ok = 0;

#if defined(HITLS_CRYPTO_NEV_ARMV8) && !defined(PQCP_NEV_DISABLE_KECCAK_X2)
    NEV_XofLadder ladder;
    NEV_XofLadderInit(&ladder);
#define NEV_KEYGEN_SAMPLE(r, n, eta) \
    NEV_PolySampleEtaLadder(&ladder, (r), seed, (n), (eta), info)
#else
#define NEV_KEYGEN_SAMPLE(r, n, eta) NEV_PolySampleEta((r), seed, (n), (eta), info)
#endif
    NEV_Hash(seed, entropy, info->seedLen, info->seedLen);
    while (ok == 0) {
        if (attempts++ == NEV_KEYGEN_MAX_ATTEMPTS) {
            goto EXIT;
        }
        NEV_KEYGEN_SAMPLE(f, nonce++, info->etaF);
        NEV_PolyAddVinv(f, info);
        NEV_PolyNtt(f, info);
        ok = info->compress != 0 ? NEV_PolyMont2InverseJudge(f, info) :
            NEV_PolyMont2Inverse(inv, f, info);
    }

    ok = 0;
    while (ok == 0) {
        if (attempts++ == NEV_KEYGEN_MAX_ATTEMPTS) {
            goto EXIT;
        }
        NEV_KEYGEN_SAMPLE(g, nonce++, info->etaG);
        NEV_PolyNtt(g, info);
        ok = info->compress != 0 ? NEV_PolyMont2Inverse(inv, g, info) :
            NEV_PolyMont2InverseJudge(g, info);
    }

    if (info->compress != 0) {
        NEV_PolyMontMul(h, inv, f, info);
    } else {
        NEV_PolyMontMul(h, inv, g, info);
    }
    const NEV_Poly *hPacked = h;
    if (hCache != NULL) {
        NEV_PolyReduceCaddqTo(hCache, h, info);
        hPacked = hCache;
    } else {
        NEV_PolyReduceCaddq(h, info);
    }
    const NEV_Poly *sPacked;
    if (info->compress != 0) {
        if (sCache != NULL) {
            NEV_PolyCaddqTo(sCache, g, info);
            sPacked = sCache;
        } else {
            NEV_PolyCaddq(g, info);
            sPacked = g;
        }
    } else {
        if (sCache != NULL) {
            NEV_PolyCaddqTo(sCache, f, info);
            sPacked = sCache;
        } else {
            NEV_PolyCaddq(f, info);
            sPacked = f;
        }
    }
    NEV_PolyToBytes(sk, sPacked, info);
    NEV_PolyToBytes(pk, hPacked, info);
    (void)memcpy(sk + info->polyBytes, pk, info->pkLen);
    NEV_Hash(sk + info->skLen - info->seedLen, pk, info->pkLen, info->seedLen);
    ret = PQCP_SUCCESS;
#undef NEV_KEYGEN_SAMPLE

EXIT:
    BSL_SAL_CleanseData(seed, sizeof(seed));
    NevCleansePolys(polys, NEV_WORKSPACE_POLY_CNT, info->n);
    return ret;
}

int32_t PQCP_NEV_EngineEncaps(const CRYPT_NevInfo *info, uint8_t *ct, uint8_t *ss,
    const uint8_t *pk, const uint8_t *pkHash, const NEV_Poly *hCache,
    const uint8_t *message)
{
    if (info == NULL || ct == NULL || ss == NULL || pk == NULL || message == NULL) {
        return PQCP_NULL_INPUT;
    }
    uint32_t polyCnt = hCache != NULL ? (info->compress != 0 ? 2U : 3U) :
        NEV_WORKSPACE_POLY_CNT;
    NEV_Poly polys[NEV_WORKSPACE_POLY_CNT] __attribute__((aligned(64)));
    uint8_t buf[2 * NEV_SEED_MAX];
    uint8_t kr[2 * NEV_SEED_MAX];

    (void)memcpy(buf, message, info->seedLen);
    if (pkHash != NULL) {
        (void)memcpy(buf + info->seedLen, pkHash, info->seedLen);
    } else {
        NEV_Hash(buf + info->seedLen, pk, info->pkLen, info->seedLen);
    }
    NEV_Hash2(kr, buf, 2U * info->seedLen, info->seedLen);
    int32_t ret = NevOwPkeEncDet(info, ct, buf, pk, kr + info->seedLen, polys, hCache);
    if (ret == PQCP_SUCCESS) {
        (void)memcpy(ss, kr, info->seedLen);
    }
    BSL_SAL_CleanseData(buf, 2U * info->seedLen);
    BSL_SAL_CleanseData(kr, 2U * info->seedLen);
    NevCleansePolys(polys, polyCnt, info->n);
    return ret;
}

int32_t PQCP_NEV_EngineDecaps(const CRYPT_NevInfo *info, uint8_t *ss, const uint8_t *ct,
    const uint8_t *sk, const NEV_Poly *hCache, const NEV_Poly *sCache)
{
    if (info == NULL || ss == NULL || ct == NULL || sk == NULL) {
        return PQCP_NULL_INPUT;
    }
    uint32_t polyCnt = hCache == NULL ? NEV_WORKSPACE_POLY_CNT :
        (sCache == NULL ? 3U : (info->compress != 0 ? 2U : 3U));
    NEV_Poly polys[NEV_WORKSPACE_POLY_CNT] __attribute__((aligned(64)));
    uint8_t buf[2 * NEV_SEED_MAX];
    uint8_t kr[2 * NEV_SEED_MAX];
    uint8_t cmp[NEV_MAX_CT_LEN];
    const uint8_t *pk = sk + info->polyBytes;

    int32_t ret = NevOwPkeDec(info, buf, ct, sk, polys, sCache);
    if (ret == PQCP_SUCCESS) {
        (void)memcpy(buf + info->seedLen, sk + info->skLen - info->seedLen, info->seedLen);
        NEV_Hash2(kr, buf, 2U * info->seedLen, info->seedLen);
        ret = NevOwPkeEncDet(info, cmp, buf, pk, kr + info->seedLen, polys, hCache);
    }
    if (ret == PQCP_SUCCESS) {
        if (NevConstTimeDifferent(ct, cmp, info->ctLen) == 0) {
            (void)memcpy(ss, kr, info->seedLen);
        } else {
            ret = PQCP_NEV_DECAP_FAIL;
        }
    }

    BSL_SAL_CleanseData(buf, 2U * info->seedLen);
    BSL_SAL_CleanseData(kr, 2U * info->seedLen);
    BSL_SAL_CleanseData(cmp, info->ctLen);
    NevCleansePolys(polys, polyCnt, info->n);
    return ret;
}
