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

#ifndef PQCP_NEON_NEV_LOCAL_H
#define PQCP_NEON_NEV_LOCAL_H

#include <stdint.h>
#include "nev_symmetric_backend.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NEV_N_MAX 2048
#define NEV_NTT_DIM_MAX 128
#define NEV_SEED_MAX 64

/* poly_bias3_ternary initial squeeze bound: Bias3InitialBlocks(n, rate) * rate
 * over every parameter set and every contract-legal KDF rate in
 * [1, NEV_KDF_RATE_MAX].  With the acceptance-margin condition in
 * Bias3InitialBlocks the observed maximum is 584 bytes (n=2048, rate=146);
 * 672 keeps headroom and is shared by nev_sample.c (KDF squeeze buffer) and
 * asm_nev_sample.c (compaction input bound) so the two cannot drift apart. */
#define NEV_BIAS3_BUF_MAX 672
#define NEV_MAX_PK_LEN 3072
#define NEV_MAX_SK_LEN 6208
#define NEV_MAX_CT_LEN 3072

typedef struct CryptNevInfo {
    int32_t paraId;
    uint16_t n;
    uint16_t q;
    uint16_t qinv;
    int16_t barrettV;
    uint8_t barrettShift;
    uint8_t nttDim;
    uint8_t etaF;
    uint8_t etaG;
    uint8_t etaR;
    uint8_t etaE;
    uint8_t compress;
    uint8_t seedLen;
    uint16_t polyBytes;
    uint16_t pkLen;
    uint16_t skLen;
    uint16_t ctLen;
    uint32_t secBits;
} CRYPT_NevInfo;

typedef struct {
    int16_t coeffs[NEV_N_MAX];
} NEV_Poly;

static inline int16_t NEV_MontReduce(int32_t a, const CRYPT_NevInfo *info)
{
    int16_t t = (int16_t)((int32_t)(int16_t)a * (int32_t)(int16_t)info->qinv);
    return (int16_t)((a - (int32_t)t * (int32_t)(int16_t)info->q) >> 16);
}

static inline int16_t NEV_FqMul(int16_t a, int16_t b, const CRYPT_NevInfo *info)
{
    return NEV_MontReduce((int32_t)a * b, info);
}

static inline int16_t NEV_BarrettReduce(int16_t a, const CRYPT_NevInfo *info)
{
    int16_t t = (int16_t)(((int32_t)info->barrettV * a +
        (1 << (info->barrettShift - 1))) >> info->barrettShift);
    return (int16_t)(a - (int32_t)t * (int32_t)(int16_t)info->q);
}

static inline int16_t NEV_Caddq(int16_t x, const CRYPT_NevInfo *info)
{
    return (int16_t)(x + ((x >> 15) & (int16_t)info->q));
}

void NEV_PolyNtt(NEV_Poly *r, const CRYPT_NevInfo *info);
void NEV_PolyInvNtt(NEV_Poly *r, const CRYPT_NevInfo *info);
void NEV_PolyReduceInvNtt(NEV_Poly *r, const CRYPT_NevInfo *info);
void NEV_PolyReduceInvNttToMsg(uint8_t *msg, NEV_Poly *r, const CRYPT_NevInfo *info);
void NEV_PolyAdd(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b, const CRYPT_NevInfo *info);
void NEV_PolyReduce(NEV_Poly *r, const CRYPT_NevInfo *info);
void NEV_PolyCaddq(NEV_Poly *r, const CRYPT_NevInfo *info);
void NEV_PolyReduceCaddqTo(NEV_Poly *r, const NEV_Poly *a, const CRYPT_NevInfo *info);
void NEV_PolyCaddqTo(NEV_Poly *r, const NEV_Poly *a, const CRYPT_NevInfo *info);
void NEV_PolyAddVinv(NEV_Poly *f, const CRYPT_NevInfo *info);
void NEV_PolyGetMontgomery(NEV_Poly *r, const CRYPT_NevInfo *info);
void NEV_PolyReduceCaddq(NEV_Poly *r, const CRYPT_NevInfo *info);
void NEV_PolyAddReduceCaddq(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b,
    const CRYPT_NevInfo *info);
void NEV_PolyGetMontgomeryCaddq(NEV_Poly *r, const CRYPT_NevInfo *info);
void NEV_PolyMontMul(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b, const CRYPT_NevInfo *info);
int32_t NEV_PolyMont2Inverse(NEV_Poly *r, const NEV_Poly *a, const CRYPT_NevInfo *info);
int32_t NEV_PolyMont2InverseJudge(const NEV_Poly *a, const CRYPT_NevInfo *info);

void NEV_PolySampleEta(NEV_Poly *r, const uint8_t *seed, uint8_t nonce, uint8_t eta,
    const CRYPT_NevInfo *info);
void NEV_PolyGetNoiseM(NEV_Poly *r, const uint8_t *msg, const uint8_t *seed, uint8_t nonce,
    const CRYPT_NevInfo *info);
#if defined(HITLS_CRYPTO_NEV_ARMV8) && !defined(PQCP_NEV_DISABLE_KECCAK_X2)
void NEV_PolySampleRAndNoiseM(NEV_Poly *r, NEV_Poly *e, const uint8_t *msg,
    const uint8_t *seed, const CRYPT_NevInfo *info);

/*
 * Key generation consumes KDF(seed || nonce) streams in increasing nonce
 * order. The SVE2 path expands four adjacent streams and retains three; the
 * base ARMv8 path expands two and retains one.
 */
#define NEV_LADDER_BUF_MAX 1584

#ifdef HITLS_CRYPTO_NEV_SVE2
typedef struct {
    uint8_t buf[NEV_LADDER_BUF_MAX];
    NEV_KdfState state;
    uint32_t bufBlocks;
    uint8_t nonce;
    uint8_t valid;
} NEV_XofLadderEntry;

typedef struct {
    NEV_XofLadderEntry cached[3];
} NEV_XofLadder;
#else
typedef struct {
    uint8_t buf[NEV_LADDER_BUF_MAX];
    NEV_KdfState state;
    uint32_t bufBlocks;
    uint8_t nonce;
    uint8_t valid;
} NEV_XofLadder;
#endif

static inline void NEV_XofLadderInit(NEV_XofLadder *ladder)
{
#ifdef HITLS_CRYPTO_NEV_SVE2
    for (uint32_t i = 0; i < 3; i++) {
        ladder->cached[i].valid = 0;
    }
#else
    ladder->valid = 0;
#endif
}

void NEV_PolySampleEtaLadder(NEV_XofLadder *ladder, NEV_Poly *r, const uint8_t *seed,
    uint8_t nonce, uint8_t eta, const CRYPT_NevInfo *info);
#endif

void NEV_PolyToBytes(uint8_t *r, const NEV_Poly *a, const CRYPT_NevInfo *info);
void NEV_PolyFromBytes(NEV_Poly *r, const uint8_t *a, const CRYPT_NevInfo *info);
void NEV_PolyCompress(uint8_t *c, const NEV_Poly *x, const CRYPT_NevInfo *info);
void NEV_PolyMontCompress(uint8_t *c, NEV_Poly *x, const CRYPT_NevInfo *info);
void NEV_PolyDecompress(NEV_Poly *x, const uint8_t *c, const CRYPT_NevInfo *info);
void NEV_PolyToMsg(uint8_t *msg, const NEV_Poly *r, const CRYPT_NevInfo *info);

int32_t PQCP_NEV_EngineKeyGen(const CRYPT_NevInfo *info, uint8_t *pk, uint8_t *sk,
    const uint8_t *entropy, NEV_Poly *hCache, NEV_Poly *sCache);
int32_t PQCP_NEV_EngineEncaps(const CRYPT_NevInfo *info, uint8_t *ct, uint8_t *ss,
    const uint8_t *pk, const uint8_t *pkHash, const NEV_Poly *hCache,
    const uint8_t *message);
int32_t PQCP_NEV_EngineDecaps(const CRYPT_NevInfo *info, uint8_t *ss, const uint8_t *ct,
    const uint8_t *sk, const NEV_Poly *hCache, const NEV_Poly *sCache);

#ifdef __cplusplus
}
#endif

#endif
