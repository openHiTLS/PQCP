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
#ifndef AIGIS_SIG_LOCAL_H
#define AIGIS_SIG_LOCAL_H

#include <stddef.h>
#include <stdint.h>

#include "aigis_sig_sha3_kdf.h"
#include "aigis_sig_sm3_kdf.h"

#ifdef ALIGN
#undef ALIGN
#endif

#if defined(__GNUC__)
#define ALIGN(x) __attribute__((aligned(x)))
#elif defined(_MSC_VER)
#define ALIGN(x) __declspec(align(x))
#elif defined(__ARMCC_VERSION)
#define ALIGN(x) __align(x)
#else
#define ALIGN(x)
#endif

#define AIGIS_SIG_Q                      4171777
#define AIGIS_SIG_QBITS                  22
#define AIGIS_SIG_N                      512
#define AIGIS_SIG_QINV                   503339009U
#define AIGIS_SIG_NHW                    15
#define AIGIS_SIG_SEC                    64
#define AIGIS_SIG_SEED_BYTES             32
#define AIGIS_SIG_RNG_SEED_BYTES         48
#define AIGIS_SIG_CRH_BYTES              48
#define AIGIS_SIG_MAX_K                  8
#define AIGIS_SIG_MAX_L                  7
#define AIGIS_SIG_MAX_SEED_BYTES         64U
#define AIGIS_SIG_MAX_RNG_SEED_BYTES     96U
#define AIGIS_SIG_MAX_CRH_BYTES          96U
#define AIGIS_SIG_REJ_UNIFORM_BYTES      1440
#define AIGIS_SIG_POLY_W1_PACKED_BYTES   192U
#define AIGIS_SIG_POLY_T1_PACKED_BYTES   448U
#define AIGIS_SIG_POLY_T0_PACKED_BYTES   960U
#define AIGIS_SIG_POLY_ETA1_PACKED_BYTES 128U

#define AIGIS_SIG_HINT_SECTIONS_PER_POLY 8U
#define AIGIS_SIG_HINT_COUNT_BYTES(k)    (((k) * AIGIS_SIG_HINT_SECTIONS_PER_POLY + 1U) >> 1)
#define AIGIS_SIG_HINT_POSITION_BYTES(w) (((w) * 6U + 7U) >> 3)
#define AIGIS_SIG_PRIVATE_KEY_BYTES(seedBytes, crhBytes, k, l, eta1Bytes, eta2Bytes, t0Bytes) \
    (2U * (seedBytes) + (crhBytes) + (l) * (eta1Bytes) + (k) * (eta2Bytes) + (k) * (t0Bytes))
#define AIGIS_SIG_PUBLIC_KEY_BYTES(seedBytes, k, t1Bytes) ((seedBytes) + (k) * (t1Bytes))
#define AIGIS_SIG_SIGNATURE_MIN_BYTES(seedBytes, l, zBytes) ((l) * (zBytes) + (seedBytes) + 1U)
#define AIGIS_SIG_SIGNATURE_MAX_BYTES(seedBytes, k, l, w, zBytes) \
    (AIGIS_SIG_SIGNATURE_MIN_BYTES((seedBytes), (l), (zBytes)) + AIGIS_SIG_HINT_COUNT_BYTES(k) + \
     AIGIS_SIG_HINT_POSITION_BYTES(w))

#define AIGIS_SIG_PARAM_I_PUBLIC_KEY_BYTES     AIGIS_SIG_PUBLIC_KEY_BYTES(32U, 2U, 448U)
#define AIGIS_SIG_PARAM_I_PRIVATE_KEY_BYTES    AIGIS_SIG_PRIVATE_KEY_BYTES(32U, 48U, 2U, 2U, 128U, 256U, 960U)
#define AIGIS_SIG_PARAM_I_SIGNATURE_MIN_BYTES  AIGIS_SIG_SIGNATURE_MIN_BYTES(32U, 2U, 960U)
#define AIGIS_SIG_PARAM_I_SIGNATURE_MAX_BYTES  AIGIS_SIG_SIGNATURE_MAX_BYTES(32U, 2U, 2U, 72U, 960U)
#define AIGIS_SIG_PARAM_II_PUBLIC_KEY_BYTES    AIGIS_SIG_PUBLIC_KEY_BYTES(32U, 4U, 448U)
#define AIGIS_SIG_PARAM_II_PRIVATE_KEY_BYTES   AIGIS_SIG_PRIVATE_KEY_BYTES(32U, 48U, 4U, 4U, 128U, 128U, 960U)
#define AIGIS_SIG_PARAM_II_SIGNATURE_MIN_BYTES AIGIS_SIG_SIGNATURE_MIN_BYTES(32U, 4U, 1088U)
#define AIGIS_SIG_PARAM_II_SIGNATURE_MAX_BYTES AIGIS_SIG_SIGNATURE_MAX_BYTES(32U, 4U, 4U, 176U, 1088U)
#define AIGIS_SIG_PARAM_III_PUBLIC_KEY_BYTES   AIGIS_SIG_PUBLIC_KEY_BYTES(64U, 8U, 576U)
#define AIGIS_SIG_PARAM_III_PRIVATE_KEY_BYTES  AIGIS_SIG_PRIVATE_KEY_BYTES(64U, 96U, 8U, 7U, 128U, 128U, 832U)
#define AIGIS_SIG_PARAM_III_SIGNATURE_MIN_BYTES AIGIS_SIG_SIGNATURE_MIN_BYTES(64U, 7U, 1280U)
#define AIGIS_SIG_PARAM_III_SIGNATURE_MAX_BYTES AIGIS_SIG_SIGNATURE_MAX_BYTES(64U, 8U, 7U, 102U, 1280U)

typedef struct {
    int32_t id;
    uint32_t seedBytes;
    uint32_t rngSeedBytes;
    uint32_t crhBytes;
    uint32_t d;
    uint32_t alpha;
    uint32_t gamma2;
    uint32_t maxHigh;
    uint32_t gamma1;
    uint32_t szBits;
    uint32_t gamma3;
    uint32_t challengeWeight;
    uint32_t k;
    uint32_t l;
    uint32_t eta2;
    uint32_t eta2Bits;
    uint32_t rejEta1Bytes;
    uint32_t rejEta2Bytes;
    uint32_t beta1;
    uint32_t beta2;
    uint32_t omega;
    uint32_t polyZPackedBytes;
    uint32_t polyW1PackedBytes;
    uint32_t polyT1PackedBytes;
    uint32_t polyT0PackedBytes;
    uint32_t polyEta1PackedBytes;
    uint32_t polyEta2PackedBytes;
    uint32_t publicKeyBytes;
    uint32_t privateKeyBytes;
    uint32_t signatureMaxBytes;
    uint32_t signatureMinBytes;
} AigisSigParams;

const AigisSigParams *PQCP_AIGIS_SIG_GetParams(int32_t paramId);

/* Common construction constants shared by every currently supported parameter set. */
#define PARAM_Q            AIGIS_SIG_Q
#define QBITS              AIGIS_SIG_QBITS
#define PARAM_N            AIGIS_SIG_N
#define QINV               AIGIS_SIG_QINV
#define NHW                AIGIS_SIG_NHW
#define SEC                AIGIS_SIG_SEC
#define SEEDBYTES          AIGIS_SIG_SEED_BYTES
#define RNG_SEED_BYTES     AIGIS_SIG_RNG_SEED_BYTES
#define CRHBYTES           AIGIS_SIG_CRH_BYTES
#define REJ_UNIFORM_BYTES  AIGIS_SIG_REJ_UNIFORM_BYTES
#define PARAM_D            15
#define ALPHA              695296
#define AIGIS_SIG_MAX_HIGH 5
#define GAMMA2             347648
#define ETA1               1
_Static_assert((AIGIS_SIG_MAX_HIGH + 1) * ALPHA == PARAM_Q - 1, "Aigis-Sig high-part range must match q and alpha");
_Static_assert(ALPHA == 695296, "Aigis-Sig I/II decomposition formula requires alpha=695296");

enum { PQCP_AIGIS_SIG_HASH_SM3 = 0, PQCP_AIGIS_SIG_HASH_SHA3 = 1 };

typedef struct {
    int32_t hashId;
    uint32_t rate;
    union {
        PQCP_AIGIS_SIG_Sm3DrngCtx sm3;
        PQCP_AIGIS_SIG_Shake256Ctx shake256;
        PQCP_AIGIS_SIG_AigisKeccakXofRate72Ctx aigisKeccakRate72;
    } state;
} PQCP_AIGIS_SIG_KdfCtx;

typedef struct {
    void *libCtx;
    PQCP_AIGIS_SIG_Sha3Cache *sha3Cache;
    int32_t paramId;
    int32_t hashId;
    const AigisSigParams *params;
} PQCP_AIGIS_SIG_CoreCtx;

int32_t PQCP_AIGIS_SIG_Kdf(const PQCP_AIGIS_SIG_CoreCtx *ctx, uint8_t *out, uint32_t outLen, const uint8_t *in,
                           uint32_t inLen);
int32_t PQCP_AIGIS_SIG_KdfTwoSegment(const PQCP_AIGIS_SIG_CoreCtx *ctx, uint8_t *out, uint32_t outLen,
                                     const uint8_t *in1, uint32_t in1Len, const uint8_t *in2, uint32_t in2Len);
int32_t PQCP_AIGIS_SIG_Hash(const PQCP_AIGIS_SIG_CoreCtx *ctx, uint8_t *out, uint32_t outLen, const uint8_t *in,
                            uint32_t inLen);
int32_t PQCP_AIGIS_SIG_KdfAbsorb(const PQCP_AIGIS_SIG_CoreCtx *ctx, PQCP_AIGIS_SIG_KdfCtx *state, const uint8_t *input,
                                 uint32_t inputLen);
int32_t PQCP_AIGIS_SIG_Kdf128Absorb(const PQCP_AIGIS_SIG_CoreCtx *ctx, PQCP_AIGIS_SIG_KdfCtx *state,
                                    const uint8_t *input, uint32_t inputLen);
int32_t PQCP_AIGIS_SIG_KdfSqueezeBlocks(uint8_t *output, uint32_t blockNum, PQCP_AIGIS_SIG_KdfCtx *state);
void PQCP_AIGIS_SIG_KdfFree(PQCP_AIGIS_SIG_KdfCtx *state);
#define PQCP_AIGIS_SIG_XOF_FREE PQCP_AIGIS_SIG_KdfFree

typedef struct {
    ALIGN(32) int32_t coeffs[AIGIS_SIG_N];
} AigisSigPoly;

void PQCP_AIGIS_SIG_PolyGReduce(AigisSigPoly *a);
void PQCP_AIGIS_SIG_PolyAModQ(AigisSigPoly *a);
void PQCP_AIGIS_SIG_PolyCModQ(AigisSigPoly *a);
void PQCP_AIGIS_SIG_PolyDecompose(AigisSigPoly *r1, AigisSigPoly *r0, const AigisSigPoly *a);
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
void PQCP_AIGIS_SIG_PolyDecomposeUseHint(int32_t *w, const int32_t *a, const int32_t *hint);
#endif
void PQCP_AIGIS_SIG_PolyPower2Round(AigisSigPoly *r1, AigisSigPoly *r0, const AigisSigPoly *a);
void PQCP_AIGIS_SIG_PolyAdd(AigisSigPoly *c, const AigisSigPoly *a, const AigisSigPoly *b);
void PQCP_AIGIS_SIG_PolySub(AigisSigPoly *c, const AigisSigPoly *a, const AigisSigPoly *b);
void PQCP_AIGIS_SIG_PolyUseHint(int32_t *w, const int32_t *high, const int32_t *low, const int32_t *hint,
                                int32_t maxHigh);
void PQCP_AIGIS_SIG_PolyShiftLeft(AigisSigPoly *a, int k);

void PQCP_AIGIS_SIG_PolyPointwise(AigisSigPoly *c, const AigisSigPoly *a, const AigisSigPoly *b);

int32_t PQCP_AIGIS_SIG_PolyCheckNorm(const AigisSigPoly *a, uint32_t b);
int32_t PQCP_AIGIS_SIG_PolyUniformSeed(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPoly *a, const uint8_t *seed,
                                       int32_t seedLen);
void PQCP_AIGIS_SIG_PolyZPack(const PQCP_AIGIS_SIG_CoreCtx *ctx, uint8_t *r, const AigisSigPoly *a);
void PQCP_AIGIS_SIG_PolyZUnpack(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPoly *r, const uint8_t *a);

/* Vectors of polynomials of length L */
typedef struct {
    AigisSigPoly vec[AIGIS_SIG_MAX_L];
} AigisSigPolyVecL;

void PQCP_AIGIS_SIG_PolyVecLNtt(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecL *v);
void PQCP_AIGIS_SIG_PolyVecLNttCopy(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecL *dst,
                                    const AigisSigPolyVecL *src);
int32_t PQCP_AIGIS_SIG_PolyVecLUniformGamma1(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecL *v,
                                             const uint8_t *seed, uint32_t nonce);
int32_t PQCP_AIGIS_SIG_PolyVecLUniformEta1(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecL *v, const uint8_t *seed,
                                           uint32_t nonce);
void PQCP_AIGIS_SIG_PolyVecLPointwiseAcc(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPoly *w, const AigisSigPolyVecL *u,
                                         const AigisSigPolyVecL *v);
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
void PQCP_AIGIS_SIG_PolyVecLPointwiseAccL2(AigisSigPoly *w, const AigisSigPolyVecL *u, const AigisSigPolyVecL *v);
void PQCP_AIGIS_SIG_PolyVecLPointwiseAccL4(AigisSigPoly *w, const AigisSigPolyVecL *u, const AigisSigPolyVecL *v);
void PQCP_AIGIS_SIG_PolyVecLPointwiseAccL2Vec(AigisSigPoly *w, const AigisSigPolyVecL *u, const AigisSigPolyVecL *v);
void PQCP_AIGIS_SIG_PolyVecLPointwiseAccL4Vec(AigisSigPoly *w, const AigisSigPolyVecL *u, const AigisSigPolyVecL *v);
void PQCP_AIGIS_SIG_PolyVecLPointwiseAccL7Vec(AigisSigPoly *w, const AigisSigPolyVecL *u, const AigisSigPolyVecL *v);
#endif

int32_t PQCP_AIGIS_SIG_PolyVecLCheckNorm(const PQCP_AIGIS_SIG_CoreCtx *ctx, const AigisSigPolyVecL *v, uint32_t b);

/* Vectors of polynomials of length K */
typedef struct {
    AigisSigPoly vec[AIGIS_SIG_MAX_K];
} AigisSigPolyVecK;

#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
void PQCP_AIGIS_SIG_PolyVecKAddPower2RoundArmv8(AigisSigPolyVecK *high, AigisSigPolyVecK *low,
                                                const AigisSigPolyVecK *left, const AigisSigPolyVecK *right,
                                                uint32_t count);
void PQCP_AIGIS_SIG_PolyVecKAddPower2RoundD13Armv8(AigisSigPolyVecK *high, AigisSigPolyVecK *low,
                                                   const AigisSigPolyVecK *left, const AigisSigPolyVecK *right,
                                                   uint32_t count);
void PQCP_AIGIS_SIG_PolyVecKDecomposeD13Armv8(AigisSigPolyVecK *high, AigisSigPolyVecK *low,
                                              const AigisSigPolyVecK *input, uint32_t count);
int32_t PQCP_AIGIS_SIG_PolyVecKMakeHintD13Armv8(AigisSigPolyVecK *hint, const AigisSigPolyVecK *low,
                                                const AigisSigPolyVecK *high, uint32_t count);
void PQCP_AIGIS_SIG_PolyVecKDecomposeUseHintD13Armv8(AigisSigPolyVecK *result, const AigisSigPolyVecK *input,
                                                     const AigisSigPolyVecK *hint, uint32_t count);
void PQCP_AIGIS_SIG_PolyVecKUnpackT1ShiftNttArmv8(AigisSigPolyVecK *out, const uint8_t *in, uint32_t count);
#endif

void PQCP_AIGIS_SIG_PolyVecKAModQ(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecK *v);
void PQCP_AIGIS_SIG_PolyVecKCModQ(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecK *v);
void PQCP_AIGIS_SIG_PolyVecKGReduce(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecK *v);
void PQCP_AIGIS_SIG_PolyVecKAddPower2Round(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecK *high,
                                           AigisSigPolyVecK *low, const AigisSigPolyVecK *u, const AigisSigPolyVecK *v);
#ifdef PQCP_AIGIS_SIG_PORTABLE_BACKEND
void PQCP_AIGIS_SIG_PolyVecKAModQDecompose(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecK *high,
                                           AigisSigPolyVecK *low, const AigisSigPolyVecK *v);
int32_t PQCP_AIGIS_SIG_PolyVecKSubWCModQCheckNorm(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecK *v,
                                                  const AigisSigPolyVecK *u, const AigisSigPolyVecK *w, uint32_t bound);
#endif
void PQCP_AIGIS_SIG_PolyVecKSubW(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecK *v, const AigisSigPolyVecK *u,
                                 const AigisSigPolyVecK *w);
void PQCP_AIGIS_SIG_PolyVecKShiftLeft(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecK *v, uint32_t k);
int32_t PQCP_AIGIS_SIG_PolyVecKUniformEta2(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecK *v, const uint8_t *seed,
                                           uint32_t nonce);
void PQCP_AIGIS_SIG_PolyVecKNtt(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecK *v);
void PQCP_AIGIS_SIG_PolyVecKInvNtt(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecK *v);
#ifdef PQCP_AIGIS_SIG_PORTABLE_BACKEND
void PQCP_AIGIS_SIG_PolyVecKInvNttPair(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecK *v);
#endif

int32_t PQCP_AIGIS_SIG_PolyVecKCheckNorm(const PQCP_AIGIS_SIG_CoreCtx *ctx, const AigisSigPolyVecK *v, uint32_t b);

void PQCP_AIGIS_SIG_PolyVecKDecompose(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecK *v1, AigisSigPolyVecK *v0,
                                      const AigisSigPolyVecK *v);
int32_t PQCP_AIGIS_SIG_PolyVecKMakeHint(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecK *h,
                                        const AigisSigPolyVecK *u, const AigisSigPolyVecK *v);
void PQCP_AIGIS_SIG_PolyVecKUseHint(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecK *w, const AigisSigPolyVecK *v,
                                    const AigisSigPolyVecK *h);

void PQCP_AIGIS_SIG_Ntt(int32_t p[PARAM_N]);
void PQCP_AIGIS_SIG_InvNtt(int32_t p[PARAM_N]);
void PQCP_AIGIS_SIG_NttCopy(int32_t dst[PARAM_N], const int32_t src[PARAM_N]);
#ifdef PQCP_AIGIS_SIG_PORTABLE_BACKEND
void PQCP_AIGIS_SIG_InvNttPair(int32_t first[PARAM_N], int32_t second[PARAM_N]);
#endif

void PQCP_AIGIS_SIG_PackPublicKey(const PQCP_AIGIS_SIG_CoreCtx *ctx, uint8_t *pk,
                                  const uint8_t rho[AIGIS_SIG_MAX_SEED_BYTES],
                                  const AigisSigPolyVecK *t1);
void PQCP_AIGIS_SIG_PackPrivateKey(const PQCP_AIGIS_SIG_CoreCtx *ctx, uint8_t *sk,
                                   const uint8_t rho[AIGIS_SIG_MAX_SEED_BYTES],
                                   const uint8_t key[AIGIS_SIG_MAX_SEED_BYTES],
                                   const uint8_t hashpk[AIGIS_SIG_MAX_CRH_BYTES],
                                   const AigisSigPolyVecL *s1, const AigisSigPolyVecK *s2, const AigisSigPolyVecK *t0);
int32_t PQCP_AIGIS_SIG_PackSignature(const PQCP_AIGIS_SIG_CoreCtx *ctx, uint8_t *sig, const AigisSigPolyVecL *z,
                                     const uint8_t *challengeSeed, const AigisSigPolyVecK *h);
void PQCP_AIGIS_SIG_UnpackPublicKey(const PQCP_AIGIS_SIG_CoreCtx *ctx, uint8_t rho[AIGIS_SIG_MAX_SEED_BYTES],
                                    AigisSigPolyVecK *t1,
                                    const uint8_t *pk);
void PQCP_AIGIS_SIG_UnpackPrivateKey(const PQCP_AIGIS_SIG_CoreCtx *ctx,
                                     uint8_t rho[AIGIS_SIG_MAX_SEED_BYTES],
                                     uint8_t key[AIGIS_SIG_MAX_SEED_BYTES],
                                     uint8_t hashpk[AIGIS_SIG_MAX_CRH_BYTES], AigisSigPolyVecL *s1,
                                     AigisSigPolyVecK *s2,
                                     AigisSigPolyVecK *t0, const uint8_t *sk);
int32_t PQCP_AIGIS_SIG_UnpackSignature(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecL *z, AigisSigPolyVecK *h,
                                       uint8_t *challengeSeed, const uint8_t *sig, uint32_t sigLen);
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
int32_t PQCP_AIGIS_SIG_UnpackSignatureCheckZ(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecL *z,
                                             AigisSigPolyVecK *h, uint8_t *challengeSeed, const uint8_t *sig,
                                             uint32_t sigLen, uint32_t bound);
#endif

int32_t PQCP_AIGIS_SIG_RejectUniformScalar(int32_t *a, int32_t *cur, const uint8_t *buf, int32_t bufLen);
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
typedef ALIGN(16) uint64_t AigisSigKeccakX2State[25][2];
void PQCP_AIGIS_SIG_Keccakx2AbsorbArmv8(AigisSigKeccakX2State state, size_t rate, const uint8_t *in0,
                                        const uint8_t *in1, size_t inLen, uint8_t domain);
void PQCP_AIGIS_SIG_Keccakx2Absorb33Shake128Armv8(AigisSigKeccakX2State state, const uint8_t in0[33],
                                                  const uint8_t in1[33]);
void PQCP_AIGIS_SIG_Keccakx2Absorb65Shake128Armv8(AigisSigKeccakX2State state, const uint8_t in0[65],
                                                  const uint8_t in1[65]);
void PQCP_AIGIS_SIG_Keccakx2SqueezeArmv8(uint8_t *out0, uint8_t *out1, size_t blockNum, unsigned int rate,
                                         AigisSigKeccakX2State state);
uint64_t PQCP_AIGIS_SIG_RejectUniformPairInitialArmv8(int32_t *a0, int32_t *a1, const uint8_t *buf0,
                                                      const uint8_t *buf1);
int32_t PQCP_AIGIS_SIG_PolyUniformSeedPairSha3Armv8(AigisSigPoly *a0, AigisSigPoly *a1, const uint8_t *seed0,
                                                    const uint8_t *seed1, uint32_t seedLen);
int32_t PQCP_AIGIS_SIG_PolyUniformEtaPairSha3Armv8(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPoly *a0,
                                                   AigisSigPoly *a1, const uint8_t *seed0, const uint8_t *seed1,
                                                   uint32_t seedLen, uint32_t etaIndex);
#endif
int32_t PQCP_AIGIS_SIG_RejectUniform(int32_t *a, int32_t *cur, const uint8_t *buf, int32_t bufLen);
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
/* Initial Eta1 parser: bufLen is unsigned and only complete 8-byte groups are consumed. */
int32_t PQCP_AIGIS_SIG_RejectEta1InitialArmv8(int32_t *a, const uint8_t *buf, uint32_t bufLen);
/* Initial Eta5 parser: bufLen is an unsigned number of bytes and only complete 8-byte groups are consumed. */
int32_t PQCP_AIGIS_SIG_RejectEta5InitialArmv8(int32_t *a, const uint8_t *buf, uint32_t bufLen);
#endif

int32_t PQCP_AIGIS_SIG_ExpandMatrix(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecL mat[AIGIS_SIG_MAX_K],
                                    const uint8_t rho[AIGIS_SIG_MAX_SEED_BYTES]);
int32_t PQCP_AIGIS_SIG_ExpandMatrixRow(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPolyVecL *row,
                                       const uint8_t rho[AIGIS_SIG_MAX_SEED_BYTES], uint32_t rowIndex);

int32_t PQCP_AIGIS_SIG_Challenge(const PQCP_AIGIS_SIG_CoreCtx *ctx, uint8_t *seed,
                                 const uint8_t mu[AIGIS_SIG_MAX_CRH_BYTES],
                                 const AigisSigPolyVecK *w1);

int32_t PQCP_AIGIS_SIG_SampleInBall(const PQCP_AIGIS_SIG_CoreCtx *ctx, AigisSigPoly *c,
                                    const uint8_t seed[AIGIS_SIG_MAX_SEED_BYTES]);

#define Hash(ctx, out, in, inLen) PQCP_AIGIS_SIG_Hash((ctx), (out), (ctx)->params->seedBytes, (in), (inLen))
#define Hash2(ctx, out, in, inLen) \
    PQCP_AIGIS_SIG_Hash((ctx), (out), 2U * (ctx)->params->seedBytes, (in), (inLen))
#define KDF(ctx, out, outLen, in, inLen)       PQCP_AIGIS_SIG_Kdf((ctx), (out), (outLen), (in), (inLen))
#define KDF_ABSORB(ctx, state, in, inLen)      PQCP_AIGIS_SIG_KdfAbsorb((ctx), (state), (in), (inLen))
#define KDF_SQUEEZEBLOCK(out, blockNum, state) PQCP_AIGIS_SIG_KdfSqueezeBlocks((out), (blockNum), (state))
#define SIG_ALGNAME                            "Aigis-sig"

int32_t PQCP_AIGIS_SIG_KeyGenInternal(const PQCP_AIGIS_SIG_CoreCtx *ctx, uint8_t *pubKey, uint8_t *prvKey);

int32_t PQCP_AIGIS_SIG_SignInternal(const PQCP_AIGIS_SIG_CoreCtx *ctx, const uint8_t *prvKey, const uint8_t *msg,
                                    uint32_t msgLen, uint8_t *sig, uint32_t *sigLen);

int32_t PQCP_AIGIS_SIG_VerifyInternal(const PQCP_AIGIS_SIG_CoreCtx *ctx, const uint8_t *pubKey, const uint8_t *sig,
                                      uint32_t sigLen, const uint8_t *msg, uint32_t msgLen);

typedef struct {
    int32_t stable[PARAM_N * 3];
    int32_t product[PARAM_N];
} AigisSigEmulateCt1Scratch;

typedef struct {
    int16_t stable[2][PARAM_N * 3];
    uint32_t offsets[44];
} AigisSigEmulateCt1PairScratch;

#define AIGIS_SIG_PSPM_REUSE_OFFSETS UINT32_C(0x80000000)

uint32_t PQCP_AIGIS_SIG_ChallengeMultiplyAddCheckNormVec(AigisSigPoly *scratch, AigisSigPoly *result,
                                                         const AigisSigPoly *base, const AigisSigPoly *challengeNtt,
                                                         const AigisSigPoly *operandNtt, uint32_t count,
                                                         uint32_t bound);
uint32_t PQCP_AIGIS_SIG_ChallengeMultiplySubCheckNormVec(AigisSigPoly *scratch, AigisSigPoly *result,
                                                         const AigisSigPoly *base, const AigisSigPoly *challengeNtt,
                                                         const AigisSigPoly *operandNtt, uint32_t count,
                                                         uint32_t bound);
void PQCP_AIGIS_SIG_ChallengePointwiseSubNtt(AigisSigPoly *resultBaseNtt, const AigisSigPoly *challengeNtt,
                                             const AigisSigPoly *shiftedOperandNtt);
void PQCP_AIGIS_SIG_EmulateCt1ShiftSubGReduce(AigisSigEmulateCt1Scratch *restrict scratch,
                                              AigisSigPoly *restrict resultBase, const AigisSigPoly *restrict challenge,
                                              const AigisSigPoly *restrict t1, uint32_t shift);
#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
void PQCP_AIGIS_SIG_EmulateCt1PairShiftSubGReduceArmv8(AigisSigEmulateCt1PairScratch *restrict scratch,
                                                       AigisSigPoly resultBase[restrict 2],
                                                       const AigisSigPoly *restrict challenge, uint32_t weight);
void PQCP_AIGIS_SIG_UnpackT1StablePairArmv8(AigisSigEmulateCt1PairScratch *scratch, const uint8_t *in);
#endif

#endif /* AIGIS_SIG_LOCAL_H */
