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

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_NEV

#include "nev_local.h"
#if defined(HITLS_CRYPTO_NEV_ARMV8) && !defined(PQCP_NEV_DISABLE_KECCAK_X2)
#include <string.h>
#include "asm_sha3.h"   // two-lane Keccak (guaranteed by the NEV_ARMV8 DEPS)
#endif

// Byte-exact runtime port of the reference sample.c: centered binomial samplers
// cbd1/2/3/4/7, the masked-CBD1 sparse ternary sampler (poly_bias8_ternary), the
// uniform ternary rejection sampler (poly_bias3_ternary) and the message-carrying
// noise expansion get_noisem. All KDF traffic goes through NEV_Kdf /
// NEV_KdfAbsorb / NEV_KdfSqueezeBlocks keyed by info->seedLen, with the KDF input
// always seed || nonce (info->seedLen + 1 bytes), exactly as the reference.

// Largest CBD input the KDF ever produces: eta * n / 4 bytes, bounded by
// 7 * NEV_N_MAX / 4 = 7 * 2048 / 4 = 3584. (Largest live case is eta 3 with
// n = 2048: 1536 bytes; the bound covers every eta in {1, 2, 3, 4, 7}.)
#define NEV_CBD_BUF_MAX (7 * NEV_N_MAX / 4)

// poly_bias8_ternary consumes 3 * n / 8 KDF bytes: at most 3 * 2048 / 8 = 768.
#define NEV_BIAS8_BUF_MAX (3 * NEV_N_MAX / 8)

// poly_bias3_ternary initial squeeze.  Start with the minimum whole-block
// prefix when it has comfortable rejection margin; retain one safety block
// for the borderline n=2048/rate=72 case so x2/x4 batches do not fragment
// into frequent scalar top-ups.  Chunking does not affect the byte stream and
// avoids the old unconditional extra Keccak permutation for n=512/1024.
// The squeeze upper bound NEV_BIAS3_BUF_MAX lives in nev_local.h and is
// shared with the asm compaction input bound in asm_nev_sample.c.

// get_noisem expands 8 * etaE planes of seedLen bytes each: 8 * etaE * seedLen
// = etaE * n / 4 (n == 32 * seedLen for every set), so NEV_CBD_BUF_MAX = 3584
// also bounds it (largest live case: etaE 3, seedLen 64: 1536 bytes).

static inline uint64_t LoadTo64(const uint8_t *x)
{
    uint64_t r = (uint64_t)x[0]
                | ((uint64_t)x[1] << 8)
                | ((uint64_t)x[2] << 16)
                | ((uint64_t)x[3] << 24)
                | ((uint64_t)x[4] << 32)
                | ((uint64_t)x[5] << 40)
                | ((uint64_t)x[6] << 48)
                | ((uint64_t)x[7] << 56);
    return r;
}

// seed || nonce, the KDF input of every sampler (seedLen + 1 bytes).
static void BuildExtSeed(uint8_t *extseed, const uint8_t *seed, uint8_t nonce, uint32_t seedLen)
{
    for (uint32_t i = 0; i < seedLen; i++) {
        extseed[i] = seed[i];
    }
    extseed[seedLen] = nonce;
}

/* Number of initial eta=9 squeeze blocks.  A prefix with comfortable
 * acceptance margin is consumed directly; a statistically borderline
 * prefix gets one more block so keygen x4 and encaps x2 stay batched instead
 * of falling back to frequent per-stream top-ups. */
static uint32_t Bias3InitialBlocks(uint32_t n, uint32_t rate)
{
    uint32_t minBytes = (n + 4) / 5;
    uint32_t blocks = (minBytes + rate - 1) / rate;
    uint64_t expected = (uint64_t)blocks * rate * 243U;
    uint64_t margin = (uint64_t)(minBytes + 8U) * 256U;

    return blocks + (expected < margin ? 1U : 0U);
}

#ifndef HITLS_CRYPTO_NEV_ARMV8
static void Cbd1(int16_t *a, const uint8_t *buf, uint32_t n)
{
    for (uint32_t i = 0; i < n / 4; i++) {
        uint8_t b = buf[i];
        a[4 * i + 0] = (int16_t)((b & 1) - ((b >> 1) & 1));
        a[4 * i + 1] = (int16_t)(((b >> 2) & 1) - ((b >> 3) & 1));
        a[4 * i + 2] = (int16_t)(((b >> 4) & 1) - ((b >> 5) & 1));
        a[4 * i + 3] = (int16_t)(((b >> 6) & 1) - ((b >> 7) & 1));
    }
}

static void Cbd2(int16_t *r, const uint8_t *buf, uint32_t n)
{
    uint64_t mask55 = 0x5555555555555555;
    for (uint32_t i = 0; i < n / 16; i++) {
        uint64_t d = LoadTo64(buf + 8 * i);
        uint64_t t = d & mask55;
        d = (d >> 1) & mask55;
        t = t + d;
        for (uint32_t j = 0; j < 16; j++) {
            int16_t a = (int16_t)(t & 0x3);
            int16_t b = (int16_t)((t >> 2) & 0x3);
            r[16 * i + j] = (int16_t)(a - b);
            t = t >> 4;
        }
    }
}

static void Cbd3(int16_t *r, const uint8_t *buf, uint32_t n)
{
    int16_t t[NEV_N_MAX];
    Cbd1(r, buf, n);
    Cbd2(t, buf + n / 4, n);
    for (uint32_t i = 0; i < n; i++) {
        r[i] = (int16_t)(r[i] + t[i]);
    }
}

static void Cbd4(int16_t *r, const uint8_t *buf, uint32_t n)
{
    const uint8_t mask1 = 0x55;
    const uint8_t mask2 = 0x33;
    const uint8_t mask3 = 0xf;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t x = buf[i];
        x -= (x >> 1) & mask1;
        x = (x & mask2) + ((x >> 2) & mask2);
        int16_t a = (int16_t)(x & mask3);
        int16_t b = (int16_t)((x >> 4) & mask3);
        r[i] = (int16_t)(a - b);
    }
}

static void Cbd7(int16_t *r, const uint8_t *buf, uint32_t n)
{
    int16_t t[NEV_N_MAX];
    Cbd4(r, buf, n);
    Cbd3(t, buf + n, n);
    for (uint32_t i = 0; i < n; i++) {
        r[i] = (int16_t)(r[i] + t[i]);
    }
}
#endif // !HITLS_CRYPTO_NEV_ARMV8

#ifdef HITLS_CRYPTO_NEV_ARMV8
/* NEON tbl-compaction + table-expansion variant (asm_nev_sample.c); the
 * accepted-byte stream and the produced coefficients are bit-identical to
 * the scalar Ternary3 below for every buffer, n and bufLen (bufLen is
 * always a multiple of the KDF rate, hence of 8). */
int32_t NEV_Ternary3Ext(int16_t *r, const uint8_t *buf, int32_t n, int32_t bufLen);
#define NEV_TERNARY3_IMPL NEV_Ternary3Ext

/* NEON centered-binomial extractors (nev_sample_armv8.S): bit-exact,
 * same-order replacements for the scalar Cbd1/2/3/4/7 above (n is a multiple
 * of 64 for every parameter set; the kernels consume exactly the same byte
 * ranges).  NEV_MaskTernary8Asm is the masking pass of SampleBias8Ternary
 * and NEV_NoiseMExtractAsm the plane-extraction nest of NoiseMExtractE. */
void NEV_Cbd1Asm(int16_t *r, const uint8_t *buf, uint32_t n);
void NEV_Cbd2Asm(int16_t *r, const uint8_t *buf, uint32_t n);
void NEV_Cbd3Asm(int16_t *r, const uint8_t *buf, uint32_t n);
void NEV_Cbd4Asm(int16_t *r, const uint8_t *buf, uint32_t n);
void NEV_Cbd7Asm(int16_t *r, const uint8_t *buf, uint32_t n);
void NEV_MaskTernary8Asm(int16_t *r, const uint8_t *mask, uint32_t n);
void NEV_NoiseMExtractAsm(int16_t *r, const uint8_t *buf, uint64_t eta, uint64_t seedLen, uint64_t dim);
#ifdef HITLS_CRYPTO_NEV_SVE2
#include "nev_sve2.h"
void NEV_Cbd1Sve2(int16_t *r, const uint8_t *buf, uint32_t n);
void NEV_Cbd2Sve2(int16_t *r, const uint8_t *buf, uint32_t n);
void NEV_Cbd3Sve2(int16_t *r, const uint8_t *buf, uint32_t n);
void NEV_Cbd4Sve2(int16_t *r, const uint8_t *buf, uint32_t n);
void NEV_Cbd7Sve2(int16_t *r, const uint8_t *buf, uint32_t n);
void NEV_MaskTernary8Sve2(int16_t *r, const uint8_t *mask, uint32_t n);
void NEV_NoiseMFoldSve2(uint8_t *buf, const uint8_t *msg, uint64_t planes,
    uint64_t seedLen);
void NEV_NoiseMExtractSve2(int16_t *r, const uint8_t *buf, uint64_t eta,
    uint64_t seedLen, uint64_t dim);
#define NEV_CBD_DISPATCH(name)                                      \
    static inline void Nev##name(int16_t *r, const uint8_t *b, uint32_t n) \
    {                                                               \
        if (NEV_Sve2Enabled() != 0) {                               \
            name##Sve2(r, b, n);                                    \
        } else {                                                    \
            name##Asm(r, b, n);                                     \
        }                                                           \
    }
NEV_CBD_DISPATCH(NEV_Cbd1)
NEV_CBD_DISPATCH(NEV_Cbd2)
NEV_CBD_DISPATCH(NEV_Cbd3)
NEV_CBD_DISPATCH(NEV_Cbd4)
NEV_CBD_DISPATCH(NEV_Cbd7)
#define NEV_CBD1_IMPL NevNEV_Cbd1
#define NEV_CBD2_IMPL NevNEV_Cbd2
#define NEV_CBD3_IMPL NevNEV_Cbd3
#define NEV_CBD4_IMPL NevNEV_Cbd4
#define NEV_CBD7_IMPL NevNEV_Cbd7
static inline void NevMaskTernary8(int16_t *r, const uint8_t *mask, uint32_t n)
{
    if (NEV_Sve2Enabled() != 0) {
        NEV_MaskTernary8Sve2(r, mask, n);
    } else {
        NEV_MaskTernary8Asm(r, mask, n);
    }
}
#define NEV_MaskTernary8Asm NevMaskTernary8
#else
#define NEV_CBD1_IMPL NEV_Cbd1Asm
#define NEV_CBD2_IMPL NEV_Cbd2Asm
#define NEV_CBD3_IMPL NEV_Cbd3Asm
#define NEV_CBD4_IMPL NEV_Cbd4Asm
#define NEV_CBD7_IMPL NEV_Cbd7Asm
#endif
#else
#define NEV_TERNARY3_IMPL Ternary3
#define NEV_CBD1_IMPL Cbd1
#define NEV_CBD2_IMPL Cbd2
#define NEV_CBD3_IMPL Cbd3
#define NEV_CBD4_IMPL Cbd4
#define NEV_CBD7_IMPL Cbd7
#endif

#ifndef HITLS_CRYPTO_NEV_ARMV8
// Uniform ternary rejection sampling: each byte < 243 yields 5 base-3 digits,
// mapped to {1, 0, -1}. Returns the number of coefficients produced.
static int32_t Ternary3(int16_t *r, const uint8_t *buf, int32_t n, int32_t bufLen)
{
    int32_t pos = 0;
    int8_t coeffs[5];
    for (int32_t i = 0; pos < n && i < bufLen; i++) {
        uint8_t x = buf[i];
        if (x < 243) {
            uint32_t y = x;
            uint32_t quo;
            quo = (y * 0xAAABu) >> 17;
            coeffs[0] = (int8_t)(1 - (int32_t)(y - 3u * quo));
            y = quo;
            quo = (y * 0xAAABu) >> 17;
            coeffs[1] = (int8_t)(1 - (int32_t)(y - 3u * quo));
            y = quo;
            quo = (y * 0xAAABu) >> 17;
            coeffs[2] = (int8_t)(1 - (int32_t)(y - 3u * quo));
            y = quo;
            quo = (y * 0xAAABu) >> 17;
            coeffs[3] = (int8_t)(1 - (int32_t)(y - 3u * quo));
            y = quo;
            coeffs[4] = (int8_t)(1 - (int32_t)y);
            for (int32_t j = 0; j < 5 && pos < n; j++) {
                r[pos++] = coeffs[j];
            }
        }
    }
    return pos;
}
#endif // !HITLS_CRYPTO_NEV_ARMV8

// Buffer-fed centered binomial extraction (eta in {1, 2, 3, 4, 7}); buf holds
// (at least) eta * n / 4 KDF bytes.
static inline void CbdDispatch(int16_t *r, const uint8_t *buf, uint32_t n, uint8_t eta)
{
    switch (eta) {
        case 1:
            NEV_CBD1_IMPL(r, buf, n);
            break;
        case 2:
            NEV_CBD2_IMPL(r, buf, n);
            break;
        case 3:
            NEV_CBD3_IMPL(r, buf, n);
            break;
        case 4:
            NEV_CBD4_IMPL(r, buf, n);
            break;
        default: // 7
            NEV_CBD7_IMPL(r, buf, n);
            break;
    }
}

// Reference poly_binomial_dist{1,2,3,4,7}: expand eta * n / 4 KDF bytes and run
// the matching centered binomial extractor.
static void SampleCbd(NEV_Poly *r, const uint8_t *seed, uint8_t nonce, uint8_t eta,
    const CRYPT_NevInfo *info)
{
    uint8_t buf[NEV_CBD_BUF_MAX];
    uint8_t extseed[NEV_SEED_MAX + 1];
    uint32_t n = info->n;
    uint32_t seedLen = info->seedLen;
    uint32_t bufLen = (uint32_t)eta * (n / 4);

    BuildExtSeed(extseed, seed, nonce, seedLen);
    NEV_Kdf(buf, bufLen, extseed, seedLen + 1, seedLen);
    CbdDispatch(r->coeffs, buf, n, eta);
}

// Reference poly_bias8_ternary: CBD1 on the first n / 4 bytes, then each of the
// remaining n / 8 bytes masks 8 consecutive coefficients (bit 0 keeps, bit 1 zeroes).
static void SampleBias8Ternary(NEV_Poly *r, const uint8_t *seed, uint8_t nonce,
    const CRYPT_NevInfo *info)
{
    uint8_t buf[NEV_BIAS8_BUF_MAX];
    uint8_t extseed[NEV_SEED_MAX + 1];
    uint32_t n = info->n;
    uint32_t seedLen = info->seedLen;

    BuildExtSeed(extseed, seed, nonce, seedLen);
    NEV_Kdf(buf, 3 * n / 8, extseed, seedLen + 1, seedLen);
    NEV_CBD1_IMPL(r->coeffs, buf, n);

    uint32_t pos = 2 * n / 8;
#ifdef HITLS_CRYPTO_NEV_ARMV8
    NEV_MaskTernary8Asm(r->coeffs, buf + pos, n);
#else
    for (uint32_t i = 0; i < n / 8; i++) {
        int16_t b = buf[pos++];
        for (uint32_t j = 0; j < 8; j++) {
            int16_t a = (int16_t)(-((b >> j) & 0x1));
            r->coeffs[8 * i + j] &= a;
        }
    }
#endif
}

// Reference poly_bias3_ternary: squeeze nblocks rate-sized blocks up front, run the
// rejection sampler, then squeeze one block at a time until n coefficients exist.
static void SampleBias3Ternary(NEV_Poly *r, const uint8_t *seed, uint8_t nonce,
    const CRYPT_NevInfo *info)
{
    uint8_t buf[NEV_BIAS3_BUF_MAX];
    uint8_t block[NEV_KDF_RATE_MAX];
    uint8_t extseed[NEV_SEED_MAX + 1];
    NEV_KdfState state;
    int32_t n = info->n;
    uint32_t seedLen = info->seedLen;
    int32_t rate = (int32_t)NEV_KdfRate(seedLen);
    int32_t nblocks = (int32_t)Bias3InitialBlocks((uint32_t)n, (uint32_t)rate);
    int32_t ctr;

    BuildExtSeed(extseed, seed, nonce, seedLen);
    NEV_KdfAbsorb(&state, extseed, seedLen + 1, seedLen);
    NEV_KdfSqueezeBlocks(buf, (uint32_t)nblocks, &state, seedLen);
    ctr = NEV_TERNARY3_IMPL(r->coeffs, buf, n, nblocks * rate);

    while (ctr < n) {
        NEV_KdfSqueezeBlocks(block, 1, &state, seedLen);
        ctr += NEV_TERNARY3_IMPL(r->coeffs + ctr, block, n - ctr, rate);
    }
}

void NEV_PolySampleEta(NEV_Poly *r, const uint8_t *seed, uint8_t nonce, uint8_t eta,
    const CRYPT_NevInfo *info)
{
    switch (eta) {
        case 1:
        case 2:
        case 3:
        case 4:
        case 7:
            SampleCbd(r, seed, nonce, eta, info);
            break;
        case 8:
            SampleBias8Ternary(r, seed, nonce, info);
            break;
        case 9:
            SampleBias3Ternary(r, seed, nonce, info);
            break;
        default: // unreachable for valid parameter sets (etaR == 0 means "no r poly")
            break;
    }
}

// Reference get_noisem_cbd{1,2,3,4,7} (both NTT_DIM variants). The KDF fills
// planes 1..8*eta-1 of seedLen bytes each; plane 0 is msg XOR-folded with every
// other plane. Coefficient c = a - b where a sums bit k of byte (bpi*i + j) over
// eta "positive" planes and b over the following eta "negative" planes; the four
// plane groups g land nttDim/4 apart, reproducing the strided incomplete-NTT
// order. With bpi = nttDim/32 this collapses the reference's NTT_DIM == 64
// (bpi 2) and NTT_DIM == 128 (bpi 4) code paths into one loop nest.
static inline void Store64(uint8_t *x, uint64_t v)
{
    x[0] = (uint8_t)v;
    x[1] = (uint8_t)(v >> 8);
    x[2] = (uint8_t)(v >> 16);
    x[3] = (uint8_t)(v >> 24);
    x[4] = (uint8_t)(v >> 32);
    x[5] = (uint8_t)(v >> 40);
    x[6] = (uint8_t)(v >> 48);
    x[7] = (uint8_t)(v >> 56);
}

// Buffer-fed extraction part of get_noisem: buf holds the KDF planes
// 1 .. 8*etaE-1 at buf + seedLen (plane 0 is computed here as the XOR fold of
// msg with every other plane, exactly as the reference).
//
// NoiseMExtractE carries eta as a parameter that every caller passes as a
// compile-time constant (the switch in NoiseMExtract below), mirroring the
// reference's per-eta get_noisem_cbd{1,2,3,4,7} functions.
//
// Loop mechanics only (the reference iterates k with all plane loads
// unrolled per bit): the XOR fold runs 8 bytes at a time (seedLen is 16, 32
// or 64, always a multiple of 8; LoadTo64/Store64 are bytewise little-endian
// so the fold stays bytewise XOR), and each plane-byte pair updates all 8
// carried coefficients through a constant-bound k loop that the compiler
// vectorizes (out[k] +/- bit k of the two plane bytes). Every coefficient
// remains the same a - b sum of the same plane bits as the reference, with
// every intermediate in [-7, 7], so the output is BIT-EXACT.
// Plane-0 XOR fold shared by the scalar and the ARMv8 extraction paths.
static inline void NoiseMFoldPlane0(const uint8_t *msg, uint8_t *buf, uint32_t planes, uint32_t seedLen)
{
    for (uint32_t i = 0; i < seedLen; i += 8) {
        uint64_t acc = LoadTo64(&msg[i]);
        for (uint32_t j = 1; j < planes; j++) {
            acc ^= LoadTo64(&buf[seedLen * j + i]);
        }
        Store64(&buf[i], acc);
    }
}

#ifndef HITLS_CRYPTO_NEV_ARMV8
static inline void NoiseMExtractE(NEV_Poly *r, const uint8_t *msg, uint8_t *buf,
    uint32_t eta, uint32_t seedLen, uint32_t dim)
{
    uint32_t bpi = dim / 32;         // bytes consumed per plane per outer iteration
    uint32_t groupStride = dim / 4;  // distance between the four plane groups

    NoiseMFoldPlane0(msg, buf, 8 * eta, seedLen);

    for (uint32_t i = 0; i < seedLen / bpi; i++) {
        for (uint32_t j = 0; j < bpi; j++) {
            uint32_t byteIdx = bpi * i + j;
            for (uint32_t g = 0; g < 4; g++) {
                const uint8_t *pa = &buf[(g * 2 * eta) * seedLen + byteIdx];
                const uint8_t *pb = &pa[eta * seedLen];
                int16_t *out = &r->coeffs[dim * i + groupStride * g + 8 * j];
                uint32_t xa = pa[0];
                uint32_t xb = pb[0];
                for (uint32_t k = 0; k < 8; k++) {
                    out[k] = (int16_t)(((xa >> k) & 0x1) - ((xb >> k) & 0x1));
                }
                for (uint32_t t = 1; t < eta; t++) {
                    xa = pa[t * seedLen];
                    xb = pb[t * seedLen];
                    for (uint32_t k = 0; k < 8; k++) {
                        out[k] = (int16_t)(out[k] + ((xa >> k) & 0x1) - ((xb >> k) & 0x1));
                    }
                }
            }
        }
    }
}

#endif // !HITLS_CRYPTO_NEV_ARMV8

static void NoiseMExtract(NEV_Poly *r, const uint8_t *msg, uint8_t *buf, const CRYPT_NevInfo *info)
{
    uint32_t seedLen = info->seedLen;
    uint32_t dim = info->nttDim;

#ifdef HITLS_CRYPTO_NEV_ARMV8
    // The SVE2 path folds 32 plane bytes at once and uses an eta-specialized
    // 32-coefficient extractor.  NEON retains the shared scalar fold.
#ifdef HITLS_CRYPTO_NEV_SVE2
    if (NEV_Sve2Enabled() != 0) {
        NEV_NoiseMFoldSve2(buf, msg, 8 * (uint32_t)info->etaE, seedLen);
        NEV_NoiseMExtractSve2(r->coeffs, buf, info->etaE, seedLen, dim);
        return;
    }
#endif
    NoiseMFoldPlane0(msg, buf, 8 * (uint32_t)info->etaE, seedLen);
    NEV_NoiseMExtractAsm(r->coeffs, buf, info->etaE, seedLen, dim);
#else
    // etaE is 1, 2, 3, 4 or 7 for every parameter set (nev.c table); the
    // switch hands each case a literal eta (same convention as CbdDispatch).
    switch (info->etaE) {
        case 1:
            NoiseMExtractE(r, msg, buf, 1, seedLen, dim);
            break;
        case 2:
            NoiseMExtractE(r, msg, buf, 2, seedLen, dim);
            break;
        case 3:
            NoiseMExtractE(r, msg, buf, 3, seedLen, dim);
            break;
        case 4:
            NoiseMExtractE(r, msg, buf, 4, seedLen, dim);
            break;
        default: // 7
            NoiseMExtractE(r, msg, buf, 7, seedLen, dim);
            break;
    }
#endif // HITLS_CRYPTO_NEV_ARMV8
}

void NEV_PolyGetNoiseM(NEV_Poly *r, const uint8_t *msg, const uint8_t *seed, uint8_t nonce,
    const CRYPT_NevInfo *info)
{
    uint8_t buf[NEV_CBD_BUF_MAX]; // 8 * etaE * seedLen <= 3584, see NEV_CBD_BUF_MAX
    uint8_t extseed[NEV_SEED_MAX + 1];
    uint32_t seedLen = info->seedLen;
    uint32_t planes = 8 * (uint32_t)info->etaE;

    BuildExtSeed(extseed, seed, nonce, seedLen);
    NEV_Kdf(buf + seedLen, (planes - 1) * seedLen, extseed, seedLen + 1, seedLen);
    NoiseMExtract(r, msg, buf, info);
}

#if defined(HITLS_CRYPTO_NEV_ARMV8) && !defined(PQCP_NEV_DISABLE_KECCAK_X2)
/*
 * Two-lane batched sampling for the COMPRESS == 0 encrypt path (nev_kem.c
 * OwPkeEncDet): r = SampleEta(seed, nonce 0, etaR) and the message noise
 * e = GetNoiseM(msg, seed, nonce 1, etaE) expand the two same-length inputs
 * seed||0 and seed||1 through the same-rate XOF.  The min(blocksR, blocksE)
 * common prefix of both streams runs in one Keccakx2 pass; then the two
 * sponge lanes are deinterleaved (lane l of state word i is the scalar
 * state word i of stream l, by the Keccakx2 layout) and any longer tail —
 * including the eta-9 rejection top-up — continues through the scalar
 * squeeze, so neither lane ever squeezes blocks the other does not need.
 *
 * Bit-exactness: Keccakx2Absorb/Squeeze produce, per lane, exactly the
 * KeccakAbsorb/KeccakSqueeze stream (same rate, same 0x1F domain), the
 * sponge squeeze is a pure function of the state array, and each extractor
 * reads the same prefix of the same stream as the single-lane code:
 *  - etaR in {2, 3, 4, 7} (sets 4, 5, 7, 8, 9): the CBD consumes exactly
 *    etaR * n / 4 bytes of the r stream;
 *  - etaR == 9 (sets 6, 10, 11, 12): blocksR is the scalar sampler's
 *    initial squeeze, and the top-up loop below repeats the scalar
 *    per-block sequence on the deinterleaved lane-0 state.
 *
 * Buffer bound: max over the COMPRESS == 0 sets of blocks * rate is
 * 8 * 136 = 1088 for the r lane (NEV-1024-3329) and 21 * 72 = 1512 for the
 * e lane (NEV-2048-3329, lenE = 23 * 64 = 1472); the e buffer additionally
 * offsets the stream by seedLen (plane 0 is derived, not squeezed).
 */
#define NEV_X2_STREAM_MAX 1512

/* Split the interleaved two-lane sponge into two scalar KDF states (lane l of
 * state word i is the scalar state word i of stream l, by the Keccakx2
 * layout), so unequal tails continue through the scalar squeeze. */
static void X2Deinterleave(const Keccakx2State state, NEV_KdfState *s0, NEV_KdfState *s1)
{
    uint64_t lanes[2 * 25];

    memcpy(lanes, state, sizeof(lanes));
    for (uint32_t i = 0; i < 25; i++) {
        s0->s[i] = lanes[2 * i];
        s1->s[i] = lanes[2 * i + 1];
    }
}

#ifdef HITLS_CRYPTO_NEV_SVE2
static void ParallelX2Expand(CRYPT_Sha3Sve2State *wide, uint32_t rate,
    const uint8_t *in0, const uint8_t *in1, uint32_t inLen,
    uint8_t *out0, uint8_t *out1, uint32_t nblocks)
{
    const uint8_t *inputs[2] = { in0, in1 };
    uint8_t *outputs[2] = { out0, out1 };

    CRYPT_Sha3Sve2Absorb(wide, rate, inputs, 2, inLen, 0x1F);
    CRYPT_Sha3Sve2Squeeze(outputs, 2, nblocks, rate, wide);
}

static void ParallelDeinterleave2(const CRYPT_Sha3Sve2State *wide, uint32_t lanes,
    NEV_KdfState *s0, NEV_KdfState *s1)
{
#ifdef HITLS_CRYPTO_NEV_SVE2_SHA3
    lanes = 2;
#endif
    for (uint32_t i = 0; i < 25; i++) {
        s0->s[i] = wide->s[lanes * i];
        s1->s[i] = wide->s[lanes * i + 1];
    }
}
#endif

void NEV_PolySampleRAndNoiseM(NEV_Poly *r, NEV_Poly *e, const uint8_t *msg, const uint8_t *seed,
    const CRYPT_NevInfo *info)
{
    uint8_t bufR[NEV_X2_STREAM_MAX];
    uint8_t bufE[NEV_SEED_MAX + NEV_X2_STREAM_MAX];
    uint8_t block[NEV_KDF_RATE_MAX];
    uint8_t extseed0[NEV_SEED_MAX + 1];
    uint8_t extseed1[NEV_SEED_MAX + 1];
    Keccakx2State state;
    NEV_KdfState st0;
    NEV_KdfState st1;
    uint32_t n = info->n;
    uint32_t seedLen = info->seedLen;
    uint32_t rate = NEV_KdfRate(seedLen);
    uint8_t etaR = info->etaR;
    uint32_t blocksR;
    uint32_t blocksE = ((8 * (uint32_t)info->etaE - 1) * seedLen + rate - 1) / rate;
    uint32_t common;

    if (etaR == 9) {
        blocksR = Bias3InitialBlocks(n, rate);
    } else {
        blocksR = ((uint32_t)etaR * (n / 4) + rate - 1) / rate;
    }
    common = (blocksR < blocksE) ? blocksR : blocksE;

    BuildExtSeed(extseed0, seed, 0, seedLen);
    BuildExtSeed(extseed1, seed, 1, seedLen);
#ifdef HITLS_CRYPTO_NEV_SVE2
    uint32_t sveLanes = CRYPT_Sha3Sve2Lanes();
    CRYPT_Sha3Sve2State wide;
    ParallelX2Expand(&wide, rate, extseed0, extseed1, seedLen + 1,
        bufR, bufE + seedLen, common);
    ParallelDeinterleave2(&wide, sveLanes, &st0, &st1);
#else
        Keccakx2Absorb(state, rate, extseed0, extseed1, seedLen + 1, 0x1F);
        Keccakx2Squeeze(bufR, bufE + seedLen, common, rate, state);
        X2Deinterleave(state, &st0, &st1);
#endif
    if (blocksR > common) {
        NEV_KdfSqueezeBlocks(bufR + common * rate, blocksR - common, &st0, seedLen);
    }
    if (blocksE > common) {
        NEV_KdfSqueezeBlocks(bufE + seedLen + common * rate, blocksE - common, &st1, seedLen);
    }

    if (etaR == 9) {
        int32_t ctr = NEV_TERNARY3_IMPL(r->coeffs, bufR, (int32_t)n, (int32_t)(blocksR * rate));
        while (ctr < (int32_t)n) {
            NEV_KdfSqueezeBlocks(block, 1, &st0, seedLen);
            ctr += NEV_TERNARY3_IMPL(r->coeffs + ctr, block, (int32_t)n - ctr, (int32_t)rate);
        }
    } else {
        CbdDispatch(r->coeffs, bufR, n, etaR);
    }
    NoiseMExtract(e, msg, bufE, info);
}

/*
 * ------------------------------------------------------------------
 * Batched XOF nonce ladder for the key-generation loops (see nev_local.h).
 *
 * Bit-exactness argument.  For every eta, the scalar NEV_PolySampleEta reads
 * a prefix of the block stream KDF(seed || nonce):
 *   - CBD eta in {1,2,3,4,7}: the first eta * n/4 bytes (NEV_Kdf squeezes
 *     ceil(need/rate) whole blocks; the extractor reads the byte prefix);
 *   - eta 8: the first 3n/8 bytes, same shape;
 *   - eta 9: Bias3InitialBlocks whole blocks (minimum prefix plus a safety
 *     block only for statistically borderline prefixes), then single whole
 *     blocks until n coefficients are accepted.  The accepted
 *     coefficient sequence is a function of the byte stream alone: the
 *     rejection filter is per byte and the only group truncation happens at
 *     the fixed boundary n, so the chunk boundaries (initial region size,
 *     per-block top-up) cannot change the output.
 * The ladder serves exactly those stream prefixes: a pair expansion produces,
 * per lane, the same absorb (seed || nonce, pad 0x1F, same rate) and the same
 * permute-then-extract block sequence as the scalar KDF (Keccakx2Absorb /
 * Keccakx2Squeeze are lane-wise identical to KeccakAbsorb / KeccakSqueeze,
 * already relied upon by NEV_PolySampleRAndNoiseM above), and the buffered
 * lane's continuation state is deinterleaved so later blocks come from the
 * scalar squeeze of the same sponge.  A LadderView hands the consumer whole
 * blocks in stream order, first from the buffered prefix, then from the
 * continuation state, so every consumer sees the same bytes at the same
 * offsets as its scalar counterpart.
 */

/* Whole-block reader over a buffered stream prefix plus its continuation. */
typedef struct {
    const uint8_t *buf;   // buffered whole blocks of the stream (may be NULL)
    uint32_t bufBlocks;   // number of buffered blocks
    uint32_t cursor;      // buffered blocks already consumed
    NEV_KdfState *state;  // sponge positioned after the buffered blocks
    uint32_t rate;
    uint32_t seedLen;
} LadderView;

static void LadderViewRead(LadderView *v, uint8_t *dst, uint32_t blocks)
{
    while (blocks > 0 && v->cursor < v->bufBlocks) {
        memcpy(dst, v->buf + (size_t)v->cursor * v->rate, v->rate);
        dst += v->rate;
        v->cursor++;
        blocks--;
    }
    if (blocks > 0) {
        NEV_KdfSqueezeBlocks(dst, blocks, v->state, v->seedLen);
    }
}

/* Whole blocks of the scalar sampler's initial squeeze for this eta. */
static uint32_t LadderInitialBlocks(uint8_t eta, const CRYPT_NevInfo *info)
{
    uint32_t rate = NEV_KdfRate(info->seedLen);
    uint32_t n = info->n;
    uint32_t need;

    if (eta == 9) {
        return Bias3InitialBlocks(n, rate);
    }
    need = (eta == 8) ? (3 * n / 8) : ((uint32_t)eta * (n / 4));
    return (need + rate - 1) / rate;
}

/* Run the per-eta extractor over a stream view (same calls, same prefixes as
 * SampleCbd / SampleBias8Ternary / SampleBias3Ternary). */
static void LadderConsume(LadderView *v, NEV_Poly *r, uint8_t eta, const CRYPT_NevInfo *info)
{
    uint8_t buf[NEV_LADDER_BUF_MAX];
    uint32_t n = info->n;
    uint32_t rate = v->rate;

    if (eta == 9) {
        uint8_t block[NEV_KDF_RATE_MAX];
        int32_t nblocks = (int32_t)LadderInitialBlocks(9, info);
        int32_t ctr;

        LadderViewRead(v, buf, (uint32_t)nblocks);
        ctr = NEV_TERNARY3_IMPL(r->coeffs, buf, (int32_t)n, nblocks * (int32_t)rate);
        while (ctr < (int32_t)n) {
            LadderViewRead(v, block, 1);
            ctr += NEV_TERNARY3_IMPL(r->coeffs + ctr, block, (int32_t)n - ctr, (int32_t)rate);
        }
        return;
    }
    LadderViewRead(v, buf, LadderInitialBlocks(eta, info));
    if (eta == 8) {
        NEV_CBD1_IMPL(r->coeffs, buf, n);
        NEV_MaskTernary8Asm(r->coeffs, buf + 2 * n / 8, n);
    } else {
        CbdDispatch(r->coeffs, buf, n, eta);
    }
}

void NEV_PolySampleEtaLadder(NEV_XofLadder *l, NEV_Poly *r, const uint8_t *seed, uint8_t nonce,
    uint8_t eta, const CRYPT_NevInfo *info)
{
    uint32_t seedLen = info->seedLen;
    uint32_t rate = NEV_KdfRate(seedLen);
    uint32_t blocks = LadderInitialBlocks(eta, info);

#ifdef HITLS_CRYPTO_NEV_SVE2
    for (uint32_t slot = 0; slot < 3; slot++) {
        NEV_XofLadderEntry *entry = &l->cached[slot];
        if (entry->valid != 0 && entry->nonce == nonce &&
            blocks * rate <= NEV_LADDER_BUF_MAX) {
            LadderView v = { entry->buf, entry->bufBlocks, 0, &entry->state,
                rate, seedLen };
            entry->valid = 0;
            LadderConsume(&v, r, eta, info);
            return;
        }
    }
    for (uint32_t slot = 0; slot < 3; slot++) {
        l->cached[slot].valid = 0;
    }
    if (nonce > 252 || blocks * rate > NEV_LADDER_BUF_MAX) {
        NEV_PolySampleEta(r, seed, nonce, eta, info);
        return;
    }

    uint8_t extseed[4][NEV_SEED_MAX + 1];
    uint8_t myBuf[NEV_LADDER_BUF_MAX];
    const uint8_t *inputs[4];
    uint8_t *outputs[4];
    CRYPT_Sha3Sve2State wide;
    NEV_KdfState st0;

    for (uint32_t lane = 0; lane < 4; lane++) {
        BuildExtSeed(extseed[lane], seed, (uint8_t)(nonce + lane), seedLen);
        inputs[lane] = extseed[lane];
        outputs[lane] = (lane == 0) ? myBuf : l->cached[lane - 1].buf;
    }
    CRYPT_Sha3Sve2Absorb(&wide, rate, inputs, 4, seedLen + 1, 0x1F);
    CRYPT_Sha3Sve2Squeeze(outputs, 4, blocks, rate, &wide);

    for (uint32_t word = 0; word < 25; word++) {
        st0.s[word] = wide.s[4 * word];
        for (uint32_t slot = 0; slot < 3; slot++) {
            l->cached[slot].state.s[word] = wide.s[4 * word + slot + 1];
        }
    }
    for (uint32_t slot = 0; slot < 3; slot++) {
        l->cached[slot].bufBlocks = blocks;
        l->cached[slot].nonce = (uint8_t)(nonce + slot + 1);
        l->cached[slot].valid = 1;
    }

    LadderView v = { myBuf, blocks, 0, &st0, rate, seedLen };
    LadderConsume(&v, r, eta, info);
#else
    if (l->valid != 0 && l->nonce == nonce && blocks * rate <= NEV_LADDER_BUF_MAX) {
        // The speculated lane is this attempt's stream: consume it.
        LadderView v = { l->buf, l->bufBlocks, 0, &l->state, rate, seedLen };
        l->valid = 0;
        LadderConsume(&v, r, eta, info);
        return;
    }
    l->valid = 0;
    if (nonce == 255 || blocks * rate > NEV_LADDER_BUF_MAX) {
        // No nonce + 1 stream exists (the keygen nonce is a uint8_t), or the
        // parameter set outgrew the ladder buffer: single-lane fallback.
        NEV_PolySampleEta(r, seed, nonce, eta, info);
        return;
    }

    // Speculative pair (nonce, nonce + 1): one Keccakx2 absorb + squeeze
    // serves this attempt (lane 0, direct) and buffers the next (lane 1).
    uint8_t extseed0[NEV_SEED_MAX + 1];
    uint8_t extseed1[NEV_SEED_MAX + 1];
    uint8_t myBuf[NEV_LADDER_BUF_MAX];
    Keccakx2State state;
    NEV_KdfState st0;

    BuildExtSeed(extseed0, seed, nonce, seedLen);
    BuildExtSeed(extseed1, seed, (uint8_t)(nonce + 1), seedLen);
#ifdef HITLS_CRYPTO_NEV_SVE2
    uint32_t sveLanes = CRYPT_Sha3Sve2Lanes();
    CRYPT_Sha3Sve2State wide;
    ParallelX2Expand(&wide, rate, extseed0, extseed1, seedLen + 1,
        myBuf, l->buf, blocks);
    ParallelDeinterleave2(&wide, sveLanes, &st0, &l->state);
#else
        Keccakx2Absorb(state, rate, extseed0, extseed1, seedLen + 1, 0x1F);
        Keccakx2Squeeze(myBuf, l->buf, blocks, rate, state);
        X2Deinterleave(state, &st0, &l->state);
#endif
    l->bufBlocks = blocks;
    l->nonce = (uint8_t)(nonce + 1);
    l->valid = 1;

    LadderView v = { myBuf, blocks, 0, &st0, rate, seedLen };
    LadderConsume(&v, r, eta, info);
#endif
}
#endif // HITLS_CRYPTO_NEV_ARMV8 && !PQCP_NEV_DISABLE_KECCAK_X2

#endif // HITLS_CRYPTO_NEV
