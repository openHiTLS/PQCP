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

#include <stdbool.h>

#include "nev_local.h"
#include "sha3_core.h"
#ifdef HITLS_CRYPTO_NEV_SVE2
#include "asm_sha3_sve2.h"
void SHA3_Sve2Permute(uint64_t *state);
#ifdef HITLS_CRYPTO_NEV_SVE2_SHA3
void NEV_SHA3_NeonPermute1(uint64_t *state);
#endif
#endif

#define NEV_SHA3_128_RATE 168
#define NEV_SHA3_256_RATE 136
#define NEV_SHA3_512_RATE 72

static inline uint64_t SpongeLoad64(const uint8_t *x)
{
#if defined(__aarch64__) && !defined(HITLS_BIG_ENDIAN)
    return *(const uint64_t *)(uintptr_t)x;
#else
    uint64_t r = 0;
    for (uint32_t i = 0; i < 8; i++) {
        r |= (uint64_t)x[i] << (8 * i);
    }
    return r;
#endif
}

static inline void SpongeStore64(uint8_t *x, uint64_t u)
{
#if defined(__aarch64__) && !defined(HITLS_BIG_ENDIAN)
    *(uint64_t *)(uintptr_t)x = u;
#else
    for (uint32_t i = 0; i < 8; i++) {
        x[i] = (uint8_t)(u >> (8 * i));
    }
#endif
}

static inline __attribute__((always_inline)) uint32_t SpongeLanes(void)
{
    return 1;
}

static inline __attribute__((always_inline)) void SpongePermute(uint64_t *state,
    uint32_t lanes)
{
#ifdef HITLS_CRYPTO_NEV_SVE2
    (void)lanes;
#ifdef HITLS_CRYPTO_NEV_SVE2_SHA3
    NEV_SHA3_NeonPermute1(state);
#else
    /* A single stream cannot fill a 256-bit SVE register.  Keep it in the
     * compact ARMv8 Keccak state and reserve SVE2 for four-way work. */
    SHA3_Keccak((uint8_t *)state);
#endif
#else
    (void)lanes;
    SHA3_Keccak((uint8_t *)state);
#endif
}

static inline void SpongeAbsorb(uint64_t *s, uint32_t lanes, uint32_t rate,
    const uint8_t *in, uint32_t inLen, uint8_t pad)
{
    uint32_t i;
    uint32_t laneCnt = rate >> 3;

    for (i = 0; i < 25 * lanes; i++) {
        s[i] = 0;
    }
    while (inLen >= rate) {
        for (i = 0; i < laneCnt; i++) {
            s[i * lanes] ^= SpongeLoad64(in + 8 * i);
        }
        in += rate;
        inLen -= rate;
        SpongePermute(s, lanes);
    }
    for (i = 0; i < inLen >> 3; i++) {
        s[i * lanes] ^= SpongeLoad64(in + 8 * i);
    }
    for (i <<= 3; i < inLen; i++) {
        s[(i / 8) * lanes] ^= (uint64_t)in[i] << (8 * (i % 8));
    }
    s[(inLen / 8) * lanes] ^= (uint64_t)pad << (8 * (inLen % 8));
    s[((rate - 1) / 8) * lanes] ^= 1ULL << 63;
}

static inline void SpongeSqueezeBlocks(uint8_t *out, uint32_t nblocks,
    uint64_t *s, uint32_t lanes, uint32_t rate)
{
    uint32_t laneCnt = rate >> 3;

    while (nblocks != 0) {
        SpongePermute(s, lanes);
        for (uint32_t i = 0; i < laneCnt; i++) {
            SpongeStore64(out + 8 * i, s[i * lanes]);
        }
        out += rate;
        nblocks--;
    }
}

static void SpongeXof(uint8_t *out, uint32_t outLen, const uint8_t *in,
    uint32_t inLen, uint32_t rate, uint8_t pad)
{
    uint64_t s[25 * NEV_SPONGE_LANES_MAX];
    uint8_t tail[NEV_KDF_RATE_MAX];
    uint32_t nblocks = outLen / rate;
    uint32_t lanes = SpongeLanes();

    SpongeAbsorb(s, lanes, rate, in, inLen, pad);
    SpongeSqueezeBlocks(out, nblocks, s, lanes, rate);
    out += nblocks * rate;
    outLen -= nblocks * rate;
    if (outLen != 0) {
        SpongeSqueezeBlocks(tail, 1, s, lanes, rate);
        for (uint32_t i = 0; i < outLen; i++) {
            out[i] = tail[i];
        }
    }
}

uint32_t NEV_KdfRate(uint32_t seedLen)
{
    return (seedLen == 16) ? NEV_SHA3_128_RATE :
        ((seedLen == 32) ? NEV_SHA3_256_RATE : NEV_SHA3_512_RATE);
}

void NEV_Hash(uint8_t *out, const uint8_t *in, uint32_t inLen, uint32_t seedLen)
{
    SpongeXof(out, seedLen, in, inLen, NEV_KdfRate(seedLen), 0x06);
}

void NEV_Hash2(uint8_t *out, const uint8_t *in, uint32_t inLen, uint32_t seedLen)
{
    uint32_t rate = (seedLen == 16) ? NEV_SHA3_256_RATE : NEV_SHA3_512_RATE;
    SpongeXof(out, 2 * seedLen, in, inLen, rate, 0x06);
}

void NEV_Kdf(uint8_t *out, uint32_t outLen, const uint8_t *in, uint32_t inLen,
    uint32_t seedLen)
{
    SpongeXof(out, outLen, in, inLen, NEV_KdfRate(seedLen), 0x1F);
}

void NEV_KdfAbsorb(NEV_KdfState *state, const uint8_t *in, uint32_t inLen,
    uint32_t seedLen)
{
    SpongeAbsorb(state->s, SpongeLanes(), NEV_KdfRate(seedLen), in, inLen, 0x1F);
}

void NEV_KdfSqueezeBlocks(uint8_t *out, uint32_t nblocks, NEV_KdfState *state,
    uint32_t seedLen)
{
    SpongeSqueezeBlocks(out, nblocks, state->s, SpongeLanes(), NEV_KdfRate(seedLen));
}
