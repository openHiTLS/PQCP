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

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_NEV) && defined(HITLS_CRYPTO_NEV_SVE2)

#include <stddef.h>

#include "asm_sha3_sve2.h"

#ifdef HITLS_CRYPTO_NEV_SVE2_SHA3
void NEV_SHA3_NeonPermute2(uint64_t *state);
#endif

static inline uint32_t ParallelLanes(uint32_t streams)
{
#ifdef HITLS_CRYPTO_NEV_SVE2_SHA3
    if (streams <= 2U) {
        return 2U;
    }
#else
    (void)streams;
#endif
    return CRYPT_Sha3Sve2Lanes();
}

static inline void ParallelPermute(uint64_t *state, uint32_t streams)
{
#ifdef HITLS_CRYPTO_NEV_SVE2_SHA3
    if (streams <= 2U) {
        NEV_SHA3_NeonPermute2(state);
        return;
    }
#else
    (void)streams;
#endif
    SHA3_Sve2Permute(state);
}

static inline uint64_t Load64Le(const uint8_t *p)
{
    uint64_t v = 0;
    for (uint32_t i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (8U * i);
    }
    return v;
}

static inline void Store64Le(uint8_t *p, uint64_t v)
{
    for (uint32_t i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8U * i));
    }
}

uint32_t CRYPT_Sha3Sve2Lanes(void)
{
    return CRYPT_SHA3_SVE2_MAX_LANES;
}

void CRYPT_Sha3Sve2Absorb(CRYPT_Sha3Sve2State *state, uint32_t rate,
    const uint8_t *const inputs[], uint32_t streams, uint32_t inLen, uint8_t pad)
{
    uint32_t maxLanes = CRYPT_Sha3Sve2Lanes();
    uint32_t lanes = ParallelLanes(streams);
    if (streams == 0 || streams > maxLanes || rate == 0 || rate > 200) {
        return;
    }
    for (uint32_t i = 0; i < 25U * lanes; i++) {
        state->s[i] = 0;
    }

    uint32_t offset = 0;
    uint32_t remaining = inLen;
    while (remaining >= rate) {
        for (uint32_t word = 0; word < rate / 8; word++) {
            for (uint32_t stream = 0; stream < streams; stream++) {
                state->s[word * lanes + stream] ^=
                    Load64Le(inputs[stream] + offset + 8U * word);
            }
        }
        offset += rate;
        remaining -= rate;
        ParallelPermute(state->s, streams);
    }

    for (uint32_t stream = 0; stream < streams; stream++) {
        const uint8_t *in = inputs[stream] + offset;
        uint32_t i = 0;
        for (; i + 8 <= remaining; i += 8) {
            state->s[(i / 8) * lanes + stream] ^= Load64Le(in + i);
        }
        for (; i < remaining; i++) {
            state->s[(i / 8) * lanes + stream] ^= (uint64_t)in[i] << (8U * (i % 8));
        }
        state->s[(remaining / 8) * lanes + stream] ^=
            (uint64_t)pad << (8U * (remaining % 8));
        state->s[((rate - 1) / 8) * lanes + stream] ^= 1ULL << 63;
    }
}

void CRYPT_Sha3Sve2Squeeze(uint8_t *const outputs[], uint32_t streams,
    uint32_t nblocks, uint32_t rate, CRYPT_Sha3Sve2State *state)
{
    uint32_t maxLanes = CRYPT_Sha3Sve2Lanes();
    uint32_t lanes = ParallelLanes(streams);
    if (streams == 0 || streams > maxLanes || rate == 0 || rate > 200) {
        return;
    }
    for (uint32_t block = 0; block < nblocks; block++) {
        ParallelPermute(state->s, streams);
        for (uint32_t word = 0; word < rate / 8; word++) {
            for (uint32_t stream = 0; stream < streams; stream++) {
                Store64Le(outputs[stream] + block * rate + 8U * word,
                    state->s[word * lanes + stream]);
            }
        }
    }
}

#endif
