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

#ifdef PQCP_HIAE

/*
 * Implementation of the HiAE algorithm in accordance with:
 * - IETF Internet-Draft "The HiAE Authenticated Encryption Algorithm"
 *   (draft-pham-cfrg-hiae-02, published on July 21, 2025).
 * - ePrint paper: https://eprint.iacr.org/2025/377
 *   (version 20250604:080522).
 */

#include <string.h>

#include "pqcp_err.h"
#include "hiae_impl.h"

#define HIAE_P_0 0u
#define HIAE_P_1 1u
#define HIAE_P_13 13u
#define HIAE_P_9 9u
#define HIAE_i_3 3u
#define HIAE_i_13 13u

static const uint8_t CONST0[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                                   0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
static const uint8_t CONST1[16] = {0x4a, 0x40, 0x93, 0x82, 0x22, 0x99, 0xf3, 0x1d,
                                   0x00, 0x82, 0xef, 0xa9, 0x8e, 0xc4, 0xe6, 0xc8};

#if defined(__AES__) && defined(__x86_64__)
#include <immintrin.h>
#include <wmmintrin.h>

#define SIMD_LOAD(x)     _mm_loadu_si128((const __m128i *)(x))
#define SIMD_STORE(x, y) _mm_storeu_si128((__m128i *)(x), (y))
#define SIMD_XOR(x, y)   _mm_xor_si128((x), (y))
#define SIMD_ZERO_128()  _mm_setzero_si128()
#define AESL(x)          _mm_aesenc_si128((x), SIMD_ZERO_128())
#define AESENC(x, y)     _mm_aesenc_si128((x), (y))

/* §3.4.2.1 The Update Function: Update(xi). */
__attribute__((always_inline)) static inline void HIAE_State_Update(DATA128b *state, DATA128b xi, const uint32_t offset)
{
    const uint32_t idxP0 = (HIAE_P_0 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP1 = (HIAE_P_1 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP13 = (HIAE_P_13 + offset) % HIAE_STATE_NUM;
    const uint32_t idxI3 = (HIAE_i_3 + offset) % HIAE_STATE_NUM;
    const uint32_t idxI13 = (HIAE_i_13 + offset) % HIAE_STATE_NUM;
    const uint32_t idxIn = offset % HIAE_STATE_NUM;

    DATA128b t;
    t = SIMD_XOR(state[idxP0], state[idxP1]);
    t = AESENC(t, xi); // t  = AESL(S0 ^ S1) ^ xi
    state[idxIn] = AESENC(state[idxP13], t); // S0 = AESL(S13) ^ t
    state[idxI3] = SIMD_XOR(state[idxI3], xi); // S3 = S3 ^ xi
    state[idxI13] = SIMD_XOR(state[idxI13], xi); // S13 = S13 ^ xi
}

/* §3.4.2.2 The UpdateEnc Function: UpdateEnc(mi) -> ci. */
__attribute__((always_inline)) static inline DATA128b HIAE_State_UpdateEnc(DATA128b *state, DATA128b mi,
                                                                           const uint32_t offset)
{
    const uint32_t idxP0 = (HIAE_P_0 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP1 = (HIAE_P_1 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP13 = (HIAE_P_13 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP9 = (HIAE_P_9 + offset) % HIAE_STATE_NUM;
    const uint32_t idxI3 = (HIAE_i_3 + offset) % HIAE_STATE_NUM;
    const uint32_t idxI13 = (HIAE_i_13 + offset) % HIAE_STATE_NUM;
    const uint32_t idxIn = offset % HIAE_STATE_NUM;

    DATA128b t;
    t = SIMD_XOR(state[idxP0], state[idxP1]);
    t = AESENC(t, mi); // t = AESL(S0 ^ S1) ^ mi
    state[idxIn] = AESENC(state[idxP13], t); // S0 = AESL(S13) ^ t
    t = SIMD_XOR(t, state[idxP9]); // ci = t ^ S9
    state[idxI3] = SIMD_XOR(state[idxI3], mi); // S3 = S3 ^ mi
    state[idxI13] = SIMD_XOR(state[idxI13], mi); // S13 = S13 ^ mi
    return t;
}

/* §3.4.2.3 The UpdateDec Function: UpdateDec(ci) -> mi. */
__attribute__((always_inline)) static inline DATA128b HIAE_State_UpdateDec(DATA128b *state, DATA128b ci,
                                                                           const uint32_t offset)
{
    const uint32_t idxP0 = (HIAE_P_0 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP1 = (HIAE_P_1 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP13 = (HIAE_P_13 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP9 = (HIAE_P_9 + offset) % HIAE_STATE_NUM;
    const uint32_t idxI3 = (HIAE_i_3 + offset) % HIAE_STATE_NUM;
    const uint32_t idxI13 = (HIAE_i_13 + offset) % HIAE_STATE_NUM;
    const uint32_t idxIn = offset % HIAE_STATE_NUM;

    DATA128b t;
    DATA128b mi;
    t = SIMD_XOR(state[idxP9], ci); // t = ci ^ S9
    mi = SIMD_XOR(state[idxP0], state[idxP1]);
    mi = AESENC(mi, t); // mi = AESL(S0 ^ S1) ^ t
    state[idxIn] = AESENC(state[idxP13], t); // S0 = AESL(S13) ^ t
    state[idxI3] = SIMD_XOR(state[idxI3], mi); // S3 = S3 ^ mi
    state[idxI13] = SIMD_XOR(state[idxI13], mi); // S13 = S13 ^ mi
    return mi;
}

/* §3.5.5 DecPartial helper: keystream reconstruction for tail bytes. */
__attribute__((always_inline)) static inline DATA128b HIAE_State_UpdateKeystream(DATA128b *state, DATA128b ci,
                                                                                 const uint32_t offset)
{
    const uint32_t idxP0 = (HIAE_P_0 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP1 = (HIAE_P_1 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP9 = (HIAE_P_9 + offset) % HIAE_STATE_NUM;

    DATA128b ks;
    ks = SIMD_XOR(state[idxP0], state[idxP1]);
    ks = AESENC(ks, ci);
    ks = SIMD_XOR(ks, state[idxP9]); // ks = AESL(S0 ^ S1) ^ ZeroPad(cn) ^ S9
    return ks;
}

#elif defined(__ARM_FEATURE_CRYPTO) && defined(__ARM_NEON)
#include <arm_neon.h>

#define SIMD_LOAD(x)     vld1q_u8((const uint8_t *)(x))
#define SIMD_STORE(x, y) vst1q_u8((uint8_t *)(x), (y))
#define SIMD_XOR(x, y)   veorq_u8((x), (y))
#define SIMD_ZERO_128()  vmovq_n_u8(0)
#define AESEMC(x, y)     vaesmcq_u8(vaeseq_u8((x), (y)))
#define AESL(x)          AESEMC((x), SIMD_ZERO_128())
#define AESENC(x, y)     SIMD_XOR(AESEMC((x), SIMD_ZERO_128()), (y))

/* §3.4.2.1 The Update Function (ARMv8 mapping). */
__attribute__((always_inline)) static inline void HIAE_State_Update(DATA128b *state, DATA128b xi, const uint32_t offset)
{
    const uint32_t idxP0 = (HIAE_P_0 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP1 = (HIAE_P_1 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP13 = (HIAE_P_13 + offset) % HIAE_STATE_NUM;
    const uint32_t idxI3 = (HIAE_i_3 + offset) % HIAE_STATE_NUM;
    const uint32_t idxI13 = (HIAE_i_13 + offset) % HIAE_STATE_NUM;
    const uint32_t idxIn = offset % HIAE_STATE_NUM;

    DATA128b t;
    t = AESEMC(state[idxP0], state[idxP1]);
    t = SIMD_XOR(t, xi); // t  = AESL(S0 ^ S1) ^ xi
    state[idxIn] = SIMD_XOR(t, AESL(state[idxP13])); // S0 = AESL(S13) ^ t
    state[idxI3] = SIMD_XOR(state[idxI3], xi); // S3 = S3 ^ xi
    state[idxI13] = SIMD_XOR(state[idxI13], xi); // S13 = S13 ^ xi
}

/* §3.4.2.2 The UpdateEnc Function (ARMv8 mapping). */
__attribute__((always_inline)) static inline DATA128b HIAE_State_UpdateEnc(DATA128b *state, DATA128b mi,
                                                                           const uint32_t offset)
{
    const uint32_t idxP0 = (HIAE_P_0 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP1 = (HIAE_P_1 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP13 = (HIAE_P_13 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP9 = (HIAE_P_9 + offset) % HIAE_STATE_NUM;
    const uint32_t idxI3 = (HIAE_i_3 + offset) % HIAE_STATE_NUM;
    const uint32_t idxI13 = (HIAE_i_13 + offset) % HIAE_STATE_NUM;
    const uint32_t idxIn = offset % HIAE_STATE_NUM;

    DATA128b t;
    t = AESEMC(state[idxP0], state[idxP1]);
    t = SIMD_XOR(t, mi); // t = AESL(S0 ^ S1) ^ mi
    state[idxIn] = SIMD_XOR(t, AESL(state[idxP13])); // S0 = AESL(S13) ^ t
    t = SIMD_XOR(t, state[idxP9]); // ci = t ^ S9
    state[idxI3] = SIMD_XOR(state[idxI3], mi); // S3 = S3 ^ mi
    state[idxI13] = SIMD_XOR(state[idxI13], mi); // S13 = S13 ^ mi
    return t;
}

/* §3.4.2.3 The UpdateDec Function (ARMv8 mapping). */
__attribute__((always_inline)) static inline DATA128b HIAE_State_UpdateDec(DATA128b *state, DATA128b ci,
                                                                           const uint32_t offset)
{
    const uint32_t idxP0 = (HIAE_P_0 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP1 = (HIAE_P_1 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP13 = (HIAE_P_13 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP9 = (HIAE_P_9 + offset) % HIAE_STATE_NUM;
    const uint32_t idxI3 = (HIAE_i_3 + offset) % HIAE_STATE_NUM;
    const uint32_t idxI13 = (HIAE_i_13 + offset) % HIAE_STATE_NUM;
    const uint32_t idxIn = offset % HIAE_STATE_NUM;

    DATA128b t;
    DATA128b mi;
    mi = AESEMC(state[idxP0], state[idxP1]);
    t = SIMD_XOR(state[idxP9], ci); // t = ci ^ S9
    state[idxIn] = SIMD_XOR(t, AESL(state[idxP13])); // S0 = AESL(S13) ^ t
    mi = SIMD_XOR(mi, t); // mi = AESL(S0 ^ S1) ^ t
    state[idxI3] = SIMD_XOR(state[idxI3], mi); // S3 = S3 ^ mi
    state[idxI13] = SIMD_XOR(state[idxI13], mi); // S13 = S13 ^ mi
    return mi;
}

/* §3.5.5 DecPartial helper (ARMv8 mapping). */
__attribute__((always_inline)) static inline DATA128b HIAE_State_UpdateKeystream(DATA128b *state, DATA128b ci,
                                                                                 const uint32_t offset)
{
    const uint32_t idxP0 = (HIAE_P_0 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP1 = (HIAE_P_1 + offset) % HIAE_STATE_NUM;
    const uint32_t idxP9 = (HIAE_P_9 + offset) % HIAE_STATE_NUM;

    DATA128b ks;
    ks = AESEMC(state[idxP0], state[idxP1]);
    ks = SIMD_XOR(ks, ci);
    ks = SIMD_XOR(ks, state[idxP9]); // ks = AESL(S0 ^ S1) ^ ZeroPad(cn) ^ S9
    return ks;
}

#else
#warning "HiAE currently supports only x86_64+AES-NI and ARMv8+Crypto+NEON."
#endif

/* §3.4.1 The State Rotation Function (Rol). */
__attribute__((always_inline)) static inline void HIAE_State_Rotation(DATA128b *state)
{
    DATA128b tmp = state[0];
    state[0] = state[1];
    state[1] = state[2];
    state[2] = state[3];
    state[3] = state[4];
    state[4] = state[5];
    state[5] = state[6];
    state[6] = state[7];
    state[7] = state[8];
    state[8] = state[9];
    state[9] = state[10];
    state[10] = state[11];
    state[11] = state[12];
    state[12] = state[13];
    state[13] = state[14];
    state[14] = state[15];
    state[15] = tmp;
}

/* §3.4.2.4 The Diffuse Function: Repeat(32, Update(x)). */
__attribute__((always_inline)) static inline void HIAE_State_Diffuse(DATA128b *state, DATA128b x)
{
    HIAE_State_Update(state, x, 0);
    HIAE_State_Update(state, x, 1);
    HIAE_State_Update(state, x, 2);
    HIAE_State_Update(state, x, 3);
    HIAE_State_Update(state, x, 4);
    HIAE_State_Update(state, x, 5);
    HIAE_State_Update(state, x, 6);
    HIAE_State_Update(state, x, 7);
    HIAE_State_Update(state, x, 8);
    HIAE_State_Update(state, x, 9);
    HIAE_State_Update(state, x, 10);
    HIAE_State_Update(state, x, 11);
    HIAE_State_Update(state, x, 12);
    HIAE_State_Update(state, x, 13);
    HIAE_State_Update(state, x, 14);
    HIAE_State_Update(state, x, 15);
    HIAE_State_Update(state, x, 0);
    HIAE_State_Update(state, x, 1);
    HIAE_State_Update(state, x, 2);
    HIAE_State_Update(state, x, 3);
    HIAE_State_Update(state, x, 4);
    HIAE_State_Update(state, x, 5);
    HIAE_State_Update(state, x, 6);
    HIAE_State_Update(state, x, 7);
    HIAE_State_Update(state, x, 8);
    HIAE_State_Update(state, x, 9);
    HIAE_State_Update(state, x, 10);
    HIAE_State_Update(state, x, 11);
    HIAE_State_Update(state, x, 12);
    HIAE_State_Update(state, x, 13);
    HIAE_State_Update(state, x, 14);
    HIAE_State_Update(state, x, 15);
}

/* §3.5.2 The Absorb Function: absorb one 16-block (256-byte) chunk. */
static inline void HIAE_Absorb(DATA128b *state, const uint8_t *ai)
{
    DATA128b m[16];

    m[0] = SIMD_LOAD(ai + HIAE_BLOCK_SIZE * 0);
    m[1] = SIMD_LOAD(ai + HIAE_BLOCK_SIZE * 1);
    m[2] = SIMD_LOAD(ai + HIAE_BLOCK_SIZE * 2);
    m[3] = SIMD_LOAD(ai + HIAE_BLOCK_SIZE * 3);
    m[4] = SIMD_LOAD(ai + HIAE_BLOCK_SIZE * 4);
    m[5] = SIMD_LOAD(ai + HIAE_BLOCK_SIZE * 5);
    m[6] = SIMD_LOAD(ai + HIAE_BLOCK_SIZE * 6);
    m[7] = SIMD_LOAD(ai + HIAE_BLOCK_SIZE * 7);
    m[8] = SIMD_LOAD(ai + HIAE_BLOCK_SIZE * 8);
    m[9] = SIMD_LOAD(ai + HIAE_BLOCK_SIZE * 9);
    m[10] = SIMD_LOAD(ai + HIAE_BLOCK_SIZE * 10);
    m[11] = SIMD_LOAD(ai + HIAE_BLOCK_SIZE * 11);
    m[12] = SIMD_LOAD(ai + HIAE_BLOCK_SIZE * 12);
    m[13] = SIMD_LOAD(ai + HIAE_BLOCK_SIZE * 13);
    m[14] = SIMD_LOAD(ai + HIAE_BLOCK_SIZE * 14);
    m[15] = SIMD_LOAD(ai + HIAE_BLOCK_SIZE * 15);
    HIAE_State_Update(state, m[0], 0);
    HIAE_State_Update(state, m[1], 1);
    HIAE_State_Update(state, m[2], 2);
    HIAE_State_Update(state, m[3], 3);
    HIAE_State_Update(state, m[4], 4);
    HIAE_State_Update(state, m[5], 5);
    HIAE_State_Update(state, m[6], 6);
    HIAE_State_Update(state, m[7], 7);
    HIAE_State_Update(state, m[8], 8);
    HIAE_State_Update(state, m[9], 9);
    HIAE_State_Update(state, m[10], 10);
    HIAE_State_Update(state, m[11], 11);
    HIAE_State_Update(state, m[12], 12);
    HIAE_State_Update(state, m[13], 13);
    HIAE_State_Update(state, m[14], 14);
    HIAE_State_Update(state, m[15], 15);
}

/* §3.5.3 The Enc Function: encrypt one 16-block (256-byte) chunk. */
static inline void HIAE_Enc(DATA128b *state, uint8_t *ci, const uint8_t *mi)
{
    DATA128b m[16];
    DATA128b c[16];

    m[0] = SIMD_LOAD(mi + HIAE_BLOCK_SIZE * 0);
    m[1] = SIMD_LOAD(mi + HIAE_BLOCK_SIZE * 1);
    m[2] = SIMD_LOAD(mi + HIAE_BLOCK_SIZE * 2);
    m[3] = SIMD_LOAD(mi + HIAE_BLOCK_SIZE * 3);
    m[4] = SIMD_LOAD(mi + HIAE_BLOCK_SIZE * 4);
    m[5] = SIMD_LOAD(mi + HIAE_BLOCK_SIZE * 5);
    m[6] = SIMD_LOAD(mi + HIAE_BLOCK_SIZE * 6);
    m[7] = SIMD_LOAD(mi + HIAE_BLOCK_SIZE * 7);
    m[8] = SIMD_LOAD(mi + HIAE_BLOCK_SIZE * 8);
    m[9] = SIMD_LOAD(mi + HIAE_BLOCK_SIZE * 9);
    m[10] = SIMD_LOAD(mi + HIAE_BLOCK_SIZE * 10);
    m[11] = SIMD_LOAD(mi + HIAE_BLOCK_SIZE * 11);
    m[12] = SIMD_LOAD(mi + HIAE_BLOCK_SIZE * 12);
    m[13] = SIMD_LOAD(mi + HIAE_BLOCK_SIZE * 13);
    m[14] = SIMD_LOAD(mi + HIAE_BLOCK_SIZE * 14);
    m[15] = SIMD_LOAD(mi + HIAE_BLOCK_SIZE * 15);
    c[0] = HIAE_State_UpdateEnc(state, m[0], 0);
    c[1] = HIAE_State_UpdateEnc(state, m[1], 1);
    c[2] = HIAE_State_UpdateEnc(state, m[2], 2);
    c[3] = HIAE_State_UpdateEnc(state, m[3], 3);
    c[4] = HIAE_State_UpdateEnc(state, m[4], 4);
    c[5] = HIAE_State_UpdateEnc(state, m[5], 5);
    c[6] = HIAE_State_UpdateEnc(state, m[6], 6);
    c[7] = HIAE_State_UpdateEnc(state, m[7], 7);
    c[8] = HIAE_State_UpdateEnc(state, m[8], 8);
    c[9] = HIAE_State_UpdateEnc(state, m[9], 9);
    c[10] = HIAE_State_UpdateEnc(state, m[10], 10);
    c[11] = HIAE_State_UpdateEnc(state, m[11], 11);
    c[12] = HIAE_State_UpdateEnc(state, m[12], 12);
    c[13] = HIAE_State_UpdateEnc(state, m[13], 13);
    c[14] = HIAE_State_UpdateEnc(state, m[14], 14);
    c[15] = HIAE_State_UpdateEnc(state, m[15], 15);
    SIMD_STORE(ci + HIAE_BLOCK_SIZE * 0, c[0]);
    SIMD_STORE(ci + HIAE_BLOCK_SIZE * 1, c[1]);
    SIMD_STORE(ci + HIAE_BLOCK_SIZE * 2, c[2]);
    SIMD_STORE(ci + HIAE_BLOCK_SIZE * 3, c[3]);
    SIMD_STORE(ci + HIAE_BLOCK_SIZE * 4, c[4]);
    SIMD_STORE(ci + HIAE_BLOCK_SIZE * 5, c[5]);
    SIMD_STORE(ci + HIAE_BLOCK_SIZE * 6, c[6]);
    SIMD_STORE(ci + HIAE_BLOCK_SIZE * 7, c[7]);
    SIMD_STORE(ci + HIAE_BLOCK_SIZE * 8, c[8]);
    SIMD_STORE(ci + HIAE_BLOCK_SIZE * 9, c[9]);
    SIMD_STORE(ci + HIAE_BLOCK_SIZE * 10, c[10]);
    SIMD_STORE(ci + HIAE_BLOCK_SIZE * 11, c[11]);
    SIMD_STORE(ci + HIAE_BLOCK_SIZE * 12, c[12]);
    SIMD_STORE(ci + HIAE_BLOCK_SIZE * 13, c[13]);
    SIMD_STORE(ci + HIAE_BLOCK_SIZE * 14, c[14]);
    SIMD_STORE(ci + HIAE_BLOCK_SIZE * 15, c[15]);
}

/* §3.5.4 The Dec Function: decrypt one 16-block (256-byte) chunk. */
static inline void HIAE_Dec(DATA128b *state, uint8_t *mi, const uint8_t *ci)
{
    DATA128b m[16];
    DATA128b c[16];

    c[0] = SIMD_LOAD(ci + HIAE_BLOCK_SIZE * 0);
    c[1] = SIMD_LOAD(ci + HIAE_BLOCK_SIZE * 1);
    c[2] = SIMD_LOAD(ci + HIAE_BLOCK_SIZE * 2);
    c[3] = SIMD_LOAD(ci + HIAE_BLOCK_SIZE * 3);
    c[4] = SIMD_LOAD(ci + HIAE_BLOCK_SIZE * 4);
    c[5] = SIMD_LOAD(ci + HIAE_BLOCK_SIZE * 5);
    c[6] = SIMD_LOAD(ci + HIAE_BLOCK_SIZE * 6);
    c[7] = SIMD_LOAD(ci + HIAE_BLOCK_SIZE * 7);
    c[8] = SIMD_LOAD(ci + HIAE_BLOCK_SIZE * 8);
    c[9] = SIMD_LOAD(ci + HIAE_BLOCK_SIZE * 9);
    c[10] = SIMD_LOAD(ci + HIAE_BLOCK_SIZE * 10);
    c[11] = SIMD_LOAD(ci + HIAE_BLOCK_SIZE * 11);
    c[12] = SIMD_LOAD(ci + HIAE_BLOCK_SIZE * 12);
    c[13] = SIMD_LOAD(ci + HIAE_BLOCK_SIZE * 13);
    c[14] = SIMD_LOAD(ci + HIAE_BLOCK_SIZE * 14);
    c[15] = SIMD_LOAD(ci + HIAE_BLOCK_SIZE * 15);
    m[0] = HIAE_State_UpdateDec(state, c[0], 0);
    m[1] = HIAE_State_UpdateDec(state, c[1], 1);
    m[2] = HIAE_State_UpdateDec(state, c[2], 2);
    m[3] = HIAE_State_UpdateDec(state, c[3], 3);
    m[4] = HIAE_State_UpdateDec(state, c[4], 4);
    m[5] = HIAE_State_UpdateDec(state, c[5], 5);
    m[6] = HIAE_State_UpdateDec(state, c[6], 6);
    m[7] = HIAE_State_UpdateDec(state, c[7], 7);
    m[8] = HIAE_State_UpdateDec(state, c[8], 8);
    m[9] = HIAE_State_UpdateDec(state, c[9], 9);
    m[10] = HIAE_State_UpdateDec(state, c[10], 10);
    m[11] = HIAE_State_UpdateDec(state, c[11], 11);
    m[12] = HIAE_State_UpdateDec(state, c[12], 12);
    m[13] = HIAE_State_UpdateDec(state, c[13], 13);
    m[14] = HIAE_State_UpdateDec(state, c[14], 14);
    m[15] = HIAE_State_UpdateDec(state, c[15], 15);
    SIMD_STORE(mi + HIAE_BLOCK_SIZE * 0, m[0]);
    SIMD_STORE(mi + HIAE_BLOCK_SIZE * 1, m[1]);
    SIMD_STORE(mi + HIAE_BLOCK_SIZE * 2, m[2]);
    SIMD_STORE(mi + HIAE_BLOCK_SIZE * 3, m[3]);
    SIMD_STORE(mi + HIAE_BLOCK_SIZE * 4, m[4]);
    SIMD_STORE(mi + HIAE_BLOCK_SIZE * 5, m[5]);
    SIMD_STORE(mi + HIAE_BLOCK_SIZE * 6, m[6]);
    SIMD_STORE(mi + HIAE_BLOCK_SIZE * 7, m[7]);
    SIMD_STORE(mi + HIAE_BLOCK_SIZE * 8, m[8]);
    SIMD_STORE(mi + HIAE_BLOCK_SIZE * 9, m[9]);
    SIMD_STORE(mi + HIAE_BLOCK_SIZE * 10, m[10]);
    SIMD_STORE(mi + HIAE_BLOCK_SIZE * 11, m[11]);
    SIMD_STORE(mi + HIAE_BLOCK_SIZE * 12, m[12]);
    SIMD_STORE(mi + HIAE_BLOCK_SIZE * 13, m[13]);
    SIMD_STORE(mi + HIAE_BLOCK_SIZE * 14, m[14]);
    SIMD_STORE(mi + HIAE_BLOCK_SIZE * 15, m[15]);
}

/* ---- Internal state interface implementations (not for external direct use) ---- */

/* §3.5.1 The Init Function. Internal state API. */
void HIAE_Init(DATA128b *state, const uint8_t *key, const uint8_t *iv)
{
    if (state == NULL || key == NULL || iv == NULL) {
        return;
    }
    DATA128b c0 = SIMD_LOAD(CONST0);
    DATA128b c1 = SIMD_LOAD(CONST1);
    DATA128b k0 = SIMD_LOAD(key);
    DATA128b k1 = SIMD_LOAD(key + 16);
    DATA128b nonce = SIMD_LOAD(iv);
    DATA128b zero = SIMD_ZERO_128();

    state[0] = c0;
    state[1] = k1;
    state[2] = nonce;
    state[3] = c0;
    state[4] = zero;
    state[5] = SIMD_XOR(nonce, k0);
    state[6] = zero;
    state[7] = c1;
    state[8] = SIMD_XOR(nonce, k1);
    state[9] = zero;
    state[10] = k1;
    state[11] = c0;
    state[12] = c1;
    state[13] = k1;
    state[14] = zero;
    state[15] = SIMD_XOR(c0, c1);

    HIAE_State_Diffuse(state, c0);
    state[9] = SIMD_XOR(state[9], k0);
    state[13] = SIMD_XOR(state[13], k1);
}

#define STORE_UINT64_LE(v, p, i)             \
    do {                                     \
        (p)[(i) + 7] = (uint8_t)((v) >> 56); \
        (p)[(i) + 6] = (uint8_t)((v) >> 48); \
        (p)[(i) + 5] = (uint8_t)((v) >> 40); \
        (p)[(i) + 4] = (uint8_t)((v) >> 32); \
        (p)[(i) + 3] = (uint8_t)((v) >> 24); \
        (p)[(i) + 2] = (uint8_t)((v) >> 16); \
        (p)[(i) + 1] = (uint8_t)((v) >> 8);  \
        (p)[(i) + 0] = (uint8_t)((v) >> 0);  \
    } while (0)

/* §3.5.6 The Finalize Function. Internal state API: Diffuse(LE64(ad_bits)||LE64(msg_bits)). */
void HIAE_Finalize(DATA128b *state, uint64_t adLen, uint64_t plainLen, uint8_t *tag)
{
    if (state == NULL || tag == NULL) {
        return;
    }
    uint8_t lens[HIAE_BLOCK_SIZE];
    uint64_t adBits;
    uint64_t msgBits;
    DATA128b temp;
    uint32_t i;

    /* t = (LE64(adLenBits) || LE64(msgLenBits)) */
    adBits = adLen << 3u;
    msgBits = plainLen << 3u;
    STORE_UINT64_LE(adBits, lens, 0);
    STORE_UINT64_LE(msgBits, lens, 8);
    temp = SIMD_LOAD(lens);

    HIAE_State_Diffuse(state, temp);

    temp = state[0];
    for (i = 1; i < HIAE_STATE_NUM; i++) {
        temp = SIMD_XOR(temp, state[i]);
    }
    SIMD_STORE(tag, temp);
}

/* §3.5.2 The Absorb Function over byte stream. Internal state API. */
void HIAE_Stream_ProcAD(DATA128b *state, const uint8_t *ad, uint32_t len)
{
    if (state == NULL || len == 0 || ad == NULL) {
        return;
    }
    uint32_t i = 0;
    uint32_t rest = len % HIAE_UNROLL_BLOCK_SIZE;
    uint32_t prefix = len - rest;
    for (; i < prefix; i += HIAE_UNROLL_BLOCK_SIZE) {
        HIAE_Absorb(state, ad + i);
    }

    DATA128b m;
    uint32_t pad = len % HIAE_BLOCK_SIZE;
    len -= pad;
    for (; i < len; i += HIAE_BLOCK_SIZE) {
        m = SIMD_LOAD(ad + i);
        HIAE_State_Update(state, m, 0);
        HIAE_State_Rotation(state);
    }
    if (pad != 0) {
        uint8_t buf[HIAE_BLOCK_SIZE];

        /* The final AD fragment is zero-padded to one full block before absorb. */
        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, ad + len, pad);
        m = SIMD_LOAD(buf);
        HIAE_State_Update(state, m, 0);
        HIAE_State_Rotation(state);
    }
}

/* §3.5.3 The Enc Function over byte stream. Internal state API. */
void HIAE_Stream_Encrypt(DATA128b *state, uint8_t *dst, const uint8_t *src, uint32_t size)
{
    if (state == NULL || size == 0 || dst == NULL || src == NULL) {
        return;
    }
    uint32_t rest = size % HIAE_UNROLL_BLOCK_SIZE;
    uint32_t prefix = size - rest;
    for (uint32_t i = 0; i < prefix; i += HIAE_UNROLL_BLOCK_SIZE) {
        HIAE_Enc(state, dst + i, src + i);
    }

    DATA128b m;
    DATA128b c;
    uint32_t pad = rest % HIAE_BLOCK_SIZE;
    rest -= pad;
    for (uint32_t i = 0; i < rest; i += HIAE_BLOCK_SIZE) {
        m = SIMD_LOAD(src + i + prefix);
        c = HIAE_State_UpdateEnc(state, m, 0);
        HIAE_State_Rotation(state);
        SIMD_STORE(dst + i + prefix, c);
    }
    if (pad != 0) {
        uint8_t buf[HIAE_BLOCK_SIZE];

        /* Tail plaintext is padded to one block; only the leading pad bytes are emitted. */
        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, src + rest + prefix, pad);
        m = SIMD_LOAD(buf);
        c = HIAE_State_UpdateEnc(state, m, 0);
        HIAE_State_Rotation(state);
        SIMD_STORE(buf, c);
        memcpy(dst + rest + prefix, buf, pad);
    }
}

/* §3.5.4/§3.5.5 The Dec/DecPartial flow over byte stream. Internal state API. */
void HIAE_Stream_Decrypt(DATA128b *state, uint8_t *dst, const uint8_t *src, uint32_t size)
{
    if (state == NULL || size == 0 || dst == NULL || src == NULL) {
        return;
    }
    uint32_t rest = size % HIAE_UNROLL_BLOCK_SIZE;
    uint32_t prefix = size - rest;
    for (uint32_t i = 0; i < prefix; i += HIAE_UNROLL_BLOCK_SIZE) {
        HIAE_Dec(state, dst + i, src + i);
    }

    DATA128b m;
    DATA128b c;
    uint32_t pad = rest % HIAE_BLOCK_SIZE;
    rest -= pad;
    for (uint32_t i = 0; i < rest; i += HIAE_BLOCK_SIZE) {
        c = SIMD_LOAD(src + i + prefix);
        m = HIAE_State_UpdateDec(state, c, 0);
        HIAE_State_Rotation(state);
        SIMD_STORE(dst + i + prefix, m);
    }
    if (pad != 0) {
        uint8_t cn[HIAE_BLOCK_SIZE];
        uint8_t ci[HIAE_BLOCK_SIZE];
        uint8_t mn[HIAE_BLOCK_SIZE];
        uint8_t ksTail[HIAE_BLOCK_SIZE];
        DATA128b ks;
        DATA128b ciBlock;
        DATA128b miBlock;

        /*
         * Follow draft-02 DecPartial(cn):
         * 1) ks = AESL(S0 ^ S1) ^ ZeroPad(cn) ^ S9
         * 2) ci = cn || Tail(ks, 128 - |cn|)
         * 3) mi = UpdateDec(ci)
         * 4) mn = Truncate(mi, |cn|)
         */
        memset(cn, 0x00, sizeof(cn));
        memcpy(cn, src + rest + prefix, pad);
        ks = HIAE_State_UpdateKeystream(state, SIMD_LOAD(cn), 0);
        SIMD_STORE(ksTail, ks);

        memcpy(ci, cn, pad);
        memcpy(ci + pad, ksTail + pad, HIAE_BLOCK_SIZE - pad);
        ciBlock = SIMD_LOAD(ci);
        miBlock = HIAE_State_UpdateDec(state, ciBlock, 0);
        HIAE_State_Rotation(state);
        SIMD_STORE(mn, miBlock);
        memcpy(dst + rest + prefix, mn, pad);
    }
}

/* ---- Public low-level API implementations ---- */

/* §3.2 Authenticated Encryption: Encrypt(msg, ad, key, nonce). */
int32_t PQCP_HIAE_AEAD_Encrypt(uint8_t *key, uint32_t keyLen, uint8_t *nonce, uint32_t nonceLen, uint8_t *msg,
    uint32_t msgLen, uint8_t *ad, uint32_t adLen, uint8_t *cipher, uint32_t cipherLen, uint8_t *tag, uint32_t tagLen)
{
    DATA128b state[HIAE_STATE_NUM];
    if (key == NULL || nonce == NULL || tag == NULL) {
        return PQCP_INVALID_ARG;
    }
    if (keyLen != HIAE_KEY_LEN || nonceLen != HIAE_IV_LEN || tagLen != HIAE_TAG_LEN) {
        return PQCP_INVALID_ARG;
    }
    if (cipherLen < msgLen) {
        return PQCP_INVALID_ARG;
    }
    if (msgLen > 0u && (msg == NULL || cipher == NULL)) {
        return PQCP_INVALID_ARG;
    }
    if (ad == NULL && adLen != 0u) {
        return PQCP_INVALID_ARG;
    }

    HIAE_Init(state, key, nonce);
    HIAE_Stream_ProcAD(state, ad, adLen);
    HIAE_Stream_Encrypt(state, cipher, msg, msgLen);
    HIAE_Finalize(state, adLen, msgLen, tag);
    return PQCP_SUCCESS;
}

/* §3.3 Authenticated Decryption: Decrypt(ct, tag, ad, key, nonce). */
int32_t PQCP_HIAE_AEAD_Decrypt(uint8_t *key, uint32_t keyLen, uint8_t *nonce, uint32_t nonceLen, uint8_t *msg,
    uint32_t msgLen, uint8_t *ad, uint32_t adLen, uint8_t *cipher, uint32_t cipherLen, uint8_t *tag, uint32_t tagLen)
{
    DATA128b state[HIAE_STATE_NUM];
    if (key == NULL || nonce == NULL || tag == NULL) {
        return PQCP_INVALID_ARG;
    }
    if (keyLen != HIAE_KEY_LEN || nonceLen != HIAE_IV_LEN || tagLen != HIAE_TAG_LEN) {
        return PQCP_INVALID_ARG;
    }
    if (cipherLen != msgLen) {
        return PQCP_INVALID_ARG;
    }
    if (msgLen > 0u && (msg == NULL || cipher == NULL)) {
        return PQCP_INVALID_ARG;
    }
    if (ad == NULL && adLen != 0u) {
        return PQCP_INVALID_ARG;
    }

    HIAE_Init(state, key, nonce);
    HIAE_Stream_ProcAD(state, ad, adLen);
    HIAE_Stream_Decrypt(state, msg, cipher, msgLen);
    HIAE_Finalize(state, adLen, msgLen, tag);
    return PQCP_SUCCESS;
}

/* §5.2 HiAE as a Message Authentication Code: Mac(data, key, nonce). */
int32_t PQCP_HIAE_Mac(uint8_t *key, uint32_t keyLen, uint8_t *iv, uint32_t ivLen, uint8_t *msg, uint32_t msgLen,
    uint8_t *tag, uint32_t tagLen)
{
    DATA128b state[HIAE_STATE_NUM];
    if (key == NULL || iv == NULL || tag == NULL) {
        return PQCP_INVALID_ARG;
    }
    if (keyLen != HIAE_KEY_LEN || ivLen != HIAE_IV_LEN || tagLen != HIAE_TAG_LEN) {
        return PQCP_INVALID_ARG;
    }
    if (msgLen > 0u && msg == NULL) {
        return PQCP_INVALID_ARG;
    }

    HIAE_Init(state, key, iv);
    HIAE_Stream_ProcAD(state, msg, msgLen);
    HIAE_Finalize(state, msgLen, 0u, tag);
    return PQCP_SUCCESS;
}

#endif
