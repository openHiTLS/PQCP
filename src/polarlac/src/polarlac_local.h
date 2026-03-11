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

#ifndef CRYPT_LAC2_LOCAL_H
#define CRYPT_LAC2_LOCAL_H
#include <stdint.h>
#include "pqcp_types.h"
#include "pqcp_err.h"

#define Q       251
#define BIG_Q   257024 //1024*Q
#define q_half  126
#define neg_one 250
#define HASHLEN 32

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

#define POLAR_LAC_128LIGHT_SECBITS 112
#define POLAR_LAC_128_SECBITS      128
#define POLAR_LAC_256_SECBITS      256

#define NTTQ        18433
#define Q_half      9217
#define Q_mod_q     110
#define neg_Q_mod_q 141 // -Q mod q + q = -110+251=141
#define Q_sub_q     18182 // NTTQ-q
#define BITLEN_Q    15
#define INVERSE_q   2611
#define B_q         25
#define Beta        65536
#define INVERSE_Q   -18431
#define B_Q         10237

#define RETURN_RET_IF(FUNC, RET) \
    do {                         \
        RET = FUNC;              \
        if (RET != 0) {          \
            return RET;          \
        }                        \
    } while (0)

typedef struct {
    uint32_t dimN;
    uint32_t seedLen;
    uint32_t msgLen;
    uint32_t c2VecNum;
    uint32_t numOne;
    uint32_t sampleLen;
    uint32_t skLen;
    uint32_t pkLen;
    uint32_t ctLen;
    uint32_t sharedLen;
    uint32_t bits;
    uint32_t secBits;
} CRYPT_Lac2Info;

typedef struct CryptPolarLacCtx {
    int32_t algId;
    const CRYPT_Lac2Info *info;
    uint8_t *sk;
    uint8_t *pk;
    void *libCtx;
} CRYPT_POLAR_LAC_Ctx;

// Returns r = a * β^(-1) mod q, where 0 < r < q, mapped to standard representation
static inline int32_t MontgomeryMapFull(int32_t a)
{
    int32_t t;
    int32_t m;
    int32_t r;
    m = a * INVERSE_Q;
    m = m & ((1 << 16) - 1); // m mod β
    t = m * NTTQ;
    r = a - t;
    r >>= 16;
    return r + ((r >> 15) & NTTQ);
}

// Polar encode and decode functions
void PQCP_POLAR_LAC_EncodePolar(uint8_t *u, int32_t algId);
void PQCP_POLAR_LAC_DecodePolar(uint8_t *mCap, const float *llr, int32_t algId);

// Poly functions
// PQCP_POLAR_LAC_PolyMul  b=[as]
void PQCP_POLAR_LAC_PolyMul(const uint8_t *a, const uint8_t *s, uint8_t *b, uint32_t vecNum, int32_t algId);
// PQCP_POLAR_LAC_PolyAff  b=as+e
void PQCP_POLAR_LAC_PolyAff(const uint8_t *a, const uint8_t *s, uint8_t *e, uint8_t *b, uint32_t vecNum, int32_t algId);
int32_t PQCP_POLAR_LAC_PolyCompress(const uint8_t *in, uint8_t *out, const uint32_t vecNum, const uint32_t bits);
int32_t PQCP_POLAR_LAC_PolyDecompress(const uint8_t *in, uint8_t *out, const uint32_t vecNum, const uint32_t bits);

// NTT functions
void PQCP_PQCP_POLAR_LAC_NttLazy1024(int16_t *a);
void PQCP_PQCP_POLAR_LAC_InttLazy1024(int16_t *a);
void PQCP_POLAR_LAC_NttLazy(int16_t *a);
void PQCP_POLAR_LAC_InttLazy(int16_t *a);

// KEM functions
int32_t PQCP_POLAR_LAC_KeyGenInternal(CRYPT_POLAR_LAC_Ctx *ctx);
int32_t PQCP_POLAR_LAC_EncapsInternal(const CRYPT_POLAR_LAC_Ctx *ctx, uint8_t *ct, uint8_t *ss);
int32_t PQCP_POLAR_LAC_DeapsInternal(const CRYPT_POLAR_LAC_Ctx *ctx, uint8_t *ss, const uint8_t *ct);

// PKE functions
int32_t PQCP_POLAR_LAC_PkeEncrypt(const CRYPT_POLAR_LAC_Ctx *ctx, const uint8_t *m, uint8_t *c,
                            uint32_t *clen, uint8_t *seed);
int32_t PQCP_POLAR_LAC_PkeDecrypt(const CRYPT_POLAR_LAC_Ctx *ctx, const uint8_t *c, uint32_t clen, uint8_t *m,
                            uint32_t *mlen);
int32_t PQCP_POLAR_LAC_PkeKeyGen(CRYPT_POLAR_LAC_Ctx *ctx, uint8_t *seed);

// Sampling functions
int32_t PQCP_POLAR_LAC_PseudoRandomBytes(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen);
int32_t PQCP_POLAR_LAC_SamplePolyA(void *libCtx, uint8_t q, const uint8_t *in, uint32_t inLen, uint8_t *out,
                              uint32_t outLen);
int32_t PQCP_POLAR_LAC_SampleSparseTernaryVector(void *libCtx, uint8_t q, const uint8_t *in, uint32_t inLen, uint8_t *e,
                                            uint32_t eLen, int32_t algId);
#endif