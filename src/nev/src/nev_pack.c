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
#include "nev_qdispatch.h"

// Packing / message codecs: byte-exact ports of the reference pack.c. The
// per-q codecs are instantiated with compile-time constants in
// nev_poly_q{769,1409,3329}.c (template: nev_poly_core.inc); this file
// dispatches on info->q. Packed sizes (info->polyBytes):
//   q = 769:  5 coefficients into 6 bytes (base-97 high parts) plus an n-dependent tail
//   q = 1409: 16 coefficients into 21 bytes (pairs combined as x0 + 1409 * x1, 21 bits each)
//   q = 3329: 2 coefficients into 3 bytes (12 bits per coefficient)

void NEV_PolyToBytes(uint8_t *r, const NEV_Poly *a, const CRYPT_NevInfo *info)
{
    if (info->q == 769) {
        NEV_PolyToBytes_Q769(r, a, info->n);
    } else if (info->q == 1409) {
        NEV_PolyToBytes_Q1409(r, a, info->n);
    } else { // q == 3329
        NEV_PolyToBytes_Q3329(r, a, info->n);
    }
}

void NEV_PolyFromBytes(NEV_Poly *r, const uint8_t *a, const CRYPT_NevInfo *info)
{
    if (info->q == 769) {
        NEV_PolyFromBytes_Q769(r, a, info->n);
    } else if (info->q == 1409) {
        NEV_PolyFromBytes_Q1409(r, a, info->n);
    } else { // q == 3329
        NEV_PolyFromBytes_Q3329(r, a, info->n);
    }
}

// 8-bit per-coefficient ciphertext compression, COMPRESS (q = 769) sets only:
// c[i] = round(coeffs[i] * 256 / 769) mod 256, computed as (coeffs[i] * 341 + 469) >> 10.
// No q-derived constants beyond the literals, so it lives here; the n
// dispatch (n is 512, 1024 or 2048 for every set) gives the loop a constant
// trip count so it vectorizes like the reference's compile-time PARAM_N.
static inline void PolyCompressN(uint8_t *c, const NEV_Poly *x, uint32_t n)
{
    uint32_t i;
    uint32_t t;

    for (i = 0; i < n; i++) {
        t = ((uint32_t)x->coeffs[i] * 341U + 469U) >> 10;
        c[i] = (uint8_t)(t & 0xff);
    }
}

void NEV_PolyCompress(uint8_t *c, const NEV_Poly *x, const CRYPT_NevInfo *info)
{
    if (info->n == 512) {
        PolyCompressN(c, x, 512);
    } else if (info->n == 1024) {
        PolyCompressN(c, x, 1024);
    } else { // n == 2048
        PolyCompressN(c, x, 2048);
    }
}

void NEV_PolyMontCompress(uint8_t *c, NEV_Poly *x, const CRYPT_NevInfo *info)
{
    NEV_PolyGetMontgomeryCaddq(x, info);
    NEV_PolyCompress(c, x, info);
}

void NEV_PolyDecompress(NEV_Poly *x, const uint8_t *c, const CRYPT_NevInfo *info)
{
    if (info->q == 769) {
        NEV_PolyDecompress_Q769(x, c, info->n);
    } else if (info->q == 1409) {
        NEV_PolyDecompress_Q1409(x, c, info->n);
    } else { // q == 3329
        NEV_PolyDecompress_Q3329(x, c, info->n);
    }
}

// Each message bit is recovered from its 4 carrier coefficients (see
// nev_poly_core.inc FlipAbs / NEV_PolyToMsg).
void NEV_PolyToMsg(uint8_t *msg, const NEV_Poly *r, const CRYPT_NevInfo *info)
{
    if (info->q == 769) {
        NEV_PolyToMsg_Q769(msg, r, info->seedLen);
    } else if (info->q == 1409) {
        NEV_PolyToMsg_Q1409(msg, r, info->seedLen);
    } else { // q == 3329
        NEV_PolyToMsg_Q3329(msg, r, info->seedLen);
    }
}

#endif // HITLS_CRYPTO_NEV
