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

#ifndef MCELIECE_KEYGEN_H
#define MCELIECE_KEYGEN_H

#include "mceliece_types.h"
#include "mceliece_gf.h"
#include "mceliece_poly.h"
#include "mceliece_matrix_ops.h"
#include "mceliece_shake.h"
#include "mceliece_genpoly.h"
#include "mceliece_kem.h"
#include "mceliece_controlbits.h"
#include "bsl_sal.h"

#ifdef __cplusplus
extern "C" {
#endif

// Core key generation functions
CRYPT_ERROR SeededKeyGen(const uint8_t *delta, CMPublicKey *pk, CMPrivateKey *sk, const McelieceParams *params);
CRYPT_ERROR SeededKeyGenSemi(const uint8_t *delta, CMPublicKey *pk, CMPrivateKey *sk, const McelieceParams *params);

// Field ordering algorithm - generates support elements for Goppa code
CRYPT_ERROR GenerateFieldOrdering(GFElement *alpha, int16_t *piTail, const uint8_t *randomBits, int32_t n, int32_t m);

// Irreducible polynomial generation algorithm
CRYPT_ERROR GenerateIrreduciblePolyFinal(GFPolynomial *g, const uint8_t *randomBits, int32_t t, int32_t m);

// Key structure management
CMPrivateKey *PrivateKeyCreate(const McelieceParams *params);
void PrivateKeyFree(CMPrivateKey *sk, const McelieceParams *params);
CMPublicKey *PublicKeyCreate(const McelieceParams *params);
void PublicKeyFree(CMPublicKey *pk);

#ifdef __cplusplus
}
#endif

#endif  // MCELIECE_KEYGEN_H
