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

#ifndef PQCP_NEV_SYMMETRIC_BACKEND_H
#define PQCP_NEV_SYMMETRIC_BACKEND_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The NEON sampler supports KDF rates up to the SHAKE128 rate. */
#define NEV_KDF_RATE_MAX 168

#ifdef HITLS_CRYPTO_NEV_SVE2
#include "asm_sha3_sve2.h"
/* Single-stream Hash/KDF uses the compact ARMv8/FEAT_SHA3 NEON state. */
#define NEV_SPONGE_LANES_MAX 1
#else
#define NEV_SPONGE_LANES_MAX 1
#endif

/* Backend-independent storage for an incremental Hash/KDF context.  The
 * SVE2 backend keeps scalar continuations compact and reserves its four-lane
 * state for genuinely parallel sponge streams. */
typedef struct {
    uint64_t s[25 * NEV_SPONGE_LANES_MAX];
} NEV_KdfState;

/*
 * A custom backend must implement this complete interface. NEV_KdfRate must
 * return a non-zero rate no larger than NEV_KDF_RATE_MAX for seed lengths
 * 16, 32 and 64. Hash and Hash2 produce seedLen and 2 * seedLen bytes.
 */
uint32_t NEV_KdfRate(uint32_t seedLen);
void NEV_Hash(uint8_t *out, const uint8_t *in, uint32_t inLen, uint32_t seedLen);
void NEV_Hash2(uint8_t *out, const uint8_t *in, uint32_t inLen, uint32_t seedLen);
void NEV_Kdf(uint8_t *out, uint32_t outLen, const uint8_t *in, uint32_t inLen, uint32_t seedLen);
void NEV_KdfAbsorb(NEV_KdfState *state, const uint8_t *in, uint32_t inLen, uint32_t seedLen);
void NEV_KdfSqueezeBlocks(uint8_t *out, uint32_t nblocks, NEV_KdfState *state, uint32_t seedLen);

#ifdef __cplusplus
}
#endif

#endif
