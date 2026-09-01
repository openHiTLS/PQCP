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

#ifndef PQCP_NEV_ASM_SHA3_SVE2_H
#define PQCP_NEV_ASM_SHA3_SVE2_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The NEV SVE2 backend is specialized for VL=256: four uint64 lanes. */
#define CRYPT_SHA3_SVE2_MAX_LANES 4U

typedef struct {
    uint64_t s[25U * CRYPT_SHA3_SVE2_MAX_LANES];
} CRYPT_Sha3Sve2State;

/* Return the compile-time uint64 lane count (four). */
uint32_t CRYPT_Sha3Sve2Lanes(void);

/* Multi-stream SHA3/SHAKE sponge helpers. All streams use the same input
 * length and rate. Absorb leaves the padded state unpermuted; Squeeze applies
 * one Keccak-f[1600] permutation before every output block. */
void CRYPT_Sha3Sve2Absorb(CRYPT_Sha3Sve2State *state, uint32_t rate,
    const uint8_t *const inputs[], uint32_t streams, uint32_t inLen, uint8_t pad);
void CRYPT_Sha3Sve2Squeeze(uint8_t *const outputs[], uint32_t streams,
    uint32_t nblocks, uint32_t rate, CRYPT_Sha3Sve2State *state);

/* Permute a four-lane interleaved state at SVE VL=256. */
void SHA3_Sve2Permute(uint64_t *state);

#ifdef __cplusplus
}
#endif

#endif
