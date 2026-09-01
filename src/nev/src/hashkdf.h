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

#ifndef HASHKDF_H
#define HASHKDF_H

#include <stddef.h>
#include <stdint.h>

#include "auxfunc.h"

#define KDF128RATE 32
#define KDF256RATE 32
#define KDF512RATE 32

#define ICCS_KDF_MAX_INPUT_BYTES 65

typedef struct {
    uint8_t input[ICCS_KDF_MAX_INPUT_BYTES];
    size_t input_len;
    uint32_t counter;
} kdfstate;

/* One-shot KDF: produces outlen bytes (seed-length agnostic). */
void kdf(uint8_t *out, int outlen, const uint8_t *in, int inlen);

/* Fixed-output hashes. The digest length is intrinsic to each variant, so the
 * per-seedLen selection is performed by the NEV_Hash / NEV_Hash2 dispatchers. */
void hash128(uint8_t *out, const uint8_t *in, int inlen);
void hash256(uint8_t *out, const uint8_t *in, int inlen);
void hash512(uint8_t *out, const uint8_t *in, int inlen);
void hash1024(uint8_t *out, const uint8_t *in, int inlen);

/* Streaming KDF: absorb once, squeeze 32-byte blocks repeatedly. */
void kdf_absorb(kdfstate *state, const uint8_t *input, int inputByteLen);
void kdf_squeezeblocks(uint8_t *output, int nblocks, kdfstate *state);

#endif
