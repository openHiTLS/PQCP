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

#include "hashkdf.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

static void store32_be(uint8_t out[4], uint32_t x)
{
    out[0] = (uint8_t)(x >> 24);
    out[1] = (uint8_t)(x >> 16);
    out[2] = (uint8_t)(x >> 8);
    out[3] = (uint8_t)x;
}

/*
 * The NEV Hash/KDF backend interface above this file is void-valued, so an
 * error cannot be propagated to the KEM, yet the SM3 adapters in auxfunc.c
 * are fallible (heap allocations).  A silently discarded failure would leave
 * the output buffer untouched while key generation or encapsulation keeps
 * running on uninitialized stack data and reports success.  Garbage key
 * material with a success code is never acceptable for a KEM, so the only
 * fail-secure outcome is to stop the process.
 */
static void hashkdf_check(int ret, const char *what)
{
    if (ret != 0) {
        fprintf(stderr, "NEV SM3 Hash/KDF: %s failed with %d, aborting (fail-secure)\n",
            what, ret);
        abort();
    }
}

/*
 * The ICCS KDF is seed-length agnostic: it always emits 32-byte SM3 blocks
 * (NEV_KdfRate returns 32 for every seedLen), so a single absorb/squeeze
 * pair replaces the former per-seedLen kdf{128,256,512}_* wrappers.
 */

void kdf_absorb(kdfstate *state, const uint8_t *input, int inputByteLen)
{
    memcpy(state->input, input, (size_t)inputByteLen);
    state->input_len = (size_t)inputByteLen;
    state->counter = 1;
}

void kdf_squeezeblocks(uint8_t *output, int nblocks, kdfstate *state)
{
    uint8_t input_with_counter[ICCS_KDF_MAX_INPUT_BYTES + 4];

    memcpy(input_with_counter, state->input, state->input_len);

    for (int i = 0; i < nblocks; ++i) {
        store32_be(input_with_counter + state->input_len, state->counter);

        hashkdf_check(sm3hash(256, input_with_counter, 8ULL * (state->input_len + 4),
            output + 32 * i), "sm3hash");

        state->counter++;
    }
}

void kdf(uint8_t *out, int outlen, const uint8_t *in, int inlen)
{
    hashkdf_check(pseudoXOF(outlen * 8, in, inlen * 8, out), "pseudoXOF");
}

void hash128(uint8_t *out, const uint8_t *in, int inlen)
{
    hashkdf_check(pseudoXOF(128, in, inlen * 8, out), "pseudoXOF");
}

void hash256(uint8_t *out, const uint8_t *in, int inlen)
{
    hashkdf_check(sm3hash(256, in, inlen * 8, out), "sm3hash");
}

void hash512(uint8_t *out, const uint8_t *in, int inlen)
{
    hashkdf_check(pseudohash(512, in, inlen * 8, out), "pseudohash");
}

void hash1024(uint8_t *out, const uint8_t *in, int inlen)
{
    hashkdf_check(pseudohash(1024, in, inlen * 8, out), "pseudohash");
}
