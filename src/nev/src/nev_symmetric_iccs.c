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

/* ICCS Hash/KDF adapter for the runtime-parameterized NEON core.
 * This deliberately preserves the submitted SM3/pseudoHash/pseudoXOF byte
 * stream instead of using the SHA3 adapter from openhitls_ngcc. */

#include "nev_local.h"
#include "hashkdf.h"

_Static_assert(sizeof(NEV_KdfState) >= sizeof(kdfstate), "NEV_KdfState is too small");

uint32_t NEV_KdfRate(uint32_t seedLen)
{
    (void)seedLen;
    return 32;
}

void NEV_Hash(uint8_t *out, const uint8_t *in, uint32_t inLen, uint32_t seedLen)
{
    if (seedLen == 16) {
        hash128(out, in, (int)inLen);
    } else if (seedLen == 32) {
        hash256(out, in, (int)inLen);
    } else {
        hash512(out, in, (int)inLen);
    }
}

void NEV_Hash2(uint8_t *out, const uint8_t *in, uint32_t inLen, uint32_t seedLen)
{
    if (seedLen == 16) {
        hash256(out, in, (int)inLen);
    } else if (seedLen == 32) {
        hash512(out, in, (int)inLen);
    } else {
        hash1024(out, in, (int)inLen);
    }
}

void NEV_Kdf(uint8_t *out, uint32_t outLen, const uint8_t *in, uint32_t inLen, uint32_t seedLen)
{
    (void)seedLen;
    kdf(out, (int)outLen, in, (int)inLen);
}

void NEV_KdfAbsorb(NEV_KdfState *state, const uint8_t *in, uint32_t inLen, uint32_t seedLen)
{
    (void)seedLen;
    kdf_absorb((kdfstate *)(void *)state, in, (int)inLen);
}

void NEV_KdfSqueezeBlocks(uint8_t *out, uint32_t nblocks, NEV_KdfState *state, uint32_t seedLen)
{
    (void)seedLen;
    kdf_squeezeblocks(out, (int)nblocks, (kdfstate *)(void *)state);
}
