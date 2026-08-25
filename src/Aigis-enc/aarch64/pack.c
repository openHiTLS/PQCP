/* Copyright (c) 2025 LiuRuikang
 * School Of Cyber Engineering, Xidian University
 *
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 * http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "pack.h"
#include "polyvec.h"


void pack_pk(uint8_t *r, const poly *pk, const uint8_t *seed)
{
  int i;
  poly_compress10(r, pk);
  for(i=0;i<SEED_BYTES;i++)
    r[PK_POLYVEC_COMPRESSED_BYTES + i] = seed[i];
}
void unpack_pk(poly *pk, uint8_t *seed, const uint8_t *packedpk)
{
	int i;
	for (i = 0; i < SEED_BYTES; i++)
		seed[i] = packedpk[PK_POLYVEC_COMPRESSED_BYTES + i];
	poly_decompress10(pk, packedpk);
}
void pack_ciphertext(uint8_t *r, const poly *b, const poly *v)
{
	poly_compress10(r,b);
	poly_compress(r + CT_POLYVEC_COMPRESSED_BYTES, v);
}

void unpack_ciphertext(poly *b, poly *v, const uint8_t *c)
{
	poly_decompress10(b, c);
	poly_decompress(v, c + CT_POLYVEC_COMPRESSED_BYTES);
}

void pack_sk(uint8_t *r, const poly *sk)
{
	poly_tobytes(r, sk);
}

void unpack_sk(poly *sk, const uint8_t *packedsk)
{
  poly_frombytes(sk, packedsk);
}
