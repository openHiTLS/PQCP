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

#ifndef _SM3_KDF_H_
#define _SM3_KDF_H_

#include <stdint.h>

#define SM3_KDF_RATE	32

typedef struct {
	unsigned char buf[512];
	unsigned int pos;
	unsigned int cnt;
} sm3kdf_ctx;

void sm3kdf_init(sm3kdf_ctx* state, const unsigned char* key, unsigned long long klen, uint16_t nonce);

void sm3kdf_absorb(sm3kdf_ctx* state, const unsigned char* input, unsigned long long inlen);

void sm3kdf_squeezeblocks(unsigned char* out, unsigned long long nblocks, sm3kdf_ctx* state);

void sm3kdf(unsigned char* output, unsigned long long outlen, const unsigned char* input, unsigned long long inlen);

#endif // !_SM3_KDF_H_
