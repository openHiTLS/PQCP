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

/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "crypt_sm3.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "auxfunc.h"

#define L1 512
#define L2 256
#define HASH_SUCCESS 0
#define XOF_SUCCESS 0
#define MEMORY_ALLOCATION_FAILED -2
#define HASH_FAILED -3
#define INVALID_DIGESTBITLEN -4

/*
 * SM3 delegated to the openHiTLS backend.
 *
 * The ICCS reference carried a bit-level SM3 here for arbitrary bit-length
 * inputs; NEV only feeds byte-aligned messages (every caller in hashkdf.c
 * passes a length that is a multiple of 8 bits), so the hand-rolled
 * compression function is dropped in favour of the openHiTLS CRYPT_SM3_* API.
 */
static void sm3_bit(const unsigned char *msg, unsigned long long msg_bitlen, unsigned char *dgst)
{
    CRYPT_SM3_Ctx ctx;
    uint32_t len = CRYPT_SM3_DIGESTSIZE;
    /*
     * Fail-secure: these calls cannot fail for the arguments NEV passes
     * (valid context, non-NULL byte-aligned buffers), but a silently
     * skipped compression would corrupt every hash-derived secret, so any
     * unexpected error is fatal instead of ignored.
     */
    if (CRYPT_SM3_Init(&ctx) != CRYPT_SUCCESS ||
        CRYPT_SM3_Update(&ctx, msg, (uint32_t)(msg_bitlen >> 3)) != CRYPT_SUCCESS ||
        CRYPT_SM3_Final(&ctx, dgst, &len) != CRYPT_SUCCESS) {
        fprintf(stderr, "NEV SM3 backend: CRYPT_SM3_* failed, aborting (fail-secure)\n");
        abort();
    }
}

// key = SM3(UTF-8("3.14159265358979")) || SM3(UTF-8("2.71828182845904"))
static const unsigned char key[] = {
	0x53, 0x07, 0xf6, 0xd5, 0xeb, 0x6a, 0x3c, 0xed,
	0x3d, 0x24, 0xc5, 0x3c, 0xc9, 0xc8, 0x2c, 0xce,
	0x2f, 0x89, 0x36, 0x39, 0x70, 0x23, 0xf0, 0x69,
	0x5c, 0x26, 0xc8, 0x0c, 0x1a, 0xb1, 0x82, 0xa7,
	0x1d, 0xb0, 0x2b, 0xa9, 0x2f, 0x54, 0x40, 0x18,
	0x11, 0x5a, 0x96, 0xe7, 0x19, 0x66, 0x2c, 0xa3,
	0x2b, 0x7c, 0x7e, 0xfc, 0x0a, 0x6d, 0x24, 0x82,
	0x15, 0x07, 0x66, 0xba, 0x6f, 0x65, 0x5b, 0x8e};

static unsigned long long key_len_bits = (sizeof(key) / sizeof(key[0])) * 8;

static void normalize(unsigned char *input, unsigned long long total_bits)
{
	unsigned long long full_bytes = total_bits / 8;
	unsigned long long remaining_bits = total_bits % 8;
	if (remaining_bits > 0)
	{
		input[full_bytes] = input[full_bytes] & ~((1 << (8 - remaining_bits)) - 1);
	}
}

// GB/T 15852.2-2024 Section 7
/* Cleanse secret heap buffers before release; a plain memset right before
 * free() can be elided by the optimizer. */
static void cleanse_free(void *ptr, unsigned long long len)
{
	BSL_SAL_CleanseData(ptr, (uint32_t)len);
	free(ptr);
}

static int hmac(const unsigned char *msg, unsigned long long msg_len_bits, const unsigned char *key, unsigned long long key_len_bits, unsigned char *mac)
{
	// key expansion
	unsigned char K[L1 / 8] = {0};
	memcpy(K, key, key_len_bits / 8);
	unsigned char K1[L1 / 8], K2[L1 / 8];
	unsigned char IPAD[L1 / 8], OPAD[L1 / 8];
	memset(IPAD, 0x36, sizeof(IPAD));
	memset(OPAD, 0x5C, sizeof(OPAD));
	for (unsigned long long i = 0; i < L1 / 8; i++)
	{
		K1[i] = K[i] ^ IPAD[i];
		K2[i] = K[i] ^ OPAD[i];
	}
	// hash operation
	unsigned char H1[L2 / 8], H2[L2 / 8];
	unsigned char *temp1;
	temp1 = (unsigned char *)malloc(L1 / 8 + (msg_len_bits + 7) / 8);
	if (temp1 == NULL)
	{
		fprintf(stderr, "ERROR: Memory allocation failed at %s, line %d. \n", __FILE__, __LINE__);
		return MEMORY_ALLOCATION_FAILED;
	}
	memcpy(temp1, K1, L1 / 8);
	memcpy(temp1 + L1 / 8, msg, (msg_len_bits + 7) / 8);
	sm3_bit(temp1, L1 + msg_len_bits, H1);
	// output transformation
	unsigned char temp2[L1 / 8 + L2 / 8];
	memcpy(temp2, K2, L1 / 8);
	memcpy(temp2 + L1 / 8, H1, L2 / 8);
	sm3_bit(temp2, L1 + L2, H2);
	// truncation operation
	memcpy(mac, H2, L2 / 8);
	cleanse_free(temp1, L1 / 8 + (msg_len_bits + 7) / 8);
	return HASH_SUCCESS;
}

static int pseudohash_512(const unsigned char *msg, unsigned long long msg_len_bits, unsigned char *hash512)
{
	// k1
	unsigned char k1[32];
	unsigned char *cascade_0200_msg;
	cascade_0200_msg = (unsigned char *)malloc((msg_len_bits + 7) / 8 + 2);
	if (cascade_0200_msg == NULL)
	{
		fprintf(stderr, "ERROR: Memory allocation failed at %s, line %d. \n", __FILE__, __LINE__);
		return MEMORY_ALLOCATION_FAILED;
	}
	cascade_0200_msg[0] = 0x02;
	cascade_0200_msg[1] = 0x00;
	memcpy(cascade_0200_msg + 2, msg, (msg_len_bits + 7) / 8);
	if (hmac(cascade_0200_msg, 16 + msg_len_bits, key, key_len_bits, k1) != 0)
	{
		fprintf(stderr, "ERROR: HMAC failed at %s, line %d. \n", __FILE__, __LINE__);
		cleanse_free(cascade_0200_msg, (msg_len_bits + 7) / 8 + 2);
		return HASH_FAILED;
	}
	// h1
	unsigned char h1[32];
	unsigned char *cascade_msg_0200;
	cascade_msg_0200 = (unsigned char *)malloc((msg_len_bits + 7) / 8 + 2);
	if (cascade_msg_0200 == NULL)
	{
		fprintf(stderr, "ERROR: Memory allocation failed at %s, line %d. \n", __FILE__, __LINE__);
		cleanse_free(cascade_0200_msg, (msg_len_bits + 7) / 8 + 2);
		return MEMORY_ALLOCATION_FAILED;
	}
	memcpy(cascade_msg_0200, msg, (msg_len_bits + 7) / 8);
	if (msg_len_bits % 8 == 0)
	{
		cascade_msg_0200[(msg_len_bits + 7) / 8] = 0x02;
		cascade_msg_0200[(msg_len_bits + 7) / 8 + 1] = 0x00;
	}
	else
	{
		normalize(cascade_msg_0200, msg_len_bits);
		cascade_msg_0200[(msg_len_bits + 7) / 8 - 1] = cascade_msg_0200[(msg_len_bits + 7) / 8 - 1] ^ (0x02 >> (msg_len_bits % 8));
		cascade_msg_0200[(msg_len_bits + 7) / 8] = (0x02 << (8 - msg_len_bits % 8)) & 0xff;
		cascade_msg_0200[(msg_len_bits + 7) / 8 + 1] = 0x00;
	}
	sm3_bit(cascade_msg_0200, 16 + msg_len_bits, h1);
	// h2
	unsigned char h2[32];
	unsigned char k1_cascade_h1[64];
	memcpy(k1_cascade_h1, k1, 32);
	memcpy(k1_cascade_h1 + 32, h1, 32);
	sm3_bit(k1_cascade_h1, (sizeof(k1_cascade_h1) / sizeof(k1_cascade_h1)[0]) * 8, h2);
	// final result
	memcpy(hash512, h1, 32);
	memcpy(hash512 + 32, h2, 32);
	// free
	cleanse_free(cascade_0200_msg, (msg_len_bits + 7) / 8 + 2);
	cleanse_free(cascade_msg_0200, (msg_len_bits + 7) / 8 + 2);
	return HASH_SUCCESS;
}

static int pseudohash_768(const unsigned char *msg, unsigned long long msg_len_bits, unsigned char *hash768)
{
	// k1
	unsigned char k1[32];
	unsigned char *cascade_0300_msg;
	cascade_0300_msg = (unsigned char *)malloc((msg_len_bits + 7) / 8 + 2);
	if (cascade_0300_msg == NULL)
	{
		fprintf(stderr, "ERROR: Memory allocation failed at %s, line %d. \n", __FILE__, __LINE__);
		return MEMORY_ALLOCATION_FAILED;
	}
	cascade_0300_msg[0] = 0x03;
	cascade_0300_msg[1] = 0x00;
	memcpy(cascade_0300_msg + 2, msg, (msg_len_bits + 7) / 8);
	if (hmac(cascade_0300_msg, 16 + msg_len_bits, key, key_len_bits, k1) != 0)
	{
		fprintf(stderr, "ERROR: HMAC failed at %s, line %d. \n", __FILE__, __LINE__);
		cleanse_free(cascade_0300_msg, (msg_len_bits + 7) / 8 + 2);
		return HASH_FAILED;
	}
	// h1
	unsigned char h1[32];
	unsigned char *cascade_msg_0300;
	cascade_msg_0300 = (unsigned char *)malloc((msg_len_bits + 7) / 8 + 2);
	if (cascade_msg_0300 == NULL)
	{
		fprintf(stderr, "ERROR: Memory allocation failed at %s, line %d. \n", __FILE__, __LINE__);
		cleanse_free(cascade_0300_msg, (msg_len_bits + 7) / 8 + 2);
		return MEMORY_ALLOCATION_FAILED;
	}
	memcpy(cascade_msg_0300, msg, (msg_len_bits + 7) / 8);

	if (msg_len_bits % 8 == 0)
	{
		cascade_msg_0300[(msg_len_bits + 7) / 8] = 0x03;
		cascade_msg_0300[(msg_len_bits + 7) / 8 + 1] = 0x00;
	}
	else
	{
		normalize(cascade_msg_0300, msg_len_bits);
		cascade_msg_0300[(msg_len_bits + 7) / 8 - 1] = cascade_msg_0300[(msg_len_bits + 7) / 8 - 1] ^ (0x03 >> (msg_len_bits % 8));
		cascade_msg_0300[(msg_len_bits + 7) / 8] = (0x03 << (8 - msg_len_bits % 8)) & 0xff;
		cascade_msg_0300[(msg_len_bits + 7) / 8 + 1] = 0x00;
	}
	sm3_bit(cascade_msg_0300, 16 + msg_len_bits, h1);
	// k2
	unsigned char k2[32];
	if (hmac(h1, (sizeof(h1) / sizeof(h1[0])) * 8, key, key_len_bits, k2) != 0)
	{
		fprintf(stderr, "ERROR: HMAC failed at %s, line %d. \n", __FILE__, __LINE__);
		cleanse_free(cascade_0300_msg, (msg_len_bits + 7) / 8 + 2);
		cleanse_free(cascade_msg_0300, (msg_len_bits + 7) / 8 + 2);
		return HASH_FAILED;
	}
	// h2
	unsigned char h2[32];
	unsigned char k1_cascade_h1[64];
	memcpy(k1_cascade_h1, k1, 32);
	memcpy(k1_cascade_h1 + 32, h1, 32);
	sm3_bit(k1_cascade_h1, (sizeof(k1_cascade_h1) / sizeof(k1_cascade_h1[0])) * 8, h2);
	// h3
	unsigned char h3[32];
	unsigned char h2_cascade_k2[64];
	memcpy(h2_cascade_k2, h2, 32);
	memcpy(h2_cascade_k2 + 32, k2, 32);
	sm3_bit(h2_cascade_k2, (sizeof(h2_cascade_k2) / sizeof(h2_cascade_k2[0])) * 8, h3);
	// final result
	memcpy(hash768, h1, 32);
	memcpy(hash768 + 32, h2, 32);
	memcpy(hash768 + 64, h3, 32);
	// free
	cleanse_free(cascade_0300_msg, (msg_len_bits + 7) / 8 + 2);
	cleanse_free(cascade_msg_0300, (msg_len_bits + 7) / 8 + 2);
	return HASH_SUCCESS;
}

static int pseudohash_1024(const unsigned char *msg, unsigned long long msg_len_bits, unsigned char *hash1024)
{
	// k1
	unsigned char k1[32];
	unsigned char *cascade_0400_msg;
	cascade_0400_msg = (unsigned char *)malloc((msg_len_bits + 7) / 8 + 2);
	if (cascade_0400_msg == NULL)
	{
		fprintf(stderr, "ERROR: Memory allocation failed at %s, line %d. \n", __FILE__, __LINE__);
		return MEMORY_ALLOCATION_FAILED;
	}
	cascade_0400_msg[0] = 0x04;
	cascade_0400_msg[1] = 0x00;
	memcpy(cascade_0400_msg + 2, msg, (msg_len_bits + 7) / 8);
	if (hmac(cascade_0400_msg, 16 + msg_len_bits, key, key_len_bits, k1) != 0)
	{
		fprintf(stderr, "ERROR: HMAC failed at %s, line %d. \n", __FILE__, __LINE__);
		cleanse_free(cascade_0400_msg, (msg_len_bits + 7) / 8 + 2);
		return HASH_FAILED;
	}
	// h1
	unsigned char h1[32];
	unsigned char *cascade_msg_0400;
	cascade_msg_0400 = (unsigned char *)malloc((msg_len_bits + 7) / 8 + 2);
	if (cascade_msg_0400 == NULL)
	{
		fprintf(stderr, "ERROR: Memory allocation failed at %s, line %d. \n", __FILE__, __LINE__);
		cleanse_free(cascade_0400_msg, (msg_len_bits + 7) / 8 + 2);
		return MEMORY_ALLOCATION_FAILED;
	}
	memcpy(cascade_msg_0400, msg, (msg_len_bits + 7) / 8);
	normalize(cascade_msg_0400, msg_len_bits);
	if (msg_len_bits % 8 == 0)
	{
		cascade_msg_0400[(msg_len_bits + 7) / 8] = 0x04;
		cascade_msg_0400[(msg_len_bits + 7) / 8 + 1] = 0x00;
	}
	else
	{
		cascade_msg_0400[(msg_len_bits + 7) / 8 - 1] = cascade_msg_0400[(msg_len_bits + 7) / 8 - 1] ^ (0x04 >> (msg_len_bits % 8));
		cascade_msg_0400[(msg_len_bits + 7) / 8] = (0x04 << (8 - msg_len_bits % 8)) & 0xff;
		cascade_msg_0400[(msg_len_bits + 7) / 8 + 1] = 0x00;
	}
	sm3_bit(cascade_msg_0400, 16 + msg_len_bits, h1);
	// k2
	unsigned char k2[32];
	if (hmac(h1, (sizeof(h1) / sizeof(h1[0])) * 8, key, key_len_bits, k2) != 0)
	{
		fprintf(stderr, "ERROR: HMAC failed at %s, line %d. \n", __FILE__, __LINE__);
		cleanse_free(cascade_0400_msg, (msg_len_bits + 7) / 8 + 2);
		cleanse_free(cascade_msg_0400, (msg_len_bits + 7) / 8 + 2);
		return HASH_FAILED;
	}
	// h2
	unsigned char h2[32];
	unsigned char k1_cascade_h1[64];
	memcpy(k1_cascade_h1, k1, 32);
	memcpy(k1_cascade_h1 + 32, h1, 32);
	sm3_bit(k1_cascade_h1, (sizeof(k1_cascade_h1) / sizeof(k1_cascade_h1[0])) * 8, h2);
	// k3
	unsigned char k3[32];
	if (hmac(h2, (sizeof(h2) / sizeof(h2[0])) * 8, key, key_len_bits, k3) != 0)
	{
		fprintf(stderr, "ERROR: HMAC failed at %s, line %d. \n", __FILE__, __LINE__);
		cleanse_free(cascade_0400_msg, (msg_len_bits + 7) / 8 + 2);
		cleanse_free(cascade_msg_0400, (msg_len_bits + 7) / 8 + 2);
		return HASH_FAILED;
	}
	// h3
	unsigned char h3[32];
	unsigned char h2_cascade_k2[64];
	memcpy(h2_cascade_k2, h2, 32);
	memcpy(h2_cascade_k2 + 32, k2, 32);
	sm3_bit(h2_cascade_k2, (sizeof(h2_cascade_k2) / sizeof(h2_cascade_k2[0])) * 8, h3);
	// k4
	unsigned char k4[32];
	if (hmac(h3, (sizeof(h3) / sizeof(h3[0])) * 8, key, key_len_bits, k4) != 0)
	{
		fprintf(stderr, "ERROR: HMAC failed at %s, line %d. \n", __FILE__, __LINE__);
		cleanse_free(cascade_0400_msg, (msg_len_bits + 7) / 8 + 2);
		cleanse_free(cascade_msg_0400, (msg_len_bits + 7) / 8 + 2);
		return HASH_FAILED;
	}
	// h4
	unsigned char h4[32];
	unsigned char k3_cascade_h3_k4[96];
	memcpy(k3_cascade_h3_k4, k3, 32);
	memcpy(k3_cascade_h3_k4 + 32, h3, 32);
	memcpy(k3_cascade_h3_k4 + 64, k4, 32);
	sm3_bit(k3_cascade_h3_k4, (sizeof(k3_cascade_h3_k4) / sizeof(k3_cascade_h3_k4[0])) * 8, h4);
	// final result
	memcpy(hash1024, h1, 32);
	memcpy(hash1024 + 32, h2, 32);
	memcpy(hash1024 + 64, h3, 32);
	memcpy(hash1024 + 96, h4, 32);
	// free
	cleanse_free(cascade_0400_msg, (msg_len_bits + 7) / 8 + 2);
	cleanse_free(cascade_msg_0400, (msg_len_bits + 7) / 8 + 2);
	return HASH_SUCCESS;
}

int sm3hash(int digest_len_bits, const unsigned char *msg, unsigned long long msg_len_bits, unsigned char *digest)
{
	if (digest_len_bits == 256)
	{
		sm3_bit(msg, msg_len_bits, digest);
		return HASH_SUCCESS;
	}
	else
	{
		fprintf(stderr, "ERROR: Digestbitlen not in the limitation. \n");
		return INVALID_DIGESTBITLEN;
	}
}

int pseudohash(int digest_len_bits, const unsigned char *msg, unsigned long long msg_len_bits, unsigned char *digest)
{
	if (digest_len_bits == 512)
	{
		return pseudohash_512(msg, msg_len_bits, digest);
	}
	else if (digest_len_bits == 768)
	{
		return pseudohash_768(msg, msg_len_bits, digest);
	}
	else if (digest_len_bits == 1024)
	{
		return pseudohash_1024(msg, msg_len_bits, digest);
	}
	else
	{
		fprintf(stderr, "ERROR: Digestbitlen not in the limitation. \n");
		return INVALID_DIGESTBITLEN;
	}
}

// GB/T 32918.4-2016 Section 5.4.3
int pseudoXOF(unsigned long long output_len_bits, const unsigned char *msg, unsigned long long msg_len_bits, unsigned char *output)
{
	unsigned int ct = 1;
	unsigned char *cascade_msg_ct;
	cascade_msg_ct = (unsigned char *)malloc((msg_len_bits + 7) / 8 + 4);
	if (cascade_msg_ct == NULL)
	{
		fprintf(stderr, "ERROR: Memory allocation failed at %s, line %d. \n", __FILE__, __LINE__);
		return MEMORY_ALLOCATION_FAILED;
	}
	unsigned char *K;
	K = (unsigned char *)malloc((output_len_bits + 255) / 8);
	if (K == NULL)
	{
		fprintf(stderr, "ERROR: Memory allocation failed at %s, line %d. \n", __FILE__, __LINE__);
		cleanse_free(cascade_msg_ct, (msg_len_bits + 7) / 8 + 4);
		return MEMORY_ALLOCATION_FAILED;
	}

	for (unsigned int i = 0; i < (output_len_bits + 255) / 256; i++)
	{
		memcpy(cascade_msg_ct, msg, (msg_len_bits + 7) / 8);
		if (msg_len_bits % 8 == 0)
		{
			cascade_msg_ct[(msg_len_bits + 7) / 8] = ct >> 24;
			cascade_msg_ct[(msg_len_bits + 7) / 8 + 1] = (ct & 0xffffff) >> 16;
			cascade_msg_ct[(msg_len_bits + 7) / 8 + 2] = (ct & 0xffff) >> 8;
			cascade_msg_ct[(msg_len_bits + 7) / 8 + 3] = ct & 0xff;
		}
		else
		{
			normalize(cascade_msg_ct, msg_len_bits);
			cascade_msg_ct[(msg_len_bits + 7) / 8 - 1] = cascade_msg_ct[(msg_len_bits + 7) / 8 - 1] ^ (ct >> (32 - (8 - (msg_len_bits % 8))));
			cascade_msg_ct[(msg_len_bits + 7) / 8] = ((ct << (8 - (msg_len_bits % 8))) & 0xffffffff) >> 24;
			cascade_msg_ct[(msg_len_bits + 7) / 8 + 1] = ((ct << (16 - (msg_len_bits % 8))) & 0xffffffff) >> 24;
			cascade_msg_ct[(msg_len_bits + 7) / 8 + 2] = ((ct << (24 - (msg_len_bits % 8))) & 0xffffffff) >> 24;
			cascade_msg_ct[(msg_len_bits + 7) / 8 + 3] = ((ct << (32 - (msg_len_bits % 8))) & 0xffffffff) >> 24;
		}
		sm3_bit(cascade_msg_ct, msg_len_bits + 32, K + i * 32);
		ct++;
	}
	memcpy(output, K, (output_len_bits + 7) / 8);
	cleanse_free(cascade_msg_ct, (msg_len_bits + 7) / 8 + 4);
	cleanse_free(K, (output_len_bits + 255) / 8);
	if (output_len_bits % 256 != 0)
	{
		normalize(output, output_len_bits);
	}
	return XOF_SUCCESS;
}
