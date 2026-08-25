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

#ifndef FIPS202X4_H
#define FIPS202X4_H

#include "avx2_neon.h"
#include "params.h"

typedef struct 
{
	__m256i s[25];
} keccakx4_state;

void shake128_absorb4x(__m256i *s,
                       const unsigned char *m0,
                       const unsigned char *m1,
                       const unsigned char *m2,
                       const unsigned char *m3,
                       unsigned long long mlen);

void shake128_squeezeblocks4x(unsigned char *h0,
                              unsigned char *h1,
                              unsigned char *h2,
                              unsigned char *h3,
                              unsigned long nblocks,
                              __m256i *s);

void shake256_absorb4x(__m256i *s,
                       const unsigned char *m0,
                       const unsigned char *m1,
                       const unsigned char *m2,
                       const unsigned char *m3,
                       unsigned long long mlen);

void shake256_squeezeblocks4x(unsigned char *h0,
                              unsigned char *h1,
                              unsigned char *h2,
                              unsigned char *h3,
                              unsigned long nblocks,
                              __m256i *s);


void shake512_absorb4x(__m256i* s,
    const unsigned char* m0,
    const unsigned char* m1,
    const unsigned char* m2,
    const unsigned char* m3,
    unsigned long long mlen);

void shake512_squeezeblocks4x(unsigned char* h0,
    unsigned char* h1,
    unsigned char* h2,
    unsigned char* h3,
    unsigned long nblocks,
    __m256i* s);

void shake128x4(unsigned char *h0,
                 unsigned char *h1,
                 unsigned char *h2,
                 unsigned char *h3,
                 unsigned long long hlen, 
                 const unsigned char *m0,
                 const unsigned char *m1,
                 const unsigned char *m2,
                 const unsigned char *m3,
                 unsigned long long mlen);

void shake256x4(unsigned char *h0,
                 unsigned char *h1,
                 unsigned char *h2,
                 unsigned char *h3,
                 unsigned long long hlen, 
                 const unsigned char *m0,
                 const unsigned char *m1,
                 const unsigned char *m2,
                 const unsigned char *m3,
                 unsigned long long mlen);

void shake512x4(unsigned char* h0,
    unsigned char* h1,
    unsigned char* h2,
    unsigned char* h3,
    unsigned long long hlen,
    const unsigned char* m0,
    const unsigned char* m1,
    const unsigned char* m2,
    const unsigned char* m3,
    unsigned long long mlen);
#endif
