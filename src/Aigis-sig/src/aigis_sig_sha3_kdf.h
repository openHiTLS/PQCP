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

#ifndef AIGIS_SIG_SHA3_KDF_H
#define AIGIS_SIG_SHA3_KDF_H

#include <stdint.h>

#define PQCP_AIGIS_SIG_SHAKE128_RATE       168U
#define PQCP_AIGIS_SIG_SHAKE256_RATE       136U
#define PQCP_AIGIS_SIG_AIGIS_KECCAK_RATE72 72U

typedef struct {
    void *mdCtx;
    uint8_t cached;
} PQCP_AIGIS_SIG_Shake256Ctx;

typedef PQCP_AIGIS_SIG_Shake256Ctx PQCP_AIGIS_SIG_Shake128Ctx;

/* Aigis-Sig+ III uses a submission-specific rate-72 Keccak XOF.  It is kept
 * private to this algorithm and is not exposed as a standard SHAKE variant. */
typedef struct {
    uint64_t state[25];
    uint32_t offset;
    uint8_t initialized;
} PQCP_AIGIS_SIG_AigisKeccakXofRate72Ctx;

typedef struct PQCP_AIGIS_SIG_Sha3Cache PQCP_AIGIS_SIG_Sha3Cache;

#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
void PQCP_AIGIS_SIG_KeccakF1600Armv8(uint64_t state[25]);
#endif
void PQCP_AIGIS_SIG_Sha3CacheFree(PQCP_AIGIS_SIG_Sha3Cache *cache);
int32_t PQCP_AIGIS_SIG_Sha3Hash256(void *libCtx, PQCP_AIGIS_SIG_Sha3Cache *cache, const uint8_t *in, uint32_t inLen,
                                   uint8_t out[32]);
int32_t PQCP_AIGIS_SIG_Sha3Hash512(void *libCtx, PQCP_AIGIS_SIG_Sha3Cache *cache, const uint8_t *in, uint32_t inLen,
                                   uint8_t out[64]);
int32_t PQCP_AIGIS_SIG_Shake256(void *libCtx, PQCP_AIGIS_SIG_Sha3Cache *cache, const uint8_t *in, uint32_t inLen,
                                uint8_t *out, uint32_t outLen);
int32_t PQCP_AIGIS_SIG_Shake256TwoSegment(void *libCtx, PQCP_AIGIS_SIG_Sha3Cache *cache, const uint8_t *in1,
                                          uint32_t in1Len, const uint8_t *in2, uint32_t in2Len, uint8_t *out,
                                          uint32_t outLen);
int32_t PQCP_AIGIS_SIG_AigisKeccakXofRate72(const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen);
int32_t PQCP_AIGIS_SIG_AigisKeccakXofRate72TwoSegment(const uint8_t *in1, uint32_t in1Len, const uint8_t *in2,
                                                      uint32_t in2Len, uint8_t *out, uint32_t outLen);
int32_t PQCP_AIGIS_SIG_Shake128Init(PQCP_AIGIS_SIG_Shake128Ctx *ctx, void *libCtx, PQCP_AIGIS_SIG_Sha3Cache *cache,
                                    const uint8_t *in, uint32_t inLen);
int32_t PQCP_AIGIS_SIG_Shake256Init(PQCP_AIGIS_SIG_Shake256Ctx *ctx, void *libCtx, PQCP_AIGIS_SIG_Sha3Cache *cache,
                                    const uint8_t *in, uint32_t inLen);
int32_t PQCP_AIGIS_SIG_Shake256Squeeze(PQCP_AIGIS_SIG_Shake256Ctx *ctx, uint8_t *out, uint32_t outLen);
void PQCP_AIGIS_SIG_Shake256Free(PQCP_AIGIS_SIG_Shake256Ctx *ctx);
int32_t PQCP_AIGIS_SIG_AigisKeccakXofRate72Init(PQCP_AIGIS_SIG_AigisKeccakXofRate72Ctx *ctx, const uint8_t *in,
                                                uint32_t inLen);
int32_t PQCP_AIGIS_SIG_AigisKeccakXofRate72Squeeze(PQCP_AIGIS_SIG_AigisKeccakXofRate72Ctx *ctx, uint8_t *out,
                                                   uint32_t outLen);
void PQCP_AIGIS_SIG_AigisKeccakXofRate72Free(PQCP_AIGIS_SIG_AigisKeccakXofRate72Ctx *ctx);

#endif
