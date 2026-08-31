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

#ifndef AIGIS_SIG_SM3_KDF_H
#define AIGIS_SIG_SM3_KDF_H

#include <stdint.h>

#define PQCP_AIGIS_SIG_SM3_RATE     32U
#define PQCP_AIGIS_SIG_SM3_SEED_LEN 55U

typedef struct {
    void *libCtx;
    void *mdCtx;
    uint8_t v[PQCP_AIGIS_SIG_SM3_SEED_LEN];
    uint8_t c[PQCP_AIGIS_SIG_SM3_SEED_LEN];
    uint8_t reseedCounter[PQCP_AIGIS_SIG_SM3_SEED_LEN];
    uint8_t initialized;
} PQCP_AIGIS_SIG_Sm3DrngCtx;

typedef struct {
    void *mdCtx;
    void *prefixCtx;
    uint8_t *blockInput;
    uint32_t inputLen;
} PQCP_AIGIS_SIG_Sm3PseudoXofBatchCtx;

int32_t PQCP_AIGIS_SIG_Sm3Hash256(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t out[32]);
int32_t PQCP_AIGIS_SIG_Sm3PseudoHash512(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t out[64]);
int32_t PQCP_AIGIS_SIG_Sm3PseudoXof(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen);
int32_t PQCP_AIGIS_SIG_Sm3PseudoXofBatchInit(PQCP_AIGIS_SIG_Sm3PseudoXofBatchCtx *ctx, void *libCtx, uint32_t inputLen);
int32_t PQCP_AIGIS_SIG_Sm3PseudoXofBatchGenerate(PQCP_AIGIS_SIG_Sm3PseudoXofBatchCtx *ctx, const uint8_t *in,
                                                 uint8_t *out, uint32_t outLen);
void PQCP_AIGIS_SIG_Sm3PseudoXofBatchFree(PQCP_AIGIS_SIG_Sm3PseudoXofBatchCtx *ctx);
int32_t PQCP_AIGIS_SIG_Sm3PseudoXofTwoSegment(void *libCtx, const uint8_t *in1, uint32_t in1Len, const uint8_t *in2,
                                              uint32_t in2Len, uint8_t *out, uint32_t outLen);
int32_t PQCP_AIGIS_SIG_Sm3DrngInit(PQCP_AIGIS_SIG_Sm3DrngCtx *ctx, void *libCtx, const uint8_t *seed, uint32_t seedLen);
int32_t PQCP_AIGIS_SIG_Sm3DrngGenerate(PQCP_AIGIS_SIG_Sm3DrngCtx *ctx, uint8_t *out, uint32_t outLen);
void PQCP_AIGIS_SIG_Sm3DrngFree(PQCP_AIGIS_SIG_Sm3DrngCtx *ctx);

#endif
