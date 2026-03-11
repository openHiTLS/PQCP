/* Copyright (c) 2025 LiuZiyao
*    Key Laboratory of Cyberspace Security Defense,Institute of Information Engineering, CAS
*    School of Cyber Security, University of Chinese Academy of Sciences     
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
#ifdef PQCP_POLARLAC
#include <string.h>

#include "crypt_eal_rand.h"
#include "polarlac_local.h"
#include "securec.h"
#include "pqcp_err.h"

#define RATIO 126 // Q/2

// message bit is 1, frozen bit is 0
static const uint8_t g_eccInfoNodesLight[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1,
    1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
    0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

// message bit is 1, frozen bit is 0
static const uint8_t g_eccInfoNodes128[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1,
    1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0,
    0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1,
    1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

// message bit is 1, frozen bit is 0
static const uint8_t g_eccInfoNodes256[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1,
    1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
    0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1,
    1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1,
    0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0,
    1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1,
    1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

static void EncodeToE2(uint8_t *e2, const uint8_t *m, int32_t *c2Len, int32_t algId)
{
    int32_t i;
    int8_t message;
    int32_t vecBound;
    uint8_t *pCode;
    uint32_t codeLen = algId == PQCP_POLAR_LAC_LIGHT ? 32 : 64;
    /* polar encoding */
    uint8_t u[codeLen * 8]; // source sequence(each element stores 1 bits)
    uint8_t code[codeLen]; // codeword sequence(each element stores 8 bits)
    memset_s(u, sizeof(u), 0, sizeof(u));
    memset_s(code, sizeof(code), 0, sizeof(code));
    const uint8_t *eccInfoNodes = NULL;
    switch (algId) {
        case PQCP_POLAR_LAC_LIGHT:
            eccInfoNodes = g_eccInfoNodesLight;
            break;
        case PQCP_POLAR_LAC_128:
            eccInfoNodes = g_eccInfoNodes128;
            break;
        case PQCP_POLAR_LAC_256:
            eccInfoNodes = g_eccInfoNodes256;
            break;
    }
    // fill the message m into the source sequence
    int32_t infoCnt = 0;
    for (uint32_t i = 0; i < codeLen; i++) {
        for (int32_t j = 0; j < 8; j++) {
            if (eccInfoNodes[8 * i + j] == 1) {
                u[8 * i + j] = (uint8_t)(m[infoCnt / 8] >> (infoCnt % 8)) & 0x01;
                infoCnt++;
            }
        }
    }
    PQCP_POLAR_LAC_EncodePolar(u, algId);

    // Convert from bit array to byte array
    for (uint32_t i = 0; i < codeLen; i++) {
        for (int32_t j = 0; j < 8; j++) {
            code[i] |= (u[i * 8 + j] << j);
        }
    }
    pCode = (uint8_t *)code;
    // compute the length of c2
    *c2Len = codeLen * 8; // the code length of the ecc
    vecBound = *c2Len;
    // compute code*q/2+e2
    for (i = 0; i < vecBound; i++) {
        // RATIO=q/2. add code*q/2 to e2
        message = RATIO * ((pCode[i / 8] >> (i % 8)) & 1);
        e2[i] = e2[i] + message;
    }
}

// key generation with seed
int32_t PQCP_POLAR_LAC_PkeKeyGen(CRYPT_POLAR_LAC_Ctx *ctx, uint8_t *seed)
{
    uint8_t *pk = ctx->pk;
    uint8_t *sk = ctx->sk;
    const CRYPT_Lac2Info *info = ctx->info;
    int32_t algId = ctx->algId;

    uint32_t seedLen = info->seedLen;
    uint32_t dimN = info->dimN;
    uint32_t skLen = info->skLen;
    uint32_t pkLen = info->pkLen;

    uint8_t a[dimN];
    uint8_t e[dimN];
    uint8_t randBuf[seedLen * 3];
    int32_t ret = 0;
    RETURN_RET_IF(PQCP_POLAR_LAC_PseudoRandomBytes(NULL, seed, seedLen, randBuf, seedLen * 3), ret);
    RETURN_RET_IF(PQCP_POLAR_LAC_SamplePolyA(NULL, Q, randBuf, seedLen, a, dimN), ret);
    // Copy the seed to the first part of pk: pk = seed | as+e;
    memcpy_s(pk, pkLen, randBuf, seedLen);
    // generate random vector r
    RETURN_RET_IF(PQCP_POLAR_LAC_SampleSparseTernaryVector(NULL, Q, randBuf + seedLen, seedLen, sk, dimN, algId), ret);
    RETURN_RET_IF(PQCP_POLAR_LAC_SampleSparseTernaryVector(NULL, Q, randBuf + seedLen * 2, seedLen, e, dimN, algId),
                  ret);
    PQCP_POLAR_LAC_PolyAff(a, sk, e, pk + seedLen, dimN, algId);
    // copy pk=as+e to the second part of sk, now sk=s|pk
    memcpy_s(sk + skLen - pkLen, pkLen, pk, pkLen);
    return PQCP_SUCCESS;
}

// encryption with seed
int32_t PQCP_POLAR_LAC_PkeEncrypt(const CRYPT_POLAR_LAC_Ctx *ctx, const uint8_t *m, uint8_t *c,
                                  uint32_t *clen, uint8_t *seed)
{
    const uint8_t *pk = ctx->pk;
    uint32_t dimN = ctx->info->dimN;
    uint32_t c2VecNum = ctx->info->c2VecNum;
    uint32_t seedLen = ctx->info->seedLen;

    uint8_t r[dimN];
    uint8_t e1[dimN], e2[dimN];
    uint8_t c2[c2VecNum];
    uint8_t a[dimN];
    uint8_t randBuf[seedLen * 3];
    int32_t c2Len;
    int32_t ret = 0;
    // gen_a(a,pk);
    RETURN_RET_IF(PQCP_POLAR_LAC_SamplePolyA(NULL, Q, pk, seedLen, a, dimN), ret);
    RETURN_RET_IF(PQCP_POLAR_LAC_PseudoRandomBytes(NULL, seed, seedLen, randBuf, seedLen * 3), ret);
    RETURN_RET_IF(PQCP_POLAR_LAC_SampleSparseTernaryVector(NULL, Q, randBuf, seedLen, r, dimN, ctx->algId), ret);
    RETURN_RET_IF(PQCP_POLAR_LAC_SampleSparseTernaryVector(NULL, Q, randBuf + seedLen, seedLen, e1, dimN, ctx->algId),
                  ret);
    RETURN_RET_IF(
        PQCP_POLAR_LAC_SampleSparseTernaryVector(NULL, Q, randBuf + 2 * seedLen, seedLen, e2, dimN, ctx->algId), ret);
    EncodeToE2(e2, m, &c2Len, ctx->algId);
    if (ctx->algId == PQCP_POLAR_LAC_LIGHT) {
        uint8_t c1[dimN];
        // generate c1: c1=a*r+e1
        PQCP_POLAR_LAC_PolyAff(a, r, e1, c1, dimN, ctx->algId);
        // compress c1
        PQCP_POLAR_LAC_PolyCompress(c1, c, dimN, 7);
        // generate c2: c2=b*r+e2+m*[q/2]
        PQCP_POLAR_LAC_PolyAff(pk + seedLen, r, e2, c2, c2Len, ctx->algId);
        // compress c2
        PQCP_POLAR_LAC_PolyCompress(c2, c + dimN * 7 / 8, c2Len, 4);
        *clen = dimN * 7 / 8 + c2Len / 2;
    } else if (ctx->algId == PQCP_POLAR_LAC_128) {
        uint8_t c1[dimN];
        // generate c1: c1=a*r+e1
        PQCP_POLAR_LAC_PolyAff(a, r, e1, c1, dimN, ctx->algId);
        // compress c1
        PQCP_POLAR_LAC_PolyCompress(c1, c, dimN, 7);
        // generate c2: c2=b*r+e2+m*[q/2]
        PQCP_POLAR_LAC_PolyAff(pk + seedLen, r, e2, c2, c2Len, ctx->algId);
        // compress c2
        PQCP_POLAR_LAC_PolyCompress(c2, c + dimN * 7 / 8, c2Len, 3);
        *clen = dimN * 7 / 8 + c2Len * 3 / 8;
    } else if (ctx->algId == PQCP_POLAR_LAC_256) {
        // generate c1: c1=a*r+e1
        PQCP_POLAR_LAC_PolyAff(a, r, e1, c, dimN, ctx->algId);
        // generate c2: c2=b*r+e2+m*[q/2]
        PQCP_POLAR_LAC_PolyAff(pk + seedLen, r, e2, c2, c2Len, ctx->algId);
        // compress c2
        PQCP_POLAR_LAC_PolyCompress(c2, c + dimN, c2Len, 4);
        *clen = dimN + c2Len / 2;
    }
    return PQCP_SUCCESS;
}

int32_t PQCP_POLAR_LAC_PkeDecrypt(const CRYPT_POLAR_LAC_Ctx *ctx, const uint8_t *c, uint32_t clen, uint8_t *m,
                                  uint32_t *mlen)
{
    uint8_t *sk = ctx->sk;
    uint32_t dimN = ctx->info->dimN;
    uint32_t msgLen = ctx->info->msgLen;
    uint32_t c2VecNum = ctx->info->c2VecNum;

    uint32_t codeLen = ctx->algId == PQCP_POLAR_LAC_LIGHT ? 32 : 64;
    uint8_t out[dimN];
    uint8_t c2[c2VecNum];
    uint8_t mBuf[msgLen];
    float llr[codeLen * 8]; // log-likelihood ratio of the received signal

    int32_t temp;
    int32_t half = 126; // Q/2
    int32_t halfTwo = 63; // half/2
    uint8_t mCap[msgLen * 8]; // estimated message(each element stores 1 bit)
    int32_t c2Len = 0;
    if (ctx->algId == PQCP_POLAR_LAC_LIGHT) {
        uint8_t c1[dimN];
        c2Len = (clen - dimN * 7 / 8) * 2;
        // c1 decompress
        PQCP_POLAR_LAC_PolyDecompress(c, c1, dimN, 7);
        // c2 decompress
        PQCP_POLAR_LAC_PolyDecompress(c + dimN * 7 / 8, c2, c2Len, 4);
        // c1*sk
        PQCP_POLAR_LAC_PolyMul(c1, sk, out, c2Len, ctx->algId);
    } else if (ctx->algId == PQCP_POLAR_LAC_128) {
        uint8_t c1[dimN];
        c2Len = (clen - dimN * 7 / 8) / 3 * 8;
        // c1 decompress
        PQCP_POLAR_LAC_PolyDecompress(c, c1, dimN, 7);
        // c2 decompress
        PQCP_POLAR_LAC_PolyDecompress(c + dimN * 7 / 8, c2, c2Len, 3);
        // c1*sk
        PQCP_POLAR_LAC_PolyMul(c1, sk, out, c2Len, ctx->algId);
    } else {
        c2Len = (clen - dimN) * 2;
        // c2 decompress
        PQCP_POLAR_LAC_PolyDecompress(c + dimN, c2, c2Len, 4);
        // c1*sk
        PQCP_POLAR_LAC_PolyMul(c, sk, out, c2Len, ctx->algId);
    }

    uint32_t dataLen = ctx->algId == PQCP_POLAR_LAC_256 ? 32 : 16;
    *mlen = dataLen;
    // compute llr
    for (int32_t i = 0; i < c2Len; i++) {
        // compute m*q/2+e in [0,250]
        temp = (c2[i] - out[i] + Q) % Q;
        // m*q/2+e in [-63,187]=[-63,125]+[126,187]
        temp = temp - halfTwo;
        // m*q/2+e in [-125,125]
        if (temp >= half) {
            temp = temp - Q; // [126,187]——>[-125,-64]
        }
        llr[i] = -(float)temp / halfTwo; // 0 is modulated to -q/4, and 1 is modulated to q/4
    }

    // polar decode to recover m
    PQCP_POLAR_LAC_DecodePolar(mCap, llr, ctx->algId);
    // each element stores 1 binary value -> each element stores 8 binary values
    memset_s(mBuf, msgLen, 0, msgLen);
    for (uint32_t i = 0; i < msgLen; i++) {
        for (uint32_t j = 0; j < 8; j++) {
            mBuf[i] |= (mCap[8 * i + j] << j);
        }
    }

    memcpy_s(m, *mlen, mBuf, *mlen);
    return PQCP_SUCCESS;
}
#endif // PQCP_POLARLAC