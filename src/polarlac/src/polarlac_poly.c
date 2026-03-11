/* Copyright (c) 2025 LiuYing, ZhangYu
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

#include "bsl_sal.h"
#include "polarlac_local.h"
#include "pqcp_err.h"

#define POLAR_LAC_256_DIM 1024
#define POLAR_LAC_LIGHT_128_DIM 512

static void PQCP_POLAR_LAC_PolyMulNttLazy(const uint16_t *a, const uint16_t *s, uint16_t *b)
{
    int32_t i;
    int16_t aBuf[POLAR_LAC_LIGHT_128_DIM], sBuf[POLAR_LAC_LIGHT_128_DIM], bBuf[POLAR_LAC_LIGHT_128_DIM];

    for (i = 0; i < POLAR_LAC_LIGHT_128_DIM; i++) {
        aBuf[i] = a[i];
        sBuf[i] = s[i];
    }

    // NTT form
    PQCP_POLAR_LAC_NttLazy(aBuf);
    PQCP_POLAR_LAC_NttLazy(sBuf);

    // point mul
    for (i = 0; i < POLAR_LAC_LIGHT_128_DIM; i++) {
        bBuf[i] = MontgomeryMapFull((int32_t)aBuf[i] * (int32_t)sBuf[i]);
        // There will introduced a Montgomery factor β^(-1) mod NTTQ
        // So we perform the multiplication with N^(-1)*β mod NTTQ in the final step of INTT
    }

    // INTT form
    PQCP_POLAR_LAC_InttLazy(bBuf);

    // mod Q
    for (i = 0; i < POLAR_LAC_LIGHT_128_DIM; i++) {
        b[i] = (bBuf[i] + NTTQ) % NTTQ; // To ensure the results are all positive numbers.
    }
}

static void PQCP_POLAR_LAC_PolyMulNttLazy1024(const uint16_t *a, const uint16_t *s, uint16_t *b)
{
    int32_t i;
    int16_t aBuf[POLAR_LAC_256_DIM], sBuf[POLAR_LAC_256_DIM], bBuf[POLAR_LAC_256_DIM];

    for (i = 0; i < POLAR_LAC_256_DIM; i++) {
        aBuf[i] = a[i];
        sBuf[i] = s[i];
    }

    // NTT form
    PQCP_PQCP_POLAR_LAC_NttLazy1024(aBuf);
    PQCP_PQCP_POLAR_LAC_NttLazy1024(sBuf);

    // point mul
    for (i = 0; i < POLAR_LAC_256_DIM; i++) {
        bBuf[i] = MontgomeryMapFull((int32_t)aBuf[i] * (int32_t)sBuf[i]);
    }

    // INTT form
    PQCP_PQCP_POLAR_LAC_InttLazy1024(bBuf);

    // mod Q
    for (i = 0; i < POLAR_LAC_256_DIM; i++) {
        b[i] = (bBuf[i] + NTTQ) % NTTQ;
    }
}
// b=as using compact lift multiplication with constant time.
void PQCP_POLAR_LAC_PolyMul(const uint8_t *a, const uint8_t *s, uint8_t *b, uint32_t vecNum, int32_t algId)
{
    uint32_t i;
    uint32_t dimN = algId == PQCP_POLAR_LAC_256 ? 1024 : 512;
    uint16_t a2[dimN], s2[dimN], b2[dimN];
    uint16_t mask;
    uint16_t a1, a2Tmp, s1, s2Tmp, b1, b2Tmp;

    // step 1: map to the lifted ring with NTTQ as the modulus
    for (i = 0; i < dimN; i++) {
        mask = (a[i] >= q_half);
        a1 = a[i] + Q_sub_q;
        a2Tmp = a[i] + NTTQ;
        a2[i] = (a1 & (-mask)) | (a2Tmp & (~(-mask)));
    }

    for (i = 0; i < dimN; i++) {
        mask = (s[i] >= q_half);
        s1 = s[i] + Q_sub_q;
        s2Tmp = s[i] + NTTQ;
        s2[i] = (s1 & (-mask)) | (s2Tmp & (~(-mask)));
    }
    if (algId == PQCP_POLAR_LAC_128 || algId == PQCP_POLAR_LAC_LIGHT) {
        PQCP_POLAR_LAC_PolyMulNttLazy(a2, s2, b2);
    } else {
        PQCP_POLAR_LAC_PolyMulNttLazy1024(a2, s2, b2);
    }
    // step 3: map back to the original ring with Q as the modulus
    for (i = 0; i < vecNum; i++) {
        mask = (b2[i] < Q_half);
        b1 = b2[i] + NTTQ;
        b2Tmp = b2[i];
        b2[i] = (b1 & (-mask)) | (b2Tmp & (~(-mask)));
        b[i] = (b2[i] + neg_Q_mod_q) % Q;
    }
}

// b=as+e using compact lift multiplication with constant time.
void PQCP_POLAR_LAC_PolyAff(const uint8_t *a, const uint8_t *s, uint8_t *e, uint8_t *b, uint32_t vecNum, int32_t algId)
{
    uint32_t i;
    uint32_t dimN = algId == PQCP_POLAR_LAC_256 ? 1024 : 512;
    uint16_t a2[dimN], s2[dimN], b2[dimN];

    uint16_t mask;
    uint16_t a1, a2Tmp, s1, s2Tmp, b1, b2Tmp;
    for (i = 0; i < dimN; i++) {
        mask = (a[i] >= q_half);
        a1 = a[i] + Q_sub_q;
        a2Tmp = a[i] + NTTQ;
        a2[i] = (a1 & (-mask)) | (a2Tmp & (~(-mask)));
    }

    for (i = 0; i < dimN; i++) {
        mask = (s[i] >= q_half);
        s1 = s[i] + Q_sub_q;
        s2Tmp = s[i] + NTTQ;
        s2[i] = (s1 & (-mask)) | (s2Tmp & (~(-mask)));
    }
    if (algId == PQCP_POLAR_LAC_LIGHT || algId == PQCP_POLAR_LAC_128) {
        PQCP_POLAR_LAC_PolyMulNttLazy(a2, s2, b2);
    } else {
        PQCP_POLAR_LAC_PolyMulNttLazy1024(a2, s2, b2);
    }

    for (i = 0; i < vecNum; i++) {
        mask = (b2[i] < Q_half);
        b1 = b2[i] + NTTQ;
        b2Tmp = b2[i];
        b2[i] = (b1 & (-mask)) | (b2Tmp & (~(-mask)));
        b2[i] = (b2[i] + neg_Q_mod_q) % Q;
        b[i] = (b2[i] + e[i] + Q) % Q;
    }
}

// Compression: c1 discards 1-bit
static void PolarLacPolyCompressC1OneBit(const uint8_t *in, uint8_t *out, const uint32_t vecNum)
{
    int32_t i;
    int32_t j;
    int32_t loop;
    loop = vecNum / 8;
    for (i = 0; i < loop; i++) {
        uint8_t buf[8];
        for (j = 0; j < 8; j++) {
            buf[j] = (in[i * 8 + j]) >> 1;
        }

        out[i * 7 + 0] = (buf[1] << 7) | buf[0];
        out[i * 7 + 1] = (buf[2] << 6) | (buf[1] >> 1);
        out[i * 7 + 2] = (buf[3] << 5) | (buf[2] >> 2);
        out[i * 7 + 3] = (buf[4] << 4) | (buf[3] >> 3);
        out[i * 7 + 4] = (buf[5] << 3) | (buf[4] >> 4);
        out[i * 7 + 5] = (buf[6] << 2) | (buf[5] >> 5);
        out[i * 7 + 6] = (buf[7] << 1) | (buf[6] >> 6);
    }
}
static void PolarLacPolyDecompressC1OneBit(const uint8_t *in, uint8_t *out, const uint32_t vecNum)
{
    int32_t i;
    int32_t loop;
    loop = vecNum / 8;
    for (i = 0; i < loop; i++) {
        out[i * 8 + 0] = (in[i * 7 + 0] << 1) + 0b00000001;
        out[i * 8 + 1] = ((in[i * 7 + 1] << 2) | ((in[i * 7 + 0] & 0b10000000) >> 6)) + 0b00000001;
        out[i * 8 + 2] = ((in[i * 7 + 2] << 3) | ((in[i * 7 + 1] & 0b11000000) >> 5)) + 0b00000001;
        out[i * 8 + 3] = ((in[i * 7 + 3] << 4) | ((in[i * 7 + 2] & 0b11100000) >> 4)) + 0b00000001;
        out[i * 8 + 4] = ((in[i * 7 + 4] << 5) | ((in[i * 7 + 3] & 0b11110000) >> 3)) + 0b00000001;
        out[i * 8 + 5] = ((in[i * 7 + 5] << 6) | ((in[i * 7 + 4] & 0b11111000) >> 2)) + 0b00000001;
        out[i * 8 + 6] = ((in[i * 7 + 6] << 7) | ((in[i * 7 + 5] & 0b11111100) >> 1)) + 0b00000001;
        out[i * 8 + 7] = (in[i * 7 + 6] & 0b11111110) + 0b00000001;
    }
}

// Compression: c2 discards 4-bit
static void PolarLacPolyCompressC2FourBit(const uint8_t *in, uint8_t *out, const uint32_t vecNum)
{
    int32_t i;
    int32_t loop;
    loop = vecNum / 2;
    for (i = 0; i < loop; i++) {
        out[i] = (in[i * 2]) >> 4;
        out[i] = out[i] ^ (in[i * 2 + 1] & 0xf0);
    }
}

static void PolarLacPolyDecompressC2FourBit(const uint8_t *in, uint8_t *out, const uint32_t vecNum)
{
    int32_t i;
    int32_t loop;
    loop = vecNum / 2;
    for (i = 0; i < loop; i++) {
        out[i * 2] = (in[i] << 4) ^ 0x08;
        out[i * 2 + 1] = (in[i] & 0xf0) ^ 0x08;
    }
}

// Compression: c2 discards 5-bit
static void PolarLacPolyCompressC2FiveBit(const uint8_t *in, uint8_t *out, const uint32_t vecNum)
{
    int32_t i;
    int32_t j;
    int32_t loop;
    loop = vecNum / 8;
    for (i = 0; i < loop; i++) {
        uint8_t buf[8];
        for (j = 0; j < 8; j++) {
            buf[j] = in[i * 8 + j] >> 5;
        }

        out[i * 3 + 0] = (buf[2] << 6) | (buf[1] << 3) | buf[0];
        out[i * 3 + 1] = (buf[5] << 7) | (buf[4] << 4) | (buf[3] << 1) | (buf[2] >> 2);
        out[i * 3 + 2] = (buf[7] << 5) | (buf[6] << 2) | (buf[5] >> 1);
    }
}

static void PolarLacPolyDecompressC2FiveBit(const uint8_t *in, uint8_t *out, const uint32_t vecNum)
{
    int32_t i;
    int32_t loop;
    loop = vecNum / 8;
    for (i = 0; i < loop; i++) {
        out[i * 8 + 0] = (in[i * 3 + 0] << 5) + 0b00010000;
        out[i * 8 + 1] = ((in[i * 3 + 0] & 0b00111000) << 2) + 0b00010000;
        out[i * 8 + 2] = ((in[i * 3 + 1] << 7) | (in[i * 3 + 0] & 0b11000000) >> 1) + 0b00010000;
        out[i * 8 + 3] = ((in[i * 3 + 1] & 0b00001110) << 4) + 0b00010000;
        out[i * 8 + 4] = ((in[i * 3 + 1] & 0b01110000) << 1) + 0b00010000;
        out[i * 8 + 5] = ((in[i * 3 + 2] << 6) | (in[i * 3 + 1] & 0b10000000) >> 2) + 0b00010000;
        out[i * 8 + 6] = ((in[i * 3 + 2] & 0b00011100) << 3) + 0b00010000;
        out[i * 8 + 7] = (in[i * 3 + 2] & 0b11100000) + 0b00010000;
    }
}

int32_t PQCP_POLAR_LAC_PolyCompress(const uint8_t *in, uint8_t *out, const uint32_t vecNum, const uint32_t bits)
{
    switch (bits) {
        case 7:
            PolarLacPolyCompressC1OneBit(in, out, vecNum);
            break;
        case 4:
            PolarLacPolyCompressC2FourBit(in, out, vecNum);
            break;
        case 3:
            PolarLacPolyCompressC2FiveBit(in, out, vecNum);
            break;
        default:
            return PQCP_INVALID_ARG;
    }
    return PQCP_SUCCESS;
}

int32_t PQCP_POLAR_LAC_PolyDecompress(const uint8_t *in, uint8_t *out, const uint32_t vecNum, const uint32_t bits)
{
    switch (bits) {
        case 7:
            PolarLacPolyDecompressC1OneBit(in, out, vecNum);
            break;
        case 4:
            PolarLacPolyDecompressC2FourBit(in, out, vecNum);
            break;
        case 3:
            PolarLacPolyDecompressC2FiveBit(in, out, vecNum);
            break;
        default:
            return PQCP_INVALID_ARG;
    }
    return PQCP_SUCCESS;
}
#endif // PQCP_POLARLAC