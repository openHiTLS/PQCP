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

#include <stdlib.h>
#include <string.h>
#include "frodo_local.h"
#include "internal/frodo_params.h"
#include "crypt_eal_cipher.h"
#include "pqcp_err.h"

// function signature of multiplication when PRNG = AES
typedef void (*MultFunctionAES)(uint16_t* out, const uint16_t* matrixS, int n, int nBar, uint16_t* rows, int rowNumber);

// multiplication function used in SA+E (AES version)
void MultSaPlusEAES(uint16_t* out, const uint16_t* matrixS, int n, int nBar, uint16_t* rows, int rowNumber);

// multiplication function used in AS+E (AES version)
void MultAsPlusEAES(uint16_t* out, const uint16_t* matrixST, int n, int nBar, uint16_t* rows, int rowNumber);

// function signature of multiplication when PRNG = SHAKE
typedef void (*MultFunctionSHAKE)(uint16_t* out, const uint16_t* matrixS, int n, int nBar, uint16_t* row0,
                                  uint16_t* row1, uint16_t* row2, uint16_t* row3, int rowNumber);

// multiplication function used in AS+E (SHAKE version)
void MulAsPlusESHAKE(uint16_t* out, const uint16_t* matrixST, int n, int nbar, uint16_t* row0, uint16_t* row1,
                     uint16_t* row2, uint16_t* row3, int rowNumber);

// multiplication function used in SA+E (SHAKE version)
void MulSaPlusESHAKE(uint16_t* out, const uint16_t* matrixS, int n, int nBar, uint16_t* row0, uint16_t* row1,
                     uint16_t* row2, uint16_t* row3, int rowNumber);

// initialize AES context
CRYPT_EAL_CipherCtx* InitRandCtx(const uint8_t* seedA, int* ret);

// initialize AES plaintext header
void InitAESHeaderBlockNumber(uint8_t* AES_PT, const int blocks_per_row);

// AES ctr mode encryption
int AESCtrEncrypt(int n, uint16_t* rows, uint8_t* plaintext, CRYPT_EAL_CipherCtx* randCtx, int blocksPerRow,
                  int rowNumber);

int FrodoCommonMulAddAsPlusESHAKE(uint16_t* out, const uint16_t* matrixST, const uint8_t* seedA,
                                  const FrodoKemParams* params, const int n, const int nbar,
                                  uint16_t rows[5376], uint8_t seeds[72], MultFunctionSHAKE multFunction);

int FrodoCommonMulAddAES(uint16_t* out, const uint16_t* matrixSTranspose, const uint8_t* seedA, const int n,
                         const int nbar, uint16_t rows[5376], uint8_t plaintext[10752],
                         MultFunctionAES multFunction)
{
    int ret = 0;
    CRYPT_EAL_CipherCtx* randCtx = InitRandCtx(seedA, &ret);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }

    const int blocksPerRow = n / 8;
    InitAESHeaderBlockNumber(plaintext, blocksPerRow);

    for (int rowNumber = 0; rowNumber < n; rowNumber += 4) {
        ret = AESCtrEncrypt(n, rows, plaintext, randCtx, blocksPerRow, rowNumber);
        if (ret != PQCP_SUCCESS) {
            goto EXIT;
        }

        multFunction(out, matrixSTranspose, n, nbar, rows, rowNumber);
    }

EXIT:
    CRYPT_EAL_CipherFreeCtx(randCtx);
    return ret;
}

int FrodoCommonMulAddAsPlusEPortable(uint16_t* out,
                                     const uint16_t* matrixST,
                                     const uint8_t* seedA,
                                     const FrodoKemParams* params)
{
    const int N = params->n;
    const int nBar = params->nBar;

#define FRODO_MAX_N         1344
#define FRODO_MAX_SEED_A    16

    ALIGN_HEADER(32) uint16_t rows[4 * FRODO_MAX_N] ALIGN_FOOTER(32);

    if (params->prg == FRODO_PRG_AES) {
        ALIGN_HEADER(32) uint8_t plaintext[4 * 16 * (FRODO_MAX_N / 8)] ALIGN_FOOTER(32);
        return FrodoCommonMulAddAES(out, matrixST, seedA, N, nBar, rows, plaintext, MultAsPlusEAES);
    } else {
        ALIGN_HEADER(32) uint8_t seeds[4 * (2 + FRODO_MAX_SEED_A)] ALIGN_FOOTER(32);
        return FrodoCommonMulAddAsPlusESHAKE(out, matrixST, seedA, params, N, nBar, rows, seeds, MulAsPlusESHAKE);
    }
}

int FrodoCommonMulAddSaPlusEPortable(uint16_t* out,
                                     const uint16_t* s,
                                     const uint16_t* e,
                                     const uint8_t* seedA,
                                     const FrodoKemParams* params)
{
    const int n = params->n;
    const int nBar = params->nBar;

    for (int i = 0; i < nBar * n; i += 2) {
        *((uint32_t*)&out[i]) = *((const uint32_t*)&e[i]);
    }

#define FRODO_MAX_N         1344
#define FRODO_MAX_SEED_A    16

    ALIGN_HEADER(32) uint16_t rows[4 * FRODO_MAX_N] ALIGN_FOOTER(32);
    if (params->prg == FRODO_PRG_AES) {
        ALIGN_HEADER(32) uint8_t plaintext[4 * 16 * (FRODO_MAX_N / 8)] ALIGN_FOOTER(32);
        return FrodoCommonMulAddAES(out, s, seedA, n, nBar, rows, plaintext, MultSaPlusEAES);
    } else {
        ALIGN_HEADER(32) uint8_t seeds[4 * (2 + FRODO_MAX_SEED_A)] ALIGN_FOOTER(32);
        return FrodoCommonMulAddAsPlusESHAKE(out, s, seedA, params, n, nBar, rows, seeds, MulSaPlusESHAKE);
    }
}

int FrodoCommonMulAddSbPlusEPortable(uint16_t* V0,
                                     const uint16_t* STp,
                                     const uint16_t* B,
                                     const uint16_t* Epp,
                                     const FrodoKemParams* params)
{
    const size_t n = params->n;
    const size_t nbar = params->nBar;
    const uint16_t qmask = (uint16_t)((1u << params->logq) - 1u);

    for (size_t i = 0; i < nbar * nbar; i++) V0[i] = (uint16_t)(Epp[i] & qmask);

    for (size_t i = 0; i < nbar; i++) {
        const size_t Si = i * n;
        const size_t Vi = i * nbar;
        for (size_t k = 0; k < n; k++) {
            const uint32_t s = (uint32_t)(STp[Si + k] & qmask);
            const size_t Bk = k * nbar;
            for (size_t j = 0; j < nbar; j++) {
                const uint32_t b = (uint32_t)(B[Bk + j] & qmask);
                uint32_t acc = (uint32_t)V0[Vi + j] + s * b;
                V0[Vi + j] = (uint16_t)(acc & qmask);
            }
        }
    }
    return 0;
}

void FrodoCommonMulBs(uint16_t* out, const uint16_t* b, const uint16_t* s,
                      const FrodoKemParams* params)
{
    const size_t n = params->n, nbar = params->nBar;
    const uint16_t qmask = (uint16_t)((1u << params->logq) - 1u);

    for (size_t i = 0; i < nbar; i++) {
        for (size_t j = 0; j < nbar; j++) {
            uint64_t acc = 0;
            for (size_t k = 0; k < n; k++) {
                acc += (uint32_t)(b[i * n + k] & qmask) * (uint32_t)(s[k * nbar + j] & qmask);
            }
            out[i * nbar + j] = (uint16_t)(acc & qmask);
        }
    }
}

void FrodoCommonMulBsUsingSt(uint16_t* out, const uint16_t* b, const uint16_t* sT,
                             const FrodoKemParams* params)
{
    const size_t n = params->n, nbar = params->nBar;
    const uint16_t qmask = (uint16_t)((1u << params->logq) - 1u);
    for (size_t i = 0; i < nbar; i++) {
        for (size_t j = 0; j < nbar; j++) {
            uint64_t acc = 0;
            for (size_t k = 0; k < n; k++) {
                uint16_t b_ik = b[i * n + k] & qmask;
                uint16_t s_kj = sT[j * n + k] & qmask;
                acc += (uint32_t)b_ik * s_kj;
            }
            out[i * nbar + j] = (uint16_t)(acc & qmask);
        }
    }
}

void FrodoCommonAdd(uint16_t* out, const uint16_t* a, const uint16_t* b,
                    const FrodoKemParams* params)
{
    const size_t ncoeff = (size_t)params->nBar * params->nBar;
    const uint16_t qmask = (uint16_t)((1u << params->logq) - 1u);
    for (size_t t = 0; t < ncoeff; t++) {
        uint32_t sum = (uint32_t)(a[t] & qmask) + (uint32_t)(b[t] & qmask);
        out[t] = (uint16_t)(sum & qmask);
    }
}

void FrodoCommonSub(uint16_t* out, const uint16_t* a, const uint16_t* b,
                    const FrodoKemParams* params)
{
    const size_t ncoeff = (size_t)params->nBar * params->nBar;
    const uint16_t qmask = (uint16_t)((1u << params->logq) - 1u);
    for (size_t t = 0; t < ncoeff; t++) {
        uint32_t diff = (uint32_t)(a[t] & qmask) - (uint32_t)(b[t] & qmask);
        out[t] = (uint16_t)(diff & qmask); // q=2^k 时，& qmask 等价于 mod q
    }
}

void FrodoCommonKeyEncode(uint16_t* out,
                          const uint16_t* in,
                          const FrodoKemParams* params)
{
    const uint8_t* mu = (const uint8_t*)in;
    const size_t total = (size_t)params->nBar * params->nBar;
    const unsigned b = (unsigned)params->extractedBits;
    const uint16_t factor = (uint16_t)(1u << (params->logq - b));

    size_t bitpos = 0;
    for (size_t t = 0; t < total; t++) {
        uint32_t x = 0;
        for (unsigned r = 0; r < b; r++, bitpos++) {
            uint8_t byte = mu[bitpos >> 3];
            unsigned s = bitpos & 7;
            x |= ((byte >> s) & 1u) << r;
        }
        out[t] = (uint16_t)(x * factor);
    }
}

void FrodoCommonKeyDecode(uint16_t* out,
                          const uint16_t* in,
                          const FrodoKemParams* params)
{
    uint8_t* mu = (uint8_t*)out;

    const size_t total = (size_t)params->nBar * params->nBar;
    const unsigned b = (unsigned)params->extractedBits;
    const unsigned s = (unsigned)(params->logq - b);
    const uint16_t round = (uint16_t)(1u << (s - 1));
    const uint16_t mask = (uint16_t)((1u << b) - 1u);

    memset(mu, 0, params->lenMu);

    size_t bitpos = 0;
    for (size_t t = 0; t < total; t++) {
        uint16_t v = in[t];
        uint16_t piece = (uint16_t)(((uint32_t)v + round) >> s) & mask;

        for (unsigned r = 0; r < b; r++, bitpos++) {
            if ((piece >> r) & 1u) {
                mu[bitpos >> 3] |= (uint8_t)(1u << (bitpos & 7));
            }
        }
    }
}

#define U16ToBytesLE(val, bytes) \
    (bytes)[0] = (val) & 0xff; \
    (bytes)[1] = (val) >> 8;

CRYPT_EAL_CipherCtx* InitRandCtx(const uint8_t* seedA, int* ret)
{
    CRYPT_EAL_CipherCtx* randCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_ECB);
    if (randCtx == NULL) {
        *ret = PQCP_MALLOC_FAIL;
        return NULL;
    }

    *ret = CRYPT_EAL_CipherInit(randCtx, seedA, 16, NULL, 0, true);
    if (*ret != PQCP_SUCCESS) {
        return randCtx;
    }
    *ret = CRYPT_EAL_CipherSetPadding(randCtx, CRYPT_PADDING_NONE);

    return randCtx;
}

void InitAESHeaderBlockNumber(uint8_t* AES_PT, const int blocks_per_row)
{
    for (int blk = 0; blk < blocks_per_row; blk++) {
        for (int r = 0; r < 4; r++) {
            uint8_t* P = &AES_PT[16 * (blk + r * blocks_per_row)];
            U16ToBytesLE(blk << 3, P + 2);
            for (int t = 4; t < 16; t++) P[t] = 0;
        }
    }
}

// ctr mode AES encryption
int AESCtrEncrypt(const int n, uint16_t* rows, uint8_t* plaintext, CRYPT_EAL_CipherCtx* randCtx, const int blocksPerRow,
                  int rowNumber)
{
    for (int blk = 0; blk < blocksPerRow; blk++) {
        U16ToBytesLE(rowNumber + 0, &plaintext[16 * (blk + 0 * blocksPerRow)]);
        U16ToBytesLE(rowNumber + 1, &plaintext[16 * (blk + 1 * blocksPerRow)]);
        U16ToBytesLE(rowNumber + 2, &plaintext[16 * (blk + 2 * blocksPerRow)]);
        U16ToBytesLE(rowNumber + 3, &plaintext[16 * (blk + 3 * blocksPerRow)]);
    }

    int outLen = 4 * blocksPerRow * 16;
    int ret = CRYPT_EAL_CipherUpdate(randCtx, plaintext, (size_t)outLen, (uint8_t*)rows, &outLen);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }

    for (int k = 0; k < 4 * n; k++) {
        rows[k] = (uint16_t)LE_TO_UINT16(rows[k]);
    }
    return 0;
}

void MultAsPlusEAES(uint16_t* out, const uint16_t* matrixST, const int n, const int nBar, uint16_t* rows,
                    int rowNumber)
{
    const uint16_t* row0 = &rows[0 * n];
    const uint16_t* row1 = &rows[1 * n];
    const uint16_t* row2 = &rows[2 * n];
    const uint16_t* row3 = &rows[3 * n];

    for (int j = 0; j < nBar; j++) {
        const uint16_t* ST_row = &matrixST[j * n];
        uint16_t sum0 = 0, sum1 = 0, sum2 = 0, sum3 = 0;
        for (int k = 0; k < n; k++) {
            uint16_t sv = ST_row[k];
            sum0 += (uint16_t)((uint32_t)row0[k] * sv);
            sum1 += (uint16_t)((uint32_t)row1[k] * sv);
            sum2 += (uint16_t)((uint32_t)row2[k] * sv);
            sum3 += (uint16_t)((uint32_t)row3[k] * sv);
        }
        out[(rowNumber + 0) * nBar + j] = (uint16_t)(out[(rowNumber + 0) * nBar + j] + sum0);
        out[(rowNumber + 1) * nBar + j] = (uint16_t)(out[(rowNumber + 1) * nBar + j] + sum1);
        out[(rowNumber + 2) * nBar + j] = (uint16_t)(out[(rowNumber + 2) * nBar + j] + sum2);
        out[(rowNumber + 3) * nBar + j] = (uint16_t)(out[(rowNumber + 3) * nBar + j] + sum3);
    }
}

void MultSaPlusEAES(uint16_t* out, const uint16_t* matrixS, const int n, const int nBar, uint16_t* rows, int rowNumber)
{
    const uint16_t* row0 = &rows[0 * n];
    const uint16_t* row1 = &rows[1 * n];
    const uint16_t* row2 = &rows[2 * n];
    const uint16_t* row3 = &rows[3 * n];

    for (int k = 0; k < nBar; k++) {
        const uint16_t s0 = matrixS[k * n + (rowNumber + 0)];
        const uint16_t s1 = matrixS[k * n + (rowNumber + 1)];
        const uint16_t s2 = matrixS[k * n + (rowNumber + 2)];
        const uint16_t s3 = matrixS[k * n + (rowNumber + 3)];

        uint16_t* out_row = &out[k * n];
        for (int j = 0; j < n; j++) {
            uint16_t acc = out_row[j];
            acc = (uint16_t)(acc + (uint16_t)(row0[j] * s0));
            acc = (uint16_t)(acc + (uint16_t)(row1[j] * s1));
            acc = (uint16_t)(acc + (uint16_t)(row2[j] * s2));
            acc = (uint16_t)(acc + (uint16_t)(row3[j] * s3));
            out_row[j] = acc;
        }
    }
}

void MulAsPlusESHAKE(uint16_t* out, const uint16_t* matrixST, const int n, const int nbar, uint16_t* row0,
                     uint16_t* row1, uint16_t* row2, uint16_t* row3, int rowNumber)
{
    for (int j = 0; j < nbar; j++) {
        const uint16_t* ST_row = &matrixST[j * n];
        uint16_t sum0 = 0, sum1 = 0, sum2 = 0, sum3 = 0;
        for (int k = 0; k < n; k++) {
            uint16_t sv = ST_row[k];
            sum0 += (uint16_t)((uint32_t)row0[k] * sv);
            sum1 += (uint16_t)((uint32_t)row1[k] * sv);
            sum2 += (uint16_t)((uint32_t)row2[k] * sv);
            sum3 += (uint16_t)((uint32_t)row3[k] * sv);
        }
        out[(rowNumber + 0) * nbar + j] = (uint16_t)(out[(rowNumber + 0) * nbar + j] + sum0);
        out[(rowNumber + 1) * nbar + j] = (uint16_t)(out[(rowNumber + 1) * nbar + j] + sum1);
        out[(rowNumber + 2) * nbar + j] = (uint16_t)(out[(rowNumber + 2) * nbar + j] + sum2);
        out[(rowNumber + 3) * nbar + j] = (uint16_t)(out[(rowNumber + 3) * nbar + j] + sum3);
    }
}

void MulSaPlusESHAKE(uint16_t* out, const uint16_t* matrixS, const int n, const int nBar, uint16_t* row0,
                     uint16_t* row1,
                     uint16_t* row2, uint16_t* row3, int rowNumber)
{
    for (int k = 0; k < nBar; k++) {
        const uint16_t s0 = matrixS[k * n + (rowNumber + 0)];
        const uint16_t s1 = matrixS[k * n + (rowNumber + 1)];
        const uint16_t s2 = matrixS[k * n + (rowNumber + 2)];
        const uint16_t s3 = matrixS[k * n + (rowNumber + 3)];

        uint16_t* out_row = &out[k * n];
        for (int j = 0; j < n; j++) {
            uint16_t acc = out_row[j];
            acc = (uint16_t)(acc + (uint16_t)(row0[j] * s0));
            acc = (uint16_t)(acc + (uint16_t)(row1[j] * s1));
            acc = (uint16_t)(acc + (uint16_t)(row2[j] * s2));
            acc = (uint16_t)(acc + (uint16_t)(row3[j] * s3));
            out_row[j] = acc;
        }
    }
}

int FrodoCommonMulAddAsPlusESHAKE(uint16_t* out, const uint16_t* matrixST, const uint8_t* seedA,
                                  const FrodoKemParams* params, const int n, const int nbar,
                                  uint16_t rows[5376], uint8_t seeds[72], MultFunctionSHAKE multFunction)
{
    const size_t inlen = 2 + (size_t)params->lenSeedA;
    uint8_t* in0 = &seeds[0 * inlen];
    uint8_t* in1 = &seeds[1 * inlen];
    uint8_t* in2 = &seeds[2 * inlen];
    uint8_t* in3 = &seeds[3 * inlen];

    for (int ctr = 0; ctr < params->lenSeedA; ctr++) {
        in0[2 + ctr] = seedA[ctr];
        in1[2 + ctr] = seedA[ctr];
        in2[2 + ctr] = seedA[ctr];
        in3[2 + ctr] = seedA[ctr];
    }

    uint16_t* row0 = &rows[0 * n];
    uint16_t* row1 = &rows[1 * n];
    uint16_t* row2 = &rows[2 * n];
    uint16_t* row3 = &rows[3 * n];

    for (int i = 0; i < n; i += 4) {
        U16ToBytesLE(i + 0, in0);
        U16ToBytesLE(i + 1, in1);
        U16ToBytesLE(i + 2, in2);
        U16ToBytesLE(i + 3, in3);

        FrodoKemShake128((uint8_t*)row0, (size_t)n * sizeof(uint16_t), in0, inlen);
        FrodoKemShake128((uint8_t*)row1, (size_t)n * sizeof(uint16_t), in1, inlen);
        FrodoKemShake128((uint8_t*)row2, (size_t)n * sizeof(uint16_t), in2, inlen);
        FrodoKemShake128((uint8_t*)row3, (size_t)n * sizeof(uint16_t), in3, inlen);

        multFunction(out, matrixST, n, nbar, row0, row1, row2, row3, i);
    }
    return 0;
}
