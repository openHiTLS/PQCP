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

#ifndef MCELIECE_MATRIX_OPS_H
#define MCELIECE_MATRIX_OPS_H

#include "mceliece_types.h"
#include "mceliece_gf.h"
#include "mceliece_vector.h"
#include "mceliece_poly.h"

#ifdef __cplusplus
extern "C"
{
#endif

// Extract the rightmost 9-byte from the matrix, perform a tail-shift, and write it back
#define LOAD_SHIFT_9TO8(tmp, src, tail)                                          \
    do                                                                           \
    {                                                                            \
        for (int32_t _i = 0; _i < 9; ++_i)                                       \
            (tmp)[_i] = (src)[_i];                                               \
        for (int32_t _i = 0; _i < 8; ++_i)                                       \
            (tmp)[_i] = ((tmp)[_i] >> (tail)) | ((tmp)[_i + 1] << (8 - (tail))); \
    } while (0)

#define STORE_SHIFT_8TO9(dst, tmp, tail)                                              \
    do                                                                                \
    {                                                                                 \
        (dst)[0] = ((tmp)[0] << (tail)) | ((dst)[0] << (8 - (tail)) >> (8 - (tail))); \
        for (int32_t _i = 1; _i < 8; ++_i)                                            \
            (dst)[_i] = ((tmp)[_i] << (tail)) | ((tmp)[_i - 1] >> (8 - (tail)));      \
        (dst)[8] = ((dst)[8] >> (tail) << (tail)) | ((tmp)[7] >> (8 - (tail)));       \
    } while (0)

#define SAME_MASK(k, val) ((uint64_t)(-(int64_t)(((((uint32_t)((k) ^ (val)))) - (1U)) >> (31))))

static uint64_t CMMakeMask(uint64_t x)
{
    int64_t sx = (int64_t)x;
    uint64_t nz = (uint64_t)((sx >> 63) | ((-sx) >> 63));
    return ~nz;
}

static uint64_t CMLoad8(const uint8_t *x)
{
    uint64_t r = 0;
    memcpy_s(&r, 8, x, 8);
    return r;
}

static void CMStore8(uint8_t *x, uint64_t v)
{
    memcpy_s(x, 8, &v, 8);
}

// trailing zero count
static int32_t CMCtz64(uint64_t x)
{
    int32_t c = 0;
    while ((x & 1) == 0)
    {
        c++;
        x >>= 1;
    }
    return c;
}

// Matrix creation and destruction
GFMatrix *MatrixCreate(const int32_t rows, const int32_t cols);
void MatrixFree(GFMatrix *mat);

// Matrix element access (bit-level operations)
void MatrixSetBit(GFMatrix *mat, const int32_t row, const int32_t col, const int32_t value);
int32_t MatrixGetBit(const GFMatrix *mat, const int32_t row, const int32_t col);

// Reference-style matrix operations (matching NIST implementation)
int32_t BuildParityCheckMatrixReferenceStyle(GFMatrix *matH, const GFPolynomial *g, const GFElement *support, const McelieceParams *params);
int32_t ReduceToSystematicFormReferenceStyle(GFMatrix *matH);

int32_t ColsRermutation(uint8_t *mat, const int32_t colsBytes, int16_t *pi, uint64_t *pivots, int32_t mt);
int32_t GaussPartialSemiSystematic(uint8_t *mat, const int32_t colsBytes, int16_t *pi, uint64_t *pivots, const int32_t mt, const int32_t paramN);

#ifdef __cplusplus
}
#endif

#endif // MCELIECE_MATRIX_OPS_H
