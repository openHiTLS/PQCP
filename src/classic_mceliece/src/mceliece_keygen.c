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

#include "mceliece_keygen.h"

typedef struct
{
    uint32_t val; // <--- must be uint32_t
    uint16_t pos;
} pair_t;

// reverses the order of the m least significant bits of a 16-bit unsigned integer x.
static uint16_t BitrevU16(const uint16_t x, const int32_t m)
{
    uint16_t r = 0;
    for (int32_t j = 0; j < m; j++)
    {
        r = (uint16_t)((r << 1) | ((x >> j) & 1U));
    }
    return (uint16_t)(r & ((1U << m) - 1U));
}

static uint32_t Load4(const uint8_t *x)
{
    uint32_t r = 0;
    memcpy_s(&r, 4, x, 4);
    return r;
}

static int32_t ComparePairs(const void *a, const void *b)
{
    const pair_t *p1 = (const pair_t *)a;
    const pair_t *p2 = (const pair_t *)b;
    if (p1->val < p2->val)
    {
        return -1;
    }
    if (p1->val > p2->val)
    {
        return 1;
    }
    if (p1->pos < p2->pos)
    {
        return -1;
    }
    if (p1->pos > p2->pos)
    {
        return 1;
    }
    return 0;
}

// systematic
static void ExtractTFromSystematicMatrix(const GFMatrix *sysH, uint32_t mt, uint32_t n, GFMatrix *dstT)
{
    for (uint32_t i = 0; i < mt; i++)
    {
        for (uint32_t j = 0; j < (n - mt); j++)
        {
            int32_t bit = MatrixGetBit(sysH, i, mt + j);
            MatrixSetBit(dstT, i, j, bit);
        }
    }
}

static CRYPT_ERROR GenGoppaAndSystematicMatrix(CMPrivateKey *sk, CMPublicKey *pk, const uint8_t *irreduciblePolyBitsPtr, const uint8_t *fieldOrderingBitsPtr, const McelieceParams *params)
{
    int32_t mt = params->m * params->t;
    int32_t n = params->n;

    if (GenerateIrreduciblePolyFinal(&sk->g, irreduciblePolyBitsPtr, params->t, params->m) != PQCP_SUCCESS)
        return PQCP_MCELIECE_KEYGEN_FAIL;

    int16_t *pi = (int16_t *)BSL_SAL_Malloc(sizeof(int16_t) * MCELIECE_Q);
    if (pi == NULL)
        return PQCP_MALLOC_FAIL;
    int16_t *pip = pi + params->n;

    if (GenerateFieldOrdering(sk->alpha, pip, fieldOrderingBitsPtr, params->n, params->m) != PQCP_SUCCESS)
    {
        BSL_SAL_FREE(pi);
        return PQCP_MCELIECE_KEYGEN_FAIL;
    }

    for (int32_t i = 0; i < params->n; i++)
    {
        if (PolynomialEval(&sk->g, sk->alpha[i]) == 0)
        {
            BSL_SAL_FREE(pi);
            return PQCP_MCELIECE_KEYGEN_FAIL;
        }
    }

    GFMatrix *tmpH = MatrixCreate(mt, n);
    if (tmpH == NULL)
    {
        BSL_SAL_FREE(pi);
        return PQCP_MALLOC_FAIL;
    }
    if (BuildParityCheckMatrixReferenceStyle(tmpH, &sk->g, sk->alpha, params) != 0 ||
        ReduceToSystematicFormReferenceStyle(tmpH) != 0)
    {
        MatrixFree(tmpH);
        BSL_SAL_FREE(pi);
        return PQCP_MCELIECE_KEYGEN_FAIL;
    }

    ExtractTFromSystematicMatrix(tmpH, mt, n, &pk->matT);
    MatrixFree(tmpH);
    BSL_SAL_FREE(pi);
    return PQCP_SUCCESS;
}

static CRYPT_ERROR GenControlBitsFromAlpha(CMPrivateKey *sk, const McelieceParams *params)
{
    int16_t *pi = (int16_t *)BSL_SAL_Malloc(sizeof(int16_t) * MCELIECE_Q);
    if (pi == NULL)
        return PQCP_MALLOC_FAIL;

    for (int64_t i = 0; i < params->n; i++)
        pi[i] = -1;

    uint8_t *used = (uint8_t *)BSL_SAL_Malloc(MCELIECE_Q);
    if (used == NULL)
    {
        BSL_SAL_FREE(pi);
        return PQCP_MALLOC_FAIL;
    }
    memset_s(used, MCELIECE_Q, 0, MCELIECE_Q);

    for (int32_t j = 0; j < params->n; j++)
    {
        uint16_t v = (uint16_t)sk->alpha[j];
        uint16_t r = 0;
        for (int32_t bi = 0; bi < params->m; bi++)
        {
            r = (uint16_t)((r << 1) | ((v >> bi) & 1U));
        }
        r &= (uint16_t)((1U << params->m) - 1U);
        pi[j] = (int16_t)r;
        used[r] = 1;
    }
    BSL_SAL_FREE(used);
    memset_s(sk->controlbits, sk->controlbitsLen, 0, sk->controlbitsLen);

    CRYPT_ERROR ret = CbitsFromPermNs(sk->controlbits, pi, params->m, MCELIECE_Q);
    if (ret != PQCP_SUCCESS)
    {
        BSL_SAL_FREE(pi);
        return ret;
    }
    BSL_SAL_FREE(pi);
    return PQCP_SUCCESS;
}

static CRYPT_ERROR SystematicLoop(const uint8_t *rndE, const uint8_t *sBitsPtr, const uint8_t *fieldOrderingBitsPtr, const uint8_t *irreduciblePolyBitsPtr, CMPublicKey *pk, CMPrivateKey *sk, const McelieceParams *params)
{
    CRYPT_ERROR ret;
    ret = GenGoppaAndSystematicMatrix(sk, pk, irreduciblePolyBitsPtr, fieldOrderingBitsPtr, params);
    if (ret != PQCP_SUCCESS)
        return ret;

    ret = GenControlBitsFromAlpha(sk, params);
    if (ret != PQCP_SUCCESS)
        return ret;

    memcpy_s(sk->s, params->nBytes, sBitsPtr, params->nBytes);
    return PQCP_SUCCESS;
}

CRYPT_ERROR SeededKeyGen(const uint8_t *delta, CMPublicKey *pk, CMPrivateKey *sk, const McelieceParams *params)
{
    if (delta == NULL || pk == NULL || sk == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    int32_t sBitLen = params->n;
    int32_t irreduciblePolyBitLen = MCELIECE_SIGMA1 * params->t;
    int32_t fieldOrderingBitLen = MCELIECE_SIGMA2 * MCELIECE_Q;
    int32_t deltaPrimeBitLen = MCELIECE_L;

    uint64_t prgOutputBitLen = (uint64_t)(uint32_t)sBitLen + (uint64_t)(uint32_t)fieldOrderingBitLen + (uint64_t)(uint32_t)irreduciblePolyBitLen + (uint64_t)(uint32_t)deltaPrimeBitLen;
    if (prgOutputBitLen > INT32_MAX)
        return PQCP_MCELIECE_KEYGEN_FAIL;
    size_t prgOutputByteLen = (prgOutputBitLen + 7) >> 3;
    size_t sByteLen = (sBitLen + 7) >> 3;
    size_t fieldOrderingByteLen = (fieldOrderingBitLen + 7) >> 3;
    size_t irreduciblePolyByteLen = (irreduciblePolyBitLen + 7) >> 3;
    size_t deltaPrimeByteLen = (deltaPrimeBitLen + 7) >> 3;

    uint8_t *rndE = (uint8_t *)BSL_SAL_Malloc(prgOutputByteLen);
    if (rndE == NULL)
    {
        return PQCP_MALLOC_FAIL;
    }

    memcpy_s(sk->delta, deltaPrimeByteLen, delta, deltaPrimeByteLen);
    // maxAttempts <- 50: pragmatic limit: keeps worst-case runtime bounded while still allowing rare, valid matrices to be found
    int32_t maxAttempts = 50; // try 50 times
    for (int32_t attempt = 0; attempt < maxAttempts; attempt++)
    {
        McEliecePrg(sk->delta, rndE, prgOutputByteLen);

        uint8_t deltaPrime[MCELIECE_L_BYTES];
        memcpy_s(deltaPrime, deltaPrimeByteLen, rndE + prgOutputByteLen - deltaPrimeByteLen, deltaPrimeByteLen);

        const uint8_t *sBitsPtr = rndE;
        const uint8_t *fieldOrderingBitsPtr = rndE + sByteLen;
        const uint8_t *irreducibleBitsPtr = fieldOrderingBitsPtr + fieldOrderingByteLen;

        CRYPT_ERROR ret = SystematicLoop(rndE, sBitsPtr, fieldOrderingBitsPtr, irreducibleBitsPtr, pk, sk, params);
        if (ret == PQCP_SUCCESS)
        {
            BSL_SAL_FREE(rndE);
            return PQCP_SUCCESS;
        }

        // if fail
        memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
    }

    BSL_SAL_FREE(rndE);
    return PQCP_MCELIECE_KEYGEN_FAIL;
}

// semi-systematic
static CRYPT_ERROR GenGoppaAndValidate(const uint8_t *irreduciblePolyBitsPtr, const uint8_t *fieldOrderingBitsPtr, CMPrivateKey *sk, const McelieceParams *params)
{
    if (GenerateIrreduciblePolyFinal(&sk->g, irreduciblePolyBitsPtr, params->t, params->m) != PQCP_SUCCESS)
    {
        return PQCP_MCELIECE_KEYGEN_FAIL;
    }

    int16_t *pi = (int16_t *)BSL_SAL_Malloc(sizeof(int16_t) * MCELIECE_Q);
    if (pi == NULL)
    {
        return PQCP_MALLOC_FAIL;
    }
    int16_t *pip = pi + params->n;

    if (GenerateFieldOrdering(sk->alpha, pip, fieldOrderingBitsPtr, params->n, params->m) != PQCP_SUCCESS)
    {
        BSL_SAL_FREE(pi);
        return PQCP_MCELIECE_KEYGEN_FAIL;
    }
    int32_t isSupportSet = 1;
    for (int32_t i = 0; i < params->n; i++)
    {
        if (PolynomialEval(&sk->g, sk->alpha[i]) == 0)
        {
            isSupportSet = 0;
            break;
        }
    }
    if (isSupportSet == 0)
    {
        BSL_SAL_FREE(pi);
        return PQCP_MCELIECE_KEYGEN_FAIL;
    }
    BSL_SAL_FREE(pi);
    return PQCP_SUCCESS;
}

static CRYPT_ERROR BuildSemiSystematicAndExtractT(CMPublicKey *pk, CMPrivateKey *sk, int16_t *pi, const McelieceParams *params)
{
    GFMatrix *tmpH = MatrixCreate(params->mt, params->n);
    if (tmpH == NULL)
        return PQCP_MALLOC_FAIL;

    if (BuildParityCheckMatrixReferenceStyle(tmpH, &sk->g, sk->alpha, params) != 0)
    {
        MatrixFree(tmpH);
        return PQCP_MCELIECE_KEYGEN_FAIL;
    }

    uint64_t pivots = 0;
    int32_t retGauss = GaussPartialSemiSystematic(tmpH->data, tmpH->colsBytes, pi, &pivots, params->mt, params->n);
    if (retGauss != 0)
    {
        MatrixFree(tmpH);
        return PQCP_MCELIECE_KEYGEN_FAIL;
    }
    sk->c = pivots;

    const int32_t tail = params->mt & 7;
    const int32_t tBytes = (params->n - params->mt + 7) / 8;
    uint8_t *tBlk = pk->matT.data;

    for (int32_t i = 0; i < params->mt; i++)
    {
        uint8_t *row = tmpH->data + i * tmpH->colsBytes;
        uint8_t *out = tBlk + i * tBytes;
        for (int32_t j = params->mt / 8; j < (params->n - 1) / 8; j++)
        {
            *out++ = (row[j] >> tail) | (row[j + 1] << (8 - tail));
        }
        *out = row[(params->n - 1) / 8] >> tail;
    }
    MatrixFree(tmpH);
    return PQCP_SUCCESS;
}

static CRYPT_ERROR GenPiInitial(int16_t *pi, const CMPrivateKey *sk, const McelieceParams *params)
{
    uint8_t *used = (uint8_t *)BSL_SAL_Calloc(MCELIECE_Q, 1);
    if (used == NULL)
        return PQCP_MALLOC_FAIL;

    for (int32_t j = 0; j < params->n; j++)
    {
        uint16_t a = (uint16_t)sk->alpha[j];
        int16_t v = (int16_t)BitrevU16(a, params->m);
        pi[j] = v;
        used[(size_t)v] = 1;
    }
    BSL_SAL_FREE(used);
    return PQCP_SUCCESS;
}

static CRYPT_ERROR GenControlBitsFromPi(CMPrivateKey *sk, const int16_t *pi, const McelieceParams *params)
{
    memset_s(sk->controlbits, sk->controlbitsLen, 0, sk->controlbitsLen);
    CRYPT_ERROR ret = CbitsFromPermNs(sk->controlbits, pi, params->m, MCELIECE_Q);
    if (ret != PQCP_SUCCESS)
    {
        BSL_SAL_FREE(sk->controlbits);
        sk->controlbits = NULL;
        return ret;
    }

    return PQCP_SUCCESS;
}

CRYPT_ERROR SeededKeyGenSemi(const uint8_t *delta, CMPublicKey *pk, CMPrivateKey *sk, const McelieceParams *params)
{
    if (delta == NULL || pk == NULL || sk == NULL)
        return PQCP_NULL_INPUT;
    size_t fieldOrderingBitLen = (size_t)MCELIECE_SIGMA2 * MCELIECE_Q;
    size_t prgOutputBitLen = params->n + fieldOrderingBitLen + ((size_t)MCELIECE_SIGMA1 * params->t) + ((size_t)MCELIECE_L); // sBitLen + fieldOrderingBitLen + irreduciblePolyBitLen + deltaPrimeBitLen
    size_t prgOutputByteLen = (prgOutputBitLen + 7) / 8;
    size_t deltaPrimeByteLen = (((size_t)MCELIECE_L) + 7) / 8;
    uint8_t *rngE = (uint8_t *)BSL_SAL_Malloc(prgOutputByteLen);
    if (rngE == NULL)
        return PQCP_MALLOC_FAIL;
    memcpy_s(sk->delta, deltaPrimeByteLen, delta, deltaPrimeByteLen);
    int32_t maxAttempts = 50; // pragmatic limit: keeps worst-case runtime bounded while still allowing rare, valid matrices to be found
    for (int32_t attempt = 0; attempt < maxAttempts; attempt++)
    {
        uint8_t deltaPrime[MCELIECE_L_BYTES];
        McEliecePrg(sk->delta, rngE, prgOutputByteLen);
        memcpy_s(deltaPrime, deltaPrimeByteLen, rngE + prgOutputByteLen - deltaPrimeByteLen, deltaPrimeByteLen);
        const uint8_t *sBitsPtr = rngE;
        const uint8_t *fieldOrderingBitsPtr = rngE + ((params->n + 7) / 8);                             // rngE + sByteLen
        const uint8_t *irreduciblePolyBitsPtr = fieldOrderingBitsPtr + ((fieldOrderingBitLen + 7) / 8); // fieldOrderingBitsPtr + fieldOrderingByteLen
        if (GenGoppaAndValidate(irreduciblePolyBitsPtr, fieldOrderingBitsPtr, sk, params) != PQCP_SUCCESS)
        {
            memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
            continue;
        }
        int16_t *pi = (int16_t *)BSL_SAL_Malloc(sizeof(int16_t) * MCELIECE_Q);
        if (pi == NULL)
        {
            memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
            continue;
        }
        if (GenPiInitial(pi, sk, params) != PQCP_SUCCESS ||
            BuildSemiSystematicAndExtractT(pk, sk, pi, params) != PQCP_SUCCESS)
        {
            memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
            BSL_SAL_FREE(pi);
            continue;
        }
        if (GenControlBitsFromPi(sk, pi, params) != PQCP_SUCCESS)
        {
            BSL_SAL_FREE(pi);
            BSL_SAL_FREE(rngE);
            return PQCP_MALLOC_FAIL;
        }
        memcpy_s(sk->s, params->nBytes, sBitsPtr, params->nBytes);
        BSL_SAL_FREE(pi);
        BSL_SAL_FREE(rngE);
        return PQCP_SUCCESS;
    }
    BSL_SAL_FREE(rngE);
    return PQCP_MCELIECE_KEYGEN_FAIL;
}

CRYPT_ERROR GenerateFieldOrdering(GFElement *alpha, int16_t *piTail, const uint8_t *randomBits, const int32_t n, const int32_t m)
{
    // Field ordering generation function
    pair_t *pairs = BSL_SAL_Malloc(MCELIECE_Q * sizeof(pair_t));
    if (pairs == NULL)
    {
        return PQCP_MALLOC_FAIL;
    }
    // random q 32-bit a_i
    for (int32_t i = 0; i < MCELIECE_Q; i++)
    {
        uint32_t a_i = Load4(randomBits + i * 4); // le 32-bit
        pairs[i].val = a_i;
        pairs[i].pos = i;
    }
    // Check for duplicate values
    pair_t *sortedForCheck = BSL_SAL_Malloc(MCELIECE_Q * sizeof(pair_t));
    if (sortedForCheck == NULL)
    {
        BSL_SAL_FREE(pairs);
        return PQCP_MALLOC_FAIL;
    }
    memcpy_s(sortedForCheck, MCELIECE_Q * sizeof(pair_t), pairs, MCELIECE_Q * sizeof(pair_t));
    qsort(sortedForCheck, MCELIECE_Q, sizeof(pair_t), ComparePairs);

    int32_t hasDuplicates = 0;
    for (int32_t i = 0; i < MCELIECE_Q_1; i++)
    {
        if (sortedForCheck[i].val == sortedForCheck[i + 1].val)
        {
            hasDuplicates = 1;
            break;
        }
    }
    BSL_SAL_FREE(sortedForCheck);

    if (hasDuplicates != 0)
    {
        BSL_SAL_FREE(pairs);
        return PQCP_MCELIECE_KEYGEN_FAIL;
    }
    qsort(pairs, MCELIECE_Q, sizeof(pair_t), ComparePairs);
    uint16_t *pi = BSL_SAL_Malloc(MCELIECE_Q * sizeof(uint16_t));
    if (pi == NULL)
    {
        BSL_SAL_FREE(pairs);
        return PQCP_MALLOC_FAIL;
    }
    for (int32_t i = 0; i < MCELIECE_Q; i++)
    {
        pi[i] = pairs[i].pos;
    }
    BSL_SAL_FREE(pairs);

    for (int32_t i = 0; i < MCELIECE_Q; i++)
    {
        uint16_t v = pi[i] & (uint16_t)MCELIECE_Q_1;
        alpha[i] = (GFElement)BitrevU16(v, m);
    }
    // tail of pi
    memcpy_s(piTail, (MCELIECE_Q - n) * sizeof(int16_t), pi + n, (MCELIECE_Q - n) * sizeof(int16_t));
    BSL_SAL_FREE(pi);
    return PQCP_SUCCESS;
}

CRYPT_ERROR GenerateIrreduciblePolyFinal(GFPolynomial *g, const uint8_t *randomBits, const int32_t t, const int32_t m)
{
    // Ensure GF tables are initialized before any gf_* operations
    if (GFInitial(m) != PQCP_SUCCESS)
    {
        return PQCP_MCELIECE_INVALID_ARG;
    }

    memset_s(g->coeffs, (g->maxDegree + 1) * sizeof(GFElement), 0, (g->maxDegree + 1) * sizeof(GFElement));
    g->degree = -1;

    // Reference-compatible packing: read t little-endian 16-bit values, mask to m bits
    // random_bits is expected to be 2*t bytes long for the poly section
    GFElement *f = BSL_SAL_Malloc(sizeof(GFElement) * t);
    if (f == NULL)
    {
        return PQCP_MALLOC_FAIL;
    }
    for (int32_t i = 0; i < t; i++)
    {
        uint16_t le = (uint16_t)randomBits[2 * i] | ((uint16_t)randomBits[2 * i + 1] << 8);
        f[i] = (GFElement)(le & ((1U << m) - 1U));
    }
    if (f[t - 1] == 0)
    {
        f[t - 1] = 1;
    }

    // Compute connection polynomial coefficients via GenpolyOverGF
    GFElement *gl = BSL_SAL_Malloc(sizeof(GFElement) * t);
    if (gl == NULL)
    {
        BSL_SAL_FREE(f);
        return PQCP_MALLOC_FAIL;
    }
    if (GenpolyOverGF(gl, f, t, m) != PQCP_SUCCESS)
    {
        BSL_SAL_FREE(f);
        BSL_SAL_FREE(gl);
        return PQCP_MCELIECE_KEYGEN_FAIL;
    }

    // Form monic g(x) = x^t + sum_{i=0}^{t-1} gl[i] x^i
    for (int32_t i = 0; i < t; i++)
    {
        PolynomialSetCoeff(g, i, gl[i]);
    }
    PolynomialSetCoeff(g, t, 1);

    BSL_SAL_FREE(f);
    BSL_SAL_FREE(gl);
    return PQCP_SUCCESS;
}

// Private key creation
CMPrivateKey *PrivateKeyCreate(const McelieceParams *params)
{
    CMPrivateKey *sk = BSL_SAL_Calloc(sizeof(CMPrivateKey), sizeof(uint8_t));
    if (sk == NULL)
    {
        return NULL;
    }
    size_t cbLen = (size_t)((((2 * params->m - 1) * MCELIECE_Q / 2) + 7) / 8);
    sk->controlbitsLen = cbLen;

    sk->controlbits = (uint8_t *)BSL_SAL_Malloc(sk->controlbitsLen);
    if (sk->controlbits == NULL)
    {
        BSL_SAL_FREE(sk);
        return NULL;
    }

    // init Goppa poly
    GFPolynomial *g = PolynomialCreate(params->t);
    if (g == NULL)
    {
        BSL_SAL_FREE(sk->controlbits);
        BSL_SAL_FREE(sk);
        return NULL;
    }
    sk->g = *g;
    BSL_SAL_FREE(g);

    sk->alpha = BSL_SAL_Calloc(MCELIECE_Q, sizeof(GFElement));
    if (sk->alpha == NULL)
    {
        BSL_SAL_FREE(sk->g.coeffs);
        BSL_SAL_FREE(sk->controlbits);
        BSL_SAL_FREE(sk);
        return NULL;
    }

    sk->s = BSL_SAL_Calloc(params->nBytes, sizeof(uint8_t));
    if (sk->s == NULL)
    {
        BSL_SAL_FREE(sk->alpha);
        BSL_SAL_FREE(sk->g.coeffs);
        BSL_SAL_FREE(sk->controlbits);
        BSL_SAL_FREE(sk);
        return NULL;
    }

    sk->c = (1ULL << 32) - 1;
    return sk;
}

// Private key deallocation
void PrivateKeyFree(CMPrivateKey *sk, const McelieceParams *params)
{
    if (sk != NULL)
    {
        if (sk->controlbits != NULL)
        {
            BSL_SAL_CleanseData(sk->controlbits, sk->controlbitsLen);
            BSL_SAL_FREE(sk->controlbits);
        }
        if (sk->g.coeffs != NULL)
        {
            BSL_SAL_CleanseData(sk->g.coeffs, params->t);
            BSL_SAL_FREE(sk->g.coeffs);
        }
        if (sk->alpha != NULL)
        {
            BSL_SAL_CleanseData(sk->alpha, MCELIECE_Q * sizeof(GFElement));
            BSL_SAL_FREE(sk->alpha);
        }
        if (sk->s != NULL)
        {
            BSL_SAL_CleanseData(sk->s, params->nBytes);
            BSL_SAL_FREE(sk->s);
        }
        BSL_SAL_FREE(sk);
    }
}

// Public key creation
CMPublicKey *PublicKeyCreate(const McelieceParams *params)
{
    CMPublicKey *pk = BSL_SAL_Calloc(sizeof(CMPublicKey), sizeof(uint8_t));
    if (pk == NULL)
    {
        return NULL;
    }
    GFMatrix *matT = MatrixCreate(params->mt, params->k);
    if (matT == NULL)
    {
        BSL_SAL_FREE(pk);
        return NULL;
    }

    pk->matT = *matT;
    BSL_SAL_FREE(matT);

    return pk;
}

// Public key deallocation
void PublicKeyFree(CMPublicKey *pk)
{
    if (pk != NULL)
    {
        if (pk->matT.data != NULL)
        {
            BSL_SAL_FREE(pk->matT.data);
        }
        BSL_SAL_FREE(pk);
    }
}
