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

#include "mceliece_encode.h"

// SWAR popcount
static inline unsigned Pop64(uint64_t x)
{   // 64-bit SWAR pop-count constants—bit masks for 2-bit, 4-bit, 8-bit and byte-lane aggregation
    x -= (x >> 1) & 0x5555555555555555ULL;
    x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
    x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
    return (unsigned)((x * 0x0101010101010101ULL) >> 56);   // Final shift to accumulate 8 byte sums into the high byte
}

// bit-flip
static inline void VecFlip(uint8_t *v, int32_t idx)
{
    v[idx >> 3] ^= 1u << (idx & 7);
}

static inline uint64_t MatrixGetU64(const GFMatrix *matT, const int32_t row, const int32_t colBase)
{
    const int32_t k = matT->cols;
    if (colBase >= k) {
        return 0;
    }

    const uint8_t *p = &matT->data[row * matT->colsBytes + (colBase >> 3)];
    const int32_t tailBits = k - colBase; // tail bits
    const int32_t tailBytes = (tailBits + 7) >> 3;

    uint64_t w = 0;
    if (tailBytes < 8) {
        // tail: less than 8 bits
        memcpy_s(&w, tailBytes, p, tailBytes);
    } else {
        // tail: full 8 bits
        memcpy_s(&w, 8, p, 8);
    }

    w >>= (colBase & 7);
    if (tailBits < 64) {
        w &= (~0ULL >> (64 - tailBits));    // Mask to keep only valid low bits when fewer than 64 bits are requested
    }
    return w;
}


static CRYPT_ERROR EncodeVector6688(const uint8_t *errorVector, const GFMatrix *matT, uint8_t *ciphertext, const McelieceParams *params)
{
    const uint8_t *pkPtr = matT->data;
    uint8_t *row = (uint8_t *)BSL_SAL_Malloc(params->nBytes);
    if (row == NULL) {
        return PQCP_MALLOC_FAIL;
    }
    for (int32_t i = 0; i < params->mt; i++) {
        memset_s(row, params->nBytes, 0, params->nBytes);
        const int32_t n64 = params->nBytes >> 3;
        uint64_t *w = (uint64_t *)row;

        for (int32_t j = 0; j < n64; j += 4) {
            __builtin_prefetch(&w[j + 8], 1, 3);    // Temporal locality hint—prefetch into L1 and mark as store
            w[j] = 0;
            w[j + 1] = 0;
            w[j + 2] = 0;
            w[j + 3] = 0;
        }
        for (int32_t j = n64 & ~3; j < n64; j++) {
            w[j] = 0;
        }
        for (int32_t j = n64 << 3; j < params->nBytes; j++) {
            row[j] = 0;
        }
        for (int32_t j = 0; j < params->kBytes; j++) {
            row[params->nBytes - params->kBytes + j] = pkPtr[j];
        }
        row[i >> 3] |= 1u << (i & 7u);

        uint8_t bit = 0;
        for (size_t j = 0; j < params->nBytes; j++) {
            uint8_t t = row[j] & errorVector[j];
            t ^= t << 4;
            t ^= t << 2;
            t ^= t << 1;
            bit ^= t >> 7;
        }
        bit &= 1;
        ciphertext[i >> 3] |= (bit << (i & 7));

        pkPtr += params->kBytes;
    }

    BSL_SAL_FREE(row);
    return PQCP_SUCCESS;
}
static void CopyHeadMT6960(uint8_t *dst, const uint8_t *src, const McelieceParams *params)
{
    int32_t wholeBytes = params->mt >> 3;
    int32_t tailBits   = params->mt & 7;
    typedef uint64_t v64;
    const v64 *s64 = (const v64 *)src;
    v64       *d64 = (v64 *)dst;
    int32_t n64    = wholeBytes >> 3;
    for (int32_t i = 0; i < n64; i++) {
        d64[i] = s64[i];
    }
    uint8_t *s = (uint8_t *)src + (n64 << 3);
    uint8_t *d = (uint8_t *)dst + (n64 << 3);
    int32_t n  = wholeBytes & 7;
    if (n >= 4) {
        memcpy_s(d, 4, s, 4);
        s += 4;
        d += 4;
        n -= 4;
    }
    if (n >= 2) {
        memcpy_s(d, 2, s, 2);
        s += 2;
        d += 2;
        n -= 2;
    }
    if (n >= 1) {
        *d = *s;
        ++s;
        ++d;
    }
    if (tailBits != 0) {
        uint8_t m = (uint8_t)((1U << tailBits) - 1);
        *d = (uint8_t)((*d & ~m) | (*s & m));
    }
}

static void ComputeParity6960(uint8_t *ciphertext, const uint8_t *errorVector, const GFMatrix *matT,  const McelieceParams *params)
{
    const int32_t slices = (params->k + 63) >> 6;
    uint64_t eSlab[slices];
    for (int32_t s = 0; s < slices; s++) {
        uint64_t w = 0;
        int32_t base  = s << 6;
        int32_t limit = (base + 64 < params->k) ? 64 : (params->k - base);  // Width of one 64-bit slice processed per inner pop-count iteration
        int32_t bitIdx = params->mt + base;
        for (int32_t b = 0; b < limit; b++) {
            int32_t bi = bitIdx + b;
            uint8_t byte = errorVector[bi >> 3];
            int32_t bp = bi & 7;
            w |= ((uint64_t)((byte >> bp) & 1)) << b;
        }
        w &= (limit == 64) ? ~0ULL : (~0ULL >> (64 - limit));
        eSlab[s] = w;
    }
    static const uint8_t pop4[16] = {0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4};
    for (int32_t r = 0; r < params->mt; r++) {
        int32_t dot = 0;
        for (int32_t s = 0; s < slices; s++) {
            uint64_t es = eSlab[s];
            uint64_t m  = MatrixGetU64(matT, r, s << 6);
            uint64_t v  = m & es;
            for (int32_t shift = 0; shift < 64; shift += 4) {   // Step size for nibble-wise pop-count using the 4-bit lookup table pop4
                dot += pop4[(v >> shift) & 0xF];
            }
        }
        if ((dot & 1) != 0) {
            VecFlip(ciphertext, r);
        }
    }
}


static void EncodeVector6960(const uint8_t *errorVector, const GFMatrix *matT, uint8_t *ciphertext, const McelieceParams *params)
{
    CopyHeadMT6960(ciphertext, errorVector, params);
    ComputeParity6960(ciphertext, errorVector, matT, params);
}


static void BuildRow8192(uint8_t *row, const uint8_t *pkPtr, int32_t rowIdx, const McelieceParams *params)
{
    const int32_t leading = params->nBytes - params->kBytes;
    const int32_t n64Copy = leading >> 3;
    uint64_t *w = (uint64_t *)row;

    for (int32_t j = 0; j < n64Copy; j += 4) {  // Quad-word (4 * 8 = 32-byte) unroll factor
        __builtin_prefetch(&w[j + 8], 1, 3);
        w[j] = 0;
        w[j + 1] = 0;
        w[j + 2] = 0;
        w[j + 3] = 0;
    }
    for (int32_t j = n64Copy & ~3; j < n64Copy; j++) {
        w[j] = 0;
    }
    for (int32_t j = leading & ~7; j < leading; j++) {
        row[j] = 0;
    }
    memcpy_s(row + leading, params->kBytes, pkPtr, params->kBytes);
    row[rowIdx >> 3] |= 1u << (rowIdx & 7u);
}

static void ComputeRow8192(uint8_t *ciphertext, const uint8_t *errorVector, const uint8_t *row, int32_t rowIdx, const McelieceParams *params)
{
    const int32_t n64 = params->nBytes >> 3;
    const uint64_t *e64 = (const uint64_t *)errorVector;
    uint64_t acc = 0;
    for (int32_t j = 0; j < n64; j++) {
        acc ^= ((uint64_t *)row)[j] & e64[j];
    }
    uint8_t bit = Pop64(acc) & 1;
    ciphertext[rowIdx >> 3] |= bit << (rowIdx & 7u);
}

static CRYPT_ERROR EncodeVector8192(const uint8_t *errorVector, const GFMatrix *matT, uint8_t *ciphertext, const McelieceParams *params)
{
    const uint8_t *pkPtr = matT->data;
    uint8_t *row = (uint8_t *)BSL_SAL_Malloc(params->nBytes);
    if (row == NULL) {
        return PQCP_MALLOC_FAIL;
    }
    for (int32_t i = 0; i < params->mt; i++) {
        memset_s(row, params->nBytes, 0, params->nBytes);
        BuildRow8192(row, pkPtr, i, params);
        ComputeRow8192(ciphertext, errorVector, row, i, params);
        pkPtr += params->kBytes;
    }
    BSL_SAL_FREE(row);
    return PQCP_SUCCESS;
}

// Encode: C = He, where H = (I_mt | T)
CRYPT_ERROR EncodeVector(const uint8_t *errorVector, const GFMatrix *matT, uint8_t *ciphertext, const McelieceParams *params)
{
    if (errorVector == NULL || matT == NULL || ciphertext == NULL || params == NULL) {
        return PQCP_NULL_INPUT;
    }

    CRYPT_ERROR ret;
    switch (params->n) {
    case 6688:
        ret = EncodeVector6688(errorVector, matT, ciphertext, params);
        if (ret != PQCP_SUCCESS) {
            return ret;
        }
        break;
    case 6960:
        EncodeVector6960(errorVector, matT, ciphertext, params);
        break;
    case 8192:
        ret = EncodeVector8192(errorVector, matT, ciphertext, params);
        if (ret != PQCP_SUCCESS) {
            return ret;
        }
        break;
    default:
        return PQCP_MCELIECE_ENCODE_FAIL;
    }
    return PQCP_SUCCESS;
}

static CRYPT_ERROR GenerateRandomBytesForEncoding(uint8_t *seedOut, uint8_t *randomBytes, size_t byteLen)
{
    if (CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL) != PQCP_SUCCESS) {
        return PQCP_MCELIECE_ENCODE_FAIL;
    }
    if (CRYPT_EAL_Randbytes(seedOut, MCELIECE_L_BYTES) != PQCP_SUCCESS) {
        return PQCP_MCELIECE_ENCODE_FAIL;
    }
    McEliecePrg(seedOut, randomBytes, byteLen);
    return PQCP_SUCCESS;
}


static CRYPT_ERROR GenerateCandidates6688Or6960(int32_t *dValues, const uint8_t *randomBytes, const int32_t randomBytesLen, const int32_t tau, const int32_t  n)
{
    if (randomBytesLen != 2 * tau) {
        return PQCP_MCELIECE_ENCODE_FAIL;
    }
    for (int32_t j = 0; j < tau; j++) {
        uint16_t d_j = (uint16_t)randomBytes[j * 2] | ((uint16_t)randomBytes[j * 2 + 1] << 8);
        dValues[j] = d_j % n;
    }
    return PQCP_SUCCESS;
}

static CRYPT_ERROR DeduplicateAndSet6688Or6960(uint8_t *e, const int32_t *dValues, const int32_t tau, const int32_t t, const int32_t n)
{
    int32_t positions[t];
    int32_t uniqueCount = 0;
    int32_t maxAttempts = tau * 2;  // Each candidate needs 2 bytes (uint16_t) to store a position < n
    for (int32_t i = 0; i < tau && uniqueCount < t && i < maxAttempts; i++) {
        int32_t pos = dValues[i];
        int32_t isUnique = 1;
        for (int32_t j = 0; j < uniqueCount; j++) {
            if (positions[j] == pos) {
                isUnique = 0;
                break;
            }
        }
        if (isUnique) {
            positions[uniqueCount++] = pos;
        }
    }
    if (uniqueCount < t) {
        return PQCP_MCELIECE_KEYGEN_FAIL;
    }
    for (int32_t i = 0; i < t; i++) {
        VectorSetBit(e, positions[i], 1);
    }
    return PQCP_SUCCESS;
}

static CRYPT_ERROR FixedWeightVector6688Or6960(uint8_t *e, const int32_t n, const int32_t t, const McelieceParams *params)
{
    /*
     * The specification only requires tau >= t.  
     * We add 10 extra candidates as a practical margin:  
     * - large enough that colliding indices are rare in practice,  
     * - small enough to keep random-byte consumption and cache footprint low.  
     * The number is empirical; adjust if measurements show more retries.
     */
    const int32_t tau = t + 10; // Extra candidate buffer to ensure t unique positions are found after de-duplication
    size_t randomByteLen = (size_t)tau * 2;
    uint8_t *randomBytes = BSL_SAL_Malloc(randomByteLen);
    if (randomBytes == NULL) {
        return PQCP_MALLOC_FAIL;
    }
    uint8_t seed[MCELIECE_L_BYTES];

    CRYPT_ERROR ret = GenerateRandomBytesForEncoding(seed, randomBytes, randomByteLen);
    if (ret != PQCP_SUCCESS) {
        BSL_SAL_FREE(randomBytes);
        return ret;
    }

    int32_t *dValues = BSL_SAL_Malloc(tau * sizeof(int32_t));
    if (dValues == NULL) {
        BSL_SAL_FREE(randomBytes);
        return PQCP_MALLOC_FAIL;
    }
    ret = GenerateCandidates6688Or6960(dValues, randomBytes, randomByteLen, tau, n);
    if (ret != PQCP_SUCCESS) {
        BSL_SAL_FREE(randomBytes);
        BSL_SAL_FREE(dValues);
        return ret;
    }
    ret = DeduplicateAndSet6688Or6960(e, dValues, tau, t, n);
    if (ret != PQCP_SUCCESS) {
        BSL_SAL_FREE(randomBytes);
        BSL_SAL_FREE(dValues);
        return ret;
    }

    BSL_SAL_FREE(dValues);
    BSL_SAL_FREE(randomBytes);
    return ret;
}

static CRYPT_ERROR GenerateAndDeduplicate8192(uint16_t *pos, uint64_t *used, const uint8_t *rnd, const int32_t tau, const int32_t t, const int32_t n)
{
    int32_t uniq = 0;
    for (int32_t i = 0; i < tau && uniq < t; i++) {
        uint16_t u = (uint16_t)rnd[i * 2] | ((uint16_t)rnd[i * 2 + 1] << 8);
        uint16_t p = u & (n - 1);
        uint64_t mask = 1ULL << (p & 63);
        int32_t idx64 = p >> 6;     // Shift amount to convert bit position to 64-bit word index
        if ((used[idx64] & mask) != 0) {
            continue;
        }
        used[idx64] |= mask;
        pos[uniq++] = p;
    }
    return (uniq < t) ? PQCP_MCELIECE_KEYGEN_FAIL : PQCP_SUCCESS;
}

static void WritePositions8192(uint8_t *e, const uint16_t *pos, const int32_t cnt)
{
    uint64_t *e64 = (uint64_t *)e;
    for (int32_t i = 0; i < cnt; i++) {
        uint16_t p   = pos[i];
        uint64_t mask = 1ULL << (p & 63);
        e64[p >> 6]  |= mask;
    }
}

static CRYPT_ERROR FixedWeightVector8192(uint8_t *e, const int32_t n, const int32_t t, const McelieceParams *params)
{
    /*
     * The specification only requires tau >= t.  
     * We add 10 extra candidates as a practical margin:  
     * - large enough that colliding indices are rare in practice,  
     * - small enough to keep random-byte consumption and cache footprint low.  
     * The number is empirical; adjust if measurements show more retries.
     */
    const int32_t tau = t + 10; // Extra candidate buffer to ensure t unique positions are found after de-duplication
    uint64_t used[128] = {0};   // Size of the used-bitmap in 64-bit words (8192 bits / 64 = 128)
    uint8_t  rnd[tau * 2] __attribute__((aligned(16))); // 16-byte alignment hint for the random buffer to enable SIMD loads if needed
    uint16_t pos[t];
    uint8_t  seed[MCELIECE_L_BYTES];

    CRYPT_ERROR ret = GenerateRandomBytesForEncoding(seed, rnd, sizeof(rnd));
    if (ret != PQCP_SUCCESS) {
        return ret;
    }

    ret = GenerateAndDeduplicate8192(pos, used, rnd, tau, t, n);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    WritePositions8192(e, pos, t);
    return PQCP_SUCCESS;
}


CRYPT_ERROR FixedWeightVector(uint8_t *e, const int32_t n, const int32_t t, const McelieceParams *params) {
    if (e == NULL || params == NULL) {
        return PQCP_MCELIECE_ENCODE_FAIL;
    }

    switch (params->n) {
    case 6688:
        return FixedWeightVector6688Or6960(e, n, t, params);
    case 6960:
        return FixedWeightVector6688Or6960(e, n, t, params);
    case 8192:
        return FixedWeightVector8192(e, n, t, params);
    default:
        return PQCP_MCELIECE_ENCODE_FAIL;
    }
}
