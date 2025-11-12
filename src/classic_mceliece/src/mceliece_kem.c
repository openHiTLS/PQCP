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

#include "mceliece_kem.h"

static CRYPT_ERROR GenDeltaFromSeed(uint8_t *delta)
{
    /* McElieceRandombytesInit copies entropyInput into seedMaterial and optionally x-ors a personalization string.
     * The copied seedMaterial is then fed to McElieceAES256CTRDrbgUpdate to initialise the global DRBG state
     * (Key, V, reseed_counter). Hence entropyInput is the raw entropy source that bootstraps the whole DRBG. */
    uint8_t entropyInput[MCELIECE_SEED_BYTES];
    if (CRYPT_EAL_Randbytes(entropyInput, MCELIECE_SEED_BYTES) != PQCP_SUCCESS)
    {
        return PQCP_MCELIECE_KEYGEN_FAIL;
    }
    uint8_t kgSeed[33];                                                            // Total buffer length for key-generation seed: 1-byte length prefix + 32-byte random
    CRYPT_ERROR ret = McElieceRandomBytesInit((uint8_t *)entropyInput, NULL, 256); // Security strength (in bits) requested from the DRBG during seed generation
    if (ret != PQCP_SUCCESS)
    {
        return ret;
    }
    /* kgSeed[0] is the length byte that Classic McEliece hard-codes to 64 (0x40) so that the later Expand-And-Split step
     * produces the correct number of field elements for the public key generation; any other value would break the
     * deterministic key schedule */
    kgSeed[0] = 64; // the value of first element must be 64
    ret = McElieceRandomBytes(kgSeed + 1, MCELIECE_L_BYTES);
    if (ret != PQCP_SUCCESS)
    {
        return ret;
    }
    memcpy_s(delta, MCELIECE_L_BYTES, kgSeed + 1, MCELIECE_L_BYTES);
    return PQCP_SUCCESS;
}

// KeyGen
CRYPT_ERROR McElieceKeygen(CMPublicKey *pk, CMPrivateKey *sk, const McelieceParams *params)
{
    if (pk == NULL || sk == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    uint8_t delta[MCELIECE_L_BYTES];
    CRYPT_ERROR ret = GenDeltaFromSeed(delta);
    if (ret != PQCP_SUCCESS)
    {
        return ret;
    }
    return SeededKeyGen(delta, pk, sk, params);
}

CRYPT_ERROR McElieceKeygenSemi(CMPublicKey *pk, CMPrivateKey *sk, const McelieceParams *params)
{
    if (pk == NULL || sk == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    uint8_t delta[MCELIECE_L_BYTES];
    CRYPT_ERROR ret = GenDeltaFromSeed(delta);
    if (ret != PQCP_SUCCESS)
    {
        return ret;
    }
    return SeededKeyGenSemi(delta, pk, sk, params);
}

// gen e & encode
static CRYPT_ERROR GenVectorE(uint8_t *c, uint8_t *e, const CMPublicKey *pk, const McelieceParams *params)
{
    CRYPT_ERROR ret = FixedWeightVector(e, params);
    if (ret != PQCP_SUCCESS)
    {
        return PQCP_MCELIECE_KEYGEN_FAIL;
    }
    memset_s(c, params->mtBytes, 0, params->mtBytes);
    EncodeVector(e, &pk->matT, c, params);
    return PQCP_SUCCESS;
}

// K = Hash(1, e, C)
static void ComputeSessionKey(uint8_t *sessionKey, const uint8_t *e, const uint8_t *c, const McelieceParams *params)
{
    size_t inLen = 1 + params->nBytes + params->cipherBytes;
    uint8_t hashIn[inLen];
    hashIn[0] = 1;
    memcpy_s(hashIn + 1, params->nBytes, e, params->nBytes);
    memcpy_s(hashIn + 1 + params->nBytes, params->cipherBytes, c, params->cipherBytes);
    McElieceShake256(sessionKey, MCELIECE_L_BYTES, hashIn, inLen);
}

// Encap algorithm (non-pc parameter sets)
CRYPT_ERROR McElieceEncaps(uint8_t *ciphertext, const CMPublicKey *pk, uint8_t *sessionKey, const McelieceParams *params)
{
    if (pk == NULL || ciphertext == NULL || sessionKey == NULL)
    {
        return PQCP_NULL_INPUT;
    }

    uint8_t *e = (uint8_t *)BSL_SAL_Malloc(params->nBytes);
    if (e == NULL)
    {
        return PQCP_MALLOC_FAIL;
    }
    CRYPT_ERROR ret = GenVectorE(ciphertext, e, pk, params);
    if (ret != PQCP_SUCCESS)
    {
        return ret;
    }
    ComputeSessionKey(sessionKey, e, ciphertext, params);
    BSL_SAL_CleanseData(e, params->nBytes);
    BSL_SAL_FREE(e);
    return PQCP_SUCCESS;
}

CRYPT_ERROR McElieceEncapsPC(uint8_t *ciphertext, const CMPublicKey *pk, uint8_t *sessionKey, const McelieceParams *params)
{
    if (pk == NULL || ciphertext == NULL || sessionKey == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    uint8_t *c0 = ciphertext;
    uint8_t *c1 = ciphertext + params->cipherBytes;

    uint8_t *e = (uint8_t *)BSL_SAL_Malloc(params->nBytes);
    if (e == NULL)
    {
        return PQCP_MALLOC_FAIL;
    }
    CRYPT_ERROR ret = GenVectorE(c0, e, pk, params);
    if (ret != PQCP_SUCCESS)
    {
        return ret;
    }

    // PC only: C1 = H(2, e)
    uint8_t hashIn[1 + MCELIECE_L_BYTES];
    hashIn[0] = 2;
    memcpy_s(hashIn + 1, MCELIECE_L_BYTES, e, MCELIECE_L_BYTES);
    McElieceShake256(c1, MCELIECE_L_BYTES, hashIn, sizeof(hashIn));

    ComputeSessionKey(sessionKey, e, c0, params);
    BSL_SAL_CleanseData(e, params->nBytes);
    BSL_SAL_FREE(e);
    return PQCP_SUCCESS;
}

static CRYPT_ERROR BuildVectorAndDecoding(uint8_t *e, const uint8_t *c0, const CMPrivateKey *sk, const McelieceParams *params)
{
    uint8_t *v = BSL_SAL_Calloc(params->nBytes, 1);
    if (v == NULL)
    {
        return PQCP_MALLOC_FAIL;
    }
    for (uint32_t i = 0; i < params->mt; i++)
    {
        uint32_t bit = VectorGetBit(c0, i);
        VectorSetBit(v, i, bit);
    }

    if (sk->controlbits == NULL)
    {
        BSL_SAL_FREE(v);
        return PQCP_MCELIECE_INVALID_ARG;
    }

    GFElement *gfL = (GFElement *)BSL_SAL_Malloc(sizeof(GFElement) * params->n);
    if (gfL == NULL)
    {
        BSL_SAL_FREE(v);
        return PQCP_MALLOC_FAIL;
    }
    SupportFromCbits(gfL, sk->controlbits, params->m, params->n);

    int32_t decodeSuccess;
    CRYPT_ERROR ret = DecodeGoppa(v, &sk->g, gfL, e, params->nBytes, &decodeSuccess, params);
    BSL_SAL_FREE(gfL);
    BSL_SAL_FREE(v);

    if (ret != PQCP_SUCCESS)
    {
        return ret;
    }
    if (decodeSuccess == 0)
    {
        memcpy_s(e, params->nBytes, sk->s, params->nBytes);
    }
    return PQCP_SUCCESS;
}

// K = Hash(b, e, C)
static void ComputeDecapSessionKey(uint8_t *sessionKey, uint8_t b, const uint8_t *e, const uint8_t *c, const McelieceParams *params)
{
    size_t inLen = 1 + params->nBytes + params->cipherBytes;
    uint8_t hashIn[inLen];
    hashIn[0] = b;
    memcpy_s(hashIn + 1, params->nBytes, e, params->nBytes);
    memcpy_s(hashIn + 1 + params->nBytes, params->cipherBytes, c, params->cipherBytes);
    McElieceShake256(sessionKey, MCELIECE_L_BYTES, hashIn, inLen);
}

// Decap algorithm (non-pc parameter sets)
CRYPT_ERROR McElieceDecaps(const uint8_t *ciphertext, const CMPrivateKey *sk, uint8_t *sessionKey, const McelieceParams *params)
{
    if (ciphertext == NULL || sk == NULL || sessionKey == NULL)
    {
        return PQCP_NULL_INPUT;
    }

    uint8_t *e = (uint8_t *)BSL_SAL_Malloc(params->nBytes);
    if (e == NULL)
    {
        return PQCP_MALLOC_FAIL;
    }

    CRYPT_ERROR ret = BuildVectorAndDecoding(e, ciphertext, sk, params);
    uint8_t b = (ret == PQCP_SUCCESS) ? 1 : 0; // If e = ⊥, set b <- 0
    ComputeDecapSessionKey(sessionKey, b, e, ciphertext, params);
    BSL_SAL_CleanseData(e, params->nBytes);
    BSL_SAL_FREE(e);
    return PQCP_SUCCESS;
}

CRYPT_ERROR McElieceDecapPC(const uint8_t *ciphertext, const CMPrivateKey *sk, uint8_t *sessionKey, const McelieceParams *params)
{
    if (ciphertext == NULL || sk == NULL || sessionKey == NULL)
    {
        return PQCP_NULL_INPUT;
    }
    const uint8_t *c0 = ciphertext;
    const uint8_t *c1 = ciphertext + params->cipherBytes;

    uint8_t *e = (uint8_t *)BSL_SAL_Malloc(params->nBytes);
    if (e == NULL)
    {
        return PQCP_MALLOC_FAIL;
    }
    CRYPT_ERROR ret = BuildVectorAndDecoding(e, c0, sk, params);
    // PC only: verify C1
    uint8_t hashIn[1 + MCELIECE_L_BYTES];
    hashIn[0] = 2;
    memcpy_s(hashIn + 1, MCELIECE_L_BYTES, e, MCELIECE_L_BYTES);
    uint8_t c1Prime[MCELIECE_L_BYTES];
    McElieceShake256(c1Prime, MCELIECE_L_BYTES, hashIn, sizeof(hashIn));

    uint8_t b = (ret == PQCP_SUCCESS) && (memcmp(c1Prime, c1, MCELIECE_L_BYTES) == 0) ? 1 : 0; // If e = ⊥ or C' != C1, set b <- 0
    ComputeDecapSessionKey(sessionKey, b, e, ciphertext, params);
    BSL_SAL_CleanseData(e, params->nBytes);
    BSL_SAL_FREE(e);
    return PQCP_SUCCESS;
}
