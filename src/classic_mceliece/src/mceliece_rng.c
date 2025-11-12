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

#include "mceliece_rng.h"

static const int32_t aes256KeyLength = 32;  // Key length in bytes for AES-256
static const int32_t aes256BlockSize = 16;  // Block size in bytes for AES
static const int32_t originSeedLength = 48; // Total seed-material length in bytes

typedef struct
{
    uint8_t Key[32];
    uint8_t V[16];
    int32_t reseed_counter;
} McElieceAES256CTRDrbgStruct;

static McElieceAES256CTRDrbgStruct g_McElieceDrbgCtx;
static int32_t g_256Ready = 0;
static CRYPT_EAL_CipherCtx *g_RandCtx = NULL;

static CRYPT_ERROR DrbgSetAES256Key(const uint8_t key[32])
{
    g_RandCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES256_ECB);
    if (g_RandCtx == NULL)
    {
        return PQCP_MALLOC_FAIL;
    }
    else
    {
        if (CRYPT_EAL_CipherInit(g_RandCtx, key, aes256KeyLength, NULL, 0, true) != 0)
        {
            CRYPT_EAL_CipherFreeCtx(g_RandCtx);
            return PQCP_MALLOC_FAIL;
        }
        if (CRYPT_EAL_CipherSetPadding(g_RandCtx, CRYPT_PADDING_NONE) != 0)
        {
            CRYPT_EAL_CipherFreeCtx(g_RandCtx);
            return PQCP_MALLOC_FAIL;
        }
        g_256Ready = 1;
    }
    return PQCP_SUCCESS;
}

static void ModeCTRIncBE(uint8_t V[16])
{
    for (int32_t i = 15; i >= 0; i--)
    { // 15  – Starting index for big-endian counter increment in ModeCTRIncBE
        if (V[i] == 0xFF)
        { // Byte value used to detect overflow during counter increment in ModeCTRIncBE
            V[i] = 0x00;
        }
        else
        {
            V[i]++;
            break;
        }
    }
}

static CRYPT_ERROR McElieceDrbgAES256Block(const uint8_t in[16], uint8_t out[16])
{
    int32_t outlen = aes256BlockSize;
    CRYPT_ERROR ret = CRYPT_EAL_CipherUpdate(g_RandCtx, in, aes256BlockSize, out, &outlen);
    if (ret != 0)
    {
        return PQCP_MALLOC_FAIL;
    }
    return PQCP_SUCCESS;
}

static CRYPT_ERROR McElieceAES256CTRDrbgUpdate(const uint8_t *providedData, uint8_t *Key, uint8_t *V)
{
    uint8_t temp[originSeedLength];
    uint8_t block[aes256BlockSize];

    for (int32_t i = 0; i < 3; i++)
    { // Number of 16-byte blocks (3 * 16 = 48) processed in McElieceAES256CTRDrbgUpdate
        ModeCTRIncBE(V);
        CRYPT_ERROR ret = McElieceDrbgAES256Block(V, block);
        if (ret != PQCP_SUCCESS)
        {
            return ret;
        }
        memcpy_s(&temp[aes256BlockSize * i], sizeof(temp) - aes256BlockSize * i, block, aes256BlockSize);
    }

    if (providedData != NULL)
    {
        for (int32_t i = 0; i < originSeedLength; i++)
            temp[i] ^= providedData[i];
    }

    memcpy_s(Key, aes256KeyLength, temp, aes256KeyLength);
    memcpy_s(V, aes256BlockSize, temp + aes256KeyLength, aes256BlockSize);
    return DrbgSetAES256Key(Key);
}

CRYPT_ERROR McElieceRandomBytesInit(const uint8_t *entropyInput, uint8_t *personalizationString, const int32_t securityStrength)
{
    uint8_t seedMaterial[originSeedLength];
    memcpy_s(seedMaterial, sizeof(seedMaterial), entropyInput, originSeedLength);
    if (personalizationString != NULL)
    {
        for (int32_t i = 0; i < originSeedLength; i++)
        {
            seedMaterial[i] ^= personalizationString[i];
        }
    }
    memset_s(g_McElieceDrbgCtx.Key, sizeof(g_McElieceDrbgCtx.Key), 0, (size_t)((securityStrength + 7) >> 3)); // bits to bytes
    memset_s(g_McElieceDrbgCtx.V, sizeof(g_McElieceDrbgCtx.V), 0, aes256BlockSize);

    CRYPT_ERROR ret = DrbgSetAES256Key(g_McElieceDrbgCtx.Key);
    if (ret != PQCP_SUCCESS)
    {
        return ret;
    }
    ret = McElieceAES256CTRDrbgUpdate(seedMaterial, g_McElieceDrbgCtx.Key, g_McElieceDrbgCtx.V);
    if (ret != PQCP_SUCCESS)
    {
        return ret;
    }
    g_McElieceDrbgCtx.reseed_counter = 1;
    return PQCP_SUCCESS;
}

CRYPT_ERROR McElieceRandomBytes(uint8_t *x, uint32_t xlen)
{
    uint8_t block[aes256BlockSize];
    uint64_t produced = 0;

    if (g_256Ready == 0)
    {
        memset_s(g_McElieceDrbgCtx.Key, sizeof(g_McElieceDrbgCtx.Key), 0, aes256KeyLength);
        CRYPT_ERROR ret = DrbgSetAES256Key(g_McElieceDrbgCtx.Key);
        if (ret != PQCP_SUCCESS)
        {
            return ret;
        }
    }

    while (xlen > 0)
    {
        ModeCTRIncBE(g_McElieceDrbgCtx.V);
        CRYPT_ERROR ret = McElieceDrbgAES256Block(g_McElieceDrbgCtx.V, block);
        if (ret != PQCP_SUCCESS)
        {
            return ret;
        }
        size_t take = (xlen >= aes256BlockSize) ? 16u : (size_t)xlen;
        memcpy_s(x + produced, xlen, block, take);
        produced += take;
        xlen -= take;
    }

    CRYPT_ERROR ret = McElieceAES256CTRDrbgUpdate(NULL, g_McElieceDrbgCtx.Key, g_McElieceDrbgCtx.V);
    if (ret != PQCP_SUCCESS)
    {
        return ret;
    }
    g_McElieceDrbgCtx.reseed_counter++;
    return PQCP_SUCCESS;
}
