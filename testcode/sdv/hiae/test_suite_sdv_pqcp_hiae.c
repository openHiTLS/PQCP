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

/* BEGIN_HEADER */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "crypt_errno.h"
#include "bsl_sal.h"
#include "crypt_types.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_mac.h"
#include "pqcp_provider.h"
#include "pqcp_err.h"
#include "hiae_local.h"
/* END_HEADER */

#ifdef PQCP_HIAE
static void FillSeq(uint8_t *buf, uint32_t len, uint8_t seed)
{
    uint32_t i;
    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t)(seed + i * 13U);
    }
}

static const uint32_t gHiaeRandLenGroups[] = {1U, 256U, 1024U, 8192U, 16384U};

static uint32_t RandRangeU32(uint32_t min, uint32_t max)
{
    if (max <= min) {
        return min;
    }
    return min + (uint32_t)(rand() % (int)(max - min + 1U));
}

static void FillRandBytes(uint8_t *buf, uint32_t len)
{
    uint32_t i;
    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xff);
    }
}

static bool IsNullInputRet(int32_t ret)
{
    return ret == PQCP_NULL_INPUT || ret == CRYPT_NULL_INPUT;
}

static int32_t HiaeSetAadByChunks(CRYPT_EAL_CipherCtx *ctx, const uint8_t *aad, uint32_t aadLen, const uint32_t *splits,
                                  uint32_t splitCount)
{
    uint32_t i;
    uint32_t offset = 0;
    int32_t ret;

    if (splitCount == 0) {
        return CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, (void *)aad, aadLen);
    }
    if (splits == NULL) {
        return PQCP_INVALID_ARG;
    }
    for (i = 0; i < splitCount; i++) {
        if (offset + splits[i] > aadLen) {
            return PQCP_INVALID_ARG;
        }
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, (void *)(aad + offset), splits[i]);
        if (ret != PQCP_SUCCESS) {
            return ret;
        }
        offset += splits[i];
    }
    return (offset == aadLen) ? PQCP_SUCCESS : PQCP_INVALID_ARG;
}

static int32_t HiaeCipherUpdateByChunks(CRYPT_EAL_CipherCtx *ctx, const uint8_t *in, uint32_t inLen, uint8_t *out,
                                        uint32_t outCap, const uint32_t *splits, uint32_t splitCount, bool callFinal,
                                        uint32_t *totalOut)
{
    uint32_t i;
    uint32_t offset = 0;
    uint32_t outOffset = 0;
    uint32_t chunkLen;
    uint32_t outLen;
    uint32_t finalLen;
    int32_t ret;

    if (splitCount == 0) {
        outLen = outCap;
        ret = CRYPT_EAL_CipherUpdate(ctx, in, inLen, out, &outLen);
        if (ret != PQCP_SUCCESS) {
            return ret;
        }
        outOffset = outLen;
    } else {
        for (i = 0; i < splitCount; i++) {
            chunkLen = splits[i];
            if (offset + chunkLen > inLen) {
                return PQCP_INVALID_ARG;
            }
            outLen = outCap - outOffset;
            ret = CRYPT_EAL_CipherUpdate(ctx, in + offset, chunkLen, out + outOffset, &outLen);
            if (ret != PQCP_SUCCESS) {
                return ret;
            }
            offset += chunkLen;
            outOffset += outLen;
        }
        if (offset != inLen) {
            return PQCP_INVALID_ARG;
        }
    }

    if (callFinal) {
        finalLen = outCap - outOffset;
        ret = CRYPT_EAL_CipherFinal(ctx, out + outOffset, &finalLen);
        if (ret != PQCP_SUCCESS) {
            return ret;
        }
        outOffset += finalLen;
    }

    *totalOut = outOffset;
    return PQCP_SUCCESS;
}

static int32_t HiaeMacUpdateByChunks(CRYPT_EAL_MacCtx *ctx, const uint8_t *data, uint32_t dataLen,
                                     const uint32_t *splits, uint32_t splitCount)
{
    uint32_t i;
    uint32_t offset = 0;
    uint32_t chunkLen;
    int32_t ret;

    if (splitCount == 0) {
        return CRYPT_EAL_MacUpdate(ctx, data, dataLen);
    }
    for (i = 0; i < splitCount; i++) {
        chunkLen = splits[i];
        if (offset + chunkLen > dataLen) {
            return PQCP_INVALID_ARG;
        }
        ret = CRYPT_EAL_MacUpdate(ctx, data + offset, chunkLen);
        if (ret != PQCP_SUCCESS) {
            return ret;
        }
        offset += chunkLen;
    }
    return (offset == dataLen) ? PQCP_SUCCESS : PQCP_INVALID_ARG;
}
#endif
/* @
* @test  SDV_CRYPTO_PQCP_HIAE_CIPHER_AEAD_API_TC001
* @spec  -
* @title  PQCP HiAE Cipher AEAD Draft Vector Test
* @precon  nan
* @brief  Validate provider AEAD output against draft-pham-cfrg-hiae vectors (ciphertext+tag)
* @expect  All vectors pass
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_HIAE_CIPHER_AEAD_API_TC001(Hex *keyHex, Hex *ivHex, Hex *aadHex, Hex *plainHex, Hex *cipherHex,
                                                Hex *tagHex)
{
#ifdef PQCP_HIAE
    CRYPT_EAL_CipherCtx *encCtx = NULL;
    CRYPT_EAL_CipherCtx *decCtx = NULL;
    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};
    uint8_t aad[4096] = {0};
    uint8_t plain[8192] = {0};
    uint8_t cipherExp[8192] = {0};
    uint8_t cipherOut[8192];
    uint8_t plainOut[8192];
    uint8_t tagExp[16] = {0};
    uint8_t tagOut[16];
    uint32_t keyLen = 0;
    uint32_t ivLen = 0;
    uint32_t aadLen = 0;
    uint32_t plainLen = 0;
    uint32_t cipherLen = 0;
    uint32_t tagLen = 0;
    uint32_t outLen;
    uint32_t totalLen;
    int32_t ret;

    encCtx = CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp");
    decCtx = CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp");
    ASSERT_TRUE(encCtx != NULL);
    ASSERT_TRUE(decCtx != NULL);
    ASSERT_TRUE(keyHex != NULL && ivHex != NULL && aadHex != NULL && plainHex != NULL && cipherHex != NULL &&
                tagHex != NULL);
    ASSERT_EQ(keyHex->len, sizeof(key));
    ASSERT_EQ(ivHex->len, sizeof(iv));
    ASSERT_EQ(tagHex->len, sizeof(tagExp));
    ASSERT_TRUE(aadHex->len <= sizeof(aad));
    ASSERT_TRUE(plainHex->len <= sizeof(plain));
    ASSERT_TRUE(cipherHex->len <= sizeof(cipherExp));

    keyLen = keyHex->len;
    ivLen = ivHex->len;
    aadLen = aadHex->len;
    plainLen = plainHex->len;
    cipherLen = cipherHex->len;
    tagLen = tagHex->len;

    ASSERT_EQ(plainLen, cipherLen);

    memcpy(key, keyHex->x, keyLen);
    memcpy(iv, ivHex->x, ivLen);
    if (aadLen > 0) {
        memcpy(aad, aadHex->x, aadLen);
    }
    if (plainLen > 0) {
        memcpy(plain, plainHex->x, plainLen);
    }
    if (cipherLen > 0) {
        memcpy(cipherExp, cipherHex->x, cipherLen);
    }
    memcpy(tagExp, tagHex->x, tagLen);

    ret = CRYPT_EAL_CipherInit(encCtx, key, keyLen, iv, ivLen, true);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_SET_AAD, aad, aadLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    outLen = plainLen;
    ret = CRYPT_EAL_CipherUpdate(encCtx, plain, plainLen, cipherOut, &outLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    totalLen = outLen;
    ASSERT_EQ(totalLen, plainLen);
    ret = CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_GET_TAG, tagOut, sizeof(tagOut));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_COMPARE("hiae aead cipher", cipherExp, cipherLen, cipherOut, totalLen);
    ASSERT_COMPARE("hiae aead tag", tagExp, tagLen, tagOut, tagLen);

    ret = CRYPT_EAL_CipherInit(decCtx, key, keyLen, iv, ivLen, false);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_SET_AAD, aad, aadLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    outLen = cipherLen;
    ret = CRYPT_EAL_CipherUpdate(decCtx, cipherExp, cipherLen, plainOut, &outLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    totalLen = outLen;
    ASSERT_EQ(totalLen, plainLen);
    ret = CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_GET_TAG, tagOut, sizeof(tagOut));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_COMPARE("hiae aead plain", plain, plainLen, plainOut, totalLen);
    ASSERT_COMPARE("hiae aead dec tag", tagExp, tagLen, tagOut, tagLen);

EXIT:
    CRYPT_EAL_CipherFreeCtx(encCtx);
    CRYPT_EAL_CipherFreeCtx(decCtx);
    return;
#else 
    SKIP_TEST();
    (void)keyHex;
    (void)ivHex;
    (void)aadHex;
    (void)plainHex;
    (void)cipherHex;
    (void)tagHex;
    return;
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_HIAE_MAC_API_TC001
* @spec  -
* @title  PQCP HiAE MAC Draft Vector Test
* @precon  nan
* @brief  Use draft vectors with empty plaintext to verify HiAE-MAC(tag over AD)
* @expect  All vectors pass
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_HIAE_MAC_API_TC001(Hex *keyHex, Hex *ivHex, Hex *aadHex, Hex *tagHex)
{
#ifdef PQCP_HIAE
    CRYPT_EAL_MacCtx *mac = NULL;
    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};
    uint8_t aad[4096] = {0};
    uint8_t tagExp[16] = {0};
    uint8_t tagOut[16];
    uint32_t keyLen = 0;
    uint32_t ivLen = 0;
    uint32_t aadLen = 0;
    uint32_t tagLen = 0;
    uint32_t maxMacLen = 0;
    int32_t ret;

    mac = CRYPT_EAL_ProviderMacNewCtx(NULL, PQCP_MAC_HIAE, "provider=pqcp");
    ASSERT_TRUE(mac != NULL);
    ASSERT_TRUE(keyHex != NULL && ivHex != NULL && aadHex != NULL && tagHex != NULL);
    ASSERT_EQ(keyHex->len, sizeof(key));
    ASSERT_EQ(ivHex->len, sizeof(iv));
    ASSERT_EQ(tagHex->len, sizeof(tagExp));
    ASSERT_TRUE(aadHex->len <= sizeof(aad));

    keyLen = keyHex->len;
    ivLen = ivHex->len;
    aadLen = aadHex->len;
    tagLen = tagHex->len;
    memcpy(key, keyHex->x, keyLen);
    memcpy(iv, ivHex->x, ivLen);
    if (aadLen > 0) {
        memcpy(aad, aadHex->x, aadLen);
    }
    memcpy(tagExp, tagHex->x, tagLen);

    ret = CRYPT_EAL_MacInit(mac, key, sizeof(key));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_MacCtrl(mac, CRYPT_CTRL_SET_IV, iv, sizeof(iv));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_MacUpdate(mac, aad, aadLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_MacCtrl(mac, CRYPT_CTRL_GET_MACLEN, &maxMacLen, sizeof(maxMacLen));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(maxMacLen, 16);
    tagLen = sizeof(tagOut);
    ret = CRYPT_EAL_MacFinal(mac, tagOut, &tagLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(tagLen, 16);
    ASSERT_COMPARE("hiae mac tag", tagExp, sizeof(tagExp), tagOut, sizeof(tagOut));

EXIT:
    CRYPT_EAL_MacFreeCtx(mac);
    return;
#else 
    SKIP_TEST();
    (void)keyHex;
    (void)ivHex;
    (void)aadHex;
    (void)tagHex;
    return;
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_HIAE_LOWLEVEL_AEAD_API_TC001
* @spec  -
* @title  PQCP HiAE Low-Level AEAD API Test
* @precon  nan
* @brief  Validate low-level one-shot AEAD encrypt/decrypt path
* @expect  ciphertext/plaintext/tag round trip succeeds
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_HIAE_LOWLEVEL_AEAD_API_TC001(void)
{
#ifdef PQCP_HIAE
    uint8_t key[HIAE_KEY_LEN];
    uint8_t iv[HIAE_IV_LEN];
    uint8_t aad[33];
    uint8_t plain[67];
    uint8_t cipher[67];
    uint8_t decode[67];
    uint8_t tagEnc[HIAE_TAG_LEN];
    uint8_t tagDec[HIAE_TAG_LEN];
    int32_t ret;

    FillSeq(key, sizeof(key), 0x11);
    FillSeq(iv, sizeof(iv), 0x22);
    FillSeq(aad, sizeof(aad), 0x33);
    FillSeq(plain, sizeof(plain), 0x44);

    ret = PQCP_HIAE_AEAD_Encrypt(key, sizeof(key), iv, sizeof(iv), plain, sizeof(plain), aad, sizeof(aad), cipher,
                            sizeof(cipher), tagEnc, sizeof(tagEnc));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = PQCP_HIAE_AEAD_Decrypt(key, sizeof(key), iv, sizeof(iv), decode, sizeof(decode), aad, sizeof(aad), cipher,
                            sizeof(cipher), tagDec, sizeof(tagDec));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ASSERT_COMPARE("hiae lowlevel cipher plain", plain, sizeof(plain), decode, sizeof(decode));
    ASSERT_COMPARE("hiae lowlevel cipher tag", tagEnc, sizeof(tagEnc), tagDec, sizeof(tagDec));

EXIT:
    return;
#else 
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_HIAE_LOWLEVEL_MAC_API_TC001
* @spec  -
* @title  PQCP HiAE Low-Level MAC API Test
* @precon  nan
* @brief  Validate low-level one-shot MAC output is stable
* @expect  repeated MAC computations produce identical tags
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_HIAE_LOWLEVEL_MAC_API_TC001(void)
{
#ifdef PQCP_HIAE
    uint8_t key[HIAE_KEY_LEN];
    uint8_t iv[HIAE_IV_LEN];
    uint8_t msg[77];
    uint8_t tagA[HIAE_TAG_LEN];
    uint8_t tagB[HIAE_TAG_LEN];
    int32_t ret;

    FillSeq(key, sizeof(key), 0x51);
    FillSeq(iv, sizeof(iv), 0x62);
    FillSeq(msg, sizeof(msg), 0x73);

    ret = PQCP_HIAE_Mac(key, sizeof(key), iv, sizeof(iv), msg, sizeof(msg), tagA, sizeof(tagA));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = PQCP_HIAE_Mac(key, sizeof(key), iv, sizeof(iv), msg, sizeof(msg), tagB, sizeof(tagB));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ASSERT_COMPARE("hiae lowlevel mac tag", tagA, sizeof(tagA), tagB, sizeof(tagB));

EXIT:
    return;
#else 
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_HIAE_CIPHER_TAMPER_API_TC001
* @spec  -
* @title  PQCP HiAE Cipher Tamper Test
* @precon  nan
* @brief  Verify tampering ciphertext changes the derived decrypt-side tag
* @expect  Decrypt-side tag differs from the original encrypt-side tag after ciphertext tampering
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_HIAE_CIPHER_TAMPER_API_TC001(void)
{
#ifdef PQCP_HIAE
    CRYPT_EAL_CipherCtx *encCtx = NULL;
    CRYPT_EAL_CipherCtx *decCtx = NULL;
    uint8_t key[HIAE_KEY_LEN];
    uint8_t iv[HIAE_IV_LEN];
    uint8_t aad[19];
    uint8_t plain[67];
    uint8_t cipher[67];
    uint8_t cipherTampered[67];
    uint8_t decode[67];
    uint8_t tagEnc[HIAE_TAG_LEN];
    uint8_t tagDec[HIAE_TAG_LEN];
    uint32_t outLen;
    uint32_t round;
    uint32_t pos;
    int32_t ret;

    FillSeq(key, sizeof(key), 0x15);
    FillSeq(iv, sizeof(iv), 0x26);
    FillSeq(aad, sizeof(aad), 0x37);
    FillSeq(plain, sizeof(plain), 0x48);

    encCtx = CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp");
    decCtx = CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp");
    ASSERT_TRUE(encCtx != NULL);
    ASSERT_TRUE(decCtx != NULL);

    ret = CRYPT_EAL_CipherInit(encCtx, key, sizeof(key), iv, sizeof(iv), true);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    outLen = sizeof(cipher);
    ret = CRYPT_EAL_CipherUpdate(encCtx, plain, sizeof(plain), cipher, &outLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(outLen, sizeof(cipher));
    ret = CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_GET_TAG, tagEnc, sizeof(tagEnc));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_CipherInit(decCtx, key, sizeof(key), iv, sizeof(iv), false);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    outLen = sizeof(decode);
    ret = CRYPT_EAL_CipherUpdate(decCtx, cipher, sizeof(cipher), decode, &outLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(outLen, sizeof(decode));
    ret = CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_GET_TAG, tagDec, sizeof(tagDec));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_COMPARE("hiae cipher untampered tag", tagEnc, sizeof(tagEnc), tagDec, sizeof(tagDec));

    srand(1);
    for (round = 0; round < 100; round++) {
        memcpy(cipherTampered, cipher, sizeof(cipherTampered));
        pos = RandRangeU32(0, sizeof(cipherTampered) - 1);
        cipherTampered[pos] ^= (uint8_t)(1 << (round % 8));

        ret = CRYPT_EAL_CipherInit(decCtx, key, sizeof(key), iv, sizeof(iv), false);
        ASSERT_EQ(ret, PQCP_SUCCESS);
        ret = CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad));
        ASSERT_EQ(ret, PQCP_SUCCESS);
        outLen = sizeof(decode);
        ret = CRYPT_EAL_CipherUpdate(decCtx, cipherTampered, sizeof(cipherTampered), decode, &outLen);
        ASSERT_EQ(ret, PQCP_SUCCESS);
        ASSERT_EQ(outLen, sizeof(decode));
        ret = CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_GET_TAG, tagDec, sizeof(tagDec));
        ASSERT_EQ(ret, PQCP_SUCCESS);

        ASSERT_NE(memcmp(tagEnc, tagDec, sizeof(tagEnc)), 0);
    }

EXIT:
    CRYPT_EAL_CipherFreeCtx(encCtx);
    CRYPT_EAL_CipherFreeCtx(decCtx);
    return;
#else 
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_HIAE_MAC_TAMPER_API_TC001
* @spec  -
* @title  PQCP HiAE MAC Tamper Test
* @precon  nan
* @brief  Verify MAC tags differ when the input data is tampered
* @expect  Tags before and after tampering are inconsistent
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_HIAE_MAC_TAMPER_API_TC001(void)
{
#ifdef PQCP_HIAE
    CRYPT_EAL_MacCtx *mac = NULL;
    uint8_t key[HIAE_KEY_LEN];
    uint8_t iv[HIAE_IV_LEN];
    uint8_t msg[77];
    uint8_t msgTampered[77];
    uint8_t tagA[HIAE_TAG_LEN];
    uint8_t tagB[HIAE_TAG_LEN];
    uint32_t tagLen;
    uint32_t round;
    uint32_t pos;
    int32_t ret;

    FillSeq(key, sizeof(key), 0x51);
    FillSeq(iv, sizeof(iv), 0x62);
    FillSeq(msg, sizeof(msg), 0x73);

    mac = CRYPT_EAL_ProviderMacNewCtx(NULL, PQCP_MAC_HIAE, "provider=pqcp");
    ASSERT_TRUE(mac != NULL);

    ret = CRYPT_EAL_MacInit(mac, key, sizeof(key));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_MacCtrl(mac, CRYPT_CTRL_SET_IV, iv, sizeof(iv));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_MacUpdate(mac, msg, sizeof(msg));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    tagLen = sizeof(tagA);
    ret = CRYPT_EAL_MacFinal(mac, tagA, &tagLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(tagLen, sizeof(tagA));

    srand(2);
    for (round = 0; round < 100; round++) {
        memcpy(msgTampered, msg, sizeof(msgTampered));
        pos = RandRangeU32(0, sizeof(msgTampered) - 1);
        msgTampered[pos] ^= (uint8_t)(1 << (round % 8));

        ret = CRYPT_EAL_MacReinit(mac);
        ASSERT_EQ(ret, PQCP_SUCCESS);
        ret = CRYPT_EAL_MacUpdate(mac, msgTampered, sizeof(msgTampered));
        ASSERT_EQ(ret, PQCP_SUCCESS);
        tagLen = sizeof(tagB);
        ret = CRYPT_EAL_MacFinal(mac, tagB, &tagLen);
        ASSERT_EQ(ret, PQCP_SUCCESS);
        ASSERT_EQ(tagLen, sizeof(tagB));

        ASSERT_NE(memcmp(tagA, tagB, sizeof(tagA)), 0);
    }

EXIT:
    CRYPT_EAL_MacFreeCtx(mac);
    return;
#else 
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_HIAE_CIPHER_ERROR_API_TC001
* @spec  -
* @title  PQCP HiAE Cipher Error Path Test
* @precon  nan
* @brief  Cover cipher provider error branches and special state transitions
* @expect  Error codes and special branches match implementation
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_HIAE_CIPHER_ERROR_API_TC001(void)
{
#ifdef PQCP_HIAE
    CRYPT_EAL_CipherCtx *ctx = NULL;
    CRYPT_EAL_CipherCtx *dupProbe = NULL;
    uint8_t key[HIAE_KEY_LEN];
    uint8_t iv[HIAE_IV_LEN];
    uint8_t aad[8];
    uint8_t in[8];
    uint8_t out[8];
    uint8_t tag[HIAE_TAG_LEN];
    uint32_t outLen;
    uint32_t blockSize;
    int32_t ret;

    FillSeq(key, sizeof(key), 0x11);
    FillSeq(iv, sizeof(iv), 0x22);
    FillSeq(aad, sizeof(aad), 0x33);
    FillSeq(in, sizeof(in), 0x44);

    ASSERT_TRUE(CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_MAC_HIAE, "provider=pqcp") == NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherDupCtx(NULL) == NULL);

    ctx = CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    ret = CRYPT_EAL_CipherInit(ctx, NULL, sizeof(key), iv, sizeof(iv), true);
    ASSERT_TRUE(IsNullInputRet(ret));
    ret = CRYPT_EAL_CipherInit(ctx, key, sizeof(key) - 1U, iv, sizeof(iv), true);
    ASSERT_EQ(ret, PQCP_INVALID_ARG);

    ret = CRYPT_EAL_CipherFinal(ctx, NULL, NULL);
    ASSERT_TRUE(IsNullInputRet(ret));
    outLen = 0;
    ret = CRYPT_EAL_CipherFinal(ctx, NULL, &outLen);
    ASSERT_TRUE(IsNullInputRet(ret));
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_IV, iv, sizeof(iv));
    ASSERT_EQ(ret, CRYPT_EAL_CIPHER_CTRL_ERROR);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad));
    ASSERT_EQ(ret, CRYPT_EAL_ERR_STATE);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, sizeof(tag));
    ASSERT_EQ(ret, CRYPT_EAL_ERR_STATE);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_BLOCKSIZE, NULL, sizeof(blockSize));
    ASSERT_EQ(ret, CRYPT_EAL_ERR_STATE);
    ret = CRYPT_EAL_CipherCtrl(ctx, 0x7fffffff, NULL, 0);
    ASSERT_EQ(ret, CRYPT_EAL_ERR_STATE);

    ret = CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    dupProbe = CRYPT_EAL_CipherDupCtx(ctx);
    ASSERT_TRUE(dupProbe != NULL);
    CRYPT_EAL_CipherFreeCtx(dupProbe);
    dupProbe = NULL;

    blockSize = 0;
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_BLOCKSIZE, &blockSize, sizeof(blockSize));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(blockSize, 16U);

    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, NULL, sizeof(aad));
    ASSERT_TRUE(IsNullInputRet(ret));
    ret = CRYPT_EAL_CipherReinit(ctx, iv, sizeof(iv));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, 0);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_CipherReinit(ctx, iv, sizeof(iv));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_CipherReinit(ctx, iv, sizeof(iv));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    outLen = sizeof(out);
    ret = CRYPT_EAL_CipherUpdate(ctx, in, 0, out, &outLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(outLen, 0U);

    outLen = 0;
    ret = CRYPT_EAL_CipherUpdate(ctx, in, sizeof(in), out, &outLen);
    ASSERT_EQ(ret, CRYPT_EAL_BUFF_LEN_NOT_ENOUGH);
    outLen = sizeof(out);
    ret = CRYPT_EAL_CipherUpdate(ctx, in, sizeof(in), NULL, &outLen);
    ASSERT_TRUE(IsNullInputRet(ret));

    outLen = sizeof(out);
    ret = CRYPT_EAL_CipherUpdate(ctx, in, 1U, out, &outLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad));
    ASSERT_EQ(ret, CRYPT_EAL_ERR_STATE);

    ret = CRYPT_EAL_CipherReinit(ctx, iv, sizeof(iv) - 1U);
    ASSERT_EQ(ret, PQCP_INVALID_ARG);
    ret = CRYPT_EAL_CipherReinit(ctx, iv, sizeof(iv));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, HIAE_TAG_LEN - 1U);
    ASSERT_EQ(ret, PQCP_INVALID_ARG);
    ret = CRYPT_EAL_CipherReinit(ctx, iv, sizeof(iv));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, sizeof(tag));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    outLen = sizeof(out);
    ret = CRYPT_EAL_CipherUpdate(ctx, in, 1U, out, &outLen);
    ASSERT_EQ(ret, CRYPT_EAL_ERR_STATE);
    CRYPT_EAL_CipherDeinit(ctx);

EXIT:
    CRYPT_EAL_CipherFreeCtx(dupProbe);
    CRYPT_EAL_CipherFreeCtx(ctx);
    return;
#else 
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_HIAE_MAC_ERROR_API_TC001
* @spec  -
* @title  PQCP HiAE MAC Error Path Test
* @precon  nan
* @brief  Cover MAC provider error branches and special state transitions
* @expect  Error codes and special branches match implementation
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_HIAE_MAC_ERROR_API_TC001(void)
{
#ifdef PQCP_HIAE
    CRYPT_EAL_MacCtx *ctx = NULL;
    CRYPT_EAL_MacCtx *dup = NULL;
    uint8_t key[HIAE_KEY_LEN];
    uint8_t iv[HIAE_IV_LEN];
    uint8_t data[17];
    uint8_t tag[HIAE_TAG_LEN];
    uint32_t outLen;
    uint32_t macLen;
    int32_t ret;

    FillSeq(key, sizeof(key), 0x31);
    FillSeq(iv, sizeof(iv), 0x42);
    FillSeq(data, sizeof(data), 0x53);

    ASSERT_TRUE(CRYPT_EAL_ProviderMacNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp") == NULL);
    ASSERT_TRUE(CRYPT_EAL_MacDupCtx(NULL) == NULL);

    ctx = CRYPT_EAL_ProviderMacNewCtx(NULL, PQCP_MAC_HIAE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    ret = CRYPT_EAL_MacInit(ctx, NULL, sizeof(key));
    ASSERT_TRUE(IsNullInputRet(ret));
    ret = CRYPT_EAL_MacInit(ctx, key, sizeof(key) - 1U);
    ASSERT_EQ(ret, PQCP_INVALID_ARG);
    ret = CRYPT_EAL_MacUpdate(ctx, data, sizeof(data));
    ASSERT_EQ(ret, CRYPT_EAL_ERR_STATE);
    ret = CRYPT_EAL_MacReinit(ctx);
    ASSERT_EQ(ret, CRYPT_EAL_ERR_STATE);
    ret = CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_IV, iv, sizeof(iv));
    ASSERT_EQ(ret, CRYPT_EAL_ERR_STATE);
    ret = CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_GET_MACLEN, NULL, sizeof(macLen));
    ASSERT_EQ(ret, PQCP_INVALID_ARG);
    ret = CRYPT_EAL_MacCtrl(ctx, 0x7fffffff, NULL, 0);
    ASSERT_EQ(ret, CRYPT_EAL_ERR_STATE);

    ret = CRYPT_EAL_MacInit(ctx, key, sizeof(key));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    dup = CRYPT_EAL_MacDupCtx(ctx);
    ASSERT_TRUE(dup != NULL);
    CRYPT_EAL_MacFreeCtx(dup);
    dup = NULL;

    ret = CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_IV, NULL, sizeof(iv));
    ASSERT_TRUE(IsNullInputRet(ret));
    ret = CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_IV, iv, sizeof(iv) - 1U);
    ASSERT_EQ(ret, PQCP_INVALID_ARG);
    ret = CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_IV, iv, sizeof(iv));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    macLen = 0;
    ret = CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_GET_MACLEN, &macLen, sizeof(macLen));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(macLen, HIAE_TAG_LEN);

    ret = CRYPT_EAL_MacUpdate(ctx, NULL, sizeof(data));
    ASSERT_TRUE(IsNullInputRet(ret));
    ret = CRYPT_EAL_MacUpdate(ctx, data, 0);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_MacUpdate(ctx, data, sizeof(data));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    outLen = HIAE_TAG_LEN - 1U;
    ret = CRYPT_EAL_MacFinal(ctx, tag, &outLen);
    ASSERT_EQ(ret, CRYPT_EAL_BUFF_LEN_NOT_ENOUGH);
    outLen = sizeof(tag);
    ret = CRYPT_EAL_MacFinal(ctx, tag, &outLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(outLen, HIAE_TAG_LEN);
    outLen = sizeof(tag);
    ret = CRYPT_EAL_MacFinal(ctx, tag, &outLen);
    ASSERT_EQ(ret, CRYPT_EAL_ERR_STATE);
    ret = CRYPT_EAL_MacUpdate(ctx, data, 1U);
    ASSERT_EQ(ret, CRYPT_EAL_ERR_STATE);

    ret = CRYPT_EAL_MacReinit(ctx);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    CRYPT_EAL_MacDeinit(ctx);

EXIT:
    CRYPT_EAL_MacFreeCtx(dup);
    CRYPT_EAL_MacFreeCtx(ctx);
    return;
#else 
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_HIAE_LOWLEVEL_ERROR_API_TC001
* @spec  -
* @title  PQCP HiAE Low-Level Error Path Test
* @precon  nan
* @brief  Cover low-level one-shot parameter validation branches
* @expect  Invalid parameters return PQCP_INVALID_ARG
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_HIAE_LOWLEVEL_ERROR_API_TC001(void)
{
#ifdef PQCP_HIAE
    uint8_t key[HIAE_KEY_LEN];
    uint8_t iv[HIAE_IV_LEN];
    uint8_t ad[8];
    uint8_t msg[8];
    uint8_t out[8];
    uint8_t tag[HIAE_TAG_LEN];
    int32_t ret;

    FillSeq(key, sizeof(key), 0x61);
    FillSeq(iv, sizeof(iv), 0x72);
    FillSeq(ad, sizeof(ad), 0x83);
    FillSeq(msg, sizeof(msg), 0x94);

    ret = PQCP_HIAE_AEAD_Encrypt(NULL, sizeof(key), iv, sizeof(iv), msg, sizeof(msg), ad, sizeof(ad), out, sizeof(out), tag,
                            sizeof(tag));
    ASSERT_EQ(ret, PQCP_INVALID_ARG);
    ret = PQCP_HIAE_AEAD_Encrypt(key, sizeof(key) - 1U, iv, sizeof(iv), msg, sizeof(msg), ad, sizeof(ad), out, sizeof(out),
                            tag, sizeof(tag));
    ASSERT_EQ(ret, PQCP_INVALID_ARG);
    ret = PQCP_HIAE_AEAD_Encrypt(key, sizeof(key), iv, sizeof(iv), msg, sizeof(msg), ad, sizeof(ad), out, sizeof(msg) - 1U,
                            tag, sizeof(tag));
    ASSERT_EQ(ret, PQCP_INVALID_ARG);
    ret = PQCP_HIAE_AEAD_Encrypt(key, sizeof(key), iv, sizeof(iv), NULL, sizeof(msg), ad, sizeof(ad), out, sizeof(out), tag,
                            sizeof(tag));
    ASSERT_EQ(ret, PQCP_INVALID_ARG);
    ret = PQCP_HIAE_AEAD_Encrypt(key, sizeof(key), iv, sizeof(iv), msg, sizeof(msg), NULL, sizeof(ad), out, sizeof(out), tag,
                            sizeof(tag));
    ASSERT_EQ(ret, PQCP_INVALID_ARG);
    ret = PQCP_HIAE_AEAD_Encrypt(key, sizeof(key), iv, sizeof(iv), msg, sizeof(msg), ad, sizeof(ad), out, sizeof(out), tag,
                            sizeof(tag) - 1U);
    ASSERT_EQ(ret, PQCP_INVALID_ARG);

    ret = PQCP_HIAE_AEAD_Decrypt(key, sizeof(key), iv, sizeof(iv), out, sizeof(msg), ad, sizeof(ad), msg, sizeof(msg) - 1U,
                            tag, sizeof(tag));
    ASSERT_EQ(ret, PQCP_INVALID_ARG);
    ret = PQCP_HIAE_AEAD_Decrypt(key, sizeof(key), iv, sizeof(iv), NULL, sizeof(msg), ad, sizeof(ad), msg, sizeof(msg), tag,
                            sizeof(tag));
    ASSERT_EQ(ret, PQCP_INVALID_ARG);
    ret = PQCP_HIAE_AEAD_Decrypt(key, sizeof(key), iv, sizeof(iv), out, sizeof(msg), NULL, sizeof(ad), msg, sizeof(msg), tag,
                            sizeof(tag));
    ASSERT_EQ(ret, PQCP_INVALID_ARG);

    ret = PQCP_HIAE_Mac(NULL, sizeof(key), iv, sizeof(iv), msg, sizeof(msg), tag, sizeof(tag));
    ASSERT_EQ(ret, PQCP_INVALID_ARG);
    ret = PQCP_HIAE_Mac(key, sizeof(key), iv, sizeof(iv) - 1U, msg, sizeof(msg), tag, sizeof(tag));
    ASSERT_EQ(ret, PQCP_INVALID_ARG);
    ret = PQCP_HIAE_Mac(key, sizeof(key), iv, sizeof(iv), NULL, sizeof(msg), tag, sizeof(tag));
    ASSERT_EQ(ret, PQCP_INVALID_ARG);
    ret = PQCP_HIAE_Mac(key, sizeof(key), iv, sizeof(iv), msg, sizeof(msg), tag, sizeof(tag) - 1U);
    ASSERT_EQ(ret, PQCP_INVALID_ARG);

EXIT:
    return;
#else 
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_HIAE_CIPHER_RANDOM_API_TC001
* @spec  -
* @title  PQCP HiAE Cipher Random Data Functional Test
* @precon  nan
* @brief  Validate random AEAD round-trip over grouped random lengths
* @expect  plaintext and tag are consistent between encrypt/decrypt paths
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_HIAE_CIPHER_RANDOM_API_TC001(void)
{
#ifdef PQCP_HIAE
    const uint32_t roundsPerGroup = 200U;
    CRYPT_EAL_CipherCtx *encCtx = NULL;
    CRYPT_EAL_CipherCtx *decCtx = NULL;
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t aad[16384];
    uint8_t plain[16384];
    uint8_t cipher[16384];
    uint8_t decode[16384];
    uint8_t tagEnc[16];
    uint8_t tagDec[16];
    uint32_t g;
    uint32_t t;
    uint32_t msgLen;
    uint32_t aadLen;
    uint32_t outLen;
    uint32_t totalOut;
    int32_t ret;

    srand(1);
    encCtx = CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp");
    decCtx = CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp");
    ASSERT_TRUE(encCtx != NULL);
    ASSERT_TRUE(decCtx != NULL);

    for (g = 0; g < (sizeof(gHiaeRandLenGroups) / sizeof(gHiaeRandLenGroups[0]) - 1U); g++) {
        for (t = 0; t < roundsPerGroup; t++) {
            msgLen = RandRangeU32(gHiaeRandLenGroups[g], gHiaeRandLenGroups[g + 1U]);
            aadLen = RandRangeU32(gHiaeRandLenGroups[g], gHiaeRandLenGroups[g + 1U]);

            FillRandBytes(key, sizeof(key));
            FillRandBytes(iv, sizeof(iv));
            FillRandBytes(aad, aadLen);
            FillRandBytes(plain, msgLen);

            ret = CRYPT_EAL_CipherInit(encCtx, key, sizeof(key), iv, sizeof(iv), true);
            ASSERT_EQ(ret, PQCP_SUCCESS);
            ret = CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_SET_AAD, aad, aadLen);
            ASSERT_EQ(ret, PQCP_SUCCESS);
            outLen = msgLen;
            ret = CRYPT_EAL_CipherUpdate(encCtx, plain, msgLen, cipher, &outLen);
            ASSERT_EQ(ret, PQCP_SUCCESS);
            totalOut = outLen;
            ASSERT_EQ(totalOut, msgLen);
            ret = CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_GET_TAG, tagEnc, sizeof(tagEnc));
            ASSERT_EQ(ret, PQCP_SUCCESS);

            ret = CRYPT_EAL_CipherInit(decCtx, key, sizeof(key), iv, sizeof(iv), false);
            ASSERT_EQ(ret, PQCP_SUCCESS);
            ret = CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_SET_AAD, aad, aadLen);
            ASSERT_EQ(ret, PQCP_SUCCESS);
            outLen = msgLen;
            ret = CRYPT_EAL_CipherUpdate(decCtx, cipher, msgLen, decode, &outLen);
            ASSERT_EQ(ret, PQCP_SUCCESS);
            totalOut = outLen;
            ASSERT_EQ(totalOut, msgLen);
            ret = CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_GET_TAG, tagDec, sizeof(tagDec));
            ASSERT_EQ(ret, PQCP_SUCCESS);

            ASSERT_COMPARE("hiae random plain", plain, msgLen, decode, msgLen);
            ASSERT_COMPARE("hiae random tag", tagEnc, sizeof(tagEnc), tagDec, sizeof(tagDec));
        }
    }

EXIT:
    CRYPT_EAL_CipherFreeCtx(encCtx);
    CRYPT_EAL_CipherFreeCtx(decCtx);
    return;
#else 
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_HIAE_CIPHER_STREAMING_API_TC001
* @spec  -
* @title  PQCP HiAE Cipher Streaming Invariance Test
* @precon  nan
* @brief  Verify ciphertext/plaintext/tag are invariant across different Update chunking under the GET_TAG endpoint
* @expect  All chunking paths produce identical outputs
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_HIAE_CIPHER_STREAMING_API_TC001(void)
{
#ifdef PQCP_HIAE
    const uint32_t aadLen = 37U;
    const uint32_t msgLen = 52U;
    const uint32_t msgSplitB[] = {16U, 16U, 8U, 12U};
    const uint32_t msgSplitD[] = {15U, 2U, 14U, 3U, 1U, 17U};
    const uint32_t msgSplitC[] = {1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U,
                                  1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U,
                                  1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U};
    const uint32_t alignedLen = 64U;
    const uint32_t alignedSplit[] = {16U, 16U, 16U, 16U};
    CRYPT_EAL_CipherCtx *encCtx = NULL;
    CRYPT_EAL_CipherCtx *decCtx = NULL;
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t aad[64];
    uint8_t msg[128];
    uint8_t cipherA[128] = {0};
    uint8_t cipherB[128] = {0};
    uint8_t cipherC[128] = {0};
    uint8_t cipherD[128] = {0};
    uint8_t plainA[128] = {0};
    uint8_t plainB[128] = {0};
    uint8_t plainC[128] = {0};
    uint8_t plainD[128] = {0};
    uint8_t tagA[16] = {0};
    uint8_t tagB[16] = {0};
    uint8_t tagC[16] = {0};
    uint8_t tagD[16] = {0};
    uint8_t alignedCipherA[128] = {0};
    uint8_t alignedCipherB[128] = {0};
    uint8_t alignedTagA[16] = {0};
    uint8_t alignedTagB[16] = {0};
    uint32_t outLenA = 0;
    uint32_t outLenB = 0;
    uint32_t outLenC = 0;
    uint32_t outLenD = 0;
    int32_t ret;

    FillSeq(key, sizeof(key), 0x21);
    FillSeq(iv, sizeof(iv), 0x43);
    FillSeq(aad, aadLen, 0x65);
    FillSeq(msg, msgLen, 0x87);

    encCtx = CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp");
    decCtx = CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp");
    ASSERT_TRUE(encCtx != NULL);
    ASSERT_TRUE(decCtx != NULL);

    ret = CRYPT_EAL_CipherInit(encCtx, key, sizeof(key), iv, sizeof(iv), true);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeSetAadByChunks(encCtx, aad, aadLen, NULL, 0);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeCipherUpdateByChunks(encCtx, msg, msgLen, cipherA, sizeof(cipherA), NULL, 0, false, &outLenA);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(outLenA, msgLen);
    ret = CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_GET_TAG, tagA, sizeof(tagA));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    CRYPT_EAL_CipherFreeCtx(encCtx);
    encCtx = CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp");
    ASSERT_TRUE(encCtx != NULL);

    ret = CRYPT_EAL_CipherInit(encCtx, key, sizeof(key), iv, sizeof(iv), true);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeSetAadByChunks(encCtx, aad, aadLen, NULL, 0);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeCipherUpdateByChunks(encCtx, msg, msgLen, cipherB, sizeof(cipherB), msgSplitB,
                                   sizeof(msgSplitB) / sizeof(msgSplitB[0]), false, &outLenB);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(outLenB, msgLen);
    ret = CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_GET_TAG, tagB, sizeof(tagB));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    CRYPT_EAL_CipherFreeCtx(encCtx);
    encCtx = CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp");
    ASSERT_TRUE(encCtx != NULL);

    ret = CRYPT_EAL_CipherInit(encCtx, key, sizeof(key), iv, sizeof(iv), true);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeSetAadByChunks(encCtx, aad, aadLen, NULL, 0);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeCipherUpdateByChunks(encCtx, msg, msgLen, cipherC, sizeof(cipherC), msgSplitC,
                                   sizeof(msgSplitC) / sizeof(msgSplitC[0]), false, &outLenC);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(outLenC, msgLen);
    ret = CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_GET_TAG, tagC, sizeof(tagC));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    CRYPT_EAL_CipherFreeCtx(encCtx);
    encCtx = CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp");
    ASSERT_TRUE(encCtx != NULL);

    ret = CRYPT_EAL_CipherInit(encCtx, key, sizeof(key), iv, sizeof(iv), true);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeSetAadByChunks(encCtx, aad, aadLen, NULL, 0);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeCipherUpdateByChunks(encCtx, msg, msgLen, cipherD, sizeof(cipherD), msgSplitD,
                                   sizeof(msgSplitD) / sizeof(msgSplitD[0]), false, &outLenD);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(outLenD, msgLen);
    ret = CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_GET_TAG, tagD, sizeof(tagD));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ASSERT_COMPARE("hiae stream enc split B", cipherA, outLenA, cipherB, outLenB);
    ASSERT_COMPARE("hiae stream enc split C", cipherA, outLenA, cipherC, outLenC);
    ASSERT_COMPARE("hiae stream enc split D", cipherA, outLenA, cipherD, outLenD);
    ASSERT_COMPARE("hiae stream tag split B", tagA, sizeof(tagA), tagB, sizeof(tagB));
    ASSERT_COMPARE("hiae stream tag split C", tagA, sizeof(tagA), tagC, sizeof(tagC));
    ASSERT_COMPARE("hiae stream tag split D", tagA, sizeof(tagA), tagD, sizeof(tagD));

    ret = CRYPT_EAL_CipherInit(decCtx, key, sizeof(key), iv, sizeof(iv), false);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeSetAadByChunks(decCtx, aad, aadLen, NULL, 0);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeCipherUpdateByChunks(decCtx, cipherA, outLenA, plainA, sizeof(plainA), NULL, 0, false, &outLenA);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_GET_TAG, tagA, sizeof(tagA));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    CRYPT_EAL_CipherFreeCtx(decCtx);
    decCtx = CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp");
    ASSERT_TRUE(decCtx != NULL);

    ret = CRYPT_EAL_CipherInit(decCtx, key, sizeof(key), iv, sizeof(iv), false);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeSetAadByChunks(decCtx, aad, aadLen, NULL, 0);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeCipherUpdateByChunks(decCtx, cipherA, outLenB, plainB, sizeof(plainB), msgSplitB,
                                   sizeof(msgSplitB) / sizeof(msgSplitB[0]), false, &outLenB);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_GET_TAG, tagB, sizeof(tagB));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    CRYPT_EAL_CipherFreeCtx(decCtx);
    decCtx = CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp");
    ASSERT_TRUE(decCtx != NULL);

    ret = CRYPT_EAL_CipherInit(decCtx, key, sizeof(key), iv, sizeof(iv), false);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeSetAadByChunks(decCtx, aad, aadLen, NULL, 0);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeCipherUpdateByChunks(decCtx, cipherA, outLenC, plainC, sizeof(plainC), msgSplitC,
                                   sizeof(msgSplitC) / sizeof(msgSplitC[0]), false, &outLenC);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_GET_TAG, tagC, sizeof(tagC));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    CRYPT_EAL_CipherFreeCtx(decCtx);
    decCtx = CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp");
    ASSERT_TRUE(decCtx != NULL);

    ret = CRYPT_EAL_CipherInit(decCtx, key, sizeof(key), iv, sizeof(iv), false);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeSetAadByChunks(decCtx, aad, aadLen, NULL, 0);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeCipherUpdateByChunks(decCtx, cipherA, outLenD, plainD, sizeof(plainD), msgSplitD,
                                   sizeof(msgSplitD) / sizeof(msgSplitD[0]), false, &outLenD);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_GET_TAG, tagD, sizeof(tagD));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ASSERT_COMPARE("hiae stream dec plain A", msg, msgLen, plainA, outLenA);
    ASSERT_COMPARE("hiae stream dec plain B", msg, msgLen, plainB, outLenB);
    ASSERT_COMPARE("hiae stream dec plain C", msg, msgLen, plainC, outLenC);
    ASSERT_COMPARE("hiae stream dec plain D", msg, msgLen, plainD, outLenD);
    ASSERT_COMPARE("hiae stream dec tag B", tagA, sizeof(tagA), tagB, sizeof(tagB));
    ASSERT_COMPARE("hiae stream dec tag C", tagA, sizeof(tagA), tagC, sizeof(tagC));
    ASSERT_COMPARE("hiae stream dec tag D", tagA, sizeof(tagA), tagD, sizeof(tagD));

    FillSeq(msg, alignedLen, 0xa6);
    CRYPT_EAL_CipherFreeCtx(encCtx);
    encCtx = CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp");
    ASSERT_TRUE(encCtx != NULL);
    ret = CRYPT_EAL_CipherInit(encCtx, key, sizeof(key), iv, sizeof(iv), true);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeSetAadByChunks(encCtx, aad, aadLen, NULL, 0);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeCipherUpdateByChunks(encCtx, msg, alignedLen, alignedCipherA, sizeof(alignedCipherA), NULL, 0, false,
                                   &outLenA);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(outLenA, alignedLen);
    ret = CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_GET_TAG, alignedTagA, sizeof(alignedTagA));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    CRYPT_EAL_CipherFreeCtx(encCtx);
    encCtx = CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp");
    ASSERT_TRUE(encCtx != NULL);
    ret = CRYPT_EAL_CipherInit(encCtx, key, sizeof(key), iv, sizeof(iv), true);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeSetAadByChunks(encCtx, aad, aadLen, NULL, 0);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeCipherUpdateByChunks(encCtx, msg, alignedLen, alignedCipherB, sizeof(alignedCipherB), alignedSplit,
                                   sizeof(alignedSplit) / sizeof(alignedSplit[0]), false, &outLenB);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(outLenB, alignedLen);
    ret = CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_GET_TAG, alignedTagB, sizeof(alignedTagB));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ASSERT_COMPARE("hiae endpoint gettag-only cipher", alignedCipherA, outLenA, alignedCipherB, outLenB);
    ASSERT_COMPARE("hiae endpoint gettag-only tag", alignedTagA, sizeof(alignedTagA), alignedTagB, sizeof(alignedTagB));

EXIT:
    CRYPT_EAL_CipherFreeCtx(encCtx);
    CRYPT_EAL_CipherFreeCtx(decCtx);
    return;
#else 
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_HIAE_CIPHER_AAD_ONCE_API_TC001
* @spec  -
* @title  PQCP HiAE Cipher SET_AAD Test
* @precon  nan
* @brief  Validate single-shot SET_AAD succeeds before payload update and is rejected after payload starts
* @expect  Single-shot SET_AAD succeeds before update, later SET_AAD fails with CRYPT_EAL_ERR_STATE
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_HIAE_CIPHER_AAD_ONCE_API_TC001(void)
{
#ifdef PQCP_HIAE
    CRYPT_EAL_CipherCtx *ctx = NULL;
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t aad[32];
    uint8_t in[8];
    uint8_t out[8];
    uint32_t outLen;
    int32_t ret;

    FillSeq(key, sizeof(key), 0x12);
    FillSeq(iv, sizeof(iv), 0x34);
    FillSeq(aad, sizeof(aad), 0x56);
    FillSeq(in, sizeof(in), 0x78);

    ctx = CRYPT_EAL_ProviderCipherNewCtx(NULL, PQCP_CIPHER_HIAE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    ret = CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    /*
     * TODO: enable this when CRYPT_EAL_CipherCtrl supports multiple AAD chunks.
     * const uint32_t aadSplits[] = {5, 7, 20, 5};
     * ret = HiaeSetAadByChunks(ctx, aad, sizeof(aad), aadSplits, sizeof(aadSplits) / sizeof(aadSplits[0]));
     * ASSERT_EQ(ret, PQCP_SUCCESS);
    */

    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    outLen = sizeof(out);
    ret = CRYPT_EAL_CipherUpdate(ctx, in, sizeof(in), out, &outLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(outLen, sizeof(in));
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, 1U);
    ASSERT_EQ(ret, CRYPT_EAL_ERR_STATE);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    return;
#else 
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_HIAE_MAC_STREAMING_API_TC001
* @spec  -
* @title  PQCP HiAE MAC Streaming Invariance Test
* @precon  nan
* @brief  Verify MAC tag is invariant for different MacUpdate chunking
* @expect  Tag is identical across all chunking strategies
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_HIAE_MAC_STREAMING_API_TC001(void)
{
#ifdef PQCP_HIAE
    const uint32_t dataLen = 77U;
    const uint32_t splitB[] = {16U, 16U, 8U, 21U, 16U};
    const uint32_t splitD[] = {15U, 2U, 14U, 3U, 1U, 17U, 25U};
    const uint32_t splitC[] = {1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U,
                               1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U,
                               1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U,
                               1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U};
    CRYPT_EAL_MacCtx *mac = NULL;
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t data[128];
    uint8_t tagA[16] = {0};
    uint8_t tagB[16] = {0};
    uint8_t tagC[16] = {0};
    uint8_t tagD[16] = {0};
    uint32_t tagLen;
    int32_t ret;

    FillSeq(key, sizeof(key), 0x10);
    FillSeq(iv, sizeof(iv), 0x40);
    FillSeq(data, dataLen, 0x70);
    mac = CRYPT_EAL_ProviderMacNewCtx(NULL, PQCP_MAC_HIAE, "provider=pqcp");
    ASSERT_TRUE(mac != NULL);

    ret = CRYPT_EAL_MacInit(mac, key, sizeof(key));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_MacCtrl(mac, CRYPT_CTRL_SET_IV, iv, sizeof(iv));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeMacUpdateByChunks(mac, data, dataLen, NULL, 0);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    tagLen = sizeof(tagA);
    ret = CRYPT_EAL_MacFinal(mac, tagA, &tagLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(tagLen, sizeof(tagA));

    ret = CRYPT_EAL_MacInit(mac, key, sizeof(key));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_MacCtrl(mac, CRYPT_CTRL_SET_IV, iv, sizeof(iv));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeMacUpdateByChunks(mac, data, dataLen, splitB, sizeof(splitB) / sizeof(splitB[0]));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    tagLen = sizeof(tagB);
    ret = CRYPT_EAL_MacFinal(mac, tagB, &tagLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(tagLen, sizeof(tagB));

    ret = CRYPT_EAL_MacInit(mac, key, sizeof(key));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_MacCtrl(mac, CRYPT_CTRL_SET_IV, iv, sizeof(iv));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeMacUpdateByChunks(mac, data, dataLen, splitC, sizeof(splitC) / sizeof(splitC[0]));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    tagLen = sizeof(tagC);
    ret = CRYPT_EAL_MacFinal(mac, tagC, &tagLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(tagLen, sizeof(tagC));

    ret = CRYPT_EAL_MacInit(mac, key, sizeof(key));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_MacCtrl(mac, CRYPT_CTRL_SET_IV, iv, sizeof(iv));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = HiaeMacUpdateByChunks(mac, data, dataLen, splitD, sizeof(splitD) / sizeof(splitD[0]));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    tagLen = sizeof(tagD);
    ret = CRYPT_EAL_MacFinal(mac, tagD, &tagLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(tagLen, sizeof(tagD));

    ASSERT_COMPARE("hiae mac split B", tagA, sizeof(tagA), tagB, sizeof(tagB));
    ASSERT_COMPARE("hiae mac split C", tagA, sizeof(tagA), tagC, sizeof(tagC));
    ASSERT_COMPARE("hiae mac split D", tagA, sizeof(tagA), tagD, sizeof(tagD));

EXIT:
    CRYPT_EAL_MacFreeCtx(mac);
    return;
#else 
    SKIP_TEST();
#endif
}
/* END_CASE */
