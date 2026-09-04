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
#include <stdint.h>
#include <string.h>

#include "bsl_params.h"
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_rand.h"
#include "pqcp_err.h"
#include "pqcp_provider.h"
#include "pqcp_types.h"
/* END_HEADER */

#ifdef PQCP_AIGIS_SIG
#define TEST_AIGIS_SIG_I_HINT_OFFSET  1952U
#define TEST_AIGIS_SIG_II_HINT_OFFSET 4384U
#define TEST_AIGIS_SIG_III_HINT_OFFSET 9024U

static const uint8_t g_aigisSigRegressionEntropy[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
static const uint8_t g_aigisSigIIIRegressionEntropy[64] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F};
static const uint8_t *g_aigisSigEntropy = NULL;
static uint32_t g_aigisSigEntropyLen = 0U;
static uint32_t g_aigisSigRandCalls = 0U;

static int32_t TEST_AigisSigRandom(uint8_t *output, uint32_t outputLen)
{
    if (output == NULL || g_aigisSigEntropy == NULL || outputLen != g_aigisSigEntropyLen || g_aigisSigRandCalls != 0U) {
        return -1;
    }
    (void)memcpy(output, g_aigisSigEntropy, outputLen);
    g_aigisSigRandCalls++;
    return 0;
}

static int32_t TEST_AigisSigRandomEx(void *libCtx, uint8_t *output, uint32_t outputLen)
{
    (void)libCtx;
    return TEST_AigisSigRandom(output, outputLen);
}

static void TEST_AigisSigRandClear(void)
{
    CRYPT_EAL_SetRandCallBack(NULL);
    CRYPT_EAL_SetRandCallBackEx(NULL);
    g_aigisSigEntropy = NULL;
    g_aigisSigEntropyLen = 0U;
    g_aigisSigRandCalls = 0U;
}

static void TEST_AigisSigSetRegressionEntropy(int32_t algId)
{
    if (algId == PQCP_AIGIS_SIG_SM3_III || algId == PQCP_AIGIS_SIG_SHA3_III) {
        g_aigisSigEntropy = g_aigisSigIIIRegressionEntropy;
        g_aigisSigEntropyLen = sizeof(g_aigisSigIIIRegressionEntropy);
    } else {
        g_aigisSigEntropy = g_aigisSigRegressionEntropy;
        g_aigisSigEntropyLen = sizeof(g_aigisSigRegressionEntropy);
    }
    g_aigisSigRandCalls = 0U;
}

static uint32_t TEST_AigisSigCompactSignatureLen(const uint8_t *signature, uint32_t hintOffset)
{
    const uint32_t sectionCount = signature[hintOffset];
    const uint32_t countLen = (sectionCount + 1U) >> 1;
    uint32_t hintCount = 0U;

    for (uint32_t i = 0U; i < sectionCount; i++) {
        const uint8_t packedCounts = signature[hintOffset + 1U + (i >> 1)];
        hintCount += (packedCounts >> ((i & 1U) << 2)) & 0x0fU;
    }
    return hintOffset + 1U + countLen + ((hintCount * 6U + 7U) >> 3);
}

static int32_t TEST_AigisSigIsZero(const uint8_t *data, uint32_t dataLen)
{
    uint8_t diff = 0U;
    for (uint32_t i = 0U; i < dataLen; i++) {
        diff |= data[i];
    }
    return diff == 0U;
}
#endif

/* @
* @test  SDV_CRYPTO_PQCP_AIGIS_SIG_KAT_TC001
* @spec  -
* @title Aigis-Sig+ accepted KAT through the PQCP provider
* @precon nan
* @brief 1. Register the accepted KAT key-generation entropy
*        2. Generate and export the key pair through the provider
*        3. Sign the accepted message and compare its compact encoding and zero padding
*        4. Verify the fixed-length signature and reject the compact legacy encoding
* @expect PK, SK and compact signature fields match the accepted vector; padding is canonical
* @prior  nan
* @auto   TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_AIGIS_SIG_KAT_TC001(int algId, Hex *entropy, Hex *expectedPk, Hex *expectedSk, Hex *message,
                                         Hex *expectedSig)
{
#ifdef PQCP_AIGIS_SIG
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *importPrvCtx = NULL;
    CRYPT_EAL_PkeyCtx *importPubCtx = NULL;
    uint8_t *pubKey = NULL;
    uint8_t *prvKey = NULL;
    uint8_t *signature = NULL;
    uint32_t pubKeyLen = 0U;
    uint32_t prvKeyLen = 0U;
    uint32_t signatureCapacity = 0U;
    uint32_t signatureLen = 0U;

    TestMemInit();
    ASSERT_EQ(entropy->len,
              algId == PQCP_AIGIS_SIG_SM3_III || algId == PQCP_AIGIS_SIG_SHA3_III ? 64U : 32U);
    g_aigisSigEntropy = entropy->x;
    g_aigisSigEntropyLen = entropy->len;
    g_aigisSigRandCalls = 0U;
    CRYPT_EAL_SetRandCallBack(TEST_AigisSigRandom);
    CRYPT_EAL_SetRandCallBackEx(TEST_AigisSigRandomEx);

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_AIGIS_SIG, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen)), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &prvKeyLen, sizeof(prvKeyLen)), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SIGNLEN, &signatureCapacity, sizeof(signatureCapacity)),
              PQCP_SUCCESS);
    ASSERT_EQ(pubKeyLen, expectedPk->len);
    ASSERT_EQ(prvKeyLen, expectedSk->len);
    ASSERT_TRUE(signatureCapacity > expectedSig->len);

    pubKey = BSL_SAL_Malloc(pubKeyLen);
    prvKey = BSL_SAL_Malloc(prvKeyLen);
    signature = BSL_SAL_Malloc(signatureCapacity);
    ASSERT_TRUE(pubKey != NULL && prvKey != NULL && signature != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), PQCP_SUCCESS);
    ASSERT_EQ(g_aigisSigRandCalls, 1U);

    BSL_Param pubParams[2] = {{PQCP_PARAM_AIGIS_SIG_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey, pubKeyLen, 0U},
                              BSL_PARAM_END};
    BSL_Param prvParams[2] = {{PQCP_PARAM_AIGIS_SIG_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvKey, prvKeyLen, 0U},
                              BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, pubParams), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(ctx, prvParams), PQCP_SUCCESS);
    ASSERT_EQ(pubParams[0].useLen, expectedPk->len);
    ASSERT_EQ(prvParams[0].useLen, expectedSk->len);
    ASSERT_COMPARE("Aigis-Sig+ KAT public key", pubKey, pubParams[0].useLen, expectedPk->x, expectedPk->len);
    ASSERT_COMPARE("Aigis-Sig+ KAT private key", prvKey, prvParams[0].useLen, expectedSk->x, expectedSk->len);

    signatureLen = signatureCapacity;
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_MAX, message->x, message->len, signature, &signatureLen), PQCP_SUCCESS);
    ASSERT_EQ(signatureLen, signatureCapacity);
    ASSERT_COMPARE("Aigis-Sig+ KAT signature", signature, expectedSig->len, expectedSig->x, expectedSig->len);
    ASSERT_TRUE(TEST_AigisSigIsZero(signature + expectedSig->len, signatureLen - expectedSig->len));
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, message->x, message->len, signature, signatureLen), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, message->x, message->len, expectedSig->x, expectedSig->len),
              PQCP_AIGIS_SIG_INVALID_SIG_LEN);
    ASSERT_EQ(g_aigisSigRandCalls, 1U);

    /*
     * Importing the authoritative keys verifies that generation and import
     * share the same external representation. The backend matrix runs this
     * byte-exact contract independently for the C and ARMv8 builds.
     */
    importPrvCtx =
        CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_AIGIS_SIG, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(importPrvCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(importPrvCtx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), PQCP_SUCCESS);
    BSL_Param importPrvParams[2] = {
        {PQCP_PARAM_AIGIS_SIG_PRVKEY, BSL_PARAM_TYPE_OCTETS, expectedSk->x, expectedSk->len, 0U}, BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(importPrvCtx, importPrvParams), PQCP_SUCCESS);
    signatureLen = signatureCapacity;
    ASSERT_EQ(CRYPT_EAL_PkeySign(importPrvCtx, CRYPT_MD_MAX, message->x, message->len, signature, &signatureLen),
              PQCP_SUCCESS);
    ASSERT_EQ(signatureLen, signatureCapacity);
    ASSERT_COMPARE("Aigis-Sig+ imported private key KAT signature", signature, expectedSig->len, expectedSig->x,
                   expectedSig->len);
    ASSERT_TRUE(TEST_AigisSigIsZero(signature + expectedSig->len, signatureLen - expectedSig->len));

    importPubCtx =
        CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_AIGIS_SIG, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(importPubCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(importPubCtx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), PQCP_SUCCESS);
    BSL_Param importPubParams[2] = {
        {PQCP_PARAM_AIGIS_SIG_PUBKEY, BSL_PARAM_TYPE_OCTETS, expectedPk->x, expectedPk->len, 0U}, BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(importPubCtx, importPubParams), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(importPubCtx, CRYPT_MD_MAX, message->x, message->len, signature, signatureLen),
              PQCP_SUCCESS);
    ASSERT_EQ(g_aigisSigRandCalls, 1U);

EXIT:
    if (prvKey != NULL) {
        BSL_SAL_CleanseData(prvKey, prvKeyLen);
    }
    BSL_SAL_Free(pubKey);
    BSL_SAL_Free(prvKey);
    BSL_SAL_Free(signature);
    CRYPT_EAL_PkeyFreeCtx(importPrvCtx);
    CRYPT_EAL_PkeyFreeCtx(importPubCtx);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TEST_AigisSigRandClear();
    return;
#else
    SKIP_TEST();
    (void)algId;
    (void)entropy;
    (void)expectedPk;
    (void)expectedSk;
    (void)message;
    (void)expectedSig;
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_AIGIS_SIG_API_TC001
* @spec  -
* @title Aigis-Sig+ provider lifecycle and negative verification
* @precon nan
* @brief 1. Exercise parameter and buffer contracts
*        2. Generate, sign and verify
*        3. Reject a modified signature
* @expect Provider API contracts hold for both supported parameter sets
* @prior  nan
* @auto   TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_AIGIS_SIG_API_TC001(int algId, Hex *message)
{
#ifdef PQCP_AIGIS_SIG
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t *signature = NULL;
    uint8_t missingKeyBuffer[1] = {0};
    uint32_t signatureCapacity = 0U;
    uint32_t signatureLen;
    uint32_t hintOffset;
    uint32_t maxHintSections;
    uint32_t countLen;
    uint32_t positionOffset;
    uint32_t positionBytes;
    uint32_t compactSignatureLen;
    uint8_t hintHeader;
    uint8_t savedCountByte;
    int32_t invalidAlg = INT32_MAX;
    BSL_Param missingPub[2] = {
        {PQCP_PARAM_AIGIS_SIG_PUBKEY, BSL_PARAM_TYPE_OCTETS, missingKeyBuffer, sizeof(missingKeyBuffer), 0U},
        BSL_PARAM_END};
    BSL_Param missingPrv[2] = {
        {PQCP_PARAM_AIGIS_SIG_PRVKEY, BSL_PARAM_TYPE_OCTETS, missingKeyBuffer, sizeof(missingKeyBuffer), 0U},
        BSL_PARAM_END};

    TestMemInit();
    TEST_AigisSigSetRegressionEntropy(algId);
    CRYPT_EAL_SetRandCallBack(TEST_AigisSigRandom);
    CRYPT_EAL_SetRandCallBackEx(TEST_AigisSigRandomEx);

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_AIGIS_SIG, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), PQCP_AIGIS_SIG_PARAM_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &invalidAlg, sizeof(invalidAlg)), PQCP_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)),
              PQCP_AIGIS_SIG_PARAM_REPEATED_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SIGNLEN, &signatureCapacity, sizeof(signatureCapacity)),
              PQCP_SUCCESS);
    ASSERT_TRUE(signatureCapacity > 1U);
    signature = BSL_SAL_Malloc(signatureCapacity);
    ASSERT_TRUE(signature != NULL);
    signatureLen = signatureCapacity;
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_MAX, message->x, message->len, signature, &signatureLen),
              PQCP_AIGIS_SIG_KEY_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, message->x, message->len, signature, signatureLen),
              PQCP_AIGIS_SIG_KEY_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, missingPub), PQCP_AIGIS_SIG_KEY_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(ctx, missingPrv), PQCP_AIGIS_SIG_KEY_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), PQCP_SUCCESS);
    ASSERT_EQ(g_aigisSigRandCalls, 1U);

    signatureLen = signatureCapacity - 1U;
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_MAX, message->x, message->len, signature, &signatureLen),
              PQCP_AIGIS_SIG_INVALID_SIG_LEN);
    signatureLen = signatureCapacity;
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_MAX, message->x, message->len, signature, &signatureLen), PQCP_SUCCESS);
    ASSERT_EQ(signatureLen, signatureCapacity);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, message->x, message->len, signature, signatureLen), PQCP_SUCCESS);
    if (algId == PQCP_AIGIS_SIG_SM3_I || algId == PQCP_AIGIS_SIG_SHA3_I) {
        hintOffset = TEST_AIGIS_SIG_I_HINT_OFFSET;
    } else if (algId == PQCP_AIGIS_SIG_SM3_II || algId == PQCP_AIGIS_SIG_SHA3_II) {
        hintOffset = TEST_AIGIS_SIG_II_HINT_OFFSET;
    } else {
        hintOffset = TEST_AIGIS_SIG_III_HINT_OFFSET;
    }
    ASSERT_TRUE(hintOffset < signatureLen);
    hintHeader = signature[hintOffset];
    maxHintSections = algId == PQCP_AIGIS_SIG_SM3_I || algId == PQCP_AIGIS_SIG_SHA3_I ? 16U :
                      algId == PQCP_AIGIS_SIG_SM3_II || algId == PQCP_AIGIS_SIG_SHA3_II ? 32U : 64U;
    compactSignatureLen = TEST_AigisSigCompactSignatureLen(signature, hintOffset);
    ASSERT_TRUE(compactSignatureLen < signatureLen);
    ASSERT_TRUE(TEST_AigisSigIsZero(signature + compactSignatureLen, signatureLen - compactSignatureLen));

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, message->x, message->len, signature, signatureLen - 1U),
              PQCP_AIGIS_SIG_INVALID_SIG_LEN);
    signature[compactSignatureLen] = 1U;
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, message->x, message->len, signature, signatureLen),
              PQCP_AIGIS_SIG_VERIFY_FAIL);
    signature[compactSignatureLen] = 0U;

    /* max is canonical: when nonzero, its final encoded section must contain
     * at least one hint.  Append one/two empty sections without changing the
     * decoded hint and require every public verify variant to reject it. */
    if (hintHeader == 0U) {
        signature[hintOffset] = 1U;
        ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, message->x, message->len, signature, signatureLen),
                  PQCP_AIGIS_SIG_VERIFY_FAIL);
        signature[hintOffset] = hintHeader;
    } else if ((hintHeader & 1U) != 0U && hintHeader < maxHintSections) {
        signature[hintOffset] = (uint8_t)(hintHeader + 1U);
        ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, message->x, message->len, signature, signatureLen),
                  PQCP_AIGIS_SIG_VERIFY_FAIL);
        signature[hintOffset] = hintHeader;
    } else if ((uint32_t)hintHeader + 2U <= maxHintSections) {
        ASSERT_TRUE(compactSignatureLen < signatureCapacity);
        countLen = ((uint32_t)hintHeader + 1U) >> 1;
        positionOffset = hintOffset + 1U + countLen;
        positionBytes = compactSignatureLen - positionOffset;
        (void)memmove(signature + positionOffset + 1U, signature + positionOffset, positionBytes);
        signature[positionOffset] = 0U;
        signature[hintOffset] = (uint8_t)(hintHeader + 2U);
        ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, message->x, message->len, signature, signatureLen),
                  PQCP_AIGIS_SIG_VERIFY_FAIL);
        (void)memmove(signature + positionOffset, signature + positionOffset + 1U, positionBytes);
        signature[compactSignatureLen] = 0U;
        signature[hintOffset] = hintHeader;
    } else {
        const uint32_t lastCount = (uint32_t)hintHeader - 1U;
        const uint32_t countOffset = hintOffset + 1U + (lastCount >> 1);
        const uint32_t shift = (lastCount & 1U) << 2;
        savedCountByte = signature[countOffset];
        signature[countOffset] &= (uint8_t)~(UINT8_C(0x0f) << shift);
        ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, message->x, message->len, signature, signatureLen),
                  PQCP_AIGIS_SIG_VERIFY_FAIL);
        signature[countOffset] = savedCountByte;
    }
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, message->x, message->len, signature, signatureLen), PQCP_SUCCESS);

    signature[hintOffset] = UINT8_MAX;
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, message->x, message->len, signature, signatureLen),
              PQCP_AIGIS_SIG_VERIFY_FAIL);
    signature[hintOffset] = hintHeader;
    signature[signatureLen / 2U] ^= 1U;
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, message->x, message->len, signature, signatureLen),
              PQCP_AIGIS_SIG_VERIFY_FAIL);
    signature[signatureLen / 2U] ^= 1U;
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, message->x, message->len, signature, signatureLen), PQCP_SUCCESS);
    ASSERT_EQ(g_aigisSigRandCalls, 1U);

EXIT:
    BSL_SAL_Free(signature);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TEST_AigisSigRandClear();
    return;
#else
    SKIP_TEST();
    (void)algId;
    (void)message;
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_AIGIS_SIG_KEY_CONTRACT_API_TC001
* @spec  -
* @title Aigis-Sig+ key import and export length contract
* @precon nan
* @brief 1. Generate and export a key pair
*        2. Reject short and oversized imported keys
*        3. Reject undersized key export buffers
*        4. Sign and verify after rejected imports
* @expect Invalid lengths are rejected without replacing the active key pair
* @prior  nan
* @auto   TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_AIGIS_SIG_KEY_CONTRACT_API_TC001(int algId, Hex *message)
{
#ifdef PQCP_AIGIS_SIG
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t *pubKey = NULL;
    uint8_t *prvKey = NULL;
    uint8_t *signature = NULL;
    uint32_t pubKeyLen = 0U;
    uint32_t prvKeyLen = 0U;
    uint32_t signatureLen = 0U;

    TestMemInit();
    TEST_AigisSigSetRegressionEntropy(algId);
    CRYPT_EAL_SetRandCallBack(TEST_AigisSigRandom);
    CRYPT_EAL_SetRandCallBackEx(TEST_AigisSigRandomEx);

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_AIGIS_SIG, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen)), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &prvKeyLen, sizeof(prvKeyLen)), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SIGNLEN, &signatureLen, sizeof(signatureLen)), PQCP_SUCCESS);

    pubKey = BSL_SAL_Malloc(pubKeyLen + 1U);
    prvKey = BSL_SAL_Malloc(prvKeyLen + 1U);
    signature = BSL_SAL_Malloc(signatureLen);
    ASSERT_TRUE(pubKey != NULL && prvKey != NULL && signature != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), PQCP_SUCCESS);

    BSL_Param getPub[2] = {{PQCP_PARAM_AIGIS_SIG_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey, pubKeyLen, 0U}, BSL_PARAM_END};
    BSL_Param getPrv[2] = {{PQCP_PARAM_AIGIS_SIG_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvKey, prvKeyLen, 0U}, BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, getPub), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(ctx, getPrv), PQCP_SUCCESS);

    BSL_Param setPub[2] = {{PQCP_PARAM_AIGIS_SIG_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey, pubKeyLen - 1U, 0U},
                           BSL_PARAM_END};
    BSL_Param setPrv[2] = {{PQCP_PARAM_AIGIS_SIG_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvKey, prvKeyLen - 1U, 0U},
                           BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, setPub), PQCP_AIGIS_SIG_KEYLEN_ERROR);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(ctx, setPrv), PQCP_AIGIS_SIG_KEYLEN_ERROR);
    setPub[0].valueLen = pubKeyLen + 1U;
    setPrv[0].valueLen = prvKeyLen + 1U;
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, setPub), PQCP_AIGIS_SIG_KEYLEN_ERROR);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(ctx, setPrv), PQCP_AIGIS_SIG_KEYLEN_ERROR);

    getPub[0].valueLen = pubKeyLen - 1U;
    getPrv[0].valueLen = prvKeyLen - 1U;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, getPub), PQCP_AIGIS_SIG_KEYLEN_ERROR);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(ctx, getPrv), PQCP_AIGIS_SIG_KEYLEN_ERROR);

    uint32_t actualSignatureLen = signatureLen;
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_MAX, message->x, message->len, signature, &actualSignatureLen),
              PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, message->x, message->len, signature, actualSignatureLen),
              PQCP_SUCCESS);

EXIT:
    BSL_SAL_Free(signature);
    BSL_SAL_ClearFree(prvKey, prvKeyLen);
    BSL_SAL_Free(pubKey);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TEST_AigisSigRandClear();
    return;
#else
    SKIP_TEST();
    (void)algId;
    (void)message;
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_AIGIS_SIG_DUP_CTX_API_TC001
* @spec  -
* @title Aigis-Sig+ context duplication
* @precon nan
* @brief 1. Generate a key pair and duplicate the context
*        2. Sign with the original context
*        3. Free the original context
*        4. Verify and sign with the duplicate
* @expect The duplicate retains independent parameter and key state
* @prior  nan
* @auto   TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_AIGIS_SIG_DUP_CTX_API_TC001(int algId, Hex *message)
{
#ifdef PQCP_AIGIS_SIG
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *dupCtx = NULL;
    uint8_t *signature = NULL;
    uint32_t signatureLen = 0U;

    TestMemInit();
    TEST_AigisSigSetRegressionEntropy(algId);
    CRYPT_EAL_SetRandCallBack(TEST_AigisSigRandom);
    CRYPT_EAL_SetRandCallBackEx(TEST_AigisSigRandomEx);

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_AIGIS_SIG, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SIGNLEN, &signatureLen, sizeof(signatureLen)), PQCP_SUCCESS);
    signature = BSL_SAL_Malloc(signatureLen);
    ASSERT_TRUE(signature != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), PQCP_SUCCESS);

    dupCtx = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(dupCtx != NULL);
    uint32_t actualSignatureLen = signatureLen;
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_MAX, message->x, message->len, signature, &actualSignatureLen),
              PQCP_SUCCESS);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    ctx = NULL;

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(dupCtx, CRYPT_MD_MAX, message->x, message->len, signature, actualSignatureLen),
              PQCP_SUCCESS);
    actualSignatureLen = signatureLen;
    ASSERT_EQ(CRYPT_EAL_PkeySign(dupCtx, CRYPT_MD_MAX, message->x, message->len, signature, &actualSignatureLen),
              PQCP_SUCCESS);

EXIT:
    BSL_SAL_Free(signature);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(dupCtx);
    TEST_AigisSigRandClear();
    return;
#else
    SKIP_TEST();
    (void)algId;
    (void)message;
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_AIGIS_SIG_NULL_CTX_API_TC001
* @spec  -
* @title Aigis-Sig+ NULL context handling
* @precon nan
* @brief Call the public key-management and signature APIs with a NULL context
* @expect Every operation rejects the NULL context
* @prior  nan
* @auto   TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_AIGIS_SIG_NULL_CTX_API_TC001(void)
{
#ifdef PQCP_AIGIS_SIG
    uint8_t buffer[32] = {0};
    uint32_t signatureLen = sizeof(buffer);
    int32_t algId = PQCP_AIGIS_SIG_SM3_I;
    BSL_Param param[2] = {{PQCP_PARAM_AIGIS_SIG_PRVKEY, BSL_PARAM_TYPE_OCTETS, buffer, sizeof(buffer), 0U},
                          BSL_PARAM_END};

    ASSERT_EQ(CRYPT_EAL_PkeyGen(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(NULL, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(NULL, param), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(NULL, param), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(NULL, param), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(NULL, param), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySign(NULL, CRYPT_MD_MAX, buffer, sizeof(buffer), buffer, &signatureLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(NULL, CRYPT_MD_MAX, buffer, sizeof(buffer), buffer, signatureLen), CRYPT_NULL_INPUT);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_AIGIS_SIG_INVALID_PARAMS_API_TC001
* @spec  -
* @title Aigis-Sig+ invalid parameter handling
* @precon nan
* @brief Reject missing key parameters, invalid algorithm IDs and malformed control requests
* @expect Every invalid input returns its documented error without changing the context
* @prior  nan
* @auto   TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_AIGIS_SIG_INVALID_PARAMS_API_TC001(void)
{
#ifdef PQCP_AIGIS_SIG
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    int32_t invalidAlgId = 99999;
    int32_t algId = PQCP_AIGIS_SIG_SM3_I;
    uint8_t buffer[32] = {0};
    BSL_Param nullValue[2] = {{PQCP_PARAM_AIGIS_SIG_PUBKEY, BSL_PARAM_TYPE_OCTETS, NULL, sizeof(buffer), 0U},
                              BSL_PARAM_END};

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_AIGIS_SIG, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(ctx, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &invalidAlgId, sizeof(invalidAlgId)),
              PQCP_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(uint16_t)), PQCP_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, nullValue), PQCP_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, nullValue), PQCP_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, INT32_MAX, &algId, sizeof(algId)), PQCP_INVALID_ARG);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_AIGIS_SIG_INTERLEAVE_TC001
* @spec  -
* @title Aigis-Sig+ runtime parameter contexts remain independent
* @precon nan
* @brief 1. Create all four supported parameter contexts
*        2. Generate keys and sign in interleaved orders
*        3. Verify every signature after the other contexts have run
* @expect Each context retains its own parameter and hash selection
* @prior  nan
* @auto   TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_AIGIS_SIG_INTERLEAVE_TC001(Hex *message)
{
#ifdef PQCP_AIGIS_SIG
    static const int32_t algIds[] = {PQCP_AIGIS_SIG_SM3_I,   PQCP_AIGIS_SIG_SM3_II,  PQCP_AIGIS_SIG_SHA3_I,
                                     PQCP_AIGIS_SIG_SHA3_II, PQCP_AIGIS_SIG_SM3_III, PQCP_AIGIS_SIG_SHA3_III};
    static const uint32_t genOrder[] = {0U, 5U, 1U, 4U, 3U, 2U};
    static const uint32_t signOrder[] = {4U, 2U, 0U, 5U, 3U, 1U};
    static const uint32_t verifyOrder[] = {1U, 5U, 3U, 0U, 4U, 2U};
    CRYPT_EAL_PkeyCtx *ctx[6] = {NULL, NULL, NULL, NULL, NULL, NULL};
    uint8_t *signature[6] = {NULL, NULL, NULL, NULL, NULL, NULL};
    uint32_t signatureLen[6] = {0U, 0U, 0U, 0U, 0U, 0U};
    uint32_t i;
    uint32_t index;

    TestMemInit();
    CRYPT_EAL_SetRandCallBack(TEST_AigisSigRandom);
    CRYPT_EAL_SetRandCallBackEx(TEST_AigisSigRandomEx);

    for (i = 0U; i < 6U; i++) {
        ctx[i] = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_AIGIS_SIG, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
        ASSERT_TRUE(ctx[i] != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx[i], CRYPT_CTRL_SET_PARA_BY_ID, (void *)&algIds[i], sizeof(algIds[i])),
                  PQCP_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx[i], CRYPT_CTRL_GET_SIGNLEN, &signatureLen[i], sizeof(signatureLen[i])),
                  PQCP_SUCCESS);
        signature[i] = BSL_SAL_Malloc(signatureLen[i]);
        ASSERT_TRUE(signature[i] != NULL);
    }

    for (i = 0U; i < 6U; i++) {
        index = genOrder[i];
        TEST_AigisSigSetRegressionEntropy(algIds[index]);
        ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx[index]), PQCP_SUCCESS);
        ASSERT_EQ(g_aigisSigRandCalls, 1U);
    }

    for (i = 0U; i < 6U; i++) {
        index = signOrder[i];
        ASSERT_EQ(CRYPT_EAL_PkeySign(ctx[index], CRYPT_MD_MAX, message->x, message->len, signature[index],
                                     &signatureLen[index]),
                  PQCP_SUCCESS);
    }
    for (i = 0U; i < 6U; i++) {
        index = verifyOrder[i];
        ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx[index], CRYPT_MD_MAX, message->x, message->len, signature[index],
                                       signatureLen[index]),
                  PQCP_SUCCESS);
    }

EXIT:
    for (i = 0U; i < 6U; i++) {
        BSL_SAL_Free(signature[i]);
        CRYPT_EAL_PkeyFreeCtx(ctx[i]);
    }
    TEST_AigisSigRandClear();
    return;
#else
    SKIP_TEST();
    (void)message;
#endif
}
/* END_CASE */
