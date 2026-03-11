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

#include "crypt_errno.h"
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_rand.h"
#include "pqcp_provider.h"
#include "pqcp_types.h"
#include "pqcp_err.h"
#include "scloudplus.h"
/* END_HEADER */

static uint8_t gScloudPlusRandBuf[3][64] = {0};
uint32_t gScloudPlusRandNum = 0;

static int32_t TEST_ScloudPlusRandom(uint8_t *randNum, uint32_t randLen)
{
    if (gScloudPlusRandNum < 3) {
        memcpy_s(randNum, randLen, gScloudPlusRandBuf[gScloudPlusRandNum], randLen);
    }
    gScloudPlusRandNum++;
    if (gScloudPlusRandNum >= 3) {
        gScloudPlusRandNum = 0;
    }
    return 0;
}

/* @
* @test  SDV_CRYPTO_PQCP_SCLOUDPLUS_KEYGEN_API_TC001
* @spec  -
* @title  PQCP SCloud+ Key Generation API Test
* @precon  nan
* @brief  1. Create provider context
*         2. Initialize SCloud+ with different security levels
*         3. Generate key pair and verify
* @expect  All operations return PQCP_SUCCESS
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_SCLOUDPLUS_KEYGEN_API_TC001(int bits)
{

    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    uint32_t val = (uint32_t)bits;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    uint32_t pubKeyLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_TRUE(pubKeyLen > 0);

    uint32_t prvKeyLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &prvKeyLen, sizeof(prvKeyLen));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_TRUE(prvKeyLen > 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_SCLOUDPLUS_ENCAPS_DECAPS_API_TC001
* @spec  -
* @title  PQCP SCloud+ Encapsulation/Decapsulation API Test
* @precon  nan
* @brief  1. Create context and generate key pair
*         2. Call encapsulation interface
*         3. Call decapsulation interface
*         4. Verify shared keys match
* @expect  All operations return PQCP_SUCCESS and shared keys match
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_SCLOUDPLUS_ENCAPS_DECAPS_API_TC001(int bits)
{
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *enCtx = NULL;
    CRYPT_EAL_PkeyCtx *deCtx = NULL;
    uint8_t *cipher = NULL;
    uint8_t *sharedKey = NULL;
    uint8_t *sharedKey2 = NULL;
    uint8_t *pubData = NULL;
    enCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    deCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    ASSERT_TRUE(enCtx != NULL);
    ASSERT_TRUE(deCtx != NULL);

    uint32_t val = (uint32_t)bits;
    int32_t ret = CRYPT_EAL_PkeyCtrl(enCtx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_PkeyCtrl(deCtx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(deCtx);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    uint32_t cipherLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(deCtx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    uint32_t sharedLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(deCtx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedLen, sizeof(sharedLen));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    cipher = BSL_SAL_Malloc(cipherLen);
    ASSERT_TRUE(cipher != NULL);
    sharedKey = BSL_SAL_Malloc(sharedLen);
    ASSERT_TRUE(sharedKey != NULL);
    sharedKey2 = BSL_SAL_Malloc(sharedLen);
    ASSERT_TRUE(sharedKey2 != NULL);
    
    pubData = BSL_SAL_Malloc(37520 / 2);
    ASSERT_TRUE(pubData != NULL);
    BSL_Param pub[2] = {
        {PQCP_PARAM_SCLOUDPLUS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubData, 37520 / 2, 0},
        BSL_PARAM_END
    };
    ret = CRYPT_EAL_PkeyGetPubEx(deCtx, pub);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    pub[0].valueLen = pub[0].useLen;

    ret = CRYPT_EAL_PkeySetPubEx(enCtx, pub);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyEncapsInit(enCtx, NULL);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyEncaps(enCtx, cipher, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyDecapsInit(deCtx, NULL);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    uint32_t sharedLen2 = sharedLen;
    ret = CRYPT_EAL_PkeyDecaps(deCtx, cipher, cipherLen, sharedKey2, &sharedLen2);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ASSERT_EQ(sharedLen, sharedLen2);
    ASSERT_COMPARE("compare shared key", sharedKey, sharedLen, sharedKey2, sharedLen2);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(enCtx);
    CRYPT_EAL_PkeyFreeCtx(deCtx);
    BSL_SAL_Free(cipher);
    BSL_SAL_Free(sharedKey);
    BSL_SAL_Free(sharedKey2);
    BSL_SAL_Free(pubData);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_SCLOUDPLUS_SETGET_PUBKEY_API_TC001
* @spec  -
* @title  PQCP SCloud+ Set/Get Public Key API Test
* @precon  nan
* @brief  1. Create context and generate key pair
*         2. Get public key
*         3. Set public key to another context
*         4. Verify keys match
* @expect  All operations return PQCP_SUCCESS
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_SCLOUDPLUS_SETGET_PUBKEY_API_TC001(int bits)
{

    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *ctx2 = NULL;
    uint8_t *pubData = NULL;
    uint8_t *pubData2 = NULL;

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    ctx2 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(ctx2 != NULL);

    uint32_t val = (uint32_t)bits;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    uint32_t pubLen = 37520 / 2;
    pubData = BSL_SAL_Malloc(pubLen);
    ASSERT_TRUE(pubData != NULL);
    pubData2 = BSL_SAL_Malloc(pubLen);
    ASSERT_TRUE(pubData2 != NULL);

    BSL_Param pub[2] = {
        {PQCP_PARAM_SCLOUDPLUS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubData, pubLen, 0},
        BSL_PARAM_END
    };

    ret = CRYPT_EAL_PkeyGetPubEx(ctx, pub);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_TRUE(pub[0].useLen > 0);

    pub[0].valueLen = pub[0].useLen;
    ret = CRYPT_EAL_PkeySetPubEx(ctx2, pub);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    BSL_Param pub2[2] = {
        {PQCP_PARAM_SCLOUDPLUS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubData2, pubLen, 0},
        BSL_PARAM_END
    };
    ret = CRYPT_EAL_PkeyGetPubEx(ctx2, pub2);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ASSERT_EQ(pub[0].useLen, pub2[0].useLen);
    ASSERT_COMPARE("compare pub keys", pub[0].value, pub[0].useLen, pub2[0].value, pub2[0].useLen);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    BSL_SAL_Free(pubData);
    BSL_SAL_Free(pubData2);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_SCLOUDPLUS_SETGET_PRVKEY_API_TC001
* @spec  -
* @title  PQCP SCloud+ Set/Get Private Key API Test
* @precon  nan
* @brief  1. Create context and generate key pair
*         2. Get private key
*         3. Set private key to another context
*         4. Verify keys match
* @expect  All operations return PQCP_SUCCESS
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_SCLOUDPLUS_SETGET_PRVKEY_API_TC001(int bits)
{

    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *ctx2 = NULL;
    uint8_t *prvData = NULL;
    uint8_t *prvData2 = NULL;

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    ctx2 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(ctx2 != NULL);

    uint32_t val = (uint32_t)bits;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    uint32_t prvLen = 43808 / 2;
    prvData = BSL_SAL_Malloc(prvLen);
    ASSERT_TRUE(prvData != NULL);
    prvData2 = BSL_SAL_Malloc(prvLen);
    ASSERT_TRUE(prvData2 != NULL);

    BSL_Param prv[2] = {
        {PQCP_PARAM_SCLOUDPLUS_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvData, prvLen, 0},
        BSL_PARAM_END
    };

    ret = CRYPT_EAL_PkeyGetPrvEx(ctx, prv);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_TRUE(prv[0].useLen > 0);

    prv[0].valueLen = prv[0].useLen;
    ret = CRYPT_EAL_PkeySetPrvEx(ctx2, prv);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    BSL_Param prv2[2] = {
        {PQCP_PARAM_SCLOUDPLUS_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvData2, prvLen, 0},
        BSL_PARAM_END
    };
    ret = CRYPT_EAL_PkeyGetPrvEx(ctx2, prv2);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ASSERT_EQ(prv[0].useLen, prv2[0].useLen);
    ASSERT_COMPARE("compare prv keys", prv[0].value, prv[0].useLen, prv2[0].value, prv2[0].useLen);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    BSL_SAL_Free(prvData);
    BSL_SAL_Free(prvData2);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_SCLOUDPLUS_CTRL_API_TC001
* @spec  -
* @title  PQCP SCloud+ Ctrl Interface Test
* @precon  nan
* @brief  1. Create context
*         2. Test various ctrl operations
*         3. Verify error handling
* @expect  Operations return expected results
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_SCLOUDPLUS_CTRL_API_TC001(int bits)
{

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    uint32_t val = (uint32_t)bits;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(NULL, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, NULL, sizeof(val));
    ASSERT_EQ(ret, PQCP_NULL_INPUT);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_SCLOUDPLUS_NULL_CTX_API_TC001
* @spec  -
* @title  PQCP SCloud+ NULL Context Error Handling Test
* @precon  nan
* @brief  1. Call APIs with NULL context
*         2. Verify proper error codes are returned
* @expect  All operations return PQCP_NULL_INPUT
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_SCLOUDPLUS_NULL_CTX_API_TC001(void)
{

    TestMemInit();
    int32_t ret = CRYPT_EAL_PkeyGen(NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeyCtrl(NULL, CRYPT_CTRL_SET_PARA_BY_ID, NULL, 0);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    uint8_t buf[32] = {0};
    uint32_t len = 32;
    ret = CRYPT_EAL_PkeyEncaps(NULL, buf, &len, buf, &len);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeyDecaps(NULL, buf, len, buf, &len);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

EXIT:
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_SCLOUDPLUS_DUP_CTX_API_TC001
* @spec  -
* @title  PQCP SCloud+ Context Duplication Test
* @precon  nan
* @brief  1. Create context and generate key pair
*         2. Duplicate context
*         3. Verify both contexts work correctly
* @expect  Duplicated context works as expected
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_SCLOUDPLUS_DUP_CTX_API_TC001(int bits)
{

    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *dupCtx = NULL;
    uint8_t *cipher = NULL;
    uint8_t *sharedKey = NULL;

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    uint32_t val = (uint32_t)bits;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    dupCtx = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(dupCtx != NULL);

    uint32_t cipherLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    uint32_t sharedLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedLen, sizeof(sharedLen));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    cipher = BSL_SAL_Malloc(cipherLen);
    ASSERT_TRUE(cipher != NULL);
    sharedKey = BSL_SAL_Malloc(sharedLen);
    ASSERT_TRUE(sharedKey != NULL);

    ret = CRYPT_EAL_PkeyEncapsInit(dupCtx, NULL);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyEncaps(dupCtx, cipher, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    CRYPT_EAL_PkeyFreeCtx(ctx);
    ctx = NULL;

    ret = CRYPT_EAL_PkeyDecapsInit(dupCtx, NULL);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyDecaps(dupCtx, cipher, cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(dupCtx);
    BSL_SAL_Free(cipher);
    BSL_SAL_Free(sharedKey);
    TestRandDeInit();
    return;
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_PQCP_SCLOUDPLUS_VECTOR_TC001
* @spec  -
* @title  PQCP SCloud+ Context Vector Test
* @precon  nan
* @brief  1. Create context and generate key pair
*         2. Stub Random Function
*         3. KeyGen and compare with expected values
*         4. Encaps/Decaps and verify shared keys match
* @expect  pk and sk match expected values, shared keys match
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_SCLOUDPLUS_VECTOR_TC001(int bits, Hex *alpha, Hex *randZ, Hex *randM, Hex *expPk, Hex *expSk,
    Hex *expCipher, Hex *expSharedKey)
{
    TestMemInit();
    uint8_t *ciphertext = NULL;
    uint8_t *sharedKey = NULL;
    uint8_t *decSharedKey = NULL;
    CRYPT_EAL_SetRandCallBack(TEST_ScloudPlusRandom);
    memcpy_s(gScloudPlusRandBuf[1], 64, alpha->x, alpha->len);
    memcpy_s(gScloudPlusRandBuf[0], 64, randZ->x, randZ->len);
    memcpy_s(gScloudPlusRandBuf[2], 64, randM->x, randM->len);
    CRYPT_EAL_PkeyCtx *pubKeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE,
        "provider=pqcp");
    
    CRYPT_EAL_PkeyCtx *prvKeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL,  PQCP_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE,
        "provider=pqcp");
    ASSERT_NE(pubKeyCtx, NULL);
    ASSERT_NE(prvKeyCtx, NULL);
    uint32_t val = (uint32_t)bits;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pubKeyCtx, val), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prvKeyCtx, val), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(pubKeyCtx, NULL), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(prvKeyCtx, NULL), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(prvKeyCtx), PQCP_SUCCESS);
    uint32_t encapsKeyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pubKeyCtx, CRYPT_CTRL_GET_PUBKEY_LEN, &encapsKeyLen, sizeof(encapsKeyLen)),
              PQCP_SUCCESS);

    uint32_t decapsKeyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pubKeyCtx, CRYPT_CTRL_GET_PRVKEY_LEN, &decapsKeyLen, sizeof(decapsKeyLen)),
              PQCP_SUCCESS);

    uint32_t cipherLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pubKeyCtx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen)),
              PQCP_SUCCESS);

    BSL_Param keys[3] = {
        {PQCP_PARAM_SCLOUDPLUS_PUBKEY, BSL_PARAM_TYPE_OCTETS, BSL_SAL_Malloc(encapsKeyLen), encapsKeyLen, 0},
        {PQCP_PARAM_SCLOUDPLUS_PRVKEY, BSL_PARAM_TYPE_OCTETS, BSL_SAL_Malloc(decapsKeyLen), decapsKeyLen, 0},
        BSL_PARAM_END
    };
    ciphertext = BSL_SAL_Malloc(cipherLen);
    uint32_t sharedLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pubKeyCtx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedLen, sizeof(sharedLen)),
        PQCP_SUCCESS);
    sharedKey = BSL_SAL_Malloc(sharedLen);
    uint32_t decSharedLen = sharedLen;
    decSharedKey = BSL_SAL_Malloc(decSharedLen);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(prvKeyCtx, keys), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(prvKeyCtx, keys), PQCP_SUCCESS);
    ASSERT_COMPARE("compare pk", keys[0].value, keys[0].useLen, expPk->x, expPk->len);
    ASSERT_COMPARE("compare sk", keys[1].value, keys[1].useLen, expSk->x, expSk->len);

    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(pubKeyCtx, keys), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(pubKeyCtx, ciphertext, &cipherLen, sharedKey, &sharedLen), PQCP_SUCCESS);
    ASSERT_COMPARE("compare ct", ciphertext, cipherLen, expCipher->x, expCipher->len);
    ASSERT_COMPARE("compare ss", sharedKey, sharedLen, expSharedKey->x, expSharedKey->len);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(prvKeyCtx,  expCipher->x, expCipher->len, decSharedKey, &decSharedLen), PQCP_SUCCESS);
    ASSERT_COMPARE("compare dec ss", decSharedKey, decSharedLen, expSharedKey->x, expSharedKey->len);
EXIT:
    BSL_SAL_Free(keys[0].value);
    BSL_SAL_Free(keys[1].value);
    BSL_SAL_Free(ciphertext);
    BSL_SAL_Free(sharedKey);
    BSL_SAL_Free(decSharedKey);
    CRYPT_EAL_PkeyFreeCtx(pubKeyCtx);
    CRYPT_EAL_PkeyFreeCtx(prvKeyCtx);
    TestRandDeInit();
    return;
}
/* END_CASE */