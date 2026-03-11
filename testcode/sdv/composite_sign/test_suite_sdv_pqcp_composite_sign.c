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
#include "bsl_params.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_provider.h"
#include "pqcp_provider.h"
#include "pqcp_types.h"
#include "pqcp_err.h"
/* END_HEADER */

/* @
* @test  SDV_CRYPTO_PQCP_COMPOSITE_KEYGEN_API_TC001
* @spec  -
* @title  PQCP Composite Sign Key Generation API Test
* @precon  nan
* @brief  1. Create provider context
*         2. Set algorithm ID
*         3. Generate key pair and verify
* @expect  All operations return PQCP_SUCCESS
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_COMPOSITE_KEYGEN_API_TC001(int algId)
{

    TestMemInit();
    TestRandInitEx(NULL);
    CRYPT_EAL_PkeyCtx *ctx = NULL;

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId));
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
* @test  SDV_CRYPTO_PQCP_COMPOSITE_GET_PRVKEY_API_TC001
* @spec  -
* @title  PQCP Composite Sign Get Private Key API Test
* @precon  nan
* @brief  1. Create context and generate key pair
*         2. Get private key
*         3. Verify key length is valid
* @expect  All operations return PQCP_SUCCESS
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_COMPOSITE_GET_PRVKEY_API_TC001(int algId)
{

    TestMemInit();
    TestRandInitEx(NULL);
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t prvKeyData[4096] = {0};

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    BSL_Param prvParams[2] = {
        {PQCP_PARAM_COMPOSITE_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvKeyData, sizeof(prvKeyData), 0},
        BSL_PARAM_END
    };
    ret = CRYPT_EAL_PkeyGetPrvEx(ctx, prvParams);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_TRUE(prvParams[0].useLen > 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_COMPOSITE_GET_PUBKEY_API_TC001
* @spec  -
* @title  PQCP Composite Sign Get Public Key API Test
* @precon  nan
* @brief  1. Create context and generate key pair
*         2. Get public key
*         3. Verify key length is valid
* @expect  All operations return PQCP_SUCCESS
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_COMPOSITE_GET_PUBKEY_API_TC001(int algId)
{
    TestMemInit();
    TestRandInitEx(NULL);
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t pubKeyData[4096] = {0};

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    BSL_Param pubParams[2] = {
        {PQCP_PARAM_COMPOSITE_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKeyData, sizeof(pubKeyData), 0},
        BSL_PARAM_END
    };
    ret = CRYPT_EAL_PkeyGetPubEx(ctx, pubParams);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_TRUE(pubParams[0].useLen > 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_COMPOSITE_SET_PRVKEY_API_TC001
* @spec  -
* @title  PQCP Composite Sign Set Private Key API Test
* @precon  nan
* @brief  1. Create context and generate key pair
*         2. Get private key
*         3. Set private key to another context
*         4. Verify operation succeeds
* @expect  All operations return PQCP_SUCCESS
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_COMPOSITE_SET_PRVKEY_API_TC001(int algId)
{
    TestRandInitEx(NULL);
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *ctx2 = NULL;
    uint8_t prvKeyData[4096] = {0};

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    ctx2 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx2 != NULL);

    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    BSL_Param prvParams[2] = {
        {PQCP_PARAM_COMPOSITE_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvKeyData, sizeof(prvKeyData), 0},
        BSL_PARAM_END
    };
    ret = CRYPT_EAL_PkeyGetPrvEx(ctx, prvParams);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    prvParams[0].valueLen = prvParams[0].useLen;
    ret = CRYPT_EAL_PkeySetPrvEx(ctx2, prvParams);
    ASSERT_EQ(ret, PQCP_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_COMPOSITE_SET_PUBKEY_API_TC001
* @spec  -
* @title  PQCP Composite Sign Set Public Key API Test
* @precon  nan
* @brief  1. Create context and generate key pair
*         2. Get public key
*         3. Set public key to another context
*         4. Verify operation succeeds
* @expect  All operations return PQCP_SUCCESS
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_COMPOSITE_SET_PUBKEY_API_TC001(int algId)
{
    TestRandInitEx(NULL);
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *ctx2 = NULL;
    uint8_t pubKeyData[4096] = {0};

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    ctx2 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx2 != NULL);

    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    BSL_Param pubParams[2] = {
        {PQCP_PARAM_COMPOSITE_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKeyData, sizeof(pubKeyData), 0},
        BSL_PARAM_END
    };
    ret = CRYPT_EAL_PkeyGetPubEx(ctx, pubParams);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    pubParams[0].valueLen = pubParams[0].useLen;
    ret = CRYPT_EAL_PkeySetPubEx(ctx2, pubParams);
    ASSERT_EQ(ret, PQCP_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_COMPOSITE_SIGN_VERIFY_API_TC001
* @spec  -
* @title  PQCP Composite Sign/Verify API Test
* @precon  nan
* @brief  1. Create context and generate key pair
*         2. Sign a message
*         3. Verify the signature
* @expect  All operations return PQCP_SUCCESS
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_COMPOSITE_SIGN_VERIFY_API_TC001(int algId, Hex *message)
{
    TestRandInitEx(NULL);
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *verifyCtx = NULL;
    uint8_t pubKeyData[4096] = {0};
    uint8_t signData[5000] = {0};
    uint32_t signLen = sizeof(signData);
    const char *context = "test sdv composite sign";
    uint32_t contextLen = strlen(context);
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    verifyCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(verifyCtx != NULL);

    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_PkeyCtrl(verifyCtx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_CTX_INFO, NULL, contextLen), PQCP_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_CTX_INFO, NULL, 0), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_CTX_INFO, (void *)context, contextLen), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(verifyCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)context, contextLen), PQCP_SUCCESS);
    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    BSL_Param pubParams[2] = {
        {PQCP_PARAM_COMPOSITE_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKeyData, sizeof(pubKeyData), 0},
        BSL_PARAM_END
    };
    ret = CRYPT_EAL_PkeyGetPubEx(ctx, pubParams);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    pubParams[0].valueLen = pubParams[0].useLen;
    ret = CRYPT_EAL_PkeySetPubEx(verifyCtx, pubParams);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_MAX, message->x, message->len, signData, &signLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(verifyCtx, CRYPT_MD_MAX, message->x, message->len, signData, signLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(verifyCtx, CRYPT_CTRL_SET_CTX_INFO, NULL, 0), PQCP_SUCCESS);
    ret = CRYPT_EAL_PkeyVerify(verifyCtx, CRYPT_MD_MAX, message->x, message->len, signData, signLen);
    ASSERT_NE(ret, PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(verifyCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)context, contextLen), PQCP_SUCCESS);
    ret = CRYPT_EAL_PkeyVerify(verifyCtx, CRYPT_MD_MAX, message->x, message->len, signData, signLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(verifyCtx);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_COMPOSITE_NULL_CTX_API_TC001
* @spec  -
* @title  PQCP Composite Sign NULL Context Error Handling Test
* @precon  nan
* @brief  1. Call APIs with NULL context
*         2. Verify proper error codes are returned
* @expect  All operations return PQCP_NULL_INPUT
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_COMPOSITE_NULL_CTX_API_TC001(void)
{
    TestRandInitEx(NULL);
    TestMemInit();

    int32_t ret = CRYPT_EAL_PkeyGen(NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeyCtrl(NULL, CRYPT_CTRL_SET_PARA_BY_ID, NULL, 0);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    uint8_t buf[32] = {0};
    BSL_Param param[2] = {
        {PQCP_PARAM_COMPOSITE_PRVKEY, BSL_PARAM_TYPE_OCTETS, buf, sizeof(buf), 0},
        BSL_PARAM_END
    };
    ret = CRYPT_EAL_PkeyGetPrvEx(NULL, param);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeyGetPubEx(NULL, param);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeySetPrvEx(NULL, param);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeySetPubEx(NULL, param);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    uint32_t signLen = sizeof(buf);
    ret = CRYPT_EAL_PkeySign(NULL, CRYPT_MD_MAX, buf, sizeof(buf), buf, &signLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeyVerify(NULL, CRYPT_MD_MAX, buf, sizeof(buf), buf, signLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

EXIT:
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_COMPOSITE_ALG_NOT_SET_API_TC001
* @spec  -
* @title  PQCP Composite Sign Algorithm Not Set Error Handling Test
* @precon  nan
* @brief  1. Create context without setting algorithm
*         2. Try to generate key
*         3. Verify proper error code is returned
* @expect  KeyGen returns PQCP_COMPOSITE_KEYINFO_NOT_SET
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_COMPOSITE_ALG_NOT_SET_API_TC001(void)
{
    TestRandInitEx(NULL);
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    int32_t ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_COMPOSITE_KEYINFO_NOT_SET);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_COMPOSITE_INVALID_PARAMS_API_TC001
* @spec  -
* @title  PQCP Composite Sign Invalid Parameters Error Handling Test
* @precon  nan
* @brief  1. Create context and set algorithm
*         2. Call APIs with invalid parameters
*         3. Verify proper error codes are returned
* @expect  Operations return expected error codes
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_COMPOSITE_INVALID_PARAMS_API_TC001(int algId)
{
    TestRandInitEx(NULL);
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *ctx2 = NULL;
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyGetPubEx(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    BSL_Param pubNullData[2] = {
        {PQCP_PARAM_COMPOSITE_PUBKEY, BSL_PARAM_TYPE_OCTETS, NULL, 100, 0},
        BSL_PARAM_END
    };
    ret = CRYPT_EAL_PkeyGetPubEx(ctx, pubNullData);
    ASSERT_EQ(ret, PQCP_NULL_INPUT);

    ret = CRYPT_EAL_PkeyGetPrvEx(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    int32_t invalidAlgId = 99999;
    ctx2 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx2 != NULL);
    ret = CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_PARA_BY_ID, &invalidAlgId, sizeof(invalidAlgId));
    ASSERT_EQ(ret, PQCP_INVALID_ARG);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_COMPOSITE_BUFFER_TOO_SMALL_API_TC001
* @spec  -
* @title  PQCP Composite Sign Buffer Too Small Error Handling Test
* @precon  nan
* @brief  1. Create context and generate key pair
*         2. Try to get public key with too small buffer
*         3. Verify proper error code is returned
* @expect  GetPubEx returns PQCP_COMPOSITE_LEN_NOT_ENOUGH
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_COMPOSITE_BUFFER_TOO_SMALL_API_TC001(int algId)
{
    TestRandInitEx(NULL);
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t pubKeyData[4] = {0};

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    BSL_Param pubParams[2] = {
        {PQCP_PARAM_COMPOSITE_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKeyData, sizeof(pubKeyData), 0},
        BSL_PARAM_END
    };
    ret = CRYPT_EAL_PkeyGetPubEx(ctx, pubParams);
    ASSERT_EQ(ret, PQCP_COMPOSITE_LEN_NOT_ENOUGH);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_COMPOSITE_GET_SIGNLEN_API_TC001
* @spec  -
* @title  PQCP Composite Sign Get Signature Length API Test
* @precon  nan
* @brief  1. Create context and generate key pair
*         2. Get signature length
*         3. Verify length is valid
* @expect  All operations return PQCP_SUCCESS and signLen > 0
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_COMPOSITE_GET_SIGNLEN_API_TC001(int algId, int expPqcSignLen)
{
    TestRandInitEx(NULL);
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint32_t signLen = 0;
    uint32_t tradSignLen = 0;
    uint32_t pqcSignLen = 0;
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SIGNLEN, &signLen, sizeof(signLen));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, PQCP_CTRL_HYBRID_GET_TRAD_SIGNLEN, &tradSignLen, sizeof(tradSignLen)),
              PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, PQCP_CTRL_HYBRID_GET_PQC_SIGNLEN, &pqcSignLen, sizeof(pqcSignLen)), PQCP_SUCCESS);
    ASSERT_EQ(pqcSignLen, expPqcSignLen);
    ASSERT_EQ(tradSignLen, 74);
    ASSERT_EQ(signLen, tradSignLen + pqcSignLen);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_COMPOSITE_DUP_CTX_API_TC001
* @spec  -
* @title  PQCP Composite Sign Context Duplication Test
* @precon  nan
* @brief  1. Create context and generate key pair
*         2. Duplicate context
*         3. Verify duplicated context works correctly
* @expect  Duplicated context works as expected
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_COMPOSITE_DUP_CTX_API_TC001(int algId)
{
    TestRandInitEx(NULL);
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *dupCtx = NULL;
    uint8_t signData[5000] = {0};
    uint32_t signLen = sizeof(signData);
    const uint8_t message[] = "Test message for composite signature";

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    dupCtx = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(dupCtx != NULL);

    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_MAX, message, sizeof(message), signData, &signLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(dupCtx, CRYPT_MD_MAX, message, sizeof(message), signData, signLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    signLen = sizeof(signData);
    ret = CRYPT_EAL_PkeySign(dupCtx, CRYPT_MD_MAX, message, sizeof(message), signData, &signLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(dupCtx);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_COMPOSITE_GET_SEPARATE_KEYLEN_API_TC001
* @spec  -
* @title  PQCP Composite Sign Get Separate Key Length API Test
* @precon  nan
* @brief  1. Create context and generate key pair
*         2. Get PQC and TRAD key lengths separately
*         3. Verify lengths are consistent
* @expect  All operations return PQCP_SUCCESS and lengths are valid
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_COMPOSITE_GET_SEPARATE_KEYLEN_API_TC001(int algId)
{
    TestRandInitEx(NULL);
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint32_t pqcPrvKeyLen = 0;
    uint32_t tradPrvKeyLen = 0;
    uint32_t pqcPubKeyLen = 0;
    uint32_t tradPubKeyLen = 0;
    uint32_t totalPrvKeyLen = 0;
    uint32_t totalPubKeyLen = 0;

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, PQCP_CTRL_HYBRID_GET_PQC_PRVKEY_LEN, &pqcPrvKeyLen, sizeof(pqcPrvKeyLen));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(pqcPrvKeyLen, 32);

    ret = CRYPT_EAL_PkeyCtrl(ctx, PQCP_CTRL_HYBRID_GET_TRAD_PRVKEY_LEN, &tradPrvKeyLen, sizeof(tradPrvKeyLen));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(tradPrvKeyLen, 32);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &totalPrvKeyLen, sizeof(totalPrvKeyLen));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(totalPrvKeyLen, pqcPrvKeyLen + tradPrvKeyLen);

    ret = CRYPT_EAL_PkeyCtrl(ctx, PQCP_CTRL_HYBRID_GET_PQC_PUBKEY_LEN, &pqcPubKeyLen, sizeof(pqcPubKeyLen));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_TRUE(pqcPubKeyLen > 0);

    ret = CRYPT_EAL_PkeyCtrl(ctx, PQCP_CTRL_HYBRID_GET_TRAD_PUBKEY_LEN, &tradPubKeyLen, sizeof(tradPubKeyLen));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_TRUE(tradPubKeyLen > 0);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &totalPubKeyLen, sizeof(totalPubKeyLen));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(totalPubKeyLen, pqcPubKeyLen + tradPubKeyLen);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_COMPOSITE_GET_SEPARATE_SIGNLEN_API_TC001
* @spec  -
* @title  PQCP Composite Sign Get Separate Signature Length API Test
* @precon  nan
* @brief  1. Create context and generate key pair
*         2. Get PQC and total signature lengths
*         3. Verify lengths are valid
* @expect  All operations return PQCP_SUCCESS and lengths are valid
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_COMPOSITE_GET_SEPARATE_SIGNLEN_API_TC001(int algId, int expPqcSignLen)
{
    TestRandInitEx(NULL);
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint32_t pqcSigLen = 0;
    uint32_t totalSigLen = 0;
    uint32_t tradSigLen = 0;

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_COMPOSITE_SIGN, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, PQCP_CTRL_HYBRID_GET_PQC_SIGNLEN, &pqcSigLen, sizeof(pqcSigLen));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(pqcSigLen, (uint32_t)expPqcSignLen);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SIGNLEN, &totalSigLen, sizeof(totalSigLen));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, PQCP_CTRL_HYBRID_GET_TRAD_SIGNLEN, &tradSigLen, sizeof(tradSigLen)), PQCP_SUCCESS);
    ASSERT_EQ(tradSigLen, 74);
    ASSERT_EQ(totalSigLen, tradSigLen + pqcSigLen);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
    return;
}
/* END_CASE */
