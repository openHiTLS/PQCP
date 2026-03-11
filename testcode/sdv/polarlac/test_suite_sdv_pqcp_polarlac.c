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
/* END_HEADER */

static int32_t TEST_PolarLacRandom(uint8_t *rand, uint32_t randLen)
{
    for (uint32_t i = 0; i < randLen; i++) {
        rand[i] = (uint8_t)(i % 256);
    }
    return 0;
}

/* @
* @test  SDV_CRYPTO_PQCP_POLARLAC_KEYGEN_API_TC001
* @spec  -
* @title  PQCP Polarlac Key Generation API Test
* @precon  nan
* @brief  1. Create provider context
*         2. Set algorithm parameter
*         3. Generate key pair and verify
* @expect  All operations return PQCP_SUCCESS
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_POLARLAC_KEYGEN_API_TC001(int algId)
{

    TestMemInit();
    CRYPT_EAL_SetRandCallBack(TEST_PolarLacRandom);
    CRYPT_EAL_PkeyCtx *ctx = NULL;

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_POLAR_LAC, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    int32_t val = algId;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyGetPubEx(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeyGetPrvEx(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

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
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_POLARLAC_ENCAPS_DECAPS_API_TC001
* @spec  -
* @title  PQCP Polarlac Encapsulation/Decapsulation API Test
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
void SDV_CRYPTO_PQCP_POLARLAC_ENCAPS_DECAPS_API_TC001(int algId)
{

    TestMemInit();
    CRYPT_EAL_SetRandCallBack(TEST_PolarLacRandom);
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *deCtx = NULL;
    CRYPT_EAL_PkeyCtx *exCtx = NULL;
    uint8_t cipher[4096] = {0};
    uint8_t sharedKey[32] = {0};
    uint8_t sharedKey2[32] = {0};
    uint8_t pubData[8192] = {0};
    uint8_t prvData[8192] = {0};

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_POLAR_LAC, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    deCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_POLAR_LAC, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    exCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_POLAR_LAC, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(deCtx != NULL);
    ASSERT_TRUE(exCtx != NULL);

    int32_t val = algId;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_PkeyCtrl(deCtx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(exCtx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val)), PQCP_SUCCESS);
    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    BSL_Param pub[2] = {
        {PQCP_PARAM_POLAR_LAC_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubData, sizeof(pubData), 0},
        BSL_PARAM_END
    };
    BSL_Param prv[2] = {
        {PQCP_PARAM_POLAR_LAC_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvData, sizeof(prvData), 0},
        BSL_PARAM_END
    };

    ret = CRYPT_EAL_PkeyGetPrvEx(ctx, prv);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_PkeyGetPubEx(ctx, pub);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    pub[0].valueLen = pub[0].useLen;
    ret = CRYPT_EAL_PkeySetPubEx(deCtx, pub);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ASSERT_NE(CRYPT_EAL_PkeySetPrvEx(deCtx, prv), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(exCtx, prv), PQCP_SUCCESS);
    uint32_t cipherLen = sizeof(cipher);
    uint32_t sharedLen = sizeof(sharedKey);
    ret = CRYPT_EAL_PkeyEncapsInit(deCtx, NULL);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_PkeyEncaps(deCtx, cipher, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyDecapsInit(ctx, NULL);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    uint32_t sharedLen2 = sizeof(sharedKey2);
    ret = CRYPT_EAL_PkeyDecaps(ctx, cipher, cipherLen, sharedKey2, &sharedLen2);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ASSERT_EQ(sharedLen, sharedLen2);
    ASSERT_COMPARE("compare shared key", sharedKey, sharedLen, sharedKey2, sharedLen2);

    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(exCtx, cipher, &cipherLen, sharedKey, &sharedLen), PQCP_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(exCtx, cipher, cipherLen, sharedKey2, &sharedLen2), PQCP_SUCCESS);
    ASSERT_EQ(sharedLen, sharedLen2);
    ASSERT_COMPARE("compare shared key", sharedKey, sharedLen, sharedKey2, sharedLen2);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(deCtx);
    CRYPT_EAL_PkeyFreeCtx(exCtx);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_POLARLAC_DUP_CTX_API_TC001
* @spec  -
* @title  PQCP Polarlac Context Duplication Test
* @precon  nan
* @brief  1. Create context and generate key pair
*         2. Duplicate context
*         3. Verify both contexts work correctly
* @expect  Duplicated context works as expected
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_POLARLAC_DUP_CTX_API_TC001(int algId)
{

    TestMemInit();
    CRYPT_EAL_SetRandCallBack(TEST_PolarLacRandom);
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *dupCtx = NULL;
    uint8_t cipher[4096] = {0};
    uint8_t sharedKey[32] = {0};
    uint8_t sharedKey2[32] = {0};

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_POLAR_LAC, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    int32_t val = algId;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    dupCtx = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(dupCtx != NULL);

    uint32_t cipherLen = sizeof(cipher);
    uint32_t sharedLen = sizeof(sharedKey);
    ret = CRYPT_EAL_PkeyEncapsInit(dupCtx, NULL);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    ret = CRYPT_EAL_PkeyEncaps(dupCtx, cipher, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ret = CRYPT_EAL_PkeyDecapsInit(dupCtx, NULL);
    ASSERT_EQ(ret, PQCP_SUCCESS);
    uint32_t sharedLen2 = sizeof(sharedKey2);
    ret = CRYPT_EAL_PkeyDecaps(dupCtx, cipher, cipherLen, sharedKey2, &sharedLen2);
    ASSERT_EQ(ret, PQCP_SUCCESS);

    ASSERT_EQ(sharedLen, sharedLen2);
    ASSERT_COMPARE("compare shared key", sharedKey, sharedLen, sharedKey2, sharedLen2);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(dupCtx);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_POLARLAC_NULL_CTX_API_TC001
* @spec  -
* @title  PQCP Polarlac NULL Context Error Handling Test
* @precon  nan
* @brief  1. Call APIs with NULL context
*         2. Verify proper error codes are returned
* @expect  All operations return PQCP_NULL_INPUT or PQCP_NULL_INPUT
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_POLARLAC_NULL_CTX_API_TC001(void)
{
    TestMemInit();
    int32_t ret = CRYPT_EAL_PkeyGen(NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyCtrl(NULL, CRYPT_CTRL_SET_PARA_BY_ID, NULL, 0);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    uint8_t buf[32] = {0};
    BSL_Param param[2] = {
        {PQCP_PARAM_POLAR_LAC_PUBKEY, BSL_PARAM_TYPE_OCTETS, buf, sizeof(buf), 0},
        BSL_PARAM_END
    };
    ret = CRYPT_EAL_PkeyGetPubEx(NULL, param);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeyGetPrvEx(NULL, param);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

EXIT:
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_PQCP_POLARLAC_KEY_NOT_SET_API_TC001
* @spec  -
* @title  PQCP Polarlac Key Not Set Error Handling Test
* @precon  nan
* @brief  1. Create context without setting algorithm
*         2. Try to generate key
*         3. Verify proper error code is returned
* @expect  KeyGen returns PQCP_POLAR_LAC_KEYINFO_NOT_SET
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_POLARLAC_KEY_NOT_SET_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_POLAR_LAC, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    int32_t ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_POLAR_LAC_KEYINFO_NOT_SET);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */
