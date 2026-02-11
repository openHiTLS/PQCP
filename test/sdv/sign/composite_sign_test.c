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

#include "pqcp_test.h"
#include "crypt_composite_sign.h"
#include "pqcp_types.h"
#include "pqcp_provider.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "pqcp_err.h"
#include "crypt_types.h"
#include "bsl_params.h"

/* Define types if not already defined */
#ifndef CRYPT_CompositePub
#define CRYPT_CompositePub CRYPT_Data
#endif

#ifndef CRYPT_CompositePrv
#define CRYPT_CompositePrv CRYPT_Data
#endif

#define ASSERT_EQ(v1, v2, msg)                   \
    do {                                    \
        if ((int32_t)(v1) != (int32_t)(v2)) {                      \
            printf("%s:%d expect:0x%x, real:0x%x, %s\n", __FILE__, __LINE__, (uint32_t)v1, (uint32_t)v2, msg); \
            goto EXIT;                      \
        }                                   \
    } while (0)

#define ASSERT_TRUE(TEST, msg)                   \
    do {                                    \
        if (!(TEST)) {                      \
            printf("%s:%d %s\n", __FILE__, __LINE__, msg); \
            goto EXIT;                      \
        }                                   \
    } while (0)

/* Test KeyGen normal operation */
PqcpTestResult TestCompositeKeyGenNormal(void)
{
    int32_t ret = -1;
    CRYPT_CompositeCtx *ctx = NULL;

    printf("\n=== TestCompositeKeyGenNormal ===\n");

    /* Test all algorithms */
    int32_t algIds[] = {
        PQCP_COMPOSITE_MLDSA44_SM2,
        PQCP_COMPOSITE_MLDSA65_SM2,
        PQCP_COMPOSITE_MLDSA87_SM2
    };

    for (size_t i = 0; i < sizeof(algIds) / sizeof(algIds[0]); i++) {
        printf("Testing KeyGen for algorithm ID: %d\n", algIds[i]);

        ctx = CRYPT_COMPOSITE_NewCtx();
        ASSERT_TRUE(ctx != NULL, "NewCtx failed");

        ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algIds[i], sizeof(algIds[i]));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl SET_PARA_BY_ID failed");

        ret = CRYPT_COMPOSITE_GenKey(ctx);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GenKey failed");

        uint32_t pubKeyLen = 0;
        ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl GET_PUBKEY_LEN failed");
        ASSERT_TRUE(pubKeyLen > 0, "pubKeyLen should be positive");

        uint32_t prvKeyLen = 0;
        ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &prvKeyLen, sizeof(prvKeyLen));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl GET_PRVKEY_LEN failed");
        ASSERT_TRUE(prvKeyLen > 0, "prvKeyLen should be positive");

        printf("  Algorithm ID %d: PASSED (pub=%u, prv=%u)\n", algIds[i], pubKeyLen, prvKeyLen);

        CRYPT_COMPOSITE_FreeCtx(ctx);
        ctx = NULL;
    }

    printf("Test PASSED - All algorithms verified\n");
    return PQCP_TEST_SUCCESS;

EXIT:
    if (ctx != NULL) {
        CRYPT_COMPOSITE_FreeCtx(ctx);
    }
    return PQCP_TEST_FAILURE;
}

/* Test GetPrvKey */
PqcpTestResult TestCompositeGetPrvKey(void)
{
    int32_t ret = -1;
    CRYPT_CompositeCtx *ctx = NULL;
    uint8_t prvKeyData[4096];
    CRYPT_CompositePrv prv = {prvKeyData, sizeof(prvKeyData)};

    printf("\n=== TestCompositeGetPrvKey ===\n");

    /* Test all algorithms */
    int32_t algIds[] = {
        PQCP_COMPOSITE_MLDSA44_SM2,
        PQCP_COMPOSITE_MLDSA65_SM2,
        PQCP_COMPOSITE_MLDSA87_SM2
    };

    for (size_t i = 0; i < sizeof(algIds) / sizeof(algIds[0]); i++) {
        printf("Testing GetPrvKey for algorithm ID: %d\n", algIds[i]);

        ctx = CRYPT_COMPOSITE_NewCtx();
        ASSERT_TRUE(ctx != NULL, "NewCtx failed");

        ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algIds[i], sizeof(algIds[i]));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl SET_PARA_BY_ID failed");

        ret = CRYPT_COMPOSITE_GenKey(ctx);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GenKey failed");

        prv.len = sizeof(prvKeyData);
        ret = CRYPT_COMPOSITE_GetPrvKey(ctx, &prv);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GetPrvKey failed");
        ASSERT_TRUE(prv.len > 0, "prv.len should be positive");

        printf("  Algorithm ID %d: PASSED (key length: %u)\n", algIds[i], prv.len);

        CRYPT_COMPOSITE_FreeCtx(ctx);
        ctx = NULL;
    }

    printf("Test PASSED - All algorithms verified\n");
    return PQCP_TEST_SUCCESS;

EXIT:
    if (ctx != NULL) {
        CRYPT_COMPOSITE_FreeCtx(ctx);
    }
    return PQCP_TEST_FAILURE;
}

/* Test GetPubKey */
PqcpTestResult TestCompositeGetPubKey(void)
{
    int32_t ret = -1;
    CRYPT_CompositeCtx *ctx = NULL;
    uint8_t pubKeyData[4096];
    CRYPT_CompositePub pub = {pubKeyData, sizeof(pubKeyData)};

    printf("\n=== TestCompositeGetPubKey ===\n");

    /* Test all algorithms */
    int32_t algIds[] = {
        PQCP_COMPOSITE_MLDSA44_SM2,
        PQCP_COMPOSITE_MLDSA65_SM2,
        PQCP_COMPOSITE_MLDSA87_SM2
    };

    for (size_t i = 0; i < sizeof(algIds) / sizeof(algIds[0]); i++) {
        printf("Testing GetPubKey for algorithm ID: %d\n", algIds[i]);

        ctx = CRYPT_COMPOSITE_NewCtx();
        ASSERT_TRUE(ctx != NULL, "NewCtx failed");

        ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algIds[i], sizeof(algIds[i]));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl SET_PARA_BY_ID failed");

        ret = CRYPT_COMPOSITE_GenKey(ctx);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GenKey failed");

        pub.len = sizeof(pubKeyData);
        ret = CRYPT_COMPOSITE_GetPubKey(ctx, &pub);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GetPubKey failed");
        ASSERT_TRUE(pub.len > 0, "pub.len should be positive");

        printf("  Algorithm ID %d: PASSED (key length: %u)\n", algIds[i], pub.len);

        CRYPT_COMPOSITE_FreeCtx(ctx);
        ctx = NULL;
    }

    printf("Test PASSED - All algorithms verified\n");
    return PQCP_TEST_SUCCESS;

EXIT:
    if (ctx != NULL) {
        CRYPT_COMPOSITE_FreeCtx(ctx);
    }
    return PQCP_TEST_FAILURE;
}

/* Test SetPrvKey */
PqcpTestResult TestCompositeSetPrvKey(void)
{
    int32_t ret = -1;
    CRYPT_CompositeCtx *ctx = NULL;
    CRYPT_CompositeCtx *ctx2 = NULL;
    uint8_t prvKeyData[4096];
    CRYPT_CompositePrv prv = {prvKeyData, sizeof(prvKeyData)};

    printf("\n=== TestCompositeSetPrvKey ===\n");

    /* Test all algorithms */
    int32_t algIds[] = {
        PQCP_COMPOSITE_MLDSA44_SM2,
        PQCP_COMPOSITE_MLDSA65_SM2,
        PQCP_COMPOSITE_MLDSA87_SM2
    };

    for (size_t i = 0; i < sizeof(algIds) / sizeof(algIds[0]); i++) {
        printf("Testing SetPrvKey for algorithm ID: %d\n", algIds[i]);

        ctx = CRYPT_COMPOSITE_NewCtx();
        ASSERT_TRUE(ctx != NULL, "NewCtx failed");

        ctx2 = CRYPT_COMPOSITE_NewCtx();
        ASSERT_TRUE(ctx2 != NULL, "NewCtx ctx2 failed");

        ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algIds[i], sizeof(algIds[i]));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl SET_PARA_BY_ID failed");
        ret = CRYPT_COMPOSITE_Ctrl(ctx2, CRYPT_CTRL_SET_PARA_BY_ID, &algIds[i], sizeof(algIds[i]));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl SET_PARA_BY_ID ctx2 failed");

        ret = CRYPT_COMPOSITE_GenKey(ctx);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GenKey failed");

        prv.len = sizeof(prvKeyData);
        ret = CRYPT_COMPOSITE_GetPrvKey(ctx, &prv);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GetPrvKey failed");

        ret = CRYPT_COMPOSITE_SetPrvKey(ctx2, &prv);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "SetPrvKey failed");

        printf("  Algorithm ID %d: PASSED\n", algIds[i]);

        CRYPT_COMPOSITE_FreeCtx(ctx);
        ctx = NULL;
        CRYPT_COMPOSITE_FreeCtx(ctx2);
        ctx2 = NULL;
    }

    printf("Test PASSED - All algorithms verified\n");
    return PQCP_TEST_SUCCESS;

EXIT:
    if (ctx != NULL) {
        CRYPT_COMPOSITE_FreeCtx(ctx);
    }
    if (ctx2 != NULL) {
        CRYPT_COMPOSITE_FreeCtx(ctx2);
    }
    return PQCP_TEST_FAILURE;
}

/* Test SetPubKey */
PqcpTestResult TestCompositeSetPubKey(void)
{
    int32_t ret = -1;
    CRYPT_CompositeCtx *ctx = NULL;
    CRYPT_CompositeCtx *ctx2 = NULL;
    uint8_t pubKeyData[4096];
    CRYPT_CompositePub pub = {pubKeyData, sizeof(pubKeyData)};

    printf("\n=== TestCompositeSetPubKey ===\n");

    /* Test all algorithms */
    int32_t algIds[] = {
        PQCP_COMPOSITE_MLDSA44_SM2,
        PQCP_COMPOSITE_MLDSA65_SM2,
        PQCP_COMPOSITE_MLDSA87_SM2
    };

    for (size_t i = 0; i < sizeof(algIds) / sizeof(algIds[0]); i++) {
        printf("Testing SetPubKey for algorithm ID: %d\n", algIds[i]);

        ctx = CRYPT_COMPOSITE_NewCtx();
        ASSERT_TRUE(ctx != NULL, "NewCtx failed");

        ctx2 = CRYPT_COMPOSITE_NewCtx();
        ASSERT_TRUE(ctx2 != NULL, "NewCtx ctx2 failed");

        ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algIds[i], sizeof(algIds[i]));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl SET_PARA_BY_ID failed");
        ret = CRYPT_COMPOSITE_Ctrl(ctx2, CRYPT_CTRL_SET_PARA_BY_ID, &algIds[i], sizeof(algIds[i]));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl SET_PARA_BY_ID ctx2 failed");

        ret = CRYPT_COMPOSITE_GenKey(ctx);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GenKey failed");

        pub.len = sizeof(pubKeyData);
        ret = CRYPT_COMPOSITE_GetPubKey(ctx, &pub);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GetPubKey failed");

        ret = CRYPT_COMPOSITE_SetPubKey(ctx2, &pub);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "SetPubKey failed");

        printf("  Algorithm ID %d: PASSED\n", algIds[i]);

        CRYPT_COMPOSITE_FreeCtx(ctx);
        ctx = NULL;
        CRYPT_COMPOSITE_FreeCtx(ctx2);
        ctx2 = NULL;
    }

    printf("Test PASSED - All algorithms verified\n");
    return PQCP_TEST_SUCCESS;

EXIT:
    if (ctx != NULL) {
        CRYPT_COMPOSITE_FreeCtx(ctx);
    }
    if (ctx2 != NULL) {
        CRYPT_COMPOSITE_FreeCtx(ctx2);
    }
    return PQCP_TEST_FAILURE;
}

/* Test Sign and Verify */
PqcpTestResult TestCompositeSignVerify(void)
{
    int32_t ret = -1;
    CRYPT_CompositeCtx *ctx = NULL;
    CRYPT_CompositeCtx *verifyCtx = NULL;
    uint8_t pubKeyData[4096];
    CRYPT_CompositePub pub = {pubKeyData, sizeof(pubKeyData)};
    uint8_t signData[5000];
    uint32_t signLen;
    const uint8_t message[] = "Test message for composite signature";

    printf("\n=== TestCompositeSignVerify ===\n");

    /* Test all algorithms */
    int32_t algIds[] = {
        PQCP_COMPOSITE_MLDSA44_SM2,
        PQCP_COMPOSITE_MLDSA65_SM2,
        PQCP_COMPOSITE_MLDSA87_SM2
    };

    for (size_t i = 0; i < sizeof(algIds) / sizeof(algIds[0]); i++) {
        printf("Testing Sign/Verify for algorithm ID: %d\n", algIds[i]);

        ctx = CRYPT_COMPOSITE_NewCtx();
        ASSERT_TRUE(ctx != NULL, "NewCtx failed");

        verifyCtx = CRYPT_COMPOSITE_NewCtx();
        ASSERT_TRUE(verifyCtx != NULL, "NewCtx verifyCtx failed");

        ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algIds[i], sizeof(algIds[i]));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl SET_PARA_BY_ID failed");
        ret = CRYPT_COMPOSITE_Ctrl(verifyCtx, CRYPT_CTRL_SET_PARA_BY_ID, &algIds[i], sizeof(algIds[i]));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl SET_PARA_BY_ID verifyCtx failed");

        ret = CRYPT_COMPOSITE_GenKey(ctx);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GenKey failed");

        pub.len = sizeof(pubKeyData);
        ret = CRYPT_COMPOSITE_GetPubKey(ctx, &pub);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GetPubKey failed");

        ret = CRYPT_COMPOSITE_SetPubKey(verifyCtx, &pub);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "SetPubKey verifyCtx failed");

        signLen = sizeof(signData);
        ret = CRYPT_COMPOSITE_Sign(ctx, CRYPT_MD_MAX, message, sizeof(message), signData, &signLen);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Sign failed");

        ret = CRYPT_COMPOSITE_Verify(verifyCtx, CRYPT_MD_MAX, message, sizeof(message), signData, signLen);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Verify failed");

        printf("  Algorithm ID %d: PASSED (signature length: %u)\n", algIds[i], signLen);

        CRYPT_COMPOSITE_FreeCtx(ctx);
        ctx = NULL;
        CRYPT_COMPOSITE_FreeCtx(verifyCtx);
        verifyCtx = NULL;
    }

    printf("Test PASSED - All algorithms verified\n");
    return PQCP_TEST_SUCCESS;

EXIT:
    if (ctx != NULL) {
        CRYPT_COMPOSITE_FreeCtx(ctx);
    }
    if (verifyCtx != NULL) {
        CRYPT_COMPOSITE_FreeCtx(verifyCtx);
    }
    return PQCP_TEST_FAILURE;
}

/* Test Error: NULL context */
PqcpTestResult TestCompositeErrNullCtx(void)
{
    int32_t ret = -1;
    uint32_t len = 0;

    ret = CRYPT_COMPOSITE_GenKey(NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT, "GenKey NULL ctx should return NULL_INPUT");

    ret = CRYPT_COMPOSITE_Ctrl(NULL, CRYPT_CTRL_SET_PARA_BY_ID, NULL, 0);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT, "Ctrl NULL ctx should return NULL_INPUT");

EXIT:
    return (ret == CRYPT_NULL_INPUT) ? PQCP_TEST_SUCCESS : PQCP_TEST_FAILURE;
}

/* Test Error: Algorithm not set */
PqcpTestResult TestCompositeErrAlgNotSet(void)
{
    int32_t ret = -1;
    CRYPT_CompositeCtx *ctx = NULL;

    ctx = CRYPT_COMPOSITE_NewCtx();
    ASSERT_TRUE(ctx != NULL, "NewCtx failed");

    /* Try GenKey without setting algorithm */
    ret = CRYPT_COMPOSITE_GenKey(ctx);
    ASSERT_EQ(ret, PQCP_COMPOSITE_KEYINFO_NOT_SET, "GenKey without alg should return KEYINFO_NOT_SET");

EXIT:
    if (ctx != NULL) {
        CRYPT_COMPOSITE_FreeCtx(ctx);
    }
    return (ret == PQCP_COMPOSITE_KEYINFO_NOT_SET) ? PQCP_TEST_SUCCESS : PQCP_TEST_FAILURE;
}

/* Test Error: Invalid parameters */
PqcpTestResult TestCompositeErrInvalidParams(void)
{
    int32_t ret = -1;
    CRYPT_CompositeCtx *ctx = NULL;
    uint8_t pubKeyData[128];
    CRYPT_CompositePub pub = {pubKeyData, sizeof(pubKeyData)};

    ctx = CRYPT_COMPOSITE_NewCtx();
    ASSERT_TRUE(ctx != NULL, "NewCtx failed");

    int32_t algId = PQCP_COMPOSITE_MLDSA44_SM2;
    ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId));
    ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl SET_PARA_BY_ID failed");

    /* GetPubKey with NULL pub */
    ret = CRYPT_COMPOSITE_GetPubKey(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT, "GetPubKey NULL should return NULL_INPUT");

    /* GetPubKey with NULL pub->data */
    CRYPT_CompositePub pubNullData = {NULL, 100};
    ret = CRYPT_COMPOSITE_GetPubKey(ctx, &pubNullData);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT, "GetPubKey NULL data should return NULL_INPUT");

EXIT:
    if (ctx != NULL) {
        CRYPT_COMPOSITE_FreeCtx(ctx);
    }
    return (ret == CRYPT_NULL_INPUT) ? PQCP_TEST_SUCCESS : PQCP_TEST_FAILURE;
}

/* Test Error: Buffer too small */
PqcpTestResult TestCompositeErrBufferTooSmall(void)
{
    int32_t ret = -1;
    CRYPT_CompositeCtx *ctx = NULL;
    uint8_t pubKeyData[4];  /* Too small */
    CRYPT_CompositePub pub = {pubKeyData, sizeof(pubKeyData)};

    ctx = CRYPT_COMPOSITE_NewCtx();
    ASSERT_TRUE(ctx != NULL, "NewCtx failed");

    int32_t algId = PQCP_COMPOSITE_MLDSA44_SM2;
    ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId));
    ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl SET_PARA_BY_ID failed");

    ret = CRYPT_COMPOSITE_GenKey(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS, "GenKey failed");

    ret = CRYPT_COMPOSITE_GetPubKey(ctx, &pub);
    ASSERT_EQ(ret, PQCP_COMPOSITE_LEN_NOT_ENOUGH, "GetPubKey small buffer should return LEN_NOT_ENOUGH");

EXIT:
    if (ctx != NULL) {
        CRYPT_COMPOSITE_FreeCtx(ctx);
    }
    return (ret == PQCP_COMPOSITE_LEN_NOT_ENOUGH) ? PQCP_TEST_SUCCESS : PQCP_TEST_FAILURE;
}

/* Test Error: Invalid algorithm ID */
PqcpTestResult TestCompositeErrInvalidAlgId(void)
{
    int32_t ret = -1;
    CRYPT_CompositeCtx *ctx = NULL;

    ctx = CRYPT_COMPOSITE_NewCtx();
    ASSERT_TRUE(ctx != NULL, "NewCtx failed");

    int32_t algId = 99999;  /* Invalid algorithm ID */
    ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId));
    ASSERT_EQ(ret, CRYPT_INVALID_ARG, "Ctrl with invalid alg should return INVALID_ARG");

EXIT:
    if (ctx != NULL) {
        CRYPT_COMPOSITE_FreeCtx(ctx);
    }
    return (ret == CRYPT_INVALID_ARG) ? PQCP_TEST_SUCCESS : PQCP_TEST_FAILURE;
}

/* Test GetSignLen */
PqcpTestResult TestCompositeGetSignLen(void)
{
    int32_t ret = -1;
    CRYPT_CompositeCtx *ctx = NULL;
    int32_t signLen = 0;

    printf("\n=== TestCompositeGetSignLen ===\n");

    /* Test all algorithms */
    int32_t algIds[] = {
        PQCP_COMPOSITE_MLDSA44_SM2,
        PQCP_COMPOSITE_MLDSA65_SM2,
        PQCP_COMPOSITE_MLDSA87_SM2
    };

    for (size_t i = 0; i < sizeof(algIds) / sizeof(algIds[0]); i++) {
        printf("Testing GetSignLen for algorithm ID: %d\n", algIds[i]);

        ctx = CRYPT_COMPOSITE_NewCtx();
        ASSERT_TRUE(ctx != NULL, "NewCtx failed");

        ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algIds[i], sizeof(algIds[i]));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl SET_PARA_BY_ID failed");

        ret = CRYPT_COMPOSITE_GenKey(ctx);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GenKey failed");

        ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_GET_SIGNLEN, &signLen, sizeof(signLen));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl GET_SIGNLEN failed");
        ASSERT_TRUE(signLen > 0, "signLen should be positive");

        printf("  Algorithm ID %d: PASSED (signature length: %d)\n", algIds[i], signLen);

        CRYPT_COMPOSITE_FreeCtx(ctx);
        ctx = NULL;
    }

    printf("Test PASSED - All algorithms verified\n");
    return PQCP_TEST_SUCCESS;

EXIT:
    if (ctx != NULL) {
        CRYPT_COMPOSITE_FreeCtx(ctx);
    }
    return PQCP_TEST_FAILURE;
}

/* Test DupCtx - Enhanced version with comprehensive verification */
PqcpTestResult TestCompositeDupCtx(void)
{
    int32_t ret = -1;
    CRYPT_CompositeCtx *ctx = NULL;
    CRYPT_CompositeCtx *dupCtx = NULL;
    uint8_t pubKeyData1[4096], pubKeyData2[4096];
    uint8_t prvKeyData1[4096], prvKeyData2[4096];
    uint8_t signData1[5000], signData2[5000];
    uint32_t signLen1, signLen2;
    uint8_t msg[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                       0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                       0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};

    /* Test all algorithms */
    int32_t algIds[] = {
        PQCP_COMPOSITE_MLDSA44_SM2,
        PQCP_COMPOSITE_MLDSA65_SM2,
        PQCP_COMPOSITE_MLDSA87_SM2
    };

    printf("\n=== TestCompositeDupCtx ===\n");

    for (size_t i = 0; i < sizeof(algIds) / sizeof(algIds[0]); i++) {
        printf("Testing DupCtx for algorithm ID: %d\n", algIds[i]);

        /* Create original context */
        ctx = CRYPT_COMPOSITE_NewCtx();
        ASSERT_TRUE(ctx != NULL, "NewCtx failed");

        /* Set algorithm */
        ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algIds[i], sizeof(algIds[i]));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl SET_PARA_BY_ID failed");

        /* Generate keys */
        ret = CRYPT_COMPOSITE_GenKey(ctx);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GenKey failed");

        /* Duplicate context */
        dupCtx = CRYPT_COMPOSITE_DupCtx(ctx);
        ASSERT_TRUE(dupCtx != NULL, "DupCtx failed");

        /* Verify public keys are identical */
        CRYPT_CompositePub pub1 = {pubKeyData1, sizeof(pubKeyData1)};
        CRYPT_CompositePub pub2 = {pubKeyData2, sizeof(pubKeyData2)};

        ret = CRYPT_COMPOSITE_GetPubKey(ctx, &pub1);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GetPubKey original failed");

        ret = CRYPT_COMPOSITE_GetPubKey(dupCtx, &pub2);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GetPubKey duplicated failed");

        ASSERT_TRUE(pub1.len == pub2.len, "Duplicated pub key length mismatch");
        ret = memcmp(pub1.data, pub2.data, pub1.len);
        ASSERT_EQ(ret, 0, "Duplicated pub key data mismatch");

        /* Verify private keys are identical */
        CRYPT_CompositePrv prv1 = {prvKeyData1, sizeof(prvKeyData1)};
        CRYPT_CompositePrv prv2 = {prvKeyData2, sizeof(prvKeyData2)};

        ret = CRYPT_COMPOSITE_GetPrvKey(ctx, &prv1);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GetPrvKey original failed");

        ret = CRYPT_COMPOSITE_GetPrvKey(dupCtx, &prv2);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GetPrvKey duplicated failed");

        ASSERT_TRUE(prv1.len == prv2.len, "Duplicated prv key length mismatch");
        ret = memcmp(prv1.data, prv2.data, prv1.len);
        ASSERT_EQ(ret, 0, "Duplicated prv key data mismatch");

        /* Test signing with original context */
        signLen1 = sizeof(signData1);
        ret = CRYPT_COMPOSITE_Sign(ctx, 0, msg, sizeof(msg), signData1, &signLen1);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Sign with original context failed");

        /* Verify signature with duplicated context (has same public key) */
        ret = CRYPT_COMPOSITE_Verify(dupCtx, 0, msg, sizeof(msg), signData1, signLen1);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Verify with duplicated context failed");

        /* Test signing with duplicated context */
        signLen2 = sizeof(signData2);
        ret = CRYPT_COMPOSITE_Sign(dupCtx, 0, msg, sizeof(msg), signData2, &signLen2);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Sign with duplicated context failed");

        /* Verify signature from duplicated context with original context */
        ret = CRYPT_COMPOSITE_Verify(ctx, 0, msg, sizeof(msg), signData2, signLen2);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Verify with original context failed");

        /* Test that both contexts can work independently after one is freed */
        CRYPT_COMPOSITE_FreeCtx(ctx);
        ctx = NULL;

        /* Duplicated context should still work */
        signLen1 = sizeof(signData1);
        ret = CRYPT_COMPOSITE_Sign(dupCtx, 0, msg, sizeof(msg), signData1, &signLen1);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Sign with dupCtx after freeing original failed");

        ret = CRYPT_COMPOSITE_Verify(dupCtx, 0, msg, sizeof(msg), signData1, signLen1);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Verify with dupCtx after freeing original failed");

        printf("  Algorithm ID %d: PASSED\n", algIds[i]);

        /* Cleanup for next iteration */
        CRYPT_COMPOSITE_FreeCtx(dupCtx);
        dupCtx = NULL;
    }

    printf("Test PASSED - All algorithms verified\n");
    return PQCP_TEST_SUCCESS;

EXIT:
    if (ctx != NULL) {
        CRYPT_COMPOSITE_FreeCtx(ctx);
    }
    if (dupCtx != NULL) {
        CRYPT_COMPOSITE_FreeCtx(dupCtx);
    }
    return (ret == 0 || ret == CRYPT_SUCCESS) ? PQCP_TEST_SUCCESS : PQCP_TEST_FAILURE;
}

/* Test Ex versions of Set/Get key */
PqcpTestResult TestCompositeKeyEx(void)
{
    int32_t ret = -1;
    CRYPT_CompositeCtx *ctx = NULL;
    CRYPT_CompositeCtx *ctx2 = NULL;
    uint8_t pubKeyData[4096];
    uint8_t prvKeyData[4096];

    printf("\n=== TestCompositeKeyEx ===\n");

    /* Test all algorithms */
    int32_t algIds[] = {
        PQCP_COMPOSITE_MLDSA44_SM2,
        PQCP_COMPOSITE_MLDSA65_SM2,
        PQCP_COMPOSITE_MLDSA87_SM2
    };

    for (size_t i = 0; i < sizeof(algIds) / sizeof(algIds[0]); i++) {
        printf("Testing KeyEx for algorithm ID: %d\n", algIds[i]);

        ctx = CRYPT_COMPOSITE_NewCtx();
        ASSERT_TRUE(ctx != NULL, "NewCtx failed");

        ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algIds[i], sizeof(algIds[i]));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl SET_PARA_BY_ID failed");

        ret = CRYPT_COMPOSITE_GenKey(ctx);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GenKey failed");

        /* Test GetPubKeyEx and GetPrvKeyEx */
        BSL_Param pubParams[2] = {
            {PQCP_PARAM_COMPOSITE_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKeyData, sizeof(pubKeyData), 0},
            BSL_PARAM_END
        };
        BSL_Param prvParams[2] = {
            {PQCP_PARAM_COMPOSITE_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvKeyData, sizeof(prvKeyData), 0},
            BSL_PARAM_END
        };

        ret = CRYPT_COMPOSITE_GetPubKeyEx(ctx, pubParams);
        pubParams[0].valueLen = pubParams[0].useLen;
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GetPubKeyEx failed");

        ret = CRYPT_COMPOSITE_GetPrvKeyEx(ctx, prvParams);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GetPrvKeyEx failed");
        prvParams[0].valueLen = prvParams[0].useLen;

        /* Test SetPubKeyEx and SetPrvKeyEx */
        ctx2 = CRYPT_COMPOSITE_NewCtx();
        ASSERT_TRUE(ctx2 != NULL, "NewCtx ctx2 failed");

        ret = CRYPT_COMPOSITE_Ctrl(ctx2, CRYPT_CTRL_SET_PARA_BY_ID, &algIds[i], sizeof(algIds[i]));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl SET_PARA_BY_ID ctx2 failed");

        ret = CRYPT_COMPOSITE_SetPubKeyEx(ctx2, pubParams);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "SetPubKeyEx failed");

        ret = CRYPT_COMPOSITE_SetPrvKeyEx(ctx2, prvParams);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "SetPrvKeyEx failed");

        printf("  Algorithm ID %d: PASSED\n", algIds[i]);

        CRYPT_COMPOSITE_FreeCtx(ctx);
        ctx = NULL;
        CRYPT_COMPOSITE_FreeCtx(ctx2);
        ctx2 = NULL;
    }

    printf("Test PASSED - All algorithms verified\n");
    return PQCP_TEST_SUCCESS;

EXIT:
    if (ctx != NULL) {
        CRYPT_COMPOSITE_FreeCtx(ctx);
    }
    if (ctx2 != NULL) {
        CRYPT_COMPOSITE_FreeCtx(ctx2);
    }
    return PQCP_TEST_FAILURE;
}

/* Test separate PQC and TRAD key/signature lengths */
PqcpTestResult TestCompositeGetSeparateKeyLen(void)
{
    int32_t ret = -1;
    CRYPT_CompositeCtx *ctx = NULL;
    uint32_t pqcPrvKeyLen = 0;
    uint32_t tradPrvKeyLen = 0;
    uint32_t pqcPubKeyLen = 0;
    uint32_t tradPubKeyLen = 0;
    uint32_t totalPrvKeyLen = 0;
    uint32_t totalPubKeyLen = 0;

    printf("\n=== TestCompositeGetSeparateKeyLen ===\n");

    /* Test all algorithms */
    int32_t algIds[] = {
        PQCP_COMPOSITE_MLDSA44_SM2,
        PQCP_COMPOSITE_MLDSA65_SM2,
        PQCP_COMPOSITE_MLDSA87_SM2
    };

    for (size_t i = 0; i < sizeof(algIds) / sizeof(algIds[0]); i++) {
        printf("Testing separate key length for algorithm ID: %d\n", algIds[i]);

        ctx = CRYPT_COMPOSITE_NewCtx();
        ASSERT_TRUE(ctx != NULL, "NewCtx failed");

        ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algIds[i], sizeof(algIds[i]));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl SET_PARA_BY_ID failed");

        ret = CRYPT_COMPOSITE_GenKey(ctx);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GenKey failed");

        /* Get PQC private key length (MLDSA seed length) */
        ret = CRYPT_COMPOSITE_Ctrl(ctx,PQCP_CTRL_HYBRID_GET_PQC_PRVKEY_LEN,
                                    &pqcPrvKeyLen, sizeof(pqcPrvKeyLen));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Failed to get PQC private key length");
        ASSERT_EQ(pqcPrvKeyLen, 32, "MLDSA seed length should be 32 bytes");

        /* Get TRAD private key length (SM2) */
        ret = CRYPT_COMPOSITE_Ctrl(ctx,PQCP_CTRL_HYBRID_GET_TRAD_PRVKEY_LEN,
                                    &tradPrvKeyLen, sizeof(tradPrvKeyLen));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Failed to get TRAD private key length");
        ASSERT_EQ(tradPrvKeyLen, 32, "SM2 private key length should be positive");

        /* Get total private key length */
        ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN,
                                    &totalPrvKeyLen, sizeof(totalPrvKeyLen));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Failed to get total private key length");
        ASSERT_EQ(totalPrvKeyLen, pqcPrvKeyLen + tradPrvKeyLen,
                  "Total private key length should equal PQC + TRAD");

        /* Get PQC public key length */
        ret = CRYPT_COMPOSITE_Ctrl(ctx,PQCP_CTRL_HYBRID_GET_PQC_PUBKEY_LEN,
                                    &pqcPubKeyLen, sizeof(pqcPubKeyLen));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Failed to get PQC public key length");
        ASSERT_TRUE(pqcPubKeyLen > 0, "MLDSA public key length should be positive");

        /* Get TRAD public key length (SM2) */
        ret = CRYPT_COMPOSITE_Ctrl(ctx,PQCP_CTRL_HYBRID_GET_TRAD_PUBKEY_LEN,
                                    &tradPubKeyLen, sizeof(tradPubKeyLen));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Failed to get TRAD public key length");
        ASSERT_TRUE(tradPubKeyLen > 0, "SM2 public key length should be positive");

        /* Get total public key length */
        ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN,
                                    &totalPubKeyLen, sizeof(totalPubKeyLen));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Failed to get total public key length");
        ASSERT_EQ(totalPubKeyLen, pqcPubKeyLen + tradPubKeyLen,
                  "Total public key length should equal PQC + TRAD");

        printf("  Algorithm ID %d: PASSED\n"
               "    PQC Prv=%u, TRAD Prv=%u, Total=%u\n"
               "    PQC Pub=%u, TRAD Pub=%u, Total=%u\n",
               algIds[i], pqcPrvKeyLen, tradPrvKeyLen, totalPrvKeyLen,
               pqcPubKeyLen, tradPubKeyLen, totalPubKeyLen);

        CRYPT_COMPOSITE_FreeCtx(ctx);
        ctx = NULL;
    }

    printf("Test PASSED - All algorithms verified\n");
    return PQCP_TEST_SUCCESS;

EXIT:
    if (ctx != NULL) {
        CRYPT_COMPOSITE_FreeCtx(ctx);
    }
    return PQCP_TEST_FAILURE;
}

/* Test separate PQC signature length */
PqcpTestResult TestCompositeGetSeparateSignLen(void)
{
    int32_t ret = -1;
    CRYPT_CompositeCtx *ctx = NULL;
    uint32_t pqcSigLen = 0;
    uint32_t totalSigLen = 0;

    printf("\n=== TestCompositeGetSeparateSignLen ===\n");

    /* Test all algorithms */
    int32_t algIds[] = {
        PQCP_COMPOSITE_MLDSA44_SM2,
        PQCP_COMPOSITE_MLDSA65_SM2,
        PQCP_COMPOSITE_MLDSA87_SM2
    };

    for (size_t i = 0; i < sizeof(algIds) / sizeof(algIds[0]); i++) {
        printf("Testing PQC signature length for algorithm ID: %d\n", algIds[i]);

        ctx = CRYPT_COMPOSITE_NewCtx();
        ASSERT_TRUE(ctx != NULL, "NewCtx failed");

        ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algIds[i], sizeof(algIds[i]));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Ctrl SET_PARA_BY_ID failed");

        ret = CRYPT_COMPOSITE_GenKey(ctx);
        ASSERT_EQ(ret, CRYPT_SUCCESS, "GenKey failed");

        /* Get PQC signature length (MLDSA) */
        ret = CRYPT_COMPOSITE_Ctrl(ctx,PQCP_CTRL_HYBRID_GET_PQC_SIGNLEN,
                                    &pqcSigLen, sizeof(pqcSigLen));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Failed to get PQC signature length");
        ASSERT_TRUE(pqcSigLen > 0, "MLDSA signature length should be positive");

        /* Verify expected MLDSA signature lengths */
        switch (algIds[i]) {
            case PQCP_COMPOSITE_MLDSA44_SM2:
                ASSERT_EQ(pqcSigLen, 2420, "MLDSA44 signature should be 2420 bytes");
                break;
            case PQCP_COMPOSITE_MLDSA65_SM2:
                ASSERT_EQ(pqcSigLen, 3309, "MLDSA65 signature should be 3309 bytes");
                break;
            case PQCP_COMPOSITE_MLDSA87_SM2:
                ASSERT_EQ(pqcSigLen, 4627, "MLDSA87 signature should be 4627 bytes");
                break;
            default:
                break;
        }

        /* Get total composite signature length (includes both MLDSA and SM2) */
        ret = CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_GET_SIGNLEN,
                                    &totalSigLen, sizeof(totalSigLen));
        ASSERT_EQ(ret, CRYPT_SUCCESS, "Failed to get total signature length");
        ASSERT_TRUE(totalSigLen > pqcSigLen, "Total signature length should include both MLDSA and SM2");

        printf("  Algorithm ID %d: PASSED\n"
               "    MLDSA Sig Len=%u, Total Sig Len=%u\n",
               algIds[i], pqcSigLen, totalSigLen);

        CRYPT_COMPOSITE_FreeCtx(ctx);
        ctx = NULL;
    }

    printf("Test PASSED - All algorithms verified\n");
    return PQCP_TEST_SUCCESS;

EXIT:
    if (ctx != NULL) {
        CRYPT_COMPOSITE_FreeCtx(ctx);
    }
    return PQCP_TEST_FAILURE;
}

/* Comprehensive test that runs all test cases and returns summary */
int32_t TestCompositeComprehensive(void)
{
    PqcpTestResult result;
    int32_t passCount = 0;
    int32_t failCount = 0;
    int32_t total = 0;

    printf("\n");
    printf("========================================\n");
    printf("   COMPOSITE_SIGN API TEST SUITE\n");
    printf("========================================\n");

    /* Define all test cases - eliminating redundant Get tests */
    struct {
        const char *name;
        PqcpTestResult (*test_func)(void);
    } tests[] = {
        {"TestCompositeKeyGenNormal", TestCompositeKeyGenNormal},
        {"TestCompositeSetPrvKey", TestCompositeSetPrvKey},
        {"TestCompositeSetPubKey", TestCompositeSetPubKey},
        {"TestCompositeSignVerify", TestCompositeSignVerify},
        {"TestCompositeDupCtx", TestCompositeDupCtx},
        {"TestCompositeGetSignLen", TestCompositeGetSignLen},
        {"TestCompositeKeyEx", TestCompositeKeyEx},
        {"TestCompositeGetSeparateKeyLen", TestCompositeGetSeparateKeyLen},
        {"TestCompositeGetSeparateSignLen", TestCompositeGetSeparateSignLen},
        {"TestCompositeErrNullCtx", TestCompositeErrNullCtx},
        {"TestCompositeErrAlgNotSet", TestCompositeErrAlgNotSet},
        {"TestCompositeErrInvalidParams", TestCompositeErrInvalidParams},
        {"TestCompositeErrBufferTooSmall", TestCompositeErrBufferTooSmall},
        {"TestCompositeErrInvalidAlgId", TestCompositeErrInvalidAlgId},
    };

    total = sizeof(tests) / sizeof(tests[0]);

    /* Run all tests */
    for (int32_t i = 0; i < total; i++) {
        printf("\n----------------------------------------");
        result = tests[i].test_func();
        printf("----------------------------------------\n");

        if (result == PQCP_TEST_SUCCESS) {
            passCount++;
        } else {
            failCount++;
        }
    }

    /* Print summary */
    printf("\n");
    printf("========================================\n");
    printf("   TEST SUMMARY\n");
    printf("========================================\n");
    printf("Total tests: %d\n", total);
    printf("Passed:      %d\n", passCount);
    printf("Failed:      %d\n", failCount);
    printf("Success rate: %.1f%%\n",
           (double)passCount / total * 100.0);
    printf("========================================\n\n");

    return (failCount == 0) ? 0 : 1;
}
