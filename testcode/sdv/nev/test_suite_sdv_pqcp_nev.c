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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "bsl_params.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_types.h"
#include "pqcp_err.h"
#include "pqcp_provider.h"
#include "pqcp_types.h"
#include "nev_kat_drng.h"

#define NEV_KAT_VECTOR_COUNT 10
#define NEV_KAT_LINE_MAX 16384

typedef struct {
    uint8_t *seed;
    uint32_t seedLen;
    uint8_t *pk;
    uint32_t pkLen;
    uint8_t *sk;
    uint32_t skLen;
    uint8_t *ct;
    uint32_t ctLen;
    uint8_t *ss;
    uint32_t ssLen;
} NevKatVector;

#ifdef PQCP_NEV
static DRNG_ctx g_nevKatDrng;

static int32_t TEST_NevKatRandom(uint8_t *random, uint32_t randomLen)
{
    return get_random_number(&g_nevKatDrng, random, (unsigned long long)randomLen * 8);
}

static void NevKatVectorFree(NevKatVector *vector)
{
    if (vector == NULL) {
        return;
    }
    free(vector->seed);
    free(vector->pk);
    free(vector->sk);
    free(vector->ct);
    free(vector->ss);
    (void)memset(vector, 0, sizeof(*vector));
}

static int NevKatCompare(const char *field, uint32_t vectorIndex,
    const uint8_t *actual, uint32_t actualLen, const uint8_t *expected, uint32_t expectedLen)
{
    if (actualLen != expectedLen) {
        (void)fprintf(stderr, "NEV KAT vector %u %s length mismatch: actual=%u expected=%u\n",
            vectorIndex, field, actualLen, expectedLen);
        return -1;
    }
    for (uint32_t i = 0; i < expectedLen; i++) {
        if (actual[i] != expected[i]) {
            (void)fprintf(stderr,
                "NEV KAT vector %u %s mismatch at byte %u: actual=%02X expected=%02X\n",
                vectorIndex, field, i, actual[i], expected[i]);
            return -1;
        }
    }
    return 0;
}

static int NevKatReadValue(FILE *file, const char *prefix, char *value, size_t valueSize)
{
    char line[NEV_KAT_LINE_MAX];
    size_t prefixLen = strlen(prefix);
    while (fgets(line, sizeof(line), file) != NULL) {
        size_t lineLen = strcspn(line, "\r\n");
        line[lineLen] = '\0';
        if (lineLen == 0) {
            continue;
        }
        if (strncmp(line, prefix, prefixLen) != 0 || lineLen - prefixLen + 1 > valueSize) {
            return -1;
        }
        (void)memcpy(value, line + prefixLen, lineLen - prefixLen + 1);
        return 0;
    }
    return -1;
}

static int NevKatReadUint32(FILE *file, const char *prefix, uint32_t *value)
{
    char text[32];
    char *end = NULL;
    if (NevKatReadValue(file, prefix, text, sizeof(text)) != 0) {
        return -1;
    }
    unsigned long parsed = strtoul(text, &end, 10);
    if (end == text || *end != '\0' || parsed > UINT32_MAX) {
        return -1;
    }
    *value = (uint32_t)parsed;
    return 0;
}

static int NevKatHexNibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int NevKatReadHex(FILE *file, const char *prefix, uint32_t valueLen, uint8_t **value)
{
    char text[NEV_KAT_LINE_MAX];
    if (valueLen > (NEV_KAT_LINE_MAX - 1) / 2 ||
        NevKatReadValue(file, prefix, text, sizeof(text)) != 0 ||
        strlen(text) != (size_t)valueLen * 2) {
        return -1;
    }
    uint8_t *data = malloc(valueLen);
    if (data == NULL) {
        return -1;
    }
    for (uint32_t i = 0; i < valueLen; i++) {
        int high = NevKatHexNibble(text[2 * i]);
        int low = NevKatHexNibble(text[2 * i + 1]);
        if (high < 0 || low < 0) {
            free(data);
            return -1;
        }
        data[i] = (uint8_t)((high << 4) | low);
    }
    *value = data;
    return 0;
}

static int NevKatReadVector(FILE *file, NevKatVector *vector)
{
    char count[32];
    if (NevKatReadValue(file, "Count = ", count, sizeof(count)) != 0 ||
        NevKatReadUint32(file, "Seed_Len = ", &vector->seedLen) != 0 ||
        NevKatReadHex(file, "Seed = ", vector->seedLen, &vector->seed) != 0 ||
        NevKatReadUint32(file, "PK_Len = ", &vector->pkLen) != 0 ||
        NevKatReadHex(file, "PK = ", vector->pkLen, &vector->pk) != 0 ||
        NevKatReadUint32(file, "SK_Len = ", &vector->skLen) != 0 ||
        NevKatReadHex(file, "SK = ", vector->skLen, &vector->sk) != 0 ||
        NevKatReadUint32(file, "CT_Len = ", &vector->ctLen) != 0 ||
        NevKatReadHex(file, "CT = ", vector->ctLen, &vector->ct) != 0 ||
        NevKatReadUint32(file, "SS_Len = ", &vector->ssLen) != 0 ||
        NevKatReadHex(file, "SS = ", vector->ssLen, &vector->ss) != 0) {
        NevKatVectorFree(vector);
        return -1;
    }
    return 0;
}
#endif
/* END_HEADER */

/* @
* @test  SDV_CRYPTO_PQCP_NEV_KAT_TC001
* @spec  -
* @title  NEV provider ICCS known-answer tests
* @precon  nan
* @brief  1. Read all ten vectors for one NEV parameter set.
*         2. Recreate the submission's deterministic DRNG from each Seed.
*         3. Generate keys, encapsulate and decapsulate through the provider.
*         4. Compare PK, SK, CT and SS with the submitted KAT.
*         5. Import and duplicate the keys, then repeat the KEM round trip.
* @expect All twelve parameter sets match all submitted vectors.
* @prior  nan
* @auto   TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_NEV_KAT_TC001(int algId, char *vectorFile)
{
#ifdef PQCP_NEV
    TestMemInit();
    FILE *file = NULL;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *encCtx = NULL;
    CRYPT_EAL_PkeyCtx *decCtx = NULL;
    CRYPT_EAL_PkeyCtx *encDup = NULL;
    CRYPT_EAL_PkeyCtx *decDup = NULL;
    NevKatVector vector = {0};
    uint8_t *actualPk = NULL;
    uint8_t *actualSk = NULL;
    uint8_t *actualCt = NULL;
    uint8_t *actualSs = NULL;
    uint8_t *decapsSs = NULL;

    file = fopen(vectorFile, "rb");
    ASSERT_TRUE(file != NULL);
    CRYPT_EAL_SetRandCallBack(TEST_NevKatRandom);

    for (uint32_t i = 0; i < NEV_KAT_VECTOR_COUNT; i++) {
        ASSERT_EQ(NevKatReadVector(file, &vector), 0);
        ASSERT_EQ(vector.seedLen, 64);
        ASSERT_EQ(init_random_number(&g_nevKatDrng, vector.seed, vector.seedLen), 0);

        ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_NEV,
            CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
        ASSERT_TRUE(ctx != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), PQCP_SUCCESS);

        uint32_t length = 0;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &length, sizeof(length)), PQCP_SUCCESS);
        ASSERT_EQ(length, vector.pkLen);
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &length, sizeof(length)), PQCP_SUCCESS);
        ASSERT_EQ(length, vector.skLen);
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &length, sizeof(length)), PQCP_SUCCESS);
        ASSERT_EQ(length, vector.ctLen);
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &length, sizeof(length)), PQCP_SUCCESS);
        ASSERT_EQ(length, vector.ssLen);

        ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), PQCP_SUCCESS);

        actualPk = malloc(vector.pkLen);
        actualSk = malloc(vector.skLen);
        actualCt = malloc(vector.ctLen);
        actualSs = malloc(vector.ssLen);
        decapsSs = malloc(vector.ssLen);
        ASSERT_TRUE(actualPk != NULL && actualSk != NULL && actualCt != NULL &&
            actualSs != NULL && decapsSs != NULL);

        BSL_Param pub[2] = {
            {PQCP_PARAM_NEV_PUBKEY, BSL_PARAM_TYPE_OCTETS, actualPk, vector.pkLen, 0},
            BSL_PARAM_END
        };
        BSL_Param prv[2] = {
            {PQCP_PARAM_NEV_PRVKEY, BSL_PARAM_TYPE_OCTETS, actualSk, vector.skLen, 0},
            BSL_PARAM_END
        };
        ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, pub), PQCP_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(ctx, prv), PQCP_SUCCESS);
        ASSERT_EQ(NevKatCompare("public key", i, actualPk, pub[0].useLen, vector.pk, vector.pkLen), 0);
        ASSERT_EQ(NevKatCompare("private key", i, actualSk, prv[0].useLen, vector.sk, vector.skLen), 0);

        uint32_t ctLen = vector.ctLen;
        uint32_t ssLen = vector.ssLen;
        ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx, NULL), PQCP_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx, actualCt, &ctLen, actualSs, &ssLen), PQCP_SUCCESS);
        ASSERT_EQ(NevKatCompare("ciphertext", i, actualCt, ctLen, vector.ct, vector.ctLen), 0);
        ASSERT_EQ(NevKatCompare("shared secret", i, actualSs, ssLen, vector.ss, vector.ssLen), 0);

        uint32_t decapsLen = vector.ssLen;
        ASSERT_EQ(CRYPT_EAL_PkeyDecapsInit(ctx, NULL), PQCP_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, actualCt, ctLen, decapsSs, &decapsLen), PQCP_SUCCESS);
        ASSERT_EQ(NevKatCompare("decapsulated secret", i,
            decapsSs, decapsLen, vector.ss, vector.ssLen), 0);

        encCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_NEV,
            CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
        decCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_NEV,
            CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
        ASSERT_TRUE(encCtx != NULL && decCtx != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(encCtx, CRYPT_CTRL_SET_PARA_BY_ID,
            &algId, sizeof(algId)), PQCP_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(decCtx, CRYPT_CTRL_SET_PARA_BY_ID,
            &algId, sizeof(algId)), PQCP_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(encCtx, pub), PQCP_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(decCtx, prv), PQCP_SUCCESS);
        encDup = CRYPT_EAL_PkeyDupCtx(encCtx);
        decDup = CRYPT_EAL_PkeyDupCtx(decCtx);
        ASSERT_TRUE(encDup != NULL && decDup != NULL);

        ctLen = vector.ctLen;
        ssLen = vector.ssLen;
        decapsLen = vector.ssLen;
        ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(encDup, NULL), PQCP_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyEncaps(encDup, actualCt, &ctLen,
            actualSs, &ssLen), PQCP_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyDecapsInit(decDup, NULL), PQCP_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(decDup, actualCt, ctLen,
            decapsSs, &decapsLen), PQCP_SUCCESS);
        ASSERT_COMPARE("imported key cache shared secret", actualSs, ssLen,
            decapsSs, decapsLen);

        CRYPT_EAL_PkeyFreeCtx(ctx);
        ctx = NULL;
        CRYPT_EAL_PkeyFreeCtx(encCtx);
        encCtx = NULL;
        CRYPT_EAL_PkeyFreeCtx(decCtx);
        decCtx = NULL;
        CRYPT_EAL_PkeyFreeCtx(encDup);
        encDup = NULL;
        CRYPT_EAL_PkeyFreeCtx(decDup);
        decDup = NULL;
        NevKatVectorFree(&vector);
        free(actualPk);
        free(actualSk);
        free(actualCt);
        free(actualSs);
        free(decapsSs);
        actualPk = NULL;
        actualSk = NULL;
        actualCt = NULL;
        actualSs = NULL;
        decapsSs = NULL;
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(encCtx);
    CRYPT_EAL_PkeyFreeCtx(decCtx);
    CRYPT_EAL_PkeyFreeCtx(encDup);
    CRYPT_EAL_PkeyFreeCtx(decDup);
    NevKatVectorFree(&vector);
    free(actualPk);
    free(actualSk);
    free(actualCt);
    free(actualSs);
    free(decapsSs);
    CRYPT_EAL_SetRandCallBack(NULL);
    if (file != NULL) {
        (void)fclose(file);
    }
#else
    SKIP_TEST();
    (void)algId;
    (void)vectorFile;
#endif
}
/* END_CASE */
