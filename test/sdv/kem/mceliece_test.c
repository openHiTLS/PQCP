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

#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "pqcp_types.h"
#include "pqcp_provider.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_rand.h"
#include "pqcp_test.h"
#include "mceliece.h"

// cache
static const int32_t maxLineLen = 8 * 1024 * 1024; // 1 MB
static uint8_t seedHex[1024];
static uint8_t *pkHex;
static uint8_t *skHex;
static uint8_t *ctHex;
static uint8_t ssHex[1024];

// MCELIECE_SEED_BYTES --> seed: 384 bit
// MCELIECE_L_BYTES    --> sharedkey: 256 bit

static uint8_t seedBin[MCELIECE_SEED_BYTES];
static uint8_t *pkBin;
static uint8_t *skBin;
static uint8_t *ctBin;
static uint8_t ssBin[MCELIECE_L_BYTES];

static size_t seedLen = 0;
static size_t pkLen = 0;
static size_t skLen = 0;
static size_t ctLen = 0;
static size_t ssLen = 0;

static const uint8_t hexVal[256] = {
    ['0'] = 0,
    ['1'] = 1,
    ['2'] = 2,
    ['3'] = 3,
    ['4'] = 4,
    ['5'] = 5,
    ['6'] = 6,
    ['7'] = 7,
    ['8'] = 8,
    ['9'] = 9,
    ['A'] = 10,
    ['B'] = 11,
    ['C'] = 12,
    ['D'] = 13,
    ['E'] = 14,
    ['F'] = 15,
    ['a'] = 10,
    ['b'] = 11,
    ['c'] = 12,
    ['d'] = 13,
    ['e'] = 14,
    ['f'] = 15,
};

static int totalCount = 0;
static int pkOK = 0;
static int pkNG = 0;
static int skOK = 0;
static int skNG = 0;
static int ssOK = 0;
static int ssNG = 0;

// tail of file name --> algID
static struct
{
    const char *suffix;
    PQC_Mceliece_AlgWithParamId id;
} g_suffixAlgIDMap[] = {
    {"6688128", PQC_ALG_ID_MCELIECE_6688128},
    {"6688128f", PQC_ALG_ID_MCELIECE_6688128_F},
    {"6688128pc", PQC_ALG_ID_MCELIECE_6688128_PC},
    {"6688128pcf", PQC_ALG_ID_MCELIECE_6688128_PCF},

    {"6960119", PQC_ALG_ID_MCELIECE_6960119},
    {"6960119f", PQC_ALG_ID_MCELIECE_6960119_F},
    {"6960119pc", PQC_ALG_ID_MCELIECE_6960119_PC},
    {"6960119pcf", PQC_ALG_ID_MCELIECE_6960119_PCF},

    {"8192128", PQC_ALG_ID_MCELIECE_8192128},
    {"8192128f", PQC_ALG_ID_MCELIECE_8192128_F},
    {"8192128pc", PQC_ALG_ID_MCELIECE_8192128_PC},
    {"8192128pcf", PQC_ALG_ID_MCELIECE_8192128_PCF},
};

static int Hex2Bin(const char *hex, uint8_t *bin, size_t *outLen, size_t binMax)
{
    if (!hex || !bin || !outLen)
    {
        return -1;
    }
    size_t hexLen = strlen(hex);
    if (hexLen & 1)
    {
        return -1;
    }

    size_t bytes = hexLen >> 1;
    if (bytes > binMax)
    {
        fprintf(stderr, "hex2bin overflow: need %zu bytes, buffer has %zu\n", bytes, binMax);
        *outLen = 0;
        return -1;
    }

    *outLen = bytes;
    for (size_t i = 0; i < bytes; i++)
    {
        uint8_t h = hexVal[(uint8_t)hex[2 * i]];
        uint8_t l = hexVal[(uint8_t)hex[2 * i + 1]];
        if (h > 15 || l > 15)
        {
            return -1;
        }
        bin[i] = (h << 4) | l;
    }
    return 0;
}

static void CommitCurrentBlock(int pkBytes, int skBytes, int ctBytes)
{
    Hex2Bin(seedHex, seedBin, &seedLen, MCELIECE_SEED_BYTES);
    Hex2Bin(pkHex, pkBin, &pkLen, pkBytes);
    Hex2Bin(skHex, skBin, &skLen, skBytes);
    Hex2Bin(ctHex, ctBin, &ctLen, ctBytes);
    Hex2Bin(ssHex, ssBin, &ssLen, MCELIECE_L_BYTES);
}

static void ObtainMcElieceBytes(
    PQC_Mceliece_AlgWithParamId algID, size_t *pkBytes, size_t *skBytes, size_t *ctBytes)
{
    switch (algID)
    {
    case PQC_ALG_ID_MCELIECE_6688128:
    case PQC_ALG_ID_MCELIECE_6688128_F:
        *pkBytes = 1044992;
        *skBytes = 13932;
        *ctBytes = 208;
        break;

    case PQC_ALG_ID_MCELIECE_6960119:
    case PQC_ALG_ID_MCELIECE_6960119_F:
        *pkBytes = 1047319;
        *skBytes = 13948;
        *ctBytes = 194;
        break;

    case PQC_ALG_ID_MCELIECE_8192128:
    case PQC_ALG_ID_MCELIECE_8192128_F:
        *pkBytes = 1357824;
        *skBytes = 14120;
        *ctBytes = 208;
        break;

    default:
        *pkBytes = 0;
        *skBytes = 0;
        *ctBytes = 0;
        break;
    }
}

// allocate buffer after getting algID
static void AllocateBinBuffers(int pkBytes, int skBytes, int ctBytes)
{
    pkBin = BSL_SAL_Malloc(pkBytes);
    skBin = BSL_SAL_Malloc(skBytes);
    ctBin = BSL_SAL_Malloc(ctBytes);
    if (!pkBin || !skBin || !ctBin)
    {
        fprintf(stderr, "malloc failed\n");
        exit(EXIT_FAILURE);
    }
}

static void AllocateHexBuffers()
{
    pkHex = BSL_SAL_Malloc(maxLineLen);
    skHex = BSL_SAL_Malloc(maxLineLen);
    ctHex = BSL_SAL_Malloc(maxLineLen);
    if (!pkHex || !skHex || !ctHex)
    {
        fprintf(stderr, "malloc failed\n");
        exit(EXIT_FAILURE);
    }
}

// free buffers
static void FreeBinBuffers(void)
{
    if (pkBin != NULL)
    {
        BSL_SAL_FREE(pkBin);
    }
    pkBin = NULL;
    if (skBin != NULL)
    {
        BSL_SAL_FREE(skBin);
    }
    skBin = NULL;
    if (ctBin != NULL)
    {
        BSL_SAL_FREE(ctBin);
    }
    ctBin = NULL;
}

static void FreeHexBuffers(void)
{
    if (pkHex != NULL)
    {
        BSL_SAL_FREE(pkHex);
    }
    pkHex = NULL;
    if (skHex != NULL)
    {
        BSL_SAL_FREE(skHex);
    }
    skHex = NULL;
    if (ctHex != NULL)
    {
        BSL_SAL_FREE(ctHex);
    }
    ctHex = NULL;
}

// extract values from .rsp files
static void ExtractValue(const char *line, char *out, size_t outLen)
{
    const char *p = strchr(line, '=');
    if (!p)
    {
        *out = '\0';
        return;
    }
    p++;
    while (*p == ' ' || *p == '\t')
    {
        p++;
    }
    strncpy(out, p, outLen - 1);
    out[outLen - 1] = '\0';

    size_t len = strlen(out);
    if (len && out[len - 1] == '\n')
    {
        out[len - 1] = '\0';
    }
}

// fixed seed
static int32_t TEST_ClassicMcElieceRandom(uint8_t *randNum, uint32_t randLen)
{
    memcpy_s(randNum, randLen, seedBin, MCELIECE_SEED_BYTES);
    return 0;
}

// process KAT testing
static void ProcessCurrentKAT(int32_t algID, int semi, int pkBytes, int skBytes, int ctBytes)
{
    // hex to dec_bin
    CommitCurrentBlock(pkBytes, skBytes, ctBytes); // copy pk_hex / sk_hex / ct_hex to pk_bin /sk_bin / ct_bin
    totalCount++;

    // -----------------------------------------------------
    int32_t ret = -1;
    int32_t sharekeyLen = MCELIECE_L_BYTES;
    uint8_t sharekey2[MCELIECE_L_BYTES];

    uint8_t *pubdata = (uint8_t *)BSL_SAL_Malloc(pkBytes);
    if (pubdata == NULL)
    {
        return PQCP_MALLOC_FAIL;
    }
    uint8_t *prvdata = (uint8_t *)BSL_SAL_Malloc(skBytes);
    if (prvdata == NULL)
    {
        BSL_SAL_FREE(pubdata);
        return PQCP_MALLOC_FAIL;
    }

    BSL_Param pub[2] = {
        {CRYPT_PARAM_MCELIECE_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubdata, pkBytes, 0},
        BSL_PARAM_END};

    BSL_Param prv[2] = {
        {CRYPT_PARAM_MCELIECE_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvdata, skBytes, 0},
        BSL_PARAM_END};

    // init ctx
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_MCELIECE, CRYPT_EAL_PKEY_KEM_OPERATE,
                                                          "provider=pqcp");
    if (ctx == NULL)
    {
        printf("ctx: create ctx failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyCtrl(ctx, PQCP_MCELIECE_ALG_PARAMS, &algID, sizeof(algID));
    if (ret != CRYPT_SUCCESS)
    {
        printf("ctx: ctrl param failed.\n");
        goto EXIT;
    }

    // fix seed
    CRYPT_EAL_SetRandCallBack(TEST_ClassicMcElieceRandom);

    // local keygen
    ret = CRYPT_EAL_PkeyGen(ctx);
    if (ret != CRYPT_SUCCESS)
    {
        printf("keygen failed.\n");
        goto EXIT;
    }

    // cancel seed fixing
    CRYPT_EAL_SetRandCallBack(NULL);

    // get pk
    ret = CRYPT_EAL_PkeyGetPubEx(ctx, &pub);
    if (ret != CRYPT_SUCCESS)
    {
        printf("get pk failed.\n");
        goto EXIT;
    }

    // compare pk
    if (memcmp(pkBin, pubdata, pkBytes) == 0)
    {
        pkOK++;
    }
    else
    {
        pkNG++;
    }

    // get sk
    ret = CRYPT_EAL_PkeyGetPrvEx(ctx, &prv);
    if (ret != CRYPT_SUCCESS)
    {
        printf("get sk failed.\n");
        goto EXIT;
    }

    // compare sk
    if (memcmp(skBin, prvdata, skBytes) == 0)
    {
        skOK++;
    }
    else
    {
        skNG++;
    }

    // get local ss
    ret = CRYPT_EAL_PkeyDecapsInit(ctx, NULL);
    if (ret != CRYPT_SUCCESS)
    {
        printf("decaps init failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyDecaps(ctx, ctBin, ctBytes, sharekey2, &sharekeyLen);
    if (ret != CRYPT_SUCCESS)
    {
        printf("decaps failed.\n");
        goto EXIT;
    }

    // compare ss
    if (memcmp(ssBin, sharekey2, MCELIECE_L_BYTES) == 0)
    {
        ssOK++;
    }
    else
    {
        ssNG++;
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(prvdata);
    BSL_SAL_FREE(pubdata);
}

PQC_Mceliece_AlgWithParamId ParseClassicMcElieceTestVector(const char *dataPath, int *semi)
{
    // get algID according the .rsp file name
    const char *name = strrchr(dataPath, '/');
    if (!name)
    {
        name = dataPath;
    }
    else
    {
        name++;
    }
    name += 2; // no need to read the prefix "[num]_"
    if (strncasecmp(name, "mceliece", 8) != 0)
    {
        return (PQC_Mceliece_AlgWithParamId)-1;
    }
    size_t len = strlen(name);
    if (len < 9 || strcasecmp(name + len - 4, ".rsp") != 0)
    {
        return (PQC_Mceliece_AlgWithParamId)-1;
    }

    char suffix[32];
    snprintf(suffix, sizeof(suffix), "%.*s", (int)(len - 8 - 4), name + 8);
    *semi = (suffix[len - 8 - 4 - 1] == 'f' || suffix[len - 8 - 4 - 1] == 'F') ? 1 : 0;

    PQC_Mceliece_AlgWithParamId algID = (PQC_Mceliece_AlgWithParamId)-1;
    for (size_t i = 0; i < sizeof(g_suffixAlgIDMap) / sizeof(g_suffixAlgIDMap[0]); i++)
    {
        if (strcasecmp(suffix, g_suffixAlgIDMap[i].suffix) == 0)
        {
            algID = g_suffixAlgIDMap[i].id;
            break;
        }
    }

    if ((int)algID == -1)
    {
        return algID;
    }

    int pkBytes, skBytes, ctBytes;
    ObtainMcElieceBytes(algID, &pkBytes, &skBytes, &ctBytes); // get pkBytes / skBytes / ctBytes according algID

    // open the .rsp file
    FILE *fp = fopen(dataPath, "r");
    if (!fp)
    {
        perror(dataPath);
        return (PQC_Mceliece_AlgWithParamId)-1;
    }

    char *line = BSL_SAL_Malloc(maxLineLen);
    if (!line)
    {
        fclose(fp);
        return (PQC_Mceliece_AlgWithParamId)-1;
    }

    int count = -1;
    AllocateHexBuffers(); // allocate pk_bin /sk_bin / ct_bin
    while (fgets(line, maxLineLen, fp))
    {
        if (line[0] == '\n')
        {
            continue;
        }
        if (strncmp(line, "count = ", 8) == 0)
        {
            sscanf(line, "count = %d", &count);
            continue;
        }
        if (strncmp(line, "seed = ", 7) == 0)
        {
            ExtractValue(line, seedHex, sizeof(seedHex));
            continue;
        }
        if (strncmp(line, "pk = ", 5) == 0)
        {
            ExtractValue(line, pkHex, maxLineLen);
            continue;
        }
        if (strncmp(line, "sk = ", 5) == 0)
        {
            ExtractValue(line, skHex, maxLineLen);
            continue;
        }
        if (strncmp(line, "ct = ", 5) == 0)
        {
            ExtractValue(line, ctHex, maxLineLen);
            continue;
        }
        if (strncmp(line, "ss = ", 5) == 0)
        {
            ExtractValue(line, ssHex, sizeof(ssHex));

            AllocateBinBuffers(pkBytes, skBytes, ctBytes); // allocate pk_bin /sk_bin / ct_bin
            ProcessCurrentKAT((int32_t)algID, semi, pkBytes, skBytes, ctBytes);
            FreeBinBuffers(); // free pk_bin /sk_bin / ct_bin
            continue;
        }
    }
    FreeHexBuffers(); // free pk_bin /sk_bin / ct_bin
    BSL_SAL_FREE(line);
    fclose(fp);

    return algID;
}

void TestClassicMcElieceKAT(const char *dataPath)
{
    int semi;
    PQC_Mceliece_AlgWithParamId algID = ParseClassicMcElieceTestVector(dataPath, &semi);
    // results
    printf("\n========= %s =========\n", dataPath);
    printf("total: %d\n", totalCount);
    printf("pk ok: %d   pk ng: %d   correct ratio: %.2f %%\n", pkOK, pkNG, totalCount ? 100.0 * pkOK / totalCount : 0);
    printf("sk ok: %d   sk ng: %d   correct ratio: %.2f %%\n", skOK, skNG, totalCount ? 100.0 * skOK / totalCount : 0);
    printf("ss ok: %d   ss ng: %d   correct ratio: %.2f %%\n", ssOK, ssNG, totalCount ? 100.0 * ssOK / totalCount : 0);
    printf("==========================\n");

    totalCount = 0;
    pkOK = 0;
    pkNG = 0;
    skOK = 0;
    skNG = 0;
    ssOK = 0;
    ssNG = 0;
}
