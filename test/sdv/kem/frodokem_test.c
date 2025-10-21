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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "pqcp_types.h"
#include "pqcp_provider.h"
#include "frodokem.h"
#include "frodo_local.h"
#include "crypt_eal_cipher.h"

#define MAX_LINE_LEN 90000

int ParseHexFromFile(FILE* infile, unsigned char* A, int length, char* buffer);

void RandombytesInit(unsigned char *entropy_input,
                     unsigned char *personalization_string,
                     int security_strength);
void RandomBytesRelease();

int GenTestRandombytes(uint8_t *x, uint32_t xlen);

static inline int BytesEq(const uint8_t* a, const uint8_t* b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

// Read decimal numbers from "count = " (until the end of the line/non-numeric character)
static int read_count_value(FILE* fp)
{
    int c, val = 0, seen = 0;
    while ((c = fgetc(fp)) != EOF && c != '\n') {
        if (c >= '0' && c <= '9') {
            val = val * 10 + (c - '0');
            seen = 1;
        }
    }
    return seen ? val : -1;
}

static void PrintHex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

void TestFrodoKemEncapsDecaps(const PQC_AlgWithParamId id, char* kat_path)
{
    FILE* fp = fopen(kat_path, "rb");
    if (!fp) {
        fprintf(stderr,
                "ERROR: Could not open KAT file '%s'.\n",
                kat_path);
        return;
    }

    const FrodoKemParams* params = FrodoGetParamsById(id);
    if (params == NULL) {
        return;
    }

    printf("Testing [%s] with [%s]\n", params->name, kat_path);

    // The seed length for AES-256 DRGB is fixed to 48 bytes.
    // It does not equal to params->ss + params->lenSeedSE + params->lenSeedA.
    const int lenSeed = 48;
    // alloca memory
    uint8_t* seed = malloc(lenSeed);
    uint8_t* pk_ref = malloc(params->pkSize);
    uint8_t* sk_ref = malloc(params->kemSkSize);
    uint8_t* ct_ref = malloc(params->ctxSize);
    uint8_t* ss_ref = malloc(params->ss);

    uint8_t* pk = malloc(params->pkSize);
    uint8_t* sk = malloc(params->kemSkSize);
    uint8_t* ct = malloc(params->ctxSize);
    uint8_t* ss = malloc(params->ss);
    uint8_t* ss2 = malloc(params->ss);

    char *buffer = malloc(MAX_LINE_LEN);

    int total = 0, pass = 0, fail = 0;

    BSL_Param pub[2] = {
        {CRYPT_PARAM_FRODOKEM_PUBKEY, BSL_PARAM_TYPE_OCTETS, pk, params->pkSize, 0},
        BSL_PARAM_END
    };

    BSL_Param pri[2] = {
        {CRYPT_PARAM_FRODOKEM_PRVKEY, BSL_PARAM_TYPE_OCTETS, sk, params->kemSkSize, 0},
        BSL_PARAM_END
    };

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_FRODOKEM, CRYPT_EAL_PKEY_KEM_OPERATE,
                    "provider=pqcp");
    if (ctx == NULL) {
        printf("create ctx failed.\n");
        goto EXIT;
    }

    int32_t val = id;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, PQCP_FRODOKEM_SET_PARAMS_BY_ID, &val, sizeof(val));
    if (ret != CRYPT_SUCCESS) {
        printf("ctrl param failed.\n");
        goto EXIT;
    }

    // skip the first line
    fgets(buffer, MAX_LINE_LEN, fp);

    for (;;) {
        // skip 2 lines
        if (fgets(buffer, MAX_LINE_LEN, fp) == NULL) {
            break;
        }
        if (fgets(buffer, MAX_LINE_LEN, fp) == NULL) {
            break;
        }

        // Read seed pk sk ct ss
        if (!ParseHexFromFile(fp, seed, lenSeed, buffer)) {
            fprintf(stderr, "Parse seed @count=%d\n", total);
            break;
        }
        if (!ParseHexFromFile(fp, pk_ref, params->pkSize, buffer)) {
            fprintf(stderr, "Parse pk   @count=%d\n", total);
            break;
        }
        if (!ParseHexFromFile(fp, sk_ref, params->kemSkSize, buffer)) {
            fprintf(stderr, "Parse sk   @count=%d\n", total);
            break;
        }
        if (!ParseHexFromFile(fp, ct_ref, params->ctxSize, buffer)) {
            fprintf(stderr, "Parse ct   @count=%d\n", total);
            break;
        }
        if (!ParseHexFromFile(fp, ss_ref, params->ss, buffer)) {
            fprintf(stderr, "Parse ss   @count=%d\n", total);
            break;
        }

        // Fix the RNG (to ensure generated results are consistent with KAT)
        RandombytesInit(seed, NULL, 256);

        CRYPT_EAL_SetRandCallBack(GenTestRandombytes);
        // Run KEM
        int ok_pk = 0, ok_sk = 0, ok_ct = 0, ok_ss = 0, ok_dec = 0;

        ret = CRYPT_EAL_PkeyGen(ctx);
        if (ret != CRYPT_SUCCESS) {
            printf("gen key failed.\n");
            goto EXIT;
        }

        ret = CRYPT_EAL_PkeyGetPubEx(ctx, &pub);
        if (ret != CRYPT_SUCCESS) {
            printf("get encaps key failed.\n");
            goto EXIT;
        }

        ret = CRYPT_EAL_PkeyGetPrvEx(ctx, &pri);
        if (ret != CRYPT_SUCCESS) {
            printf("get decaps key failed.\n");
            goto EXIT;
        }

        ok_pk = BytesEq(pk_ref, pk, params->pkSize);
        ok_sk = BytesEq(sk_ref, sk, params->kemSkSize);

        ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
        if (ret != CRYPT_SUCCESS) {
            printf("encaps init failed.\n");
            goto EXIT;
        }
        int32_t cipherLen = params->ctxSize;
        int32_t shareKeyLen = params->ss;
        ret = CRYPT_EAL_PkeyEncaps(ctx, ct, &cipherLen, ss, &shareKeyLen);
        if (ret != CRYPT_SUCCESS) {
            printf("encaps failed.\n");
            goto EXIT;
        }

        ok_ct = BytesEq(ct_ref, ct, params->ctxSize);
        ok_ss = BytesEq(ss_ref, ss, params->ss);

        ret = CRYPT_EAL_PkeyDecapsInit(ctx, NULL);
        if (ret != CRYPT_SUCCESS) {
            printf("decaps init failed.\n");
            goto EXIT;
        }
        ret = CRYPT_EAL_PkeyDecaps(ctx, ct, cipherLen, ss2, &shareKeyLen);
        if (ret != CRYPT_SUCCESS) {
            printf("decaps failed.\n");
            goto EXIT;
        }

        ok_dec = BytesEq(ss_ref, ss2, params->ss);

        const int ok_all = ok_pk & ok_sk & ok_ct & ok_ss & ok_dec;

        // === Output Compare ===

        /*
        printf("count=%-4d  pk:%s  sk:%s  ct:%s  ss:%s  dec:%s\n",
        count,
        ok_pk ? "OK" : "FAIL",
        ok_sk ? "OK" : "FAIL",
        ok_ct ? "OK" : "FAIL",
        ok_ss ? "OK" : "FAIL",
        ok_dec ? "OK" : "FAIL");
        */

        total++;

        if (ok_all) pass++;
        else fail++;
        RandomBytesRelease();
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);

    free(buffer);
    free(seed);
    free(pk_ref);
    free(sk_ref);
    free(ct_ref);
    free(ss_ref);

    free(pk);
    free(sk);
    free(ct);
    free(ss);
    free(ss2);
    RandomBytesRelease();
    fclose(fp);
    printf("%s KAT: total=%d  pass=%d  fail=%d\n", params->name, total, pass, fail);
    if (total != pass) {
        fprintf(stderr, "ERROR: %s test failed!!!\n", params->name);
    }
    printf("\n");
}

int GetNumberFromHex(const char a)
{
    if (a >= '0' && a <= '9') {
        return a - '0';
    }
    if (a >= 'A' && a <= 'F') {
        return a - 'A' + 10;
    }
    perror("GetNumberFromHex error");
    return -1;
}

int ParseHexFromFile(FILE* infile, unsigned char* A, int length, char* buffer)
{
    if (length == 0) {
        return 1;
    }

    if (fgets(buffer, MAX_LINE_LEN, infile) == NULL) {
        return 0;
    }
    size_t len = strlen(buffer);
    if (len < 10) {
        return 0;
    }

    const char* ptr;
    if (buffer[6] == ' ') {
        // "seed = "
        ptr = buffer + 7;
        len -= 7;
    } else if (buffer[4] == ' ') {
        // "xx = "
        ptr = buffer + 5;
        len -= 5;
    } else {
        return 0;
    }

    if (len < length * 2) {
        return 0;
    }

    for (int i = 0; i < length; i++) {
        const int a = GetNumberFromHex(ptr[2 * i + 0]);
        const int b = GetNumberFromHex(ptr[2 * i + 1]);
        A[i] = (a << 4) | b;
    }

    return 1;
}

#define RNG_SUCCESS       0
#define RNG_BAD_MAXLEN   -1
#define RNG_BAD_OUTBUF   -2
#define RNG_BAD_REQ_LEN  -3

typedef struct {
    unsigned char   buffer[16];
    int             buffer_pos;
    unsigned long   length_remaining;
    unsigned char   key[32];
    unsigned char   ctr[16];
} AES_XOF_struct;

typedef struct {
    unsigned char   Key[32];
    unsigned char   V[16];
    int             reseed_counter;
} AES256_CTR_DRBG_struct;

static AES256_CTR_DRBG_struct DRBG_ctx;

static uint8_t g_rk256[240];
static int g_rk256_ready = 0;
CRYPT_EAL_CipherCtx *g_RandCtx = NULL;

static inline void drbg_set_aes256_key(const uint8_t key[32]) {
    if (g_RandCtx != NULL) {
        CRYPT_EAL_CipherFreeCtx(g_RandCtx);
    }
    g_RandCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES256_ECB);
    if (g_RandCtx == NULL) {
        fprintf(stderr, "ERROR! CRYPT_EAL_CipherNewCtx failed!\n");
        exit(1);
    } else {
        if (CRYPT_EAL_CipherInit(g_RandCtx, key, 32, NULL, 0, true) != 0) {
            fprintf(stderr, "ERROR! CRYPT_EAL_CipherInit failed!\n");
            CRYPT_EAL_CipherFreeCtx(g_RandCtx);
        }
        if (CRYPT_EAL_CipherSetPadding(g_RandCtx, CRYPT_PADDING_NONE) != 0) {
            fprintf(stderr, "ERROR! CRYPT_EAL_CipherSetPadding failed!\n");
            CRYPT_EAL_CipherFreeCtx(g_RandCtx);
        }
        g_rk256_ready = 1;
    }
}

static inline void drbg_aes256_block(const uint8_t in[16], uint8_t out[16]) {
    int outlen = 16;
    int32_t ret = CRYPT_EAL_CipherUpdate(g_RandCtx, in, 16, out, &outlen);
    if (ret != 0) {
        fprintf(stderr, "ERROR! CRYPT_EAL_CipherUpdate failed! : %d\n", ret);
        exit(1);
    }
}

static inline void ctr_inc_be(uint8_t V[16]) {
    for (int j = 15; j >= 0; --j) {
        if (V[j] == 0xFF) V[j] = 0x00;
        else { V[j]++; break; }
    }
}

void AES256_CTR_DRBG_Update(unsigned char *provided_data,
                            unsigned char *Key,
                            unsigned char *V)
{
    uint8_t temp[48];
    uint8_t block[16];

    for (int i = 0; i < 3; i++) {
        ctr_inc_be(V);
        drbg_aes256_block(V, block);
        memcpy(&temp[16 * i], block, 16);
    }

    if (provided_data != NULL) {
        for (int i = 0; i < 48; i++) temp[i] ^= provided_data[i];
    }

    memcpy(Key, temp,      32);
    memcpy(V,   temp + 32, 16);

    drbg_set_aes256_key(Key);
}

void RandombytesInit(unsigned char *entropy_input,
                     unsigned char *personalization_string,
                     int security_strength)
{
    (void)security_strength;
    uint8_t seed_material[48];

    memcpy(seed_material, entropy_input, 48);
    if (personalization_string) {
        for (int i = 0; i < 48; i++) {
            seed_material[i] ^= personalization_string[i];
        }
    }
    memset(DRBG_ctx.Key, 0x00, 32);
    memset(DRBG_ctx.V,   0x00, 16);

    drbg_set_aes256_key(DRBG_ctx.Key);

    AES256_CTR_DRBG_Update(seed_material, DRBG_ctx.Key, DRBG_ctx.V);
    DRBG_ctx.reseed_counter = 1;
}

void RandomBytesRelease() {
    CRYPT_EAL_CipherFreeCtx(g_RandCtx);
    g_RandCtx = NULL;
}

int GenTestRandombytes(uint8_t *x, uint32_t xlen)
{
    uint8_t block[16];
    unsigned long long produced = 0;

    if (!g_rk256_ready) {
        memset(DRBG_ctx.Key, 0, 32);
        drbg_set_aes256_key(DRBG_ctx.Key);
    }

    while (xlen > 0) {
        ctr_inc_be(DRBG_ctx.V);
        drbg_aes256_block(DRBG_ctx.V, block);

        size_t take = (xlen >= 16) ? 16u : (size_t)xlen;
        memcpy(x + produced, block, take);
        produced += take;
        xlen     -= take;
    }

    AES256_CTR_DRBG_Update(NULL, DRBG_ctx.Key, DRBG_ctx.V);
    DRBG_ctx.reseed_counter++;

    return RNG_SUCCESS;
}