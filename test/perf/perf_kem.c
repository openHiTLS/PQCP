#include "crypt_eal_pkey.h"
#include "pqcp_types.h"
#include "pqcp_test.h"
#include "pqcp_provider.h"
#include "pqcp_err.h"
#include "crypt_errno.h" 
#include "perf_kem.h"



int32_t PQCP_BENCHMARK_KEM_KeyGen(char* algName, int32_t algId, int32_t setParaCmd, int32_t algParaId, uint32_t duration)
{
    int ret = 0;
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, algId, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    if (ctx == NULL) {
        return -1;
    }
    PRINT_ERR_IF_FAIL("Set Para Failed", CRYPT_EAL_PkeyCtrl(ctx, setParaCmd, &algParaId, sizeof(int32_t)), ret);
    RUN_BENCHMARK(algName, "KeyGen", CRYPT_EAL_PkeyGen(ctx), g_duration, 0);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return ret;
}

int32_t PQCP_BENCHMARK_KEM_Encaps(char* algName, int32_t algId, int32_t setParaCmd,  int32_t algParaId, int32_t getCipherLenCmd, uint32_t duration)
{
    int ret = 0;
    uint8_t *cipher = NULL;
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, algId, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    if (ctx == NULL) {
        return -1;
    }
    PRINT_ERR_IF_FAIL("Set Para Failed", CRYPT_EAL_PkeyCtrl(ctx, setParaCmd, &algParaId, sizeof(int32_t)), ret);
    PRINT_ERR_IF_FAIL("PkeyGen Failed", CRYPT_EAL_PkeyGen(ctx), ret);
    uint8_t sharedKey[32];
    uint32_t sharedKeyLen = 32;
    uint32_t cipherLen = 0;
    PRINT_ERR_IF_FAIL("PkeyGen Failed", CRYPT_EAL_PkeyCtrl(ctx, getCipherLenCmd, &cipherLen, sizeof(uint32_t)), ret);
    cipher = malloc(cipherLen);
    PRINT_ERR_IF_FAIL("Encaps init Failed", CRYPT_EAL_PkeyEncapsInit(ctx, NULL), ret);
    RUN_BENCHMARK(algName, "Encaps", CRYPT_EAL_PkeyEncaps(ctx, cipher, &cipherLen, sharedKey, &sharedKeyLen), g_duration, 0);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (cipher != NULL) {
        free(cipher);
        cipher = NULL;
    }
    return ret;
}

int32_t PQCP_BENCHMARK_KEM_Decaps(char* algName, int32_t algId, int32_t setParaCmd,  int32_t algParaId, int32_t getCipherLenCmd, uint32_t duration)
{
    int ret = 0;
    uint8_t* cipher = NULL;
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, algId, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    if (ctx == NULL) {
        return -1;
    }
    PRINT_ERR_IF_FAIL("Set Para Failed", CRYPT_EAL_PkeyCtrl(ctx, setParaCmd, &algParaId, sizeof(int32_t)), ret);
    PRINT_ERR_IF_FAIL("PkeyGen Failed", CRYPT_EAL_PkeyGen(ctx), ret);
    uint8_t sharedKey[32];
    uint32_t sharedKeyLen = 32;
    uint32_t cipherLen = 0;
    PRINT_ERR_IF_FAIL("PkeyGen Failed", CRYPT_EAL_PkeyCtrl(ctx, getCipherLenCmd, &cipherLen, sizeof(uint32_t)), ret);
    cipher = malloc(cipherLen);
    PRINT_ERR_IF_FAIL("Encaps Init Failed", CRYPT_EAL_PkeyEncapsInit(ctx, NULL), ret);
    PRINT_ERR_IF_FAIL("Encaps Failed", CRYPT_EAL_PkeyEncaps(ctx, cipher, &cipherLen, sharedKey, &sharedKeyLen), ret);
    PRINT_ERR_IF_FAIL("Decaps Init Failed", CRYPT_EAL_PkeyDecapsInit(ctx, NULL), ret);
    RUN_BENCHMARK(algName, "Decaps", CRYPT_EAL_PkeyDecaps(ctx, cipher, cipherLen, sharedKey, &sharedKeyLen), g_duration, 0);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    if (cipher != NULL) {
        free(cipher);
        cipher = NULL;
    }
    return ret;
}