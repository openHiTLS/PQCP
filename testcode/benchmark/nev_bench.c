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

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "bsl_sal.h"
#include "crypt_eal_init.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_provider.h"
#include "crypt_errno.h"
#include "pqcp_provider.h"
#include "pqcp_types.h"

#ifndef PQCP_BENCH_PROVIDER_PATH
#define PQCP_BENCH_PROVIDER_PATH "."
#endif

#define NEV_BENCH_DEFAULT_TIMES 1000U
#define NEV_BENCH_ALL_OPS       0x7U
#define NEV_BENCH_KEYGEN        0x1U
#define NEV_BENCH_ENCAPS        0x2U
#define NEV_BENCH_DECAPS        0x4U

typedef struct {
    const char *name;
    int32_t id;
} NevParameter;

typedef struct {
    const char *algorithm;
    const char *parameter;
    const char *providerPath;
    uint32_t times;
    uint32_t seconds;
} NevBenchOptions;

typedef struct {
    CRYPT_EAL_PkeyCtx *ctx;
    uint8_t *ciphertext;
    uint8_t *sharedSecret;
    uint8_t *decapsulatedSecret;
    uint32_t ciphertextLen;
    uint32_t sharedSecretLen;
} NevBenchState;

typedef int32_t (*NevBenchOperation)(NevBenchState *state);

static const NevParameter g_nevParameters[] = {
    {"nev-512-769-c", PQCP_NEV_512_769_C},   {"nev-1024-769-c", PQCP_NEV_1024_769_C},
    {"nev-2048-769-c", PQCP_NEV_2048_769_C}, {"nev-512-1409", PQCP_NEV_512_1409},
    {"nev-1024-1409", PQCP_NEV_1024_1409},   {"nev-2048-1409", PQCP_NEV_2048_1409},
    {"nev-512-3329", PQCP_NEV_512_3329},     {"nev-1024-3329", PQCP_NEV_1024_3329},
    {"nev-2048-3329", PQCP_NEV_2048_3329},   {"nev-512-769", PQCP_NEV_512_769},
    {"nev-1024-769", PQCP_NEV_1024_769},     {"nev-2048-769", PQCP_NEV_2048_769},
};

static void PrintUsage(const char *program)
{
    (void)printf("Usage: %s [options]\n", program);
    (void)printf("Options:\n");
    (void)printf("  -a <algorithm>      Operation filter: nev*, nev-KeyGen, nev-Encaps or nev-Decaps\n");
    (void)printf("  -t <times>          Number of times to run each benchmark (default: %u)\n",
                 NEV_BENCH_DEFAULT_TIMES);
    (void)printf("  -s <seconds>        Run each benchmark for this many seconds (overrides -t)\n");
    (void)printf("  -p <parameter>      NEV parameter name; omit to benchmark all parameter sets\n");
    (void)printf("  -m <provider path>  Directory containing libpqcp_provider.so\n");
    (void)printf("  -h                  Show this help message\n");
}

static int ParseUint32(const char *text, uint32_t *value)
{
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed == 0 || parsed > UINT32_MAX) {
        return -1;
    }
    *value = (uint32_t)parsed;
    return 0;
}

static int ParseOptions(int argc, char **argv, NevBenchOptions *options)
{
    int option;
    while ((option = getopt(argc, argv, "a:t:s:p:m:h")) != -1) {
        switch (option) {
            case 'a':
                options->algorithm = optarg;
                break;
            case 't':
                if (ParseUint32(optarg, &options->times) != 0) {
                    (void)fprintf(stderr, "Invalid run count: %s\n", optarg);
                    return -1;
                }
                break;
            case 's':
                if (ParseUint32(optarg, &options->seconds) != 0) {
                    (void)fprintf(stderr, "Invalid duration: %s\n", optarg);
                    return -1;
                }
                break;
            case 'p':
                options->parameter = optarg;
                break;
            case 'm':
                options->providerPath = optarg;
                break;
            case 'h':
                PrintUsage(argv[0]);
                exit(EXIT_SUCCESS);
            default:
                return -1;
        }
    }
    if (optind != argc) {
        (void)fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        return -1;
    }
    return 0;
}

static int ResolveOperations(const char *algorithm, uint32_t *operations)
{
    if (algorithm == NULL || strcasecmp(algorithm, "nev") == 0 || strcasecmp(algorithm, "nev*") == 0 ||
        strcmp(algorithm, "*") == 0) {
        *operations = NEV_BENCH_ALL_OPS;
        return 0;
    }

    const char *operation = strchr(algorithm, '-');
    if (operation == NULL || (strncasecmp(algorithm, "nev-", 4) != 0 && strncmp(algorithm, "*-", 2) != 0)) {
        return -1;
    }
    operation++;
    if (strcasecmp(operation, "keygen") == 0) {
        *operations = NEV_BENCH_KEYGEN;
    } else if (strcasecmp(operation, "encaps") == 0) {
        *operations = NEV_BENCH_ENCAPS;
    } else if (strcasecmp(operation, "decaps") == 0) {
        *operations = NEV_BENCH_DECAPS;
    } else {
        return -1;
    }
    return 0;
}

static const NevParameter *FindParameter(const char *name)
{
    if (name == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < sizeof(g_nevParameters) / sizeof(g_nevParameters[0]); i++) {
        if (strcasecmp(name, g_nevParameters[i].name) == 0) {
            return &g_nevParameters[i];
        }
    }
    return NULL;
}

static uint64_t BenchNowNs(void)
{
    struct timespec now = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static CRYPT_EAL_PkeyCtx *NevNewCtx(int32_t parameterId)
{
    CRYPT_EAL_PkeyCtx *ctx =
        CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_NEV, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    if (ctx == NULL) {
        return NULL;
    }
    if (CRYPT_EAL_PkeySetParaById(ctx, (CRYPT_PKEY_ParaId)parameterId) != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return NULL;
    }
    return ctx;
}

static int32_t NevEncapsOnce(NevBenchState *state)
{
    uint32_t ciphertextLen = state->ciphertextLen;
    uint32_t sharedSecretLen = state->sharedSecretLen;
    return CRYPT_EAL_PkeyEncaps(state->ctx, state->ciphertext, &ciphertextLen, state->sharedSecret, &sharedSecretLen);
}

static int32_t NevDecapsOnce(NevBenchState *state)
{
    uint32_t sharedSecretLen = state->sharedSecretLen;
    return CRYPT_EAL_PkeyDecaps(state->ctx, state->ciphertext, state->ciphertextLen, state->decapsulatedSecret,
                                &sharedSecretLen);
}

static int32_t NevBenchStateInit(NevBenchState *state, int32_t parameterId)
{
    int32_t ret;
    (void)memset(state, 0, sizeof(*state));
    state->ctx = NevNewCtx(parameterId);
    if (state->ctx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_EAL_PkeyGen(state->ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_EAL_PkeyCtrl(state->ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &state->ciphertextLen,
                             sizeof(state->ciphertextLen));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_EAL_PkeyCtrl(state->ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &state->sharedSecretLen,
                             sizeof(state->sharedSecretLen));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    state->ciphertext = malloc(state->ciphertextLen);
    state->sharedSecret = malloc(state->sharedSecretLen);
    state->decapsulatedSecret = malloc(state->sharedSecretLen);
    if (state->ciphertext == NULL || state->sharedSecret == NULL || state->decapsulatedSecret == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_EAL_PkeyEncapsInit(state->ctx, NULL);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_EAL_PkeyDecapsInit(state->ctx, NULL);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = NevEncapsOnce(state);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = NevDecapsOnce(state);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (memcmp(state->sharedSecret, state->decapsulatedSecret, state->sharedSecretLen) != 0) {
        return CRYPT_INVALID_ARG;
    }
    return CRYPT_SUCCESS;
}

static void NevBenchStateFree(NevBenchState *state)
{
    if (state == NULL) {
        return;
    }
    CRYPT_EAL_PkeyFreeCtx(state->ctx);
    free(state->ciphertext);
    free(state->sharedSecret);
    free(state->decapsulatedSecret);
    (void)memset(state, 0, sizeof(*state));
}

static void PrintResult(const char *header, int32_t length, uint64_t count, uint64_t elapsed)
{
    double operationsPerSecond = elapsed == 0 ? 0.0 : (double)count * 1000000000.0 / (double)elapsed;
    (void)printf("%-35s, %10d, %15" PRIu64 ", %16.2f, %20.2f\n", header, length, count, (double)elapsed / 1000000.0,
                 operationsPerSecond);
}

static int32_t RunKeyGen(const NevParameter *parameter, const NevBenchOptions *options)
{
    uint64_t count = 0;
    uint64_t elapsed = 0;
    uint64_t duration = (uint64_t)options->seconds * 1000000000ULL;
    int32_t ret = CRYPT_SUCCESS;

    while ((options->seconds != 0 && elapsed < duration) || (options->seconds == 0 && count < options->times)) {
        CRYPT_EAL_PkeyCtx *ctx = NevNewCtx(parameter->id);
        if (ctx == NULL) {
            ret = CRYPT_MEM_ALLOC_FAIL;
            break;
        }
        uint64_t start = BenchNowNs();
        ret = CRYPT_EAL_PkeyGen(ctx);
        uint64_t end = BenchNowNs();
        CRYPT_EAL_PkeyFreeCtx(ctx);
        if (start == 0 || end == 0 || end < start) {
            ret = CRYPT_INVALID_ARG;
            break;
        }
        elapsed += end - start;
        if (ret != CRYPT_SUCCESS) {
            break;
        }
        count++;
    }

    char header[128];
    (void)snprintf(header, sizeof(header), "%s keyGen", parameter->name);
    PrintResult(header, -1, count, elapsed);
    if (ret != CRYPT_SUCCESS) {
        (void)fprintf(stderr, "Benchmark operation failed: %s, ret = 0x%08x\n", header, (uint32_t)ret);
    }
    return ret;
}

static int32_t RunOperation(const char *header, int32_t length, NevBenchOperation operation, NevBenchState *state,
                            const NevBenchOptions *options)
{
    uint64_t count = 0;
    int32_t ret = CRYPT_SUCCESS;
    uint64_t start = BenchNowNs();
    if (start == 0) {
        return CRYPT_INVALID_ARG;
    }

    if (options->seconds != 0) {
        uint64_t duration = (uint64_t)options->seconds * 1000000000ULL;
        do {
            ret = operation(state);
            if (ret != CRYPT_SUCCESS) {
                break;
            }
            count++;
        } while (BenchNowNs() - start < duration);
    } else {
        for (uint32_t i = 0; i < options->times; i++) {
            ret = operation(state);
            if (ret != CRYPT_SUCCESS) {
                break;
            }
            count++;
        }
    }

    uint64_t elapsed = BenchNowNs() - start;
    PrintResult(header, length, count, elapsed);
    if (ret != CRYPT_SUCCESS) {
        (void)fprintf(stderr, "Benchmark operation failed: %s, ret = 0x%08x\n", header, (uint32_t)ret);
    }
    return ret;
}

static int RunParameter(const NevParameter *parameter, uint32_t operations, const NevBenchOptions *options)
{
    int result = 0;
    NevBenchState state = {0};
    char header[128];

    if ((operations & NEV_BENCH_KEYGEN) != 0) {
        if (RunKeyGen(parameter, options) != CRYPT_SUCCESS) {
            result = -1;
        }
    }

    if ((operations & (NEV_BENCH_ENCAPS | NEV_BENCH_DECAPS)) != 0) {
        int32_t ret = NevBenchStateInit(&state, parameter->id);
        if (ret != CRYPT_SUCCESS) {
            (void)fprintf(stderr, "Failed to set up %s benchmark: 0x%08x\n", parameter->name, (uint32_t)ret);
            NevBenchStateFree(&state);
            return -1;
        }
        if ((operations & NEV_BENCH_ENCAPS) != 0) {
            (void)snprintf(header, sizeof(header), "%s encaps", parameter->name);
            if (RunOperation(header, (int32_t)state.ciphertextLen, NevEncapsOnce, &state, options) != CRYPT_SUCCESS) {
                result = -1;
            }
        }
        if ((operations & NEV_BENCH_DECAPS) != 0) {
            (void)snprintf(header, sizeof(header), "%s decaps", parameter->name);
            if (RunOperation(header, (int32_t)state.ciphertextLen, NevDecapsOnce, &state, options) != CRYPT_SUCCESS) {
                result = -1;
            }
        }
    }
    NevBenchStateFree(&state);
    return result;
}

int main(int argc, char **argv)
{
    int result = EXIT_FAILURE;
    int32_t ret;
    uint32_t operations = 0;
    int providerLoaded = 0;
    int ealInitialized = 0;
    NevBenchOptions options = {
        .algorithm = "nev*",
        .providerPath = PQCP_BENCH_PROVIDER_PATH,
        .times = NEV_BENCH_DEFAULT_TIMES,
    };

    if (ParseOptions(argc, argv, &options) != 0) {
        PrintUsage(argv[0]);
        return EXIT_FAILURE;
    }
    if (ResolveOperations(options.algorithm, &operations) != 0) {
        (void)fprintf(stderr, "No benchmark matched algorithm pattern: %s\n", options.algorithm);
        return EXIT_FAILURE;
    }
    const NevParameter *selectedParameter = FindParameter(options.parameter);
    if (options.parameter != NULL && selectedParameter == NULL) {
        (void)fprintf(stderr, "Unknown NEV parameter: %s\n", options.parameter);
        return EXIT_FAILURE;
    }

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        (void)fprintf(stderr, "Failed to initialize openHiTLS: 0x%08x\n", (uint32_t)ret);
        goto EXIT;
    }
    ealInitialized = 1;
    ret = CRYPT_EAL_ProviderSetLoadPath(NULL, options.providerPath);
    if (ret != CRYPT_SUCCESS) {
        (void)fprintf(stderr, "Failed to set provider path '%s': 0x%08x\n", options.providerPath, (uint32_t)ret);
        goto EXIT;
    }
    ret = CRYPT_EAL_ProviderLoad(NULL, BSL_SAL_LIB_FMT_LIBSO, "pqcp_provider", NULL, NULL);
    if (ret != CRYPT_SUCCESS) {
        (void)fprintf(stderr, "Failed to load PQCP provider from '%s': 0x%08x\n", options.providerPath, (uint32_t)ret);
        goto EXIT;
    }
    providerLoaded = 1;

    (void)printf("%-35s, %10s, %15s, %16s, %20s\n", "algorithm operation", "len", "run times", "time elapsed(ms)",
                 "ops/s");
    result = EXIT_SUCCESS;
    if (selectedParameter != NULL) {
        if (RunParameter(selectedParameter, operations, &options) != 0) {
            result = EXIT_FAILURE;
        }
    } else {
        for (size_t i = 0; i < sizeof(g_nevParameters) / sizeof(g_nevParameters[0]); i++) {
            if (RunParameter(&g_nevParameters[i], operations, &options) != 0) {
                result = EXIT_FAILURE;
            }
        }
    }

EXIT:
    if (providerLoaded != 0) {
        (void)CRYPT_EAL_ProviderUnload(NULL, BSL_SAL_LIB_FMT_LIBSO, "pqcp_provider");
    }
    if (ealInitialized != 0) {
        CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    }
    return result;
}
