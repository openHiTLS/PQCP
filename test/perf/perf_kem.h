#include "pqcp_test.h"

extern uint32_t g_duration;
extern PerfResult g_perfRes;

#define PRINT_ERR_IF_FAIL(failPrefix, func, retVal)       \
    do                                                    \
    {                                                     \
        (retVal) = (func);                                \
        if ((retVal) != 0)                                \
        {                                                 \
            printf("%s: 0x%x\n", (failPrefix), (retVal)); \
            goto EXIT;                                    \
        }                                                 \
    } while (0)

#define RECORD_AND_PRINT_RES(algName, operationName)         \
    g_perfRes.algorithm = algName;                           \
    g_perfRes.operation = operationName;                     \
    g_perfRes.avgTimeMs = totalTime / count;                 \
    g_perfRes.opsPerSec = count / (actualDuration / 1000.0); \
    g_perfRes.iterations = count;                            \
    g_perfRes.maxTimeMs = maxTime;                           \
    g_perfRes.minTimeMs = minTime;                           \
    g_perfRes.totalTimeMs = actualDuration;                  \
    PrintResult(&g_perfRes, 0);

#define RUN_BENCHMARK(algName, operationName, func, duration, retVal) \
    do                                                                \
    {                                                                 \
        double start = GetTimeMs();                                   \
        double end = start + duration * 1000;                         \
        double maxTime = 0;                                           \
        double minTime = 1e9;                                         \
        double totalTime = 0;                                         \
        uint32_t count = 0;                                           \
        while (GetTimeMs() < end)                                     \
        {                                                             \
            double opStart = GetTimeMs();                             \
            if (func != retVal)                                       \
            {                                                         \
                goto EXIT;                                            \
            }                                                         \
            double opEnd = GetTimeMs();                               \
            double elapsed = opEnd - opStart;                         \
            totalTime += elapsed;                                     \
            maxTime = elapsed > maxTime ? elapsed : maxTime;          \
            minTime = elapsed < minTime ? elapsed : minTime;          \
            count++;                                                  \
        }                                                             \
        double actualDuration = GetTimeMs() - start;                  \
        RECORD_AND_PRINT_RES(algName, operationName)                  \
    } while (0)

int32_t PQCP_BENCHMARK_KEM_KeyGen(char* algName, int32_t algId, int32_t setParaCmd, int32_t algParaId, uint32_t duration);

int32_t PQCP_BENCHMARK_KEM_Encaps(char* algName, int32_t algId, int32_t setParaCmd,  int32_t algParaId, int32_t getCipherLenCmd, uint32_t duration);

int32_t PQCP_BENCHMARK_KEM_Decaps(char* algName, int32_t algId, int32_t setParaCmd,  int32_t algParaId, int32_t getCipherLenCmd, uint32_t duration);