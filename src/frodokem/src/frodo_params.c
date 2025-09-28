#include "internal/frodo_params.h"
#include <stddef.h>

static const uint16_t CDF_TABLE_640[] = {
    4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767
};
static const uint16_t CDF_TABLE_976[] = {
    5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767
};
static const uint16_t CDF_TABLE_1344[] = {
    9142, 23462, 30338, 32361, 32725, 32765, 32767
};

static FrodoKemParams all_frodo_params[PQC_ALG_ID_FRODOKEM_COUNT] = {
    /* [PQC_ALG_ID_FRODOKEM_640_SHAKE] */
    {
        .name = "FrodoKEM-640-SHAKE",
        .n = 640, .nBar = 8, .logq = 15, .extractedBits = 2, .d = 12, .pkSize = 9616, .kemSkSize = 19888, .ctxSize = 9752,
        .ss = 16, .lenSeedA = 16, .lenSeedSE = 32, .lenSalt = 32, .lenMu = 16, .lenPkHash = 16,
        .cdfTable = CDF_TABLE_640, .cdfLen = 13, .prg = FRODO_PRG_SHAKE
    },
    /* [PQC_ALG_ID_FRODOKEM_976_SHAKE] */
    {
        .name = "FrodoKEM-976-SHAKE",
        .n = 976, .nBar = 8, .logq = 16, .extractedBits = 3, .d = 10, .pkSize = 15632, .kemSkSize = 31296,
        .ctxSize = 15792, .ss = 24, .lenSeedA = 16, .lenSeedSE = 48, .lenSalt = 48, .lenMu = 24,
        .lenPkHash = 24, .cdfTable = CDF_TABLE_976, .cdfLen = 11, .prg = FRODO_PRG_SHAKE
    },
    /* [PQC_ALG_ID_FRODOKEM_1344_SHAKE] */
    {
        .name = "FrodoKEM-1344-SHAKE",
        .n = 1344, .nBar = 8, .logq = 16, .extractedBits = 4, .d = 6, .pkSize = 21520, .kemSkSize = 43088,
        .ctxSize = 21696, .ss = 32, .lenSeedA = 16, .lenSeedSE = 64, .lenSalt = 64, .lenMu = 32,
        .lenPkHash = 32, .cdfTable = CDF_TABLE_1344, .cdfLen = 7, .prg = FRODO_PRG_SHAKE
    },
    /* [PQC_ALG_ID_FRODOKEM_640_AES] */
    {
        .name = "FrodoKEM-640-AES",
        .n = 640, .nBar = 8, .logq = 15, .extractedBits = 2, .d = 12, .pkSize = 9616, .kemSkSize = 19888, .ctxSize = 9752,
        .ss = 16, .lenSeedA = 16, .lenSeedSE = 32, .lenSalt = 32, .lenMu = 16, .lenPkHash = 16,
        .cdfTable = CDF_TABLE_640, .cdfLen = 13, .prg = FRODO_PRG_AES
    },
    /* [PQC_ALG_ID_FRODOKEM_976_AES] */
    {
        .name = "FrodoKEM-976-AES",
        .n = 976, .nBar = 8, .logq = 16, .extractedBits = 3, .d = 10, .pkSize = 15632, .kemSkSize = 31296,
        .ctxSize = 15792, .ss = 24, .lenSeedA = 16, .lenSeedSE = 48, .lenSalt = 48, .lenMu = 24,
        .lenPkHash = 24, .cdfTable = CDF_TABLE_976, .cdfLen = 11, .prg = FRODO_PRG_AES
    },
    /* [PQC_ALG_ID_FRODOKEM_1344_AES] */
    {
        .name = "FrodoKEM-1344-AES",
        .n = 1344, .nBar = 8, .logq = 16, .extractedBits = 4, .d = 6, .pkSize = 21520, .kemSkSize = 43088,
        .ctxSize = 21696, .ss = 32, .lenSeedA = 16, .lenSeedSE = 64, .lenSalt = 64, .lenMu = 32,
        .lenPkHash = 32, .cdfTable = CDF_TABLE_1344, .cdfLen = 7, .prg = FRODO_PRG_AES
    },
    /* [PQC_ALG_ID_eFRODOKEM_640_SHAKE] */
    {
        .name = "eFrodoKEM-640-SHAKE",
        .n = 640, .nBar = 8, .logq = 15, .extractedBits = 2, .d = 12, .pkSize = 9616, .kemSkSize = 19888, .ctxSize = 9720,
        .ss = 16, .lenSeedA = 16, .lenSeedSE = 16, .lenSalt = 0, .lenMu = 16, .lenPkHash = 16,
        .cdfTable = CDF_TABLE_640, .cdfLen = 13, .prg = FRODO_PRG_SHAKE
    },
    /* [PQC_ALG_ID_eFRODOKEM_976_SHAKE] */
    {
        .name = "eFrodoKEM-976-SHAKE",
        .n = 976, .nBar = 8, .logq = 16, .extractedBits = 3, .d = 10, .pkSize = 15632, .kemSkSize = 31296,
        .ctxSize = 15744, .ss = 24, .lenSeedA = 16, .lenSeedSE = 24, .lenSalt = 0, .lenMu = 24,
        .lenPkHash = 24, .cdfTable = CDF_TABLE_976, .cdfLen = 11, .prg = FRODO_PRG_SHAKE
    },
    /* [PQC_ALG_ID_eFRODOKEM_1344_SHAKE] */
    {
        .name = "eFrodoKEM-1344-SHAKE",
        .n = 1344, .nBar = 8, .logq = 16, .extractedBits = 4, .d = 6, .pkSize = 21520, .kemSkSize = 43088,
        .ctxSize = 21632, .ss = 32, .lenSeedA = 16, .lenSeedSE = 32, .lenSalt = 0, .lenMu = 32,
        .lenPkHash = 32, .cdfTable = CDF_TABLE_1344, .cdfLen = 7, .prg = FRODO_PRG_SHAKE
    },
    /* [PQC_ALG_ID_eFRODOKEM_640_AES] */
    {
        .name = "eFrodoKEM-640-AES",
        .n = 640, .nBar = 8, .logq = 15, .extractedBits = 2, .d = 12, .pkSize = 9616, .kemSkSize = 19888, .ctxSize = 9720,
        .ss = 16, .lenSeedA = 16, .lenSeedSE = 16, .lenSalt = 0, .lenMu = 16, .lenPkHash = 16,
        .cdfTable = CDF_TABLE_640, .cdfLen = 13, .prg = FRODO_PRG_AES
    },
    /* [PQC_ALG_ID_eFRODOKEM_976_AES] */
    {
        .name = "eFrodoKEM-976-AES",
        .n = 976, .nBar = 8, .logq = 16, .extractedBits = 3, .d = 10, .pkSize = 15632, .kemSkSize = 31296,
        .ctxSize = 15744, .ss = 24, .lenSeedA = 16, .lenSeedSE = 24, .lenSalt = 0, .lenMu = 24,
        .lenPkHash = 24, .cdfTable = CDF_TABLE_976, .cdfLen = 11, .prg = FRODO_PRG_AES
    },
    /* [PQC_ALG_ID_eFRODOKEM_1344_AES] */
    {
        .name = "eFrodoKEM-1344-AES",
        .n = 1344, .nBar = 8, .logq = 16, .extractedBits = 4, .d = 6, .pkSize = 21520, .kemSkSize = 43088,
        .ctxSize = 21632, .ss = 32, .lenSeedA = 16, .lenSeedSE = 32, .lenSalt = 0, .lenMu = 32,
        .lenPkHash = 32, .cdfTable = CDF_TABLE_1344, .cdfLen = 7, .prg = FRODO_PRG_AES
    },
};

FrodoKemParams* FrodoGetParamsById(const PQC_AlgWithParamId alg_id)
{
    if (alg_id > PQC_ALG_ID_FRODOKEM_FIRST && alg_id < PQC_ALG_ID_FRODOKEM_LAST) {
        return all_frodo_params + alg_id - 1;
    }
    return NULL;
}
