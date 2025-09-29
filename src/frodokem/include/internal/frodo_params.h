#ifndef FRODO_PARAMS_H
#define FRODO_PARAMS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define FRODOKEM_LEN_A 16
#define FRODOKEM_NBAR 8

#define PQC_ALG_ID_FRODOKEM_COUNT 12
typedef enum
{
    PQC_ALG_ID_FRODOKEM_FIRST,
    PQC_ALG_ID_FRODOKEM_640_SHAKE,
    PQC_ALG_ID_FRODOKEM_976_SHAKE,
    PQC_ALG_ID_FRODOKEM_1344_SHAKE,
    PQC_ALG_ID_FRODOKEM_640_AES,
    PQC_ALG_ID_FRODOKEM_976_AES,
    PQC_ALG_ID_FRODOKEM_1344_AES,

    PQC_ALG_ID_eFRODOKEM_640_SHAKE,
    PQC_ALG_ID_eFRODOKEM_976_SHAKE,
    PQC_ALG_ID_eFRODOKEM_1344_SHAKE,
    PQC_ALG_ID_eFRODOKEM_640_AES,
    PQC_ALG_ID_eFRODOKEM_976_AES,
    PQC_ALG_ID_eFRODOKEM_1344_AES,
    PQC_ALG_ID_FRODOKEM_LAST
} PQC_AlgWithParamId;

typedef enum
{
    FRODO_PRG_AES,
    FRODO_PRG_SHAKE
} FrodoKemPrgType;

typedef struct
{
    char name[30];
    uint16_t n;
    uint16_t nBar;
    uint8_t logq;
    uint8_t extractedBits;
    uint8_t d;

    uint16_t pkSize;
    uint16_t kemSkSize;
    uint16_t ctxSize;
    uint16_t ss;
    uint8_t lenSeedA;
    uint8_t lenSeedSE;
    uint8_t lenMu;
    uint8_t lenPkHash;
    uint8_t lenSalt;

    const uint16_t* cdfTable;
    uint8_t cdfLen;

    FrodoKemPrgType prg;
} FrodoKemParams;

FrodoKemParams* FrodoGetParamsById(PQC_AlgWithParamId alg_id);

#ifdef __cplusplus
}
#endif

#endif
