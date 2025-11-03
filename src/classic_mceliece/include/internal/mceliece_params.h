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

#ifndef MCELIECE_PARAMS_H
#define MCELIECE_PARAMS_H
#ifdef __cplusplus
extern "C" {
#endif

#include "bsl_sal.h"
#include <stdint.h>

#define PQC_ALG_ID_MCELIECE_COUNT 12

typedef enum
{
    PQC_ALG_ID_MCELIECE_6688128,
    PQC_ALG_ID_MCELIECE_6688128_F,
    PQC_ALG_ID_MCELIECE_6688128_PC,
    PQC_ALG_ID_MCELIECE_6688128_PCF,

    PQC_ALG_ID_MCELIECE_6960119,
    PQC_ALG_ID_MCELIECE_6960119_F,
    PQC_ALG_ID_MCELIECE_6960119_PC,
    PQC_ALG_ID_MCELIECE_6960119_PCF,

    PQC_ALG_ID_MCELIECE_8192128,
    PQC_ALG_ID_MCELIECE_8192128_F,
    PQC_ALG_ID_MCELIECE_8192128_PC,
    PQC_ALG_ID_MCELIECE_8192128_PCF

} PQC_Mceliece_AlgWithParamId;

typedef struct
{
    char name[30];

    int32_t m;
    int32_t n;
    int32_t t;

    int32_t mt;
    int32_t k;
    int32_t q;
    int32_t q1;

    int32_t nBytes;
    int32_t mtBytes;
    int32_t kBytes;

    int32_t privateKeyBytes;
    int32_t publicKeyBytes;
    int32_t sharedKeyBytes;
    int32_t cipherBytes;

    uint8_t semi;
    uint8_t pc;

} McelieceParams;

McelieceParams* McelieceGetParamsById(PQC_Mceliece_AlgWithParamId alg_id);

#ifdef __cplusplus
}
#endif

#endif //MCELIECE_PARAMS_H
