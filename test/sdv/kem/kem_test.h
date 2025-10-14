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
#include "frodokem.h"

#define ASSERT_EQ(v1, v2, msg)                   \
    do {                                    \
        if (v1 != v2) {                      \
            printf("%s%d:expect:0x%x, real: 0x%x, %s\n", __FILE__, __LINE__, v1, v2, msg); \
            goto EXIT;                      \
        }                                   \
    } while (0)

#define ASSERT_TRUE(TEST, msg)                   \
    do {                                    \
        if (!(TEST)) {                      \
            printf("%s%d:%s\n", __FILE__, __LINE__, msg); \
            goto EXIT;                      \
        }                                   \
    } while (0)

PqcpTestResult TestScloudPlusEncapsDecaps(const char *data_path);

#define MAX_FILENAME_LEN 100

typedef struct
{
    PQC_AlgWithParamId id;
    char filename[MAX_FILENAME_LEN];
} KatFileMap;

KatFileMap gKatFileMap[] = {
    {
        PQC_ALG_ID_eFRODOKEM_640_SHAKE,
        "eFrodoKEM/PQCkemKAT_19888_shake.rsp",
    },
    {
        PQC_ALG_ID_eFRODOKEM_976_SHAKE,
        "eFrodoKEM/PQCkemKAT_31296_shake.rsp",
    },
    {
        PQC_ALG_ID_eFRODOKEM_1344_SHAKE,
        "eFrodoKEM/PQCkemKAT_43088_shake.rsp",
    },
    {
        PQC_ALG_ID_FRODOKEM_640_SHAKE,
        "FrodoKEM/PQCkemKAT_19888_shake.rsp",
    },
    {
        PQC_ALG_ID_FRODOKEM_976_SHAKE,
        "FrodoKEM/PQCkemKAT_31296_shake.rsp",
    },
    {
        PQC_ALG_ID_FRODOKEM_1344_SHAKE,
        "FrodoKEM/PQCkemKAT_43088_shake.rsp",
    },
    {
        PQC_ALG_ID_eFRODOKEM_640_AES,
        "eFrodoKEM/PQCkemKAT_19888.rsp",
    },
    {
        PQC_ALG_ID_eFRODOKEM_976_AES,
        "eFrodoKEM/PQCkemKAT_31296.rsp",
    },
    {
        PQC_ALG_ID_eFRODOKEM_1344_AES,
        "eFrodoKEM/PQCkemKAT_43088.rsp",
    },
    {
        PQC_ALG_ID_FRODOKEM_640_AES,
        "FrodoKEM/PQCkemKAT_19888.rsp",
    },
    {
        PQC_ALG_ID_FRODOKEM_976_AES,
        "FrodoKEM/PQCkemKAT_31296.rsp",
    },
    {
        PQC_ALG_ID_FRODOKEM_1344_AES,
        "FrodoKEM/PQCkemKAT_43088.rsp",
    }
};

#if defined(_WIN32) || defined(__CYGWIN__)
#  define DIR_SEP '\\'
#else
#  define DIR_SEP '/'
#endif

void TestFrodoKemEncapsDecaps(const PQC_AlgWithParamId id, char* kat_path);