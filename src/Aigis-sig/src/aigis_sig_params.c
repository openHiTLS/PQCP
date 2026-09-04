/* Copyright (c) 2025 LiuRuikang
 * School Of Cyber Engineering, Xidian University
 *
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
#include "aigis_sig_local.h"

#include <stddef.h>

_Static_assert(AIGIS_SIG_PARAM_I_PUBLIC_KEY_BYTES == 928U, "parameter I public-key size mismatch");
_Static_assert(AIGIS_SIG_PARAM_I_PRIVATE_KEY_BYTES == 2800U, "parameter I private-key size mismatch");
_Static_assert(AIGIS_SIG_PARAM_I_SIGNATURE_BYTES == 2015U, "parameter I signature size mismatch");
_Static_assert(AIGIS_SIG_PARAM_II_PUBLIC_KEY_BYTES == 1824U, "parameter II public-key size mismatch");
_Static_assert(AIGIS_SIG_PARAM_II_PRIVATE_KEY_BYTES == 4976U, "parameter II private-key size mismatch");
_Static_assert(AIGIS_SIG_PARAM_II_SIGNATURE_BYTES == 4533U, "parameter II signature size mismatch");
_Static_assert(AIGIS_SIG_PARAM_III_PUBLIC_KEY_BYTES == 4672U, "parameter III public-key size mismatch");
_Static_assert(AIGIS_SIG_PARAM_III_PRIVATE_KEY_BYTES == 8800U, "parameter III private-key size mismatch");
_Static_assert(AIGIS_SIG_PARAM_III_SIGNATURE_BYTES == 9134U, "parameter III signature size mismatch");

static const AigisSigParams AIGIS_SIG_PARAMS[] = {
    {
        .id = 1,
        .seedBytes = 32U,
        .rngSeedBytes = 48U,
        .crhBytes = 48U,
        .d = 15U,
        .alpha = 695296U,
        .gamma2 = 347648U,
        .maxHigh = 5U,
        .gamma1 = 16384U,
        .szBits = 15U,
        .gamma3 = 504000U,
        .challengeWeight = 24U,
        .k = 2U,
        .l = 2U,
        .eta2 = 5U,
        .eta2Bits = 4U,
        .rejEta1Bytes = 192U,
        .rejEta2Bytes = 384U,
        .beta1 = 24U,
        .beta2 = 120U,
        .omega = 72U,
        .polyZPackedBytes = 960U,
        .polyW1PackedBytes = 192U,
        .polyT1PackedBytes = 448U,
        .polyT0PackedBytes = 960U,
        .polyEta1PackedBytes = 128U,
        .polyEta2PackedBytes = 256U,
        .publicKeyBytes = AIGIS_SIG_PARAM_I_PUBLIC_KEY_BYTES,
        .privateKeyBytes = AIGIS_SIG_PARAM_I_PRIVATE_KEY_BYTES,
        .signatureBytes = AIGIS_SIG_PARAM_I_SIGNATURE_BYTES,
    },
    {
        .id = 2,
        .seedBytes = 32U,
        .rngSeedBytes = 48U,
        .crhBytes = 48U,
        .d = 15U,
        .alpha = 695296U,
        .gamma2 = 347648U,
        .maxHigh = 5U,
        .gamma1 = 65536U,
        .szBits = 17U,
        .gamma3 = 575000U,
        .challengeWeight = 44U,
        .k = 4U,
        .l = 4U,
        .eta2 = 1U,
        .eta2Bits = 2U,
        .rejEta1Bytes = 192U,
        .rejEta2Bytes = 192U,
        .beta1 = 44U,
        .beta2 = 44U,
        .omega = 176U,
        .polyZPackedBytes = 1088U,
        .polyW1PackedBytes = 192U,
        .polyT1PackedBytes = 448U,
        .polyT0PackedBytes = 960U,
        .polyEta1PackedBytes = 128U,
        .polyEta2PackedBytes = 128U,
        .publicKeyBytes = AIGIS_SIG_PARAM_II_PUBLIC_KEY_BYTES,
        .privateKeyBytes = AIGIS_SIG_PARAM_II_PRIVATE_KEY_BYTES,
        .signatureBytes = AIGIS_SIG_PARAM_II_SIGNATURE_BYTES,
    },
    {
        .id = 3,
        .seedBytes = 64U,
        .rngSeedBytes = 96U,
        .crhBytes = 96U,
        .d = 13U,
        .alpha = 1042944U,
        .gamma2 = 521472U,
        .maxHigh = 3U,
        .gamma1 = 524288U,
        .szBits = 20U,
        .gamma3 = 612000U,
        .challengeWeight = 118U,
        .k = 8U,
        .l = 7U,
        .eta2 = 1U,
        .eta2Bits = 2U,
        .rejEta1Bytes = 192U,
        .rejEta2Bytes = 192U,
        .beta1 = 118U,
        .beta2 = 118U,
        .omega = 102U,
        .polyZPackedBytes = 1280U,
        .polyW1PackedBytes = 128U,
        .polyT1PackedBytes = 576U,
        .polyT0PackedBytes = 832U,
        .polyEta1PackedBytes = 128U,
        .polyEta2PackedBytes = 128U,
        .publicKeyBytes = AIGIS_SIG_PARAM_III_PUBLIC_KEY_BYTES,
        .privateKeyBytes = AIGIS_SIG_PARAM_III_PRIVATE_KEY_BYTES,
        .signatureBytes = AIGIS_SIG_PARAM_III_SIGNATURE_BYTES,
    },
};

const AigisSigParams *PQCP_AIGIS_SIG_GetParams(int32_t paramId)
{
    for (uint32_t i = 0; i < sizeof(AIGIS_SIG_PARAMS) / sizeof(AIGIS_SIG_PARAMS[0]); i++) {
        if (AIGIS_SIG_PARAMS[i].id == paramId) {
            return &AIGIS_SIG_PARAMS[i];
        }
    }
    return NULL;
}
