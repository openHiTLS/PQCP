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

#include <string.h>

#include "aigis_sig_local.h"
#include "aigis_sig_portable.h"

uint32_t PQCP_AIGIS_SIG_ChallengeMultiplyAddCheckNormVec(AigisSigPoly *scratch, AigisSigPoly *result,
                                                         const AigisSigPoly *base, const AigisSigPoly *challengeNtt,
                                                         const AigisSigPoly *operandNtt, uint32_t count, uint32_t bound)
{
    uint32_t outOfRange = 0;
    uint32_t vectorIndex = 0;
    for (; vectorIndex + 1U < count; vectorIndex += 2U) {
        PQCP_AIGIS_SIG_PolyPointwise(&scratch[vectorIndex], challengeNtt, &operandNtt[vectorIndex]);
        PQCP_AIGIS_SIG_PolyPointwise(&scratch[vectorIndex + 1U], challengeNtt, &operandNtt[vectorIndex + 1U]);
        PQCP_AIGIS_SIG_InvNttPair(scratch[vectorIndex].coeffs, scratch[vectorIndex + 1U].coeffs);
        for (uint32_t coefficient = 0; coefficient < PARAM_N; ++coefficient) {
            for (uint32_t lane = 0; lane < 2U; ++lane) {
                const uint32_t index = vectorIndex + lane;
                const int32_t product =
                    PQCP_AIGIS_SIG_CenteredReduce(PQCP_AIGIS_SIG_GeneralReduce(scratch[index].coeffs[coefficient]));
                const int32_t value = (int32_t)((int64_t)base[index].coeffs[coefficient] + product);
                result[index].coeffs[coefficient] = value;
                outOfRange |= (uint32_t)((int64_t)value > (int64_t)bound);
                outOfRange |= (uint32_t)((int64_t)value < 1 - (int64_t)bound);
            }
        }
    }
    if (vectorIndex < count) {
        PQCP_AIGIS_SIG_PolyPointwise(&scratch[vectorIndex], challengeNtt, &operandNtt[vectorIndex]);
        PQCP_AIGIS_SIG_InvNtt(scratch[vectorIndex].coeffs);
        for (uint32_t coefficient = 0; coefficient < PARAM_N; ++coefficient) {
            const int32_t product =
                PQCP_AIGIS_SIG_CenteredReduce(PQCP_AIGIS_SIG_GeneralReduce(scratch[vectorIndex].coeffs[coefficient]));
            const int32_t value = (int32_t)((int64_t)base[vectorIndex].coeffs[coefficient] + product);
            result[vectorIndex].coeffs[coefficient] = value;
            outOfRange |= (uint32_t)((int64_t)value > (int64_t)bound);
            outOfRange |= (uint32_t)((int64_t)value < 1 - (int64_t)bound);
        }
    }
    return outOfRange;
}

uint32_t PQCP_AIGIS_SIG_ChallengeMultiplySubCheckNormVec(AigisSigPoly *scratch, AigisSigPoly *result,
                                                         const AigisSigPoly *base, const AigisSigPoly *challengeNtt,
                                                         const AigisSigPoly *operandNtt, uint32_t count, uint32_t bound)
{
    uint32_t outOfRange = 0;
    /* Every supported parameter has an even k (2 or 4). */
    for (uint32_t vectorIndex = 0; vectorIndex < count; vectorIndex += 2U) {
        PQCP_AIGIS_SIG_PolyPointwise(&scratch[vectorIndex], challengeNtt, &operandNtt[vectorIndex]);
        PQCP_AIGIS_SIG_PolyPointwise(&scratch[vectorIndex + 1U], challengeNtt, &operandNtt[vectorIndex + 1U]);
        PQCP_AIGIS_SIG_InvNttPair(scratch[vectorIndex].coeffs, scratch[vectorIndex + 1U].coeffs);
        for (uint32_t coefficient = 0; coefficient < PARAM_N; ++coefficient) {
            for (uint32_t lane = 0; lane < 2U; ++lane) {
                const uint32_t index = vectorIndex + lane;
                const int32_t product =
                    PQCP_AIGIS_SIG_CenteredReduce(PQCP_AIGIS_SIG_GeneralReduce(scratch[index].coeffs[coefficient]));
                const int32_t value = (int32_t)((int64_t)base[index].coeffs[coefficient] - product);
                result[index].coeffs[coefficient] = value;
                outOfRange |= (uint32_t)((int64_t)value > (int64_t)bound);
                outOfRange |= (uint32_t)((int64_t)value < 1 - (int64_t)bound);
            }
        }
    }
    return outOfRange;
}

void PQCP_AIGIS_SIG_ChallengePointwiseSubNtt(AigisSigPoly *resultBaseNtt, const AigisSigPoly *challengeNtt,
                                             const AigisSigPoly *shiftedOperandNtt)
{
    /* Both terms use the portable Plantard pointwise scale.  Reducing their
     * difference before the shared inverse NTT keeps its input within one q. */
    for (uint32_t i = 0; i < PARAM_N; ++i) {
        const int32_t product =
            PQCP_AIGIS_SIG_PlantardMulReduce((int64_t)challengeNtt->coeffs[i] * shiftedOperandNtt->coeffs[i]);
        const int32_t difference = (int32_t)((int64_t)resultBaseNtt->coeffs[i] - product);
        resultBaseNtt->coeffs[i] = PQCP_AIGIS_SIG_GeneralReduce(difference);
    }
}

void PQCP_AIGIS_SIG_EmulateCt1ShiftSubGReduce(AigisSigEmulateCt1Scratch *restrict scratch,
                                              AigisSigPoly *restrict resultBase, const AigisSigPoly *restrict challenge,
                                              const AigisSigPoly *restrict t1, uint32_t shift)
{
    (void)memset(scratch->product, 0, sizeof(scratch->product));
    for (uint32_t i = 0; i < PARAM_N; ++i) {
        scratch->stable[i] = -t1->coeffs[i];
        scratch->stable[PARAM_N + i] = t1->coeffs[i];
        scratch->stable[2 * PARAM_N + i] = -t1->coeffs[i];
    }
    for (uint32_t i = 0; i < PARAM_N; ++i) {
        const int32_t sign = challenge->coeffs[i];
        if (sign != 0) {
            const uint32_t offset = PARAM_N - i + (sign < 0 ? PARAM_N : 0U);
            for (uint32_t j = 0; j < PARAM_N; ++j) {
                scratch->product[j] += scratch->stable[offset + j];
            }
        }
    }
    for (uint32_t i = 0; i < PARAM_N; ++i) {
        const int64_t shifted = (int64_t)scratch->product[i] * ((int64_t)1 << shift);
        const int32_t difference = (int32_t)((int64_t)resultBase->coeffs[i] - shifted);
        resultBase->coeffs[i] = PQCP_AIGIS_SIG_GeneralReduce(difference);
    }
}
