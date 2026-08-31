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

#include <stddef.h>

#include "aigis_sig_local.h"
#include "aigis_sig_portable.h"
#include "aigis_sig_zetas.h"

void PQCP_AIGIS_SIG_Ntt(int32_t values[PARAM_N])
{
    int32_t product;
    size_t tableIndex = 1;
    const uint64_t *plantardZetas = AIGIS_PLANTARD_ZETAS;

    for (size_t length = PARAM_N / 2; length > 0; length >>= 1) {
        size_t start = 0;
        while (start < PARAM_N) {
            ++tableIndex;
            const uint64_t plantardZeta = plantardZetas[tableIndex - 1];
            size_t end = start + length;
            for (size_t index = start; index < end; ++index) {
                const int32_t value = values[index];
                const int32_t other = values[index + length];
                product = PQCP_AIGIS_SIG_PlantardReduce(plantardZeta * (uint64_t)(int64_t)other);
                values[index + length] = value - product;
                values[index] = value + product;
            }
            start = end + length;
        }
    }
}

void PQCP_AIGIS_SIG_NttCopy(int32_t dst[PARAM_N], const int32_t src[PARAM_N])
{
    const uint64_t *plantardZetas = AIGIS_PLANTARD_ZETAS;
    size_t tableIndex = 2;
    const uint64_t firstZeta = plantardZetas[1];

    for (size_t index = 0; index < PARAM_N / 2; ++index) {
        const int32_t value = src[index];
        const int32_t other = src[index + PARAM_N / 2];
        const int32_t product = PQCP_AIGIS_SIG_PlantardReduce(firstZeta * (uint64_t)(int64_t)other);
        dst[index] = value + product;
        dst[index + PARAM_N / 2] = value - product;
    }

    for (size_t length = PARAM_N / 4; length > 0; length >>= 1) {
        size_t start = 0;
        while (start < PARAM_N) {
            const uint64_t plantardZeta = plantardZetas[tableIndex++];
            const size_t end = start + length;
            for (size_t index = start; index < end; ++index) {
                const int32_t value = dst[index];
                const int32_t other = dst[index + length];
                const int32_t product = PQCP_AIGIS_SIG_PlantardReduce(plantardZeta * (uint64_t)(int64_t)other);
                dst[index] = value + product;
                dst[index + length] = value - product;
            }
            start = end + length;
        }
    }
}

void PQCP_AIGIS_SIG_InvNtt(int32_t values[PARAM_N])
{
    const uint64_t inversePlantard = UINT64_C(18271446419482553993);
    const uint64_t inversePlantardZeta = UINT64_C(3849831685881375588);
    size_t tableIndex = PARAM_N;
    const uint64_t *plantardZetas = AIGIS_PLANTARD_ZETAS;

    for (size_t length = 1; length < PARAM_N / 2; length <<= 1) {
        size_t start = 0;
        while (start < PARAM_N) {
            --tableIndex;
            const uint64_t plantardZeta = UINT64_C(0) - plantardZetas[tableIndex];
            size_t end = start + length;
            for (size_t index = start; index < end; ++index) {
                int32_t value = values[index];
                int32_t other = values[index + length];
                values[index] = value + other;
                values[index + length] =
                    PQCP_AIGIS_SIG_PlantardReduce(plantardZeta * (uint64_t)(int64_t)(value - other));
            }
            start = end + length;
        }
    }

    for (size_t index = 0; index < PARAM_N / 2; ++index) {
        int32_t value = values[index];
        int32_t other = values[index + PARAM_N / 2];
        values[index] = PQCP_AIGIS_SIG_PlantardReduce(inversePlantard * (uint64_t)(int64_t)(value + other));
        values[index + PARAM_N / 2] =
            PQCP_AIGIS_SIG_PlantardReduce(inversePlantardZeta * (uint64_t)(int64_t)(value - other));
    }
}

void PQCP_AIGIS_SIG_InvNttPair(int32_t first[PARAM_N], int32_t second[PARAM_N])
{
    const uint64_t inversePlantard = UINT64_C(18271446419482553993);
    const uint64_t inversePlantardZeta = UINT64_C(3849831685881375588);
    size_t tableIndex = PARAM_N;
    const uint64_t *plantardZetas = AIGIS_PLANTARD_ZETAS;

    for (size_t length = 1; length < PARAM_N / 2; length <<= 1) {
        size_t start = 0;
        while (start < PARAM_N) {
            const uint64_t plantardZeta = UINT64_C(0) - plantardZetas[--tableIndex];
            const size_t end = start + length;
            for (size_t index = start; index < end; ++index) {
                const int32_t firstValue = first[index];
                const int32_t firstOther = first[index + length];
                const int32_t secondValue = second[index];
                const int32_t secondOther = second[index + length];
                first[index] = firstValue + firstOther;
                first[index + length] =
                    PQCP_AIGIS_SIG_PlantardReduce(plantardZeta * (uint64_t)(int64_t)(firstValue - firstOther));
                second[index] = secondValue + secondOther;
                second[index + length] =
                    PQCP_AIGIS_SIG_PlantardReduce(plantardZeta * (uint64_t)(int64_t)(secondValue - secondOther));
            }
            start = end + length;
        }
    }

    for (size_t index = 0; index < PARAM_N / 2; ++index) {
        const int32_t firstValue = first[index];
        const int32_t firstOther = first[index + PARAM_N / 2];
        const int32_t secondValue = second[index];
        const int32_t secondOther = second[index + PARAM_N / 2];
        first[index] = PQCP_AIGIS_SIG_PlantardReduce(inversePlantard * (uint64_t)(int64_t)(firstValue + firstOther));
        first[index + PARAM_N / 2] =
            PQCP_AIGIS_SIG_PlantardReduce(inversePlantardZeta * (uint64_t)(int64_t)(firstValue - firstOther));
        second[index] = PQCP_AIGIS_SIG_PlantardReduce(inversePlantard * (uint64_t)(int64_t)(secondValue + secondOther));
        second[index + PARAM_N / 2] =
            PQCP_AIGIS_SIG_PlantardReduce(inversePlantardZeta * (uint64_t)(int64_t)(secondValue - secondOther));
    }
}

void PQCP_AIGIS_SIG_PolyVecKInvNttPair(const PQCP_AIGIS_SIG_CoreCtx *opCtx, AigisSigPolyVecK *v)
{
    uint32_t i;
    const uint32_t k = opCtx->params->k;

    for (i = 0; i + 1U < k; i += 2U) {
        PQCP_AIGIS_SIG_InvNttPair(v->vec[i].coeffs, v->vec[i + 1U].coeffs);
    }
    if (i < k) {
        PQCP_AIGIS_SIG_InvNtt(v->vec[i].coeffs);
    }
}
