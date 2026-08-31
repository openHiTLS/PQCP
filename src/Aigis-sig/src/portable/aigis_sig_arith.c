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

#include "aigis_sig_portable.h"

#ifndef PQCP_AIGIS_SIG_PORTABLE_BACKEND
int32_t PQCP_AIGIS_SIG_MontgomeryReduce(int64_t value)
{
    const uint32_t lowBits = (uint32_t)value * (uint32_t)QINV;
    const int64_t low = (int64_t)lowBits - ((int64_t)(lowBits >> 31) << 32);
    return (int32_t)PQCP_AIGIS_SIG_ArithmeticShiftRight(value - low * PARAM_Q, 32);
}
#endif

#ifndef PQCP_AIGIS_SIG_PORTABLE_BACKEND
int32_t PQCP_AIGIS_SIG_GeneralReduce(int32_t value)
{
    const int64_t quotient = PQCP_AIGIS_SIG_ArithmeticShiftRight((int64_t)value * 2159079753LL, 53);
    return (int32_t)((int64_t)value - quotient * PARAM_Q);
}
#endif

#ifndef PQCP_AIGIS_SIG_PORTABLE_BACKEND
int32_t PQCP_AIGIS_SIG_PositiveReduce(int32_t value)
{
    const uint32_t negativeMask = 0U - ((uint32_t)value >> 31);
    return value + (int32_t)(negativeMask & PARAM_Q);
}

int32_t PQCP_AIGIS_SIG_CenteredReduce(int32_t value)
{
    int32_t reduced = PQCP_AIGIS_SIG_PositiveReduce(value);
    int32_t distance = PARAM_Q / 2 - reduced;
    const uint32_t negativeMask = 0U - ((uint32_t)distance >> 31);
    return reduced - (int32_t)(negativeMask & PARAM_Q);
}
#endif

#ifndef PQCP_AIGIS_SIG_PORTABLE_BACKEND
int32_t PQCP_AIGIS_SIG_Power2Round(int32_t value, int32_t *low)
{
    const uint32_t high = ((uint32_t)value + (UINT32_C(1) << (PARAM_D - 1)) - 1U) >> PARAM_D;
    *low = value - (int32_t)(high << PARAM_D);
    return (int32_t)high;
}

int32_t PQCP_AIGIS_SIG_Decompose(int32_t value, int32_t *low)
{
    int32_t high;
    uint32_t mask;

    high = (value + 127) >> 7;
    high = (high * 6177 + (1 << 24)) >> 25;
    mask = 0U - (uint32_t)(high > 5);
    high = (int32_t)((uint32_t)high & ~mask);

    *low = value - high * ALPHA;
    mask = 0U - (uint32_t)(*low > (PARAM_Q - 1) / 2);
    *low -= (int32_t)(mask & PARAM_Q);
    return high;
}

uint32_t PQCP_AIGIS_SIG_MakeHint(int32_t low, int32_t high)
{
    const uint32_t aboveLower = (uint32_t)(low > GAMMA2);
    const uint32_t belowUpper = (uint32_t)(low < PARAM_Q - GAMMA2);
    const uint32_t atUpperWithHigh = (uint32_t)(low == PARAM_Q - GAMMA2) & (uint32_t)(high != 0);
    return aboveLower & (belowUpper | atUpperWithHigh);
}
#endif
