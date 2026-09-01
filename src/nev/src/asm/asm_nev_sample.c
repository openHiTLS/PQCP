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

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_NEV

#include <arm_neon.h>
#include "nev_local.h"
#ifdef HITLS_CRYPTO_NEV_SVE2
#include "nev_sve2.h"
#endif

/*
 * ARMv8 fast path for the uniform-ternary rejection sampler (nev_sample.c
 * poly_bias3_ternary): the byte-acceptance filter runs in the NEON
 * tbl-compaction kernel of asm/nev_sample_armv8.S, and the base-3 digit
 * extraction becomes one 5-coefficient table row per accepted byte.
 *
 * Bit-exactness: the kernel accepts exactly the bytes x < 243 in stream
 * order; NEV_TERNARY5[x][j] is by construction 1 - digit_j(x) with digit_j
 * the j-th base-3 digit exactly as the scalar Ternary3 computes it (same
 * 0xaaab reciprocal chain; verified for all 243 rows by the differential
 * harness and, independently, against plain base-3 expansion by the table
 * generator).  The copy loop reproduces the scalar cutoff semantics: a
 * whole 5-digit group per accepted byte while pos + 5 <= n, then one
 * partial group; the result is the reference stream truncated at
 * min(n, 5 * accepted).
 */

uint64_t NEV_RejTernaryCompactAsm(uint8_t *dst, const uint8_t *src, uint64_t len);
#ifdef HITLS_CRYPTO_NEV_SVE2
uint64_t NEV_RejTernaryCompactSve2(uint8_t *dst, const uint8_t *src, uint64_t len);
#endif

/* Largest single filter input: every caller (nev_sample.c, both the
 * single-lane and the Keccakx2-batched path) passes at most the bias3
 * initial squeeze, Bias3InitialBlocks(n, rate) * rate, which is bounded by
 * NEV_BIAS3_BUF_MAX (672) for every parameter set and every contract-legal
 * custom KDF rate in [1, NEV_KDF_RATE_MAX] (the shipped backends peak at
 * 504 bytes for n=2048/rate=72).  Plus the 8 bytes of store slack the
 * compaction kernels require (nev_sample_armv8.S: dst needs len + 8). */
#define NEV_REJ_COMPACT_BUF (NEV_BIAS3_BUF_MAX + 8)

/* NEV_TERNARY5[x][j] = 1 - digit_j(x) for the base-3 digits of x < 243. */
static const int16_t NEV_TERNARY5[243][8] = {
    { 1,  1,  1,  1,  1},
    { 0,  1,  1,  1,  1},
    {-1,  1,  1,  1,  1},
    { 1,  0,  1,  1,  1},
    { 0,  0,  1,  1,  1},
    {-1,  0,  1,  1,  1},
    { 1, -1,  1,  1,  1},
    { 0, -1,  1,  1,  1},
    {-1, -1,  1,  1,  1},
    { 1,  1,  0,  1,  1},
    { 0,  1,  0,  1,  1},
    {-1,  1,  0,  1,  1},
    { 1,  0,  0,  1,  1},
    { 0,  0,  0,  1,  1},
    {-1,  0,  0,  1,  1},
    { 1, -1,  0,  1,  1},
    { 0, -1,  0,  1,  1},
    {-1, -1,  0,  1,  1},
    { 1,  1, -1,  1,  1},
    { 0,  1, -1,  1,  1},
    {-1,  1, -1,  1,  1},
    { 1,  0, -1,  1,  1},
    { 0,  0, -1,  1,  1},
    {-1,  0, -1,  1,  1},
    { 1, -1, -1,  1,  1},
    { 0, -1, -1,  1,  1},
    {-1, -1, -1,  1,  1},
    { 1,  1,  1,  0,  1},
    { 0,  1,  1,  0,  1},
    {-1,  1,  1,  0,  1},
    { 1,  0,  1,  0,  1},
    { 0,  0,  1,  0,  1},
    {-1,  0,  1,  0,  1},
    { 1, -1,  1,  0,  1},
    { 0, -1,  1,  0,  1},
    {-1, -1,  1,  0,  1},
    { 1,  1,  0,  0,  1},
    { 0,  1,  0,  0,  1},
    {-1,  1,  0,  0,  1},
    { 1,  0,  0,  0,  1},
    { 0,  0,  0,  0,  1},
    {-1,  0,  0,  0,  1},
    { 1, -1,  0,  0,  1},
    { 0, -1,  0,  0,  1},
    {-1, -1,  0,  0,  1},
    { 1,  1, -1,  0,  1},
    { 0,  1, -1,  0,  1},
    {-1,  1, -1,  0,  1},
    { 1,  0, -1,  0,  1},
    { 0,  0, -1,  0,  1},
    {-1,  0, -1,  0,  1},
    { 1, -1, -1,  0,  1},
    { 0, -1, -1,  0,  1},
    {-1, -1, -1,  0,  1},
    { 1,  1,  1, -1,  1},
    { 0,  1,  1, -1,  1},
    {-1,  1,  1, -1,  1},
    { 1,  0,  1, -1,  1},
    { 0,  0,  1, -1,  1},
    {-1,  0,  1, -1,  1},
    { 1, -1,  1, -1,  1},
    { 0, -1,  1, -1,  1},
    {-1, -1,  1, -1,  1},
    { 1,  1,  0, -1,  1},
    { 0,  1,  0, -1,  1},
    {-1,  1,  0, -1,  1},
    { 1,  0,  0, -1,  1},
    { 0,  0,  0, -1,  1},
    {-1,  0,  0, -1,  1},
    { 1, -1,  0, -1,  1},
    { 0, -1,  0, -1,  1},
    {-1, -1,  0, -1,  1},
    { 1,  1, -1, -1,  1},
    { 0,  1, -1, -1,  1},
    {-1,  1, -1, -1,  1},
    { 1,  0, -1, -1,  1},
    { 0,  0, -1, -1,  1},
    {-1,  0, -1, -1,  1},
    { 1, -1, -1, -1,  1},
    { 0, -1, -1, -1,  1},
    {-1, -1, -1, -1,  1},
    { 1,  1,  1,  1,  0},
    { 0,  1,  1,  1,  0},
    {-1,  1,  1,  1,  0},
    { 1,  0,  1,  1,  0},
    { 0,  0,  1,  1,  0},
    {-1,  0,  1,  1,  0},
    { 1, -1,  1,  1,  0},
    { 0, -1,  1,  1,  0},
    {-1, -1,  1,  1,  0},
    { 1,  1,  0,  1,  0},
    { 0,  1,  0,  1,  0},
    {-1,  1,  0,  1,  0},
    { 1,  0,  0,  1,  0},
    { 0,  0,  0,  1,  0},
    {-1,  0,  0,  1,  0},
    { 1, -1,  0,  1,  0},
    { 0, -1,  0,  1,  0},
    {-1, -1,  0,  1,  0},
    { 1,  1, -1,  1,  0},
    { 0,  1, -1,  1,  0},
    {-1,  1, -1,  1,  0},
    { 1,  0, -1,  1,  0},
    { 0,  0, -1,  1,  0},
    {-1,  0, -1,  1,  0},
    { 1, -1, -1,  1,  0},
    { 0, -1, -1,  1,  0},
    {-1, -1, -1,  1,  0},
    { 1,  1,  1,  0,  0},
    { 0,  1,  1,  0,  0},
    {-1,  1,  1,  0,  0},
    { 1,  0,  1,  0,  0},
    { 0,  0,  1,  0,  0},
    {-1,  0,  1,  0,  0},
    { 1, -1,  1,  0,  0},
    { 0, -1,  1,  0,  0},
    {-1, -1,  1,  0,  0},
    { 1,  1,  0,  0,  0},
    { 0,  1,  0,  0,  0},
    {-1,  1,  0,  0,  0},
    { 1,  0,  0,  0,  0},
    { 0,  0,  0,  0,  0},
    {-1,  0,  0,  0,  0},
    { 1, -1,  0,  0,  0},
    { 0, -1,  0,  0,  0},
    {-1, -1,  0,  0,  0},
    { 1,  1, -1,  0,  0},
    { 0,  1, -1,  0,  0},
    {-1,  1, -1,  0,  0},
    { 1,  0, -1,  0,  0},
    { 0,  0, -1,  0,  0},
    {-1,  0, -1,  0,  0},
    { 1, -1, -1,  0,  0},
    { 0, -1, -1,  0,  0},
    {-1, -1, -1,  0,  0},
    { 1,  1,  1, -1,  0},
    { 0,  1,  1, -1,  0},
    {-1,  1,  1, -1,  0},
    { 1,  0,  1, -1,  0},
    { 0,  0,  1, -1,  0},
    {-1,  0,  1, -1,  0},
    { 1, -1,  1, -1,  0},
    { 0, -1,  1, -1,  0},
    {-1, -1,  1, -1,  0},
    { 1,  1,  0, -1,  0},
    { 0,  1,  0, -1,  0},
    {-1,  1,  0, -1,  0},
    { 1,  0,  0, -1,  0},
    { 0,  0,  0, -1,  0},
    {-1,  0,  0, -1,  0},
    { 1, -1,  0, -1,  0},
    { 0, -1,  0, -1,  0},
    {-1, -1,  0, -1,  0},
    { 1,  1, -1, -1,  0},
    { 0,  1, -1, -1,  0},
    {-1,  1, -1, -1,  0},
    { 1,  0, -1, -1,  0},
    { 0,  0, -1, -1,  0},
    {-1,  0, -1, -1,  0},
    { 1, -1, -1, -1,  0},
    { 0, -1, -1, -1,  0},
    {-1, -1, -1, -1,  0},
    { 1,  1,  1,  1, -1},
    { 0,  1,  1,  1, -1},
    {-1,  1,  1,  1, -1},
    { 1,  0,  1,  1, -1},
    { 0,  0,  1,  1, -1},
    {-1,  0,  1,  1, -1},
    { 1, -1,  1,  1, -1},
    { 0, -1,  1,  1, -1},
    {-1, -1,  1,  1, -1},
    { 1,  1,  0,  1, -1},
    { 0,  1,  0,  1, -1},
    {-1,  1,  0,  1, -1},
    { 1,  0,  0,  1, -1},
    { 0,  0,  0,  1, -1},
    {-1,  0,  0,  1, -1},
    { 1, -1,  0,  1, -1},
    { 0, -1,  0,  1, -1},
    {-1, -1,  0,  1, -1},
    { 1,  1, -1,  1, -1},
    { 0,  1, -1,  1, -1},
    {-1,  1, -1,  1, -1},
    { 1,  0, -1,  1, -1},
    { 0,  0, -1,  1, -1},
    {-1,  0, -1,  1, -1},
    { 1, -1, -1,  1, -1},
    { 0, -1, -1,  1, -1},
    {-1, -1, -1,  1, -1},
    { 1,  1,  1,  0, -1},
    { 0,  1,  1,  0, -1},
    {-1,  1,  1,  0, -1},
    { 1,  0,  1,  0, -1},
    { 0,  0,  1,  0, -1},
    {-1,  0,  1,  0, -1},
    { 1, -1,  1,  0, -1},
    { 0, -1,  1,  0, -1},
    {-1, -1,  1,  0, -1},
    { 1,  1,  0,  0, -1},
    { 0,  1,  0,  0, -1},
    {-1,  1,  0,  0, -1},
    { 1,  0,  0,  0, -1},
    { 0,  0,  0,  0, -1},
    {-1,  0,  0,  0, -1},
    { 1, -1,  0,  0, -1},
    { 0, -1,  0,  0, -1},
    {-1, -1,  0,  0, -1},
    { 1,  1, -1,  0, -1},
    { 0,  1, -1,  0, -1},
    {-1,  1, -1,  0, -1},
    { 1,  0, -1,  0, -1},
    { 0,  0, -1,  0, -1},
    {-1,  0, -1,  0, -1},
    { 1, -1, -1,  0, -1},
    { 0, -1, -1,  0, -1},
    {-1, -1, -1,  0, -1},
    { 1,  1,  1, -1, -1},
    { 0,  1,  1, -1, -1},
    {-1,  1,  1, -1, -1},
    { 1,  0,  1, -1, -1},
    { 0,  0,  1, -1, -1},
    {-1,  0,  1, -1, -1},
    { 1, -1,  1, -1, -1},
    { 0, -1,  1, -1, -1},
    {-1, -1,  1, -1, -1},
    { 1,  1,  0, -1, -1},
    { 0,  1,  0, -1, -1},
    {-1,  1,  0, -1, -1},
    { 1,  0,  0, -1, -1},
    { 0,  0,  0, -1, -1},
    {-1,  0,  0, -1, -1},
    { 1, -1,  0, -1, -1},
    { 0, -1,  0, -1, -1},
    {-1, -1,  0, -1, -1},
    { 1,  1, -1, -1, -1},
    { 0,  1, -1, -1, -1},
    {-1,  1, -1, -1, -1},
    { 1,  0, -1, -1, -1},
    { 0,  0, -1, -1, -1},
    {-1,  0, -1, -1, -1},
    { 1, -1, -1, -1, -1},
    { 0, -1, -1, -1, -1},
    {-1, -1, -1, -1, -1},
};

int32_t NEV_Ternary3Ext(int16_t *r, const uint8_t *buf, int32_t n, int32_t bufLen)
{
    uint8_t cbuf[NEV_REJ_COMPACT_BUF];
    int32_t acc;
#ifdef HITLS_CRYPTO_NEV_SVE2
    if (NEV_Sve2Enabled() != 0) {
        acc = (int32_t)NEV_RejTernaryCompactSve2(cbuf, buf, (uint64_t)bufLen);
    } else
#endif
    {
        acc = (int32_t)NEV_RejTernaryCompactAsm(cbuf, buf, (uint64_t)bufLen);
    }
    int32_t pos = 0;
    int32_t i = 0;

    /* Store five coefficients plus three padding lanes at a time.  Every
     * padding lane is overwritten by a following group or the scalar tail. */
    while (pos + 8 <= n && i < acc) {
        vst1q_s16(&r[pos], vld1q_s16(NEV_TERNARY5[cbuf[i++]]));
        pos += 5;
    }
    while (pos + 5 <= n && i < acc) {
        const int16_t *row = NEV_TERNARY5[cbuf[i++]];
        r[pos] = row[0];
        r[pos + 1] = row[1];
        r[pos + 2] = row[2];
        r[pos + 3] = row[3];
        r[pos + 4] = row[4];
        pos += 5;
    }
    if (pos < n && i < acc) { // partial final group, scalar cutoff semantics
        const int16_t *row = NEV_TERNARY5[cbuf[i]];
        for (int32_t j = 0; j < 5 && pos < n; j++) {
            r[pos++] = row[j];
        }
    }
    return pos;
}

#endif // HITLS_CRYPTO_NEV
