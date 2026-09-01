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

/*
 * ARMv8 NEON backend (v2) for the NEV NTT-CRT polynomial arithmetic:
 * link-time replacement for nev_poly.c.  The Karatsuba / batch-inversion
 * control flow stays here; the data-parallel work runs in the whole-array
 * NEON kernels of asm/nev_poly_armv8.S.
 *
 * v2 correctness contract (see the range/congruence discussion in the .S
 * header): NEV_PolyAdd / NEV_PolyReduce / NEV_PolyCaddq /
 * NEV_PolyGetMontgomery / NEV_PolyAddVinv are BIT-EXACT equivalents of
 * nev_poly.c.  NEV_PolyMontMul / NEV_PolyMont2Inverse produce values that
 * are CONGRUENT mod q to the reference outputs within proven wrap-free
 * int16 ranges, and NEV_PolyMont2Inverse* return identical invertibility
 * decisions.  Every consumer of the congruent values passes them through
 * an exact canonicalization (NEV_PolyReduce / the fused *Caddq passes
 * below / NEV_PolyGetMontgomery) before any packing or message decoding,
 * so all packed bytes are unchanged.
 *
 * Deviations from the reference dataflow (all congruence-preserving):
 *  - Karatsuba operand sums use NEV_AddBarrettArrAsm (add + exact Barrett),
 *    keeping every "middle" product operand <= (q-1)/2;
 *  - every Mont2Inverse level and every Norm-map intermediate is normalized
 *    with the exact Barrett before it feeds the next level;
 *  - chains of MontReduce results are accumulated raw in 32 bits and
 *    reduced once per output (linearity of MontReduce mod q);
 *  - adjacent MR(x*y) +/- MR(z*y) pairs are merged into MR((x +/- z)*y).
 * Invertibility decisions are unchanged: the s array of the norm map is
 * produced by the proven exact Barrett + Caddq from wrap-free values, so it
 * is bit-identical to the reference s array (unique standard representative
 * of a class that depends only on the inputs mod q), and the scalar
 * BatchMont2Inv below then sees identical inputs.
 */

/* NEON kernels (asm/nev_poly_armv8.S). */
void NEV_AddArrAsm(int16_t *r, const int16_t *a, const int16_t *b, uint64_t n);
void NEV_SubArrAsm(int16_t *r, const int16_t *a, const int16_t *b, uint64_t n);
void NEV_NegArrAsm(int16_t *r, const int16_t *a, uint64_t n);
void NEV_CaddqArrAsm(int16_t *r, const int16_t *a, uint64_t n, uint64_t q);
void NEV_BarrettArrAsm(int16_t *r, const int16_t *a, uint64_t n, uint64_t bPacked);
void NEV_MontArrAsm(int16_t *r, const int16_t *a, uint64_t n, uint64_t qPacked);
void NEV_AddBarrettArrAsm(int16_t *r, const int16_t *a, const int16_t *b, uint64_t n,
    uint64_t qbPacked);
void NEV_BarrettCaddqArrAsm(int16_t *r, const int16_t *a, uint64_t n, uint64_t qbPacked);
void NEV_AddBarrettCaddqArrAsm(int16_t *r, const int16_t *a, const int16_t *b, uint64_t n,
    uint64_t qbPacked);
void NEV_MontCaddqArrAsm(int16_t *r, const int16_t *a, uint64_t n, uint64_t qPacked);
void NEV_Sub2ArrAsm(int16_t *r, const int16_t *a, const int16_t *b, const int16_t *c, uint64_t n);
void NEV_Comb4Asm(int16_t *r, const int16_t *a, const int16_t *b, const int16_t *c,
    const int16_t *d, uint64_t n);
void NEV_CopyBlocksAsm(int16_t *r, const int16_t *a, uint64_t dimBlocks, uint64_t aStride);
void NEV_MulYCombAsm(int16_t *r, const int16_t *a, const int16_t *a2, const int16_t *b,
    const int16_t *b2, const int16_t *y, uint64_t geom, uint64_t qbPacked);
void NEV_MontMul4Asm(int16_t *r, const int16_t *a, const int16_t *b, uint64_t dim,
    uint64_t qbPacked, uint64_t dbl);
void NEV_PolyMulRed4Asm(int16_t *r, const int16_t *a, const int16_t *b, const int16_t *y,
    uint64_t dim, uint64_t qbPacked);
void NEV_PolyMulCombAsm(int16_t *r, const int16_t *t0, const int16_t *t1, const int16_t *t2,
    const int16_t *y, uint64_t geom, uint64_t qbPacked);
void NEV_MontSquare4Asm(int16_t *r, const int16_t *a, uint64_t dim, uint64_t qPacked);
void NEV_MontMul8TailAsm(int16_t *r, const int16_t *t1, uint64_t dim, uint64_t qbPacked);
void NEV_Inv4NormAsm(int16_t *a20, int16_t *a21, int16_t *s, const int16_t *a, const int16_t *y,
    uint64_t dim, uint64_t qbPacked);
void NEV_Inv4FinishAsm(int16_t *r, const int16_t *a, const int16_t *a20, const int16_t *a21,
    const int16_t *sInv, const int16_t *y, uint64_t dim, uint64_t qbPacked);

#ifdef HITLS_CRYPTO_NEV_SVE2
#include "nev_sve2.h"

/* SVE2 counterparts selected unconditionally in an SVE2-enabled build. */
void NEV_AddArrSve2(int16_t *r, const int16_t *a, const int16_t *b, uint64_t n);
void NEV_SubArrSve2(int16_t *r, const int16_t *a, const int16_t *b, uint64_t n);
void NEV_NegArrSve2(int16_t *r, const int16_t *a, uint64_t n);
void NEV_CaddqArrSve2(int16_t *r, const int16_t *a, uint64_t n, uint64_t q);
void NEV_BarrettArrSve2(int16_t *r, const int16_t *a, uint64_t n, uint64_t bPacked);
void NEV_MontArrSve2(int16_t *r, const int16_t *a, uint64_t n, uint64_t qPacked);
void NEV_AddBarrettArrSve2(int16_t *r, const int16_t *a, const int16_t *b, uint64_t n,
    uint64_t qbPacked);
void NEV_BarrettCaddqArrSve2(int16_t *r, const int16_t *a, uint64_t n, uint64_t qbPacked);
void NEV_AddBarrettCaddqArrSve2(int16_t *r, const int16_t *a, const int16_t *b, uint64_t n,
    uint64_t qbPacked);
void NEV_MontCaddqArrSve2(int16_t *r, const int16_t *a, uint64_t n, uint64_t qPacked);
void NEV_Sub2ArrSve2(int16_t *r, const int16_t *a, const int16_t *b, const int16_t *c, uint64_t n);
void NEV_Comb4Sve2(int16_t *r, const int16_t *a, const int16_t *b, const int16_t *c,
    const int16_t *d, uint64_t n);
void NEV_CopyBlocksSve2(int16_t *r, const int16_t *a, uint64_t dimBlocks, uint64_t aStride);
void NEV_MulYCombSve2(int16_t *r, const int16_t *a, const int16_t *a2, const int16_t *b,
    const int16_t *b2, const int16_t *y, uint64_t geom, uint64_t qbPacked);
void NEV_MontMul4Sve2(int16_t *r, const int16_t *a, const int16_t *b, uint64_t dim,
    uint64_t qbPacked, uint64_t dbl);
void NEV_PolyMulRed4Sve2(int16_t *r, const int16_t *a, const int16_t *b, const int16_t *y,
    uint64_t dim, uint64_t qbPacked);
void NEV_PolyMulCombSve2(int16_t *r, const int16_t *t0, const int16_t *t1, const int16_t *t2,
    const int16_t *y, uint64_t geom, uint64_t qbPacked);
void NEV_MontSquare4Sve2(int16_t *r, const int16_t *a, uint64_t dim, uint64_t qPacked);
void NEV_MontMul8TailSve2(int16_t *r, const int16_t *t1, uint64_t dim, uint64_t qbPacked);
void NEV_Inv4NormSve2(int16_t *a20, int16_t *a21, int16_t *s, const int16_t *a, const int16_t *y,
    uint64_t dim, uint64_t qbPacked);
void NEV_Inv4FinishSve2(int16_t *r, const int16_t *a, const int16_t *a20, const int16_t *a21,
    const int16_t *sInv, const int16_t *y, uint64_t dim, uint64_t qbPacked);
int32_t NEV_BatchMont2InvSve2(int16_t *r, const int16_t *a, uint64_t dim, uint64_t qPacked);

#define NEV_SVE2_SHIM(name, params, args)                       \
    static inline void Nev##name params                         \
    {                                                           \
        if (NEV_Sve2Enabled() != 0) {                           \
            name##Sve2 args;                                    \
        } else {                                                \
            name##Asm args;                                     \
        }                                                       \
    }

NEV_SVE2_SHIM(NEV_AddArr, (int16_t *r, const int16_t *a, const int16_t *b, uint64_t n),
    (r, a, b, n))
NEV_SVE2_SHIM(NEV_SubArr, (int16_t *r, const int16_t *a, const int16_t *b, uint64_t n),
    (r, a, b, n))
NEV_SVE2_SHIM(NEV_NegArr, (int16_t *r, const int16_t *a, uint64_t n), (r, a, n))
NEV_SVE2_SHIM(NEV_CaddqArr, (int16_t *r, const int16_t *a, uint64_t n, uint64_t q), (r, a, n, q))
NEV_SVE2_SHIM(NEV_BarrettArr, (int16_t *r, const int16_t *a, uint64_t n, uint64_t b), (r, a, n, b))
NEV_SVE2_SHIM(NEV_MontArr, (int16_t *r, const int16_t *a, uint64_t n, uint64_t qp), (r, a, n, qp))
NEV_SVE2_SHIM(NEV_AddBarrettArr,
    (int16_t *r, const int16_t *a, const int16_t *b, uint64_t n, uint64_t qb), (r, a, b, n, qb))
NEV_SVE2_SHIM(NEV_BarrettCaddqArr, (int16_t *r, const int16_t *a, uint64_t n, uint64_t qb),
    (r, a, n, qb))
NEV_SVE2_SHIM(NEV_AddBarrettCaddqArr,
    (int16_t *r, const int16_t *a, const int16_t *b, uint64_t n, uint64_t qb), (r, a, b, n, qb))
NEV_SVE2_SHIM(NEV_MontCaddqArr, (int16_t *r, const int16_t *a, uint64_t n, uint64_t qp),
    (r, a, n, qp))
NEV_SVE2_SHIM(NEV_Sub2Arr,
    (int16_t *r, const int16_t *a, const int16_t *b, const int16_t *c, uint64_t n), (r, a, b, c, n))
NEV_SVE2_SHIM(NEV_Comb4,
    (int16_t *r, const int16_t *a, const int16_t *b, const int16_t *c, const int16_t *d,
    uint64_t n), (r, a, b, c, d, n))
NEV_SVE2_SHIM(NEV_CopyBlocks,
    (int16_t *r, const int16_t *a, uint64_t db, uint64_t stride), (r, a, db, stride))
NEV_SVE2_SHIM(NEV_MulYComb,
    (int16_t *r, const int16_t *a, const int16_t *a2, const int16_t *b, const int16_t *b2,
    const int16_t *y, uint64_t geom, uint64_t qb), (r, a, a2, b, b2, y, geom, qb))
NEV_SVE2_SHIM(NEV_MontMul4,
    (int16_t *r, const int16_t *a, const int16_t *b, uint64_t dim, uint64_t qb, uint64_t dbl),
    (r, a, b, dim, qb, dbl))
NEV_SVE2_SHIM(NEV_PolyMulRed4,
    (int16_t *r, const int16_t *a, const int16_t *b, const int16_t *y, uint64_t dim, uint64_t qb),
    (r, a, b, y, dim, qb))
NEV_SVE2_SHIM(NEV_PolyMulComb,
    (int16_t *r, const int16_t *t0, const int16_t *t1, const int16_t *t2, const int16_t *y,
    uint64_t geom, uint64_t qb), (r, t0, t1, t2, y, geom, qb))
NEV_SVE2_SHIM(NEV_MontSquare4,
    (int16_t *r, const int16_t *a, uint64_t dim, uint64_t qp), (r, a, dim, qp))
NEV_SVE2_SHIM(NEV_MontMul8Tail, (int16_t *r, const int16_t *t1, uint64_t dim, uint64_t qb),
    (r, t1, dim, qb))
NEV_SVE2_SHIM(NEV_Inv4Norm,
    (int16_t *a20, int16_t *a21, int16_t *s, const int16_t *a, const int16_t *y,
    uint64_t dim, uint64_t qb), (a20, a21, s, a, y, dim, qb))
NEV_SVE2_SHIM(NEV_Inv4Finish,
    (int16_t *r, const int16_t *a, const int16_t *a20, const int16_t *a21,
    const int16_t *sInv, const int16_t *y, uint64_t dim, uint64_t qb),
    (r, a, a20, a21, sInv, y, dim, qb))

#define NEV_AddArrAsm NevNEV_AddArr
#define NEV_SubArrAsm NevNEV_SubArr
#define NEV_NegArrAsm NevNEV_NegArr
#define NEV_CaddqArrAsm NevNEV_CaddqArr
#define NEV_BarrettArrAsm NevNEV_BarrettArr
#define NEV_MontArrAsm NevNEV_MontArr
#define NEV_AddBarrettArrAsm NevNEV_AddBarrettArr
#define NEV_BarrettCaddqArrAsm NevNEV_BarrettCaddqArr
#define NEV_AddBarrettCaddqArrAsm NevNEV_AddBarrettCaddqArr
#define NEV_MontCaddqArrAsm NevNEV_MontCaddqArr
#define NEV_Sub2ArrAsm NevNEV_Sub2Arr
#define NEV_Comb4Asm NevNEV_Comb4
#define NEV_CopyBlocksAsm NevNEV_CopyBlocks
#define NEV_MulYCombAsm NevNEV_MulYComb
#define NEV_MontMul4Asm NevNEV_MontMul4
#define NEV_PolyMulRed4Asm NevNEV_PolyMulRed4
#define NEV_PolyMulCombAsm NevNEV_PolyMulComb
#define NEV_MontSquare4Asm NevNEV_MontSquare4
#define NEV_MontMul8TailAsm NevNEV_MontMul8Tail
#define NEV_Inv4NormAsm NevNEV_Inv4Norm
#define NEV_Inv4FinishAsm NevNEV_Inv4Finish
#endif

/* Packed runtime constants, computed once per top-level operation. */
static inline uint64_t NevQPack(const CRYPT_NevInfo *info)
{
    return (uint64_t)info->q | ((uint64_t)info->qinv << 16);
}

static inline uint64_t NevBPack(const CRYPT_NevInfo *info)
{
    return (uint64_t)info->q | ((uint64_t)(uint16_t)info->barrettV << 16) |
        ((uint64_t)info->barrettShift << 32);
}

static inline uint64_t NevQbPack(const CRYPT_NevInfo *info)
{
    return (uint64_t)info->q | ((uint64_t)info->qinv << 16) |
        ((uint64_t)(uint16_t)info->barrettV << 32) | ((uint64_t)info->barrettShift << 48);
}

/* NEV_MulYCombAsm geometry word: dim | blocks<<16 | rStride<<24 | signs. */
#define NEV_SIGN_A2_MINUS (1ULL << 40)  // subtract the a2 operand
#define NEV_SIGN_MR_MINUS (1ULL << 41)  // subtract the MR((b +/- b2) * y) term
#define NEV_SIGN_B2_MINUS (1ULL << 42)  // subtract b2 inside the product

static inline uint64_t NevGeom(int32_t dim, int32_t blocks, int32_t rStride, uint64_t signs)
{
    return (uint64_t)dim | ((uint64_t)blocks << 16) | ((uint64_t)rStride << 24) | signs;
}

/* Shared all-zero source for unused NEV_MulYCombAsm operands.  The kernel
 * advances a2/b2 by dim per block, so this must cover the largest
 * multi-block use: 15 blocks x 64 (t = 32) / 7 blocks x 128 (t = 16). */
static const int16_t NEV_ZERO_BLOCK[NEV_N_MAX / 2] = {0};

/*
 * Evaluation points y_i (Montgomery domain) of the incomplete NTT, one table
 * per q; identical to the tables in nev_poly.c. Generation script (verified
 * against all three tables):
 *
 *   # psi = 7 (q = 769, dim = 128), 21 (q = 1409, dim = 64),
 *   #       17 (q = 3329, dim = 128): the 2*dim-th root of unity used by
 *   # the reference NTT. y_{2k} is the (bit-reversed) power of psi at which
 *   # CRT slot 2k evaluates X^t, in Montgomery form; slot 2k+1 uses -y_{2k}.
 *
 *   def bitrev(x, n):
 *       r = 0
 *       for _ in range(n): r = (r << 1) | (x & 1); x >>= 1
 *       return r
 *
 *   def mod_pm(a, q):  # signed representative in [-(q-1)/2, (q-1)/2]
 *       r = a % q
 *       return r - q if r > q // 2 else r
 *
 *   def gen_y(q, dim, psi):  # -> dim entries
 *       lg = dim.bit_length() - 1
 *       mont = 2**16 % q
 *       y = []
 *       for k in range(dim // 2):
 *           z = mod_pm(mont * pow(psi, bitrev(dim // 2 + k, lg), q), q)
 *           y += [z, -z]
 *       return y
 */
static const int16_t NTT_Y_769[128] = {
    -341, 341, -379, 379, 202, -202, 220, -220,
    236, -236, 21, -21, 212, -212, 71, -71,
    -134, 134, 151, -151, 23, -23, -112, 112,
    -232, 232, 227, -227, -52, 52, -148, 148,
    244, -244, -252, 252, -237, 237, -83, 83,
    -117, 117, -333, 333, -66, 66, -247, 247,
    -292, 292, 352, -352, -145, 145, 238, -238,
    -276, 276, -194, 194, -274, 274, -70, 70,
    209, -209, -115, 115, -99, 99, 14, -14,
    29, -29, 260, -260, -378, 378, -366, 366,
    355, -355, -291, 291, 358, -358, -105, 105,
    167, -167, 357, -357, -241, 241, -331, 331,
    -348, 348, -44, 44, -78, 78, -222, 222,
    -350, 350, -168, 168, -158, 158, 201, -201,
    303, -303, 330, -330, -184, 184, 127, -127,
    318, -318, -278, 278, -353, 353, -354, 354
};

static const int16_t NTT_Y_3329[128] = {
    -1103, 1103, 430, -430, 555, -555, 843, -843,
    -1251, 1251, 871, -871, 1550, -1550, 105, -105,
    422, -422, 587, -587, 177, -177, -235, 235,
    -291, 291, -460, 460, 1574, -1574, 1653, -1653,
    -246, 246, 778, -778, 1159, -1159, -147, 147,
    -777, 777, 1483, -1483, -602, 602, 1119, -1119,
    -1590, 1590, 644, -644, -872, 872, 349, -349,
    418, -418, 329, -329, -156, 156, -75, 75,
    817, -817, 1097, -1097, 603, -603, 610, -610,
    1322, -1322, -1285, 1285, -1465, 1465, 384, -384,
    -1215, 1215, -136, 136, 1218, -1218, -1335, 1335,
    -874, 874, 220, -220, -1187, 1187, -1659, 1659,
    -1185, 1185, -1530, 1530, -1278, 1278, 794, -794,
    -1510, 1510, -854, 854, -870, 870, 478, -478,
    -108, 108, -308, 308, 996, -996, 991, -991,
    958, -958, -1460, 1460, 1522, -1522, 1628, -1628
};

static const int16_t NTT_Y_1409[64] = {
    -337, 337, -152, 152, -328, 328, -311, 311,
    299, -299, -116, 116, -102, 102, 393, -393,
    -462, 462, -292, 292, -111, 111, 552, -552,
    389, -389, -297, 297, 249, -249, -172, 172,
    -672, 672, 600, -600, 479, -479, -478, 478,
    -587, 587, -432, 432, 106, -106, 6, -6,
    563, -563, -553, 553, 364, -364, -325, 325,
    -349, 349, 60, -60, -93, 93, 234, -234
};

static const int16_t *NevNttY(const CRYPT_NevInfo *info)
{
    if (info->q == 769) {
        return NTT_Y_769;
    }
    if (info->q == 3329) {
        return NTT_Y_3329;
    }
    return NTT_Y_1409;
}

/*
 * Sixteen-lane Fermat inversion, one function per q.  Lane j runs exactly the
 * addition chain of the scalar Mont2Inv* in nev_poly_core.inc, in the same
 * order, so it returns Mont2Inv(v[j]) bit-for-bit.
 *
 * NevFqMul8 is NEV_FqMul lane-wise, not an approximation of it: smull/smull2
 * form the exact int32 product, uzp1 takes its low half (the C
 * (int16_t)a cast), mul by qinv is the C 16-bit truncating product, smlsl /
 * smlsl2 subtract t*q in int32, and uzp2 takes the high half, which is the C
 * >> 16.  Every step is a full-width operation on the same bit patterns, so no
 * lane can differ from the scalar result for any int16 input.
 */
static inline int16x8_t NevFqMul8(int16x8_t a, int16x8_t b, int16x8_t q, int16x8_t qinv)
{
    int32x4_t lo = vmull_s16(vget_low_s16(a), vget_low_s16(b));
    int32x4_t hi = vmull_high_s16(a, b);
    int16x8_t t = vuzp1q_s16(vreinterpretq_s16_s32(lo), vreinterpretq_s16_s32(hi));
    t = vmulq_s16(t, qinv);
    lo = vmlsl_s16(lo, vget_low_s16(t), vget_low_s16(q));
    hi = vmlsl_high_s16(hi, t, q);
    return vuzp2q_s16(vreinterpretq_s16_s32(lo), vreinterpretq_s16_s32(hi));
}

#define NEV_FQ16(d, x, y)                                           \
    do {                                                            \
        (d)[0] = NevFqMul8((x)[0], (y)[0], q, qinv);                \
        (d)[1] = NevFqMul8((x)[1], (y)[1], q, qinv);                \
    } while (0)

static void Mont2Inv769x16(int16x8_t v[2], int16x8_t q, int16x8_t qinv)
{
    int16x8_t a[2], y0[2], y1[2];

    a[0] = v[0];
    a[1] = v[1];
    NEV_FQ16(y0, a, a);      // 2
    NEV_FQ16(y0, y0, y0);    // 4
    NEV_FQ16(y0, y0, y0);    // 8
    NEV_FQ16(y1, y0, y0);    // 16
    NEV_FQ16(y1, y1, y1);    // 32
    NEV_FQ16(y1, y1, y1);    // 64
    NEV_FQ16(y0, y1, y0);    // 72
    NEV_FQ16(y0, y0, a);     // 73
    NEV_FQ16(y1, y0, y1);    // 137
    NEV_FQ16(y1, y1, y1);    // 274
    NEV_FQ16(y1, y1, y0);    // 347
    NEV_FQ16(y1, y1, y1);    // 694
    NEV_FQ16(v, y1, y0);     // 767 = q - 2
}

static void Mont2Inv1409x16(int16x8_t v[2], int16x8_t q, int16x8_t qinv)
{
    int16x8_t a[2], y0[2], y1[2], y2[2], y3[2], y4[2], y5[2], y6[2];
    int16x8_t y7[2], y8[2], y9[2], y10[2], y11[2], y12[2];

    a[0] = v[0];
    a[1] = v[1];
    NEV_FQ16(y0, a, a);        // 2
    NEV_FQ16(y1, y0, y0);      // 4
    NEV_FQ16(y2, y1, y1);      // 8
    NEV_FQ16(y3, y2, y2);      // 16
    NEV_FQ16(y4, y3, y3);      // 32
    NEV_FQ16(y5, y4, y4);      // 64
    NEV_FQ16(y6, y5, y5);      // 128
    NEV_FQ16(y7, y5, y6);      // 192
    NEV_FQ16(y8, y7, y2);      // 200
    NEV_FQ16(y9, y8, a);       // 201
    NEV_FQ16(y10, y9, y9);     // 402
    NEV_FQ16(y11, y10, y10);   // 804
    NEV_FQ16(y12, y10, y11);   // 1206
    NEV_FQ16(v, y12, y9);      // 1407 = q - 2
}

static void Mont2Inv3329x16(int16x8_t v[2], int16x8_t q, int16x8_t qinv)
{
    int16x8_t a[2], y0[2], y1[2], y2[2], y3[2], y4[2], y5[2], y6[2];
    int16x8_t y7[2], y8[2], y9[2], y10[2], y11[2], y12[2], y13[2];

    a[0] = v[0];
    a[1] = v[1];
    NEV_FQ16(y0, a, a);        // 2
    NEV_FQ16(y1, y0, y0);      // 4
    NEV_FQ16(y2, y1, y1);      // 8
    NEV_FQ16(y3, y2, y2);      // 16
    NEV_FQ16(y4, y3, y3);      // 32
    NEV_FQ16(y5, y4, y4);      // 64
    NEV_FQ16(y6, y5, y5);      // 128
    NEV_FQ16(y7, y3, y6);      // 144
    NEV_FQ16(y8, y7, a);       // 145
    NEV_FQ16(y9, y8, y6);      // 273
    NEV_FQ16(y10, y9, y8);     // 418
    NEV_FQ16(y11, y10, y10);   // 836
    NEV_FQ16(y12, y11, y9);    // 1109
    NEV_FQ16(y13, y12, y12);   // 2218
    NEV_FQ16(v, y13, y12);     // 3327 = q - 2
}

static void Mont2Inv16(int16x8_t v[2], const CRYPT_NevInfo *info, int16x8_t q, int16x8_t qinv)
{
    if (info->q == 769) {
        Mont2Inv769x16(v, q, qinv);
        return;
    }
    if (info->q == 3329) {
        Mont2Inv3329x16(v, q, qinv);
        return;
    }
    Mont2Inv1409x16(v, q, qinv);
}

/*
 * Montgomery batch inversion of nttDim field elements; returns 0 if any element
 * is 0 mod q.  Split into L = 16 independent chunks of m = dim/16 (dim is 64 or
 * 128, so m is 4 or 8) and run the sixteen prefix-product recurrences as two
 * NEON lanes-wide chains.
 *
 * Why: the recurrence is a chain of dependent NEV_FqMul steps, each a
 * multiply-reduce whose latency far exceeds its throughput cost, so one chain
 * cannot keep the multiply pipes busy.  Sixteen chunks are independent, and -
 * this is what changed - chunk j is the set { a[16i + j] }, i.e. the chunks are
 * strided by one lane rather than contiguous.  That makes step i of all sixteen
 * recurrences a single contiguous 16-element load, so the whole recurrence runs
 * as vector NEV_FqMul (NevFqMul8) instead of one scalar multiply-reduce per
 * element: ~6x fewer instructions AND a chain a quarter as long.  Total
 * multiply work is unchanged (very slightly lower: each chunk's first element is
 * a copy, not a multiply).
 *
 * Exactness.  This is NOT the "verbatim from the reference" argument the single
 * chain used, so the equality is established directly:
 *
 *  - Outputs are congruent, chunk length cancels.  With FqMul(x,y) = xy R^-1
 *    and P the product of a chunk of length m, the forward pass ends at
 *    T = P R^-(m-1); the Fermat step returns T^-1 R^2 = P^-1 R^(m+1); and the
 *    backward recurrence then yields r[i] = a[i]^-1 R^2 for every i, with the
 *    m-dependence cancelling.  So each output is in the same residue class as
 *    the single-chain version for ANY chunking, element for element.
 *  - The zero decision is bit-identical.  a[] here is the sArr produced by
 *    NEV_Inv4NormAsm, already canonical in [0, q).  A chunk total is a
 *    MontReduce output, so |T| <= q/2 + q^2/2^16 < q for all three q; hence
 *    T == 0 iff T = 0 mod q iff some element of that chunk is 0 (q prime).
 *    OR-ing the sixteen chunk tests is therefore the same predicate as the
 *    single test on the whole array - the chunks partition the same index set,
 *    whatever their stride - so the return value, and with it the keygen retry
 *    count and nonce sequence, is unchanged.
 *  - Bytes out are identical, not merely congruent.  MontReduce returns a
 *    representative in (-q, q), not a canonical one, so a small fraction of the
 *    raw r[] entries do differ from the single-chain values by exactly q.  They
 *    never escape: r[] is consumed only by NEV_Inv4FinishAsm, every output of
 *    which passes through the exact Barrett (verified exhaustively over all
 *    int16 inputs, see the .S header) that maps each class to its unique
 *    centered representative.  Mont2Inverse4's polynomial output is therefore
 *    bit-identical, which is what the packed key bytes depend on.
 *
 * Ranges are unchanged: every intermediate is still MontReduce(x*y) with
 * |x|,|y| <= q-1, and the chunk anchors are copies of inputs already bounded by
 * q-1, so the RANGE-VERIFY anchors in nev_poly.c need no revision.
 */
static int32_t BatchMont2Inv(int16_t *r, const int16_t *a, const CRYPT_NevInfo *info)
{
#ifdef HITLS_CRYPTO_NEV_SVE2
    if (NEV_Sve2Enabled() != 0) {
        return NEV_BatchMont2InvSve2(r, a, info->nttDim, NevQPack(info));
    }
#endif
    int32_t i;
    const int32_t m = info->nttDim / 16;
    const int16x8_t q = vdupq_n_s16((int16_t)info->q);
    const int16x8_t qinv = vdupq_n_s16((int16_t)info->qinv);
    int16x8_t acc[2];

    acc[0] = vld1q_s16(&a[0]);
    acc[1] = vld1q_s16(&a[8]);
    vst1q_s16(&r[0], acc[0]);
    vst1q_s16(&r[8], acc[1]);
    for (i = 1; i < m; i++) {
        acc[0] = NevFqMul8(acc[0], vld1q_s16(&a[16 * i]), q, qinv);
        acc[1] = NevFqMul8(acc[1], vld1q_s16(&a[16 * i + 8]), q, qinv);
        vst1q_s16(&r[16 * i], acc[0]);
        vst1q_s16(&r[16 * i + 8], acc[1]);
    }

    // "some chunk total is zero", branch-free across the sixteen lanes.
    if (vmaxvq_u16(vorrq_u16(vceqzq_s16(acc[0]), vceqzq_s16(acc[1]))) != 0) {
        return 0;
    }

    Mont2Inv16(acc, info, q, qinv);

    for (i = m - 1; i > 0; i--) {
        int16x8_t t0 = NevFqMul8(acc[0], vld1q_s16(&r[16 * (i - 1)]), q, qinv);
        int16x8_t t1 = NevFqMul8(acc[1], vld1q_s16(&r[16 * (i - 1) + 8]), q, qinv);
        acc[0] = NevFqMul8(acc[0], vld1q_s16(&a[16 * i]), q, qinv);
        acc[1] = NevFqMul8(acc[1], vld1q_s16(&a[16 * i + 8]), q, qinv);
        vst1q_s16(&r[16 * i], t0);
        vst1q_s16(&r[16 * i + 8], t1);
    }

    vst1q_s16(&r[0], acc[0]);
    vst1q_s16(&r[8], acc[1]);
    return 1;
}

/*
 * Karatsuba product of two degree-7 slot elements (8 blocks in, 15 blocks out).
 * Operand sums are Barrett-normalized (congruent), so the middle MontMul4
 * operands are <= (q-1)/2; the recombination runs in the fused tail kernel.
 * dbl != 0 computes (2a) * b (the kernels double the b-side strips).
 */
static void MontMul8(int16_t *r, const int16_t *a, const int16_t *b, const CRYPT_NevInfo *info,
    uint64_t qb, uint64_t dbl)
{
    int16_t t1[7 * NEV_NTT_DIM_MAX];
    int16_t t2[4 * NEV_NTT_DIM_MAX];
    const int32_t dim = info->nttDim;

    NEV_AddBarrettArrAsm(t1, a, &a[4 * dim], (uint64_t)(4 * dim), qb);
    NEV_AddBarrettArrAsm(t2, b, &b[4 * dim], (uint64_t)(4 * dim), qb);
    NEV_MontMul4Asm(t1, t1, t2, (uint64_t)dim, qb, dbl);
    NEV_MontMul4Asm(&r[8 * dim], &a[4 * dim], &b[4 * dim], (uint64_t)dim, qb, dbl);
    NEV_MontMul4Asm(r, a, b, (uint64_t)dim, qb, dbl);
    NEV_MontMul8TailAsm(r, t1, (uint64_t)dim, qb);
}

/* Square of a degree-7 slot element (8 blocks in, 15 blocks out). */
static void MontSquare8(int16_t *r, const int16_t *a, const CRYPT_NevInfo *info,
    uint64_t qp, uint64_t qb)
{
    int16_t t1[7 * NEV_NTT_DIM_MAX];
    const int32_t dim = info->nttDim;

    NEV_MontMul4Asm(t1, a, &a[4 * dim], (uint64_t)dim, qb, 1);          // 2 * a_lo * a_hi
    NEV_MontSquare4Asm(&r[8 * dim], &a[4 * dim], (uint64_t)dim, qp);
    NEV_MontSquare4Asm(r, a, (uint64_t)dim, qp);

    // reference: r7 = Barrett(t1_3); t1_3 is already Barrett-normalized in-kernel
    NEV_CopyBlocksAsm(&r[7 * dim], &t1[3 * dim], (uint64_t)dim | (1ULL << 16), (uint64_t)dim);
    NEV_AddBarrettArrAsm(&r[4 * dim], &r[4 * dim], t1, (uint64_t)(3 * dim), qb);
    NEV_AddBarrettArrAsm(&r[8 * dim], &r[8 * dim], &t1[4 * dim], (uint64_t)(3 * dim), qb);
}

/* Karatsuba product of two degree-15 slot elements (16 blocks in, 31 blocks out).
 * Only reached for q = 1409 (t = 32), which keeps every recombination row wrap-free. */
static void MontMul16(int16_t *r, const int16_t *a, const int16_t *b, const CRYPT_NevInfo *info,
    uint64_t qb)
{
    int16_t t1[15 * NEV_NTT_DIM_MAX];
    int16_t t2[8 * NEV_NTT_DIM_MAX];
    const int32_t dim = info->nttDim;

    NEV_AddBarrettArrAsm(t1, a, &a[8 * dim], (uint64_t)(8 * dim), qb);
    NEV_AddBarrettArrAsm(t2, b, &b[8 * dim], (uint64_t)(8 * dim), qb);
    MontMul8(t1, t1, t2, info, qb, 0);
    MontMul8(&r[16 * dim], &a[8 * dim], &b[8 * dim], info, qb, 0);
    MontMul8(r, a, b, info, qb, 0);

    NEV_Sub2ArrAsm(&r[15 * dim], &t1[7 * dim], &r[7 * dim], &r[23 * dim], (uint64_t)dim);
    NEV_Comb4Asm(t1, &r[8 * dim], t1, r, &r[16 * dim], (uint64_t)(7 * dim));
    NEV_Comb4Asm(&r[16 * dim], &t1[8 * dim], &r[16 * dim], &r[8 * dim], &r[24 * dim],
        (uint64_t)(7 * dim));
    NEV_CopyBlocksAsm(&r[8 * dim], t1, (uint64_t)dim | (7ULL << 16), (uint64_t)dim);
}

/* Square of a degree-15 slot element (16 blocks in, 31 blocks out); q = 1409 only. */
static void MontSquare16(int16_t *r, const int16_t *a, const CRYPT_NevInfo *info,
    uint64_t qp, uint64_t qb)
{
    int16_t t0[15 * NEV_NTT_DIM_MAX];
    int16_t t1[15 * NEV_NTT_DIM_MAX];
    int16_t t2[15 * NEV_NTT_DIM_MAX];
    const int32_t dim = info->nttDim;

    MontSquare8(t0, a, info, qp, qb);
    MontMul8(t1, a, &a[8 * dim], info, qb, 1);                          // 2 * a_lo * a_hi
    MontSquare8(t2, &a[8 * dim], info, qp, qb);

    NEV_CopyBlocksAsm(r, t0, (uint64_t)dim | (8ULL << 16), (uint64_t)dim);
    NEV_AddArrAsm(&r[8 * dim], &t0[8 * dim], t1, (uint64_t)(7 * dim));
    NEV_CopyBlocksAsm(&r[15 * dim], &t1[7 * dim], (uint64_t)dim | (1ULL << 16), (uint64_t)dim);
    NEV_AddArrAsm(&r[16 * dim], &t1[8 * dim], t2, (uint64_t)(7 * dim));
    NEV_CopyBlocksAsm(&r[23 * dim], &t2[7 * dim], (uint64_t)dim | (8ULL << 16), (uint64_t)dim);
}

/* Inversion of a degree-3 slot element via the norm map to F_q and batch inversion.
 * Outputs are Barrett-normalized in NEV_Inv4FinishAsm: |r| <= (q-1)/2. */
static int32_t Mont2Inverse4(int16_t *r, const int16_t *a, const CRYPT_NevInfo *info, uint64_t qb)
{
    int16_t a20[NEV_NTT_DIM_MAX];
    int16_t a21[NEV_NTT_DIM_MAX];
    int16_t sArr[NEV_NTT_DIM_MAX];
    int16_t sInv[NEV_NTT_DIM_MAX];
    const int32_t dim = info->nttDim;
    const int16_t *nttY = NevNttY(info);

    NEV_Inv4NormAsm(a20, a21, sArr, a, nttY, (uint64_t)dim, qb);

    if (BatchMont2Inv(sInv, sArr, info) == 0) {
        return 0;
    }

    NEV_Inv4FinishAsm(r, a, a20, a21, sInv, nttY, (uint64_t)dim, qb);
    return 1;
}

/* Invertibility test for a degree-3 slot element (norm map only). */
static int32_t Mont2Inverse4Judge(const int16_t *a, const CRYPT_NevInfo *info, uint64_t qb)
{
    int16_t a20[NEV_NTT_DIM_MAX];
    int16_t a21[NEV_NTT_DIM_MAX];
    int16_t sArr[NEV_NTT_DIM_MAX];
    int32_t i;
    const int32_t dim = info->nttDim;
    uint16x8_t acc;

    NEV_Inv4NormAsm(a20, a21, sArr, a, NevNttY(info), (uint64_t)dim, qb);

    /*
     * NEV_Inv4NormAsm leaves sArr canonical in [0, q), so an unsigned
     * minimum is zero exactly when at least one coefficient has no inverse.
     * Both supported dimensions are multiples of eight.
     */
    acc = vld1q_u16((const uint16_t *)sArr);
    for (i = 8; i < dim; i += 8) {
        acc = vminq_u16(acc, vld1q_u16((const uint16_t *)&sArr[i]));
    }
    return (vminvq_u16(acc) == 0) ? 0 : 1;
}

/*
 * Split a into even/odd halves and reduce the degree-7 inversion to a degree-3
 * one.  The recombination rows merge the reference's MR(x*y) terms
 * (congruent); b0 is Barrett-normalized before it feeds the next level.
 */
static void Mont2Inverse8Norm(int16_t *t0, int16_t *t1, int16_t *b0, int16_t *b1, const int16_t *a,
    const CRYPT_NevInfo *info, uint64_t qp, uint64_t qb)
{
    const int32_t dim = info->nttDim;
    const int16_t *nttY = NevNttY(info);

    NEV_CopyBlocksAsm(t0, a, (uint64_t)dim | (4ULL << 16), (uint64_t)(2 * dim));
    NEV_CopyBlocksAsm(t1, &a[dim], (uint64_t)dim | (4ULL << 16), (uint64_t)(2 * dim));

    NEV_MontSquare4Asm(b0, t0, (uint64_t)dim, qp);
    NEV_MontSquare4Asm(b1, t1, (uint64_t)dim, qp);

    // b0_0 = b0_0 + MR((b0_4 - b1_3) * y)
    NEV_MulYCombAsm(b0, b0, NEV_ZERO_BLOCK, &b0[4 * dim], &b1[3 * dim], nttY,
        NevGeom(dim, 1, dim, NEV_SIGN_B2_MINUS), qb);
    // b0_{1+i} = b0_{1+i} - b1_i + MR((b0_{5+i} - b1_{4+i}) * y), i = 0..1
    NEV_MulYCombAsm(&b0[dim], &b0[dim], b1, &b0[5 * dim], &b1[4 * dim], nttY,
        NevGeom(dim, 2, dim, NEV_SIGN_A2_MINUS | NEV_SIGN_B2_MINUS), qb);
    // b0_3 = b0_3 - b1_2 - MR(b1_6 * y)
    NEV_MulYCombAsm(&b0[3 * dim], &b0[3 * dim], &b1[2 * dim], &b1[6 * dim], NEV_ZERO_BLOCK, nttY,
        NevGeom(dim, 1, dim, NEV_SIGN_A2_MINUS | NEV_SIGN_MR_MINUS), qb);

    NEV_BarrettArrAsm(b0, b0, (uint64_t)(4 * dim), NevBPack(info));
}

/* Inversion of a degree-7 slot element via the tower F_q[x]/(x^8-y) over F_q[x]/(x^4-y'). */
static int32_t Mont2Inverse8(int16_t *r, const int16_t *a, const CRYPT_NevInfo *info,
    uint64_t qp, uint64_t qb)
{
    int16_t t0[4 * NEV_NTT_DIM_MAX];
    int16_t t1[4 * NEV_NTT_DIM_MAX];
    int16_t b0[7 * NEV_NTT_DIM_MAX];
    int16_t b1[7 * NEV_NTT_DIM_MAX];
    const int32_t dim = info->nttDim;
    const int16_t *nttY = NevNttY(info);

    Mont2Inverse8Norm(t0, t1, b0, b1, a, info, qp, qb);

    if (Mont2Inverse4(b1, b0, info, qb) == 0) {
        return 0;
    }

    NEV_MontMul4Asm(b0, b1, t0, (uint64_t)dim, qb, 0);
    NEV_MontMul4Asm(b1, b1, t1, (uint64_t)dim, qb, 0);

    // r_{2i} = b0_i + MR(b0_{4+i} * y); r_{2i+1} = -b1_i - MR(b1_{4+i} * y)
    NEV_MulYCombAsm(r, b0, NEV_ZERO_BLOCK, &b0[4 * dim], NEV_ZERO_BLOCK, nttY,
        NevGeom(dim, 3, 2 * dim, 0), qb);
    NEV_MulYCombAsm(&r[dim], NEV_ZERO_BLOCK, b1, &b1[4 * dim], NEV_ZERO_BLOCK, nttY,
        NevGeom(dim, 3, 2 * dim, NEV_SIGN_A2_MINUS | NEV_SIGN_MR_MINUS), qb);
    NEV_CopyBlocksAsm(&r[6 * dim], &b0[3 * dim], (uint64_t)dim | (1ULL << 16), (uint64_t)dim);
    NEV_NegArrAsm(&r[7 * dim], &b1[3 * dim], (uint64_t)dim);

    NEV_BarrettArrAsm(r, r, (uint64_t)(8 * dim), NevBPack(info));
    return 1;
}

static int32_t Mont2Inverse8Judge(const int16_t *a, const CRYPT_NevInfo *info,
    uint64_t qp, uint64_t qb)
{
    int16_t t0[4 * NEV_NTT_DIM_MAX];
    int16_t t1[4 * NEV_NTT_DIM_MAX];
    int16_t b0[7 * NEV_NTT_DIM_MAX];
    int16_t b1[7 * NEV_NTT_DIM_MAX];

    Mont2Inverse8Norm(t0, t1, b0, b1, a, info, qp, qb);

    return Mont2Inverse4Judge(b0, info, qb);
}

/* Split a into even/odd halves and reduce the degree-15 inversion to a degree-7 one. */
static void Mont2Inverse16Norm(int16_t *t0, int16_t *t1, int16_t *b0, int16_t *b1, const int16_t *a,
    const CRYPT_NevInfo *info, uint64_t qp, uint64_t qb)
{
    const int32_t dim = info->nttDim;
    const int16_t *nttY = NevNttY(info);

    NEV_CopyBlocksAsm(t0, a, (uint64_t)dim | (8ULL << 16), (uint64_t)(2 * dim));
    NEV_CopyBlocksAsm(t1, &a[dim], (uint64_t)dim | (8ULL << 16), (uint64_t)(2 * dim));

    MontSquare8(b0, t0, info, qp, qb);
    MontSquare8(b1, t1, info, qp, qb);

    // b0_0 = b0_0 + MR((b0_8 - b1_7) * y)
    NEV_MulYCombAsm(b0, b0, NEV_ZERO_BLOCK, &b0[8 * dim], &b1[7 * dim], nttY,
        NevGeom(dim, 1, dim, NEV_SIGN_B2_MINUS), qb);
    // b0_{1+i} = b0_{1+i} - b1_i + MR((b0_{9+i} - b1_{8+i}) * y), i = 0..5
    NEV_MulYCombAsm(&b0[dim], &b0[dim], b1, &b0[9 * dim], &b1[8 * dim], nttY,
        NevGeom(dim, 6, dim, NEV_SIGN_A2_MINUS | NEV_SIGN_B2_MINUS), qb);
    // b0_7 = b0_7 - b1_6 - MR(b1_14 * y)
    NEV_MulYCombAsm(&b0[7 * dim], &b0[7 * dim], &b1[6 * dim], &b1[14 * dim], NEV_ZERO_BLOCK, nttY,
        NevGeom(dim, 1, dim, NEV_SIGN_A2_MINUS | NEV_SIGN_MR_MINUS), qb);

    NEV_BarrettArrAsm(b0, b0, (uint64_t)(8 * dim), NevBPack(info));
}

/* Inversion of a degree-15 slot element. */
static int32_t Mont2Inverse16(int16_t *r, const int16_t *a, const CRYPT_NevInfo *info,
    uint64_t qp, uint64_t qb)
{
    int16_t t0[8 * NEV_NTT_DIM_MAX];
    int16_t t1[8 * NEV_NTT_DIM_MAX];
    int16_t b0[15 * NEV_NTT_DIM_MAX];
    int16_t b1[15 * NEV_NTT_DIM_MAX];
    const int32_t dim = info->nttDim;
    const int16_t *nttY = NevNttY(info);

    Mont2Inverse16Norm(t0, t1, b0, b1, a, info, qp, qb);

    if (Mont2Inverse8(b1, b0, info, qp, qb) == 0) {
        return 0;
    }

    MontMul8(b0, b1, t0, info, qb, 0);
    MontMul8(b1, b1, t1, info, qb, 0);

    // r_{2i} = b0_i + MR(b0_{8+i} * y) (i = 0..6), r_14 = b0_7
    NEV_MulYCombAsm(r, b0, NEV_ZERO_BLOCK, &b0[8 * dim], NEV_ZERO_BLOCK, nttY,
        NevGeom(dim, 7, 2 * dim, 0), qb);
    NEV_CopyBlocksAsm(&r[14 * dim], &b0[7 * dim], (uint64_t)dim | (1ULL << 16), (uint64_t)dim);
    // r_{2i+1} = -(b1_i + MR(b1_{8+i} * y)) (i = 0..6), r_15 = -b1_7
    NEV_MulYCombAsm(&r[dim], NEV_ZERO_BLOCK, b1, &b1[8 * dim], NEV_ZERO_BLOCK, nttY,
        NevGeom(dim, 7, 2 * dim, NEV_SIGN_A2_MINUS | NEV_SIGN_MR_MINUS), qb);
    NEV_NegArrAsm(&r[15 * dim], &b1[7 * dim], (uint64_t)dim);

    NEV_BarrettArrAsm(r, r, (uint64_t)(16 * dim), NevBPack(info));
    return 1;
}

static int32_t Mont2Inverse16Judge(const int16_t *a, const CRYPT_NevInfo *info,
    uint64_t qp, uint64_t qb)
{
    int16_t t0[8 * NEV_NTT_DIM_MAX];
    int16_t t1[8 * NEV_NTT_DIM_MAX];
    int16_t b0[15 * NEV_NTT_DIM_MAX];
    int16_t b1[15 * NEV_NTT_DIM_MAX];

    Mont2Inverse16Norm(t0, t1, b0, b1, a, info, qp, qb);

    return Mont2Inverse8Judge(b0, info, qp, qb);
}

/* Split a into even/odd halves and reduce the degree-31 inversion to a degree-15 one.
 * t = 32 occurs only for NEV-2048-1409 (nttDim 64), so 16 * dim <= NEV_N_MAX / 2. */
static void Mont2Inverse32Norm(int16_t *t0, int16_t *t1, int16_t *b0, int16_t *b1, const int16_t *a,
    const CRYPT_NevInfo *info, uint64_t qp, uint64_t qb)
{
    const int32_t dim = info->nttDim;
    const int16_t *nttY = NevNttY(info);

    NEV_CopyBlocksAsm(t0, a, (uint64_t)dim | (16ULL << 16), (uint64_t)(2 * dim));
    NEV_CopyBlocksAsm(t1, &a[dim], (uint64_t)dim | (16ULL << 16), (uint64_t)(2 * dim));

    MontSquare16(b0, t0, info, qp, qb);
    MontSquare16(b1, t1, info, qp, qb);

    // b0_0 = b0_0 + MR((b0_16 - b1_15) * y)
    NEV_MulYCombAsm(b0, b0, NEV_ZERO_BLOCK, &b0[16 * dim], &b1[15 * dim], nttY,
        NevGeom(dim, 1, dim, NEV_SIGN_B2_MINUS), qb);
    // b0_{1+i} = b0_{1+i} - b1_i + MR((b0_{17+i} - b1_{16+i}) * y), i = 0..13
    NEV_MulYCombAsm(&b0[dim], &b0[dim], b1, &b0[17 * dim], &b1[16 * dim], nttY,
        NevGeom(dim, 14, dim, NEV_SIGN_A2_MINUS | NEV_SIGN_B2_MINUS), qb);
    // b0_15 = b0_15 - b1_14 - MR(b1_30 * y)
    NEV_MulYCombAsm(&b0[15 * dim], &b0[15 * dim], &b1[14 * dim], &b1[30 * dim], NEV_ZERO_BLOCK,
        nttY, NevGeom(dim, 1, dim, NEV_SIGN_A2_MINUS | NEV_SIGN_MR_MINUS), qb);

    NEV_BarrettArrAsm(b0, b0, (uint64_t)(16 * dim), NevBPack(info));
}

/* Inversion of a degree-31 slot element. */
static int32_t Mont2Inverse32(int16_t *r, const int16_t *a, const CRYPT_NevInfo *info,
    uint64_t qp, uint64_t qb)
{
    int16_t t0[NEV_N_MAX / 2];
    int16_t t1[NEV_N_MAX / 2];
    int16_t b0[NEV_N_MAX];
    int16_t b1[NEV_N_MAX];
    const int32_t dim = info->nttDim;
    const int16_t *nttY = NevNttY(info);

    Mont2Inverse32Norm(t0, t1, b0, b1, a, info, qp, qb);

    if (Mont2Inverse16(b1, b0, info, qp, qb) == 0) {
        return 0;
    }

    MontMul16(b0, b1, t0, info, qb);
    MontMul16(b1, b1, t1, info, qb);

    // r_{2i} = b0_i + MR(b0_{16+i} * y) (i = 0..14), r_30 = b0_15
    NEV_MulYCombAsm(r, b0, NEV_ZERO_BLOCK, &b0[16 * dim], NEV_ZERO_BLOCK, nttY,
        NevGeom(dim, 15, 2 * dim, 0), qb);
    NEV_CopyBlocksAsm(&r[30 * dim], &b0[15 * dim], (uint64_t)dim | (1ULL << 16), (uint64_t)dim);
    // r_{2i+1} = -(b1_i + MR(b1_{16+i} * y)) (i = 0..14), r_31 = -b1_15
    NEV_MulYCombAsm(&r[dim], NEV_ZERO_BLOCK, b1, &b1[16 * dim], NEV_ZERO_BLOCK, nttY,
        NevGeom(dim, 15, 2 * dim, NEV_SIGN_A2_MINUS | NEV_SIGN_MR_MINUS), qb);
    NEV_NegArrAsm(&r[31 * dim], &b1[15 * dim], (uint64_t)dim);

    NEV_BarrettArrAsm(r, r, (uint64_t)(32 * dim), NevBPack(info));
    return 1;
}

static int32_t Mont2Inverse32Judge(const int16_t *a, const CRYPT_NevInfo *info,
    uint64_t qp, uint64_t qb)
{
    int16_t t0[NEV_N_MAX / 2];
    int16_t t1[NEV_N_MAX / 2];
    int16_t b0[NEV_N_MAX];
    int16_t b1[NEV_N_MAX];

    Mont2Inverse32Norm(t0, t1, b0, b1, a, info, qp, qb);

    return Mont2Inverse16Judge(b0, info, qp, qb);
}

/* r = a * b mod (X^4 - y_i) per slot, t = 4: single fused kernel call. */
static void PolyMontMul4(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b,
    const CRYPT_NevInfo *info, uint64_t qb)
{
    NEV_PolyMulRed4Asm(r->coeffs, a->coeffs, b->coeffs, NevNttY(info), (uint64_t)info->nttDim, qb);
}

/*
 * Shared wrap-around recombination of PolyMontMul{8,16,32}: with the direct
 * products in t0 (low), t2 (high) and the middle product in t1, h = t/2
 * blocks per half:
 *     t1 -= t0 + t2                                (2h-1 blocks)
 *     r_i        = t0_i + MR((t2_i + t1_{h+i})*y)  i = 0..h-2
 *     r_{h-1}    = t0_{h-1} + MR(t2_{h-1}*y)
 *     r_{h+i}    = t0_{h+i} + t1_i + MR(t2_{h+i}*y)  i = 0..h-2
 *     r_{2h-1}   = t1_{h-1}
 * Congruent to the reference recombination (MR terms merged; range table).
 */
static void PolyMontMulComb(NEV_Poly *r, int16_t *t0, int16_t *t1, int16_t *t2,
    const CRYPT_NevInfo *info, int32_t h, uint64_t qb)
{
    const int32_t dim = info->nttDim;
    uint64_t geom = (uint64_t)(uint32_t)dim | ((uint64_t)(uint32_t)h << 32);

    NEV_PolyMulCombAsm(r->coeffs, t0, t1, t2, NevNttY(info), geom, qb);
}

/* r = a * b mod (X^8 - y_i) per slot, t = 8: one Karatsuba layer over MontMul4. */
static void PolyMontMul8(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b,
    const CRYPT_NevInfo *info, uint64_t qb)
{
    int16_t t0[NEV_N_MAX];
    int16_t t1[NEV_N_MAX];
    int16_t t2[NEV_N_MAX];
    const int32_t n = info->n;
    const int32_t dim = info->nttDim;

    NEV_AddBarrettArrAsm(t0, a->coeffs, &a->coeffs[n / 2], (uint64_t)(n / 2), qb);
    NEV_AddBarrettArrAsm(t1, b->coeffs, &b->coeffs[n / 2], (uint64_t)(n / 2), qb);

    NEV_MontMul4Asm(t1, t0, t1, (uint64_t)dim, qb, 0);
    NEV_MontMul4Asm(t0, a->coeffs, b->coeffs, (uint64_t)dim, qb, 0);
    NEV_MontMul4Asm(t2, &a->coeffs[n / 2], &b->coeffs[n / 2], (uint64_t)dim, qb, 0);

    PolyMontMulComb(r, t0, t1, t2, info, 4, qb);
}

/* r = a * b mod (X^16 - y_i) per slot, t = 16: one Karatsuba layer over MontMul8. */
static void PolyMontMul16(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b,
    const CRYPT_NevInfo *info, uint64_t qb)
{
    int16_t t0[NEV_N_MAX];
    int16_t t1[NEV_N_MAX];
    int16_t t2[NEV_N_MAX];
    const int32_t n = info->n;

    NEV_AddBarrettArrAsm(t0, a->coeffs, &a->coeffs[n / 2], (uint64_t)(n / 2), qb);
    NEV_AddBarrettArrAsm(t1, b->coeffs, &b->coeffs[n / 2], (uint64_t)(n / 2), qb);

    MontMul8(t1, t0, t1, info, qb, 0);
    MontMul8(t0, a->coeffs, b->coeffs, info, qb, 0);
    MontMul8(t2, &a->coeffs[n / 2], &b->coeffs[n / 2], info, qb, 0);

    PolyMontMulComb(r, t0, t1, t2, info, 8, qb);
}

/* r = a * b mod (X^32 - y_i) per slot, t = 32: one Karatsuba layer over MontMul16. */
static void PolyMontMul32(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b,
    const CRYPT_NevInfo *info, uint64_t qb)
{
    int16_t t0[NEV_N_MAX];
    int16_t t1[NEV_N_MAX];
    int16_t t2[NEV_N_MAX];
    const int32_t n = info->n;

    NEV_AddBarrettArrAsm(t0, a->coeffs, &a->coeffs[n / 2], (uint64_t)(n / 2), qb);
    NEV_AddBarrettArrAsm(t1, b->coeffs, &b->coeffs[n / 2], (uint64_t)(n / 2), qb);

    MontMul16(t1, t0, t1, info, qb);
    MontMul16(t0, a->coeffs, b->coeffs, info, qb);
    MontMul16(t2, &a->coeffs[n / 2], &b->coeffs[n / 2], info, qb);

    PolyMontMulComb(r, t0, t1, t2, info, 16, qb);
}

void NEV_PolyAdd(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b, const CRYPT_NevInfo *info)
{
    NEV_AddArrAsm(r->coeffs, a->coeffs, b->coeffs, info->n);
}

void NEV_PolyReduce(NEV_Poly *r, const CRYPT_NevInfo *info)
{
    NEV_BarrettArrAsm(r->coeffs, r->coeffs, info->n, NevBPack(info));
}

void NEV_PolyCaddq(NEV_Poly *r, const CRYPT_NevInfo *info)
{
    NEV_CaddqArrAsm(r->coeffs, r->coeffs, info->n, info->q);
}

void NEV_PolyReduceCaddqTo(NEV_Poly *r, const NEV_Poly *a, const CRYPT_NevInfo *info)
{
    NEV_BarrettCaddqArrAsm(r->coeffs, a->coeffs, info->n, NevQbPack(info));
}

void NEV_PolyCaddqTo(NEV_Poly *r, const NEV_Poly *a, const CRYPT_NevInfo *info)
{
    NEV_CaddqArrAsm(r->coeffs, a->coeffs, info->n, info->q);
}

void NEV_PolyAddVinv(NEV_Poly *f, const CRYPT_NevInfo *info)
{
    const uint16_t qdiv2 = (uint16_t)((info->q + 1) / 2);
    const int32_t dim = info->nttDim;

    f->coeffs[0] = (int16_t)(f->coeffs[0] + qdiv2);
    f->coeffs[dim / 2] = (int16_t)(f->coeffs[dim / 2] + qdiv2);
    f->coeffs[dim / 4] = (int16_t)(f->coeffs[dim / 4] + qdiv2);
    f->coeffs[dim * 3 / 4] = (int16_t)(f->coeffs[dim * 3 / 4] + qdiv2);
}

void NEV_PolyGetMontgomery(NEV_Poly *r, const CRYPT_NevInfo *info)
{
    NEV_MontArrAsm(r->coeffs, r->coeffs, info->n, NevQPack(info));
}

/* Fused canonicalization passes (bit-exact synchronization points, see
 * nev_local.h): each kernel composes the proven-exact Barrett / MontReduce
 * with the Caddq conditional add in a single memory pass. */

void NEV_PolyReduceCaddq(NEV_Poly *r, const CRYPT_NevInfo *info)
{
    NEV_BarrettCaddqArrAsm(r->coeffs, r->coeffs, info->n, NevQbPack(info));
}

void NEV_PolyAddReduceCaddq(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b,
    const CRYPT_NevInfo *info)
{
    NEV_AddBarrettCaddqArrAsm(r->coeffs, a->coeffs, b->coeffs, info->n, NevQbPack(info));
}

void NEV_PolyGetMontgomeryCaddq(NEV_Poly *r, const CRYPT_NevInfo *info)
{
    NEV_MontCaddqArrAsm(r->coeffs, r->coeffs, info->n, NevQPack(info));
}

void NEV_PolyMontMul(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b, const CRYPT_NevInfo *info)
{
    const int32_t t = info->n / info->nttDim;
    const uint64_t qb = NevQbPack(info);

    if (t == 4) {
        PolyMontMul4(r, a, b, info, qb);
    } else if (t == 8) {
        PolyMontMul8(r, a, b, info, qb);
    } else if (t == 16) {
        PolyMontMul16(r, a, b, info, qb);
    } else {
        PolyMontMul32(r, a, b, info, qb);
    }
}

int32_t NEV_PolyMont2Inverse(NEV_Poly *r, const NEV_Poly *a, const CRYPT_NevInfo *info)
{
    const int32_t t = info->n / info->nttDim;
    const uint64_t qp = NevQPack(info);
    const uint64_t qb = NevQbPack(info);

    if (t == 4) {
        return Mont2Inverse4(r->coeffs, a->coeffs, info, qb);
    }
    if (t == 8) {
        return Mont2Inverse8(r->coeffs, a->coeffs, info, qp, qb);
    }
    if (t == 16) {
        return Mont2Inverse16(r->coeffs, a->coeffs, info, qp, qb);
    }
    return Mont2Inverse32(r->coeffs, a->coeffs, info, qp, qb);
}

int32_t NEV_PolyMont2InverseJudge(const NEV_Poly *a, const CRYPT_NevInfo *info)
{
    const int32_t t = info->n / info->nttDim;
    const uint64_t qp = NevQPack(info);
    const uint64_t qb = NevQbPack(info);

    if (t == 4) {
        return Mont2Inverse4Judge(a->coeffs, info, qb);
    }
    if (t == 8) {
        return Mont2Inverse8Judge(a->coeffs, info, qp, qb);
    }
    if (t == 16) {
        return Mont2Inverse16Judge(a->coeffs, info, qp, qb);
    }
    return Mont2Inverse32Judge(a->coeffs, info, qp, qb);
}

#endif // HITLS_CRYPTO_NEV
