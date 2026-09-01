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

/*
 * ============================================================================
 * NEV polynomial arithmetic - ARMv8 NEON kernels (v2, congruence contract)
 * ============================================================================
 *
 * Runtime-parameterized (q in {769, 1409, 3329}) NEON kernels for the NEV
 * NTT-CRT polynomial arithmetic in asm_nev_poly.c.
 *
 * v2 correctness contract (ML-KEM discipline). The backend must produce
 * byte-identical results at every packed interface and identical
 * invertibility decisions, but internal representatives only need to be
 * CONGRUENT mod q within proven wrap-free ranges:
 *   - NEV_PolyAdd / NEV_PolyReduce / NEV_PolyCaddq / NEV_PolyGetMontgomery
 *     remain BIT-EXACT for every int16 input (they are the synchronization
 *     points; the exact Barrett was proven, exhaustively over all 65536
 *     int16 inputs for all three q, to return the unique centered
 *     representative, so it collapses any congruent difference).
 *   - The Karatsuba slot kernels exploit the linearity of Montgomery
 *     reduction mod q: instead of reducing every partial product as the
 *     reference does, each output is accumulated as a raw 32-bit linear
 *     combination of smull/smlal/smlsl products and reduced ONCE with the
 *     exact full-width Montgomery reduction (NEV_MRP below).  The result is
 *     congruent (not bit-equal) to the reference output and every store is
 *     provably wrap-free (int16 wrap-around would NOT be congruent since
 *     2^16 mod q != 0; see the range table).
 *   - Judge/inverse zero-tests: the s output of NEV_Inv4NormAsm is produced
 *     by the proven exact Barrett + Caddq from a wrap-free int16 value, so
 *     it is the unique standard representative in [0, q-1] of its class and
 *     therefore BIT-IDENTICAL to the reference s (the class only depends on
 *     the inputs mod q).  Every '== 0' decision downstream (kernel s array,
 *     scalar BatchMont2Inv prefix product) is unchanged.
 *
 * Modular primitives:
 *
 *  NEV_MRP (exact Montgomery reduction of 8 x int32 accumulator lanes,
 *  lanes 0-3 in \vlo\().4s, lanes 4-7 in \vhi\().4s):
 *      uzp1   t.8h, lo.8h, hi.8h      // low 16 bits of every 32-bit lane
 *      mul    t.8h, t.8h, qinv        // m = (int16)(lo16(P) * qinv)
 *      smlsl  lo.4s, t.4h, q          // P -= m*q: low 16 bits become zero
 *      smlsl2 hi.4s, t.8h, q
 *      uzp2   out.8h, lo.8h, hi.8h    // (P - m*q) >> 16
 *  This is exactly NEV_MontReduce(P) for any |P| <= 2^31 - 2^15*q - 1
 *  (|m*q| <= 2^15*q, so P - m*q never wraps int32, and its low 16 bits are
 *  zero because qinv*q == 1 mod 2^16).  All accumulators are bounded far
 *  below that (see table).  Output bound: |MR(P)| <= q/2 + |P|/2^16.
 *
 *  NEV_BR8 (exact Barrett reduction of 8 int16 lanes, 3 instructions):
 *      sqdmulh t.8h, x.8h, barrettV   // (2*x*v) >> 16
 *      srshl   t.8h, t.8h, -(shift-15)// rounding shift right
 *      mls     x.8h, t.8h, q
 *  With the per-q (barrettV, shift) pairs (21817,24)/(23814,25)/(20159,26)
 *  this equals NEV_BarrettReduce for ALL int16 inputs (proven exhaustively;
 *  re-verified by the differential harness sweep).  Output: unique centered
 *  representative, |out| <= (q-1)/2.
 *
 * Packed runtime constants (built once per top-level operation by the glue):
 *      qPacked  = q | qinv << 16
 *      qbPacked = q | qinv << 16 | (uint16)barrettV << 32 | barrettShift << 48
 *      bPacked  = q | (uint16)barrettV << 16 | barrettShift << 32  (legacy,
 *                 NEV_BarrettArrAsm / NEV_CaddqArrAsm only)
 *
 * ----------------------------------------------------------------------------
 * Range chain (worst case per q; script: scratchpad poly-v2/range_verify.py,
 * reproduced below).  Anchors:
 *   - NTT-domain operands of PolyMontMul / Mont2Inverse*: |x| <= W(q) with
 *     W = 1023 (q=769, 9.6-bit unpack), 2047 (q=1409), 4095 (q=3329) = the
 *     largest value NEV_PolyFromBytes can produce (malformed ciphertexts
 *     included); honest canonical values are <= q-1, post-NTT <= (q-1)/2.
 *   - every Karatsuba operand-sum pass uses NEV_AddBarrettArrAsm, so the
 *     "middle" product operands are always <= (q-1)/2;
 *   - every Mont2Inverse level and every Norm-map result is normalized with
 *     the exact Barrett before it feeds the next level (congruent, keeps all
 *     recursion operands <= (q-1)/2).
 *
 *   verifier output (q=3329, W=4095, the binding case):
 *     mm4  direct(W)   : [1920, 3200, 3456, 1664, 3456, 3200, 1920]
 *     mm4  dbl (q-1)   : [2003, 3693, 4031, 1664, 4031, 3693, 2003]
 *     sq4  (q-1)       : [1834, 2003, 2172, 3693, 2172, 2003, 1834]
 *     mm8  rows max(W) : 3456      sq8 rows max : 3693
 *     inv4 (q-1)       : a20 3554, a21 3883, s_pre 3570, finish_preB 5533
 *     norm8/16 row     : 9238      inv8/16 final row : 3978
 *     poly_mul out max : 5169 (t=4) / 13264 (t=8) / 12243 (t=16)
 *   q=1409 (t=32 exists only here): sq16 max 1832, mm16 max(W) 3765,
 *     norm32 row 4408, inv32 final row 3819, poly_mul t=32 out max 11921.
 *   All stores < 2^15, and max PolyMontMul row + (q-1)/2 < 2^15, so the
 *   int16 add in NEV_PolyAddReduceCaddq cannot wrap either (bit-exactness
 *   of that pass holds regardless: its add wraps identically to the C
 *   helper's int16 add).
 *   RANGE-VERIFY OK: every int16 store < 2^15, every int32 accum safe.
 *
 *   verifier script (python3; asserts abort on any wrap):
 *     I16 = 1 << 15; I32 = 1 << 31
 *     def MR(q, x):                     # exact MontReduce bound, 32b -> 16b
 *         assert x + I16 * q < I32
 *         return q // 2 + x // (1 << 16) + 1
 *     def BR(q, x):                     # exact Barrett: int16 -> centered
 *         assert x < I16
 *         return (q - 1) // 2
 *     def mm4(q, A, B, dbl=0):          # NEV_MontMul4Asm rows
 *         B *= (2 if dbl else 1)
 *         assert 4 * A < I16 and 4 * B < I16      # Karatsuba sums
 *         P, P01, PA, PA01 = A*B, 4*A*B, 4*A*B, 16*A*B
 *         return [MR(q, P), MR(q, P01 + 2*P), MR(q, PA + 3*P),
 *                 BR(q, MR(q, PA01 + 2*PA + 2*(P01 + 2*P))),
 *                 MR(q, PA + 3*P), MR(q, P01 + 2*P), MR(q, P)]
 *     def sq4(q, A):                    # NEV_MontSquare4Asm rows
 *         assert 4 * A < I16
 *         return [MR(q, A*A), MR(q, 2*A*A), MR(q, 3*A*A), MR(q, 12*A*A),
 *                 MR(q, 3*A*A), MR(q, 2*A*A), MR(q, A*A)]
 *     def mm8(q, A, B, dbl=0):          # MontMul8 glue + fused tail rows
 *         S = (q - 1) // 2              # AddBarrett'ed operand sums
 *         L = mm4(q, A, B, dbl); H = mm4(q, A, B, dbl); M = mm4(q, S, S, dbl)
 *         return (L[0:4]
 *             + [BR(q, L[4+i] + M[i] + L[i] + H[i]) for i in range(3)]
 *             + [BR(q, M[3] + L[3] + H[3])]
 *             + [BR(q, M[4+i] + L[4+i] + H[4+i] + H[i]) for i in range(3)]
 *             + H[3:7])
 *     def sq8(q, A):                    # MontSquare8 glue rows
 *         t1 = mm4(q, A, A, dbl=1); r = sq4(q, A); r2 = sq4(q, A)
 *         return (r[0:4] + [BR(q, r[4+i] + t1[i]) for i in range(3)]
 *             + [t1[3]] + [BR(q, r2[i] + t1[4+i]) for i in range(3)] + r2[3:7])
 *     def sq16(q, A):                   # MontSquare16 glue rows (q = 1409)
 *         t0 = sq8(q, A); t1 = mm8(q, A, A, 1); t2 = sq8(q, A)
 *         out = (t0[0:8] + [t0[8+i] + t1[i] for i in range(7)] + [t1[7]]
 *             + [t1[8+i] + t2[i] for i in range(7)] + t2[7:15])
 *         assert max(out) < I16; return out
 *     def mm16(q, A, B):                # MontMul16 glue rows (q = 1409)
 *         S = (q - 1) // 2
 *         L = mm8(q, A, B); H = mm8(q, A, B); M = mm8(q, S, S)
 *         t1p  = [L[8+i] + M[i] + L[i] + H[i] for i in range(7)]
 *         r16p = [M[8+i] + L[8+i] + H[8+i] + H[i] for i in range(7)]
 *         out = L[0:8] + t1p + [M[7]+L[7]+H[7]] + r16p + H[7:15]
 *         assert max(out) < I16; return out
 *     def poly_mul(q, t, W):            # PolyMontMul final rows + '+e' room
 *         S = (q - 1) // 2; y = q // 2
 *         if t == 4:
 *             D = mm4(q, W, W)
 *             rows = [D[i] + MR(q, D[4+i]*y) for i in range(3)] + [D[3]]
 *         else:
 *             core = {8: mm4, 16: mm8, 32: mm16}[t]
 *             T0 = core(q, W, W); T2 = core(q, W, W); T1 = core(q, S, S)
 *             t1r = [T1[i] + T0[i] + T2[i] for i in range(len(T0))]
 *             assert max(t1r) < I16     # Sub2 pass
 *             h = t // 2; rows = []
 *             for i in range(h - 1):
 *                 arg = T2[i] + t1r[h + i]; assert arg < I16
 *                 rows.append(T0[i] + MR(q, arg * y))
 *             rows.append(T0[h-1] + MR(q, T2[h-1] * y))
 *             rows += [T0[h+i] + t1r[i] + MR(q, T2[h+i]*y) for i in range(h-1)]
 *             rows.append(t1r[h-1])
 *         m = max(rows); assert m < I16 and m + S < I16; return m
 *     def inv_rows(q, blk):             # Norm / final MulYComb rows
 *         b = max(blk); assert 2 * b < I16
 *         row = 2 * b + MR(q, 2 * b * (q // 2)); assert row < I16; return row
 *     for q, W, dim in ((769, 1023, 128), (1409, 2047, 64), (3329, 4095, 128)):
 *         mm4(q, W, W); mm4(q, q-1, q-1, 1); sq4(q, q-1); mm8(q, W, W)
 *         sq8(q, q-1); inv_rows(q, sq4(q, q-1)); inv_rows(q, sq8(q, q-1))
 *         inv_rows(q, mm4(q, (q-1)//2, q-1)); inv_rows(q, mm8(q, (q-1)//2, q-1))
 *         for t in (4, 8, 16): poly_mul(q, t, W)
 *         if q == 1409:
 *             sq16(q, q-1); mm16(q, W, W); poly_mul(q, 32, W)
 *             inv_rows(q, sq16(q, q-1)); inv_rows(q, mm16(q, (q-1)//2, q-1))
 *     print("RANGE-VERIFY OK")
 *
 *   Measured per-slot costs (objdump loop bodies, 8 slots/strip):
 *     NEV_MontMul4Asm  116 (14.0/slot on the dbl == 0 path, 14.5 with dbl)
 *     NEV_MontSquare4Asm 75 (9.4/slot)
 *     NEV_Inv4NormAsm    88 (11.0/slot)
 *     NEV_Inv4FinishAsm 106 (13.25/slot incl. the 4 output-normalizing
 *                            Barretts that replace a separate array pass)
 *     NEV_PolyMulRed4Asm 133 (16.6/slot for the whole PolyMontMul4)
 * ----------------------------------------------------------------------------
 *
 * Functions (AAPCS64; only x0-x17 and v0-v7/v16-v31 are used, no
 * callee-saved registers are spilled).  Element counts n are multiples of
 * 32 for the elementwise/fused kernels (every caller passes k*dim with
 * dim in {64, 128}); slot kernels need dim % 16 == 0.  Elementwise kernels
 * support in-place operation; slot kernels tolerate r == a / r == b (each
 * strip loads all of its inputs before its stores).
 *
 *  exact elementwise (bit-exact vs the C helpers, all int16 inputs):
 *   NEV_AddArrAsm(r, a, b, n)                r[i] = a[i] + b[i]  (int16 wrap)
 *   NEV_SubArrAsm(r, a, b, n)                r[i] = a[i] - b[i]
 *   NEV_NegArrAsm(r, a, n)                   r[i] = -a[i]
 *   NEV_CaddqArrAsm(r, a, n, q)              r[i] = NEV_Caddq(a[i])
 *   NEV_BarrettArrAsm(r, a, n, bPacked)      r[i] = NEV_BarrettReduce(a[i])
 *   NEV_MontArrAsm(r, a, n, qPacked)         r[i] = NEV_MontReduce(a[i])
 *   NEV_AddBarrettArrAsm(r, a, b, n, qbPacked)
 *                                            r[i] = BarrettReduce(a[i]+b[i])
 *   NEV_BarrettCaddqArrAsm(r, a, n, qbPacked)
 *                                            r[i] = Caddq(BarrettReduce(a[i]))
 *   NEV_AddBarrettCaddqArrAsm(r, a, b, n, qbPacked)
 *                                     r[i] = Caddq(BarrettReduce(a[i]+b[i]))
 *   NEV_MontCaddqArrAsm(r, a, n, qPacked)    r[i] = Caddq(MontReduce(a[i]))
 *  fused passes (congruent):
 *   NEV_Sub2ArrAsm(r, a, b, c, n)            r[i] = a[i] - b[i] - c[i]
 *   NEV_Comb4Asm(r, a, b, c, d, n)           r[i] = a[i] + b[i] - c[i] - d[i]
 *   NEV_CopyBlocksAsm(r, a, dimBlocks, aStride)
 *       copy `blocks` source blocks of dim int16 (source block j at
 *       a + j*aStride elements) to contiguous r; dimBlocks = dim|blocks<<16
 *   NEV_MulYCombAsm(r, a, a2, b, b2, y, geom, qbPacked)
 *       per block: r = a s2*a2 s1*MR((b s3*b2) * y)  with signs s? in {+,-};
 *       geom = dim | blocks<<16 | rStrideElems<<24 |
 *              signA2<<40 | signMR<<41 | signB2<<42  (bit set = minus);
 *       r advances rStride elements per block, a/a2/b/b2 advance dim, y is
 *       one dim-sized array reused for every block.  MR is the exact
 *       full-width Montgomery reduction of the combined product.
 *  slot kernels (congruent, accumulate-then-reduce):
 *   NEV_MontMul4Asm(r, a, b, dim, qbPacked, dbl)
 *       slot-wise Karatsuba product of two degree-3 slot elements
 *       (4+4 blocks in, 7 blocks out); dbl=1 computes (2a)*b by pre-shifting
 *       the b strips left by 1 (values <= 2*(q-1) by contract).  Output
 *       row 3 is Barrett-normalized in-kernel (range table).
 *   NEV_MontSquare4Asm(r, a, dim, qPacked)   slot-wise square, 7 blocks out
 *   NEV_MontMul8TailAsm(r, t1, dim, qbPacked)
 *       fused Karatsuba recombination of MontMul8: given the three
 *       sub-products (low in r[0..7d), high in r[8d..15d), middle in t1),
 *       computes rows 4..10 of the reference MontMul8Tail with the exact
 *       Barrett, in one memory pass.
 *   NEV_PolyMulRed4Asm(r, a, b, y, dim, qbPacked)
 *       whole PolyMontMul4: MontMul4 core plus the in-register fold
 *       r_j = c_j + MR(c_{4+j} * y) (j=0..2), r_3 = c_3; 4 blocks out.
 *   NEV_PolyMulCombAsm(r, t0, t1, t2, y, dim|h<<32, qbPacked)
 *       fused final Karatsuba recombination for t in {8,16,32}; computes
 *       t1-t0-t2 in registers and writes each final output only once.
 *   NEV_Inv4NormAsm(a20, a21, s, a, y, dim, qbPacked)
 *       norm-map pass of Mont2Inverse4/Judge; s = Caddq(Barrett(...)) is
 *       bit-identical to the reference (exactness island for the zero-test).
 *   NEV_Inv4FinishAsm(r, a, a20, a21, sInv, y, dim, qbPacked)
 *       back-substitution pass; outputs Barrett-normalized (<= (q-1)/2).
 * ============================================================================
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_NEV

#include "crypt_arm.h"
#include "nev_arm_asm.h"

CRYPT_AARCH64_ARCH_BASE

/*
 * Exact Montgomery reduction of the 8 int32 lanes held in \vlo (lanes 0-3)
 * and \vhi (lanes 4-7); the reduced 8 int16 lanes are left in \vout.
 * \vout must be distinct from \vlo/\vhi (both are clobbered).
 * v7.h[0] must hold q, v7.h[1] qinv.
 */
.macro NEV_MRP vlo, vhi, vout
    uzp1    \vout\().8h, \vlo\().8h, \vhi\().8h
    mul     \vout\().8h, \vout\().8h, v7.h[1]
    smlsl   \vlo\().4s, \vout\().4h, v7.h[0]
    smlsl2  \vhi\().4s, \vout\().8h, v7.h[0]
    uzp2    \vout\().8h, \vlo\().8h, \vhi\().8h
.endm

/*
 * Exact Barrett reduction of 8 int16 lanes of \vx in place (\vt scratch).
 * v7.h[0] must hold q, v7.h[2] barrettV, v6.8h the (negative) rounding
 * shift amount 15 - barrettShift.  Equals NEV_BarrettReduce for all int16
 * inputs with the NEV (v, shift) constants (proven exhaustively).
 */
.macro NEV_BR8 vx, vt
    sqdmulh \vt\().8h, \vx\().8h, v7.h[2]
    srshl   \vt\().8h, \vt\().8h, v6.8h
    mls     \vx\().8h, \vt\().8h, v7.h[0]
.endm

/*
 * Load the packed constants for kernels taking qbPacked in register \rp:
 * v7.h[0] = q, v7.h[1] = qinv, v7.h[2] = barrettV, v6.8h = 15 - shift.
 * Clobbers w9/w10 (callers must not alias them with live arguments).
 */
.macro NEV_QB_CONSTS rp
    fmov    s7, w\rp
    lsr     x9, x\rp, #32
    mov     v7.h[2], w9
    lsr     x9, x\rp, #48
    mov     w10, #15
    sub     w9, w10, w9
    dup     v6.8h, w9
.endm

// =============================================================================
// void NEV_AddArrAsm(int16_t *r, const int16_t *a, const int16_t *b, uint64_t n)
//   r[i] = (int16_t)(a[i] + b[i]), n % 16 == 0
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_AddArrAsm)
AARCH64_PACIASP
1:
    ld1     {v0.8h, v1.8h}, [x1], #32
    ld1     {v2.8h, v3.8h}, [x2], #32
    add     v0.8h, v0.8h, v2.8h
    add     v1.8h, v1.8h, v3.8h
    st1     {v0.8h, v1.8h}, [x0], #32
    subs    x3, x3, #16
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_AddArrAsm)

// =============================================================================
// void NEV_SubArrAsm(int16_t *r, const int16_t *a, const int16_t *b, uint64_t n)
//   r[i] = (int16_t)(a[i] - b[i]), n % 16 == 0
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_SubArrAsm)
AARCH64_PACIASP
1:
    ld1     {v0.8h, v1.8h}, [x1], #32
    ld1     {v2.8h, v3.8h}, [x2], #32
    sub     v0.8h, v0.8h, v2.8h
    sub     v1.8h, v1.8h, v3.8h
    st1     {v0.8h, v1.8h}, [x0], #32
    subs    x3, x3, #16
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_SubArrAsm)

// =============================================================================
// void NEV_NegArrAsm(int16_t *r, const int16_t *a, uint64_t n)
//   r[i] = (int16_t)(-a[i]), n % 16 == 0
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_NegArrAsm)
AARCH64_PACIASP
1:
    ld1     {v0.8h, v1.8h}, [x1], #32
    neg     v0.8h, v0.8h
    neg     v1.8h, v1.8h
    st1     {v0.8h, v1.8h}, [x0], #32
    subs    x2, x2, #16
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_NegArrAsm)

// =============================================================================
// void NEV_CaddqArrAsm(int16_t *r, const int16_t *a, uint64_t n, uint64_t q)
//   r[i] = a[i] + ((a[i] >> 15) & q), n % 16 == 0
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_CaddqArrAsm)
AARCH64_PACIASP
    dup     v29.8h, w3                  // q
1:
    ld1     {v0.8h, v1.8h}, [x1], #32
    sshr    v2.8h, v0.8h, #15
    sshr    v3.8h, v1.8h, #15
    and     v2.16b, v2.16b, v29.16b
    and     v3.16b, v3.16b, v29.16b
    add     v0.8h, v0.8h, v2.8h
    add     v1.8h, v1.8h, v3.8h
    st1     {v0.8h, v1.8h}, [x0], #32
    subs    x2, x2, #16
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_CaddqArrAsm)

// =============================================================================
// void NEV_BarrettArrAsm(int16_t *r, const int16_t *a, uint64_t n,
//                        uint64_t bPacked)
//   r[i] = NEV_BarrettReduce(a[i]); bPacked = q | v << 16 | shift << 32,
//   n % 16 == 0.  Exact for all int16 a[i] (harness sweep).  Backs the
//   NEV_PolyReduce synchronization point.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_BarrettArrAsm)
AARCH64_PACIASP
    fmov    s7, w3                      // v7.h[0] = q
    ubfx    x9, x3, #16, #16
    mov     v7.h[2], w9                 // barrettV
    lsr     x9, x3, #32
    mov     w10, #15
    sub     w9, w10, w9
    dup     v6.8h, w9                   // 15 - shift (srshl amount)
1:
    ld1     {v0.8h, v1.8h}, [x1], #32
    NEV_BR8 v0, v4
    NEV_BR8 v1, v5
    st1     {v0.8h, v1.8h}, [x0], #32
    subs    x2, x2, #16
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_BarrettArrAsm)

// =============================================================================
// void NEV_MontArrAsm(int16_t *r, const int16_t *a, uint64_t n,
//                     uint64_t qPacked)
//   r[i] = NEV_MontReduce((int32_t)a[i]); qPacked = q | qinv << 16,
//   n % 16 == 0.  Exact for all int16 a[i]; backs NEV_PolyGetMontgomery.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_MontArrAsm)
AARCH64_PACIASP
    dup     v29.8h, w3                  // q
    lsr     x5, x3, #16
    dup     v28.8h, w5                  // qinv
1:
    ld1     {v0.8h, v1.8h}, [x1], #32
    sxtl    v16.4s, v0.4h               // P = (int32_t)a
    sxtl2   v17.4s, v0.8h
    sxtl    v18.4s, v1.4h
    sxtl2   v19.4s, v1.8h
    mul     v4.8h, v0.8h, v28.8h        // m = (int16_t)(lo16(P) * qinv)
    mul     v5.8h, v1.8h, v28.8h
    smlsl   v16.4s, v4.4h, v29.4h       // P - m * q
    smlsl2  v17.4s, v4.8h, v29.8h
    smlsl   v18.4s, v5.4h, v29.4h
    smlsl2  v19.4s, v5.8h, v29.8h
    uzp2    v0.8h, v16.8h, v17.8h       // (P - m * q) >> 16
    uzp2    v1.8h, v18.8h, v19.8h
    st1     {v0.8h, v1.8h}, [x0], #32
    subs    x2, x2, #16
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MontArrAsm)

// =============================================================================
// void NEV_AddBarrettArrAsm(int16_t *r, const int16_t *a, const int16_t *b,
//                           uint64_t n, uint64_t qbPacked)
//   r[i] = NEV_BarrettReduce((int16_t)(a[i] + b[i])), n % 16 == 0.
//   Bit-exact composition of the two C helpers for any int16 inputs (the
//   int16 add wraps identically).  Used for every Karatsuba operand-sum
//   pass, keeping all "middle" product operands <= (q-1)/2.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_AddBarrettArrAsm)
AARCH64_PACIASP
    NEV_QB_CONSTS 4
1:
    ld1     {v0.8h, v1.8h}, [x1], #32
    ld1     {v2.8h, v3.8h}, [x2], #32
    ld1     {v16.8h, v17.8h}, [x1], #32
    ld1     {v18.8h, v19.8h}, [x2], #32
    add     v0.8h, v0.8h, v2.8h
    add     v1.8h, v1.8h, v3.8h
    add     v16.8h, v16.8h, v18.8h
    add     v17.8h, v17.8h, v19.8h
    NEV_BR8 v0, v4
    NEV_BR8 v1, v5
    NEV_BR8 v16, v4
    NEV_BR8 v17, v5
    st1     {v0.8h, v1.8h}, [x0], #32
    st1     {v16.8h, v17.8h}, [x0], #32
    subs    x3, x3, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_AddBarrettArrAsm)

// =============================================================================
// void NEV_BarrettCaddqArrAsm(int16_t *r, const int16_t *a, uint64_t n,
//                             uint64_t qbPacked)
//   r[i] = NEV_Caddq(NEV_BarrettReduce(a[i])), n % 16 == 0.  Bit-exact
//   composition of the two C helpers for every int16 input (exact Barrett,
//   then the same sshr/and/add conditional add).  Backs the fused
//   NEV_PolyReduceCaddq synchronization point.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_BarrettCaddqArrAsm)
AARCH64_PACIASP
    NEV_QB_CONSTS 3
    dup     v29.8h, v7.h[0]             // q (full vector, for Caddq)
1:
    ld1     {v0.8h, v1.8h}, [x1], #32
    NEV_BR8 v0, v4
    NEV_BR8 v1, v5
    sshr    v2.8h, v0.8h, #15
    sshr    v3.8h, v1.8h, #15
    and     v2.16b, v2.16b, v29.16b
    and     v3.16b, v3.16b, v29.16b
    add     v0.8h, v0.8h, v2.8h
    add     v1.8h, v1.8h, v3.8h
    st1     {v0.8h, v1.8h}, [x0], #32
    subs    x2, x2, #16
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_BarrettCaddqArrAsm)

// =============================================================================
// void NEV_AddBarrettCaddqArrAsm(int16_t *r, const int16_t *a, const int16_t *b,
//                                uint64_t n, uint64_t qbPacked)
//   r[i] = NEV_Caddq(NEV_BarrettReduce((int16_t)(a[i] + b[i]))), n % 16 == 0.
//   The int16 add wraps identically to the C helper, the Barrett is exact for
//   every int16 input, so the composition is bit-exact.  Backs the fused
//   NEV_PolyAddReduceCaddq synchronization point.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_AddBarrettCaddqArrAsm)
AARCH64_PACIASP
    NEV_QB_CONSTS 4
    dup     v29.8h, v7.h[0]             // q (full vector, for Caddq)
1:
    ld1     {v0.8h, v1.8h}, [x1], #32
    ld1     {v2.8h, v3.8h}, [x2], #32
    add     v0.8h, v0.8h, v2.8h
    add     v1.8h, v1.8h, v3.8h
    NEV_BR8 v0, v4
    NEV_BR8 v1, v5
    sshr    v2.8h, v0.8h, #15
    sshr    v3.8h, v1.8h, #15
    and     v2.16b, v2.16b, v29.16b
    and     v3.16b, v3.16b, v29.16b
    add     v0.8h, v0.8h, v2.8h
    add     v1.8h, v1.8h, v3.8h
    st1     {v0.8h, v1.8h}, [x0], #32
    subs    x3, x3, #16
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_AddBarrettCaddqArrAsm)

// =============================================================================
// void NEV_MontCaddqArrAsm(int16_t *r, const int16_t *a, uint64_t n,
//                          uint64_t qPacked)
//   r[i] = NEV_Caddq(NEV_MontReduce((int32_t)a[i])), n % 16 == 0.  Same
//   exact MontReduce as NEV_MontArrAsm plus the conditional add; bit-exact
//   for every int16 input.  Backs the fused NEV_PolyGetMontgomeryCaddq
//   synchronization point.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_MontCaddqArrAsm)
AARCH64_PACIASP
    dup     v29.8h, w3                  // q
    lsr     x5, x3, #16
    dup     v28.8h, w5                  // qinv
1:
    ld1     {v0.8h, v1.8h}, [x1], #32
    sxtl    v16.4s, v0.4h               // P = (int32_t)a
    sxtl2   v17.4s, v0.8h
    sxtl    v18.4s, v1.4h
    sxtl2   v19.4s, v1.8h
    mul     v4.8h, v0.8h, v28.8h        // m = (int16_t)(lo16(P) * qinv)
    mul     v5.8h, v1.8h, v28.8h
    smlsl   v16.4s, v4.4h, v29.4h       // P - m * q
    smlsl2  v17.4s, v4.8h, v29.8h
    smlsl   v18.4s, v5.4h, v29.4h
    smlsl2  v19.4s, v5.8h, v29.8h
    uzp2    v0.8h, v16.8h, v17.8h       // (P - m * q) >> 16
    uzp2    v1.8h, v18.8h, v19.8h
    sshr    v2.8h, v0.8h, #15           // Caddq
    sshr    v3.8h, v1.8h, #15
    and     v2.16b, v2.16b, v29.16b
    and     v3.16b, v3.16b, v29.16b
    add     v0.8h, v0.8h, v2.8h
    add     v1.8h, v1.8h, v3.8h
    st1     {v0.8h, v1.8h}, [x0], #32
    subs    x2, x2, #16
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MontCaddqArrAsm)

// =============================================================================
// void NEV_Sub2ArrAsm(int16_t *r, const int16_t *a, const int16_t *b,
//                     const int16_t *c, uint64_t n)
//   r[i] = (int16_t)(a[i] - b[i] - c[i]), n % 16 == 0.  Callers guarantee
//   the mathematical value fits int16 (range table), so the result is the
//   congruent wrap-free representative.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_Sub2ArrAsm)
AARCH64_PACIASP
1:
    ld1     {v0.8h, v1.8h}, [x1], #32
    ld1     {v2.8h, v3.8h}, [x2], #32
    ld1     {v4.8h, v5.8h}, [x3], #32
    ld1     {v16.8h, v17.8h}, [x1], #32
    ld1     {v18.8h, v19.8h}, [x2], #32
    ld1     {v20.8h, v21.8h}, [x3], #32
    sub     v0.8h, v0.8h, v2.8h
    sub     v1.8h, v1.8h, v3.8h
    sub     v16.8h, v16.8h, v18.8h
    sub     v17.8h, v17.8h, v19.8h
    sub     v0.8h, v0.8h, v4.8h
    sub     v1.8h, v1.8h, v5.8h
    sub     v16.8h, v16.8h, v20.8h
    sub     v17.8h, v17.8h, v21.8h
    st1     {v0.8h, v1.8h}, [x0], #32
    st1     {v16.8h, v17.8h}, [x0], #32
    subs    x4, x4, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Sub2ArrAsm)

// =============================================================================
// void NEV_Comb4Asm(int16_t *r, const int16_t *a, const int16_t *b,
//                   const int16_t *c, const int16_t *d, uint64_t n)
//   r[i] = (int16_t)(a[i] + b[i] - c[i] - d[i]), n % 16 == 0; wrap-free by
//   caller contract (range table).  In-place with r == any operand is safe.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_Comb4Asm)
AARCH64_PACIASP
1:
    ld1     {v0.8h, v1.8h}, [x1], #32
    ld1     {v2.8h, v3.8h}, [x2], #32
    ld1     {v4.8h, v5.8h}, [x3], #32
    ld1     {v16.8h, v17.8h}, [x4], #32
    ld1     {v20.8h, v21.8h}, [x1], #32
    ld1     {v22.8h, v23.8h}, [x2], #32
    ld1     {v24.8h, v25.8h}, [x3], #32
    ld1     {v26.8h, v27.8h}, [x4], #32
    add     v0.8h, v0.8h, v2.8h
    add     v1.8h, v1.8h, v3.8h
    add     v20.8h, v20.8h, v22.8h
    add     v21.8h, v21.8h, v23.8h
    sub     v0.8h, v0.8h, v4.8h
    sub     v1.8h, v1.8h, v5.8h
    sub     v20.8h, v20.8h, v24.8h
    sub     v21.8h, v21.8h, v25.8h
    sub     v0.8h, v0.8h, v16.8h
    sub     v1.8h, v1.8h, v17.8h
    sub     v20.8h, v20.8h, v26.8h
    sub     v21.8h, v21.8h, v27.8h
    st1     {v0.8h, v1.8h}, [x0], #32
    st1     {v20.8h, v21.8h}, [x0], #32
    subs    x5, x5, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Comb4Asm)

// =============================================================================
// void NEV_CopyBlocksAsm(int16_t *r, const int16_t *a, uint64_t dimBlocks,
//                        uint64_t aStride)
//   Copy `blocks` blocks of dim int16 values; source block j starts at
//   a + j*aStride elements, destination is contiguous.  dim % 16 == 0,
//   dimBlocks = dim | blocks << 16, aStride in elements.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_CopyBlocksAsm)
AARCH64_PACIASP
    ubfx    x4, x2, #0, #16             // dim
    ubfx    x5, x2, #16, #16            // blocks
    lsl     x3, x3, #1                  // stride bytes
1:
    mov     x6, x1                      // block source
    mov     x7, x4
2:
    ld1     {v0.8h, v1.8h}, [x6], #32
    ld1     {v2.8h, v3.8h}, [x6], #32
    st1     {v0.8h, v1.8h}, [x0], #32
    st1     {v2.8h, v3.8h}, [x0], #32
    subs    x7, x7, #32
    b.ne    2b
    add     x1, x1, x3
    subs    x5, x5, #1
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_CopyBlocksAsm)

// =============================================================================
// void NEV_MulYCombAsm(int16_t *r, const int16_t *a, const int16_t *a2,
//                      const int16_t *b, const int16_t *b2, const int16_t *y,
//                      uint64_t geom, uint64_t qbPacked)
//
//   Per block (blocks and strides from geom, see header):
//       r[j] = a[j] s2 a2[j] s1 NEV_MontReduce((b[j] s3 b2[j]) * y[j])
//   with s? = +/- selected by geom bits 40 (s2), 41 (s1), 42 (s3).
//   The MR is the exact full-width Montgomery reduction, so the MR term is
//   congruent to MR(b*y) s3 MR(b2*y) as computed by the reference (linearity
//   of MontReduce mod q); callers guarantee |b s3 b2| and the final value
//   are wrap-free (range table).  In-place r == a is safe.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_MulYCombAsm)
AARCH64_PACIASP
    NEV_QB_CONSTS 7
    ubfx    x8, x6, #0, #16             // dim
    ubfx    x9, x6, #16, #8             // blocks
    ubfx    x10, x6, #24, #16           // rStride (elements)
    lsl     x11, x8, #1                 // dim bytes
    sub     x10, x10, x8
    lsl     x10, x10, #1                // (rStride - dim) bytes
    mov     w12, #1
    mov     w13, #-1
    tst     x6, #(1 << 40)
    csel    w14, w13, w12, ne
    dup     v4.8h, w14                  // s2 (a2 sign)
    tst     x6, #(1 << 41)
    csel    w14, w13, w12, ne
    dup     v5.8h, w14                  // s1 (MR-term sign)
    tst     x6, #(1 << 42)
    csel    w14, w13, w12, ne
    dup     v3.8h, w14                  // s3 (b2 sign)
1:
    mov     x14, x5                     // y
    mov     x15, x8                     // dim countdown
2:
    ld1     {v16.8h, v17.8h}, [x1], #32 // a
    ld1     {v23.8h, v24.8h}, [x2], #32 // a2
    ld1     {v18.8h, v19.8h}, [x3], #32 // b
    ld1     {v25.8h, v26.8h}, [x4], #32 // b2
    ld1     {v0.8h, v1.8h}, [x14], #32  // y
    mla     v18.8h, v25.8h, v3.8h       // b s3 b2
    mla     v19.8h, v26.8h, v3.8h
    smull   v21.4s, v18.4h, v0.4h
    smull2  v22.4s, v18.8h, v0.8h
    NEV_MRP v21, v22, v18
    smull   v21.4s, v19.4h, v1.4h
    smull2  v22.4s, v19.8h, v1.8h
    NEV_MRP v21, v22, v19
    mla     v16.8h, v23.8h, v4.8h       // a s2 a2
    mla     v17.8h, v24.8h, v4.8h
    mla     v16.8h, v18.8h, v5.8h       // ... s1 MR
    mla     v17.8h, v19.8h, v5.8h
    st1     {v16.8h, v17.8h}, [x0], #32
    subs    x15, x15, #16
    b.ne    2b
    add     x0, x0, x10                 // advance r to next output block
    subs    x9, x9, #1
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MulYCombAsm)

/*
 * MontMul4 core: slot-wise Karatsuba product of two degree-3 slot elements
 * for 8 slots.  Inputs: a0..a3 in v16-v19, b0..b3 in v20-v23 (8h lanes).
 * Every output is accumulated as one raw 32-bit linear combination of the
 * nine schoolbook/Karatsuba products and reduced once (congruent to the
 * reference MontMul4 by linearity of MontReduce mod q):
 *     R0 = MR(P0)                         R6 = MR(P3)
 *     R1 = MR(P01 - P0 - P1)              R5 = MR(P23 - P2 - P3)
 *     R2 = MR(PA0 - P0 - P2 + P1)         R4 = MR(PA1 - P1 - P3 + P2)
 *     R3 = Barrett(MR(PA01 - PA0 - PA1 - (P01-P0-P1) - (P23-P2-P3)))
 * with P_i = a_i*b_i, P01 = (a0+a1)(b0+b1), P23 = (a2+a3)(b2+b3),
 * PA0 = (a0+a2)(b0+b2), PA1 = (a1+a3)(b1+b3), PA01 = (Sa)(Sb).
 * Results: r0=v28, r1=v30, r2=v19, r3=v23, r4=v3, r5=v2, r6=v0.
 * Clobbers v0-v4, v16-v31; preserves v5-v7.
 */
.macro NEV_MM4_P1
    // Flat schoolbook: 16 coefficient products, no operand sums and no
    // recombination.  This replaces a two-level Karatsuba (9 products, but 14
    // operand-sum adds and 24 recombination subtractions).
    //
    // Karatsuba minimises MULTIPLICATION COUNT, which is the right objective
    // only when a multiply is much dearer than an add.  This kernel multiplies
    // with smull/smlal and accumulates in 32 bits, deferring reduction to one
    // NEV_MRP per output; smull/smlal cost half of mul .8h and fuse the
    // accumulate, so Karatsuba's 38 extra add/sub cost more than the 7 products
    // they save on cores where vector adds are full rate.
    //
    // Tuned for HiSilicon TSV110 (Kunpeng 920).  Core body cycles per 8 slots
    // (llvm-mca), Karatsuba -> schoolbook:
    //   TSV110       56.0 -> 32.0     Cortex-A53   102.0 -> 32.0
    //   Cortex-A55   59.0 -> 32.0     Neoverse N2   28.0 -> 18.1
    //   Apple M1     20.0 -> 16.0     Neoverse V1   16.0 -> 16.0
    // Known trade-off: on cores whose vector adds are half-rate the balance
    // tips back and this costs ~3% - Cortex-A57/A72/A76/X1 31.1 -> 32.0 and
    // Neoverse N1 31.0 -> 32.0.  Accepted deliberately: the deployment target
    // is Kunpeng 920, where this is the largest single win available in the
    // basemul tower, and the regression elsewhere is small and bounded.
    //
    // Exactness: no modular reduction happens before NEV_MRP, so each output is
    // the exact integer convolution coefficient - r3 = a0b3+a1b2+a2b1+a3b0 -
    // identical to what the Karatsuba form produced.  Widest accumulator is
    // 8(q-1)^2 on the dbl path, narrower than either previous formulation.
    // Output registers are unchanged, so both callers are untouched.
    // Reduce r0 early so all live accumulators stay out of v8-v15, whose low
    // halves are callee-saved by AAPCS64.
    smull   v0.4s, v16.4h, v20.4h
    smull2  v1.4s, v16.8h, v20.8h
    NEV_MRP v0, v1, v4                  // r0 temporary
    smull   v0.4s, v16.4h, v21.4h
    smull2  v1.4s, v16.8h, v21.8h
    smull   v2.4s, v16.4h, v22.4h
    smull2  v3.4s, v16.8h, v22.8h
    smull   v24.4s, v16.4h, v23.4h
    smull2  v25.4s, v16.8h, v23.8h
    smlal   v0.4s, v17.4h, v20.4h
    smlal2  v1.4s, v17.8h, v20.8h
    smlal   v2.4s, v17.4h, v21.4h
    smlal2  v3.4s, v17.8h, v21.8h
    smlal   v24.4s, v17.4h, v22.4h
    smlal2  v25.4s, v17.8h, v22.8h
    smull   v26.4s, v17.4h, v23.4h
    smull2  v27.4s, v17.8h, v23.8h
    smlal   v2.4s, v18.4h, v20.4h
    smlal2  v3.4s, v18.8h, v20.8h
    smlal   v24.4s, v18.4h, v21.4h
    smlal2  v25.4s, v18.8h, v21.8h
    smlal   v26.4s, v18.4h, v22.4h
    smlal2  v27.4s, v18.8h, v22.8h
    smull   v28.4s, v18.4h, v23.4h
    smull2  v29.4s, v18.8h, v23.8h
    smlal   v24.4s, v19.4h, v20.4h
    smlal2  v25.4s, v19.8h, v20.8h
    smlal   v26.4s, v19.4h, v21.4h
    smlal2  v27.4s, v19.8h, v21.8h
    smlal   v28.4s, v19.4h, v22.4h
    smlal2  v29.4s, v19.8h, v22.8h
    smull   v30.4s, v19.4h, v23.4h
    smull2  v31.4s, v19.8h, v23.8h
.endm

/* Reduction tail of the schoolbook core: one NEV_MRP per output plus the
 * r3 Barrett.  Split out of NEV_MM4CORE so NEV_MontMul4Asm can interleave
 * each output's store with the next output's reduction (store-buffer
 * pressure: Kunpeng 920 perf shows the trailing store burst stalling).
 * Same registers as before: r1=v16, r2=v19, r3=v23, r4=v3, r5=v2, r6=v0,
 * r0 stays in v4 (moved to v28 only for the composite macro's callers). */
.macro NEV_MM4_P2
    NEV_MRP v0,  v1,  v16               // r1 temporary
    NEV_MRP v2,  v3,  v19               // r2 -> v19
    NEV_MRP v24, v25, v23               // r3 -> v23 (pre-Barrett)
    NEV_MRP v26, v27, v3                // r4 -> v3
    NEV_MRP v28, v29, v2                // r5 -> v2
    NEV_MRP v30, v31, v0                // r6 -> v0
    mov     v28.16b, v4.16b              // r0 -> v28
    mov     v30.16b, v16.16b             // r1 -> v30
    NEV_BR8 v23, v1                     // r3 Barrett-normalized
.endm

/* Composite core for callers that keep all seven results in registers
 * (NEV_PolyMulRed4Asm folds c4..c6 before storing): unchanged behaviour. */
.macro NEV_MM4CORE
    NEV_MM4_P1
    NEV_MM4_P2
.endm

// =============================================================================
// void NEV_MontMul4Asm(int16_t *r, const int16_t *a, const int16_t *b,
//                      uint64_t dim, uint64_t qbPacked, uint64_t dbl)
//
// Slot-wise Karatsuba product of two degree-3 slot elements (nev_poly.c
// MontMul4 for dbl == 0, MontDoubleMul4 for dbl == 1): a and b hold 4
// blocks of dim int16 each (block j at offset j*dim), r receives 7 blocks.
// dim % 8 == 0.  8 slots per iteration, congruent per-output
// accumulate-then-reduce (NEV_MM4CORE above).  dbl == 1 shifts the b
// strips left by 1 before the core (operands <= 2(q-1) by contract).
// In-place r == a / r == b is safe.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_MontMul4Asm)
AARCH64_PACIASP
    NEV_QB_CONSTS 4
    lsl     x4, x3, #1                  // block stride in bytes
    add     x7, x1, x4                  // a1
    add     x8, x7, x4                  // a2
    add     x9, x8, x4                  // a3
    add     x10, x2, x4                 // b1
    add     x11, x10, x4                // b2
    add     x12, x11, x4                // b3
    add     x13, x0, x4                 // r1
    add     x14, x13, x4                // r2
    add     x15, x14, x4                // r3
    add     x16, x15, x4                // r4
    add     x17, x16, x4                // r5
    add     x4, x17, x4                 // r6
1:
    ld1     {v16.8h}, [x1], #16         // a0
    ld1     {v17.8h}, [x7], #16         // a1
    ld1     {v18.8h}, [x8], #16         // a2
    ld1     {v19.8h}, [x9], #16         // a3
    ld1     {v20.8h}, [x2], #16         // b0
    ld1     {v21.8h}, [x10], #16        // b1
    ld1     {v22.8h}, [x11], #16        // b2
    ld1     {v23.8h}, [x12], #16        // b3
    cbz     x5, 2f
    shl     v20.8h, v20.8h, #1          // (2b) for the dbl variant
    shl     v21.8h, v21.8h, #1
    shl     v22.8h, v22.8h, #1
    shl     v23.8h, v23.8h, #1
2:
    // Schoolbook core with each output stored as soon as it is reduced:
    // the seven stores spread across the reduction chain instead of a
    // trailing burst (the trailing st1 cluster was the #1 hotspot on
    // Kunpeng 920).  All loads of this strip precede every store, so the
    // documented r == a / r == b in-place contract is preserved.
    NEV_MM4_P1
    st1     {v4.8h},  [x0],  #16        // r0 (reduced since core entry)
    NEV_MRP v0,  v1,  v16               // r1
    st1     {v16.8h}, [x13], #16
    NEV_MRP v2,  v3,  v19               // r2
    st1     {v19.8h}, [x14], #16
    NEV_MRP v24, v25, v23               // r3 (pre-Barrett)
    NEV_BR8 v23, v1                     // r3 Barrett-normalized
    st1     {v23.8h}, [x15], #16
    NEV_MRP v26, v27, v3                // r4
    st1     {v3.8h},  [x16], #16
    NEV_MRP v28, v29, v2                // r5
    st1     {v2.8h},  [x17], #16
    NEV_MRP v30, v31, v0                // r6
    st1     {v0.8h},  [x4],  #16
    subs    x3, x3, #8
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MontMul4Asm)

// =============================================================================
// void NEV_PolyMulRed4Asm(int16_t *r, const int16_t *a, const int16_t *b,
//                         const int16_t *y, uint64_t dim, uint64_t qbPacked)
//
// Whole PolyMontMul4 (t = 4): the MontMul4 core plus the in-register
// wrap-around fold r_j = c_j + MR(c_{4+j} * y) for j = 0..2 and r_3 = c_3;
// only the 4 output blocks are stored.  Congruent to the reference
// PolyMontMul4 (fold merged into the same MR by linearity).
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_PolyMulRed4Asm)
AARCH64_PACIASP
    NEV_QB_CONSTS 5
    lsl     x5, x4, #1                  // block stride in bytes
    mov     x17, x4                     // countdown
    add     x7, x1, x5                  // a1
    add     x8, x7, x5                  // a2
    add     x9, x8, x5                  // a3
    add     x10, x2, x5                 // b1
    add     x11, x10, x5                // b2
    add     x12, x11, x5                // b3
    add     x13, x0, x5                 // r1
    add     x14, x13, x5                // r2
    add     x15, x14, x5                // r3
1:
    ld1     {v16.8h}, [x1], #16
    ld1     {v17.8h}, [x7], #16
    ld1     {v18.8h}, [x8], #16
    ld1     {v19.8h}, [x9], #16
    ld1     {v20.8h}, [x2], #16
    ld1     {v21.8h}, [x10], #16
    ld1     {v22.8h}, [x11], #16
    ld1     {v23.8h}, [x12], #16
    NEV_MM4CORE
    // c0=v28 c1=v30 c2=v19 c3=v23 c4=v3 c5=v2 c6=v0; fold c4..c6 by y
    ld1     {v1.8h}, [x3], #16          // y
    smull   v4.4s, v3.4h, v1.4h         // MR(c4 * y)
    smull2  v5.4s, v3.8h, v1.8h
    NEV_MRP v4, v5, v3
    add     v28.8h, v28.8h, v3.8h
    smull   v4.4s, v2.4h, v1.4h         // MR(c5 * y)
    smull2  v5.4s, v2.8h, v1.8h
    NEV_MRP v4, v5, v2
    add     v30.8h, v30.8h, v2.8h
    smull   v4.4s, v0.4h, v1.4h         // MR(c6 * y)
    smull2  v5.4s, v0.8h, v1.8h
    NEV_MRP v4, v5, v0
    add     v19.8h, v19.8h, v0.8h
    st1     {v28.8h}, [x0], #16         // r0
    st1     {v30.8h}, [x13], #16        // r1
    st1     {v19.8h}, [x14], #16        // r2
    st1     {v23.8h}, [x15], #16        // r3
    subs    x17, x17, #8
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_PolyMulRed4Asm)

// =============================================================================
// void NEV_PolyMulCombAsm(int16_t *r, const int16_t *t0, const int16_t *t1,
//                         const int16_t *t2, const int16_t *y,
//                         uint64_t geom, uint64_t qbPacked)
//
// geom = dim | h<<32.  Fuses the temporary t1 -= t0+t2 pass with all four
// wrap-around output passes used by PolyMontMul{8,16,32}.  For i < h-1:
//   u_i       = t1_i       - t0_i       - t2_i
//   u_{h+i}   = t1_{h+i}   - t0_{h+i}   - t2_{h+i}
//   r_i       = t0_i + MR((t2_i + u_{h+i}) * y)
//   r_{h+i}   = t0_{h+i} + u_i + MR(t2_{h+i} * y)
// The two edge blocks are r_{h-1}=t0_{h-1}+MR(t2_{h-1}*y) and
// r_{2h-1}=u_{h-1}.  All int16 additions are wrap-free by the range table.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_PolyMulCombAsm)
AARCH64_PACIASP
    NEV_QB_CONSTS 6
    lsr     x14, x5, #32                // h
    mov     w5, w5                      // dim (elements)
    lsl     x15, x5, #1                 // block stride in bytes
    mul     x16, x14, x15               // h blocks in bytes
    add     x7, x1, x16                 // t0 high half
    add     x8, x2, x16                 // t1 high half
    add     x9, x3, x16                 // t2 high half
    add     x10, x0, x16                // output high half
    mov     x12, x4                     // y base
    sub     x14, x14, #1                // paired block count

.LNEV_PolyMulCombBlock:
    mov     x4, x12
    mov     x13, x5
.LNEV_PolyMulCombStrip:
    ld1     {v0.8h}, [x1], #16          // t0_i
    ld1     {v1.8h}, [x2], #16          // t1_i
    ld1     {v2.8h}, [x3], #16          // t2_i
    ld1     {v3.8h}, [x7], #16          // t0_{h+i}
    ld1     {v4.8h}, [x8], #16          // t1_{h+i}
    ld1     {v5.8h}, [x9], #16          // t2_{h+i}
    ld1     {v16.8h}, [x4], #16         // y

    sub     v1.8h, v1.8h, v0.8h        // u_i
    sub     v1.8h, v1.8h, v2.8h
    sub     v4.8h, v4.8h, v3.8h        // u_{h+i}
    sub     v4.8h, v4.8h, v5.8h

    add     v17.8h, v2.8h, v4.8h
    smull   v18.4s, v17.4h, v16.4h
    smull2  v19.4s, v17.8h, v16.8h
    NEV_MRP v18, v19, v17
    add     v0.8h, v0.8h, v17.8h       // r_i

    smull   v18.4s, v5.4h, v16.4h
    smull2  v19.4s, v5.8h, v16.8h
    NEV_MRP v18, v19, v17
    add     v3.8h, v3.8h, v1.8h
    add     v3.8h, v3.8h, v17.8h       // r_{h+i}

    st1     {v0.8h}, [x0], #16
    st1     {v3.8h}, [x10], #16
    subs    x13, x13, #8
    b.ne    .LNEV_PolyMulCombStrip
    subs    x14, x14, #1
    b.ne    .LNEV_PolyMulCombBlock

    mov     x4, x12
    mov     x13, x5
.LNEV_PolyMulCombEdge:
    ld1     {v0.8h}, [x1], #16          // t0_{h-1}
    ld1     {v1.8h}, [x2], #16          // t1_{h-1}
    ld1     {v2.8h}, [x3], #16          // t2_{h-1}
    ld1     {v16.8h}, [x4], #16
    sub     v1.8h, v1.8h, v0.8h
    sub     v1.8h, v1.8h, v2.8h        // r_{2h-1}
    smull   v18.4s, v2.4h, v16.4h
    smull2  v19.4s, v2.8h, v16.8h
    NEV_MRP v18, v19, v17
    add     v0.8h, v0.8h, v17.8h       // r_{h-1}
    st1     {v0.8h}, [x0], #16
    st1     {v1.8h}, [x10], #16
    subs    x13, x13, #8
    b.ne    .LNEV_PolyMulCombEdge
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_PolyMulCombAsm)

// =============================================================================
// void NEV_MontSquare4Asm(int16_t *r, const int16_t *a, uint64_t dim,
//                         uint64_t qPacked)
//
// Slot-wise square of a degree-3 slot element (4 blocks in, 7 blocks out),
// congruent per-output accumulate-then-reduce version of nev_poly.c
// MontSquare4:
//     o0 = MR(a0^2)              o1 = MR(2 a0 a1)
//     o2 = MR(a1^2 + 2 a0 a2)    o3 = MR((2a0+2a1)(a2+a3) - 2a1a3 - 2a0a2)
//     o4 = MR(2 a1 a3 + a2^2)    o5 = MR(2 a2 a3)          o6 = MR(a3^2)
// dim % 8 == 0.  In-place r == a is safe.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_MontSquare4Asm)
AARCH64_PACIASP
    fmov    s7, w3                      // v7.h[0] = q, v7.h[1] = qinv
    lsl     x4, x2, #1                  // block stride in bytes
    add     x5, x1, x4                  // a1
    add     x6, x5, x4                  // a2
    add     x7, x6, x4                  // a3
    add     x8, x0, x4                  // r1
    add     x9, x8, x4                  // r2
    add     x10, x9, x4                 // r3
    add     x11, x10, x4                // r4
    add     x12, x11, x4                // r5
    add     x13, x12, x4                // r6
1:
    ld1     {v16.8h}, [x1], #16         // a0
    ld1     {v17.8h}, [x5], #16         // a1
    ld1     {v18.8h}, [x6], #16         // a2
    ld1     {v19.8h}, [x7], #16         // a3
    shl     v0.8h, v16.8h, #1           // 2 a0
    shl     v1.8h, v17.8h, #1           // 2 a1
    shl     v2.8h, v18.8h, #1           // 2 a2
    add     v3.8h, v18.8h, v19.8h       // a2 + a3
    add     v4.8h, v0.8h, v1.8h         // 2 a0 + 2 a1
    smull   v20.4s, v16.4h, v16.4h      // o0: a0^2
    smull2  v21.4s, v16.8h, v16.8h
    smull   v22.4s, v0.4h, v17.4h       // o1: 2 a0 a1
    smull2  v23.4s, v0.8h, v17.8h
    smull   v24.4s, v17.4h, v17.4h      // o2: a1^2 + 2 a0 a2
    smull2  v25.4s, v17.8h, v17.8h
    smlal   v24.4s, v0.4h, v18.4h
    smlal2  v25.4s, v0.8h, v18.8h
    smull   v26.4s, v4.4h, v3.4h        // o3: (2a0+2a1)(a2+a3) - 2a1a3 - 2a0a2
    smull2  v27.4s, v4.8h, v3.8h
    smlsl   v26.4s, v1.4h, v19.4h
    smlsl2  v27.4s, v1.8h, v19.8h
    smlsl   v26.4s, v0.4h, v18.4h
    smlsl2  v27.4s, v0.8h, v18.8h
    smull   v28.4s, v1.4h, v19.4h       // o4: 2 a1 a3 + a2^2
    smull2  v29.4s, v1.8h, v19.8h
    smlal   v28.4s, v18.4h, v18.4h
    smlal2  v29.4s, v18.8h, v18.8h
    smull   v30.4s, v2.4h, v19.4h       // o5: 2 a2 a3
    smull2  v31.4s, v2.8h, v19.8h
    smull   v16.4s, v19.4h, v19.4h      // o6: a3^2
    smull2  v17.4s, v19.8h, v19.8h
    // Reduce-and-store each output in turn: the seven stores spread across
    // the MRP chain instead of a trailing burst (same treatment as
    // NEV_MontMul4Asm; the load/store contract r == a is unchanged because
    // every load still precedes every store of the strip).
    NEV_MRP v20, v21, v18               // o0
    st1     {v18.8h}, [x0], #16
    NEV_MRP v22, v23, v19               // o1
    st1     {v19.8h}, [x8], #16
    NEV_MRP v24, v25, v20               // o2
    st1     {v20.8h}, [x9], #16
    NEV_MRP v26, v27, v22               // o3
    st1     {v22.8h}, [x10], #16
    NEV_MRP v28, v29, v24               // o4
    st1     {v24.8h}, [x11], #16
    NEV_MRP v30, v31, v26               // o5
    st1     {v26.8h}, [x12], #16
    NEV_MRP v16, v17, v28               // o6
    st1     {v28.8h}, [x13], #16
    subs    x2, x2, #8
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MontSquare4Asm)

// =============================================================================
// void NEV_MontMul8TailAsm(int16_t *r, const int16_t *t1, uint64_t dim,
//                          uint64_t qbPacked)
//
// Fused Karatsuba recombination tail of MontMul8 / MontDoubleMul8 (the
// reference MontMul8Tail): with the low product in r[0..7d), the high
// product in r[8d..15d) and the middle product in t1[0..7d), computes
//     r[7d+j]      = Barrett(t1_3 - r_3 - r_11)
//     r[(4+i)d+j]  = Barrett(r_{4+i} + t1_i - r_i - r_{8+i})   i = 0..2
//     r[(8+i)d+j]  = Barrett(t1_{4+i} - r_{4+i} - r_{12+i} + r_{8+i})
// in a single memory pass per row group (all pre-Barrett values wrap-free,
// see range table).  Replaces 11 elementwise passes plus a scalar copy.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_MontMul8TailAsm)
AARCH64_PACIASP
    NEV_QB_CONSTS 3
    lsl     x3, x2, #1                  // dim bytes
    // pass A: r7 = Barrett(t1_3 - r3 - r11)
    add     x4, x1, x3, lsl #1
    add     x4, x4, x3                  // t1_3
    add     x5, x0, x3, lsl #1
    add     x5, x5, x3                  // r3
    add     x6, x0, x3, lsl #3
    add     x6, x6, x3, lsl #1
    add     x6, x6, x3                  // r11
    add     x7, x0, x3, lsl #2
    add     x7, x7, x3, lsl #1
    add     x7, x7, x3                  // r7
    mov     x8, x2
1:
    ld1     {v0.8h}, [x4], #16
    ld1     {v1.8h}, [x5], #16
    ld1     {v2.8h}, [x6], #16
    sub     v0.8h, v0.8h, v1.8h
    sub     v0.8h, v0.8h, v2.8h
    NEV_BR8 v0, v4
    st1     {v0.8h}, [x7], #16
    subs    x8, x8, #8
    b.ne    1b
    // pass B, i = 0..2: r4+i and r8+i rows
    mov     x17, #0                     // i
2:
    madd    x4, x17, x3, x0             // r_i
    add     x5, x4, x3, lsl #2          // r_{4+i}
    add     x6, x5, x3, lsl #2          // r_{8+i}
    add     x7, x6, x3, lsl #2          // r_{12+i}
    madd    x8, x17, x3, x1             // t1_i
    add     x9, x8, x3, lsl #2          // t1_{4+i}
    mov     x10, x2
3:
    ld1     {v0.8h}, [x4], #16          // r_i
    ld1     {v1.8h}, [x5]               // r_{4+i}   (read, then written)
    ld1     {v2.8h}, [x6]               // r_{8+i}   (read, then written)
    ld1     {v3.8h}, [x7], #16          // r_{12+i}
    ld1     {v16.8h}, [x8], #16         // t1_i
    ld1     {v17.8h}, [x9], #16         // t1_{4+i}
    add     v18.8h, v1.8h, v16.8h       // r4' = r_{4+i} + t1_i - r_i - r_{8+i}
    sub     v18.8h, v18.8h, v0.8h
    sub     v18.8h, v18.8h, v2.8h
    sub     v19.8h, v17.8h, v1.8h       // r8' = t1_{4+i} - r_{4+i} - r_{12+i} + r_{8+i}
    sub     v19.8h, v19.8h, v3.8h
    add     v19.8h, v19.8h, v2.8h
    NEV_BR8 v18, v4
    NEV_BR8 v19, v4
    st1     {v18.8h}, [x5], #16
    st1     {v19.8h}, [x6], #16
    subs    x10, x10, #8
    b.ne    3b
    add     x17, x17, #1
    cmp     x17, #3
    b.ne    2b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MontMul8TailAsm)

// =============================================================================
// void NEV_Inv4NormAsm(int16_t *a20, int16_t *a21, int16_t *s,
//                      const int16_t *a, const int16_t *y, uint64_t dim,
//                      uint64_t qbPacked)
//
// Norm-map pass of nev_poly.c Mont2Inverse4 / Mont2Inverse4Judge.  Per slot
// (8 slots per iteration, t_i = input blocks, y = NTT_Y):
//     a2_0 = MR(MR(t2^2 - 2 t1 t3) * y) + MR(t0^2)
//     a2_1 = MR(2 t0 t2 - t1^2) - MR(MR(t3^2) * y)
//     s    = Caddq(Barrett(MR(a2_0^2) - MR(MR(a2_1^2) * y)))
// a2_0 / a2_1 are congruent to the reference values (per-output combined
// MRs); s is BIT-IDENTICAL to the reference (exact Barrett + Caddq of a
// wrap-free int16 value canonicalizes the class, and the class only depends
// on the inputs mod q).  Inputs |a| <= q-1 by contract.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_Inv4NormAsm)
AARCH64_PACIASP
    NEV_QB_CONSTS 6
    dup     v5.8h, v7.h[0]              // q (full vector, for Caddq)
    lsl     x8, x5, #1                  // block stride in bytes
    add     x9, x3, x8                  // a1
    add     x10, x9, x8                 // a2
    add     x11, x10, x8                // a3
1:
    ld1     {v16.8h}, [x3], #16         // t0
    ld1     {v17.8h}, [x9], #16         // t1
    ld1     {v18.8h}, [x10], #16        // t2
    ld1     {v19.8h}, [x11], #16        // t3
    ld1     {v20.8h}, [x4], #16         // y
    shl     v0.8h, v17.8h, #1           // 2 t1
    shl     v1.8h, v16.8h, #1           // 2 t0
    smull   v21.4s, v18.4h, v18.4h      // X1 = MR(t2^2 - 2 t1 t3)
    smull2  v22.4s, v18.8h, v18.8h
    smlsl   v21.4s, v0.4h, v19.4h
    smlsl2  v22.4s, v0.8h, v19.8h
    NEV_MRP v21, v22, v2
    smull   v21.4s, v2.4h, v20.4h       // X2 = MR(X1 * y)
    smull2  v22.4s, v2.8h, v20.8h
    NEV_MRP v21, v22, v3
    smull   v21.4s, v16.4h, v16.4h      // T00 = MR(t0^2)
    smull2  v22.4s, v16.8h, v16.8h
    NEV_MRP v21, v22, v4
    add     v3.8h, v3.8h, v4.8h         // a2_0
    st1     {v3.8h}, [x0], #16          // store a2_0 mid-chain (spread the
                                       // store burst; v3 still feeds T6)
    smull   v21.4s, v1.4h, v18.4h       // Y1 = MR(2 t0 t2 - t1^2)
    smull2  v22.4s, v1.8h, v18.8h
    smlsl   v21.4s, v17.4h, v17.4h
    smlsl2  v22.4s, v17.8h, v17.8h
    NEV_MRP v21, v22, v4
    smull   v21.4s, v19.4h, v19.4h      // MR(t3^2)
    smull2  v22.4s, v19.8h, v19.8h
    NEV_MRP v21, v22, v0
    smull   v21.4s, v0.4h, v20.4h       // Y2 = MR(MR(t3^2) * y)
    smull2  v22.4s, v0.8h, v20.8h
    NEV_MRP v21, v22, v1
    sub     v4.8h, v4.8h, v1.8h         // a2_1
    st1     {v4.8h}, [x1], #16          // store a2_1 mid-chain (v4 still
                                       // feeds its square below)
    smull   v21.4s, v3.4h, v3.4h        // T6 = MR(a2_0^2)
    smull2  v22.4s, v3.8h, v3.8h
    NEV_MRP v21, v22, v0
    smull   v21.4s, v4.4h, v4.4h        // MR(a2_1^2)
    smull2  v22.4s, v4.8h, v4.8h
    NEV_MRP v21, v22, v1
    smull   v21.4s, v1.4h, v20.4h       // T7 = MR(MR(a2_1^2) * y)
    smull2  v22.4s, v1.8h, v20.8h
    NEV_MRP v21, v22, v1
    sub     v0.8h, v0.8h, v1.8h         // s = T6 - T7 (|.| <= 3570, wrap-free)
    NEV_BR8 v0, v2                      // exact Barrett (canonical centered)
    sshr    v1.8h, v0.8h, #15           // Caddq
    and     v1.16b, v1.16b, v5.16b
    add     v0.8h, v0.8h, v1.8h
    st1     {v0.8h}, [x2], #16          // s (a2_0/a2_1 stored mid-chain)
    subs    x5, x5, #8
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Inv4NormAsm)

// =============================================================================
// void NEV_Inv4FinishAsm(int16_t *r, const int16_t *a, const int16_t *a20,
//                        const int16_t *a21, const int16_t *sInv,
//                        const int16_t *y, uint64_t dim, uint64_t qbPacked)
//
// Back-substitution pass of nev_poly.c Mont2Inverse4.  Per slot:
//     t4 = MR(a20*s); t5 = MR(a21*s); t6 = MR(t0*t4); t7 = MR(t1*t4)
//     u0 = MR((t0+t2)*(t4-t5)); u1 = MR((t1-t3)*(t4+t5))
//     t2' = MR(t2*t5); t3' = MR(t3*t5); t4'' = MR(t2'*y); t5'' = MR(t3'*y)
//     r0 = B(t6 - t4''); r1 = B(t5'' - t7)
//     r2 = B(u0 - t6 + t2'); r3 = B(u1 - t7 + t3')
// All products use the exact full-width MR; outputs are Barrett-normalized
// (congruent to the reference, |out| <= (q-1)/2) so they can feed the next
// Karatsuba level directly.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_Inv4FinishAsm)
AARCH64_PACIASP
    NEV_QB_CONSTS 7
    lsl     x8, x6, #1                  // block stride in bytes
    add     x9, x1, x8                  // a1
    add     x10, x9, x8                 // a2
    add     x11, x10, x8                // a3
    add     x12, x0, x8                 // r1
    add     x13, x12, x8                // r2
    add     x14, x13, x8                // r3
1:
    ld1     {v16.8h}, [x1], #16         // t0
    ld1     {v17.8h}, [x9], #16         // t1
    ld1     {v18.8h}, [x10], #16        // t2
    ld1     {v19.8h}, [x11], #16        // t3
    ld1     {v20.8h}, [x2], #16         // a20
    ld1     {v21.8h}, [x3], #16         // a21
    ld1     {v22.8h}, [x4], #16         // sInv
    ld1     {v23.8h}, [x5], #16         // y
    smull   v24.4s, v20.4h, v22.4h      // t4 = MR(a20 * s)
    smull2  v25.4s, v20.8h, v22.8h
    NEV_MRP v24, v25, v0
    smull   v24.4s, v21.4h, v22.4h      // t5 = MR(a21 * s)
    smull2  v25.4s, v21.8h, v22.8h
    NEV_MRP v24, v25, v1
    smull   v24.4s, v16.4h, v0.4h       // t6 = MR(t0 * t4)
    smull2  v25.4s, v16.8h, v0.8h
    NEV_MRP v24, v25, v2
    smull   v24.4s, v17.4h, v0.4h       // t7 = MR(t1 * t4)
    smull2  v25.4s, v17.8h, v0.8h
    NEV_MRP v24, v25, v3
    add     v20.8h, v16.8h, v18.8h      // t0 + t2
    sub     v21.8h, v0.8h, v1.8h        // t4 - t5
    smull   v24.4s, v20.4h, v21.4h      // u0
    smull2  v25.4s, v20.8h, v21.8h
    NEV_MRP v24, v25, v4
    sub     v20.8h, v17.8h, v19.8h      // t1 - t3
    add     v21.8h, v0.8h, v1.8h        // t4 + t5
    smull   v24.4s, v20.4h, v21.4h      // u1
    smull2  v25.4s, v20.8h, v21.8h
    NEV_MRP v24, v25, v5
    smull   v24.4s, v18.4h, v1.4h       // t2' = MR(t2 * t5)
    smull2  v25.4s, v18.8h, v1.8h
    NEV_MRP v24, v25, v18
    smull   v24.4s, v19.4h, v1.4h       // t3' = MR(t3 * t5)
    smull2  v25.4s, v19.8h, v1.8h
    NEV_MRP v24, v25, v19
    smull   v24.4s, v18.4h, v23.4h      // t4'' = MR(t2' * y)
    smull2  v25.4s, v18.8h, v23.8h
    NEV_MRP v24, v25, v20
    smull   v24.4s, v19.4h, v23.4h      // t5'' = MR(t3' * y)
    smull2  v25.4s, v19.8h, v23.8h
    NEV_MRP v24, v25, v21
    sub     v20.8h, v2.8h, v20.8h       // r0 = t6 - t4''
    NEV_BR8 v20, v24
    st1     {v20.8h}, [x0], #16
    sub     v21.8h, v21.8h, v3.8h       // r1 = t5'' - t7
    NEV_BR8 v21, v24
    st1     {v21.8h}, [x12], #16
    sub     v4.8h, v4.8h, v2.8h         // r2 = u0 - t6 + t2'
    add     v4.8h, v4.8h, v18.8h
    NEV_BR8 v4, v24
    st1     {v4.8h}, [x13], #16
    sub     v5.8h, v5.8h, v3.8h         // r3 = u1 - t7 + t3'
    add     v5.8h, v5.8h, v19.8h
    NEV_BR8 v5, v24
    st1     {v5.8h}, [x14], #16
    subs    x6, x6, #8
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Inv4FinishAsm)

#endif // HITLS_CRYPTO_NEV

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
