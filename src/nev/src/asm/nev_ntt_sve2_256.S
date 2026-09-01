/*
 * based on https://eprint.iacr.org/2021/986, CC0 1.0 Universal.
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

/*
 * ============================================================================
 * NEV per-block negacyclic NTT — SVE2 kernels for a 256-bit vector length
 * ============================================================================
 *
 * SVE2 twins of the NEON kernels in nev_ntt_armv8.S (same twiddle multiply,
 * same exact Barrett, same layer math, same congruence contract) with 16
 * halfword lanes per vector: one dim-128 block is 8 z registers, one dim-64
 * block is 4.  An SVE2-enabled pqcp build selects these kernels at compile
 * time; the whole file assumes z registers of exactly 32 bytes, so enabling
 * the backend is a platform contract that the live vector length is 256 bits.
 *
 * Because every butterfly applies the identical mul/sqrdmulh/mls multiply
 * with the identical (root, root_hi) pair in the identical layer order, and
 * the exact Barrett passes sit at the same points of the schedule, each
 * coefficient's value history is the same as in the NEON kernels: the
 * outputs are BIT-IDENTICAL to the NEV_NTT../NEV_INTT.. kernels for every
 * input block (asserted by the differential harness), so the forward
 * bit-exactness and
 * inverse congruence/range proofs of nev_ntt_armv8.S carry over verbatim.
 *
 * Layer scheme (dim 128; dim 64 in brackets):
 *   cross-register layers len 64,32,16 [32,16]: whole-register butterflies,
 *     scalar twiddles broadcast with ld1rh.
 *   in-register tail len 8,4,2,1: each pair of registers (32 coefficients)
 *     enters a split domain via one two-source TBL per output (the len-8
 *     "a"/"b" lanes live in the two 128-bit register halves, which no base
 *     SVE2 granule permute can separate); the len 4/2/1 sub-splits are plain
 *     uzp1/uzp2 at .d/.s/.h granules; twiddles are per-lane 16-wide vectors
 *     in split-domain order.  The forward tail ends with the exact Barrett
 *     sync pass (lane-wise, layout-irrelevant) and un-permutes with one TBL
 *     per output; the composed split permutation is an involution, so the
 *     inverse tail ENTERS through the same UE1/UE2 index vectors and merges
 *     back through QA/QB.  The inverse keeps the lazy schedule: no
 *     reductions except the single exact Barrett after the len-4 layer, and
 *     the last cross-register layer is fused with the mont^2/dim scale
 *     ((fP, fP_hi, fzetaP, fzetaP_hi) as movz+dup immediates).
 *
 * Table layout (asm_nev_ntt.c, generator + design-time validator
 * scripts/embedded there; all offsets in bytes from the table pointer x1):
 *   [0..127]   4 TBL index vectors: QA(+0), QB(+32), UE1(+64), UE2(+96)
 *   [128..159] head scalar (root, root_hi) pairs in consumption order
 *   [160..]    per-register-pair tail groups of 8 twiddle vectors (root and
 *              hi per layer, consumption order), 256 bytes per pair
 *
 * Register allocation: z0-z7 block data, z16-z21 tail work/temps, z24-z27
 * TBL index vectors, z20-z28/z30 broadcast twiddles (head layers reuse the
 * dead index/work registers), z29 = barrettV, z31 = q, p0 = all-true .h.
 * z8-z15 are never written: no callee-saved spills.  x0 = block, x1 = table,
 * x2 = head scalars, x3/x4 = tail groups of the pair being processed,
 * w9 = immediate scratch.
 * ============================================================================
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_NEV) && defined(HITLS_CRYPTO_NEV_SVE2)

#include "crypt_arm.h"
#include "nev_arm_asm.h"

CRYPT_AARCH64_ARCH_SVE2

// ----------------------------------------------------------------------------
// Building-block macros.  Vector registers are passed as bare numbers.
// ----------------------------------------------------------------------------

// Exact Barrett reduction of z\zx in place (z\zt scratch): z29 = barrettV,
// z31 = q, immediate rounding shift \sh = barrettShift - 15.
.macro NEV_SVE2_NTT_BR zx, zt, sh
    sqdmulh z\zt\().h, z\zx\().h, z29.h
    srshr   z\zt\().h, p0/m, z\zt\().h, #\sh
    mls     z\zx\().h, p0/m, z\zt\().h, z31.h
.endm

// Four whole-register CT butterflies (temps z16-z19):
//   t = mm3(b, root); b' = a - t; a' = a + t
// r*/h* are the register numbers of each pair's broadcast (root, root_hi).
.macro NEV_SVE2_CT4 a0, b0, r0, h0, a1, b1, r1, h1, a2, b2, r2, h2, a3, b3, r3, h3
    mul      z16.h, z\b0\().h, z\r0\().h
    mul      z17.h, z\b1\().h, z\r1\().h
    mul      z18.h, z\b2\().h, z\r2\().h
    mul      z19.h, z\b3\().h, z\r3\().h
    sqrdmulh z\b0\().h, z\b0\().h, z\h0\().h
    sqrdmulh z\b1\().h, z\b1\().h, z\h1\().h
    sqrdmulh z\b2\().h, z\b2\().h, z\h2\().h
    sqrdmulh z\b3\().h, z\b3\().h, z\h3\().h
    mls      z16.h, p0/m, z\b0\().h, z31.h
    mls      z17.h, p0/m, z\b1\().h, z31.h
    mls      z18.h, p0/m, z\b2\().h, z31.h
    mls      z19.h, p0/m, z\b3\().h, z31.h
    sub      z\b0\().h, z\a0\().h, z16.h
    sub      z\b1\().h, z\a1\().h, z17.h
    sub      z\b2\().h, z\a2\().h, z18.h
    sub      z\b3\().h, z\a3\().h, z19.h
    add      z\a0\().h, z\a0\().h, z16.h
    add      z\a1\().h, z\a1\().h, z17.h
    add      z\a2\().h, z\a2\().h, z18.h
    add      z\a3\().h, z\a3\().h, z19.h
.endm

// Two whole-register CT butterflies (temps z16/z17), dim-64 head layers.
.macro NEV_SVE2_CT2 a0, b0, r0, h0, a1, b1, r1, h1
    mul      z16.h, z\b0\().h, z\r0\().h
    mul      z17.h, z\b1\().h, z\r1\().h
    sqrdmulh z\b0\().h, z\b0\().h, z\h0\().h
    sqrdmulh z\b1\().h, z\b1\().h, z\h1\().h
    mls      z16.h, p0/m, z\b0\().h, z31.h
    mls      z17.h, p0/m, z\b1\().h, z31.h
    sub      z\b0\().h, z\a0\().h, z16.h
    sub      z\b1\().h, z\a1\().h, z17.h
    add      z\a0\().h, z\a0\().h, z16.h
    add      z\a1\().h, z\a1\().h, z17.h
.endm

// Four whole-register lazy GS butterflies (temps z4-z7; no reduction):
//   d = b - a; a' = a + b; b' = mm3(d, root)
.macro NEV_SVE2_GS4 a0, b0, r0, h0, a1, b1, r1, h1, a2, b2, r2, h2, a3, b3, r3, h3
    sub      z4.h, z\b0\().h, z\a0\().h
    sub      z5.h, z\b1\().h, z\a1\().h
    sub      z6.h, z\b2\().h, z\a2\().h
    sub      z7.h, z\b3\().h, z\a3\().h
    add      z\a0\().h, z\a0\().h, z\b0\().h
    add      z\a1\().h, z\a1\().h, z\b1\().h
    add      z\a2\().h, z\a2\().h, z\b2\().h
    add      z\a3\().h, z\a3\().h, z\b3\().h
    mul      z\b0\().h, z4.h, z\r0\().h
    mul      z\b1\().h, z5.h, z\r1\().h
    mul      z\b2\().h, z6.h, z\r2\().h
    mul      z\b3\().h, z7.h, z\r3\().h
    sqrdmulh z4.h, z4.h, z\h0\().h
    sqrdmulh z5.h, z5.h, z\h1\().h
    sqrdmulh z6.h, z6.h, z\h2\().h
    sqrdmulh z7.h, z7.h, z\h3\().h
    mls      z\b0\().h, p0/m, z4.h, z31.h
    mls      z\b1\().h, p0/m, z5.h, z31.h
    mls      z\b2\().h, p0/m, z6.h, z31.h
    mls      z\b3\().h, p0/m, z7.h, z31.h
.endm

// Two whole-register lazy GS butterflies (temps z4/z5), dim-64 head layers.
.macro NEV_SVE2_GS2 a0, b0, r0, h0, a1, b1, r1, h1
    sub      z4.h, z\b0\().h, z\a0\().h
    sub      z5.h, z\b1\().h, z\a1\().h
    add      z\a0\().h, z\a0\().h, z\b0\().h
    add      z\a1\().h, z\a1\().h, z\b1\().h
    mul      z\b0\().h, z4.h, z\r0\().h
    mul      z\b1\().h, z5.h, z\r1\().h
    sqrdmulh z4.h, z4.h, z\h0\().h
    sqrdmulh z5.h, z5.h, z\h1\().h
    mls      z\b0\().h, p0/m, z4.h, z31.h
    mls      z\b1\().h, p0/m, z5.h, z31.h
.endm

// Tail CT butterfly on two split-domain pairs with per-lane twiddle vectors
// from the pair groups at x3/x4 (temps z20/z21, twiddles z30/z28 and z23/z22).
.macro NEV_SVE2_TBF2 a0, b0, a1, b1, toff
    ld1h     {z30.h}, p0/z, [x3, #\toff, mul vl]
    ld1h     {z28.h}, p0/z, [x3, #(\toff+1), mul vl]
    ld1h     {z23.h}, p0/z, [x4, #\toff, mul vl]
    ld1h     {z22.h}, p0/z, [x4, #(\toff+1), mul vl]
    mul      z20.h, z\b0\().h, z30.h
    mul      z21.h, z\b1\().h, z23.h
    sqrdmulh z\b0\().h, z\b0\().h, z28.h
    sqrdmulh z\b1\().h, z\b1\().h, z22.h
    mls      z20.h, p0/m, z\b0\().h, z31.h
    mls      z21.h, p0/m, z\b1\().h, z31.h
    sub      z\b0\().h, z\a0\().h, z20.h
    sub      z\b1\().h, z\a1\().h, z21.h
    add      z\a0\().h, z\a0\().h, z20.h
    add      z\a1\().h, z\a1\().h, z21.h
.endm

// Tail lazy GS butterfly on two split-domain pairs (temps z20/z21).
.macro NEV_SVE2_TGS2 a0, b0, a1, b1, toff
    ld1h     {z30.h}, p0/z, [x3, #\toff, mul vl]
    ld1h     {z28.h}, p0/z, [x3, #(\toff+1), mul vl]
    ld1h     {z23.h}, p0/z, [x4, #\toff, mul vl]
    ld1h     {z22.h}, p0/z, [x4, #(\toff+1), mul vl]
    sub      z20.h, z\b0\().h, z\a0\().h
    sub      z21.h, z\b1\().h, z\a1\().h
    add      z\a0\().h, z\a0\().h, z\b0\().h
    add      z\a1\().h, z\a1\().h, z\b1\().h
    mul      z\b0\().h, z20.h, z30.h
    mul      z\b1\().h, z21.h, z23.h
    sqrdmulh z20.h, z20.h, z28.h
    sqrdmulh z21.h, z21.h, z22.h
    mls      z\b0\().h, p0/m, z20.h, z31.h
    mls      z\b1\().h, p0/m, z21.h, z31.h
.endm

// Tail CT butterfly for the same two register pairs in TWO independent
// dim-64 blocks.  Both blocks reuse the x3/x4 twiddles; four independent
// multiply/reduce chains occupy z16-z19.
.macro NEV_SVE2_TBF4 a0, b0, a1, b1, a2, b2, a3, b3, toff
    ld1h     {z30.h}, p0/z, [x3, #\toff, mul vl]
    ld1h     {z28.h}, p0/z, [x3, #(\toff+1), mul vl]
    ld1h     {z23.h}, p0/z, [x4, #\toff, mul vl]
    ld1h     {z22.h}, p0/z, [x4, #(\toff+1), mul vl]
    mul      z16.h, z\b0\().h, z30.h
    mul      z17.h, z\b1\().h, z23.h
    mul      z18.h, z\b2\().h, z30.h
    mul      z19.h, z\b3\().h, z23.h
    sqrdmulh z\b0\().h, z\b0\().h, z28.h
    sqrdmulh z\b1\().h, z\b1\().h, z22.h
    sqrdmulh z\b2\().h, z\b2\().h, z28.h
    sqrdmulh z\b3\().h, z\b3\().h, z22.h
    mls      z16.h, p0/m, z\b0\().h, z31.h
    mls      z17.h, p0/m, z\b1\().h, z31.h
    mls      z18.h, p0/m, z\b2\().h, z31.h
    mls      z19.h, p0/m, z\b3\().h, z31.h
    sub      z\b0\().h, z\a0\().h, z16.h
    sub      z\b1\().h, z\a1\().h, z17.h
    sub      z\b2\().h, z\a2\().h, z18.h
    sub      z\b3\().h, z\a3\().h, z19.h
    add      z\a0\().h, z\a0\().h, z16.h
    add      z\a1\().h, z\a1\().h, z17.h
    add      z\a2\().h, z\a2\().h, z18.h
    add      z\a3\().h, z\a3\().h, z19.h
.endm

// Tail lazy GS twin of NEV_SVE2_TBF4.
.macro NEV_SVE2_TGS4 a0, b0, a1, b1, a2, b2, a3, b3, toff
    ld1h     {z30.h}, p0/z, [x3, #\toff, mul vl]
    ld1h     {z28.h}, p0/z, [x3, #(\toff+1), mul vl]
    ld1h     {z23.h}, p0/z, [x4, #\toff, mul vl]
    ld1h     {z22.h}, p0/z, [x4, #(\toff+1), mul vl]
    sub      z16.h, z\b0\().h, z\a0\().h
    sub      z17.h, z\b1\().h, z\a1\().h
    sub      z18.h, z\b2\().h, z\a2\().h
    sub      z19.h, z\b3\().h, z\a3\().h
    add      z\a0\().h, z\a0\().h, z\b0\().h
    add      z\a1\().h, z\a1\().h, z\b1\().h
    add      z\a2\().h, z\a2\().h, z\b2\().h
    add      z\a3\().h, z\a3\().h, z\b3\().h
    mul      z\b0\().h, z16.h, z30.h
    mul      z\b1\().h, z17.h, z23.h
    mul      z\b2\().h, z18.h, z30.h
    mul      z\b3\().h, z19.h, z23.h
    sqrdmulh z16.h, z16.h, z28.h
    sqrdmulh z17.h, z17.h, z22.h
    sqrdmulh z18.h, z18.h, z28.h
    sqrdmulh z19.h, z19.h, z22.h
    mls      z\b0\().h, p0/m, z16.h, z31.h
    mls      z\b1\().h, p0/m, z17.h, z31.h
    mls      z\b2\().h, p0/m, z18.h, z31.h
    mls      z\b3\().h, p0/m, z19.h, z31.h
.endm

// ----------------------------------------------------------------------------
// Forward tail for TWO register pairs (da0,da1) and (db0,db1): q-split via
// TBL, layers len 8/4/2/1 with uzp sub-splits, exact Barrett sync pass,
// un-permute, store to [x0, #so.. #so+3].  (wa*,wb*) are the four work
// registers of the uzp ping-pong; x3/x4 point at the two pairs' tail groups.
// ----------------------------------------------------------------------------
.macro NEV_SVE2_NTT_TAIL2 da0, da1, db0, db1, wa0, wa1, wb0, wb1, sh, so
    tbl     z\wa0\().h, {z\da0\().h, z\da1\().h}, z24.h
    tbl     z\wa1\().h, {z\da0\().h, z\da1\().h}, z25.h
    tbl     z\wb0\().h, {z\db0\().h, z\db1\().h}, z24.h
    tbl     z\wb1\().h, {z\db0\().h, z\db1\().h}, z25.h
    NEV_SVE2_TBF2 \wa0, \wa1, \wb0, \wb1, 0                 // len=8
    uzp1    z\da0\().d, z\wa0\().d, z\wa1\().d
    uzp2    z\da1\().d, z\wa0\().d, z\wa1\().d
    uzp1    z\db0\().d, z\wb0\().d, z\wb1\().d
    uzp2    z\db1\().d, z\wb0\().d, z\wb1\().d
    NEV_SVE2_TBF2 \da0, \da1, \db0, \db1, 2                 // len=4
    uzp1    z\wa0\().s, z\da0\().s, z\da1\().s
    uzp2    z\wa1\().s, z\da0\().s, z\da1\().s
    uzp1    z\wb0\().s, z\db0\().s, z\db1\().s
    uzp2    z\wb1\().s, z\db0\().s, z\db1\().s
    NEV_SVE2_TBF2 \wa0, \wa1, \wb0, \wb1, 4                 // len=2
    uzp1    z\da0\().h, z\wa0\().h, z\wa1\().h
    uzp2    z\da1\().h, z\wa0\().h, z\wa1\().h
    uzp1    z\db0\().h, z\wb0\().h, z\wb1\().h
    uzp2    z\db1\().h, z\wb0\().h, z\wb1\().h
    NEV_SVE2_TBF2 \da0, \da1, \db0, \db1, 6                 // len=1
    // exact Barrett sync pass (lane-wise, layout-irrelevant); DO NOT weaken
    // or move: it makes the forward output bit-identical to C
    NEV_SVE2_NTT_BR \da0, 20, \sh
    NEV_SVE2_NTT_BR \da1, 21, \sh
    NEV_SVE2_NTT_BR \db0, 20, \sh
    NEV_SVE2_NTT_BR \db1, 21, \sh
    tbl     z\wa0\().h, {z\da0\().h, z\da1\().h}, z26.h
    tbl     z\wa1\().h, {z\da0\().h, z\da1\().h}, z27.h
    tbl     z\wb0\().h, {z\db0\().h, z\db1\().h}, z26.h
    tbl     z\wb1\().h, {z\db0\().h, z\db1\().h}, z27.h
    st1h    {z\wa0\().h}, p0, [x0, #(\so+0), mul vl]
    st1h    {z\wa1\().h}, p0, [x0, #(\so+1), mul vl]
    st1h    {z\wb0\().h}, p0, [x0, #(\so+2), mul vl]
    st1h    {z\wb1\().h}, p0, [x0, #(\so+3), mul vl]
.endm

// ----------------------------------------------------------------------------
// Inverse tail for TWO register pairs: entry through UE1/UE2 (the split
// permutation is an involution), lazy GS layers len 1/2/4 with zip re-merges,
// the ONE exact Barrett of the lazy schedule after len 4, lazy len 8, then
// merge back through QA/QB.  Results land in the WORK registers
// (wa0,wa1,wb0,wb1) — the caller's head layers use them there.
// ----------------------------------------------------------------------------
.macro NEV_SVE2_INTT_TAIL2 da0, da1, db0, db1, wa0, wa1, wb0, wb1, sh
    tbl     z\wa0\().h, {z\da0\().h, z\da1\().h}, z26.h
    tbl     z\wa1\().h, {z\da0\().h, z\da1\().h}, z27.h
    tbl     z\wb0\().h, {z\db0\().h, z\db1\().h}, z26.h
    tbl     z\wb1\().h, {z\db0\().h, z\db1\().h}, z27.h
    NEV_SVE2_TGS2 \wa0, \wa1, \wb0, \wb1, 0                 // len=1
    zip1    z\da0\().h, z\wa0\().h, z\wa1\().h
    zip2    z\da1\().h, z\wa0\().h, z\wa1\().h
    zip1    z\db0\().h, z\wb0\().h, z\wb1\().h
    zip2    z\db1\().h, z\wb0\().h, z\wb1\().h
    NEV_SVE2_TGS2 \da0, \da1, \db0, \db1, 2                 // len=2
    zip1    z\wa0\().s, z\da0\().s, z\da1\().s
    zip2    z\wa1\().s, z\da0\().s, z\da1\().s
    zip1    z\wb0\().s, z\db0\().s, z\db1\().s
    zip2    z\wb1\().s, z\db0\().s, z\db1\().s
    NEV_SVE2_TGS2 \wa0, \wa1, \wb0, \wb1, 4                 // len=4
    // the ONE exact Barrett pass of the lazy inverse (after len 4)
    NEV_SVE2_NTT_BR \wa0, 20, \sh
    NEV_SVE2_NTT_BR \wa1, 21, \sh
    NEV_SVE2_NTT_BR \wb0, 20, \sh
    NEV_SVE2_NTT_BR \wb1, 21, \sh
    zip1    z\da0\().d, z\wa0\().d, z\wa1\().d
    zip2    z\da1\().d, z\wa0\().d, z\wa1\().d
    zip1    z\db0\().d, z\wb0\().d, z\wb1\().d
    zip2    z\db1\().d, z\wb0\().d, z\wb1\().d
    NEV_SVE2_TGS2 \da0, \da1, \db0, \db1, 6                 // len=8
    tbl     z\wa0\().h, {z\da0\().h, z\da1\().h}, z24.h
    tbl     z\wa1\().h, {z\da0\().h, z\da1\().h}, z25.h
    tbl     z\wb0\().h, {z\db0\().h, z\db1\().h}, z24.h
    tbl     z\wb1\().h, {z\db0\().h, z\db1\().h}, z25.h
.endm

// Materialize the fused-scale broadcast vectors: z30 = fP, z28 = fP_hi,
// z26 = fzetaP, z25 = fzetaP_hi (16-bit immediates from the kernel args).
.macro NEV_SVE2_LDF fp, fphi, fz, fzhi
    movz    w9, #\fp
    dup     z30.h, w9
    movz    w9, #\fphi
    dup     z28.h, w9
    movz    w9, #\fz
    dup     z26.h, w9
    movz    w9, #\fzhi
    dup     z25.h, w9
.endm

// Shared kernel constants.  Whole-polynomial entries materialize these once
// and reuse them across every 64/128-coefficient block.
.macro NEV_SVE2_NTT_CONSTS qval, mval
    ptrue   p0.h
    movz    w9, #\qval
    dup     z31.h, w9
    movz    w9, #\mval
    dup     z29.h, w9
.endm

.macro NEV_SVE2_NTT_PTRS
    add     x2, x1, #128                // head scalar pairs
    add     x3, x1, #160                // tail group, first pair
    add     x4, x1, #(160+256)          // tail group, second pair
.endm

// Shared kernel prologue: predicate, q/barrettV broadcasts, region base
// pointers (the block loads live in each body macro).
.macro NEV_SVE2_NTT_PROLOG qval, mval
    NEV_SVE2_NTT_CONSTS \qval, \mval
    NEV_SVE2_NTT_PTRS
.endm

// Load the four TBL index vectors: z24 = QA, z25 = QB, z26 = UE1, z27 = UE2.
.macro NEV_SVE2_NTT_IDX
    ld1h    {z24.h}, p0/z, [x1, #0, mul vl]
    ld1h    {z25.h}, p0/z, [x1, #1, mul vl]
    ld1h    {z26.h}, p0/z, [x1, #2, mul vl]
    ld1h    {z27.h}, p0/z, [x1, #3, mul vl]
.endm

/* Recover two message bytes from sixteen base carriers and their three
 * quarter-block companions.  The input vectors are inverse-NTT outputs and
 * may be destroyed.  z31=q, z27=q/2, z28={1,2,...,2^15}, x7=message. */
.macro NEV_SVE2_MSG4 za, zb, zc, zd, off
    // FlipAbs(x): distance from q/2 after the inverse output's Caddq.
    asr     z20.h, z\za\().h, #15
    asr     z21.h, z\zb\().h, #15
    asr     z22.h, z\zc\().h, #15
    asr     z23.h, z\zd\().h, #15
    and     z20.d, z20.d, z31.d
    and     z21.d, z21.d, z31.d
    and     z22.d, z22.d, z31.d
    and     z23.d, z23.d, z31.d
    add     z\za\().h, z\za\().h, z20.h
    add     z\zb\().h, z\zb\().h, z21.h
    add     z\zc\().h, z\zc\().h, z22.h
    add     z\zd\().h, z\zd\().h, z23.h
    sub     z\za\().h, z\za\().h, z27.h
    sub     z\zb\().h, z\zb\().h, z27.h
    sub     z\zc\().h, z\zc\().h, z27.h
    sub     z\zd\().h, z\zd\().h, z27.h
    asr     z20.h, z\za\().h, #15
    asr     z21.h, z\zb\().h, #15
    asr     z22.h, z\zc\().h, #15
    asr     z23.h, z\zd\().h, #15
    add     z\za\().h, z\za\().h, z20.h
    add     z\zb\().h, z\zb\().h, z21.h
    add     z\zc\().h, z\zc\().h, z22.h
    add     z\zd\().h, z\zd\().h, z23.h
    eor     z\za\().d, z\za\().d, z20.d
    eor     z\zb\().d, z\zb\().d, z21.d
    eor     z\zc\().d, z\zc\().d, z22.d
    eor     z\zd\().d, z\zd\().d, z23.d
    add     z\za\().h, z\za\().h, z\zb\().h
    add     z\zc\().h, z\zc\().h, z\zd\().h
    add     z\za\().h, z\za\().h, z\zc\().h
    cmplo   p1.h, p0/z, z\za\().h, z31.h
    mov     z24.h, #0
    cpy     z24.h, p1/m, #1
    mul     z24.h, z24.h, z28.h
    uaddv   d24, p0, z24.h
    fmov    x9, d24
    strb    w9, [x7, #\off]
    lsr     w10, w9, #8
    strb    w10, [x7, #(\off + 1)]
.endm

// ----------------------------------------------------------------------------
// Whole-kernel bodies.
// ----------------------------------------------------------------------------

// Forward NTT, dim = 128 (len 64/32/16 cross-register + tail groups).
.macro NEV_SVE2_NTT128_BODY qval, mval, sh, fp, fphi, fz, fzhi, setup=1
.if \setup
    NEV_SVE2_NTT_PROLOG \qval, \mval
.else
    NEV_SVE2_NTT_PTRS
.endif
    ld1h    {z0.h}, p0/z, [x0, #0, mul vl]
    ld1h    {z1.h}, p0/z, [x0, #1, mul vl]
    ld1h    {z2.h}, p0/z, [x0, #2, mul vl]
    ld1h    {z3.h}, p0/z, [x0, #3, mul vl]
    ld1h    {z4.h}, p0/z, [x0, #4, mul vl]
    ld1h    {z5.h}, p0/z, [x0, #5, mul vl]
    ld1h    {z6.h}, p0/z, [x0, #6, mul vl]
    ld1h    {z7.h}, p0/z, [x0, #7, mul vl]
    // len=64: zeta_1
    ld1rh   {z30.h}, p0/z, [x2, #0]
    ld1rh   {z28.h}, p0/z, [x2, #2]
    NEV_SVE2_CT4 0, 4, 30, 28, 1, 5, 30, 28, 2, 6, 30, 28, 3, 7, 30, 28
    // len=32: zeta_2 (first half), zeta_3 (second half)
    ld1rh   {z30.h}, p0/z, [x2, #4]
    ld1rh   {z28.h}, p0/z, [x2, #6]
    ld1rh   {z23.h}, p0/z, [x2, #8]
    ld1rh   {z22.h}, p0/z, [x2, #10]
    NEV_SVE2_CT4 0, 2, 30, 28, 1, 3, 30, 28, 4, 6, 23, 22, 5, 7, 23, 22
    // len=16: zeta_4..7
    ld1rh   {z30.h}, p0/z, [x2, #12]
    ld1rh   {z28.h}, p0/z, [x2, #14]
    ld1rh   {z23.h}, p0/z, [x2, #16]
    ld1rh   {z22.h}, p0/z, [x2, #18]
    ld1rh   {z21.h}, p0/z, [x2, #20]
    ld1rh   {z20.h}, p0/z, [x2, #22]
    ld1rh   {z27.h}, p0/z, [x2, #24]
    ld1rh   {z26.h}, p0/z, [x2, #26]
    NEV_SVE2_CT4 0, 1, 30, 28, 2, 3, 23, 22, 4, 5, 21, 20, 6, 7, 27, 26
    // len=8/4/2/1 + Barrett in the split domain (see NEV_SVE2_NTT_TAIL2)
    NEV_SVE2_NTT_IDX
    NEV_SVE2_NTT_TAIL2 0, 1, 2, 3, 16, 17, 18, 19, \sh, 0
    add     x3, x3, #512
    add     x4, x4, #512
    NEV_SVE2_NTT_TAIL2 4, 5, 6, 7, 16, 17, 18, 19, \sh, 4
.endm

// Inverse NTT, dim = 128.  After the two tail sets the block lives in
// (z16,z17) (coeffs 0..31), (z18,z19) (32..63), (z0,z1) (64..95),
// (z2,z3) (96..127); the head layers and the fused final scale work there.
.macro NEV_SVE2_INTT128_BODY qval, mval, sh, fp, fphi, fz, fzhi, setup=1, input_reduce=0, to_msg=0
.if \setup
    NEV_SVE2_NTT_PROLOG \qval, \mval
.else
    NEV_SVE2_NTT_PTRS
.endif
    ld1h    {z0.h}, p0/z, [x0, #0, mul vl]
    ld1h    {z1.h}, p0/z, [x0, #1, mul vl]
    ld1h    {z2.h}, p0/z, [x0, #2, mul vl]
    ld1h    {z3.h}, p0/z, [x0, #3, mul vl]
    ld1h    {z4.h}, p0/z, [x0, #4, mul vl]
    ld1h    {z5.h}, p0/z, [x0, #5, mul vl]
    ld1h    {z6.h}, p0/z, [x0, #6, mul vl]
    ld1h    {z7.h}, p0/z, [x0, #7, mul vl]
.if \input_reduce
    // Fold the caller's exact PolyReduce pass into the initial block load.
    // This restores the inverse NTT's |x| <= (q-1)/2 input contract without
    // writing and immediately reloading the normalized polynomial.
    NEV_SVE2_NTT_BR 0, 16, \sh
    NEV_SVE2_NTT_BR 1, 16, \sh
    NEV_SVE2_NTT_BR 2, 16, \sh
    NEV_SVE2_NTT_BR 3, 16, \sh
    NEV_SVE2_NTT_BR 4, 16, \sh
    NEV_SVE2_NTT_BR 5, 16, \sh
    NEV_SVE2_NTT_BR 6, 16, \sh
    NEV_SVE2_NTT_BR 7, 16, \sh
.endif
    NEV_SVE2_NTT_IDX
    NEV_SVE2_INTT_TAIL2 0, 1, 2, 3, 16, 17, 18, 19, \sh
    add     x3, x3, #512
    add     x4, x4, #512
    NEV_SVE2_INTT_TAIL2 4, 5, 6, 7, 0, 1, 2, 3, \sh
    // len=16 (lazy): zeta_7..4
    ld1rh   {z30.h}, p0/z, [x2, #0]
    ld1rh   {z28.h}, p0/z, [x2, #2]
    ld1rh   {z26.h}, p0/z, [x2, #4]
    ld1rh   {z25.h}, p0/z, [x2, #6]
    ld1rh   {z24.h}, p0/z, [x2, #8]
    ld1rh   {z23.h}, p0/z, [x2, #10]
    ld1rh   {z22.h}, p0/z, [x2, #12]
    ld1rh   {z21.h}, p0/z, [x2, #14]
    NEV_SVE2_GS4 16, 17, 30, 28, 18, 19, 26, 25, 0, 1, 24, 23, 2, 3, 22, 21
    // len=32 (lazy): zeta_3, zeta_2
    ld1rh   {z30.h}, p0/z, [x2, #16]
    ld1rh   {z28.h}, p0/z, [x2, #18]
    ld1rh   {z26.h}, p0/z, [x2, #20]
    ld1rh   {z25.h}, p0/z, [x2, #22]
    NEV_SVE2_GS4 16, 18, 30, 28, 17, 19, 30, 28, 0, 2, 26, 25, 1, 3, 26, 25
    // len=64 fused with the mont^2/dim scale:
    //   out_a = mm3(a + b, fP), out_b = mm3(b - a, fzetaP)
    NEV_SVE2_LDF \fp, \fphi, \fz, \fzhi
    sub      z4.h, z0.h, z16.h
    sub      z5.h, z1.h, z17.h
    sub      z6.h, z2.h, z18.h
    sub      z7.h, z3.h, z19.h
    add      z16.h, z16.h, z0.h
    add      z17.h, z17.h, z1.h
    add      z18.h, z18.h, z2.h
    add      z19.h, z19.h, z3.h
    mul      z0.h, z16.h, z30.h
    mul      z1.h, z17.h, z30.h
    mul      z2.h, z18.h, z30.h
    mul      z3.h, z19.h, z30.h
    sqrdmulh z16.h, z16.h, z28.h
    sqrdmulh z17.h, z17.h, z28.h
    sqrdmulh z18.h, z18.h, z28.h
    sqrdmulh z19.h, z19.h, z28.h
    mls      z0.h, p0/m, z16.h, z31.h
    mls      z1.h, p0/m, z17.h, z31.h
    mls      z2.h, p0/m, z18.h, z31.h
    mls      z3.h, p0/m, z19.h, z31.h
    mul      z16.h, z4.h, z26.h
    mul      z17.h, z5.h, z26.h
    mul      z18.h, z6.h, z26.h
    mul      z19.h, z7.h, z26.h
    sqrdmulh z4.h, z4.h, z25.h
    sqrdmulh z5.h, z5.h, z25.h
    sqrdmulh z6.h, z6.h, z25.h
    sqrdmulh z7.h, z7.h, z25.h
    mls      z16.h, p0/m, z4.h, z31.h
    mls      z17.h, p0/m, z5.h, z31.h
    mls      z18.h, p0/m, z6.h, z31.h
    mls      z19.h, p0/m, z7.h, z31.h
.if \to_msg
    movz    w9, #(\qval / 2)
    dup     z27.h, w9
    index   z26.h, #0, #1
    mov     z28.h, #1
    lsl     z28.h, p0/m, z28.h, z26.h
    NEV_SVE2_MSG4 0, 2, 16, 18, 0
    NEV_SVE2_MSG4 1, 3, 17, 19, 2
.else
    st1h    {z0.h}, p0, [x0, #0, mul vl]
    st1h    {z1.h}, p0, [x0, #1, mul vl]
    st1h    {z2.h}, p0, [x0, #2, mul vl]
    st1h    {z3.h}, p0, [x0, #3, mul vl]
    st1h    {z16.h}, p0, [x0, #4, mul vl]
    st1h    {z17.h}, p0, [x0, #5, mul vl]
    st1h    {z18.h}, p0, [x0, #6, mul vl]
    st1h    {z19.h}, p0, [x0, #7, mul vl]
.endif
.endm

// Forward NTT, dim = 64 (len 32/16 cross-register + one tail set).
.macro NEV_SVE2_NTT64_BODY qval, mval, sh, fp, fphi, fz, fzhi, setup=1
.if \setup
    NEV_SVE2_NTT_PROLOG \qval, \mval
.else
    NEV_SVE2_NTT_PTRS
.endif
    ld1h    {z0.h}, p0/z, [x0, #0, mul vl]
    ld1h    {z1.h}, p0/z, [x0, #1, mul vl]
    ld1h    {z2.h}, p0/z, [x0, #2, mul vl]
    ld1h    {z3.h}, p0/z, [x0, #3, mul vl]
    // len=32: zeta_1
    ld1rh   {z30.h}, p0/z, [x2, #0]
    ld1rh   {z28.h}, p0/z, [x2, #2]
    NEV_SVE2_CT2 0, 2, 30, 28, 1, 3, 30, 28
    // len=16: zeta_2, zeta_3
    ld1rh   {z30.h}, p0/z, [x2, #4]
    ld1rh   {z28.h}, p0/z, [x2, #6]
    ld1rh   {z23.h}, p0/z, [x2, #8]
    ld1rh   {z22.h}, p0/z, [x2, #10]
    NEV_SVE2_CT2 0, 1, 30, 28, 2, 3, 23, 22
    NEV_SVE2_NTT_IDX
    NEV_SVE2_NTT_TAIL2 0, 1, 2, 3, 16, 17, 18, 19, \sh, 0
.endm

// Inverse NTT, dim = 64.  After the tail set the block lives in
// (z16,z17) (coeffs 0..31) and (z18,z19) (32..63).
.macro NEV_SVE2_INTT64_BODY qval, mval, sh, fp, fphi, fz, fzhi, setup=1
.if \setup
    NEV_SVE2_NTT_PROLOG \qval, \mval
.else
    NEV_SVE2_NTT_PTRS
.endif
    ld1h    {z0.h}, p0/z, [x0, #0, mul vl]
    ld1h    {z1.h}, p0/z, [x0, #1, mul vl]
    ld1h    {z2.h}, p0/z, [x0, #2, mul vl]
    ld1h    {z3.h}, p0/z, [x0, #3, mul vl]
    NEV_SVE2_NTT_IDX
    NEV_SVE2_INTT_TAIL2 0, 1, 2, 3, 16, 17, 18, 19, \sh
    // len=16 (lazy): zeta_3, zeta_2
    ld1rh   {z30.h}, p0/z, [x2, #0]
    ld1rh   {z28.h}, p0/z, [x2, #2]
    ld1rh   {z26.h}, p0/z, [x2, #4]
    ld1rh   {z25.h}, p0/z, [x2, #6]
    NEV_SVE2_GS2 16, 17, 30, 28, 18, 19, 26, 25
    // len=32 fused with the scale
    NEV_SVE2_LDF \fp, \fphi, \fz, \fzhi
    sub      z4.h, z18.h, z16.h
    sub      z5.h, z19.h, z17.h
    add      z16.h, z16.h, z18.h
    add      z17.h, z17.h, z19.h
    mul      z0.h, z16.h, z30.h
    mul      z1.h, z17.h, z30.h
    sqrdmulh z16.h, z16.h, z28.h
    sqrdmulh z17.h, z17.h, z28.h
    mls      z0.h, p0/m, z16.h, z31.h
    mls      z1.h, p0/m, z17.h, z31.h
    st1h    {z0.h}, p0, [x0, #0, mul vl]
    st1h    {z1.h}, p0, [x0, #1, mul vl]
    mul      z2.h, z4.h, z26.h
    mul      z3.h, z5.h, z26.h
    sqrdmulh z4.h, z4.h, z25.h
    sqrdmulh z5.h, z5.h, z25.h
    mls      z2.h, p0/m, z4.h, z31.h
    mls      z3.h, p0/m, z5.h, z31.h
    st1h    {z2.h}, p0, [x0, #2, mul vl]
    st1h    {z3.h}, p0, [x0, #3, mul vl]
.endm

// Forward NTT for TWO adjacent dim-64 blocks.  The head layers share scalar
// twiddle broadcasts and issue four independent butterflies at once.  The
// tail keeps both blocks live in z8-z15, reuses every twiddle vector, and
// interleaves four independent multiply/reduce chains.
.macro NEV_SVE2_NTT64_PAIR_BODY qval, mval, sh, fp, fphi, fz, fzhi
    NEV_SVE2_NTT_PTRS
    ld1h    {z0.h}, p0/z, [x0, #0, mul vl]
    ld1h    {z1.h}, p0/z, [x0, #1, mul vl]
    ld1h    {z2.h}, p0/z, [x0, #2, mul vl]
    ld1h    {z3.h}, p0/z, [x0, #3, mul vl]
    ld1h    {z4.h}, p0/z, [x0, #4, mul vl]
    ld1h    {z5.h}, p0/z, [x0, #5, mul vl]
    ld1h    {z6.h}, p0/z, [x0, #6, mul vl]
    ld1h    {z7.h}, p0/z, [x0, #7, mul vl]

    // len=32, same zeta_1 in both blocks.
    ld1rh   {z30.h}, p0/z, [x2, #0]
    ld1rh   {z28.h}, p0/z, [x2, #2]
    NEV_SVE2_CT4 0, 2, 30, 28, 1, 3, 30, 28, 4, 6, 30, 28, 5, 7, 30, 28

    // len=16, zeta_2/zeta_3 reused by the corresponding halves.
    ld1rh   {z30.h}, p0/z, [x2, #4]
    ld1rh   {z28.h}, p0/z, [x2, #6]
    ld1rh   {z23.h}, p0/z, [x2, #8]
    ld1rh   {z22.h}, p0/z, [x2, #10]
    NEV_SVE2_CT4 0, 1, 30, 28, 2, 3, 23, 22, 4, 5, 30, 28, 6, 7, 23, 22

    NEV_SVE2_NTT_IDX
    tbl     z8.h, {z0.h, z1.h}, z24.h
    tbl     z9.h, {z0.h, z1.h}, z25.h
    tbl     z10.h, {z2.h, z3.h}, z24.h
    tbl     z11.h, {z2.h, z3.h}, z25.h
    tbl     z12.h, {z4.h, z5.h}, z24.h
    tbl     z13.h, {z4.h, z5.h}, z25.h
    tbl     z14.h, {z6.h, z7.h}, z24.h
    tbl     z15.h, {z6.h, z7.h}, z25.h

    NEV_SVE2_TBF4 8, 9, 10, 11, 12, 13, 14, 15, 0       // len=8
    uzp1    z0.d, z8.d, z9.d
    uzp2    z1.d, z8.d, z9.d
    uzp1    z2.d, z10.d, z11.d
    uzp2    z3.d, z10.d, z11.d
    uzp1    z4.d, z12.d, z13.d
    uzp2    z5.d, z12.d, z13.d
    uzp1    z6.d, z14.d, z15.d
    uzp2    z7.d, z14.d, z15.d
    NEV_SVE2_TBF4 0, 1, 2, 3, 4, 5, 6, 7, 2             // len=4
    uzp1    z8.s, z0.s, z1.s
    uzp2    z9.s, z0.s, z1.s
    uzp1    z10.s, z2.s, z3.s
    uzp2    z11.s, z2.s, z3.s
    uzp1    z12.s, z4.s, z5.s
    uzp2    z13.s, z4.s, z5.s
    uzp1    z14.s, z6.s, z7.s
    uzp2    z15.s, z6.s, z7.s
    NEV_SVE2_TBF4 8, 9, 10, 11, 12, 13, 14, 15, 4       // len=2
    uzp1    z0.h, z8.h, z9.h
    uzp2    z1.h, z8.h, z9.h
    uzp1    z2.h, z10.h, z11.h
    uzp2    z3.h, z10.h, z11.h
    uzp1    z4.h, z12.h, z13.h
    uzp2    z5.h, z12.h, z13.h
    uzp1    z6.h, z14.h, z15.h
    uzp2    z7.h, z14.h, z15.h
    NEV_SVE2_TBF4 0, 1, 2, 3, 4, 5, 6, 7, 6             // len=1

    NEV_SVE2_NTT_BR 0, 16, \sh
    NEV_SVE2_NTT_BR 1, 17, \sh
    NEV_SVE2_NTT_BR 2, 18, \sh
    NEV_SVE2_NTT_BR 3, 19, \sh
    NEV_SVE2_NTT_BR 4, 16, \sh
    NEV_SVE2_NTT_BR 5, 17, \sh
    NEV_SVE2_NTT_BR 6, 18, \sh
    NEV_SVE2_NTT_BR 7, 19, \sh

    tbl     z8.h, {z0.h, z1.h}, z26.h
    tbl     z9.h, {z0.h, z1.h}, z27.h
    tbl     z10.h, {z2.h, z3.h}, z26.h
    tbl     z11.h, {z2.h, z3.h}, z27.h
    tbl     z12.h, {z4.h, z5.h}, z26.h
    tbl     z13.h, {z4.h, z5.h}, z27.h
    tbl     z14.h, {z6.h, z7.h}, z26.h
    tbl     z15.h, {z6.h, z7.h}, z27.h
    st1h    {z8.h}, p0, [x0, #0, mul vl]
    st1h    {z9.h}, p0, [x0, #1, mul vl]
    st1h    {z10.h}, p0, [x0, #2, mul vl]
    st1h    {z11.h}, p0, [x0, #3, mul vl]
    st1h    {z12.h}, p0, [x0, #4, mul vl]
    st1h    {z13.h}, p0, [x0, #5, mul vl]
    st1h    {z14.h}, p0, [x0, #6, mul vl]
    st1h    {z15.h}, p0, [x0, #7, mul vl]
.endm

// Inverse NTT for TWO adjacent dim-64 blocks.  The inverse tail and head use
// the same four-chain schedule and share all table loads between the blocks.
.macro NEV_SVE2_INTT64_PAIR_BODY qval, mval, sh, fp, fphi, fz, fzhi, input_reduce=0, to_msg=0
    NEV_SVE2_NTT_PTRS
    ld1h    {z0.h}, p0/z, [x0, #0, mul vl]
    ld1h    {z1.h}, p0/z, [x0, #1, mul vl]
    ld1h    {z2.h}, p0/z, [x0, #2, mul vl]
    ld1h    {z3.h}, p0/z, [x0, #3, mul vl]
    ld1h    {z4.h}, p0/z, [x0, #4, mul vl]
    ld1h    {z5.h}, p0/z, [x0, #5, mul vl]
    ld1h    {z6.h}, p0/z, [x0, #6, mul vl]
    ld1h    {z7.h}, p0/z, [x0, #7, mul vl]
.if \input_reduce
    NEV_SVE2_NTT_BR 0, 16, \sh
    NEV_SVE2_NTT_BR 1, 16, \sh
    NEV_SVE2_NTT_BR 2, 16, \sh
    NEV_SVE2_NTT_BR 3, 16, \sh
    NEV_SVE2_NTT_BR 4, 16, \sh
    NEV_SVE2_NTT_BR 5, 16, \sh
    NEV_SVE2_NTT_BR 6, 16, \sh
    NEV_SVE2_NTT_BR 7, 16, \sh
.endif
    NEV_SVE2_NTT_IDX

    tbl     z8.h, {z0.h, z1.h}, z26.h
    tbl     z9.h, {z0.h, z1.h}, z27.h
    tbl     z10.h, {z2.h, z3.h}, z26.h
    tbl     z11.h, {z2.h, z3.h}, z27.h
    tbl     z12.h, {z4.h, z5.h}, z26.h
    tbl     z13.h, {z4.h, z5.h}, z27.h
    tbl     z14.h, {z6.h, z7.h}, z26.h
    tbl     z15.h, {z6.h, z7.h}, z27.h

    NEV_SVE2_TGS4 8, 9, 10, 11, 12, 13, 14, 15, 0       // len=1
    zip1    z0.h, z8.h, z9.h
    zip2    z1.h, z8.h, z9.h
    zip1    z2.h, z10.h, z11.h
    zip2    z3.h, z10.h, z11.h
    zip1    z4.h, z12.h, z13.h
    zip2    z5.h, z12.h, z13.h
    zip1    z6.h, z14.h, z15.h
    zip2    z7.h, z14.h, z15.h
    NEV_SVE2_TGS4 0, 1, 2, 3, 4, 5, 6, 7, 2             // len=2
    zip1    z8.s, z0.s, z1.s
    zip2    z9.s, z0.s, z1.s
    zip1    z10.s, z2.s, z3.s
    zip2    z11.s, z2.s, z3.s
    zip1    z12.s, z4.s, z5.s
    zip2    z13.s, z4.s, z5.s
    zip1    z14.s, z6.s, z7.s
    zip2    z15.s, z6.s, z7.s
    NEV_SVE2_TGS4 8, 9, 10, 11, 12, 13, 14, 15, 4       // len=4

    NEV_SVE2_NTT_BR 8, 16, \sh
    NEV_SVE2_NTT_BR 9, 17, \sh
    NEV_SVE2_NTT_BR 10, 18, \sh
    NEV_SVE2_NTT_BR 11, 19, \sh
    NEV_SVE2_NTT_BR 12, 16, \sh
    NEV_SVE2_NTT_BR 13, 17, \sh
    NEV_SVE2_NTT_BR 14, 18, \sh
    NEV_SVE2_NTT_BR 15, 19, \sh

    zip1    z0.d, z8.d, z9.d
    zip2    z1.d, z8.d, z9.d
    zip1    z2.d, z10.d, z11.d
    zip2    z3.d, z10.d, z11.d
    zip1    z4.d, z12.d, z13.d
    zip2    z5.d, z12.d, z13.d
    zip1    z6.d, z14.d, z15.d
    zip2    z7.d, z14.d, z15.d
    NEV_SVE2_TGS4 0, 1, 2, 3, 4, 5, 6, 7, 6             // len=8

    tbl     z8.h, {z0.h, z1.h}, z24.h
    tbl     z9.h, {z0.h, z1.h}, z25.h
    tbl     z10.h, {z2.h, z3.h}, z24.h
    tbl     z11.h, {z2.h, z3.h}, z25.h
    tbl     z12.h, {z4.h, z5.h}, z24.h
    tbl     z13.h, {z4.h, z5.h}, z25.h
    tbl     z14.h, {z6.h, z7.h}, z24.h
    tbl     z15.h, {z6.h, z7.h}, z25.h

    // len=16, zeta_3/zeta_2 shared by both blocks.
    ld1rh   {z30.h}, p0/z, [x2, #0]
    ld1rh   {z28.h}, p0/z, [x2, #2]
    ld1rh   {z26.h}, p0/z, [x2, #4]
    ld1rh   {z25.h}, p0/z, [x2, #6]
    NEV_SVE2_GS4 8, 9, 30, 28, 10, 11, 26, 25, 12, 13, 30, 28, 14, 15, 26, 25

    // len=32 fused with the scale, four independent chains per scale.
    NEV_SVE2_LDF \fp, \fphi, \fz, \fzhi
    sub      z4.h, z10.h, z8.h
    sub      z5.h, z11.h, z9.h
    sub      z6.h, z14.h, z12.h
    sub      z7.h, z15.h, z13.h
    add      z8.h, z8.h, z10.h
    add      z9.h, z9.h, z11.h
    add      z12.h, z12.h, z14.h
    add      z13.h, z13.h, z15.h

    mul      z0.h, z8.h, z30.h
    mul      z1.h, z9.h, z30.h
    mul      z16.h, z12.h, z30.h
    mul      z17.h, z13.h, z30.h
    sqrdmulh z8.h, z8.h, z28.h
    sqrdmulh z9.h, z9.h, z28.h
    sqrdmulh z12.h, z12.h, z28.h
    sqrdmulh z13.h, z13.h, z28.h
    mls      z0.h, p0/m, z8.h, z31.h
    mls      z1.h, p0/m, z9.h, z31.h
    mls      z16.h, p0/m, z12.h, z31.h
    mls      z17.h, p0/m, z13.h, z31.h

    mul      z2.h, z4.h, z26.h
    mul      z3.h, z5.h, z26.h
    mul      z18.h, z6.h, z26.h
    mul      z19.h, z7.h, z26.h
    sqrdmulh z4.h, z4.h, z25.h
    sqrdmulh z5.h, z5.h, z25.h
    sqrdmulh z6.h, z6.h, z25.h
    sqrdmulh z7.h, z7.h, z25.h
    mls      z2.h, p0/m, z4.h, z31.h
    mls      z3.h, p0/m, z5.h, z31.h
    mls      z18.h, p0/m, z6.h, z31.h
    mls      z19.h, p0/m, z7.h, z31.h

.if \to_msg
    movz    w9, #(\qval / 2)
    dup     z27.h, w9
    index   z26.h, #0, #1
    mov     z28.h, #1
    lsl     z28.h, p0/m, z28.h, z26.h
    NEV_SVE2_MSG4 0, 1, 2, 3, 0
    NEV_SVE2_MSG4 16, 17, 18, 19, 2
.else
    st1h    {z0.h}, p0, [x0, #0, mul vl]
    st1h    {z1.h}, p0, [x0, #1, mul vl]
    st1h    {z2.h}, p0, [x0, #2, mul vl]
    st1h    {z3.h}, p0, [x0, #3, mul vl]
    st1h    {z16.h}, p0, [x0, #4, mul vl]
    st1h    {z17.h}, p0, [x0, #5, mul vl]
    st1h    {z18.h}, p0, [x0, #6, mul vl]
    st1h    {z19.h}, p0, [x0, #7, mul vl]
.endif
.endm

// ----------------------------------------------------------------------------
// Kernel entry points.  No callee-saved registers are written (z8-z15
// untouched, GPRs x0-x4/x9 only), so there is no frame beyond PAC.
// ----------------------------------------------------------------------------
.macro NEV_SVE2_KERNEL_FUNC name, body, qval, mval, sh, fp, fphi, fz, fzhi
CRYPT_AARCH64_FUNC_START(\name)
AARCH64_PACIASP
    \body   \qval, \mval, \sh, \fp, \fphi, \fz, \fzhi
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(\name)
.endm

// Whole-polynomial entry: x0=coeffs, x1=table, x2=n.  x5/x6 survive each
// inline block body, eliminating C-to-assembly calls and hoisting p0/q/V.
.macro NEV_SVE2_POLY_FUNC name, body, dim, qval, mval, sh, fp, fphi, fz, fzhi
CRYPT_AARCH64_FUNC_START(\name)
AARCH64_PACIASP
    NEV_SVE2_NTT_CONSTS \qval, \mval
    mov     x5, x0
    mov     x6, x2
.Lpoly_loop_\@:
    mov     x0, x5
    \body   \qval, \mval, \sh, \fp, \fphi, \fz, \fzhi, 0
    add     x5, x5, #(2 * \dim)
    subs    x6, x6, #\dim
    b.ne    .Lpoly_loop_\@
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(\name)
.endm

// Whole-polynomial inverse entry with the exact input Barrett normalization
// fused into each block's initial register loads.
.macro NEV_SVE2_POLY_REDUCE_FUNC name, body, dim, qval, mval, sh, fp, fphi, fz, fzhi
CRYPT_AARCH64_FUNC_START(\name)
AARCH64_PACIASP
    NEV_SVE2_NTT_CONSTS \qval, \mval
    mov     x5, x0
    mov     x6, x2
.Lpoly_reduce_loop_\@:
    mov     x0, x5
    \body   \qval, \mval, \sh, \fp, \fphi, \fz, \fzhi, 0, 1
    add     x5, x5, #(2 * \dim)
    subs    x6, x6, #\dim
    b.ne    .Lpoly_reduce_loop_\@
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(\name)
.endm

// x0=coeffs, x1=table, x2=n, x3=message.  Each inverse block is reduced,
// transformed and decoded while resident in registers; the polynomial output
// is intentionally not written because the decapsulation caller consumes
// only the recovered message.
.macro NEV_SVE2_POLY_REDUCE_MSG_FUNC name, body, dim, qval, mval, sh, fp, fphi, fz, fzhi
CRYPT_AARCH64_FUNC_START(\name)
AARCH64_PACIASP
    NEV_SVE2_NTT_CONSTS \qval, \mval
    mov     x5, x0
    mov     x6, x2
    mov     x7, x3
.Lpoly_reduce_msg_loop_\@:
    mov     x0, x5
    \body   \qval, \mval, \sh, \fp, \fphi, \fz, \fzhi, 0, 1, 1
    add     x5, x5, #(2 * \dim)
    add     x7, x7, #(\dim / 32)
    subs    x6, x6, #\dim
    b.ne    .Lpoly_reduce_msg_loop_\@
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(\name)
.endm

// Whole-polynomial dim-64 entry specialized for adjacent block pairs.  Every
// q=1409 parameter has n/64 in {8,16,32}, so there is no odd-block tail.
// The ABI-preserved d8-d15 halves are saved once per polynomial; using their
// z-registers keeps both blocks live and avoids vector spills in the loop.
.macro NEV_SVE2_POLY64_PAIR_FUNC name, body, qval, mval, sh, fp, fphi, fz, fzhi
CRYPT_AARCH64_FUNC_START(\name)
AARCH64_PACIASP
    sub     sp, sp, #64
    stp     d8, d9, [sp, #0]
    stp     d10, d11, [sp, #16]
    stp     d12, d13, [sp, #32]
    stp     d14, d15, [sp, #48]
    NEV_SVE2_NTT_CONSTS \qval, \mval
    mov     x5, x0
    mov     x6, x2
.Lpoly64_pair_loop_\@:
    mov     x0, x5
    \body   \qval, \mval, \sh, \fp, \fphi, \fz, \fzhi
    add     x5, x5, #256                // two 64-coefficient blocks
    subs    x6, x6, #128
    b.ne    .Lpoly64_pair_loop_\@
    ldp     d8, d9, [sp, #0]
    ldp     d10, d11, [sp, #16]
    ldp     d12, d13, [sp, #32]
    ldp     d14, d15, [sp, #48]
    add     sp, sp, #64
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(\name)
.endm

.macro NEV_SVE2_POLY64_PAIR_REDUCE_FUNC name, body, qval, mval, sh, fp, fphi, fz, fzhi
CRYPT_AARCH64_FUNC_START(\name)
AARCH64_PACIASP
    sub     sp, sp, #64
    stp     d8, d9, [sp, #0]
    stp     d10, d11, [sp, #16]
    stp     d12, d13, [sp, #32]
    stp     d14, d15, [sp, #48]
    NEV_SVE2_NTT_CONSTS \qval, \mval
    mov     x5, x0
    mov     x6, x2
.Lpoly64_pair_reduce_loop_\@:
    mov     x0, x5
    \body   \qval, \mval, \sh, \fp, \fphi, \fz, \fzhi, 1
    add     x5, x5, #256
    subs    x6, x6, #128
    b.ne    .Lpoly64_pair_reduce_loop_\@
    ldp     d8, d9, [sp, #0]
    ldp     d10, d11, [sp, #16]
    ldp     d12, d13, [sp, #32]
    ldp     d14, d15, [sp, #48]
    add     sp, sp, #64
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(\name)
.endm

.macro NEV_SVE2_POLY64_PAIR_REDUCE_MSG_FUNC name, body, qval, mval, sh, fp, fphi, fz, fzhi
CRYPT_AARCH64_FUNC_START(\name)
AARCH64_PACIASP
    sub     sp, sp, #64
    stp     d8, d9, [sp, #0]
    stp     d10, d11, [sp, #16]
    stp     d12, d13, [sp, #32]
    stp     d14, d15, [sp, #48]
    NEV_SVE2_NTT_CONSTS \qval, \mval
    mov     x5, x0
    mov     x6, x2
    mov     x7, x3
.Lpoly64_pair_reduce_msg_loop_\@:
    mov     x0, x5
    \body   \qval, \mval, \sh, \fp, \fphi, \fz, \fzhi, 1, 1
    add     x5, x5, #256
    add     x7, x7, #4
    subs    x6, x6, #128
    b.ne    .Lpoly64_pair_reduce_msg_loop_\@
    ldp     d8, d9, [sp, #0]
    ldp     d10, d11, [sp, #16]
    ldp     d12, d13, [sp, #32]
    ldp     d14, d15, [sp, #48]
    add     sp, sp, #64
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(\name)
.endm

// Fused-scale immediates: identical to nev_ntt_armv8.S (same generator).
//   q=769:  fP = (-257, -10951), fzetaP = (215, 9161)
//   q=1409: fP = (-385, -8954),  fzetaP = (696, 16186)
//   q=3329: fP = (512, 5040),    fzetaP = (-266, -2618)
// srshr shift = barrettShift - 15 = 9 / 10 / 11.

// void NEV_NTT128_Q769_SVE2(int16_t *block, const int16_t *table)
NEV_SVE2_KERNEL_FUNC NEV_NTT128_Q769_SVE2, NEV_SVE2_NTT128_BODY, 769, 21817, 9, 0, 0, 0, 0

// void NEV_INTT128_Q769_SVE2(int16_t *block, const int16_t *table)
NEV_SVE2_KERNEL_FUNC NEV_INTT128_Q769_SVE2, NEV_SVE2_INTT128_BODY, 769, 21817, 9, 0xfeff, 0xd539, 0x00d7, 0x23c9

// void NEV_NTT128_Q3329_SVE2(int16_t *block, const int16_t *table)
NEV_SVE2_KERNEL_FUNC NEV_NTT128_Q3329_SVE2, NEV_SVE2_NTT128_BODY, 3329, 20159, 11, 0, 0, 0, 0

// void NEV_INTT128_Q3329_SVE2(int16_t *block, const int16_t *table)
NEV_SVE2_KERNEL_FUNC NEV_INTT128_Q3329_SVE2, NEV_SVE2_INTT128_BODY, 3329, 20159, 11, 0x0200, 0x13b0, 0xfef6, 0xf5c6

// void NEV_NTT64_Q1409_SVE2(int16_t *block, const int16_t *table)
NEV_SVE2_KERNEL_FUNC NEV_NTT64_Q1409_SVE2, NEV_SVE2_NTT64_BODY, 1409, 23814, 10, 0, 0, 0, 0

// void NEV_INTT64_Q1409_SVE2(int16_t *block, const int16_t *table)
NEV_SVE2_KERNEL_FUNC NEV_INTT64_Q1409_SVE2, NEV_SVE2_INTT64_BODY, 1409, 23814, 10, 0xfe7f, 0xdd06, 0x02b8, 0x3f3a

// Complete polynomial transforms; q and predicates remain live between
// blocks, which is most useful for the 32 blocks of NEV-2048-1409.
NEV_SVE2_POLY_FUNC NEV_POLY_NTT128_Q769_SVE2, NEV_SVE2_NTT128_BODY, 128, 769, 21817, 9, 0, 0, 0, 0
NEV_SVE2_POLY_FUNC NEV_POLY_INTT128_Q769_SVE2, NEV_SVE2_INTT128_BODY, 128, 769, 21817, 9, 0xfeff, 0xd539, 0x00d7, 0x23c9
NEV_SVE2_POLY_FUNC NEV_POLY_NTT128_Q3329_SVE2, NEV_SVE2_NTT128_BODY, 128, 3329, 20159, 11, 0, 0, 0, 0
NEV_SVE2_POLY_FUNC NEV_POLY_INTT128_Q3329_SVE2, NEV_SVE2_INTT128_BODY, 128, 3329, 20159, 11, 0x0200, 0x13b0, 0xfef6, 0xf5c6
NEV_SVE2_POLY64_PAIR_FUNC NEV_POLY_NTT64_Q1409_SVE2, NEV_SVE2_NTT64_PAIR_BODY, 1409, 23814, 10, 0, 0, 0, 0
NEV_SVE2_POLY64_PAIR_FUNC NEV_POLY_INTT64_Q1409_SVE2, NEV_SVE2_INTT64_PAIR_BODY, 1409, 23814, 10, 0xfe7f, 0xdd06, 0x02b8, 0x3f3a
NEV_SVE2_POLY_REDUCE_FUNC NEV_POLY_REDUCE_INTT128_Q769_SVE2, NEV_SVE2_INTT128_BODY, 128, 769, 21817, 9, 0xfeff, 0xd539, 0x00d7, 0x23c9
NEV_SVE2_POLY_REDUCE_FUNC NEV_POLY_REDUCE_INTT128_Q3329_SVE2, NEV_SVE2_INTT128_BODY, 128, 3329, 20159, 11, 0x0200, 0x13b0, 0xfef6, 0xf5c6
NEV_SVE2_POLY64_PAIR_REDUCE_FUNC NEV_POLY_REDUCE_INTT64_Q1409_SVE2, NEV_SVE2_INTT64_PAIR_BODY, 1409, 23814, 10, 0xfe7f, 0xdd06, 0x02b8, 0x3f3a
NEV_SVE2_POLY_REDUCE_MSG_FUNC NEV_POLY_REDUCE_INTT_MSG128_Q769_SVE2, NEV_SVE2_INTT128_BODY, 128, 769, 21817, 9, 0xfeff, 0xd539, 0x00d7, 0x23c9
NEV_SVE2_POLY_REDUCE_MSG_FUNC NEV_POLY_REDUCE_INTT_MSG128_Q3329_SVE2, NEV_SVE2_INTT128_BODY, 128, 3329, 20159, 11, 0x0200, 0x13b0, 0xfef6, 0xf5c6
NEV_SVE2_POLY64_PAIR_REDUCE_MSG_FUNC NEV_POLY_REDUCE_INTT_MSG64_Q1409_SVE2, NEV_SVE2_INTT64_PAIR_BODY, 1409, 23814, 10, 0xfe7f, 0xdd06, 0x02b8, 0x3f3a

#endif // HITLS_CRYPTO_NEV && HITLS_CRYPTO_NEV_SVE2

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
