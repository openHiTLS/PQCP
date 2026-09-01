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
#if defined(HITLS_CRYPTO_NEV) && defined(HITLS_CRYPTO_NEV_SVE2)

#include "crypt_arm.h"
#include "nev_arm_asm.h"
CRYPT_AARCH64_ARCH_SVE2

/*
 * ============================================================================
 * NEV NTT-CRT polynomial arithmetic — supplemental SVE2 kernels
 * ============================================================================
 *
 * Supplemental vector-length-agnostic SVE2 counterparts of the NEON kernels in
 * nev_poly_armv8.S, exporting *Sve2 symbols that the glue in asm_nev_poly.c
 * selects whenever HITLS_CRYPTO_NEV_SVE2 is enabled at build time. The NEON
 * kernels are untouched and remain available in NEON-only builds. These
 * supplemental kernels retain VLA loops even though the primary SVE2
 * arithmetic and NTT kernels are specialized for VL=256.
 *
 * Each kernel computes, lane for lane, the SAME function of the same inputs
 * as the NEON kernel it replaces, so it inherits that kernel's place in the
 * v2 correctness contract verbatim (see the header of asm_nev_poly.c): the
 * exact passes (Barrett, Caddq, Montgomery and their fused forms) stay
 * bit-exact against the C helpers for every int16 input, and the congruent
 * passes stay congruent inside the same proven wrap-free ranges.  Only the
 * lane count and the loop control change.
 *
 * Loop shape.  SVE2 has no post-index addressing and no multi-register
 * contiguous load, so every kernel keeps ONE halfword index in x5 and
 * addresses all of its arrays as [Xn, x5, LSL #1]; INCH advances it by the
 * vector length and WHILELT/B.FIRST closes the loop.  There is no scalar
 * tail: WHILELT handles a final partial vector, which also means these
 * kernels do not need n to be a multiple of the (unknown) lane count, unlike
 * their NEON counterparts.
 *
 * Registers:
 *   p0       loop predicate (WHILELT over the coefficient index)
 *   p1       all-true .h predicate, for the few predicated-only forms
 *   z7       packed constants replicated into EVERY 128-bit segment:
 *            .h[0] = q, .h[1] = qinv, .h[2] = barrettV.  The segment
 *            replication is required because SVE indexed forms select an
 *            element WITHIN each 128-bit segment (they are not whole-vector
 *            broadcasts), and the indexed operand must live in z0-z7.
 *   z6       broadcast (15 - barrettShift), the SRSHL amount
 *   z5       broadcast q, for the Caddq mask
 *   z0-z4, z16-z31   data and temporaries (mirrors the NEON allocation)
 *
 * Bottom/top vs low/high.  This is the one place a mechanical NEON->SVE2
 * transliteration is WRONG and needed care: NEON's SMULL/SMULL2 widen the
 * LOW/HIGH 64-bit halves of a vector, while SVE2's SMULLB/SMULLT widen the
 * EVEN/ODD elements.  So after SMULLB/SMULLT the 32-bit product of
 * coefficient k lives in (k even ? Zlo : Zhi).S[k/2], and the 16-bit
 * recombination that NEON writes as UZP1/UZP2 must be written as TRN1/TRN2:
 *   TRN1 Zd.H, Zlo.H, Zhi.H  ->  Zd.H[k] = low 16 bits of product k
 *   TRN2 Zd.H, Zlo.H, Zhi.H  ->  Zd.H[k] = high 16 bits of product k
 * Every 32-bit accumulation in between is lane-wise and therefore agnostic
 * to which of the two conventions is in force, as long as it is used
 * consistently — which it is: no kernel here mixes SMULL-style and
 * SMULLB-style pairs.
 * ============================================================================
 */

/*
 * Load the packed constants for kernels taking qbPacked in x\rp:
 *   z7 = {q, qinv, barrettV, 0, ...} replicated per 128-bit segment
 *   z6 = 15 - barrettShift (SRSHL amount)   z5 = q
 * INSR shifts the vector up one element and inserts at lane 0, so the three
 * values are inserted in reverse order; DUP .Q then copies the assembled
 * low quadword into every segment.  Clobbers w9/w10 (callers must not alias
 * them with live arguments).
 */
.macro NEV_SVE_QB rp
    lsr     x9, x\rp, #32
    dup     z7.h, #0
    insr    z7.h, w9                    // barrettV -> lane 0
    lsr     x9, x\rp, #16
    insr    z7.h, w9                    // qinv     -> lane 0, barrettV -> 1
    insr    z7.h, w\rp                  // q        -> lane 0
    dup     z7.q, z7.q[0]
    lsr     x9, x\rp, #48
    mov     w10, #15
    sub     w9, w10, w9
    dup     z6.h, w9
    dup     z5.h, w\rp
.endm

/* Same, for kernels taking only qPacked = q | qinv << 16 (no Barrett). */
.macro NEV_SVE_Q rp
    lsr     x9, x\rp, #16
    dup     z7.h, #0
    insr    z7.h, w9                    // qinv
    insr    z7.h, w\rp                  // q
    dup     z7.q, z7.q[0]
    dup     z5.h, w\rp
.endm

/*
 * Montgomery-reduce the 32-bit pair (\zlo even lanes, \zhi odd lanes) into
 * the 16-bit \zout — the SVE2 form of NEV_MRP, with TRN1/TRN2 in place of
 * UZP1/UZP2 for the reason given in the header.  Destroys \zlo and \zhi.
 */
.macro NEV_SVE_MRP zlo, zhi, zout
    trn1    \zout\().h, \zlo\().h, \zhi\().h
    mul     \zout\().h, \zout\().h, z7.h[1]
    smlslb  \zlo\().s, \zout\().h, z7.h[0]
    smlslt  \zhi\().s, \zout\().h, z7.h[0]
    trn2    \zout\().h, \zlo\().h, \zhi\().h
.endm

/* Exact Barrett reduction of \zx in place (\zt scratch): the proven
 * sqdmulh/srshr/mls sequence of NEV_BR8, with SVE2's predicated SRSHL
 * standing in for SRSHR (the amount in z6 is negative, i.e. a right shift). */
.macro NEV_SVE_BR zx, zt
    sqdmulh \zt\().h, \zx\().h, z7.h[2]
    srshl   \zt\().h, p1/m, \zt\().h, z6.h
    mls     \zx\().h, \zt\().h, z7.h[0]
.endm

/* Conditional add of q: r += (r >> 15) & q, identical to NEV_Caddq. */
.macro NEV_SVE_CADDQ zx, zt
    asr     \zt\().h, \zx\().h, #15
    and     \zt\().d, \zt\().d, z5.d
    add     \zx\().h, \zx\().h, \zt\().h
.endm

/*
 * Montgomery reduction of a SIGN-EXTENDED int16, in 4 instructions instead
 * of the NEON widen/multiply/narrow chain.  With P = (int32)a and
 * m = (int16)(a * qinv), the low 16 bits of P and of m*q are equal by
 * construction, so the subtraction cannot borrow out of bit 15 and
 *   (P - m*q) >> 16 == hi16(P) - hi16(m*q) == (a >> 15) - SMULH(m, q),
 * which is exactly NEV_MontReduce((int32_t)a) for every int16 a.
 * z5 must hold q, z7.h[1] qinv.  \zt1/\zt2 are scratch.
 */
.macro NEV_SVE_MONT16 zx, zt1, zt2
    mul     \zt1\().h, \zx\().h, z7.h[1]
    smulh   \zt1\().h, p1/m, \zt1\().h, z5.h
    asr     \zt2\().h, \zx\().h, #15
    sub     \zx\().h, \zt2\().h, \zt1\().h
.endm

/* Full-width Montgomery product. Operands and output may alias. */
.macro NEV_SVE_FQMUL za, zb, zout, zlo=z24, zhi=z25
    smullb  \zlo\().s, \za\().h, \zb\().h
    smullt  \zhi\().s, \za\().h, \zb\().h
    NEV_SVE_MRP \zlo, \zhi, \zout
.endm

.text

// =============================================================================
// uint64_t NEV_Sve2CntH(void)
//   Number of int16 lanes in the build-selected SVE vector (VL / 16).
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_Sve2CntH)
AARCH64_PACIASP
    cnth    x0
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Sve2CntH)
// =============================================================================
// int32_t NEV_BatchMont2InvSve2(int16_t *r, const int16_t *a,
//                               uint64_t dim, uint64_t qPacked)
//
// Sixteen independent strided prefix-product chains, processed in VLA chunks
// so the same implementation covers every architectural SVE vector length.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_BatchMont2InvSve2)
AARCH64_PACIASP
    NEV_SVE_Q 3
    lsr     x4, x2, #4                  // number of rows, 4 or 8
    mov     x14, #0                     // chain-column offset
    mov     x15, #16
9:
    whilelt p0.h, x14, x15
    ld1h    {z16.h}, p0/z, [x1, x14, lsl #1]
    st1h    {z16.h}, p0, [x0, x14, lsl #1]
    mov     x5, #1
1:
    cmp     x5, x4
    b.hs    2f
    lsl     x6, x5, #4                  // row offset in int16 elements
    add     x6, x6, x14
    ld1h    {z17.h}, p0/z, [x1, x6, lsl #1]
    NEV_SVE_FQMUL z16, z17, z16
    st1h    {z16.h}, p0, [x0, x6, lsl #1]
    add     x5, x5, #1
    b       1b
2:
    cmpeq   p2.h, p0/z, z16.h, #0
    ptest   p0, p2.b
    b.any   6f

    // acc = total^(q-2), left-to-right binary exponentiation.  Repeated
    // Montgomery multiplication naturally leaves the required R^2 factor.
    mov     z17.d, z16.d                // immutable base
    uxth    w8, w3
    sub     w8, w8, #2                  // q - 2 (q is low halfword)
    clz     w9, w8
    mov     w10, #30
    sub     w9, w10, w9                 // bit below the leading one
3:
    tbnz    w9, #31, 4f
    NEV_SVE_FQMUL z16, z16, z16
    lsr     w10, w8, w9
    tbz     w10, #0, 5f
    NEV_SVE_FQMUL z16, z17, z16
5:
    sub     w9, w9, #1
    b       3b

4:
    sub     x5, x4, #1
7:
    cbz     x5, 8f
    sub     x6, x5, #1
    lsl     x6, x6, #4
    add     x6, x6, x14
    ld1h    {z18.h}, p0/z, [x0, x6, lsl #1] // previous prefix
    NEV_SVE_FQMUL z16, z18, z19
    lsl     x6, x5, #4
    add     x6, x6, x14
    st1h    {z19.h}, p0, [x0, x6, lsl #1]
    ld1h    {z18.h}, p0/z, [x1, x6, lsl #1] // current input
    NEV_SVE_FQMUL z16, z18, z16
    sub     x5, x5, #1
    b       7b
8:
    st1h    {z16.h}, p0, [x0, x14, lsl #1]
    inch    x14
    cmp     x14, x15
    b.lo    9b
    mov     w0, #1
AARCH64_AUTIASP
    ret
6:
    mov     w0, #0
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_BatchMont2InvSve2)
// =============================================================================
// void NEV_SubArrSve2(int16_t *r, const int16_t *a, const int16_t *b, uint64_t n)
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_SubArrSve2)
AARCH64_PACIASP
    mov     x5, #0
    whilelt p0.h, x5, x3
1:
    ld1h    {z0.h}, p0/z, [x1, x5, lsl #1]
    ld1h    {z1.h}, p0/z, [x2, x5, lsl #1]
    sub     z0.h, z0.h, z1.h
    st1h    {z0.h}, p0, [x0, x5, lsl #1]
    inch    x5
    whilelt p0.h, x5, x3
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_SubArrSve2)
// =============================================================================
// void NEV_CopyBlocksSve2(int16_t *r, const int16_t *a,
//                         uint64_t dimBlocks, uint64_t aStride)
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_CopyBlocksSve2)
AARCH64_PACIASP
    ubfx    x4, x2, #0, #16              // dim
    ubfx    x5, x2, #16, #16             // blocks
    lsl     x3, x3, #1                   // source stride bytes
    lsl     x6, x4, #1                   // destination block bytes
1:
    mov     x7, #0
    whilelt p0.h, x7, x4
2:
    ld1h    {z0.h}, p0/z, [x1, x7, lsl #1]
    st1h    {z0.h}, p0, [x0, x7, lsl #1]
    inch    x7
    whilelt p0.h, x7, x4
    b.first 2b
    add     x0, x0, x6
    add     x1, x1, x3
    subs    x5, x5, #1
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_CopyBlocksSve2)
// =============================================================================
// void NEV_PolyMulCombSve2(int16_t *r, const int16_t *t0,
//                          const int16_t *t1, const int16_t *t2,
//                          const int16_t *y, uint64_t geom,
//                          uint64_t qbPacked)
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_PolyMulCombSve2)
AARCH64_PACIASP
    ptrue   p1.h
    NEV_SVE_QB 6
    lsr     x14, x5, #32                  // h
    mov     w5, w5                        // dim
    lsl     x15, x5, #1                   // block bytes
    mul     x16, x14, x15                 // high-half displacement
    add     x7, x1, x16
    add     x8, x2, x16
    add     x9, x3, x16
    add     x10, x0, x16
    sub     x14, x14, #1                  // paired block count
1:
    mov     x13, #0
    whilelt p0.h, x13, x5
2:
    ld1h    {z0.h}, p0/z, [x1, x13, lsl #1]
    ld1h    {z1.h}, p0/z, [x2, x13, lsl #1]
    ld1h    {z2.h}, p0/z, [x3, x13, lsl #1]
    ld1h    {z3.h}, p0/z, [x7, x13, lsl #1]
    ld1h    {z4.h}, p0/z, [x8, x13, lsl #1]
    ld1h    {z5.h}, p0/z, [x9, x13, lsl #1]
    ld1h    {z16.h}, p0/z, [x4, x13, lsl #1]
    sub     z1.h, z1.h, z0.h
    sub     z1.h, z1.h, z2.h             // u_i
    sub     z4.h, z4.h, z3.h
    sub     z4.h, z4.h, z5.h             // u_{h+i}
    add     z17.h, z2.h, z4.h
    smullb  z18.s, z17.h, z16.h
    smullt  z19.s, z17.h, z16.h
    NEV_SVE_MRP z18, z19, z17
    add     z0.h, z0.h, z17.h
    smullb  z18.s, z5.h, z16.h
    smullt  z19.s, z5.h, z16.h
    NEV_SVE_MRP z18, z19, z17
    add     z3.h, z3.h, z1.h
    add     z3.h, z3.h, z17.h
    st1h    {z0.h}, p0, [x0, x13, lsl #1]
    st1h    {z3.h}, p0, [x10, x13, lsl #1]
    inch    x13
    whilelt p0.h, x13, x5
    b.first 2b
    add     x0, x0, x15
    add     x1, x1, x15
    add     x2, x2, x15
    add     x3, x3, x15
    add     x7, x7, x15
    add     x8, x8, x15
    add     x9, x9, x15
    add     x10, x10, x15
    subs    x14, x14, #1
    b.ne    1b

    mov     x13, #0
    whilelt p0.h, x13, x5
3:
    ld1h    {z0.h}, p0/z, [x1, x13, lsl #1]
    ld1h    {z1.h}, p0/z, [x2, x13, lsl #1]
    ld1h    {z2.h}, p0/z, [x3, x13, lsl #1]
    ld1h    {z16.h}, p0/z, [x4, x13, lsl #1]
    sub     z1.h, z1.h, z0.h
    sub     z1.h, z1.h, z2.h             // r_{2h-1}
    smullb  z18.s, z2.h, z16.h
    smullt  z19.s, z2.h, z16.h
    NEV_SVE_MRP z18, z19, z17
    add     z0.h, z0.h, z17.h            // r_{h-1}
    st1h    {z0.h}, p0, [x0, x13, lsl #1]
    st1h    {z1.h}, p0, [x10, x13, lsl #1]
    inch    x13
    whilelt p0.h, x13, x5
    b.first 3b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_PolyMulCombSve2)
#endif /* HITLS_CRYPTO_NEV && HITLS_CRYPTO_NEV_SVE2 */

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
