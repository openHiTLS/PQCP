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
 * NEV NTT-CRT polynomial arithmetic — SVE2 kernels
 * ============================================================================
 *
 * Vector-length-agnostic SVE2 counterparts of the NEON kernels in
 * nev_poly_armv8.S, exporting *Sve2 symbols that the glue in asm_nev_poly.c
 * selects whenever HITLS_CRYPTO_NEV_SVE2 is enabled at build time. The NEON
 * kernels are untouched and remain available in NEON-only builds.
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
// void NEV_AddArrSve2(int16_t *r, const int16_t *a, const int16_t *b, uint64_t n)
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_AddArrSve2)
AARCH64_PACIASP
    mov     x5, #0
    whilelt p0.h, x5, x3
1:
    ld1h    {z0.h}, p0/z, [x1, x5, lsl #1]
    ld1h    {z1.h}, p0/z, [x2, x5, lsl #1]
    add     z0.h, z0.h, z1.h
    st1h    {z0.h}, p0, [x0, x5, lsl #1]
    inch    x5
    whilelt p0.h, x5, x3
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_AddArrSve2)

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
// void NEV_NegArrSve2(int16_t *r, const int16_t *a, uint64_t n)
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_NegArrSve2)
AARCH64_PACIASP
    ptrue   p1.h
    mov     x5, #0
    whilelt p0.h, x5, x2
1:
    ld1h    {z0.h}, p0/z, [x1, x5, lsl #1]
    neg     z0.h, p1/m, z0.h
    st1h    {z0.h}, p0, [x0, x5, lsl #1]
    inch    x5
    whilelt p0.h, x5, x2
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_NegArrSve2)

// =============================================================================
// void NEV_CaddqArrSve2(int16_t *r, const int16_t *a, uint64_t n, uint64_t q)
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_CaddqArrSve2)
AARCH64_PACIASP
    dup     z5.h, w3
    mov     x5, #0
    whilelt p0.h, x5, x2
1:
    ld1h    {z0.h}, p0/z, [x1, x5, lsl #1]
    NEV_SVE_CADDQ z0, z1
    st1h    {z0.h}, p0, [x0, x5, lsl #1]
    inch    x5
    whilelt p0.h, x5, x2
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_CaddqArrSve2)

// =============================================================================
// void NEV_BarrettArrSve2(int16_t *r, const int16_t *a, uint64_t n,
//                         uint64_t bPacked)
//   bPacked = q | barrettV << 16 | shift << 32 (no qinv field), so the
//   constants are loaded with the qb macro and only z7.h[0]/.h[2]/z6 are used.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_BarrettArrSve2)
AARCH64_PACIASP
    ptrue   p1.h
    lsr     x9, x3, #16
    dup     z7.h, #0
    insr    z7.h, w9                    // barrettV -> lane 0
    insr    z7.h, wzr                   // (qinv slot, unused here)
    insr    z7.h, w3                    // q -> lane 0
    dup     z7.q, z7.q[0]
    lsr     x9, x3, #32
    mov     w10, #15
    sub     w9, w10, w9
    dup     z6.h, w9
    mov     x5, #0
    whilelt p0.h, x5, x2
1:
    ld1h    {z0.h}, p0/z, [x1, x5, lsl #1]
    NEV_SVE_BR z0, z1
    st1h    {z0.h}, p0, [x0, x5, lsl #1]
    inch    x5
    whilelt p0.h, x5, x2
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_BarrettArrSve2)

// =============================================================================
// void NEV_MontArrSve2(int16_t *r, const int16_t *a, uint64_t n,
//                      uint64_t qPacked)
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_MontArrSve2)
AARCH64_PACIASP
    ptrue   p1.h
    NEV_SVE_Q 3
    mov     x5, #0
    whilelt p0.h, x5, x2
1:
    ld1h    {z0.h}, p0/z, [x1, x5, lsl #1]
    NEV_SVE_MONT16 z0, z1, z2
    st1h    {z0.h}, p0, [x0, x5, lsl #1]
    inch    x5
    whilelt p0.h, x5, x2
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MontArrSve2)

// =============================================================================
// void NEV_MontCaddqArrSve2(int16_t *r, const int16_t *a, uint64_t n,
//                           uint64_t qPacked)
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_MontCaddqArrSve2)
AARCH64_PACIASP
    ptrue   p1.h
    NEV_SVE_Q 3
    mov     x5, #0
    whilelt p0.h, x5, x2
1:
    ld1h    {z0.h}, p0/z, [x1, x5, lsl #1]
    NEV_SVE_MONT16 z0, z1, z2
    NEV_SVE_CADDQ z0, z1
    st1h    {z0.h}, p0, [x0, x5, lsl #1]
    inch    x5
    whilelt p0.h, x5, x2
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MontCaddqArrSve2)

// =============================================================================
// void NEV_AddBarrettArrSve2(int16_t *r, const int16_t *a, const int16_t *b,
//                            uint64_t n, uint64_t qbPacked)
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_AddBarrettArrSve2)
AARCH64_PACIASP
    ptrue   p1.h
    NEV_SVE_QB 4
    mov     x5, #0
    whilelt p0.h, x5, x3
1:
    ld1h    {z0.h}, p0/z, [x1, x5, lsl #1]
    ld1h    {z1.h}, p0/z, [x2, x5, lsl #1]
    add     z0.h, z0.h, z1.h
    NEV_SVE_BR z0, z2
    st1h    {z0.h}, p0, [x0, x5, lsl #1]
    inch    x5
    whilelt p0.h, x5, x3
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_AddBarrettArrSve2)

// =============================================================================
// void NEV_BarrettCaddqArrSve2(int16_t *r, const int16_t *a, uint64_t n,
//                              uint64_t qbPacked)
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_BarrettCaddqArrSve2)
AARCH64_PACIASP
    ptrue   p1.h
    NEV_SVE_QB 3
    mov     x5, #0
    whilelt p0.h, x5, x2
1:
    ld1h    {z0.h}, p0/z, [x1, x5, lsl #1]
    NEV_SVE_BR z0, z1
    NEV_SVE_CADDQ z0, z1
    st1h    {z0.h}, p0, [x0, x5, lsl #1]
    inch    x5
    whilelt p0.h, x5, x2
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_BarrettCaddqArrSve2)

// =============================================================================
// void NEV_AddBarrettCaddqArrSve2(int16_t *r, const int16_t *a,
//                                 const int16_t *b, uint64_t n,
//                                 uint64_t qbPacked)
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_AddBarrettCaddqArrSve2)
AARCH64_PACIASP
    ptrue   p1.h
    NEV_SVE_QB 4
    mov     x5, #0
    whilelt p0.h, x5, x3
1:
    ld1h    {z0.h}, p0/z, [x1, x5, lsl #1]
    ld1h    {z1.h}, p0/z, [x2, x5, lsl #1]
    add     z0.h, z0.h, z1.h
    NEV_SVE_BR z0, z2
    NEV_SVE_CADDQ z0, z2
    st1h    {z0.h}, p0, [x0, x5, lsl #1]
    inch    x5
    whilelt p0.h, x5, x3
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_AddBarrettCaddqArrSve2)

// =============================================================================
// void NEV_Sub2ArrSve2(int16_t *r, const int16_t *a, const int16_t *b,
//                      const int16_t *c, uint64_t n)
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_Sub2ArrSve2)
AARCH64_PACIASP
    mov     x5, #0
    whilelt p0.h, x5, x4
1:
    ld1h    {z0.h}, p0/z, [x1, x5, lsl #1]
    ld1h    {z1.h}, p0/z, [x2, x5, lsl #1]
    ld1h    {z2.h}, p0/z, [x3, x5, lsl #1]
    sub     z0.h, z0.h, z1.h
    sub     z0.h, z0.h, z2.h
    st1h    {z0.h}, p0, [x0, x5, lsl #1]
    inch    x5
    whilelt p0.h, x5, x4
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Sub2ArrSve2)

// =============================================================================
// void NEV_Comb4Sve2(int16_t *r, const int16_t *a, const int16_t *b,
//                    const int16_t *c, const int16_t *d, uint64_t n)
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_Comb4Sve2)
AARCH64_PACIASP
    mov     x6, #0
    whilelt p0.h, x6, x5
1:
    ld1h    {z0.h}, p0/z, [x1, x6, lsl #1]
    ld1h    {z1.h}, p0/z, [x2, x6, lsl #1]
    ld1h    {z2.h}, p0/z, [x3, x6, lsl #1]
    ld1h    {z3.h}, p0/z, [x4, x6, lsl #1]
    add     z0.h, z0.h, z1.h
    sub     z0.h, z0.h, z2.h
    sub     z0.h, z0.h, z3.h
    st1h    {z0.h}, p0, [x0, x6, lsl #1]
    inch    x6
    whilelt p0.h, x6, x5
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Comb4Sve2)

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
// void NEV_MulYCombSve2(int16_t *r, const int16_t *a, const int16_t *a2,
//                       const int16_t *b, const int16_t *b2, const int16_t *y,
//                       uint64_t geom, uint64_t qbPacked)
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_MulYCombSve2)
AARCH64_PACIASP
    ptrue   p1.h
    NEV_SVE_QB 7
    ubfx    x8, x6, #0, #16              // dim
    ubfx    x9, x6, #16, #8              // blocks
    ubfx    x10, x6, #24, #16            // output block stride
    lsl     x11, x8, #1                  // input block bytes
    lsl     x10, x10, #1                 // output stride bytes
    mov     w12, #1
    mov     w13, #-1
    tst     x6, #(1 << 40)
    csel    w14, w13, w12, ne
    dup     z8.h, w14                     // a2 sign
    tst     x6, #(1 << 41)
    csel    w14, w13, w12, ne
    dup     z9.h, w14                     // Montgomery term sign
    tst     x6, #(1 << 42)
    csel    w14, w13, w12, ne
    dup     z10.h, w14                    // b2 sign
1:
    mov     x14, #0
    whilelt p0.h, x14, x8
2:
    ld1h    {z16.h}, p0/z, [x1, x14, lsl #1]
    ld1h    {z17.h}, p0/z, [x2, x14, lsl #1]
    ld1h    {z18.h}, p0/z, [x3, x14, lsl #1]
    ld1h    {z19.h}, p0/z, [x4, x14, lsl #1]
    ld1h    {z20.h}, p0/z, [x5, x14, lsl #1]
    mla     z18.h, p1/m, z19.h, z10.h
    smullb  z21.s, z18.h, z20.h
    smullt  z22.s, z18.h, z20.h
    NEV_SVE_MRP z21, z22, z18
    mla     z16.h, p1/m, z17.h, z8.h
    mla     z16.h, p1/m, z18.h, z9.h
    st1h    {z16.h}, p0, [x0, x14, lsl #1]
    inch    x14
    whilelt p0.h, x14, x8
    b.first 2b
    add     x0, x0, x10
    add     x1, x1, x11
    add     x2, x2, x11
    add     x3, x3, x11
    add     x4, x4, x11
    subs    x9, x9, #1
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MulYCombSve2)

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

// =============================================================================
// void NEV_Inv4NormSve2(int16_t *a20, int16_t *a21, int16_t *s,
//                       const int16_t *a, const int16_t *y, uint64_t dim,
//                       uint64_t qbPacked)
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_Inv4NormSve2)
AARCH64_PACIASP
    ptrue   p1.h
    NEV_SVE_QB 6
    lsl     x8, x5, #1
    add     x9, x3, x8
    add     x10, x9, x8
    add     x11, x10, x8
    mov     x12, #0
    whilelt p0.h, x12, x5
1:
    ld1h    {z16.h}, p0/z, [x3, x12, lsl #1]
    ld1h    {z17.h}, p0/z, [x9, x12, lsl #1]
    ld1h    {z18.h}, p0/z, [x10, x12, lsl #1]
    ld1h    {z19.h}, p0/z, [x11, x12, lsl #1]
    ld1h    {z20.h}, p0/z, [x4, x12, lsl #1]
    lsl     z0.h, z17.h, #1
    lsl     z1.h, z16.h, #1
    smullb  z21.s, z18.h, z18.h
    smullt  z22.s, z18.h, z18.h
    smlslb  z21.s, z0.h, z19.h
    smlslt  z22.s, z0.h, z19.h
    NEV_SVE_MRP z21, z22, z2
    smullb  z21.s, z2.h, z20.h
    smullt  z22.s, z2.h, z20.h
    NEV_SVE_MRP z21, z22, z3
    smullb  z21.s, z16.h, z16.h
    smullt  z22.s, z16.h, z16.h
    NEV_SVE_MRP z21, z22, z4
    add     z3.h, z3.h, z4.h
    smullb  z21.s, z1.h, z18.h
    smullt  z22.s, z1.h, z18.h
    smlslb  z21.s, z17.h, z17.h
    smlslt  z22.s, z17.h, z17.h
    NEV_SVE_MRP z21, z22, z4
    smullb  z21.s, z19.h, z19.h
    smullt  z22.s, z19.h, z19.h
    NEV_SVE_MRP z21, z22, z0
    smullb  z21.s, z0.h, z20.h
    smullt  z22.s, z0.h, z20.h
    NEV_SVE_MRP z21, z22, z1
    sub     z4.h, z4.h, z1.h
    smullb  z21.s, z3.h, z3.h
    smullt  z22.s, z3.h, z3.h
    NEV_SVE_MRP z21, z22, z0
    smullb  z21.s, z4.h, z4.h
    smullt  z22.s, z4.h, z4.h
    NEV_SVE_MRP z21, z22, z1
    smullb  z21.s, z1.h, z20.h
    smullt  z22.s, z1.h, z20.h
    NEV_SVE_MRP z21, z22, z1
    sub     z0.h, z0.h, z1.h
    NEV_SVE_BR z0, z2
    NEV_SVE_CADDQ z0, z2
    st1h    {z3.h}, p0, [x0, x12, lsl #1]
    st1h    {z4.h}, p0, [x1, x12, lsl #1]
    st1h    {z0.h}, p0, [x2, x12, lsl #1]
    inch    x12
    whilelt p0.h, x12, x5
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Inv4NormSve2)

// =============================================================================
// void NEV_Inv4FinishSve2(int16_t *r, const int16_t *a,
//                         const int16_t *a20, const int16_t *a21,
//                         const int16_t *sInv, const int16_t *y,
//                         uint64_t dim, uint64_t qbPacked)
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_Inv4FinishSve2)
AARCH64_PACIASP
    ptrue   p1.h
    NEV_SVE_QB 7
    lsl     x8, x6, #1
    add     x9, x1, x8
    add     x10, x9, x8
    add     x11, x10, x8
    add     x12, x0, x8
    add     x13, x12, x8
    add     x14, x13, x8
    mov     x15, #0
    whilelt p0.h, x15, x6
1:
    ld1h    {z16.h}, p0/z, [x1, x15, lsl #1]
    ld1h    {z17.h}, p0/z, [x9, x15, lsl #1]
    ld1h    {z18.h}, p0/z, [x10, x15, lsl #1]
    ld1h    {z19.h}, p0/z, [x11, x15, lsl #1]
    ld1h    {z20.h}, p0/z, [x2, x15, lsl #1]
    ld1h    {z21.h}, p0/z, [x3, x15, lsl #1]
    ld1h    {z22.h}, p0/z, [x4, x15, lsl #1]
    ld1h    {z23.h}, p0/z, [x5, x15, lsl #1]
    smullb  z24.s, z20.h, z22.h
    smullt  z25.s, z20.h, z22.h
    NEV_SVE_MRP z24, z25, z0
    smullb  z24.s, z21.h, z22.h
    smullt  z25.s, z21.h, z22.h
    NEV_SVE_MRP z24, z25, z1
    smullb  z24.s, z16.h, z0.h
    smullt  z25.s, z16.h, z0.h
    NEV_SVE_MRP z24, z25, z2
    smullb  z24.s, z17.h, z0.h
    smullt  z25.s, z17.h, z0.h
    NEV_SVE_MRP z24, z25, z3
    add     z20.h, z16.h, z18.h
    sub     z21.h, z0.h, z1.h
    smullb  z24.s, z20.h, z21.h
    smullt  z25.s, z20.h, z21.h
    NEV_SVE_MRP z24, z25, z4
    sub     z20.h, z17.h, z19.h
    add     z21.h, z0.h, z1.h
    smullb  z24.s, z20.h, z21.h
    smullt  z25.s, z20.h, z21.h
    NEV_SVE_MRP z24, z25, z5
    smullb  z24.s, z18.h, z1.h
    smullt  z25.s, z18.h, z1.h
    NEV_SVE_MRP z24, z25, z18
    smullb  z24.s, z19.h, z1.h
    smullt  z25.s, z19.h, z1.h
    NEV_SVE_MRP z24, z25, z19
    smullb  z24.s, z18.h, z23.h
    smullt  z25.s, z18.h, z23.h
    NEV_SVE_MRP z24, z25, z20
    smullb  z24.s, z19.h, z23.h
    smullt  z25.s, z19.h, z23.h
    NEV_SVE_MRP z24, z25, z21
    sub     z20.h, z2.h, z20.h
    NEV_SVE_BR z20, z24
    st1h    {z20.h}, p0, [x0, x15, lsl #1]
    sub     z21.h, z21.h, z3.h
    NEV_SVE_BR z21, z24
    st1h    {z21.h}, p0, [x12, x15, lsl #1]
    sub     z4.h, z4.h, z2.h
    add     z4.h, z4.h, z18.h
    NEV_SVE_BR z4, z24
    st1h    {z4.h}, p0, [x13, x15, lsl #1]
    sub     z5.h, z5.h, z3.h
    add     z5.h, z5.h, z19.h
    NEV_SVE_BR z5, z24
    st1h    {z5.h}, p0, [x14, x15, lsl #1]
    inch    x15
    whilelt p0.h, x15, x6
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Inv4FinishSve2)

// =============================================================================
// void NEV_MontSquare4Sve2(int16_t *r, const int16_t *a, uint64_t dim,
//                          uint64_t qPacked)
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_MontSquare4Sve2)
AARCH64_PACIASP
    ptrue   p1.h
    NEV_SVE_Q 3
    lsl     x4, x2, #1
    add     x5, x1, x4                   // a1
    add     x6, x5, x4                   // a2
    add     x7, x6, x4                   // a3
    add     x8, x0, x4                   // r1
    add     x9, x8, x4                   // r2
    add     x10, x9, x4                  // r3
    add     x11, x10, x4                 // r4
    add     x12, x11, x4                 // r5
    add     x13, x12, x4                 // r6
    mov     x14, #0
    whilelt p0.h, x14, x2
1:
    ld1h    {z16.h}, p0/z, [x1, x14, lsl #1]
    ld1h    {z17.h}, p0/z, [x5, x14, lsl #1]
    ld1h    {z18.h}, p0/z, [x6, x14, lsl #1]
    ld1h    {z19.h}, p0/z, [x7, x14, lsl #1]
    lsl     z0.h, z16.h, #1
    lsl     z1.h, z17.h, #1
    lsl     z2.h, z18.h, #1
    add     z3.h, z18.h, z19.h
    add     z4.h, z0.h, z1.h
    smullb  z20.s, z16.h, z16.h          // o0
    smullt  z21.s, z16.h, z16.h
    smullb  z22.s, z0.h, z17.h           // o1
    smullt  z23.s, z0.h, z17.h
    smullb  z24.s, z17.h, z17.h          // o2
    smullt  z25.s, z17.h, z17.h
    smlalb  z24.s, z0.h, z18.h
    smlalt  z25.s, z0.h, z18.h
    smullb  z26.s, z4.h, z3.h            // o3
    smullt  z27.s, z4.h, z3.h
    smlslb  z26.s, z1.h, z19.h
    smlslt  z27.s, z1.h, z19.h
    smlslb  z26.s, z0.h, z18.h
    smlslt  z27.s, z0.h, z18.h
    smullb  z28.s, z1.h, z19.h           // o4
    smullt  z29.s, z1.h, z19.h
    smlalb  z28.s, z18.h, z18.h
    smlalt  z29.s, z18.h, z18.h
    smullb  z30.s, z2.h, z19.h           // o5
    smullt  z31.s, z2.h, z19.h
    smullb  z16.s, z19.h, z19.h          // o6
    smullt  z17.s, z19.h, z19.h
    NEV_SVE_MRP z20, z21, z18
    NEV_SVE_MRP z22, z23, z19
    NEV_SVE_MRP z24, z25, z20
    NEV_SVE_MRP z26, z27, z22
    NEV_SVE_MRP z28, z29, z24
    NEV_SVE_MRP z30, z31, z26
    NEV_SVE_MRP z16, z17, z28
    st1h    {z18.h}, p0, [x0, x14, lsl #1]
    st1h    {z19.h}, p0, [x8, x14, lsl #1]
    st1h    {z20.h}, p0, [x9, x14, lsl #1]
    st1h    {z22.h}, p0, [x10, x14, lsl #1]
    st1h    {z24.h}, p0, [x11, x14, lsl #1]
    st1h    {z26.h}, p0, [x12, x14, lsl #1]
    st1h    {z28.h}, p0, [x13, x14, lsl #1]
    inch    x14
    whilelt p0.h, x14, x2
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MontSquare4Sve2)

/*
 * ----------------------------------------------------------------------------
 * NEV_SVE_MM4CORE — SVE2 transliteration of NEV_MM4CORE (nev_poly_armv8.S).
 *
 * Inputs  z16-z19 = a0..a3, z20-z23 = b0..b3 (one vector of coefficients per
 * block).  Outputs, exactly as in the NEON core:
 *   r0 -> z28   r1 -> z30   r2 -> z19   r3 -> z23 (Barrett-normalized)
 *   r4 -> z3    r5 -> z2    r6 -> z0
 * Same Karatsuba schedule, same accumulate-then-reduce-once structure, same
 * single Barrett on r3; only SMULL/SMULL2 become SMULLB/SMULLT and NEV_MRP
 * becomes its TRN1/TRN2 form.
 * ----------------------------------------------------------------------------
 */
.macro NEV_SVE_MM4CORE
    add     z0.h, z16.h, z17.h          // s01a
    add     z1.h, z18.h, z19.h          // s23a
    add     z2.h, z16.h, z18.h          // A0
    add     z3.h, z17.h, z19.h          // A1
    add     z4.h, z2.h, z3.h            // Sa
    add     z24.h, z20.h, z21.h         // s01b
    add     z25.h, z22.h, z23.h         // s23b
    add     z26.h, z20.h, z22.h         // B0
    add     z27.h, z21.h, z23.h         // B1
    add     z28.h, z26.h, z27.h         // Sb
    smullb  z29.s, z16.h, z20.h         // P0   -> (z29, z30)
    smullt  z30.s, z16.h, z20.h
    smullb  z16.s, z17.h, z21.h         // P1   -> (z16, z20)
    smullt  z20.s, z17.h, z21.h
    smullb  z17.s, z18.h, z22.h         // P2   -> (z17, z21)
    smullt  z21.s, z18.h, z22.h
    smullb  z18.s, z19.h, z23.h         // P3   -> (z18, z22)
    smullt  z22.s, z19.h, z23.h
    smullb  z19.s, z0.h, z24.h          // P01  -> (z19, z23)
    smullt  z23.s, z0.h, z24.h
    smullb  z24.s, z1.h, z25.h          // P23  -> (z24, z0)
    smullt  z0.s, z1.h, z25.h
    smullb  z1.s, z2.h, z26.h           // PA0  -> (z1, z25)
    smullt  z25.s, z2.h, z26.h
    smullb  z2.s, z3.h, z27.h           // PA1  -> (z2, z26)
    smullt  z26.s, z3.h, z27.h
    smullb  z3.s, z4.h, z28.h           // PA01 -> (z3, z27)
    smullt  z27.s, z4.h, z28.h
    sub     z19.s, z19.s, z29.s         // D01 = P01 - P0 - P1
    sub     z23.s, z23.s, z30.s
    sub     z19.s, z19.s, z16.s
    sub     z23.s, z23.s, z20.s
    sub     z24.s, z24.s, z17.s         // D23 = P23 - P2 - P3
    sub     z0.s, z0.s, z21.s
    sub     z24.s, z24.s, z18.s
    sub     z0.s, z0.s, z22.s
    sub     z3.s, z3.s, z1.s            // R3 = PA01 - PA0 - PA1 - D01 - D23
    sub     z27.s, z27.s, z25.s
    sub     z3.s, z3.s, z2.s
    sub     z27.s, z27.s, z26.s
    sub     z3.s, z3.s, z19.s
    sub     z27.s, z27.s, z23.s
    sub     z3.s, z3.s, z24.s
    sub     z27.s, z27.s, z0.s
    sub     z1.s, z1.s, z29.s           // R2 = PA0 - P0 - P2 + P1
    sub     z25.s, z25.s, z30.s
    sub     z1.s, z1.s, z17.s
    sub     z25.s, z25.s, z21.s
    add     z1.s, z1.s, z16.s
    add     z25.s, z25.s, z20.s
    sub     z2.s, z2.s, z16.s           // R4 = PA1 - P1 - P3 + P2
    sub     z26.s, z26.s, z20.s
    sub     z2.s, z2.s, z18.s
    sub     z26.s, z26.s, z22.s
    add     z2.s, z2.s, z17.s
    add     z26.s, z26.s, z21.s
    NEV_SVE_MRP z29, z30, z28           // r0 -> z28
    NEV_SVE_MRP z19, z23, z30           // r1 -> z30
    NEV_SVE_MRP z1,  z25, z19           // r2 -> z19
    NEV_SVE_MRP z3,  z27, z23           // r3 -> z23 (pre-Barrett)
    NEV_SVE_MRP z2,  z26, z3            // r4 -> z3
    NEV_SVE_MRP z24, z0,  z2            // r5 -> z2
    NEV_SVE_MRP z18, z22, z0            // r6 -> z0
    NEV_SVE_BR  z23, z1                 // r3 Barrett-normalized
.endm

// =============================================================================
// void NEV_MontMul4Sve2(int16_t *r, const int16_t *a, const int16_t *b,
//                       uint64_t dim, uint64_t qbPacked, uint64_t dbl)
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_MontMul4Sve2)
AARCH64_PACIASP
    ptrue   p1.h
    NEV_SVE_QB 4                        // consumes x4, clobbers x9/x10
    lsl     x6, x3, #1                  // block stride in bytes
    add     x7, x1, x6                  // a1
    add     x8, x7, x6                  // a2
    add     x9, x8, x6                  // a3
    add     x10, x2, x6                 // b1
    add     x11, x10, x6                // b2
    add     x12, x11, x6                // b3
    add     x13, x0, x6                 // r1
    add     x14, x13, x6                // r2
    add     x15, x14, x6                // r3
    add     x16, x15, x6                // r4
    add     x17, x16, x6                // r5
    add     x4, x17, x6                 // r6
    mov     x6, #0                      // coefficient index
    whilelt p0.h, x6, x3
1:
    ld1h    {z16.h}, p0/z, [x1, x6, lsl #1]     // a0
    ld1h    {z17.h}, p0/z, [x7, x6, lsl #1]     // a1
    ld1h    {z18.h}, p0/z, [x8, x6, lsl #1]     // a2
    ld1h    {z19.h}, p0/z, [x9, x6, lsl #1]     // a3
    ld1h    {z20.h}, p0/z, [x2, x6, lsl #1]     // b0
    ld1h    {z21.h}, p0/z, [x10, x6, lsl #1]    // b1
    ld1h    {z22.h}, p0/z, [x11, x6, lsl #1]    // b2
    ld1h    {z23.h}, p0/z, [x12, x6, lsl #1]    // b3
    cbz     x5, 2f
    lsl     z20.h, z20.h, #1            // (2b) for the dbl variant
    lsl     z21.h, z21.h, #1
    lsl     z22.h, z22.h, #1
    lsl     z23.h, z23.h, #1
2:
    NEV_SVE_MM4CORE
    st1h    {z28.h}, p0, [x0, x6, lsl #1]       // r0
    st1h    {z30.h}, p0, [x13, x6, lsl #1]      // r1
    st1h    {z19.h}, p0, [x14, x6, lsl #1]      // r2
    st1h    {z23.h}, p0, [x15, x6, lsl #1]      // r3
    st1h    {z3.h},  p0, [x16, x6, lsl #1]      // r4
    st1h    {z2.h},  p0, [x17, x6, lsl #1]      // r5
    st1h    {z0.h},  p0, [x4, x6, lsl #1]       // r6
    inch    x6
    whilelt p0.h, x6, x3
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MontMul4Sve2)

// =============================================================================
// void NEV_PolyMulRed4Sve2(int16_t *r, const int16_t *a, const int16_t *b,
//                          const int16_t *y, uint64_t dim, uint64_t qbPacked)
//   MontMul4 core plus the wrap-around fold r_j = c_j + MR(c_{4+j} * y),
//   j = 0..2, r_3 = c_3; only the 4 output blocks are stored.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_PolyMulRed4Sve2)
AARCH64_PACIASP
    ptrue   p1.h
    NEV_SVE_QB 5                        // consumes x5, clobbers x9/x10
    lsl     x6, x4, #1                  // block stride in bytes
    add     x7, x1, x6                  // a1
    add     x8, x7, x6                  // a2
    add     x9, x8, x6                  // a3
    add     x10, x2, x6                 // b1
    add     x11, x10, x6                // b2
    add     x12, x11, x6                // b3
    add     x13, x0, x6                 // r1
    add     x14, x13, x6                // r2
    add     x15, x14, x6                // r3
    mov     x6, #0                      // coefficient index
    whilelt p0.h, x6, x4
1:
    ld1h    {z16.h}, p0/z, [x1, x6, lsl #1]
    ld1h    {z17.h}, p0/z, [x7, x6, lsl #1]
    ld1h    {z18.h}, p0/z, [x8, x6, lsl #1]
    ld1h    {z19.h}, p0/z, [x9, x6, lsl #1]
    ld1h    {z20.h}, p0/z, [x2, x6, lsl #1]
    ld1h    {z21.h}, p0/z, [x10, x6, lsl #1]
    ld1h    {z22.h}, p0/z, [x11, x6, lsl #1]
    ld1h    {z23.h}, p0/z, [x12, x6, lsl #1]
    NEV_SVE_MM4CORE
    // c0=z28 c1=z30 c2=z19 c3=z23 c4=z3 c5=z2 c6=z0; fold c4..c6 by y.
    // z5 holds the broadcast q for the Caddq macro but is dead here, so it
    // doubles as the SMULLT accumulator, exactly as v5 does in the NEON kernel.
    ld1h    {z1.h}, p0/z, [x3, x6, lsl #1]      // y
    smullb  z4.s, z3.h, z1.h                    // MR(c4 * y)
    smullt  z5.s, z3.h, z1.h
    NEV_SVE_MRP z4, z5, z3
    add     z28.h, z28.h, z3.h
    smullb  z4.s, z2.h, z1.h                    // MR(c5 * y)
    smullt  z5.s, z2.h, z1.h
    NEV_SVE_MRP z4, z5, z2
    add     z30.h, z30.h, z2.h
    smullb  z4.s, z0.h, z1.h                    // MR(c6 * y)
    smullt  z5.s, z0.h, z1.h
    NEV_SVE_MRP z4, z5, z0
    add     z19.h, z19.h, z0.h
    st1h    {z28.h}, p0, [x0, x6, lsl #1]       // r0
    st1h    {z30.h}, p0, [x13, x6, lsl #1]      // r1
    st1h    {z19.h}, p0, [x14, x6, lsl #1]      // r2
    st1h    {z23.h}, p0, [x15, x6, lsl #1]      // r3
    inch    x6
    whilelt p0.h, x6, x4
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_PolyMulRed4Sve2)

// =============================================================================
// void NEV_MontMul8TailSve2(int16_t *r, const int16_t *t1, uint64_t dim,
//                           uint64_t qbPacked)
//   Fused Karatsuba recombination tail of MontMul8 / MontDoubleMul8, the same
//   two passes and the same row arithmetic as the NEON kernel.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_MontMul8TailSve2)
AARCH64_PACIASP
    ptrue   p1.h
    NEV_SVE_QB 3                        // consumes x3, clobbers x9/x10
    lsl     x3, x2, #1                  // dim in bytes
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
    mov     x8, #0
    whilelt p0.h, x8, x2
1:
    ld1h    {z0.h}, p0/z, [x4, x8, lsl #1]
    ld1h    {z1.h}, p0/z, [x5, x8, lsl #1]
    ld1h    {z2.h}, p0/z, [x6, x8, lsl #1]
    sub     z0.h, z0.h, z1.h
    sub     z0.h, z0.h, z2.h
    NEV_SVE_BR z0, z4
    st1h    {z0.h}, p0, [x7, x8, lsl #1]
    inch    x8
    whilelt p0.h, x8, x2
    b.first 1b
    // pass B, i = 0..2: the r_{4+i} and r_{8+i} rows
    mov     x17, #0                     // i
2:
    madd    x4, x17, x3, x0             // r_i
    add     x5, x4, x3, lsl #2          // r_{4+i}
    add     x6, x5, x3, lsl #2          // r_{8+i}
    add     x7, x6, x3, lsl #2          // r_{12+i}
    madd    x11, x17, x3, x1            // t1_i
    add     x12, x11, x3, lsl #2        // t1_{4+i}
    mov     x8, #0
    whilelt p0.h, x8, x2
3:
    ld1h    {z0.h}, p0/z, [x4, x8, lsl #1]      // r_i
    ld1h    {z1.h}, p0/z, [x5, x8, lsl #1]      // r_{4+i}
    ld1h    {z2.h}, p0/z, [x6, x8, lsl #1]      // r_{8+i}
    ld1h    {z3.h}, p0/z, [x7, x8, lsl #1]      // r_{12+i}
    ld1h    {z16.h}, p0/z, [x11, x8, lsl #1]    // t1_i
    ld1h    {z17.h}, p0/z, [x12, x8, lsl #1]    // t1_{4+i}
    add     z18.h, z1.h, z16.h          // r4' = r_{4+i} + t1_i - r_i - r_{8+i}
    sub     z18.h, z18.h, z0.h
    sub     z18.h, z18.h, z2.h
    sub     z19.h, z17.h, z1.h          // r8' = t1_{4+i} - r_{4+i} - r_{12+i} + r_{8+i}
    sub     z19.h, z19.h, z3.h
    add     z19.h, z19.h, z2.h
    NEV_SVE_BR z18, z4
    NEV_SVE_BR z19, z4
    st1h    {z18.h}, p0, [x5, x8, lsl #1]
    st1h    {z19.h}, p0, [x6, x8, lsl #1]
    inch    x8
    whilelt p0.h, x8, x2
    b.first 3b
    add     x17, x17, #1
    cmp     x17, #3
    b.ne    2b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MontMul8TailSve2)

#endif /* HITLS_CRYPTO_NEV && HITLS_CRYPTO_NEV_SVE2 */

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
