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

/* SVE2 sampling kernels for NEV. */
#include "hitls_build.h"
#if defined(HITLS_CRYPTO_NEV) && defined(HITLS_CRYPTO_NEV_SVE2)
#include "crypt_arm.h"
#include "nev_arm_asm.h"
CRYPT_AARCH64_ARCH_SVE2

.text

// uint64_t NEV_RejTernaryCompactSve2(uint8_t *dst, const uint8_t *src,
//                                    uint64_t len)
CRYPT_AARCH64_FUNC_START(NEV_RejTernaryCompactSve2)
AARCH64_PACIASP
    mov     x3, #0
    mov     x4, x0
    mov     w7, #243
    dup     z2.s, w7
    ptrue   p7.s
    // COMPACT has no byte form, so one .s vector consumes only eight bytes
    // at VL=256.  Run four independent chunks per iteration to cover the
    // full 32-byte vector width while retaining each chunk's stream order.
1:
    sub     x8, x2, x3
    cmp     x8, #32
    b.lo    3f
    add     x8, x1, x3
    ld1b    {z0.s}, p7/z, [x8]
    add     x9, x8, #8
    ld1b    {z3.s}, p7/z, [x9]
    add     x9, x8, #16
    ld1b    {z5.s}, p7/z, [x9]
    add     x9, x8, #24
    ld1b    {z16.s}, p7/z, [x9]
    cmplo   p1.s, p7/z, z0.s, z2.s
    cmplo   p2.s, p7/z, z3.s, z2.s
    cmplo   p3.s, p7/z, z5.s, z2.s
    cmplo   p4.s, p7/z, z16.s, z2.s
    compact z1.s, p1, z0.s
    compact z4.s, p2, z3.s
    compact z6.s, p3, z5.s
    compact z17.s, p4, z16.s
    cntp    x10, p7, p1.s
    cntp    x11, p7, p2.s
    cntp    x12, p7, p3.s
    cntp    x13, p7, p4.s
    // Storing eight lanes is safe: the next compacted chunk overwrites the
    // unused suffix, and the caller provides eight bytes of final slack.
    st1b    {z1.s}, p7, [x4]
    add     x4, x4, x10
    st1b    {z4.s}, p7, [x4]
    add     x4, x4, x11
    st1b    {z6.s}, p7, [x4]
    add     x4, x4, x12
    st1b    {z17.s}, p7, [x4]
    add     x4, x4, x13
    add     x3, x3, #32
    b       1b
3:
    whilelt p0.s, x3, x2
    b.none  2f
    ld1b    {z0.s}, p0/z, [x1, x3]
    cmplo   p1.s, p0/z, z0.s, z2.s
    compact z1.s, p1, z0.s
    cntp    x5, p0, p1.s
    st1b    {z1.s}, p0, [x4]
    add     x4, x4, x5
    incw    x3
    b       3b
2:
    sub     x0, x4, x0
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_RejTernaryCompactSve2)

.macro NEV_CBD1_BODY add=0
    lsr     x3, x2, #2
    mov     x4, #0
    mov     z12.h, #1
1:
    whilelt p0.h, x4, x3
    b.none  2f
    ld1b    {z8.h}, p0/z, [x1, x4]
    and     z0.d, z8.d, z12.d
    lsr     z9.h, z8.h, #1
    and     z9.d, z9.d, z12.d
    sub     z0.h, z0.h, z9.h
    lsr     z1.h, z8.h, #2
    and     z1.d, z1.d, z12.d
    lsr     z9.h, z8.h, #3
    and     z9.d, z9.d, z12.d
    sub     z1.h, z1.h, z9.h
    lsr     z2.h, z8.h, #4
    and     z2.d, z2.d, z12.d
    lsr     z9.h, z8.h, #5
    and     z9.d, z9.d, z12.d
    sub     z2.h, z2.h, z9.h
    lsr     z3.h, z8.h, #6
    and     z3.d, z3.d, z12.d
    lsr     z9.h, z8.h, #7
    sub     z3.h, z3.h, z9.h
.if \add
    ld4h    {z16.h-z19.h}, p0/z, [x0]
    add     z0.h, z0.h, z16.h
    add     z1.h, z1.h, z17.h
    add     z2.h, z2.h, z18.h
    add     z3.h, z3.h, z19.h
.endif
    st4h    {z0.h-z3.h}, p0, [x0]
    addvl   x0, x0, #4
    inch    x4
    b       1b
2:
.endm

CRYPT_AARCH64_FUNC_START(NEV_Cbd1Sve2)
AARCH64_PACIASP
    NEV_CBD1_BODY 0
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Cbd1Sve2)

CRYPT_AARCH64_FUNC_START(NEV_Cbd1AddSve2)
AARCH64_PACIASP
    NEV_CBD1_BODY 1
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Cbd1AddSve2)

.macro NEV_CBD2_BODY add=0
    lsr     x3, x2, #1
    mov     x4, #0
    mov     z12.h, #0x55
    mov     z13.h, #3
1:
    whilelt p0.h, x4, x3
    b.none  2f
    ld1b    {z8.h}, p0/z, [x1, x4]
    and     z9.d, z8.d, z12.d
    lsr     z8.h, z8.h, #1
    and     z8.d, z8.d, z12.d
    add     z8.h, z8.h, z9.h
    and     z0.d, z8.d, z13.d
    lsr     z9.h, z8.h, #2
    and     z9.d, z9.d, z13.d
    sub     z0.h, z0.h, z9.h
    lsr     z1.h, z8.h, #4
    and     z1.d, z1.d, z13.d
    lsr     z9.h, z8.h, #6
    sub     z1.h, z1.h, z9.h
.if \add
    ld2h    {z16.h-z17.h}, p0/z, [x0]
    add     z0.h, z0.h, z16.h
    add     z1.h, z1.h, z17.h
.endif
    st2h    {z0.h-z1.h}, p0, [x0]
    addvl   x0, x0, #2
    inch    x4
    b       1b
2:
.endm

CRYPT_AARCH64_FUNC_START(NEV_Cbd2Sve2)
AARCH64_PACIASP
    NEV_CBD2_BODY 0
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Cbd2Sve2)

CRYPT_AARCH64_FUNC_START(NEV_Cbd2AddSve2)
AARCH64_PACIASP
    NEV_CBD2_BODY 1
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Cbd2AddSve2)

.macro NEV_CBD4_BODY add=0
    mov     x3, #0
    mov     z12.h, #0x55
    mov     z13.h, #0x33
    mov     z14.h, #0x0f
1:
    whilelt p0.h, x3, x2
    b.none  2f
    ld1b    {z0.h}, p0/z, [x1, x3]
    lsr     z1.h, z0.h, #1
    and     z1.d, z1.d, z12.d
    sub     z0.h, z0.h, z1.h
    and     z1.d, z0.d, z13.d
    lsr     z0.h, z0.h, #2
    and     z0.d, z0.d, z13.d
    add     z0.h, z0.h, z1.h
    and     z1.d, z0.d, z14.d
    lsr     z0.h, z0.h, #4
    sub     z0.h, z1.h, z0.h
.if \add
    ld1h    {z1.h}, p0/z, [x0, x3, lsl #1]
    add     z0.h, z0.h, z1.h
.endif
    st1h    {z0.h}, p0, [x0, x3, lsl #1]
    inch    x3
    b       1b
2:
.endm

CRYPT_AARCH64_FUNC_START(NEV_Cbd4Sve2)
AARCH64_PACIASP
    NEV_CBD4_BODY 0
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Cbd4Sve2)

CRYPT_AARCH64_FUNC_START(NEV_Cbd4AddSve2)
AARCH64_PACIASP
    NEV_CBD4_BODY 1
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Cbd4AddSve2)

/* Fused eta=3: sixteen CBD1 bytes and thirty-two CBD2 bytes produce the
 * same sixty-four output coefficients.  UZP converts the two CBD2 vectors
 * into the four modulo-four fields used by a single ST4H. */
CRYPT_AARCH64_FUNC_START(NEV_Cbd3Sve2)
AARCH64_PACIASP
    lsr     x3, x2, #2
    add     x5, x1, x3
    mov     x4, #0
    mov     z12.h, #1
    mov     z13.h, #0x55
    mov     z14.h, #3
    ptrue   p0.h
1:
    ld1b    {z8.h}, p0/z, [x1, x4]
    and     z0.d, z8.d, z12.d
    lsr     z9.h, z8.h, #1
    and     z9.d, z9.d, z12.d
    sub     z0.h, z0.h, z9.h
    lsr     z1.h, z8.h, #2
    and     z1.d, z1.d, z12.d
    lsr     z9.h, z8.h, #3
    and     z9.d, z9.d, z12.d
    sub     z1.h, z1.h, z9.h
    lsr     z2.h, z8.h, #4
    and     z2.d, z2.d, z12.d
    lsr     z9.h, z8.h, #5
    and     z9.d, z9.d, z12.d
    sub     z2.h, z2.h, z9.h
    lsr     z3.h, z8.h, #6
    and     z3.d, z3.d, z12.d
    lsr     z9.h, z8.h, #7
    sub     z3.h, z3.h, z9.h

    add     x6, x4, x4
    add     x7, x5, x6
    ld1b    {z8.h}, p0/z, [x7]
    and     z9.d, z8.d, z13.d
    lsr     z8.h, z8.h, #1
    and     z8.d, z8.d, z13.d
    add     z8.h, z8.h, z9.h
    and     z4.d, z8.d, z14.d
    lsr     z9.h, z8.h, #2
    and     z9.d, z9.d, z14.d
    sub     z4.h, z4.h, z9.h
    lsr     z5.h, z8.h, #4
    and     z5.d, z5.d, z14.d
    lsr     z9.h, z8.h, #6
    sub     z5.h, z5.h, z9.h
    add     x7, x7, #16
    ld1b    {z8.h}, p0/z, [x7]
    and     z9.d, z8.d, z13.d
    lsr     z8.h, z8.h, #1
    and     z8.d, z8.d, z13.d
    add     z8.h, z8.h, z9.h
    and     z6.d, z8.d, z14.d
    lsr     z9.h, z8.h, #2
    and     z9.d, z9.d, z14.d
    sub     z6.h, z6.h, z9.h
    lsr     z7.h, z8.h, #4
    and     z7.d, z7.d, z14.d
    lsr     z9.h, z8.h, #6
    sub     z7.h, z7.h, z9.h

    uzp1    z8.h, z4.h, z6.h
    uzp1    z9.h, z5.h, z7.h
    uzp2    z10.h, z4.h, z6.h
    uzp2    z11.h, z5.h, z7.h
    add     z0.h, z0.h, z8.h
    add     z1.h, z1.h, z9.h
    add     z2.h, z2.h, z10.h
    add     z3.h, z3.h, z11.h
    st4h    {z0.h-z3.h}, p0, [x0]
    add     x0, x0, #128
    add     x4, x4, #16
    cmp     x4, x3
    b.lo    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Cbd3Sve2)

/* Fused eta=7: work in four modulo-four coefficient fields.  Four CBD4
 * vectors are unzipped into those fields, then the CBD1 and CBD2 fields are
 * accumulated before the only output store. */
CRYPT_AARCH64_FUNC_START(NEV_Cbd7Sve2)
AARCH64_PACIASP
    add     x3, x1, x2
    add     x4, x3, x2, lsr #2
    mov     x5, #0
    mov     x7, x0
    mov     z24.h, #1
    mov     z25.h, #3
    mov     z28.h, #0x55
    mov     z29.h, #0x33
    mov     z30.h, #0x0f
    ptrue   p0.h
1:
    add     x6, x1, x5
    ld1b    {z16.h}, p0/z, [x6]
    add     x6, x6, #16
    ld1b    {z17.h}, p0/z, [x6]
    add     x6, x6, #16
    ld1b    {z18.h}, p0/z, [x6]
    add     x6, x6, #16
    ld1b    {z19.h}, p0/z, [x6]
    lsr     z27.h, z16.h, #1
    and     z27.d, z27.d, z28.d
    sub     z16.h, z16.h, z27.h
    and     z27.d, z16.d, z29.d
    lsr     z16.h, z16.h, #2
    and     z16.d, z16.d, z29.d
    add     z16.h, z16.h, z27.h
    and     z27.d, z16.d, z30.d
    lsr     z16.h, z16.h, #4
    sub     z16.h, z27.h, z16.h
    lsr     z27.h, z17.h, #1
    and     z27.d, z27.d, z28.d
    sub     z17.h, z17.h, z27.h
    and     z27.d, z17.d, z29.d
    lsr     z17.h, z17.h, #2
    and     z17.d, z17.d, z29.d
    add     z17.h, z17.h, z27.h
    and     z27.d, z17.d, z30.d
    lsr     z17.h, z17.h, #4
    sub     z17.h, z27.h, z17.h
    lsr     z27.h, z18.h, #1
    and     z27.d, z27.d, z28.d
    sub     z18.h, z18.h, z27.h
    and     z27.d, z18.d, z29.d
    lsr     z18.h, z18.h, #2
    and     z18.d, z18.d, z29.d
    add     z18.h, z18.h, z27.h
    and     z27.d, z18.d, z30.d
    lsr     z18.h, z18.h, #4
    sub     z18.h, z27.h, z18.h
    lsr     z27.h, z19.h, #1
    and     z27.d, z27.d, z28.d
    sub     z19.h, z19.h, z27.h
    and     z27.d, z19.d, z29.d
    lsr     z19.h, z19.h, #2
    and     z19.d, z19.d, z29.d
    add     z19.h, z19.h, z27.h
    and     z27.d, z19.d, z30.d
    lsr     z19.h, z19.h, #4
    sub     z19.h, z27.h, z19.h

    uzp1    z0.h, z16.h, z17.h
    uzp1    z1.h, z18.h, z19.h
    uzp1    z20.h, z0.h, z1.h
    uzp2    z22.h, z0.h, z1.h
    uzp2    z2.h, z16.h, z17.h
    uzp2    z3.h, z18.h, z19.h
    uzp1    z21.h, z2.h, z3.h
    uzp2    z23.h, z2.h, z3.h

    lsr     x6, x5, #2
    add     x6, x3, x6
    ld1b    {z8.h}, p0/z, [x6]
    and     z0.d, z8.d, z24.d
    lsr     z9.h, z8.h, #1
    and     z9.d, z9.d, z24.d
    sub     z0.h, z0.h, z9.h
    lsr     z1.h, z8.h, #2
    and     z1.d, z1.d, z24.d
    lsr     z9.h, z8.h, #3
    and     z9.d, z9.d, z24.d
    sub     z1.h, z1.h, z9.h
    lsr     z2.h, z8.h, #4
    and     z2.d, z2.d, z24.d
    lsr     z9.h, z8.h, #5
    and     z9.d, z9.d, z24.d
    sub     z2.h, z2.h, z9.h
    lsr     z3.h, z8.h, #6
    and     z3.d, z3.d, z24.d
    lsr     z9.h, z8.h, #7
    sub     z3.h, z3.h, z9.h
    add     z20.h, z20.h, z0.h
    add     z21.h, z21.h, z1.h
    add     z22.h, z22.h, z2.h
    add     z23.h, z23.h, z3.h

    lsr     x6, x5, #1
    add     x6, x4, x6
    ld1b    {z8.h}, p0/z, [x6]
    and     z9.d, z8.d, z28.d
    lsr     z8.h, z8.h, #1
    and     z8.d, z8.d, z28.d
    add     z8.h, z8.h, z9.h
    and     z4.d, z8.d, z25.d
    lsr     z9.h, z8.h, #2
    and     z9.d, z9.d, z25.d
    sub     z4.h, z4.h, z9.h
    lsr     z5.h, z8.h, #4
    and     z5.d, z5.d, z25.d
    lsr     z9.h, z8.h, #6
    sub     z5.h, z5.h, z9.h
    add     x6, x6, #16
    ld1b    {z8.h}, p0/z, [x6]
    and     z9.d, z8.d, z28.d
    lsr     z8.h, z8.h, #1
    and     z8.d, z8.d, z28.d
    add     z8.h, z8.h, z9.h
    and     z6.d, z8.d, z25.d
    lsr     z9.h, z8.h, #2
    and     z9.d, z9.d, z25.d
    sub     z6.h, z6.h, z9.h
    lsr     z7.h, z8.h, #4
    and     z7.d, z7.d, z25.d
    lsr     z9.h, z8.h, #6
    sub     z7.h, z7.h, z9.h
    uzp1    z8.h, z4.h, z6.h
    uzp1    z9.h, z5.h, z7.h
    uzp2    z10.h, z4.h, z6.h
    uzp2    z11.h, z5.h, z7.h
    add     z20.h, z20.h, z8.h
    add     z21.h, z21.h, z9.h
    add     z22.h, z22.h, z10.h
    add     z23.h, z23.h, z11.h
    st4h    {z20.h-z23.h}, p0, [x7]
    add     x7, x7, #128
    add     x5, x5, #64
    cmp     x5, x2
    b.lo    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Cbd7Sve2)

// void NEV_MaskTernary8Sve2(int16_t *r, const uint8_t *mask, uint32_t n)
CRYPT_AARCH64_FUNC_START(NEV_MaskTernary8Sve2)
AARCH64_PACIASP
    mov     w2, w2
    mov     x3, #0
    mov     z14.s, #7
1:
    whilelt p0.s, x3, x2
    b.none  2f
    index   z10.s, w3, #1
    lsr     z11.s, z10.s, #3
    and     z12.d, z10.d, z14.d
    ld1b    {z0.s}, p0/z, [x1, z11.s, uxtw]
    lsr     z0.s, p0/m, z0.s, z12.s
    and     z0.s, z0.s, #1
    neg     z0.s, p0/m, z0.s
    ld1h    {z1.s}, p0/z, [x0, x3, lsl #1]
    and     z1.d, z1.d, z0.d
    st1h    {z1.s}, p0, [x0, x3, lsl #1]
    incw    x3
    b       1b
2:
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MaskTernary8Sve2)

// void NEV_NoiseMFoldSve2(uint8_t *buf, const uint8_t *msg,
//                         uint64_t planes, uint64_t seedLen)
// Fold plane zero 32 bytes at a time.  A tail predicate handles seedLen=16.
CRYPT_AARCH64_FUNC_START(NEV_NoiseMFoldSve2)
AARCH64_PACIASP
    mov     x4, #0
1:
    whilelt p0.b, x4, x3
    b.none  4f
    ld1b    {z0.b}, p0/z, [x1, x4]
    add     x5, x0, x3
    add     x5, x5, x4
    sub     x6, x2, #1
2:
    ld1b    {z1.b}, p0/z, [x5]
    eor     z0.d, z0.d, z1.d
    add     x5, x5, x3
    subs    x6, x6, #1
    b.ne    2b
    st1b    {z0.b}, p0, [x0, x4]
    incb    x4
    b       1b
4:
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_NoiseMFoldSve2)

/* Expand four adjacent bytes into two vectors of sixteen one-bit int16
 * values and accumulate pa - pb.  x13/x14 walk the eta planes directly,
 * avoiding the old multiply-add address chain in the inner loop. */
.macro NEV_NOISE_ACCUM_PLANE
    ldr     w16, [x13]
    ldr     w17, [x14]
#ifdef HITLS_BIG_ENDIAN
    rev     w16, w16
    rev     w17, w17
#endif
    dup     z0.h, w16
    lsr     w18, w16, #16
    dup     z1.h, w18
    dup     z2.h, w17
    lsr     w18, w17, #16
    dup     z3.h, w18
    lsr     z0.h, p0/m, z0.h, z30.h
    lsr     z1.h, p0/m, z1.h, z30.h
    lsr     z2.h, p0/m, z2.h, z30.h
    lsr     z3.h, p0/m, z3.h, z30.h
    and     z0.d, z0.d, z31.d
    and     z1.d, z1.d, z31.d
    and     z2.d, z2.d, z31.d
    and     z3.d, z3.d, z31.d
    sub     z0.h, z0.h, z2.h
    sub     z1.h, z1.h, z3.h
    add     z16.h, z16.h, z0.h
    add     z17.h, z17.h, z1.h
    add     x13, x13, x3
    add     x14, x14, x3
.endm

/* One eta-specialized complete extractor.  Four input bytes map either to
 * one contiguous 32-coefficient region (dim=128), or to two 16-coefficient
 * regions 64 coefficients apart (dim=64).  x15 is the byte gap between the
 * two stores: 32 for dim=128 and 128 for dim=64. */
.macro NEV_NOISE_KERNEL eta
.if \eta == 1
    mov     x5, x3
.elseif \eta == 2
    lsl     x5, x3, #1
.elseif \eta == 3
    add     x5, x3, x3, lsl #1
.elseif \eta == 4
    lsl     x5, x3, #2
.else
    lsl     x5, x3, #3
    sub     x5, x5, x3
.endif
    lsl     x6, x5, #1                  // input bytes per group
    lsr     x7, x4, #1                  // output bytes per group
    mov     x8, #4
    mov     x9, x1                      // group input base
    mov     x12, x0                     // group output base
.Lnoise_group_\@:
    mov     x10, x12                    // current output pair
    mov     x11, #0                     // byte index
.Lnoise_bytes_\@:
    add     x13, x9, x11                // positive plane pointer
    add     x14, x13, x5                // negative plane pointer
    mov     z16.h, #0
    mov     z17.h, #0
    .rept \eta
        NEV_NOISE_ACCUM_PLANE
    .endr
    st1h    {z16.h}, p0, [x10]
    add     x18, x10, x15
    st1h    {z17.h}, p0, [x18]
    add     x10, x10, #256
    add     x11, x11, #4
    cmp     x11, x3
    b.lo    .Lnoise_bytes_\@
    add     x9, x9, x6
    add     x12, x12, x7
    subs    x8, x8, #1
    b.ne    .Lnoise_group_\@
    b       .Lnoise_done
.endm

// void NEV_NoiseMExtractSve2(int16_t *r, const uint8_t *buf,
//                            uint64_t eta, uint64_t seedLen, uint64_t dim)
CRYPT_AARCH64_FUNC_START(NEV_NoiseMExtractSve2)
AARCH64_PACIASP
    ptrue   p0.h
    index   z30.h, #0, #1
    mov     z31.h, #1
    mov     x15, #32
    cmp     x4, #64
    b.ne    .Lnoise_dim_ready
    mov     x15, #128
.Lnoise_dim_ready:
    cmp     x2, #1
    b.eq    .Lnoise_eta1
    cmp     x2, #2
    b.eq    .Lnoise_eta2
    cmp     x2, #3
    b.eq    .Lnoise_eta3
    cmp     x2, #4
    b.eq    .Lnoise_eta4
    NEV_NOISE_KERNEL 7
.Lnoise_eta1:
    NEV_NOISE_KERNEL 1
.Lnoise_eta2:
    NEV_NOISE_KERNEL 2
.Lnoise_eta3:
    NEV_NOISE_KERNEL 3
.Lnoise_eta4:
    NEV_NOISE_KERNEL 4
.Lnoise_done:
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_NoiseMExtractSve2)

#endif

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
