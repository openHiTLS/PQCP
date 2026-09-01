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

/* Three-instruction twiddle multiply used by the NEON NTT. */
.macro NEV_SVE_NTT_MUL src, dst, tmp, root, root_hi, q
    mul      \dst\().h, \src\().h, \root\().h
    sqrdmulh \tmp\().h, \src\().h, \root_hi\().h
    mls      \dst\().h, p1/m, \tmp\().h, \q\().h
.endm

/* Exact Barrett reduction. z5 contains 15-barrettShift. */
.macro NEV_SVE_NTT_BR value, tmp, v, q
    sqdmulh \tmp\().h, \value\().h, \v\().h
    srshl   \tmp\().h, p1/m, \tmp\().h, z5.h
    mls     \value\().h, p1/m, \tmp\().h, \q\().h
.endm

.text

// void NEV_NttSve2(int16_t *block, const int16_t *pairs, uint64_t dim,
//                  uint64_t q, uint64_t barrettV, uint64_t barrettShift)
// pairs[k] is {root, root_hi}; pair zero is unused by the forward transform.
CRYPT_AARCH64_FUNC_START(NEV_NttSve2)
AARCH64_PACIASP
    ptrue   p1.h
    dup     z7.h, w3
    dup     z6.h, w4
    mov     w9, #15
    sub     w9, w9, w5
    dup     z5.h, w9
    lsr     x6, x2, #1                  // len
    mov     x7, #1                      // twiddle index
1:
    cmp     x6, #4
    b.ls    5f
    mov     x8, #0                      // start
2:
    cmp     x8, x2
    b.hs    4f
    lsl     x9, x7, #2
    add     x13, x1, x9
    ldrsh   w10, [x13]
    ldrsh   w11, [x13, #2]
    dup     z8.h, w10
    dup     z9.h, w11
    add     x7, x7, #1
    add     x11, x8, x6                 // end
    mov     x10, x8                     // j
    whilelt p0.h, x10, x11
3:
    add     x12, x10, x6
    ld1h    {z0.h}, p0/z, [x0, x10, lsl #1]
    ld1h    {z1.h}, p0/z, [x0, x12, lsl #1]
    NEV_SVE_NTT_MUL z1, z2, z3, z8, z9, z7
    sub     z1.h, z0.h, z2.h
    add     z0.h, z0.h, z2.h
    st1h    {z0.h}, p0, [x0, x10, lsl #1]
    st1h    {z1.h}, p0, [x0, x12, lsl #1]
    inch    x10
    whilelt p0.h, x10, x11
    b.first 3b
    add     x8, x11, x6
    b       2b
4:
    lsr     x6, x6, #1
    b       1b

    /*
     * Pack the short layers across independent twiddle groups.  The generic
     * loop above vectorizes within one group, which leaves only 4/2/1 active
     * halfword lanes here.  Structured loads instead make every active lane
     * belong to a different group (or to one of its independent positions),
     * so the same code remains VLA while avoiding the short predicated loads
     * that dominate the 64- and 128-point transforms.
     */
5:
    // len = 4: LD4 sees alternating a/b structures; UZP splits the groups.
    lsr     x14, x2, #3                 // groups = dim / 8
    lsr     x15, x2, #2                 // four-halfword structures
    cnth    x16
    lsr     x16, x16, #1                // groups carried per LD4
    mov     x8, #0                      // structure index
7:
    whilelt p0.h, x8, x15
    lsl     x11, x8, #3
    add     x11, x0, x11
    ld4h    {z0.h, z1.h, z2.h, z3.h}, p0/z, [x11]
    lsr     x10, x8, #1                 // group index
    add     x12, x10, x16
    cmp     x12, x14
    csel    x12, x12, x14, lo
    whilelt p2.h, x10, x12
    add     x12, x7, x10
    lsl     x12, x12, #2
    add     x13, x1, x12
    ld2h    {z8.h, z9.h}, p2/z, [x13]
    uzp1    z10.h, z0.h, z0.h
    uzp2    z14.h, z0.h, z0.h
    uzp1    z11.h, z1.h, z1.h
    uzp2    z15.h, z1.h, z1.h
    uzp1    z12.h, z2.h, z2.h
    uzp2    z16.h, z2.h, z2.h
    uzp1    z13.h, z3.h, z3.h
    uzp2    z17.h, z3.h, z3.h
    NEV_SVE_NTT_MUL z14, z18, z19, z8, z9, z7
    sub     z14.h, z10.h, z18.h
    add     z10.h, z10.h, z18.h
    NEV_SVE_NTT_MUL z15, z18, z19, z8, z9, z7
    sub     z15.h, z11.h, z18.h
    add     z11.h, z11.h, z18.h
    NEV_SVE_NTT_MUL z16, z18, z19, z8, z9, z7
    sub     z16.h, z12.h, z18.h
    add     z12.h, z12.h, z18.h
    NEV_SVE_NTT_MUL z17, z18, z19, z8, z9, z7
    sub     z17.h, z13.h, z18.h
    add     z13.h, z13.h, z18.h
    zip1    z0.h, z10.h, z14.h
    zip1    z1.h, z11.h, z15.h
    zip1    z2.h, z12.h, z16.h
    zip1    z3.h, z13.h, z17.h
    st4h    {z0.h, z1.h, z2.h, z3.h}, p0, [x11]
    inch    x8
    whilelt p0.h, x8, x15
    b.first 7b
    add     x7, x7, x14

    // len = 2: each LD4 lane is one position of a complete butterfly group.
    lsr     x14, x2, #2                 // groups = dim / 4
    mov     x8, #0
8:
    whilelt p0.h, x8, x14
    lsl     x11, x8, #3
    add     x11, x0, x11
    ld4h    {z0.h, z1.h, z2.h, z3.h}, p0/z, [x11]
    add     x12, x7, x8
    lsl     x12, x12, #2
    add     x13, x1, x12
    ld2h    {z8.h, z9.h}, p0/z, [x13]
    mul     z10.h, z2.h, z8.h
    mul     z11.h, z3.h, z8.h
    sqrdmulh z12.h, z2.h, z9.h
    sqrdmulh z13.h, z3.h, z9.h
    mls     z10.h, p1/m, z12.h, z7.h
    mls     z11.h, p1/m, z13.h, z7.h
    sub     z2.h, z0.h, z10.h
    sub     z3.h, z1.h, z11.h
    add     z0.h, z0.h, z10.h
    add     z1.h, z1.h, z11.h
    st4h    {z0.h, z1.h, z2.h, z3.h}, p0, [x11]
    inch    x8
    whilelt p0.h, x8, x14
    b.first 8b
    add     x7, x7, x14

    // len = 1: LD2/ST2 turn adjacent coefficients into full vectors.
    lsr     x14, x2, #1                 // groups = dim / 2
    mov     x8, #0
9:
    whilelt p0.h, x8, x14
    lsl     x11, x8, #2
    add     x11, x0, x11
    ld2h    {z0.h, z1.h}, p0/z, [x11]
    add     x12, x7, x8
    lsl     x12, x12, #2
    add     x13, x1, x12
    ld2h    {z8.h, z9.h}, p0/z, [x13]
    NEV_SVE_NTT_MUL z1, z2, z3, z8, z9, z7
    sub     z1.h, z0.h, z2.h
    add     z0.h, z0.h, z2.h
    st2h    {z0.h, z1.h}, p0, [x11]
    inch    x8
    whilelt p0.h, x8, x14
    b.first 9b

    mov     x10, #0
    whilelt p0.h, x10, x2
6:
    ld1h    {z0.h}, p0/z, [x0, x10, lsl #1]
    NEV_SVE_NTT_BR z0, z1, z6, z7
    st1h    {z0.h}, p0, [x0, x10, lsl #1]
    inch    x10
    whilelt p0.h, x10, x2
    b.first 6b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_NttSve2)

// void NEV_InvNttSve2(int16_t *block, const int16_t *pairs, uint64_t dim,
//                     uint64_t q, uint64_t barrettV,
//                     uint64_t barrettShift)
// The fused final pairs {fP,fP_hi,fzetaP,fzetaP_hi} follow pairs[dim-1].
CRYPT_AARCH64_FUNC_START(NEV_InvNttSve2)
AARCH64_PACIASP
    ptrue   p1.h
    dup     z7.h, w3
    dup     z6.h, w4
    mov     w9, #15
    sub     w9, w9, w5
    dup     z5.h, w9
    cnth    x14
    cmp     x14, #16                    // tuned path for the measured VL=256
    b.eq    9f
    mov     x7, x2                      // reverse twiddle index
    mov     x6, #1                      // len
1:
    lsr     x9, x2, #2
    cmp     x6, x9
    b.hi    7f
    mov     x8, #0
2:
    cmp     x8, x2
    b.hs    4f
    sub     x7, x7, #1
    lsl     x9, x7, #2
    add     x13, x1, x9
    ldrsh   w10, [x13]
    ldrsh   w11, [x13, #2]
    dup     z8.h, w10
    dup     z9.h, w11
    add     x11, x8, x6
    mov     x10, x8
    whilelt p0.h, x10, x11
3:
    add     x12, x10, x6
    ld1h    {z0.h}, p0/z, [x0, x10, lsl #1]
    ld1h    {z1.h}, p0/z, [x0, x12, lsl #1]
    sub     z2.h, z1.h, z0.h
    add     z0.h, z0.h, z1.h
    NEV_SVE_NTT_MUL z2, z1, z3, z8, z9, z7
    st1h    {z0.h}, p0, [x0, x10, lsl #1]
    st1h    {z1.h}, p0, [x0, x12, lsl #1]
    inch    x10
    whilelt p0.h, x10, x11
    b.first 3b
    add     x8, x11, x6
    b       2b
4:
    cmp     x6, #4
    b.ne    6f
    mov     x10, #0
    whilelt p0.h, x10, x2
5:
    ld1h    {z0.h}, p0/z, [x0, x10, lsl #1]
    NEV_SVE_NTT_BR z0, z1, z6, z7
    st1h    {z0.h}, p0, [x0, x10, lsl #1]
    inch    x10
    whilelt p0.h, x10, x2
    b.first 5b
6:
    lsl     x6, x6, #1
    b       1b
7:
    // Fused final GS layer.  Four halfwords are stored after dim pairs.
    lsl     x9, x2, #2
    add     x9, x1, x9
    ldrsh   w10, [x9]
    ldrsh   w11, [x9, #2]
    ldrsh   w12, [x9, #4]
    ldrsh   w13, [x9, #6]
    dup     z8.h, w10
    dup     z9.h, w11
    dup     z10.h, w12
    dup     z11.h, w13
    lsr     x6, x2, #1
    mov     x10, #0
    whilelt p0.h, x10, x6
8:
    add     x12, x10, x6
    ld1h    {z0.h}, p0/z, [x0, x10, lsl #1]
    ld1h    {z1.h}, p0/z, [x0, x12, lsl #1]
    sub     z2.h, z1.h, z0.h
    add     z0.h, z0.h, z1.h
    NEV_SVE_NTT_MUL z0, z3, z4, z8, z9, z7
    NEV_SVE_NTT_MUL z2, z1, z4, z10, z11, z7
    st1h    {z3.h}, p0, [x0, x10, lsl #1]
    st1h    {z1.h}, p0, [x0, x12, lsl #1]
    inch    x10
    whilelt p0.h, x10, x6
    b.first 8b
AARCH64_AUTIASP
    ret

    /*
     * VL=256 inverse short-layer path.  The inverse roots run backwards, so
     * load each contiguous table chunk forwards and REV it once instead of
     * doing one scalar root load/dup and one tiny data load per group.  The
     * len=4 layer then rejoins the VLA loop above; it is a much smaller part
     * of the remaining cost and keeps the shared Barrett synchronization
     * point unchanged.
     */
9:
    mov     x7, x2                      // reverse twiddle index

    // len = 1: sixteen adjacent butterfly groups per LD2/ST2.
    lsr     x14, x2, #1
    mov     x8, #0
10:
    whilelt p0.h, x8, x14
    lsl     x11, x8, #2
    add     x11, x0, x11
    ld2h    {z0.h, z1.h}, p0/z, [x11]
    sub     x12, x7, x8
    sub     x12, x12, #16
    lsl     x12, x12, #2
    add     x13, x1, x12
    ld2h    {z8.h, z9.h}, p1/z, [x13]
    rev     z8.h, z8.h
    rev     z9.h, z9.h
    sub     z2.h, z1.h, z0.h
    add     z0.h, z0.h, z1.h
    NEV_SVE_NTT_MUL z2, z1, z3, z8, z9, z7
    st2h    {z0.h, z1.h}, p0, [x11]
    inch    x8
    whilelt p0.h, x8, x14
    b.first 10b
    sub     x7, x7, x14

    // len = 2: two independent butterfly positions per structure.
    lsr     x14, x2, #2
    mov     x8, #0
11:
    whilelt p0.h, x8, x14
    lsl     x11, x8, #3
    add     x11, x0, x11
    ld4h    {z0.h, z1.h, z2.h, z3.h}, p0/z, [x11]
    sub     x12, x7, x8
    sub     x12, x12, #16
    lsl     x12, x12, #2
    add     x13, x1, x12
    ld2h    {z8.h, z9.h}, p1/z, [x13]
    rev     z8.h, z8.h
    rev     z9.h, z9.h
    sub     z10.h, z2.h, z0.h
    sub     z11.h, z3.h, z1.h
    add     z0.h, z0.h, z2.h
    add     z1.h, z1.h, z3.h
    NEV_SVE_NTT_MUL z10, z2, z12, z8, z9, z7
    NEV_SVE_NTT_MUL z11, z3, z12, z8, z9, z7
    st4h    {z0.h, z1.h, z2.h, z3.h}, p0, [x11]
    inch    x8
    whilelt p0.h, x8, x14
    b.first 11b
    sub     x7, x7, x14
    mov     x6, #4
    b       1b
CRYPT_AARCH64_FUNC_END(NEV_InvNttSve2)

#endif

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
