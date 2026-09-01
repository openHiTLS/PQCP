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

/* SVE2 packed-boundary kernels for NEV. */
#include "hitls_build.h"
#if defined(HITLS_CRYPTO_NEV) && defined(HITLS_CRYPTO_NEV_SVE2)
#include "crypt_arm.h"
#include "nev_arm_asm.h"
CRYPT_AARCH64_ARCH_SVE2

.text

.macro NEV_TOMSG_FLIP zval, ztmp
    asr     \ztmp\().s, \zval\().s, #31
    and     \ztmp\().d, \ztmp\().d, z28.d
    add     \zval\().s, \zval\().s, \ztmp\().s
    sub     \zval\().s, \zval\().s, z29.s
    abs     \zval\().s, p0/m, \zval\().s
.endm

.macro NEV_TOMSG_BIT bit
    mov     z12.d, z11.d
.if \bit
    add     z12.s, z12.s, #(2 * \bit)
.endif
    ld1sh   {z1.s}, p0/z, [x1, z12.s, uxtw]
    add     z12.s, z12.s, z26.s
    ld1sh   {z2.s}, p0/z, [x1, z12.s, uxtw]
    add     z12.s, z12.s, z26.s
    ld1sh   {z3.s}, p0/z, [x1, z12.s, uxtw]
    add     z12.s, z12.s, z26.s
    ld1sh   {z4.s}, p0/z, [x1, z12.s, uxtw]
    NEV_TOMSG_FLIP z1, z5
    NEV_TOMSG_FLIP z2, z5
    NEV_TOMSG_FLIP z3, z5
    NEV_TOMSG_FLIP z4, z5
    add     z5.s, z1.s, z2.s
    add     z6.s, z3.s, z4.s
    add     z5.s, z5.s, z6.s
    and     z5.s, z5.s, #0xffff
    sub     z5.s, z5.s, z28.s
    lsr     z5.s, z5.s, #15
    and     z5.s, z5.s, #1
.if \bit
    lsl     z5.s, z5.s, #\bit
.endif
    orr     z0.d, z0.d, z5.d
.endm

// void NEV_ToMsgSve2(uint8_t *msg, const int16_t *a, uint64_t blocks,
//                    uint64_t dim, uint64_t q)
CRYPT_AARCH64_FUNC_START(NEV_ToMsgSve2)
AARCH64_PACIASP
    lsr     x5, x3, #5                  // message bytes per block
    mul     x2, x2, x5                  // total output bytes
    sub     x6, x5, #1
    clz     x7, x5
    mov     x8, #63
    sub     x7, x8, x7
    lsr     x8, x3, #1                  // quarter stride in bytes
    dup     z26.s, w8
    dup     z28.s, w4
    lsr     w9, w4, #1
    dup     z29.s, w9
    dup     z30.s, w3
    dup     z31.s, w6
    dup     z27.s, w7
    ptrue   p1.s
    mov     x3, #0
1:
    whilelt p0.s, x3, x2
    b.none  2f
    index   z10.s, w3, #1
    mov     z11.d, z10.d
    lsr     z11.s, p1/m, z11.s, z27.s
    and     z12.d, z10.d, z31.d
    mul     z11.s, z11.s, z30.s
    lsl     z12.s, z12.s, #3
    add     z11.s, z11.s, z12.s
    lsl     z11.s, z11.s, #1           // carrier-0 byte offsets
    dup     z0.s, #0
    NEV_TOMSG_BIT 0
    NEV_TOMSG_BIT 1
    NEV_TOMSG_BIT 2
    NEV_TOMSG_BIT 3
    NEV_TOMSG_BIT 4
    NEV_TOMSG_BIT 5
    NEV_TOMSG_BIT 6
    NEV_TOMSG_BIT 7
    st1b    {z0.s}, p0, [x0, x3]
    incw    x3
    b       1b
2:
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_ToMsgSve2)

// void NEV_ToBytes769Sve2(uint8_t *r, const int16_t *a, uint64_t records)
// One .s lane carries one independent five-coefficient mixed-radix record.
CRYPT_AARCH64_FUNC_START(NEV_ToBytes769Sve2)
AARCH64_PACIASP
    index   z10.s, #0, #10              // input record byte offsets
    index   z11.s, #0, #6               // output record byte offsets
    mov     w5, #97
    dup     z12.s, w5
    mov     w5, #48
    dup     z13.s, w5
    mov     x3, #0
1:
    whilelo p0.s, x3, x2
    b.none  2f
    ld1h    {z0.s}, p0/z, [x1, z10.s, uxtw]
    mov     z14.d, z10.d
    add     z14.s, z14.s, #2
    ld1h    {z1.s}, p0/z, [x1, z14.s, uxtw]
    add     z14.s, z14.s, #2
    ld1h    {z2.s}, p0/z, [x1, z14.s, uxtw]
    add     z14.s, z14.s, #2
    ld1h    {z3.s}, p0/z, [x1, z14.s, uxtw]
    add     z14.s, z14.s, #2
    ld1h    {z4.s}, p0/z, [x1, z14.s, uxtw]
    mov     z5.d, z0.d
    and     z5.s, z5.s, #7
    mov     z6.d, z1.d
    and     z6.s, z6.s, #7
    lsl     z6.s, z6.s, #3
    orr     z5.d, z5.d, z6.d
    mov     z6.d, z2.d
    and     z6.s, z6.s, #7
    lsl     z6.s, z6.s, #6
    orr     z5.d, z5.d, z6.d
    mov     z6.d, z3.d
    and     z6.s, z6.s, #7
    lsl     z6.s, z6.s, #9
    orr     z5.d, z5.d, z6.d
    mov     z6.d, z4.d
    and     z6.s, z6.s, #7
    lsl     z6.s, z6.s, #12
    orr     z5.d, z5.d, z6.d
    lsl     z5.s, z5.s, #1              // wl
    lsr     z6.s, z4.s, #3              // wh
    mul     z6.s, z6.s, z12.s
    lsr     z7.s, z3.s, #3
    add     z6.s, z6.s, z7.s
    mul     z6.s, z6.s, z12.s
    lsr     z7.s, z2.s, #3
    add     z6.s, z6.s, z7.s
    mul     z6.s, z6.s, z12.s
    lsr     z7.s, z1.s, #3
    add     z6.s, z6.s, z7.s
    mul     z7.s, z6.s, z13.s           // t = wh * 48
    lsr     z8.s, z7.s, #31
    orr     z5.d, z5.d, z8.d
    lsl     z7.s, z7.s, #1
    lsr     z8.s, z0.s, #3
    add     z6.s, z6.s, z8.s
    add     z6.s, z7.s, z6.s
    bic     z8.d, z7.d, z6.d
    lsr     z8.s, z8.s, #31
    orr     z5.d, z5.d, z8.d
    st1b    {z5.s}, p0, [x0, z11.s, uxtw]
    mov     z14.d, z11.d
    add     z14.s, z14.s, #1
    lsr     z8.s, z5.s, #8
    st1b    {z8.s}, p0, [x0, z14.s, uxtw]
    add     z14.s, z14.s, #1
    st1b    {z6.s}, p0, [x0, z14.s, uxtw]
    lsr     z6.s, z6.s, #8
    add     z14.s, z14.s, #1
    st1b    {z6.s}, p0, [x0, z14.s, uxtw]
    lsr     z6.s, z6.s, #8
    add     z14.s, z14.s, #1
    st1b    {z6.s}, p0, [x0, z14.s, uxtw]
    lsr     z6.s, z6.s, #8
    add     z14.s, z14.s, #1
    st1b    {z6.s}, p0, [x0, z14.s, uxtw]
    cntp    x4, p0, p0.s
    add     x1, x1, x4, lsl #3
    add     x1, x1, x4, lsl #1          // 10 bytes / record
    add     x0, x0, x4, lsl #1
    add     x0, x0, x4, lsl #2          // 6 bytes / record
    add     x3, x3, x4
    b       1b
2:
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_ToBytes769Sve2)

// void NEV_FromBytes769Sve2(int16_t *r, const uint8_t *a, uint64_t records)
CRYPT_AARCH64_FUNC_START(NEV_FromBytes769Sve2)
AARCH64_PACIASP
    index   z10.s, #0, #6
    index   z11.s, #0, #10
    mov     w5, #43241
    dup     z12.s, w5
    movz    w5, #0xa3a1
    movk    w5, #0x5f02, lsl #16        // 1594008481
    dup     z13.s, w5
    mov     w5, #97
    dup     z14.s, w5
    mov     x3, #0
1:
    whilelo p0.s, x3, x2
    b.none  2f
    ld1b    {z0.s}, p0/z, [x1, z10.s, uxtw]
    mov     z15.d, z10.d
    add     z15.s, z15.s, #1
    ld1b    {z1.s}, p0/z, [x1, z15.s, uxtw]
    add     z15.s, z15.s, #1
    ld1b    {z2.s}, p0/z, [x1, z15.s, uxtw]
    add     z15.s, z15.s, #1
    ld1b    {z3.s}, p0/z, [x1, z15.s, uxtw]
    add     z15.s, z15.s, #1
    ld1b    {z4.s}, p0/z, [x1, z15.s, uxtw]
    add     z15.s, z15.s, #1
    ld1b    {z5.s}, p0/z, [x1, z15.s, uxtw]
    lsl     z1.s, z1.s, #8
    orr     z0.d, z0.d, z1.d            // wl
    lsl     z3.s, z3.s, #8
    orr     z2.d, z2.d, z3.d
    lsl     z4.s, z4.s, #16
    orr     z2.d, z2.d, z4.d
    lsl     z5.s, z5.s, #24
    orr     z2.d, z2.d, z5.d            // wh
    mov     z3.d, z0.d
    and     z3.s, z3.s, #1
    lsl     z3.s, z3.s, #13
    lsr     z4.s, z2.s, #19
    orr     z3.d, z3.d, z4.d
    lsl     z4.s, z3.s, #1
    add     z4.s, z4.s, z3.s
    mov     z3.d, z2.d
    and     z3.s, z3.s, #0x7ffff
    add     z3.s, z3.s, z4.s            // z
    lsr     z0.s, z0.s, #1
    lsr     z4.s, z3.s, #9
    mov     z5.s, #27
    mul     z4.s, z4.s, z5.s
    mov     z5.d, z3.d
    and     z5.s, z5.s, #0x1ff
    add     z3.s, z4.s, z5.s
    mul     z4.s, z3.s, z12.s
    lsr     z4.s, z4.s, #22
    mls     z3.s, p0/m, z4.s, z14.s
    lsl     z5.s, z3.s, #3
    mov     z6.d, z0.d
    and     z6.s, z6.s, #7
    add     z5.s, z5.s, z6.s
    st1h    {z5.s}, p0, [x0, z11.s, uxtw]
    lsr     z0.s, z0.s, #3
    sub     z2.s, z2.s, z3.s
    mul     z2.s, z2.s, z13.s
    lsr     z3.s, z2.s, #19
    mov     z4.d, z3.d
    lsl     z4.s, z4.s, #1
    add     z3.s, z3.s, z4.s
    mov     z4.d, z2.d
    and     z4.s, z4.s, #0x7ffff
    add     z3.s, z3.s, z4.s
    lsr     z4.s, z3.s, #9
    mov     z5.s, #27
    mul     z4.s, z4.s, z5.s
    mov     z5.d, z3.d
    and     z5.s, z5.s, #0x1ff
    add     z3.s, z4.s, z5.s
    mul     z4.s, z3.s, z12.s
    lsr     z4.s, z4.s, #22
    mls     z3.s, p0/m, z4.s, z14.s
    lsl     z5.s, z3.s, #3
    mov     z6.d, z0.d
    and     z6.s, z6.s, #7
    add     z5.s, z5.s, z6.s
    mov     z15.d, z11.d
    add     z15.s, z15.s, #2
    st1h    {z5.s}, p0, [x0, z15.s, uxtw]
    lsr     z0.s, z0.s, #3
    sub     z2.s, z2.s, z3.s
    mul     z2.s, z2.s, z13.s
    lsr     z3.s, z2.s, #9
    mov     z4.s, #27
    mul     z3.s, z3.s, z4.s
    mov     z4.d, z2.d
    and     z4.s, z4.s, #0x1ff
    add     z3.s, z3.s, z4.s
    mul     z4.s, z3.s, z12.s
    lsr     z4.s, z4.s, #22
    mls     z3.s, p0/m, z4.s, z14.s
    lsl     z5.s, z3.s, #3
    mov     z6.d, z0.d
    and     z6.s, z6.s, #7
    add     z5.s, z5.s, z6.s
    add     z15.s, z15.s, #2
    st1h    {z5.s}, p0, [x0, z15.s, uxtw]
    lsr     z0.s, z0.s, #3
    sub     z2.s, z2.s, z3.s
    mul     z2.s, z2.s, z13.s
    mul     z3.s, z2.s, z12.s
    lsr     z3.s, z3.s, #22             // x4 high part for last coefficient
    mls     z2.s, p0/m, z3.s, z14.s
    lsl     z4.s, z2.s, #3
    mov     z5.d, z0.d
    and     z5.s, z5.s, #7
    add     z4.s, z4.s, z5.s
    add     z15.s, z15.s, #2
    st1h    {z4.s}, p0, [x0, z15.s, uxtw]
    lsr     z0.s, z0.s, #3
    lsl     z3.s, z3.s, #3
    add     z3.s, z3.s, z0.s
    add     z15.s, z15.s, #2
    st1h    {z3.s}, p0, [x0, z15.s, uxtw]
    cntp    x4, p0, p0.s
    add     x1, x1, x4, lsl #1
    add     x1, x1, x4, lsl #2
    add     x0, x0, x4, lsl #3
    add     x0, x0, x4, lsl #1
    add     x3, x3, x4
    b       1b
2:
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_FromBytes769Sve2)

// void NEV_ToBytes1409Sve2(uint8_t *r, const int16_t *a, uint64_t n)
CRYPT_AARCH64_FUNC_START(NEV_ToBytes1409Sve2)
AARCH64_PACIASP
    lsr     x2, x2, #4
    index   z10.s, #0, #1
    mov     w5, #32
    dup     z15.s, w5
    mul     z10.s, z10.s, z15.s
    index   z11.s, #0, #1
    mov     w5, #21
    dup     z15.s, w5
    mul     z11.s, z11.s, z15.s
    mov     w5, #1409
    dup     z13.s, w5
    mov     x3, #0
1:
    whilelo p0.s, x3, x2
    b.none  2f
    mov     z19.d, z10.d
    ld1h    {z0.s}, p0/z, [x1, z19.s, uxtw]
    add     z19.s, z19.s, #2
    ld1h    {z18.s}, p0/z, [x1, z19.s, uxtw]
    mla     z0.s, p0/m, z18.s, z13.s
    mov     z19.d, z10.d
    add     z19.s, z19.s, #4
    ld1h    {z1.s}, p0/z, [x1, z19.s, uxtw]
    add     z19.s, z19.s, #2
    ld1h    {z18.s}, p0/z, [x1, z19.s, uxtw]
    mla     z1.s, p0/m, z18.s, z13.s
    mov     z19.d, z10.d
    add     z19.s, z19.s, #8
    ld1h    {z2.s}, p0/z, [x1, z19.s, uxtw]
    add     z19.s, z19.s, #2
    ld1h    {z18.s}, p0/z, [x1, z19.s, uxtw]
    mla     z2.s, p0/m, z18.s, z13.s
    mov     z19.d, z10.d
    add     z19.s, z19.s, #12
    ld1h    {z3.s}, p0/z, [x1, z19.s, uxtw]
    add     z19.s, z19.s, #2
    ld1h    {z18.s}, p0/z, [x1, z19.s, uxtw]
    mla     z3.s, p0/m, z18.s, z13.s
    mov     z19.d, z10.d
    add     z19.s, z19.s, #16
    ld1h    {z4.s}, p0/z, [x1, z19.s, uxtw]
    add     z19.s, z19.s, #2
    ld1h    {z18.s}, p0/z, [x1, z19.s, uxtw]
    mla     z4.s, p0/m, z18.s, z13.s
    mov     z19.d, z10.d
    add     z19.s, z19.s, #20
    ld1h    {z5.s}, p0/z, [x1, z19.s, uxtw]
    add     z19.s, z19.s, #2
    ld1h    {z18.s}, p0/z, [x1, z19.s, uxtw]
    mla     z5.s, p0/m, z18.s, z13.s
    mov     z19.d, z10.d
    add     z19.s, z19.s, #24
    ld1h    {z6.s}, p0/z, [x1, z19.s, uxtw]
    add     z19.s, z19.s, #2
    ld1h    {z18.s}, p0/z, [x1, z19.s, uxtw]
    mla     z6.s, p0/m, z18.s, z13.s
    mov     z19.d, z10.d
    add     z19.s, z19.s, #28
    ld1h    {z7.s}, p0/z, [x1, z19.s, uxtw]
    add     z19.s, z19.s, #2
    ld1h    {z18.s}, p0/z, [x1, z19.s, uxtw]
    mla     z7.s, p0/m, z18.s, z13.s
    and     z0.s, z0.s, #0xffffff
    and     z1.s, z1.s, #0x7ffffff
    and     z2.s, z2.s, #0x3fffff
    and     z3.s, z3.s, #0x1ffffff
    and     z4.s, z4.s, #0xfffffff
    and     z5.s, z5.s, #0x7fffff
    and     z6.s, z6.s, #0x3ffffff
    and     z7.s, z7.s, #0x1fffff
    mov     z16.d, z0.d
    mov     z19.d, z11.d
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z0.d
    lsr     z16.s, z16.s, #8
    mov     z19.d, z11.d
    add     z19.s, z19.s, #1
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z0.d
    lsr     z16.s, z16.s, #16
    mov     z17.d, z1.d
    lsl     z17.s, z17.s, #5
    orr     z16.d, z16.d, z17.d
    mov     z19.d, z11.d
    add     z19.s, z19.s, #2
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z1.d
    lsr     z16.s, z16.s, #3
    mov     z19.d, z11.d
    add     z19.s, z19.s, #3
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z1.d
    lsr     z16.s, z16.s, #11
    mov     z19.d, z11.d
    add     z19.s, z19.s, #4
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z1.d
    lsr     z16.s, z16.s, #19
    mov     z17.d, z2.d
    lsl     z17.s, z17.s, #2
    orr     z16.d, z16.d, z17.d
    mov     z19.d, z11.d
    add     z19.s, z19.s, #5
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z2.d
    lsr     z16.s, z16.s, #6
    mov     z19.d, z11.d
    add     z19.s, z19.s, #6
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z2.d
    lsr     z16.s, z16.s, #14
    mov     z17.d, z3.d
    lsl     z17.s, z17.s, #7
    orr     z16.d, z16.d, z17.d
    mov     z19.d, z11.d
    add     z19.s, z19.s, #7
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z3.d
    lsr     z16.s, z16.s, #1
    mov     z19.d, z11.d
    add     z19.s, z19.s, #8
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z3.d
    lsr     z16.s, z16.s, #9
    mov     z19.d, z11.d
    add     z19.s, z19.s, #9
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z3.d
    lsr     z16.s, z16.s, #17
    mov     z17.d, z4.d
    lsl     z17.s, z17.s, #4
    orr     z16.d, z16.d, z17.d
    mov     z19.d, z11.d
    add     z19.s, z19.s, #10
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z4.d
    lsr     z16.s, z16.s, #4
    mov     z19.d, z11.d
    add     z19.s, z19.s, #11
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z4.d
    lsr     z16.s, z16.s, #12
    mov     z19.d, z11.d
    add     z19.s, z19.s, #12
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z4.d
    lsr     z16.s, z16.s, #20
    mov     z17.d, z5.d
    lsl     z17.s, z17.s, #1
    orr     z16.d, z16.d, z17.d
    mov     z19.d, z11.d
    add     z19.s, z19.s, #13
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z5.d
    lsr     z16.s, z16.s, #7
    mov     z19.d, z11.d
    add     z19.s, z19.s, #14
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z5.d
    lsr     z16.s, z16.s, #15
    mov     z17.d, z6.d
    lsl     z17.s, z17.s, #6
    orr     z16.d, z16.d, z17.d
    mov     z19.d, z11.d
    add     z19.s, z19.s, #15
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z6.d
    lsr     z16.s, z16.s, #2
    mov     z19.d, z11.d
    add     z19.s, z19.s, #16
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z6.d
    lsr     z16.s, z16.s, #10
    mov     z19.d, z11.d
    add     z19.s, z19.s, #17
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z6.d
    lsr     z16.s, z16.s, #18
    mov     z17.d, z7.d
    lsl     z17.s, z17.s, #3
    orr     z16.d, z16.d, z17.d
    mov     z19.d, z11.d
    add     z19.s, z19.s, #18
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z7.d
    lsr     z16.s, z16.s, #5
    mov     z19.d, z11.d
    add     z19.s, z19.s, #19
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    mov     z16.d, z7.d
    lsr     z16.s, z16.s, #13
    mov     z19.d, z11.d
    add     z19.s, z19.s, #20
    st1b    {z16.s}, p0, [x0, z19.s, uxtw]
    cntp    x4, p0, p0.s
    lsl     x5, x4, #5
    add     x1, x1, x5
    add     x5, x4, x4, lsl #2
    add     x0, x0, x4
    add     x0, x0, x5, lsl #2
    add     x3, x3, x4
    b       1b
2:
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_ToBytes1409Sve2)

// void NEV_FromBytes1409Sve2(int16_t *r, const uint8_t *a, uint64_t n)
CRYPT_AARCH64_FUNC_START(NEV_FromBytes1409Sve2)
AARCH64_PACIASP
    lsr     x2, x2, #4
    index   z10.s, #0, #1
    mov     w5, #21
    dup     z15.s, w5
    mul     z10.s, z10.s, z15.s
    index   z11.s, #0, #1
    mov     w5, #32
    dup     z15.s, w5
    mul     z11.s, z11.s, z15.s
    mov     w5, #1409
    dup     z13.s, w5
    movz    w5, #0x832e
    movk    w5, #0x2e, lsl #16
    dup     z14.s, w5
    mov     x3, #0
1:
    whilelo p0.s, x3, x2
    b.none  2f
    mov     z19.d, z10.d
    ld1b    {z0.s}, p0/z, [x1, z19.s, uxtw]
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #8
    orr     z0.d, z0.d, z18.d
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #16
    orr     z0.d, z0.d, z18.d
    and     z0.s, z0.s, #0x1fffff
    mov     z19.d, z10.d
    add     z19.s, z19.s, #2
    ld1b    {z1.s}, p0/z, [x1, z19.s, uxtw]
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #8
    orr     z1.d, z1.d, z18.d
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #16
    orr     z1.d, z1.d, z18.d
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #24
    orr     z1.d, z1.d, z18.d
    lsr     z1.s, z1.s, #5
    and     z1.s, z1.s, #0x1fffff
    mov     z19.d, z10.d
    add     z19.s, z19.s, #5
    ld1b    {z2.s}, p0/z, [x1, z19.s, uxtw]
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #8
    orr     z2.d, z2.d, z18.d
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #16
    orr     z2.d, z2.d, z18.d
    lsr     z2.s, z2.s, #2
    and     z2.s, z2.s, #0x1fffff
    mov     z19.d, z10.d
    add     z19.s, z19.s, #7
    ld1b    {z3.s}, p0/z, [x1, z19.s, uxtw]
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #8
    orr     z3.d, z3.d, z18.d
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #16
    orr     z3.d, z3.d, z18.d
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #24
    orr     z3.d, z3.d, z18.d
    lsr     z3.s, z3.s, #7
    and     z3.s, z3.s, #0x1fffff
    mov     z19.d, z10.d
    add     z19.s, z19.s, #10
    ld1b    {z4.s}, p0/z, [x1, z19.s, uxtw]
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #8
    orr     z4.d, z4.d, z18.d
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #16
    orr     z4.d, z4.d, z18.d
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #24
    orr     z4.d, z4.d, z18.d
    lsr     z4.s, z4.s, #4
    and     z4.s, z4.s, #0x1fffff
    mov     z19.d, z10.d
    add     z19.s, z19.s, #13
    ld1b    {z5.s}, p0/z, [x1, z19.s, uxtw]
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #8
    orr     z5.d, z5.d, z18.d
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #16
    orr     z5.d, z5.d, z18.d
    lsr     z5.s, z5.s, #1
    and     z5.s, z5.s, #0x1fffff
    mov     z19.d, z10.d
    add     z19.s, z19.s, #15
    ld1b    {z6.s}, p0/z, [x1, z19.s, uxtw]
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #8
    orr     z6.d, z6.d, z18.d
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #16
    orr     z6.d, z6.d, z18.d
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #24
    orr     z6.d, z6.d, z18.d
    lsr     z6.s, z6.s, #6
    and     z6.s, z6.s, #0x1fffff
    mov     z19.d, z10.d
    add     z19.s, z19.s, #18
    ld1b    {z7.s}, p0/z, [x1, z19.s, uxtw]
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #8
    orr     z7.d, z7.d, z18.d
    add     z19.s, z19.s, #1
    ld1b    {z18.s}, p0/z, [x1, z19.s, uxtw]
    lsl     z18.s, z18.s, #16
    orr     z7.d, z7.d, z18.d
    lsr     z7.s, z7.s, #3
    and     z7.s, z7.s, #0x1fffff
    umullb  z16.d, z0.s, z14.s
    umullt  z17.d, z0.s, z14.s
    trn2    z18.s, z16.s, z17.s
    mls     z0.s, p0/m, z18.s, z13.s
    mov     z19.d, z11.d
    st1h    {z0.s}, p0, [x0, z19.s, uxtw]
    add     z19.s, z19.s, #2
    st1h    {z18.s}, p0, [x0, z19.s, uxtw]
    umullb  z16.d, z1.s, z14.s
    umullt  z17.d, z1.s, z14.s
    trn2    z18.s, z16.s, z17.s
    mls     z1.s, p0/m, z18.s, z13.s
    mov     z19.d, z11.d
    add     z19.s, z19.s, #4
    st1h    {z1.s}, p0, [x0, z19.s, uxtw]
    add     z19.s, z19.s, #2
    st1h    {z18.s}, p0, [x0, z19.s, uxtw]
    umullb  z16.d, z2.s, z14.s
    umullt  z17.d, z2.s, z14.s
    trn2    z18.s, z16.s, z17.s
    mls     z2.s, p0/m, z18.s, z13.s
    mov     z19.d, z11.d
    add     z19.s, z19.s, #8
    st1h    {z2.s}, p0, [x0, z19.s, uxtw]
    add     z19.s, z19.s, #2
    st1h    {z18.s}, p0, [x0, z19.s, uxtw]
    umullb  z16.d, z3.s, z14.s
    umullt  z17.d, z3.s, z14.s
    trn2    z18.s, z16.s, z17.s
    mls     z3.s, p0/m, z18.s, z13.s
    mov     z19.d, z11.d
    add     z19.s, z19.s, #12
    st1h    {z3.s}, p0, [x0, z19.s, uxtw]
    add     z19.s, z19.s, #2
    st1h    {z18.s}, p0, [x0, z19.s, uxtw]
    umullb  z16.d, z4.s, z14.s
    umullt  z17.d, z4.s, z14.s
    trn2    z18.s, z16.s, z17.s
    mls     z4.s, p0/m, z18.s, z13.s
    mov     z19.d, z11.d
    add     z19.s, z19.s, #16
    st1h    {z4.s}, p0, [x0, z19.s, uxtw]
    add     z19.s, z19.s, #2
    st1h    {z18.s}, p0, [x0, z19.s, uxtw]
    umullb  z16.d, z5.s, z14.s
    umullt  z17.d, z5.s, z14.s
    trn2    z18.s, z16.s, z17.s
    mls     z5.s, p0/m, z18.s, z13.s
    mov     z19.d, z11.d
    add     z19.s, z19.s, #20
    st1h    {z5.s}, p0, [x0, z19.s, uxtw]
    add     z19.s, z19.s, #2
    st1h    {z18.s}, p0, [x0, z19.s, uxtw]
    umullb  z16.d, z6.s, z14.s
    umullt  z17.d, z6.s, z14.s
    trn2    z18.s, z16.s, z17.s
    mls     z6.s, p0/m, z18.s, z13.s
    mov     z19.d, z11.d
    add     z19.s, z19.s, #24
    st1h    {z6.s}, p0, [x0, z19.s, uxtw]
    add     z19.s, z19.s, #2
    st1h    {z18.s}, p0, [x0, z19.s, uxtw]
    umullb  z16.d, z7.s, z14.s
    umullt  z17.d, z7.s, z14.s
    trn2    z18.s, z16.s, z17.s
    mls     z7.s, p0/m, z18.s, z13.s
    mov     z19.d, z11.d
    add     z19.s, z19.s, #28
    st1h    {z7.s}, p0, [x0, z19.s, uxtw]
    add     z19.s, z19.s, #2
    st1h    {z18.s}, p0, [x0, z19.s, uxtw]
    cntp    x4, p0, p0.s
    add     x5, x4, x4, lsl #2
    add     x1, x1, x4
    add     x1, x1, x5, lsl #2
    lsl     x5, x4, #5
    add     x0, x0, x5
    add     x3, x3, x4
    b       1b
2:
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_FromBytes1409Sve2)
// void NEV_ToBytes3329Sve2(uint8_t *r, const int16_t *a, uint64_t n)
CRYPT_AARCH64_FUNC_START(NEV_ToBytes3329Sve2)
AARCH64_PACIASP
    lsr     x2, x2, #1                  // coefficient pairs
    mov     x3, #0
    index   z10.s, #0, #4               // input byte offsets: 2 int16
    index   z11.s, #2, #4
    index   z12.s, #0, #3               // output byte offsets
1:
    whilelo p0.s, x3, x2
    b.none  2f
    ld1h    {z0.s}, p0/z, [x1, z10.s, uxtw]
    ld1h    {z1.s}, p0/z, [x1, z11.s, uxtw]
    lsr     z2.s, z0.s, #8
    lsl     z3.s, z1.s, #4
    orr     z2.d, z2.d, z3.d
    lsr     z3.s, z1.s, #4
    st1b    {z0.s}, p0, [x0, z12.s, uxtw]
    mov     z13.d, z12.d
    add     z13.s, z13.s, #1
    st1b    {z2.s}, p0, [x0, z13.s, uxtw]
    mov     z13.d, z12.d
    add     z13.s, z13.s, #2
    st1b    {z3.s}, p0, [x0, z13.s, uxtw]
    cntp    x4, p0, p0.s
    lsl     x5, x4, #2
    add     x1, x1, x5
    add     x5, x4, x4, lsl #1
    add     x0, x0, x5
    add     x3, x3, x4
    b       1b
2:
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_ToBytes3329Sve2)

// void NEV_FromBytes3329Sve2(int16_t *r, const uint8_t *a, uint64_t n)
CRYPT_AARCH64_FUNC_START(NEV_FromBytes3329Sve2)
AARCH64_PACIASP
    lsr     x2, x2, #1
    mov     x3, #0
    mov     z8.s, #0x0f
    index   z10.s, #0, #3
    index   z11.s, #0, #4
1:
    whilelo p0.s, x3, x2
    b.none  2f
    ld1b    {z0.s}, p0/z, [x1, z10.s, uxtw]
    mov     z12.d, z10.d
    add     z12.s, z12.s, #1
    ld1b    {z1.s}, p0/z, [x1, z12.s, uxtw]
    mov     z12.d, z10.d
    add     z12.s, z12.s, #2
    ld1b    {z2.s}, p0/z, [x1, z12.s, uxtw]
    and     z3.d, z1.d, z8.d
    lsl     z3.s, z3.s, #8
    orr     z3.d, z0.d, z3.d
    lsr     z4.s, z1.s, #4
    lsl     z2.s, z2.s, #4
    orr     z4.d, z4.d, z2.d
    st1h    {z3.s}, p0, [x0, z11.s, uxtw]
    mov     z12.d, z11.d
    add     z12.s, z12.s, #2
    st1h    {z4.s}, p0, [x0, z12.s, uxtw]
    cntp    x4, p0, p0.s
    lsl     x5, x4, #2
    add     x0, x0, x5
    add     x5, x4, x4, lsl #1
    add     x1, x1, x5
    add     x3, x3, x4
    b       1b
2:
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_FromBytes3329Sve2)

// void NEV_CompressSve2(uint8_t *c, const int16_t *a, uint64_t n)
CRYPT_AARCH64_FUNC_START(NEV_CompressSve2)
AARCH64_PACIASP
    mov     w4, #341
    dup     z8.h, w4
    mov     w4, #469
    dup     z9.s, w4
    mov     x3, #0
    whilelt p0.h, x3, x2
1:
    ld1h    {z0.h}, p0/z, [x1, x3, lsl #1]
    smullb  z1.s, z0.h, z8.h
    smullt  z2.s, z0.h, z8.h
    add     z1.s, z1.s, z9.s
    add     z2.s, z2.s, z9.s
    lsr     z1.s, z1.s, #10
    lsr     z2.s, z2.s, #10
    trn1    z3.h, z1.h, z2.h
    st1b    {z3.h}, p0, [x0, x3]
    inch    x3
    whilelt p0.h, x3, x2
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_CompressSve2)

// void NEV_MontCompress769Sve2(uint8_t *c, const int16_t *a, uint64_t n)
//
// Compose Caddq(MontReduce(a[i])) with the q=769 8-bit compressor while the
// coefficient is resident in a z register.  This removes the intermediate
// halfword store and the following compressor reload over the whole poly.
CRYPT_AARCH64_FUNC_START(NEV_MontCompress769Sve2)
AARCH64_PACIASP
    ptrue   p0.h
    mov     w4, #769
    dup     z31.h, w4                   // q
    mov     w4, #64769
    dup     z30.h, w4                   // qinv
    mov     w4, #341
    dup     z29.h, w4                   // compression multiplier
    mov     w4, #469
    dup     z28.s, w4                   // compression rounding bias
1:
    ld1h    {z0.h}, p0/z, [x1]
    ld1h    {z1.h}, p0/z, [x1, #1, mul vl]
    add     x1, x1, #64

    // Exact Montgomery reduction of two 16-lane vectors.
    mul     z4.h, z0.h, z30.h
    mul     z5.h, z1.h, z30.h
    sshllb  z16.s, z0.h, #0
    sshllt  z17.s, z0.h, #0
    sshllb  z18.s, z1.h, #0
    sshllt  z19.s, z1.h, #0
    smlslb  z16.s, z4.h, z31.h
    smlslt  z17.s, z4.h, z31.h
    smlslb  z18.s, z5.h, z31.h
    smlslt  z19.s, z5.h, z31.h
    shrnb   z0.h, z16.s, #16
    shrnt   z0.h, z17.s, #16
    shrnb   z1.h, z18.s, #16
    shrnt   z1.h, z19.s, #16

    // Conditional add q, then ((x * 341 + 469) >> 10) & 0xff.
    asr     z4.h, z0.h, #15
    asr     z5.h, z1.h, #15
    and     z4.d, z4.d, z31.d
    and     z5.d, z5.d, z31.d
    add     z0.h, z0.h, z4.h
    add     z1.h, z1.h, z5.h
    smullb  z16.s, z0.h, z29.h
    smullt  z17.s, z0.h, z29.h
    smullb  z18.s, z1.h, z29.h
    smullt  z19.s, z1.h, z29.h
    add     z16.s, z16.s, z28.s
    add     z17.s, z17.s, z28.s
    add     z18.s, z18.s, z28.s
    add     z19.s, z19.s, z28.s
    lsr     z16.s, z16.s, #10
    lsr     z17.s, z17.s, #10
    lsr     z18.s, z18.s, #10
    lsr     z19.s, z19.s, #10
    trn1    z2.h, z16.h, z17.h
    trn1    z3.h, z18.h, z19.h
    st1b    {z2.h}, p0, [x0]
    add     x5, x0, #16
    st1b    {z3.h}, p0, [x5]
    add     x0, x0, #32
    subs    x2, x2, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MontCompress769Sve2)

// void NEV_DecompressSve2(int16_t *r, const uint8_t *c, uint64_t n,
//                         uint64_t q)
CRYPT_AARCH64_FUNC_START(NEV_DecompressSve2)
AARCH64_PACIASP
    dup     z8.h, w3
    mov     z9.s, #128
    mov     x4, #0
    whilelt p0.h, x4, x2
1:
    ld1b    {z0.h}, p0/z, [x1, x4]
    umullb  z1.s, z0.h, z8.h
    umullt  z2.s, z0.h, z8.h
    add     z1.s, z1.s, z9.s
    add     z2.s, z2.s, z9.s
    lsr     z1.s, z1.s, #8
    lsr     z2.s, z2.s, #8
    trn1    z3.h, z1.h, z2.h
    st1h    {z3.h}, p0, [x0, x4, lsl #1]
    inch    x4
    whilelt p0.h, x4, x2
    b.first 1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_DecompressSve2)

#endif

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
