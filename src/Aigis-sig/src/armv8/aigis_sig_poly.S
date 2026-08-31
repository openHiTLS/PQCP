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
    .arch armv8-a
    .text
    .balign 16

/*
 * Reduce 512 signed 32-bit coefficients with
 *   a - floor(a * 2159079753 / 2^53) * Q.
 * SMULL plus SSHR implements the C floor division for the full int32_t
 * input domain. The quotient is in [-516, 515], so MLS cannot overflow.
 */
    .global PQCP_AIGIS_SIG_PolyGReduce
    .hidden PQCP_AIGIS_SIG_PolyGReduce
    .type PQCP_AIGIS_SIG_PolyGReduce, %function
PQCP_AIGIS_SIG_PolyGReduce:
    mov     w2, #0xf149
    movk    w2, #0xb0, lsl #16
    dup     v4.4s, w2
    mov     w2, #0xa801
    movk    w2, #0x3f, lsl #16
    dup     v5.4s, w2
    mov     x1, #0
.Lpoly_greduce:
    ldr     q0, [x0, x1]
    smull   v1.2d, v0.2s, v4.2s
    smull2  v2.2d, v0.4s, v4.4s
    sxtl    v3.2d, v0.2s
    sxtl2   v6.2d, v0.4s
    shl     v3.2d, v3.2d, #31
    shl     v6.2d, v6.2d, #31
    add     v1.2d, v1.2d, v3.2d
    add     v2.2d, v2.2d, v6.2d
    sshr    v1.2d, v1.2d, #53
    sshr    v2.2d, v2.2d, #53
    xtn     v1.2s, v1.2d
    xtn2    v1.4s, v2.2d
    mls     v0.4s, v1.4s, v5.4s
    str     q0, [x0, x1]
    add     x1, x1, #16
    cmp     x1, #2048
    b.lo    .Lpoly_greduce
    ret
    .size PQCP_AIGIS_SIG_PolyGReduce, .-PQCP_AIGIS_SIG_PolyGReduce

/* Add 512 signed 32-bit coefficients. Input/output aliasing is supported. */
    .global PQCP_AIGIS_SIG_PolyAdd
    .hidden PQCP_AIGIS_SIG_PolyAdd
    .type PQCP_AIGIS_SIG_PolyAdd, %function
PQCP_AIGIS_SIG_PolyAdd:
    mov     x3, #0
.Lpoly_add:
    ldr     q0, [x1, x3]
    ldr     q1, [x2, x3]
    add     v0.4s, v0.4s, v1.4s
    str     q0, [x0, x3]
    add     x3, x3, #16
    cmp     x3, #2048
    b.lo    .Lpoly_add
    ret
    .size PQCP_AIGIS_SIG_PolyAdd, .-PQCP_AIGIS_SIG_PolyAdd

/* Subtract 512 signed 32-bit coefficients. Input/output aliasing is supported. */
    .global PQCP_AIGIS_SIG_PolySub
    .hidden PQCP_AIGIS_SIG_PolySub
    .type PQCP_AIGIS_SIG_PolySub, %function
PQCP_AIGIS_SIG_PolySub:
    mov     x3, #0
.Lpoly_sub:
    ldr     q0, [x1, x3]
    ldr     q1, [x2, x3]
    sub     v0.4s, v0.4s, v1.4s
    str     q0, [x0, x3]
    add     x3, x3, #16
    cmp     x3, #2048
    b.lo    .Lpoly_sub
    ret
    .size PQCP_AIGIS_SIG_PolySub, .-PQCP_AIGIS_SIG_PolySub

/* Fixed-L pointwise accumulation with inlined Montgomery and general reduction. */
.macro POINTWISE_ACC_BODY count
    mov     w10, #0xa801
    movk    w10, #0x3f, lsl #16
    mov     w11, #0x5801
    movk    w11, #0x1e00, lsl #16
    mov     w12, #0xf149
    movk    w12, #0x80b0, lsl #16
    add     x4, x1, #2048
    add     x5, x2, #2048
.if \count == 4
    add     x6, x4, #2048
    add     x7, x5, #2048
    add     x8, x6, #2048
    add     x9, x7, #2048
.endif
.if \count == 7
    add     x6, x4, #2048
    add     x7, x5, #2048
    add     x8, x6, #2048
    add     x9, x7, #2048
    add     x10, x8, #2048
    add     x11, x9, #2048
    add     x12, x10, #2048
    add     x13, x11, #2048
    add     x16, x12, #2048
    add     x17, x13, #2048
.endif
    mov     x3, #0
.Lpointwise_acc_\count:
    ldr     w13, [x1, x3]
    ldr     w14, [x2, x3]
    smull   x15, w13, w14
.if \count == 2
    ldr     w13, [x4, x3]
    ldr     w14, [x5, x3]
    smaddl  x15, w13, w14, x15
.else
    ldr     w13, [x4, x3]
    ldr     w14, [x5, x3]
    smaddl  x15, w13, w14, x15
    ldr     w13, [x6, x3]
    ldr     w14, [x7, x3]
    smaddl  x15, w13, w14, x15
    ldr     w13, [x8, x3]
    ldr     w14, [x9, x3]
    smaddl  x15, w13, w14, x15
.endif
    mul     w16, w15, w11
    sxtw    x16, w16
    mul     x16, x16, x10
    sub     x15, x15, x16
    asr     x15, x15, #32
    mul     x16, x15, x12
    asr     x16, x16, #53
    mul     x16, x16, x10
    sub     x15, x15, x16
    str     w15, [x0, x3]
    add     x3, x3, #4
    cmp     x3, #2048
    b.lo    .Lpointwise_acc_\count
.endm

    .global PQCP_AIGIS_SIG_PolyVecLPointwiseAccL2
    .hidden PQCP_AIGIS_SIG_PolyVecLPointwiseAccL2
    .type PQCP_AIGIS_SIG_PolyVecLPointwiseAccL2, %function
PQCP_AIGIS_SIG_PolyVecLPointwiseAccL2:
    POINTWISE_ACC_BODY 2
    ret
    .size PQCP_AIGIS_SIG_PolyVecLPointwiseAccL2, .-PQCP_AIGIS_SIG_PolyVecLPointwiseAccL2

    .global PQCP_AIGIS_SIG_PolyVecLPointwiseAccL4
    .hidden PQCP_AIGIS_SIG_PolyVecLPointwiseAccL4
    .type PQCP_AIGIS_SIG_PolyVecLPointwiseAccL4, %function
PQCP_AIGIS_SIG_PolyVecLPointwiseAccL4:
    POINTWISE_ACC_BODY 4
    ret
    .size PQCP_AIGIS_SIG_PolyVecLPointwiseAccL4, .-PQCP_AIGIS_SIG_PolyVecLPointwiseAccL4

/* Process 16 coefficients per pass while retaining all 64-bit sums. */
.macro ACCUMULATE_16 base_a, base_b, first
    add     x14, \base_a, x3
    add     x15, \base_b, x3
    ldp     q0, q2, [x14]
    ldp     q1, q3, [x15]
    ldp     q4, q6, [x14, #32]
    ldp     q5, q7, [x15, #32]
.if \first
    smull   v16.2d, v0.2s, v1.2s
    smull2  v17.2d, v0.4s, v1.4s
    smull   v18.2d, v2.2s, v3.2s
    smull2  v19.2d, v2.4s, v3.4s
    smull   v20.2d, v4.2s, v5.2s
    smull2  v21.2d, v4.4s, v5.4s
    smull   v22.2d, v6.2s, v7.2s
    smull2  v23.2d, v6.4s, v7.4s
.else
    smlal   v16.2d, v0.2s, v1.2s
    smlal2  v17.2d, v0.4s, v1.4s
    smlal   v18.2d, v2.2s, v3.2s
    smlal2  v19.2d, v2.4s, v3.4s
    smlal   v20.2d, v4.2s, v5.2s
    smlal2  v21.2d, v4.4s, v5.4s
    smlal   v22.2d, v6.2s, v7.2s
    smlal2  v23.2d, v6.4s, v7.4s
.endif
.endm

.macro MONT_CENTER_4 acc_lo, acc_hi, out
    uzp1    v24.4s, \acc_lo\().4s, \acc_hi\().4s
    mul     v24.4s, v24.4s, v28.4s
    smull   v25.2d, v24.2s, v29.2s
    smull2  v26.2d, v24.4s, v29.4s
    sub     \acc_lo\().2d, \acc_lo\().2d, v25.2d
    sub     \acc_hi\().2d, \acc_hi\().2d, v26.2d
    uzp2    \out\().4s, \acc_lo\().4s, \acc_hi\().4s
    sqdmulh v27.4s, \out\().4s, v30.4s
    srshr   v27.4s, v27.4s, #21
    mls     \out\().4s, v27.4s, v29.4s
.endm

.macro POINTWISE_ACC_VECTOR_BODY count
    mov     w10, #0xa801
    movk    w10, #0x3f, lsl #16
    mov     w11, #0x5801
    movk    w11, #0x1e00, lsl #16
    dup     v29.4s, w10
    dup     v28.4s, w11
    mov     w12, #0x78a5
    movk    w12, #0x4058, lsl #16
    dup     v30.4s, w12
    add     x4, x1, #2048
    add     x5, x2, #2048
.if \count == 4
    add     x6, x4, #2048
    add     x7, x5, #2048
    add     x8, x6, #2048
    add     x9, x7, #2048
.endif
.if \count == 7
    add     x6, x4, #2048
    add     x7, x5, #2048
    add     x8, x6, #2048
    add     x9, x7, #2048
    add     x10, x8, #2048
    add     x11, x9, #2048
    add     x12, x10, #2048
    add     x13, x11, #2048
    add     x16, x12, #2048
    add     x17, x13, #2048
.endif
    mov     x3, #0
.Lpointwise_vec_\count:
    ACCUMULATE_16 x1, x2, 1
.if \count == 2
    ACCUMULATE_16 x4, x5, 0
.else
    ACCUMULATE_16 x4, x5, 0
    ACCUMULATE_16 x6, x7, 0
    ACCUMULATE_16 x8, x9, 0
.if \count == 7
    ACCUMULATE_16 x10, x11, 0
    ACCUMULATE_16 x12, x13, 0
    ACCUMULATE_16 x16, x17, 0
.endif
.endif
    MONT_CENTER_4 v16, v17, v0
    MONT_CENTER_4 v18, v19, v1
    MONT_CENTER_4 v20, v21, v2
    MONT_CENTER_4 v22, v23, v3
    add     x14, x0, x3
    stp     q0, q1, [x14]
    stp     q2, q3, [x14, #32]
    add     x3, x3, #64
    cmp     x3, #2048
    b.lo    .Lpointwise_vec_\count
.endm

    .global PQCP_AIGIS_SIG_PolyVecLPointwiseAccL2Vec
    .hidden PQCP_AIGIS_SIG_PolyVecLPointwiseAccL2Vec
    .type PQCP_AIGIS_SIG_PolyVecLPointwiseAccL2Vec, %function
PQCP_AIGIS_SIG_PolyVecLPointwiseAccL2Vec:
    POINTWISE_ACC_VECTOR_BODY 2
    ret
    .size PQCP_AIGIS_SIG_PolyVecLPointwiseAccL2Vec, .-PQCP_AIGIS_SIG_PolyVecLPointwiseAccL2Vec

    .global PQCP_AIGIS_SIG_PolyVecLPointwiseAccL4Vec
    .hidden PQCP_AIGIS_SIG_PolyVecLPointwiseAccL4Vec
    .type PQCP_AIGIS_SIG_PolyVecLPointwiseAccL4Vec, %function
PQCP_AIGIS_SIG_PolyVecLPointwiseAccL4Vec:
    POINTWISE_ACC_VECTOR_BODY 4
    ret
    .size PQCP_AIGIS_SIG_PolyVecLPointwiseAccL4Vec, .-PQCP_AIGIS_SIG_PolyVecLPointwiseAccL4Vec

    .global PQCP_AIGIS_SIG_PolyVecLPointwiseAccL7Vec
    .hidden PQCP_AIGIS_SIG_PolyVecLPointwiseAccL7Vec
    .type PQCP_AIGIS_SIG_PolyVecLPointwiseAccL7Vec, %function
PQCP_AIGIS_SIG_PolyVecLPointwiseAccL7Vec:
    POINTWISE_ACC_VECTOR_BODY 7
    ret
    .size PQCP_AIGIS_SIG_PolyVecLPointwiseAccL7Vec, .-PQCP_AIGIS_SIG_PolyVecLPointwiseAccL7Vec


/*
 * Aigis power-of-two rounding with PARAM_D == 15:
 *   high = trunc((a + 2^14 - 1) / 2^15), low = a - high * 2^15.
 * The correction converts arithmetic-shift floor division to C truncation
 * for negative adjusted values. Four lanes are processed per iteration.
 */
    .global PQCP_AIGIS_SIG_PolyPower2Round
    .hidden PQCP_AIGIS_SIG_PolyPower2Round
    .type PQCP_AIGIS_SIG_PolyPower2Round, %function
PQCP_AIGIS_SIG_PolyPower2Round:
    mov     x4, #16383
    dup     v4.2d, x4
    mov     x4, #1
    dup     v5.2d, x4
    mov     x4, #32767
    dup     v17.2d, x4
    mov     x3, #0
.Lpoly_power2round:
    ldr     q0, [x2, x3]
    sxtl    v1.2d, v0.2s
    sxtl2   v2.2d, v0.4s
    add     v1.2d, v1.2d, v4.2d
    add     v2.2d, v2.2d, v4.2d
    sshr    v3.2d, v1.2d, #63
    sshr    v6.2d, v2.2d, #63
    cmtst   v7.2d, v1.2d, v17.2d
    cmtst   v16.2d, v2.2d, v17.2d
    and     v3.16b, v3.16b, v5.16b
    and     v6.16b, v6.16b, v5.16b
    and     v3.16b, v3.16b, v7.16b
    and     v6.16b, v6.16b, v16.16b
    sshr    v1.2d, v1.2d, #15
    sshr    v2.2d, v2.2d, #15
    add     v1.2d, v1.2d, v3.2d
    add     v2.2d, v2.2d, v6.2d
    xtn     v7.2s, v1.2d
    xtn2    v7.4s, v2.2d
    shl     v6.4s, v7.4s, #15
    sub     v6.4s, v0.4s, v6.4s
    str     q7, [x0, x3]
    str     q6, [x1, x3]
    add     x3, x3, #16
    cmp     x3, #2048
    b.lo    .Lpoly_power2round
    ret
    .size PQCP_AIGIS_SIG_PolyPower2Round, .-PQCP_AIGIS_SIG_PolyPower2Round

/* Key-generation-only whole-VecK fusion.  The caller proves each left+right
 * coefficient is in (-Q,Q), so adding Q exactly to negative lanes yields the
 * canonical [0,Q) representative before PARAM_D=15 Power2Round. */
    .global PQCP_AIGIS_SIG_PolyVecKAddPower2RoundArmv8
    .hidden PQCP_AIGIS_SIG_PolyVecKAddPower2RoundArmv8
    .type PQCP_AIGIS_SIG_PolyVecKAddPower2RoundArmv8, %function
PQCP_AIGIS_SIG_PolyVecKAddPower2RoundArmv8:
    mov     w5, #0xa801
    movk    w5, #0x3f, lsl #16
    dup     v16.4s, w5
    mov     w5, #16383
    dup     v17.4s, w5
    lsl     w4, w4, #11
    add     x5, x2, x4
.Lpolyveck_add_power2round:
    ldr     q0, [x2], #16
    ldr     q1, [x3], #16
    add     v0.4s, v0.4s, v1.4s
    sshr    v2.4s, v0.4s, #31
    and     v2.16b, v2.16b, v16.16b
    add     v0.4s, v0.4s, v2.4s
    add     v1.4s, v0.4s, v17.4s
    ushr    v1.4s, v1.4s, #15
    shl     v2.4s, v1.4s, #15
    sub     v2.4s, v0.4s, v2.4s
    str     q1, [x0], #16
    str     q2, [x1], #16
    cmp     x2, x5
    b.lo    .Lpolyveck_add_power2round
    ret
    .size PQCP_AIGIS_SIG_PolyVecKAddPower2RoundArmv8, .-PQCP_AIGIS_SIG_PolyVecKAddPower2RoundArmv8

/* Parameter-III key-generation fusion.  Keep it separate from the d=15
 * primitive so the parameter-I/II instruction path remains unchanged. */
    .global PQCP_AIGIS_SIG_PolyVecKAddPower2RoundD13Armv8
    .hidden PQCP_AIGIS_SIG_PolyVecKAddPower2RoundD13Armv8
    .type PQCP_AIGIS_SIG_PolyVecKAddPower2RoundD13Armv8, %function
PQCP_AIGIS_SIG_PolyVecKAddPower2RoundD13Armv8:
    mov     w5, #0xa801
    movk    w5, #0x3f, lsl #16
    dup     v16.4s, w5
    mov     w5, #4095
    dup     v17.4s, w5
    lsl     w4, w4, #11
    add     x5, x2, x4
.Lpolyveck_add_power2round_d13:
    ldr     q0, [x2], #16
    ldr     q1, [x3], #16
    add     v0.4s, v0.4s, v1.4s
    sshr    v2.4s, v0.4s, #31
    and     v2.16b, v2.16b, v16.16b
    add     v0.4s, v0.4s, v2.4s
    add     v1.4s, v0.4s, v17.4s
    ushr    v1.4s, v1.4s, #13
    shl     v2.4s, v1.4s, #13
    sub     v2.4s, v0.4s, v2.4s
    str     q1, [x0], #16
    str     q2, [x1], #16
    cmp     x2, x5
    b.lo    .Lpolyveck_add_power2round_d13
    ret
    .size PQCP_AIGIS_SIG_PolyVecKAddPower2RoundD13Armv8, .-PQCP_AIGIS_SIG_PolyVecKAddPower2RoundD13Armv8

/* Parameter-III decomposition: alpha=1042944, maxHigh=3. */
    .global PQCP_AIGIS_SIG_PolyVecKDecomposeD13Armv8
    .hidden PQCP_AIGIS_SIG_PolyVecKDecomposeD13Armv8
    .type PQCP_AIGIS_SIG_PolyVecKDecomposeD13Armv8, %function
PQCP_AIGIS_SIG_PolyVecKDecomposeD13Armv8:
    mov     w4, #127
    dup     v16.4s, w4
    mov     w4, #2059
    dup     v17.4s, w4
    movz    w4, #0x80, lsl #16
    dup     v18.4s, w4
    mov     w4, #4
    dup     v19.4s, w4
    mov     w4, #0xea00
    movk    w4, #0x000f, lsl #16
    dup     v20.4s, w4
    mov     w4, #0xd400
    movk    w4, #0x001f, lsl #16
    dup     v21.4s, w4
    mov     w4, #0xa801
    movk    w4, #0x003f, lsl #16
    dup     v22.4s, w4
    lsl     w3, w3, #11
    add     x4, x2, x3
.Lpolyveck_decompose_d13:
    ldr     q0, [x2], #16
    add     v1.4s, v0.4s, v16.4s
    sshr    v1.4s, v1.4s, #7
    mul     v1.4s, v1.4s, v17.4s
    add     v1.4s, v1.4s, v18.4s
    sshr    v1.4s, v1.4s, #24
    cmgt    v2.4s, v19.4s, v1.4s
    and     v1.16b, v1.16b, v2.16b
    mov     v2.16b, v0.16b
    mls     v2.4s, v1.4s, v20.4s
    cmgt    v3.4s, v2.4s, v21.4s
    and     v3.16b, v3.16b, v22.16b
    sub     v2.4s, v2.4s, v3.4s
    str     q1, [x0], #16
    str     q2, [x1], #16
    cmp     x2, x4
    b.lo    .Lpolyveck_decompose_d13
    ret
    .size PQCP_AIGIS_SIG_PolyVecKDecomposeD13Armv8, .-PQCP_AIGIS_SIG_PolyVecKDecomposeD13Armv8

/* Parameter-III hint generation.  Each public 64-coefficient section is
 * reduced independently so the NHW=15 early-failure contract is preserved. */
    .global PQCP_AIGIS_SIG_PolyVecKMakeHintD13Armv8
    .hidden PQCP_AIGIS_SIG_PolyVecKMakeHintD13Armv8
    .type PQCP_AIGIS_SIG_PolyVecKMakeHintD13Armv8, %function
PQCP_AIGIS_SIG_PolyVecKMakeHintD13Armv8:
    mov     w4, #0xf500
    movk    w4, #0x0007, lsl #16
    dup     v16.4s, w4
    mov     w4, #0xb301
    movk    w4, #0x0037, lsl #16
    dup     v17.4s, w4
    movi    v18.4s, #1
    lsl     w3, w3, #3
    mov     w4, #0
.Lpolyveck_make_hint_d13_section:
    movi    v20.4s, #0
    mov     w5, #16
.Lpolyveck_make_hint_d13_vector:
    ldr     q0, [x1], #16
    ldr     q1, [x2], #16
    cmgt    v2.4s, v0.4s, v16.4s
    cmgt    v3.4s, v17.4s, v0.4s
    cmeq    v4.4s, v0.4s, v17.4s
    cmeq    v5.4s, v1.4s, #0
    bic     v4.16b, v4.16b, v5.16b
    orr     v3.16b, v3.16b, v4.16b
    and     v2.16b, v2.16b, v3.16b
    and     v2.16b, v2.16b, v18.16b
    str     q2, [x0], #16
    add     v20.4s, v20.4s, v2.4s
    subs    w5, w5, #1
    b.ne    .Lpolyveck_make_hint_d13_vector
    addv    s21, v20.4s
    fmov    w5, s21
    cmp     w5, #15
    b.hi    .Lpolyveck_make_hint_d13_fail
    add     w4, w4, w5
    subs    w3, w3, #1
    b.ne    .Lpolyveck_make_hint_d13_section
    mov     w0, w4
    ret
.Lpolyveck_make_hint_d13_fail:
    mov     w0, #-1
    ret
    .size PQCP_AIGIS_SIG_PolyVecKMakeHintD13Armv8, .-PQCP_AIGIS_SIG_PolyVecKMakeHintD13Armv8

/* Parameter-III fused Decompose+UseHint for verify. */
    .global PQCP_AIGIS_SIG_PolyVecKDecomposeUseHintD13Armv8
    .hidden PQCP_AIGIS_SIG_PolyVecKDecomposeUseHintD13Armv8
    .type PQCP_AIGIS_SIG_PolyVecKDecomposeUseHintD13Armv8, %function
PQCP_AIGIS_SIG_PolyVecKDecomposeUseHintD13Armv8:
    mov     w4, #127
    dup     v16.4s, w4
    mov     w4, #2059
    dup     v17.4s, w4
    movz    w4, #0x80, lsl #16
    dup     v18.4s, w4
    mov     w4, #4
    dup     v19.4s, w4
    mov     w4, #0xea00
    movk    w4, #0x000f, lsl #16
    dup     v20.4s, w4
    mov     w4, #0xd400
    movk    w4, #0x001f, lsl #16
    dup     v21.4s, w4
    mov     w4, #0xa801
    movk    w4, #0x003f, lsl #16
    dup     v22.4s, w4
    movi    v23.4s, #0
    movi    v24.4s, #1
    movi    v25.4s, #3
    lsl     w3, w3, #11
    add     x4, x1, x3
.Lpolyveck_decompose_use_hint_d13:
    ldr     q0, [x1], #16
    ldr     q6, [x2], #16
    add     v1.4s, v0.4s, v16.4s
    sshr    v1.4s, v1.4s, #7
    mul     v1.4s, v1.4s, v17.4s
    add     v1.4s, v1.4s, v18.4s
    sshr    v1.4s, v1.4s, #24
    cmgt    v2.4s, v19.4s, v1.4s
    and     v1.16b, v1.16b, v2.16b
    mov     v2.16b, v0.16b
    mls     v2.4s, v1.4s, v20.4s
    cmgt    v3.4s, v2.4s, v21.4s
    and     v3.16b, v3.16b, v22.16b
    sub     v2.4s, v2.4s, v3.4s

    cmgt    v3.4s, v2.4s, v23.4s
    cmeq    v4.4s, v1.4s, v25.4s
    cmeq    v5.4s, v1.4s, v23.4s
    add     v7.4s, v1.4s, v24.4s
    bic     v7.16b, v7.16b, v4.16b
    sub     v26.4s, v1.4s, v24.4s
    bsl     v5.16b, v25.16b, v26.16b
    bsl     v3.16b, v7.16b, v5.16b
    cmtst   v4.4s, v6.4s, v6.4s
    bsl     v4.16b, v3.16b, v1.16b
    str     q4, [x0], #16
    cmp     x1, x4
    b.lo    .Lpolyveck_decompose_use_hint_d13
    ret
    .size PQCP_AIGIS_SIG_PolyVecKDecomposeUseHintD13Armv8, .-PQCP_AIGIS_SIG_PolyVecKDecomposeUseHintD13Armv8

/* Apply 512 decomposition hints without secret-dependent branches. */
    .global PQCP_AIGIS_SIG_PolyUseHint
    .hidden PQCP_AIGIS_SIG_PolyUseHint
    .type PQCP_AIGIS_SIG_PolyUseHint, %function
PQCP_AIGIS_SIG_PolyUseHint:
    dup     v17.4s, w4
    movi    v18.4s, #0
    movi    v16.4s, #1
    mov     x4, #0
.Lpoly_use_hint:
    ldr     q0, [x1, x4]
    ldr     q1, [x2, x4]
    ldr     q2, [x3, x4]
    cmgt    v3.4s, v1.4s, v18.4s
    cmeq    v4.4s, v0.4s, v17.4s
    cmeq    v5.4s, v0.4s, v18.4s
    add     v6.4s, v0.4s, v18.4s
    add     v6.4s, v6.4s, v16.4s
    bic     v6.16b, v6.16b, v4.16b
    sub     v7.4s, v0.4s, v16.4s
    bsl     v5.16b, v17.16b, v7.16b
    bsl     v3.16b, v6.16b, v5.16b
    cmtst   v4.4s, v2.4s, v2.4s
    bsl     v4.16b, v3.16b, v0.16b
    str     q4, [x0, x4]
    add     x4, x4, #16
    cmp     x4, #2048
    b.lo    .Lpoly_use_hint
    ret
    .size PQCP_AIGIS_SIG_PolyUseHint, .-PQCP_AIGIS_SIG_PolyUseHint

/* Add Q to negative coefficients; positive coefficients are unchanged. */
    .global PQCP_AIGIS_SIG_PolyAModQ
    .hidden PQCP_AIGIS_SIG_PolyAModQ
    .type PQCP_AIGIS_SIG_PolyAModQ, %function
PQCP_AIGIS_SIG_PolyAModQ:
    mov     w2, #0xa801
    movk    w2, #0x3f, lsl #16
    dup     v2.4s, w2
    mov     x1, #0
.Lpoly_amodq:
    ldr     q0, [x0, x1]
    sshr    v1.4s, v0.4s, #31
    and     v1.16b, v1.16b, v2.16b
    add     v0.4s, v0.4s, v1.4s
    str     q0, [x0, x1]
    add     x1, x1, #16
    cmp     x1, #2048
    b.lo    .Lpoly_amodq
    ret
    .size PQCP_AIGIS_SIG_PolyAModQ, .-PQCP_AIGIS_SIG_PolyAModQ

/* Center coefficients around zero; exact for the full int32_t domain. */
    .global PQCP_AIGIS_SIG_PolyCModQ
    .hidden PQCP_AIGIS_SIG_PolyCModQ
    .type PQCP_AIGIS_SIG_PolyCModQ, %function
PQCP_AIGIS_SIG_PolyCModQ:
    mov     w2, #0xa801
    movk    w2, #0x3f, lsl #16
    dup     v4.4s, w2
    mov     w2, #0xd400
    movk    w2, #0x1f, lsl #16
    dup     v5.4s, w2
    mov     x1, #0
.Lpoly_cmodq:
    ldr     q0, [x0, x1]
    sshr    v1.4s, v0.4s, #31
    and     v1.16b, v1.16b, v4.16b
    add     v0.4s, v0.4s, v1.4s
    sub     v1.4s, v5.4s, v0.4s
    sshr    v1.4s, v1.4s, #31
    and     v1.16b, v1.16b, v4.16b
    sub     v0.4s, v0.4s, v1.4s
    str     q0, [x0, x1]
    add     x1, x1, #16
    cmp     x1, #2048
    b.lo    .Lpoly_cmodq
    ret
    .size PQCP_AIGIS_SIG_PolyCModQ, .-PQCP_AIGIS_SIG_PolyCModQ

/*
 * Check value <= bound and value >= 1 - bound without secret-dependent
 * control flow. Signed widening keeps the full int32_t/uint32_t contract.
 */
    .global PQCP_AIGIS_SIG_PolyCheckNorm
    .hidden PQCP_AIGIS_SIG_PolyCheckNorm
    .type PQCP_AIGIS_SIG_PolyCheckNorm, %function
PQCP_AIGIS_SIG_PolyCheckNorm:
    tbnz    w1, #31, .Lpoly_check_norm_large_bound
    dup     v4.4s, w1
    mov     w2, #1
    sub     w2, w2, w1
    dup     v5.4s, w2
    movi    v6.4s, #0
    mov     x1, #0
.Lpoly_check_norm_small_loop:
    ldr     q0, [x0, x1]
    cmgt    v1.4s, v0.4s, v4.4s
    cmgt    v2.4s, v5.4s, v0.4s
    orr     v6.16b, v6.16b, v1.16b
    orr     v6.16b, v6.16b, v2.16b
    add     x1, x1, #16
    cmp     x1, #2048
    b.lo    .Lpoly_check_norm_small_loop
.Lpoly_check_norm_reduce:
    ext     v1.16b, v6.16b, v6.16b, #8
    orr     v6.16b, v6.16b, v1.16b
    ext     v1.16b, v6.16b, v6.16b, #4
    orr     v6.16b, v6.16b, v1.16b
    umov    w0, v6.s[0]
    and     w0, w0, #1
    ret

.Lpoly_check_norm_large_bound:
    mov     w2, #0x80000000
    cmp     w1, w2
    b.ne    .Lpoly_check_norm_return_zero
    dup     v4.4s, w2
    movi    v6.4s, #0
    mov     x1, #0
.Lpoly_check_norm_large_loop:
    ldr     q0, [x0, x1]
    cmeq    v1.4s, v0.4s, v4.4s
    orr     v6.16b, v6.16b, v1.16b
    add     x1, x1, #16
    cmp     x1, #2048
    b.lo    .Lpoly_check_norm_large_loop
    b       .Lpoly_check_norm_reduce
.Lpoly_check_norm_return_zero:
    mov     w0, #0
    ret
    .size PQCP_AIGIS_SIG_PolyCheckNorm, .-PQCP_AIGIS_SIG_PolyCheckNorm

    .p2align 4
    .global PQCP_AIGIS_SIG_PolyDecompose
    .hidden PQCP_AIGIS_SIG_PolyDecompose
    .type PQCP_AIGIS_SIG_PolyDecompose, %function
PQCP_AIGIS_SIG_PolyDecompose:
    mov     w3, #127
    dup     v16.4s, w3
    mov     w3, #6177
    dup     v17.4s, w3
    mov     w3, #0
    movk    w3, #0x100, lsl #16
    dup     v18.4s, w3
    mov     w3, #5
    dup     v19.4s, w3
    mov     w3, #0x9c00
    movk    w3, #0xa, lsl #16
    dup     v20.4s, w3
    mov     w3, #0xd400
    movk    w3, #0x1f, lsl #16
    dup     v21.4s, w3
    mov     w3, #0xa801
    movk    w3, #0x3f, lsl #16
    dup     v22.4s, w3
    mov     w3, #512
.Lpoly_decompose_loop:
    ldr     q0, [x2], #16
    add     v1.4s, v0.4s, v16.4s
    sshr    v1.4s, v1.4s, #7
    mul     v1.4s, v1.4s, v17.4s
    add     v1.4s, v1.4s, v18.4s
    sshr    v1.4s, v1.4s, #25
    cmgt    v2.4s, v1.4s, v19.4s
    bic     v1.16b, v1.16b, v2.16b
    mul     v2.4s, v1.4s, v20.4s
    sub     v2.4s, v0.4s, v2.4s
    cmgt    v3.4s, v2.4s, v21.4s
    and     v3.16b, v3.16b, v22.16b
    sub     v2.4s, v2.4s, v3.4s
    str     q1, [x0], #16
    str     q2, [x1], #16
    subs    w3, w3, #4
    b.ne    .Lpoly_decompose_loop
    ret
    .size PQCP_AIGIS_SIG_PolyDecompose, .-PQCP_AIGIS_SIG_PolyDecompose

/* Decompose and apply a hint in one pass; Aigis-Sig+ has maxHigh == 5. */
    .global PQCP_AIGIS_SIG_PolyDecomposeUseHint
    .hidden PQCP_AIGIS_SIG_PolyDecomposeUseHint
    .type PQCP_AIGIS_SIG_PolyDecomposeUseHint, %function
PQCP_AIGIS_SIG_PolyDecomposeUseHint:
    mov     w3, #127
    dup     v16.4s, w3
    mov     w3, #6177
    dup     v17.4s, w3
    mov     w3, #0
    movk    w3, #0x100, lsl #16
    dup     v18.4s, w3
    mov     w3, #5
    dup     v19.4s, w3
    mov     w3, #0x9c00
    movk    w3, #0xa, lsl #16
    dup     v20.4s, w3
    mov     w3, #0xd400
    movk    w3, #0x1f, lsl #16
    dup     v21.4s, w3
    mov     w3, #0xa801
    movk    w3, #0x3f, lsl #16
    dup     v22.4s, w3
    movi    v23.4s, #0
    movi    v24.4s, #1
    mov     w3, #512
.Lpoly_decompose_use_hint_loop:
    ldp     q0, q25, [x1], #32
    add     v1.4s, v0.4s, v16.4s
    add     v26.4s, v25.4s, v16.4s
    sshr    v1.4s, v1.4s, #7
    sshr    v26.4s, v26.4s, #7
    mul     v1.4s, v1.4s, v17.4s
    mul     v26.4s, v26.4s, v17.4s
    add     v1.4s, v1.4s, v18.4s
    add     v26.4s, v26.4s, v18.4s
    sshr    v1.4s, v1.4s, #25
    sshr    v26.4s, v26.4s, #25
    cmgt    v2.4s, v1.4s, v19.4s
    cmgt    v27.4s, v26.4s, v19.4s
    bic     v1.16b, v1.16b, v2.16b
    bic     v26.16b, v26.16b, v27.16b
    mls     v0.4s, v1.4s, v20.4s
    mls     v25.4s, v26.4s, v20.4s
    cmgt    v2.4s, v0.4s, v21.4s
    cmgt    v27.4s, v25.4s, v21.4s
    and     v2.16b, v2.16b, v22.16b
    and     v27.16b, v27.16b, v22.16b
    sub     v0.4s, v0.4s, v2.4s
    sub     v25.4s, v25.4s, v27.4s
    cmgt    v2.4s, v0.4s, v23.4s
    cmgt    v27.4s, v25.4s, v23.4s
    cmeq    v4.4s, v1.4s, v19.4s
    cmeq    v28.4s, v26.4s, v19.4s
    cmeq    v5.4s, v1.4s, v23.4s
    cmeq    v29.4s, v26.4s, v23.4s
    add     v6.4s, v1.4s, v24.4s
    add     v30.4s, v26.4s, v24.4s
    bic     v6.16b, v6.16b, v4.16b
    bic     v30.16b, v30.16b, v28.16b
    sub     v7.4s, v1.4s, v24.4s
    sub     v31.4s, v26.4s, v24.4s
    bsl     v5.16b, v19.16b, v7.16b
    bsl     v29.16b, v19.16b, v31.16b
    bsl     v2.16b, v6.16b, v5.16b
    bsl     v27.16b, v30.16b, v29.16b
    ldp     q3, q28, [x2], #32
    cmtst   v3.4s, v3.4s, v3.4s
    cmtst   v28.4s, v28.4s, v28.4s
    bsl     v3.16b, v2.16b, v1.16b
    bsl     v28.16b, v27.16b, v26.16b
    stp     q3, q28, [x0], #32
    subs    w3, w3, #8
    b.ne    .Lpoly_decompose_use_hint_loop
    ret
    .size PQCP_AIGIS_SIG_PolyDecomposeUseHint, .-PQCP_AIGIS_SIG_PolyDecomposeUseHint

    .section .note.GNU-stack,"",%progbits
