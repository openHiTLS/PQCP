/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the
 * Mulan PSL v2.
 */

.arch armv8-a
.text
.p2align 4

.macro PSPM_UNPACK_T1_16 ptr
    movi    v0.16b, #0
    ldr     d0, [\ptr]
    ldr     w7, [\ptr, #8]
    ldrh    w8, [\ptr, #12]
    mov     v0.s[2], w7
    mov     v0.h[6], w8
    tbl     v1.16b, {v0.16b}, v28.16b
    tbl     v2.16b, {v0.16b}, v29.16b
    ushl    v1.16b, v1.16b, v30.16b
    ushl    v2.16b, v2.16b, v31.16b
    orr     v1.16b, v1.16b, v2.16b
    movi    v2.16b, #0x7f
    and     v1.16b, v1.16b, v2.16b
.endm

.macro PSPM_ACC_OFFSET offset
    add     x9, x3, \offset, uxtw #1
    add     x13, x0, x9
    ldp     q18, q19, [x13]
    ldp     q20, q21, [x13, #32]
    saddw   v0.4s, v0.4s, v18.4h
    saddw2  v1.4s, v1.4s, v18.8h
    saddw   v2.4s, v2.4s, v19.4h
    saddw2  v3.4s, v3.4s, v19.8h
    saddw   v4.4s, v4.4s, v20.4h
    saddw2  v5.4s, v5.4s, v20.8h
    saddw   v6.4s, v6.4s, v21.4h
    saddw2  v7.4s, v7.4s, v21.8h
    add     x14, x10, x9
    ldp     q18, q19, [x14]
    ldp     q20, q21, [x14, #32]
    saddw   v24.4s, v24.4s, v18.4h
    saddw2  v25.4s, v25.4s, v18.8h
    saddw   v26.4s, v26.4s, v19.4h
    saddw2  v27.4s, v27.4s, v19.8h
    saddw   v28.4s, v28.4s, v20.4h
    saddw2  v29.4s, v29.4s, v20.8h
    saddw   v30.4s, v30.4s, v21.4h
    saddw2  v31.4s, v31.4s, v21.8h
.endm

.macro PSPM_GENERAL_REDUCE_PAIR value0, value1
    smull   v18.2d, \value0\().2s, v16.2s
    smull2  v19.2d, \value0\().4s, v16.4s
    smull   v20.2d, \value1\().2s, v16.2s
    smull2  v21.2d, \value1\().4s, v16.4s
    sxtl    v22.2d, \value0\().2s
    sxtl2   v23.2d, \value0\().4s
    shl     v22.2d, v22.2d, #31
    shl     v23.2d, v23.2d, #31
    add     v18.2d, v18.2d, v22.2d
    add     v19.2d, v19.2d, v23.2d
    sxtl    v22.2d, \value1\().2s
    sxtl2   v23.2d, \value1\().4s
    shl     v22.2d, v22.2d, #31
    shl     v23.2d, v23.2d, #31
    add     v20.2d, v20.2d, v22.2d
    add     v21.2d, v21.2d, v23.2d
    sshr    v18.2d, v18.2d, #53
    sshr    v19.2d, v19.2d, #53
    sshr    v20.2d, v20.2d, #53
    sshr    v21.2d, v21.2d, #53
    xtn     v18.2s, v18.2d
    xtn2    v18.4s, v19.2d
    xtn     v20.2s, v20.2d
    xtn2    v20.4s, v21.2d
    mls     \value0\().4s, v18.4s, v17.4s
    mls     \value1\().4s, v20.4s, v17.4s
.endm

/* Decode the two parameter-I T1 polynomials directly into PSPM stable tables. */
.global PQCP_AIGIS_SIG_UnpackT1StablePairArmv8
.hidden PQCP_AIGIS_SIG_UnpackT1StablePairArmv8
.type PQCP_AIGIS_SIG_UnpackT1StablePairArmv8, %function
PQCP_AIGIS_SIG_UnpackT1StablePairArmv8:
    adr     x7, .Lpspm_unpack_tables
    ldp     q28, q29, [x7]
    ldp     q30, q31, [x7, #32]
    mov     w2, #2
.Lpspm_unpack_poly:
    mov     x3, xzr
.Lpspm_unpack_group:
    PSPM_UNPACK_T1_16 x1
    uxtl    v16.8h, v1.8b
    uxtl2   v17.8h, v1.16b
    neg     v18.8h, v16.8h
    neg     v19.8h, v17.8h
    add     x4, x0, x3
    add     x5, x4, #1024
    add     x6, x4, #2048
    stp     q18, q19, [x4]
    stp     q16, q17, [x5]
    stp     q18, q19, [x6]
    add     x1, x1, #14
    add     x3, x3, #32
    cmp     x3, #1024
    b.ne    .Lpspm_unpack_group
    add     x0, x0, #3072
    subs    w2, w2, #1
    b.ne    .Lpspm_unpack_poly
    ret
.size PQCP_AIGIS_SIG_UnpackT1StablePairArmv8, .-PQCP_AIGIS_SIG_UnpackT1StablePairArmv8

.p2align 4

/*
 * Sparse verification helper for parameter I/II row pairs.
 *
 * x0: AigisSigEmulateCt1PairScratch *scratch
 * x1: AigisSigPoly resultBase[2] (in/out)
 * x2: const AigisSigPoly *challenge
 * w3: challenge weight (24/44); bit 31 reuses precomputed offsets
 *
 * The challenge and stable T1 tables are public verification inputs. The caller guarantees
 * the encoded weight and non-overlapping objects. The implementation is a
 * leaf and uses only AAPCS64 caller-saved GPR/SIMD registers.
 */
.global PQCP_AIGIS_SIG_EmulateCt1PairShiftSubGReduceArmv8
.hidden PQCP_AIGIS_SIG_EmulateCt1PairShiftSubGReduceArmv8
.type PQCP_AIGIS_SIG_EmulateCt1PairShiftSubGReduceArmv8, %function
PQCP_AIGIS_SIG_EmulateCt1PairShiftSubGReduceArmv8:
    mov     w17, w3
    /* offsets = 2 rows * 3 * 512 int16 after the stable tables. */
    add     x6, x0, #1, lsl #12
    add     x6, x6, #2048
    tbnz    w17, #31, .Lpspm_scan_done
    mov     x3, x2
    mov     w4, wzr
    mov     w5, wzr
.Lpspm_scan:
    ldp     q18, q19, [x3]
    ldp     q20, q21, [x3, #32]
    add     x3, x3, #64
    cmtst   v18.4s, v18.4s, v18.4s
    cmtst   v19.4s, v19.4s, v19.4s
    cmtst   v20.4s, v20.4s, v20.4s
    cmtst   v21.4s, v21.4s, v21.4s
    xtn     v22.4h, v18.4s
    xtn2    v22.8h, v19.4s
    xtn     v23.4h, v20.4s
    xtn2    v23.8h, v21.4s
    xtn     v22.8b, v22.8h
    xtn2    v22.16b, v23.8h
    fmov    x9, d22
    umov    x12, v22.d[1]
    mov     w15, w4
    mov     w16, #2
.Lpspm_scan_mask:
    cbz     x9, .Lpspm_scan_half_done
    rbit    x13, x9
    clz     x13, x13
    lsr     w8, w13, #3
    add     w8, w15, w8
    ldr     w7, [x2, w8, uxtw #2]
    mov     w14, #0xff
    lsl     x14, x14, x13
    bic     x9, x9, x14
    mov     w14, #512
    sub     w14, w14, w8
    add     w8, w14, #512
    cmp     w7, #0
    csel    w14, w8, w14, lt
    str     w14, [x6, w5, uxtw #2]
    add     w5, w5, #1
    b       .Lpspm_scan_mask
.Lpspm_scan_half_done:
    subs    w16, w16, #1
    b.eq    .Lpspm_scan_next
    mov     x9, x12
    add     w15, w4, #8
    b       .Lpspm_scan_mask
.Lpspm_scan_next:
    add     w4, w4, #16
    cmp     w4, #512
    b.ne    .Lpspm_scan
.Lpspm_scan_done:
    and     w17, w17, #0xff
    /* stable1 = scratch + 3 * 512 int16. */
    add     x10, x0, #3072
    /* Constants used by the exact existing GeneralReduce formula. */
    mov     w12, #0xf149
    movk    w12, #0x00b0, lsl #16
    dup     v16.4s, w12
    mov     w12, #0xa801
    movk    w12, #0x003f, lsl #16
    dup     v17.4s, w12

    add     x11, x1, #2048
    mov     x4, xzr
    mov     x3, xzr
.Lpspm_product:
    movi    v0.4s, #0
    movi    v1.4s, #0
    movi    v2.4s, #0
    movi    v3.4s, #0
    movi    v4.4s, #0
    movi    v5.4s, #0
    movi    v6.4s, #0
    movi    v7.4s, #0
    movi    v24.4s, #0
    movi    v25.4s, #0
    movi    v26.4s, #0
    movi    v27.4s, #0
    movi    v28.4s, #0
    movi    v29.4s, #0
    movi    v30.4s, #0
    movi    v31.4s, #0
    mov     x8, x6
    lsr     w7, w17, #3
.Lpspm_accumulate:
    ldp     w9, w12, [x8], #8
    ldp     w15, w5, [x8], #8
    PSPM_ACC_OFFSET w9
    PSPM_ACC_OFFSET w12
    PSPM_ACC_OFFSET w15
    PSPM_ACC_OFFSET w5
    ldp     w9, w12, [x8], #8
    ldp     w15, w5, [x8], #8
    PSPM_ACC_OFFSET w9
    PSPM_ACC_OFFSET w12
    PSPM_ACC_OFFSET w15
    PSPM_ACC_OFFSET w5
    subs    w7, w7, #1
    b.ne    .Lpspm_accumulate
    tbz     w17, #2, .Lpspm_accumulated
    ldp     w9, w12, [x8], #8
    ldp     w15, w5, [x8], #8
    PSPM_ACC_OFFSET w9
    PSPM_ACC_OFFSET w12
    PSPM_ACC_OFFSET w15
    PSPM_ACC_OFFSET w5

.Lpspm_accumulated:
    shl     v0.4s, v0.4s, #15
    shl     v1.4s, v1.4s, #15
    shl     v2.4s, v2.4s, #15
    shl     v3.4s, v3.4s, #15
    shl     v4.4s, v4.4s, #15
    shl     v5.4s, v5.4s, #15
    shl     v6.4s, v6.4s, #15
    shl     v7.4s, v7.4s, #15
    shl     v24.4s, v24.4s, #15
    shl     v25.4s, v25.4s, #15
    shl     v26.4s, v26.4s, #15
    shl     v27.4s, v27.4s, #15
    shl     v28.4s, v28.4s, #15
    shl     v29.4s, v29.4s, #15
    shl     v30.4s, v30.4s, #15
    shl     v31.4s, v31.4s, #15
    add     x13, x1, x4
    ldp     q18, q19, [x13]
    ldp     q20, q21, [x13, #32]
    sub     v0.4s, v18.4s, v0.4s
    sub     v1.4s, v19.4s, v1.4s
    sub     v2.4s, v20.4s, v2.4s
    sub     v3.4s, v21.4s, v3.4s
    ldp     q18, q19, [x13, #64]
    ldp     q20, q21, [x13, #96]
    sub     v4.4s, v18.4s, v4.4s
    sub     v5.4s, v19.4s, v5.4s
    sub     v6.4s, v20.4s, v6.4s
    sub     v7.4s, v21.4s, v7.4s
    add     x14, x11, x4
    ldp     q18, q19, [x14]
    ldp     q20, q21, [x14, #32]
    sub     v24.4s, v18.4s, v24.4s
    sub     v25.4s, v19.4s, v25.4s
    sub     v26.4s, v20.4s, v26.4s
    sub     v27.4s, v21.4s, v27.4s
    ldp     q18, q19, [x14, #64]
    ldp     q20, q21, [x14, #96]
    sub     v28.4s, v18.4s, v28.4s
    sub     v29.4s, v19.4s, v29.4s
    sub     v30.4s, v20.4s, v30.4s
    sub     v31.4s, v21.4s, v31.4s

    PSPM_GENERAL_REDUCE_PAIR v0, v1
    PSPM_GENERAL_REDUCE_PAIR v2, v3
    PSPM_GENERAL_REDUCE_PAIR v4, v5
    PSPM_GENERAL_REDUCE_PAIR v6, v7
    PSPM_GENERAL_REDUCE_PAIR v24, v25
    PSPM_GENERAL_REDUCE_PAIR v26, v27
    PSPM_GENERAL_REDUCE_PAIR v28, v29
    PSPM_GENERAL_REDUCE_PAIR v30, v31

    stp     q0, q1, [x13]
    stp     q2, q3, [x13, #32]
    stp     q4, q5, [x13, #64]
    stp     q6, q7, [x13, #96]
    stp     q24, q25, [x14]
    stp     q26, q27, [x14, #32]
    stp     q28, q29, [x14, #64]
    stp     q30, q31, [x14, #96]
    add     x4, x4, #128
    add     x3, x3, #64
    cmp     x4, #2048
    b.ne    .Lpspm_product
    ret
.size PQCP_AIGIS_SIG_EmulateCt1PairShiftSubGReduceArmv8, .-PQCP_AIGIS_SIG_EmulateCt1PairShiftSubGReduceArmv8

.section .rodata
.p2align 4
.Lpspm_unpack_tables:
    .byte 0, 0, 1, 2, 3, 4, 5, 6, 7, 7, 8, 9, 10, 11, 12, 13
    .byte 1, 1, 2, 3, 4, 5, 6, 7, 8, 8, 9, 10, 11, 12, 13, 14
    .byte 0, -7, -6, -5, -4, -3, -2, -1, 0, -7, -6, -5, -4, -3, -2, -1
    .byte 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7

.section .note.GNU-stack,"",%progbits
