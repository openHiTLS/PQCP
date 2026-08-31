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

    .text
    .p2align 4
    .global PQCP_AIGIS_SIG_UnpackCenteredArmv8
    .hidden PQCP_AIGIS_SIG_UnpackCenteredArmv8
    .type PQCP_AIGIS_SIG_UnpackCenteredArmv8, %function
PQCP_AIGIS_SIG_UnpackCenteredArmv8:
    cmp     w3, #2
    b.eq    .Lunpack_centered_2
    cmp     w3, #4
    b.eq    .Lunpack_centered_4
    cmp     w3, #15
    b.eq    .Lunpack_centered_15
    cmp     w3, #17
    b.eq    .Lunpack_centered_17
    cmp     w3, #20
    b.eq    .Lunpack_centered_20

    ret

/* Decode two tightly packed 20-bit coefficients from each 5-byte block. */
.Lunpack_centered_20:
    mov     w4, #256
.Lunpack_centered_20_loop:
    ldrb    w5, [x1]
    ldrb    w6, [x1, #1]
    ldrb    w7, [x1, #2]
    ldrb    w8, [x1, #3]
    ldrb    w9, [x1, #4]
    orr     w5, w5, w6, lsl #8
    and     w6, w7, #15
    orr     w5, w5, w6, lsl #16
    lsr     w7, w7, #4
    orr     w7, w7, w8, lsl #4
    orr     w7, w7, w9, lsl #12
    sub     w5, w2, w5
    sub     w7, w2, w7
    stp     w5, w7, [x0], #8
    add     x1, x1, #5
    subs    w4, w4, #1
    b.ne    .Lunpack_centered_20_loop
    ret

.Lunpack_centered_2:
    mov     w4, #128
.Lunpack_centered_2_loop:
    ldrb    w5, [x1], #1
    and     w6, w5, #3
    sub     w6, w2, w6
    str     w6, [x0], #4
    ubfx    w6, w5, #2, #2
    sub     w6, w2, w6
    str     w6, [x0], #4
    ubfx    w6, w5, #4, #2
    sub     w6, w2, w6
    str     w6, [x0], #4
    lsr     w6, w5, #6
    sub     w6, w2, w6
    str     w6, [x0], #4
    subs    w4, w4, #1
    b.ne    .Lunpack_centered_2_loop
    ret

.Lunpack_centered_4:
    mov     w4, #256
.Lunpack_centered_4_loop:
    ldrb    w5, [x1], #1
    and     w6, w5, #15
    sub     w6, w2, w6
    str     w6, [x0], #4
    lsr     w6, w5, #4
    sub     w6, w2, w6
    str     w6, [x0], #4
    subs    w4, w4, #1
    b.ne    .Lunpack_centered_4_loop
    ret

/* Decode 16 tightly packed 15-bit coefficients from each 30-byte block. */
.Lunpack_centered_15:
    adr     x4, .Lunpack_centered_15_tables
    ldp     q24, q25, [x4], #32
    ldp     q26, q27, [x4], #32
    ldp     q28, q29, [x4]
    mov     w4, #0x7fff
    dup     v30.4s, w4
    dup     v31.4s, w2
    mov     w4, #32
.Lunpack_centered_15_loop:
    ldr     q0, [x1]
    movi    v1.16b, #0
    ldr     d1, [x1, #16]
    ldr     w5, [x1, #24]
    ins     v1.s[2], w5
    ldrh    w5, [x1, #28]
    ins     v1.h[6], w5
    movi    v2.16b, #0
    add     x1, x1, #30

    tbl     v4.16b, {v0.16b, v1.16b, v2.16b}, v24.16b
    tbl     v5.16b, {v0.16b, v1.16b, v2.16b}, v25.16b
    tbl     v6.16b, {v0.16b, v1.16b, v2.16b}, v26.16b
    tbl     v7.16b, {v0.16b, v1.16b, v2.16b}, v27.16b
    ushl    v4.4s, v4.4s, v28.4s
    ushl    v5.4s, v5.4s, v29.4s
    ushl    v6.4s, v6.4s, v28.4s
    ushl    v7.4s, v7.4s, v29.4s
    and     v4.16b, v4.16b, v30.16b
    and     v5.16b, v5.16b, v30.16b
    and     v6.16b, v6.16b, v30.16b
    and     v7.16b, v7.16b, v30.16b
    sub     v4.4s, v31.4s, v4.4s
    sub     v5.4s, v31.4s, v5.4s
    sub     v6.4s, v31.4s, v6.4s
    sub     v7.4s, v31.4s, v7.4s
    stp     q4, q5, [x0], #32
    stp     q6, q7, [x0], #32
    subs    w4, w4, #1
    b.ne    .Lunpack_centered_15_loop
    ret

/* Decode 16 tightly packed 17-bit coefficients from each 34-byte block. */
.Lunpack_centered_17:
    adr     x4, .Lunpack_centered_17_tables
    ldp     q24, q25, [x4], #32
    ldp     q26, q27, [x4], #32
    ldp     q28, q29, [x4]
    mov     w4, #0xffff
    movk    w4, #1, lsl #16
    dup     v30.4s, w4
    dup     v31.4s, w2
    mov     w4, #32
.Lunpack_centered_17_loop:
    ldp     q0, q1, [x1]
    movi    v2.16b, #0
    ldrh    w5, [x1, #32]
    ins     v2.h[0], w5
    add     x1, x1, #34

    tbl     v4.16b, {v0.16b, v1.16b, v2.16b}, v24.16b
    tbl     v5.16b, {v0.16b, v1.16b, v2.16b}, v25.16b
    tbl     v6.16b, {v0.16b, v1.16b, v2.16b}, v26.16b
    tbl     v7.16b, {v0.16b, v1.16b, v2.16b}, v27.16b
    ushl    v4.4s, v4.4s, v28.4s
    ushl    v5.4s, v5.4s, v29.4s
    ushl    v6.4s, v6.4s, v28.4s
    ushl    v7.4s, v7.4s, v29.4s
    and     v4.16b, v4.16b, v30.16b
    and     v5.16b, v5.16b, v30.16b
    and     v6.16b, v6.16b, v30.16b
    and     v7.16b, v7.16b, v30.16b
    sub     v4.4s, v31.4s, v4.4s
    sub     v5.4s, v31.4s, v5.4s
    sub     v6.4s, v31.4s, v6.4s
    sub     v7.4s, v31.4s, v7.4s
    stp     q4, q5, [x0], #32
    stp     q6, q7, [x0], #32
    subs    w4, w4, #1
    b.ne    .Lunpack_centered_17_loop
    ret
    .size PQCP_AIGIS_SIG_UnpackCenteredArmv8, .-PQCP_AIGIS_SIG_UnpackCenteredArmv8

/* Decode a complete VecL of 15/17-bit response polynomials and accumulate the
 * strict Aigis-Sig norm predicate while the coefficients are still resident.
 * x0=output, x1=input, w2=poly count, w3=center, w4=bits, w5=bound. */
    .p2align 4
    .global PQCP_AIGIS_SIG_PolyVecLUnpackZCheckNormArmv8
    .hidden PQCP_AIGIS_SIG_PolyVecLUnpackZCheckNormArmv8
    .type PQCP_AIGIS_SIG_PolyVecLUnpackZCheckNormArmv8, %function
PQCP_AIGIS_SIG_PolyVecLUnpackZCheckNormArmv8:
    cmp     w4, #15
    b.eq    .Lunpack_vecl_check_15
    cmp     w4, #17
    b.ne    .Lunpack_vecl_check_invalid

    adr     x6, .Lunpack_centered_17_tables
    ldp     q24, q25, [x6], #32
    ldp     q26, q27, [x6], #32
    ldp     q28, q29, [x6]
    mov     w4, #0xffff
    movk    w4, #1, lsl #16
    dup     v30.4s, w4
    dup     v31.4s, w3
    lsl     w2, w2, #5
    b       .Lunpack_vecl_check_setup

.Lunpack_vecl_check_15:
    adr     x6, .Lunpack_centered_15_tables
    ldp     q24, q25, [x6], #32
    ldp     q26, q27, [x6], #32
    ldp     q28, q29, [x6]
    mov     w4, #0x7fff
    dup     v30.4s, w4
    dup     v31.4s, w3
    lsl     w2, w2, #5

.Lunpack_vecl_check_setup:
    mov     w4, #0x80000000
    dup     v16.4s, w4
    mov     w4, #0x7fffffff
    dup     v17.4s, w4
    cmp     w3, #16384
    b.eq    .Lunpack_vecl_check_15_loop

.macro unpack_vecl_check_store loop
    smax    v16.4s, v16.4s, v4.4s
    smin    v17.4s, v17.4s, v4.4s
    smax    v16.4s, v16.4s, v5.4s
    smin    v17.4s, v17.4s, v5.4s
    smax    v16.4s, v16.4s, v6.4s
    smin    v17.4s, v17.4s, v6.4s
    smax    v16.4s, v16.4s, v7.4s
    smin    v17.4s, v17.4s, v7.4s
    stp     q4, q5, [x0], #32
    stp     q6, q7, [x0], #32
    subs    w2, w2, #1
    b.ne    \loop
    b       .Lunpack_vecl_check_done
.endm

.Lunpack_vecl_check_17_loop:
    ldp     q0, q1, [x1]
    movi    v2.16b, #0
    ldrh    w4, [x1, #32]
    ins     v2.h[0], w4
    add     x1, x1, #34

    tbl     v4.16b, {v0.16b, v1.16b, v2.16b}, v24.16b
    tbl     v5.16b, {v0.16b, v1.16b, v2.16b}, v25.16b
    tbl     v6.16b, {v0.16b, v1.16b, v2.16b}, v26.16b
    tbl     v7.16b, {v0.16b, v1.16b, v2.16b}, v27.16b
    ushl    v4.4s, v4.4s, v28.4s
    ushl    v5.4s, v5.4s, v29.4s
    ushl    v6.4s, v6.4s, v28.4s
    ushl    v7.4s, v7.4s, v29.4s
    and     v4.16b, v4.16b, v30.16b
    and     v5.16b, v5.16b, v30.16b
    and     v6.16b, v6.16b, v30.16b
    and     v7.16b, v7.16b, v30.16b
    sub     v4.4s, v31.4s, v4.4s
    sub     v5.4s, v31.4s, v5.4s
    sub     v6.4s, v31.4s, v6.4s
    sub     v7.4s, v31.4s, v7.4s
    unpack_vecl_check_store .Lunpack_vecl_check_17_loop

.Lunpack_vecl_check_15_loop:
    ldr     q0, [x1]
    movi    v1.16b, #0
    ldr     d1, [x1, #16]
    ldr     w4, [x1, #24]
    ins     v1.s[2], w4
    ldrh    w4, [x1, #28]
    ins     v1.h[6], w4
    movi    v2.16b, #0
    add     x1, x1, #30

    tbl     v4.16b, {v0.16b, v1.16b, v2.16b}, v24.16b
    tbl     v5.16b, {v0.16b, v1.16b, v2.16b}, v25.16b
    tbl     v6.16b, {v0.16b, v1.16b, v2.16b}, v26.16b
    tbl     v7.16b, {v0.16b, v1.16b, v2.16b}, v27.16b
    ushl    v4.4s, v4.4s, v28.4s
    ushl    v5.4s, v5.4s, v29.4s
    ushl    v6.4s, v6.4s, v28.4s
    ushl    v7.4s, v7.4s, v29.4s
    and     v4.16b, v4.16b, v30.16b
    and     v5.16b, v5.16b, v30.16b
    and     v6.16b, v6.16b, v30.16b
    and     v7.16b, v7.16b, v30.16b
    sub     v4.4s, v31.4s, v4.4s
    sub     v5.4s, v31.4s, v5.4s
    sub     v6.4s, v31.4s, v6.4s
    sub     v7.4s, v31.4s, v7.4s
    unpack_vecl_check_store .Lunpack_vecl_check_15_loop

.Lunpack_vecl_check_done:
    smaxv   s0, v16.4s
    sminv   s1, v17.4s
    fmov    w0, s0
    fmov    w1, s1
    cmp     w0, w5
    cset    w0, gt
    mov     w2, #1
    sub     w2, w2, w5
    cmp     w1, w2
    cset    w1, lt
    orr     w0, w0, w1
    ret

.Lunpack_vecl_check_invalid:
    mov     w0, #1
    ret
    .size PQCP_AIGIS_SIG_PolyVecLUnpackZCheckNormArmv8, .-PQCP_AIGIS_SIG_PolyVecLUnpackZCheckNormArmv8
    .purgem unpack_vecl_check_store

    .section .rodata
    .p2align 4
.Lunpack_centered_15_tables:
    .byte 0, 1, 2, 3, 1, 2, 3, 4, 3, 4, 5, 6, 5, 6, 7, 8
    .byte 7, 8, 9, 10, 9, 10, 11, 12, 11, 12, 13, 14, 13, 14, 15, 16
    .byte 15, 16, 17, 18, 16, 17, 18, 19, 18, 19, 20, 21, 20, 21, 22, 23
    .byte 22, 23, 24, 25, 24, 25, 26, 27, 26, 27, 28, 29, 28, 29, 30, 31
    .word 0, -7, -6, -5
    .word -4, -3, -2, -1

.Lunpack_centered_17_tables:
    .byte 0, 1, 2, 3, 2, 3, 4, 5, 4, 5, 6, 7, 6, 7, 8, 9
    .byte 8, 9, 10, 11, 10, 11, 12, 13, 12, 13, 14, 15, 14, 15, 16, 17
    .byte 17, 18, 19, 20, 19, 20, 21, 22, 21, 22, 23, 24, 23, 24, 25, 26
    .byte 25, 26, 27, 28, 27, 28, 29, 30, 29, 30, 31, 32, 31, 32, 33, 34
    .word 0, -1, -2, -3
    .word -4, -5, -6, -7

    .section .note.GNU-stack,"",%progbits
