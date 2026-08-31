/*
 * Aigis-Sig+ 512-point three-pass Barrett NTT/INTT for AArch64 ASIMD.
 *
 * Contract:
 *   ordinary input -> Barrett NTT -> Montgomery pointwise (R^-1)
 *   -> fused Barrett INTT -> ordinary output.
 *
 * The generated table and its oracle prove |forward| <= 23054492, L4
 * accumulation < 2^51, centered pointwise |r| <= q/2+2, and the final
 * inverse-root input < 2^30.  All loop bounds and table addresses are public.
 */

    .arch armv8-a
    .text
    .balign 16

/* Paired product: out = value*zl - round(value*zh/2^31)*q. */
.macro BARRETT_MUL out, value, low, high
    sqrdmulh v28.4s, \value\().4s, \high\().4s
    mul      \out\().4s, \value\().4s, \low\().4s
    mls      \out\().4s, v28.4s, v31.4s
.endm

.macro CT a, b
    BARRETT_MUL v27, \b, v29, v30
    sub     v28.4s, \a\().4s, v27.4s
    add     \a\().4s, \a\().4s, v27.4s
    mov     \b\().16b, v28.16b
.endm

.macro GS a, b
    add     v27.4s, \a\().4s, \b\().4s
    sub     v26.4s, \a\().4s, \b\().4s
    mov     \a\().16b, v27.16b
    BARRETT_MUL v27, v26, v29, v30
    mov     \b\().16b, v27.16b
.endm

.macro LOAD_SCALAR_TWIDDLE
    ld2r    {v29.4s, v30.4s}, [x1], #8
.endm

.macro LOAD_VECTOR_TWIDDLES
    ld2     {v29.4s, v30.4s}, [x1], #32
.endm

.macro LOAD16
    ldr     q0, [x4, #0]
    ldr     q1, [x4, #64]
    ldr     q2, [x4, #128]
    ldr     q3, [x4, #192]
    ldr     q4, [x4, #256]
    ldr     q5, [x4, #320]
    ldr     q6, [x4, #384]
    ldr     q7, [x4, #448]
    ldr     q8, [x4, #512]
    ldr     q9, [x4, #576]
    ldr     q10, [x4, #640]
    ldr     q11, [x4, #704]
    ldr     q12, [x4, #768]
    ldr     q13, [x4, #832]
    ldr     q14, [x4, #896]
    ldr     q15, [x4, #960]
.endm

.macro STORE16
    str     q0, [x4, #0]
    str     q1, [x4, #64]
    str     q2, [x4, #128]
    str     q3, [x4, #192]
    str     q4, [x4, #256]
    str     q5, [x4, #320]
    str     q6, [x4, #384]
    str     q7, [x4, #448]
    str     q8, [x4, #512]
    str     q9, [x4, #576]
    str     q10, [x4, #640]
    str     q11, [x4, #704]
    str     q12, [x4, #768]
    str     q13, [x4, #832]
    str     q14, [x4, #896]
    str     q15, [x4, #960]
.endm

.macro SAVE_SIMD
    sub     sp, sp, #64
    stp     d8, d9, [sp, #0]
    stp     d10, d11, [sp, #16]
    stp     d12, d13, [sp, #32]
    stp     d14, d15, [sp, #48]
.endm

.macro RESTORE_SIMD
    ldp     d8, d9, [sp, #0]
    ldp     d10, d11, [sp, #16]
    ldp     d12, d13, [sp, #32]
    ldp     d14, d15, [sp, #48]
    add     sp, sp, #64
.endm

.macro SAVE_FORWARD
    sub     sp, sp, #80
    stp     d8, d9, [sp, #0]
    stp     d10, d11, [sp, #16]
    stp     d12, d13, [sp, #32]
    stp     d14, d15, [sp, #48]
    str     x30, [sp, #64]
.endm

.macro RESTORE_FORWARD
    ldp     d8, d9, [sp, #0]
    ldp     d10, d11, [sp, #16]
    ldp     d12, d13, [sp, #32]
    ldp     d14, d15, [sp, #48]
    ldr     x30, [sp, #64]
    add     sp, sp, #80
.endm

/* Decode one exact seven-byte T1 group into two uint7 vectors. */
.macro UNPACK_T1_8 ptr, lo, hi
    ldr     w7, [\ptr]
    ldrh    w8, [\ptr, #4]
    ldrb    w9, [\ptr, #6]
    orr     x7, x7, x8, lsl #32
    orr     x7, x7, x9, lsl #48
    and     w8, w7, #0x7f
    mov     \lo\().s[0], w8
    ubfx    x8, x7, #7, #7
    mov     \lo\().s[1], w8
    ubfx    x8, x7, #14, #7
    mov     \lo\().s[2], w8
    ubfx    x8, x7, #21, #7
    mov     \lo\().s[3], w8
    ubfx    x8, x7, #28, #7
    mov     \hi\().s[0], w8
    ubfx    x8, x7, #35, #7
    mov     \hi\().s[1], w8
    ubfx    x8, x7, #42, #7
    mov     \hi\().s[2], w8
    ubfx    x8, x7, #49, #7
    mov     \hi\().s[3], w8
.endm

/*
 * One 16-coefficient forward subtree:
 * len=8/4 stay in natural vectors; len=2/1 use 64/32-bit transposes.
 */
.macro FORWARD_BOTTOM_BLOCK
    ldp     q0, q1, [x4]
    ldp     q2, q3, [x4, #32]

    LOAD_SCALAR_TWIDDLE
    CT      v0, v2
    CT      v1, v3

    LOAD_SCALAR_TWIDDLE
    CT      v0, v1
    LOAD_SCALAR_TWIDDLE
    CT      v2, v3

    ld2     {v24.4s, v25.4s}, [x1], #32
    uzp1    v4.2d, v0.2d, v1.2d
    uzp2    v5.2d, v0.2d, v1.2d
    zip1    v29.4s, v24.4s, v24.4s
    zip1    v30.4s, v25.4s, v25.4s
    CT      v4, v5
    zip1    v0.2d, v4.2d, v5.2d
    zip2    v1.2d, v4.2d, v5.2d
    uzp1    v4.2d, v2.2d, v3.2d
    uzp2    v5.2d, v2.2d, v3.2d
    zip2    v29.4s, v24.4s, v24.4s
    zip2    v30.4s, v25.4s, v25.4s
    CT      v4, v5
    zip1    v2.2d, v4.2d, v5.2d
    zip2    v3.2d, v4.2d, v5.2d

    uzp1    v4.4s, v0.4s, v1.4s
    uzp2    v5.4s, v0.4s, v1.4s
    LOAD_VECTOR_TWIDDLES
    CT      v4, v5
    zip1    v0.4s, v4.4s, v5.4s
    zip2    v1.4s, v4.4s, v5.4s
    uzp1    v4.4s, v2.4s, v3.4s
    uzp2    v5.4s, v2.4s, v3.4s
    LOAD_VECTOR_TWIDDLES
    CT      v4, v5
    zip1    v2.4s, v4.4s, v5.4s
    zip2    v3.4s, v4.4s, v5.4s

    stp     q0, q1, [x4]
    stp     q2, q3, [x4, #32]
.endm

.macro INVERSE_BOTTOM_BLOCK
    ldp     q0, q1, [x4]
    ldp     q2, q3, [x4, #32]

    uzp1    v4.4s, v0.4s, v1.4s
    uzp2    v5.4s, v0.4s, v1.4s
    LOAD_VECTOR_TWIDDLES
    GS      v4, v5
    zip1    v0.4s, v4.4s, v5.4s
    zip2    v1.4s, v4.4s, v5.4s
    uzp1    v4.4s, v2.4s, v3.4s
    uzp2    v5.4s, v2.4s, v3.4s
    LOAD_VECTOR_TWIDDLES
    GS      v4, v5
    zip1    v2.4s, v4.4s, v5.4s
    zip2    v3.4s, v4.4s, v5.4s

    ld2     {v24.4s, v25.4s}, [x1], #32
    uzp1    v4.2d, v0.2d, v1.2d
    uzp2    v5.2d, v0.2d, v1.2d
    zip1    v29.4s, v24.4s, v24.4s
    zip1    v30.4s, v25.4s, v25.4s
    GS      v4, v5
    zip1    v0.2d, v4.2d, v5.2d
    zip2    v1.2d, v4.2d, v5.2d
    uzp1    v4.2d, v2.2d, v3.2d
    uzp2    v5.2d, v2.2d, v3.2d
    zip2    v29.4s, v24.4s, v24.4s
    zip2    v30.4s, v25.4s, v25.4s
    GS      v4, v5
    zip1    v2.2d, v4.2d, v5.2d
    zip2    v3.2d, v4.2d, v5.2d

    LOAD_SCALAR_TWIDDLE
    GS      v0, v1
    LOAD_SCALAR_TWIDDLE
    GS      v2, v3

    LOAD_SCALAR_TWIDDLE
    GS      v0, v2
    GS      v1, v3

    stp     q0, q1, [x4]
    stp     q2, q3, [x4, #32]
.endm

    .global PQCP_AIGIS_SIG_Ntt
    .hidden PQCP_AIGIS_SIG_Ntt
    .type PQCP_AIGIS_SIG_Ntt, %function
PQCP_AIGIS_SIG_Ntt:
    SAVE_FORWARD
    mov     w2, #0xa801
    movk    w2, #0x003f, lsl #16
    dup     v31.4s, w2

    /* Pass 1: the cross-half len=256 root. */
    adrp    x1, aigis_ntt_root_paired
    add     x1, x1, :lo12:aigis_ntt_root_paired
    LOAD_SCALAR_TWIDDLE
    mov     x2, #0
.Lforward_root:
    add     x3, x0, x2
    add     x4, x3, #1024
    ldp     q0, q1, [x3]
    ldp     q2, q3, [x3, #32]
    ldp     q4, q5, [x4]
    ldp     q6, q7, [x4, #32]
    CT      v0, v4
    CT      v1, v5
    CT      v2, v6
    CT      v3, v7
    stp     q0, q1, [x3]
    stp     q2, q3, [x3, #32]
    stp     q4, q5, [x4]
    stp     q6, q7, [x4, #32]
    add     x2, x2, #64
    cmp     x2, #1024
    b.lo    .Lforward_root

    bl      .Lforward_after_root
    RESTORE_FORWARD
    ret
    .size PQCP_AIGIS_SIG_Ntt, .-PQCP_AIGIS_SIG_Ntt

    .balign 16
    .global PQCP_AIGIS_SIG_NttCopy
    .hidden PQCP_AIGIS_SIG_NttCopy
    .type PQCP_AIGIS_SIG_NttCopy, %function
PQCP_AIGIS_SIG_NttCopy:
    SAVE_FORWARD
    mov     w2, #0xa801
    movk    w2, #0x003f, lsl #16
    dup     v31.4s, w2
    adrp    x2, aigis_ntt_root_paired
    add     x2, x2, :lo12:aigis_ntt_root_paired
    ld2r    {v29.4s, v30.4s}, [x2]
    mov     x2, #0
.Lforward_copy_root:
    add     x3, x1, x2
    add     x4, x3, #1024
    ldp     q0, q1, [x3]
    ldp     q2, q3, [x3, #32]
    ldp     q4, q5, [x4]
    ldp     q6, q7, [x4, #32]
    CT      v0, v4
    CT      v1, v5
    CT      v2, v6
    CT      v3, v7
    add     x3, x0, x2
    add     x4, x3, #1024
    stp     q0, q1, [x3]
    stp     q2, q3, [x3, #32]
    stp     q4, q5, [x4]
    stp     q6, q7, [x4, #32]
    add     x2, x2, #64
    cmp     x2, #1024
    b.lo    .Lforward_copy_root
    bl      .Lforward_after_root
    RESTORE_FORWARD
    ret
    .size PQCP_AIGIS_SIG_NttCopy, .-PQCP_AIGIS_SIG_NttCopy

    .balign 16
    .global PQCP_AIGIS_SIG_PolyVecKUnpackT1ShiftNttArmv8
    .hidden PQCP_AIGIS_SIG_PolyVecKUnpackT1ShiftNttArmv8
    .type PQCP_AIGIS_SIG_PolyVecKUnpackT1ShiftNttArmv8, %function
PQCP_AIGIS_SIG_PolyVecKUnpackT1ShiftNttArmv8:
    stp     x19, x20, [sp, #-112]!
    stp     x21, x22, [sp, #16]
    stp     x23, x30, [sp, #32]
    stp     d8, d9, [sp, #48]
    stp     d10, d11, [sp, #64]
    stp     d12, d13, [sp, #80]
    stp     d14, d15, [sp, #96]
    mov     x19, x0
    mov     x20, x1
    mov     w21, w2
    mov     w2, #0xa801
    movk    w2, #0x003f, lsl #16
    dup     v31.4s, w2
.Lforward_unpack_poly:
    adrp    x2, aigis_ntt_root_paired
    add     x2, x2, :lo12:aigis_ntt_root_paired
    ld2r    {v29.4s, v30.4s}, [x2]
    mov     x10, x20
    add     x11, x20, #224
    mov     x12, #0
.Lforward_unpack_root:
    UNPACK_T1_8 x10, v0, v1
    UNPACK_T1_8 x11, v2, v3
    shl     v0.4s, v0.4s, #15
    shl     v1.4s, v1.4s, #15
    shl     v2.4s, v2.4s, #15
    shl     v3.4s, v3.4s, #15
    CT      v0, v2
    CT      v1, v3
    add     x13, x19, x12
    add     x14, x13, #1024
    stp     q0, q1, [x13]
    stp     q2, q3, [x14]
    add     x10, x10, #7
    add     x11, x11, #7
    add     x12, x12, #32
    cmp     x12, #1024
    b.lo    .Lforward_unpack_root
    mov     x0, x19
    bl      .Lforward_after_root
    add     x19, x19, #2048
    add     x20, x20, #448
    subs    w21, w21, #1
    b.ne    .Lforward_unpack_poly
    ldp     d14, d15, [sp, #96]
    ldp     d12, d13, [sp, #80]
    ldp     d10, d11, [sp, #64]
    ldp     d8, d9, [sp, #48]
    ldp     x23, x30, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #112
    ret
    .size PQCP_AIGIS_SIG_PolyVecKUnpackT1ShiftNttArmv8, .-PQCP_AIGIS_SIG_PolyVecKUnpackT1ShiftNttArmv8
/* x0 points at a polynomial whose len=256 root is already complete. */
.Lforward_after_root:

    /* Pass 2: four in-register layers in each 256-coefficient half. */
    adrp    x5, aigis_ntt_top_paired
    add     x5, x5, :lo12:aigis_ntt_top_paired
    mov     x6, #0
.Lforward_top_half:
    mov     x2, #0
.Lforward_top_stripe:
    add     x4, x0, x6
    add     x4, x4, x2
    mov     x1, x5
    LOAD16

    LOAD_SCALAR_TWIDDLE
    CT v0, v8
    CT v1, v9
    CT v2, v10
    CT v3, v11
    CT v4, v12
    CT v5, v13
    CT v6, v14
    CT v7, v15

    LOAD_SCALAR_TWIDDLE
    CT v0, v4
    CT v1, v5
    CT v2, v6
    CT v3, v7
    LOAD_SCALAR_TWIDDLE
    CT v8, v12
    CT v9, v13
    CT v10, v14
    CT v11, v15

    LOAD_SCALAR_TWIDDLE
    CT v0, v2
    CT v1, v3
    LOAD_SCALAR_TWIDDLE
    CT v4, v6
    CT v5, v7
    LOAD_SCALAR_TWIDDLE
    CT v8, v10
    CT v9, v11
    LOAD_SCALAR_TWIDDLE
    CT v12, v14
    CT v13, v15

    LOAD_SCALAR_TWIDDLE
    CT v0, v1
    LOAD_SCALAR_TWIDDLE
    CT v2, v3
    LOAD_SCALAR_TWIDDLE
    CT v4, v5
    LOAD_SCALAR_TWIDDLE
    CT v6, v7
    LOAD_SCALAR_TWIDDLE
    CT v8, v9
    LOAD_SCALAR_TWIDDLE
    CT v10, v11
    LOAD_SCALAR_TWIDDLE
    CT v12, v13
    LOAD_SCALAR_TWIDDLE
    CT v14, v15

    STORE16
    add     x2, x2, #16
    cmp     x2, #64
    b.lo    .Lforward_top_stripe
    add     x5, x5, #120
    add     x6, x6, #1024
    cmp     x6, #2048
    b.lo    .Lforward_top_half

    /* Pass 3: two 16-coefficient subtrees per public loop iteration. */
    adrp    x1, aigis_ntt_bottom_paired
    add     x1, x1, :lo12:aigis_ntt_bottom_paired
    mov     x4, x0
    mov     x2, #16
.Lforward_bottom:
    FORWARD_BOTTOM_BLOCK
    add     x4, x4, #64
    FORWARD_BOTTOM_BLOCK
    add     x4, x4, #64
    subs    x2, x2, #1
    b.ne    .Lforward_bottom

    ret

    .balign 16
    .global PQCP_AIGIS_SIG_InvNtt
    .hidden PQCP_AIGIS_SIG_InvNtt
    .type PQCP_AIGIS_SIG_InvNtt, %function
PQCP_AIGIS_SIG_InvNtt:
    SAVE_SIMD
    mov     w2, #0xa801
    movk    w2, #0x003f, lsl #16
    dup     v31.4s, w2

    /* Pass 1: two mirrored 16-coefficient subtrees per iteration. */
    adrp    x1, aigis_invntt_bottom_paired
    add     x1, x1, :lo12:aigis_invntt_bottom_paired
    mov     x4, x0
    mov     x2, #16
.Linverse_bottom:
    INVERSE_BOTTOM_BLOCK
    add     x4, x4, #64
    INVERSE_BOTTOM_BLOCK
    add     x4, x4, #64
    subs    x2, x2, #1
    b.ne    .Linverse_bottom

    /* Pass 2: mirrored four-layer top in each half. */
    adrp    x5, aigis_invntt_top_paired
    add     x5, x5, :lo12:aigis_invntt_top_paired
    mov     x6, #0
.Linverse_top_half:
    mov     x2, #0
.Linverse_top_stripe:
    add     x4, x0, x6
    add     x4, x4, x2
    mov     x1, x5
    LOAD16

    LOAD_SCALAR_TWIDDLE
    GS v0, v1
    LOAD_SCALAR_TWIDDLE
    GS v2, v3
    LOAD_SCALAR_TWIDDLE
    GS v4, v5
    LOAD_SCALAR_TWIDDLE
    GS v6, v7
    LOAD_SCALAR_TWIDDLE
    GS v8, v9
    LOAD_SCALAR_TWIDDLE
    GS v10, v11
    LOAD_SCALAR_TWIDDLE
    GS v12, v13
    LOAD_SCALAR_TWIDDLE
    GS v14, v15

    LOAD_SCALAR_TWIDDLE
    GS v0, v2
    GS v1, v3
    LOAD_SCALAR_TWIDDLE
    GS v4, v6
    GS v5, v7
    LOAD_SCALAR_TWIDDLE
    GS v8, v10
    GS v9, v11
    LOAD_SCALAR_TWIDDLE
    GS v12, v14
    GS v13, v15

    LOAD_SCALAR_TWIDDLE
    GS v0, v4
    GS v1, v5
    GS v2, v6
    GS v3, v7
    LOAD_SCALAR_TWIDDLE
    GS v8, v12
    GS v9, v13
    GS v10, v14
    GS v11, v15

    LOAD_SCALAR_TWIDDLE
    GS v0, v8
    GS v1, v9
    GS v2, v10
    GS v3, v11
    GS v4, v12
    GS v5, v13
    GS v6, v14
    GS v7, v15

    STORE16
    add     x2, x2, #16
    cmp     x2, #64
    b.lo    .Linverse_top_stripe
    add     x5, x5, #120
    add     x6, x6, #1024
    cmp     x6, #2048
    b.lo    .Linverse_top_half

    /* Pass 3: len=256 root fused with F=R/512 and G=F/root. */
    adrp    x1, aigis_invntt_final_paired
    add     x1, x1, :lo12:aigis_invntt_final_paired
    ldp     w2, w3, [x1]
    ldp     w5, w6, [x1, #8]
    dup     v20.4s, w2
    dup     v21.4s, w3
    dup     v22.4s, w5
    dup     v23.4s, w6
    mov     x2, #0
.Linverse_final:
    add     x3, x0, x2
    add     x4, x3, #1024
    ldp     q0, q1, [x3]
    ldp     q2, q3, [x3, #32]
    ldp     q4, q5, [x4]
    ldp     q6, q7, [x4, #32]
    add     v8.4s, v0.4s, v4.4s
    sub     v12.4s, v0.4s, v4.4s
    add     v9.4s, v1.4s, v5.4s
    sub     v13.4s, v1.4s, v5.4s
    add     v10.4s, v2.4s, v6.4s
    sub     v14.4s, v2.4s, v6.4s
    add     v11.4s, v3.4s, v7.4s
    sub     v15.4s, v3.4s, v7.4s
    BARRETT_MUL v0, v8, v20, v21
    BARRETT_MUL v1, v9, v20, v21
    BARRETT_MUL v2, v10, v20, v21
    BARRETT_MUL v3, v11, v20, v21
    BARRETT_MUL v4, v12, v22, v23
    BARRETT_MUL v5, v13, v22, v23
    BARRETT_MUL v6, v14, v22, v23
    BARRETT_MUL v7, v15, v22, v23
    stp     q0, q1, [x3]
    stp     q2, q3, [x3, #32]
    stp     q4, q5, [x4]
    stp     q6, q7, [x4, #32]
    add     x2, x2, #64
    cmp     x2, #1024
    b.lo    .Linverse_final

    RESTORE_SIMD
    ret
    .size PQCP_AIGIS_SIG_InvNtt, .-PQCP_AIGIS_SIG_InvNtt

    .section .rodata
    .local aigis_ntt_root_paired
    .local aigis_ntt_top_paired
    .local aigis_ntt_bottom_paired
    .local aigis_invntt_bottom_paired
    .local aigis_invntt_top_paired
    .local aigis_invntt_final_paired
    .include "armv8/aigis_sig_ntt_paired_tables.h"
    .section .note.GNU-stack,"",%progbits
