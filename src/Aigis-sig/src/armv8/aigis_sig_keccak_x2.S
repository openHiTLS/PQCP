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

/*
 * Aigis-Sig+ internal two-stream Keccak-f[1600] backend.
 * Derived from openHiTLS commit 6482a94f8ff930fec9950f0c4eb86a40cac4f8ff,
 * crypto/sha3/src/asm/sha3_armv8.S.  The symbols are PQCP-private.
 */

.arch armv8-a
.section .rodata
.p2align 6
.Lpqcp_aigis_keccak_round_constants:
    .quad   0x0000000000000001
    .quad   0x0000000000008082
    .quad   0x800000000000808a
    .quad   0x8000000080008000
    .quad   0x000000000000808b
    .quad   0x0000000080000001
    .quad   0x8000000080008081
    .quad   0x8000000000008009
    .quad   0x000000000000008a
    .quad   0x0000000000000088
    .quad   0x0000000080008009
    .quad   0x000000008000000a
    .quad   0x000000008000808b
    .quad   0x800000000000008b
    .quad   0x8000000000008089
    .quad   0x8000000000008003
    .quad   0x8000000000008002
    .quad   0x8000000000000080
    .quad   0x000000000000800a
    .quad   0x800000008000000a
    .quad   0x8000000080008081
    .quad   0x8000000000008080
    .quad   0x0000000080000001
    .quad   0x8000000080008008
.text
.p2align 4
/* ROL: rotate left by n bits for 2D vector */
.macro ROL dst, src, n
    shl     \dst\().2d, \src\().2d, #\n
    sri     \dst\().2d, \src\().2d, #(64 - \n)
.endm

.macro STORE_X2_LANE reg
#ifdef HITLS_BIG_ENDIAN
    rev64   v25.16b, v\reg\().16b
    st1     {v25.d}[0], [x19], #8
    st1     {v25.d}[1], [x20], #8
#else
    st1     {v\reg\().d}[0], [x19], #8
    st1     {v\reg\().d}[1], [x20], #8
#endif
.endm

/*
 * KeccakF1600StatePermutex2 - Keccak-f[1600] permutation for two parallel states
 *
 * void KeccakF1600StatePermutex2(Keccakx2State state)
 *   x0: pointer to state array of 25 x uint64x2_t (400 bytes)
 *
 * Register allocation:
 *   v0-v24:  state s[0]-s[24]
 *   v25-v29: temporaries (t0-t4 / C / D)
 *   v30-v31: additional temporaries
 *   x0:      state pointer (preserved in x19)
 *   x1:      round counter
 *   x2:      pointer to round constants
 */
.global PQCP_AIGIS_SIG_KeccakF1600x2Armv8
.hidden PQCP_AIGIS_SIG_KeccakF1600x2Armv8
.type PQCP_AIGIS_SIG_KeccakF1600x2Armv8, %function
PQCP_AIGIS_SIG_KeccakF1600x2Armv8:
    stp     x29, x30, [sp, #-112]!
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     d8,  d9,  [sp, #48]
    stp     d10, d11, [sp, #64]
    stp     d12, d13, [sp, #80]
    stp     d14, d15, [sp, #96]
    mov     x29, sp

    mov     x19, x0

    ldp     q0,  q1,  [x0]
    ldp     q2,  q3,  [x0, #32]
    ldp     q4,  q5,  [x0, #64]
    ldp     q6,  q7,  [x0, #96]
    ldp     q8,  q9,  [x0, #128]
    ldp     q10, q11, [x0, #160]
    ldp     q12, q13, [x0, #192]
    ldp     q14, q15, [x0, #224]
    ldp     q16, q17, [x0, #256]
    ldp     q18, q19, [x0, #288]
    ldp     q20, q21, [x0, #320]
    ldp     q22, q23, [x0, #352]
    ldr     q24, [x0, #384]

    bl      .Lx2_permute_regs
    b       .Lx2_store_state

.Lx2_permute_regs:
    adrp    x2, .Lpqcp_aigis_keccak_round_constants
    add     x2, x2, :lo12:.Lpqcp_aigis_keccak_round_constants
    mov     x1, #24

.Lx2_round_loop:
    /* ===== Theta ===== */
    eor     v25.16b, v0.16b,  v5.16b
    eor     v30.16b, v10.16b, v15.16b
    eor     v25.16b, v25.16b, v30.16b
    eor     v25.16b, v25.16b, v20.16b

    eor     v26.16b, v1.16b,  v6.16b
    eor     v30.16b, v11.16b, v16.16b
    eor     v26.16b, v26.16b, v30.16b
    eor     v26.16b, v26.16b, v21.16b

    eor     v27.16b, v2.16b,  v7.16b
    eor     v30.16b, v12.16b, v17.16b
    eor     v27.16b, v27.16b, v30.16b
    eor     v27.16b, v27.16b, v22.16b

    eor     v28.16b, v3.16b,  v8.16b
    eor     v30.16b, v13.16b, v18.16b
    eor     v28.16b, v28.16b, v30.16b
    eor     v28.16b, v28.16b, v23.16b

    eor     v29.16b, v4.16b,  v9.16b
    eor     v30.16b, v14.16b, v19.16b
    eor     v29.16b, v29.16b, v30.16b
    eor     v29.16b, v29.16b, v24.16b

    ROL     v30, v26, 1
    eor     v30.16b, v29.16b, v30.16b
    ROL     v31, v27, 1
    eor     v31.16b, v25.16b, v31.16b

    eor     v0.16b,  v0.16b,  v30.16b
    eor     v5.16b,  v5.16b,  v30.16b
    eor     v10.16b, v10.16b, v30.16b
    eor     v15.16b, v15.16b, v30.16b
    eor     v20.16b, v20.16b, v30.16b

    eor     v1.16b,  v1.16b,  v31.16b
    eor     v6.16b,  v6.16b,  v31.16b
    eor     v11.16b, v11.16b, v31.16b
    eor     v16.16b, v16.16b, v31.16b
    eor     v21.16b, v21.16b, v31.16b

    ROL     v30, v28, 1
    eor     v30.16b, v26.16b, v30.16b

    eor     v2.16b,  v2.16b,  v30.16b
    eor     v7.16b,  v7.16b,  v30.16b
    eor     v12.16b, v12.16b, v30.16b
    eor     v17.16b, v17.16b, v30.16b
    eor     v22.16b, v22.16b, v30.16b

    ROL     v30, v29, 1
    eor     v30.16b, v27.16b, v30.16b

    eor     v3.16b,  v3.16b,  v30.16b
    eor     v8.16b,  v8.16b,  v30.16b
    eor     v13.16b, v13.16b, v30.16b
    eor     v18.16b, v18.16b, v30.16b
    eor     v23.16b, v23.16b, v30.16b

    ROL     v30, v25, 1
    eor     v30.16b, v28.16b, v30.16b

    eor     v4.16b,  v4.16b,  v30.16b
    eor     v9.16b,  v9.16b,  v30.16b
    eor     v14.16b, v14.16b, v30.16b
    eor     v19.16b, v19.16b, v30.16b
    eor     v24.16b, v24.16b, v30.16b

    /* ===== Rho + Pi + Chi ===== */
    sub     sp, sp, #160

    /* Rho + Pi: compute rotated values and store to stack in row order */
    str     q0, [sp, #0]
    ROL     v25, v6, 44
    str     q25, [sp, #16]
    ROL     v25, v12, 43
    str     q25, [sp, #32]
    ROL     v25, v18, 21
    str     q25, [sp, #48]
    ROL     v25, v24, 14
    str     q25, [sp, #64]

    ROL     v25, v3, 28
    str     q25, [sp, #80]
    ROL     v25, v9, 20
    str     q25, [sp, #96]
    ROL     v25, v10, 3
    str     q25, [sp, #112]
    ROL     v25, v16, 45
    str     q25, [sp, #128]
    ROL     v25, v22, 61
    str     q25, [sp, #144]

    /* Preserve the only row-three/four sources clobbered by direct rows. */
    ROL     v28, v11, 10
    ROL     v29, v14, 39

    /* Rho/Pi row two directly into its final registers, then in-place Chi. */
    ROL     v12, v13, 25
    ROL     v10, v1, 1
    ROL     v11, v7, 6
    ROL     v13, v19, 8
    ROL     v14, v20, 18
    bic     v24.16b, v12.16b, v11.16b
    bic     v25.16b, v11.16b, v10.16b
    bic     v26.16b, v10.16b, v14.16b
    bic     v27.16b, v13.16b, v12.16b
    eor     v10.16b, v10.16b, v24.16b
    eor     v11.16b, v11.16b, v27.16b
    bic     v24.16b, v14.16b, v13.16b
    eor     v12.16b, v12.16b, v24.16b
    eor     v13.16b, v13.16b, v26.16b
    eor     v14.16b, v14.16b, v25.16b

    /* Row three needs old v17 before replacing it and keeps old v15 for row four. */
    ROL     v18, v17, 15
    mov     v17.16b, v28.16b
    ROL     v28, v15, 41
    ROL     v15, v4, 27
    ROL     v16, v5, 36
    ROL     v19, v23, 56
    bic     v24.16b, v17.16b, v16.16b
    bic     v25.16b, v16.16b, v15.16b
    bic     v26.16b, v15.16b, v19.16b
    bic     v27.16b, v18.16b, v17.16b
    eor     v15.16b, v15.16b, v24.16b
    eor     v16.16b, v16.16b, v27.16b
    bic     v24.16b, v19.16b, v18.16b
    eor     v17.16b, v17.16b, v24.16b
    eor     v18.16b, v18.16b, v26.16b
    eor     v19.16b, v19.16b, v25.16b

    /* Row four consumes its two saved lanes and completes the direct suffix. */
    ROL     v24, v21, 2
    ROL     v20, v2, 62
    ROL     v21, v8, 55
    mov     v22.16b, v29.16b
    mov     v23.16b, v28.16b
    bic     v25.16b, v22.16b, v21.16b
    bic     v26.16b, v21.16b, v20.16b
    bic     v27.16b, v20.16b, v24.16b
    bic     v28.16b, v23.16b, v22.16b
    eor     v20.16b, v20.16b, v25.16b
    eor     v21.16b, v21.16b, v28.16b
    bic     v25.16b, v24.16b, v23.16b
    eor     v22.16b, v22.16b, v25.16b
    eor     v23.16b, v23.16b, v27.16b
    eor     v24.16b, v24.16b, v26.16b

    /* Chi + Iota */
    ldp     q25, q26, [sp, #0]
    ldp     q27, q28, [sp, #32]
    ldr     q29, [sp, #64]

    bic     v30.16b, v27.16b, v26.16b
    eor     v0.16b, v25.16b, v30.16b
    ldr     x3, [x2]
    dup     v30.2d, x3
    eor     v0.16b, v0.16b, v30.16b

    bic     v30.16b, v28.16b, v27.16b
    eor     v1.16b, v26.16b, v30.16b
    bic     v30.16b, v29.16b, v28.16b
    eor     v2.16b, v27.16b, v30.16b
    bic     v30.16b, v25.16b, v29.16b
    eor     v3.16b, v28.16b, v30.16b
    bic     v30.16b, v26.16b, v25.16b
    eor     v4.16b, v29.16b, v30.16b

    ldp     q25, q26, [sp, #80]
    ldp     q27, q28, [sp, #112]
    ldr     q29, [sp, #144]
    bic     v30.16b, v27.16b, v26.16b
    eor     v5.16b, v25.16b, v30.16b
    bic     v30.16b, v28.16b, v27.16b
    eor     v6.16b, v26.16b, v30.16b
    bic     v30.16b, v29.16b, v28.16b
    eor     v7.16b, v27.16b, v30.16b
    bic     v30.16b, v25.16b, v29.16b
    eor     v8.16b, v28.16b, v30.16b
    bic     v30.16b, v26.16b, v25.16b
    eor     v9.16b, v29.16b, v30.16b

    add     sp, sp, #160

    add     x2, x2, #8
    subs    x1, x1, #1
    b.ne    .Lx2_round_loop
    ret

.Lx2_store_state:
    /* Store state back */
    stp     q0,  q1,  [x19]
    stp     q2,  q3,  [x19, #32]
    stp     q4,  q5,  [x19, #64]
    stp     q6,  q7,  [x19, #96]
    stp     q8,  q9,  [x19, #128]
    stp     q10, q11, [x19, #160]
    stp     q12, q13, [x19, #192]
    stp     q14, q15, [x19, #224]
    stp     q16, q17, [x19, #256]
    stp     q18, q19, [x19, #288]
    stp     q20, q21, [x19, #320]
    stp     q22, q23, [x19, #352]
    str     q24, [x19, #384]

    ldp     x19, x20, [x29, #16]
    ldp     x21, x22, [x29, #32]
    ldp     d8,  d9,  [x29, #48]
    ldp     d10, d11, [x29, #64]
    ldp     d12, d13, [x29, #80]
    ldp     d14, d15, [x29, #96]
    ldp     x29, x30, [sp], #112
    ret
.size PQCP_AIGIS_SIG_KeccakF1600x2Armv8, .-PQCP_AIGIS_SIG_KeccakF1600x2Armv8

/* Fixed SHAKE128 absorb used by matrix expansion: 33 input bytes, domain 0x1f. */
.p2align 4
.global PQCP_AIGIS_SIG_Keccakx2Absorb33Shake128Armv8
.hidden PQCP_AIGIS_SIG_Keccakx2Absorb33Shake128Armv8
.type PQCP_AIGIS_SIG_Keccakx2Absorb33Shake128Armv8, %function
PQCP_AIGIS_SIG_Keccakx2Absorb33Shake128Armv8:
    movi    v0.2d, #0
    stp     q0, q0, [x0]
    stp     q0, q0, [x0, #32]
    stp     q0, q0, [x0, #64]
    stp     q0, q0, [x0, #96]
    stp     q0, q0, [x0, #128]
    stp     q0, q0, [x0, #160]
    stp     q0, q0, [x0, #192]
    stp     q0, q0, [x0, #224]
    stp     q0, q0, [x0, #256]
    stp     q0, q0, [x0, #288]
    stp     q0, q0, [x0, #320]
    stp     q0, q0, [x0, #352]
    str     q0, [x0, #384]
    ld1     {v1.d}[0], [x1], #8
    ld1     {v1.d}[1], [x2], #8
    ld1     {v2.d}[0], [x1], #8
    ld1     {v2.d}[1], [x2], #8
    ld1     {v3.d}[0], [x1], #8
    ld1     {v3.d}[1], [x2], #8
    ld1     {v4.d}[0], [x1], #8
    ld1     {v4.d}[1], [x2], #8
#ifdef HITLS_BIG_ENDIAN
    rev64   v1.16b, v1.16b
    rev64   v2.16b, v2.16b
    rev64   v3.16b, v3.16b
    rev64   v4.16b, v4.16b
#endif
    stp     q1, q2, [x0]
    stp     q3, q4, [x0, #32]
    ldrb    w4, [x1]
    ldrb    w5, [x2]
    orr     x4, x4, #0x1f00
    orr     x5, x5, #0x1f00
    fmov    d1, x4
    mov     v1.d[1], x5
    str     q1, [x0, #64]
    mov     x4, #1
    lsl     x4, x4, #63
    dup     v1.2d, x4
    str     q1, [x0, #320]
    ret
.size PQCP_AIGIS_SIG_Keccakx2Absorb33Shake128Armv8, .-PQCP_AIGIS_SIG_Keccakx2Absorb33Shake128Armv8

/* Fixed SHAKE128 absorb used by parameter III matrix expansion:
 * 65 input bytes, domain 0x1f. */
.p2align 4
.global PQCP_AIGIS_SIG_Keccakx2Absorb65Shake128Armv8
.hidden PQCP_AIGIS_SIG_Keccakx2Absorb65Shake128Armv8
.type PQCP_AIGIS_SIG_Keccakx2Absorb65Shake128Armv8, %function
PQCP_AIGIS_SIG_Keccakx2Absorb65Shake128Armv8:
    movi    v0.2d, #0
    stp     q0, q0, [x0]
    stp     q0, q0, [x0, #32]
    stp     q0, q0, [x0, #64]
    stp     q0, q0, [x0, #96]
    stp     q0, q0, [x0, #128]
    stp     q0, q0, [x0, #160]
    stp     q0, q0, [x0, #192]
    stp     q0, q0, [x0, #224]
    stp     q0, q0, [x0, #256]
    stp     q0, q0, [x0, #288]
    stp     q0, q0, [x0, #320]
    stp     q0, q0, [x0, #352]
    str     q0, [x0, #384]
    ld1     {v1.d}[0], [x1], #8
    ld1     {v1.d}[1], [x2], #8
    ld1     {v2.d}[0], [x1], #8
    ld1     {v2.d}[1], [x2], #8
    ld1     {v3.d}[0], [x1], #8
    ld1     {v3.d}[1], [x2], #8
    ld1     {v4.d}[0], [x1], #8
    ld1     {v4.d}[1], [x2], #8
    ld1     {v5.d}[0], [x1], #8
    ld1     {v5.d}[1], [x2], #8
    ld1     {v6.d}[0], [x1], #8
    ld1     {v6.d}[1], [x2], #8
    ld1     {v7.d}[0], [x1], #8
    ld1     {v7.d}[1], [x2], #8
#ifdef HITLS_BIG_ENDIAN
    rev64   v1.16b, v1.16b
    rev64   v2.16b, v2.16b
    rev64   v3.16b, v3.16b
    rev64   v4.16b, v4.16b
    rev64   v5.16b, v5.16b
    rev64   v6.16b, v6.16b
    rev64   v7.16b, v7.16b
#endif
    stp     q1, q2, [x0]
    stp     q3, q4, [x0, #32]
    stp     q5, q6, [x0, #64]
    str     q7, [x0, #96]
    ld1     {v1.d}[0], [x1], #8
    ld1     {v1.d}[1], [x2], #8
#ifdef HITLS_BIG_ENDIAN
    rev64   v1.16b, v1.16b
#endif
    str     q1, [x0, #112]
    ldrb    w4, [x1]
    ldrb    w5, [x2]
    orr     x4, x4, #0x1f00
    orr     x5, x5, #0x1f00
    fmov    d1, x4
    mov     v1.d[1], x5
    str     q1, [x0, #128]
    mov     x4, #1
    lsl     x4, x4, #63
    dup     v1.2d, x4
    str     q1, [x0, #320]
    ret
.size PQCP_AIGIS_SIG_Keccakx2Absorb65Shake128Armv8, .-PQCP_AIGIS_SIG_Keccakx2Absorb65Shake128Armv8

/**
 * Keccakx2Absorb - AArch64 NEON implementation
 *
 * void Keccakx2Absorb(Keccakx2State state, size_t rate,
 *                     const uint8_t *in0, const uint8_t *in1,
 *                     size_t inlen, uint8_t domain)
 *
 * Register allocation (caller convention, AAPCS64):
 *   x0  = state (Keccakx2State: 25 x uint64x2_t = 400 bytes)
 *   x1  = rate  (bytes per block, e.g. 168 for SHAKE128)
 *   x2  = in0
 *   x3  = in1
 *   x4  = inlen
 *   x5  = domain (passed as uint8_t in w5)
 *
 * The Keccakx2State layout: s[i] = { lane_i_stream0, lane_i_stream1 }
 * (two parallel 1600-bit states tucked into 25 uint64x2_t registers)
 */
.global PQCP_AIGIS_SIG_Keccakx2AbsorbArmv8
.hidden PQCP_AIGIS_SIG_Keccakx2AbsorbArmv8
.type PQCP_AIGIS_SIG_Keccakx2AbsorbArmv8, %function
PQCP_AIGIS_SIG_Keccakx2AbsorbArmv8:
    stp     x29, x30, [sp, #-128]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     d8,  d9,  [sp, #64]
    stp     d10, d11, [sp, #80]
    stp     d12, d13, [sp, #96]
    stp     d14, d15, [sp, #112]

    /* Save parameters */
    mov     x19, x0     /* state  */
    mov     x20, x1     /* rate   */
    mov     x21, x2     /* in0    */
    mov     x22, x3     /* in1    */
    mov     x23, x4     /* inlen  */
    and     x24, x5, #0xFF  /* domain */

    /* Step 1: initialize state to zero (25 x uint64x2_t = 400 bytes) */
    movi    v0.2d,  #0
    stp     q0, q0, [x19]
    stp     q0, q0, [x19, #32]
    stp     q0, q0, [x19, #64]
    stp     q0, q0, [x19, #96]
    stp     q0, q0, [x19, #128]
    stp     q0, q0, [x19, #160]
    stp     q0, q0, [x19, #192]
    stp     q0, q0, [x19, #224]
    stp     q0, q0, [x19, #256]
    stp     q0, q0, [x19, #288]
    stp     q0, q0, [x19, #320]
    stp     q0, q0, [x19, #352]
    str     q0, [x19, #384]

    /* Step 2: absorb full blocks */
    /* while (inlen >= rate): XOR rate/8 words from in0+in1 into state, then permute */
.Labsorb2_full_block_check:
    cmp     x23, x20
    blo     .Labsorb2_tail

    /* XOR rate/8 words into state.  Each state word s[i] gets:
       lower 64 bits <- in0[i*8 .. i*8+7]
       upper 64 bits <- in1[i*8 .. i*8+7]
       We walk via pointer arithmetic: x0 = state offset, x6 = word index */
    mov     x0,  x19    /* state ptr current word */
    mov     x6,  x21    /* in0 current */
    mov     x7,  x22    /* in1 current */
    lsr     x8,  x20, #3    /* remaining words in this block = rate / 8 */

.Labsorb2_word_loop:
    ld1     {v30.d}[0], [x6], #8
    ld1     {v30.d}[1], [x7], #8
#ifdef HITLS_BIG_ENDIAN
    rev64   v30.16b, v30.16b
#endif
    ldr     q31, [x0]
    eor     v31.16b, v31.16b, v30.16b
    str     q31, [x0], #16   /* advance state pointer by sizeof(uint64x2_t) = 16 */
    subs    x8,  x8,  #1
    b.ne    .Labsorb2_word_loop

    /* Advance input pointers and reduce inlen */
    add     x21, x21, x20
    add     x22, x22, x20
    sub     x23, x23, x20

    /* Call KeccakF1600StatePermutex2(state) */
    mov     x0, x19
    bl      PQCP_AIGIS_SIG_KeccakF1600x2Armv8

    b       .Labsorb2_full_block_check

    /* Step 3: handle remaining bytes (< rate) */
.Labsorb2_tail:
    /* x23 = number of remaining bytes; x6 = byte index 0..inlen-1 */
    cbz     x23, .Labsorb2_pad

    mov     x6,  #0   /* byte index i */
    mov     x0,  x19
    lsr     x8,  x23, #3
    cbz     x8,  .Labsorb2_byte_loop
    mov     x14, x21
    mov     x15, x22

.Labsorb2_tail_word_loop:
    ld1     {v30.d}[0], [x14], #8
    ld1     {v30.d}[1], [x15], #8
#ifdef HITLS_BIG_ENDIAN
    rev64   v30.16b, v30.16b
#endif
    ldr     q31, [x0]
    eor     v31.16b, v31.16b, v30.16b
    str     q31, [x0], #16
    add     x6,  x6,  #8
    subs    x8,  x8,  #1
    b.ne    .Labsorb2_tail_word_loop

.Labsorb2_byte_loop:
    cmp     x6,  x23
    bge     .Labsorb2_pad

    /* lane = (uint64_t)in0[i] << (8*(i%8))
       packed into state[i/8] = { lane0, lane1 } */
    ldrb    w9,  [x21, x6]
    ldrb    w10, [x22, x6]
    and     x11, x6,  #7          /* i % 8            */
    lsl     x11, x11, #3          /* shift = 8*(i%8)  */
    lsl     x9,  x9,  x11         /* lane0            */
    lsl     x10, x10, x11         /* lane1            */
    /* state word index = i/8, byte offset in state = (i/8)*16 */
    lsr     x12, x6,  #3          /* i / 8            */
    add     x13, x19, x12, lsl #4 /* &state[i/8]      */
    ldr     q30, [x13]
    fmov    x14, d30
    fmov    x15, v30.d[1]
    eor     x14, x14, x9
    eor     x15, x15, x10
    fmov    d30, x14
    fmov    v30.d[1], x15
    str     q30, [x13]

    add     x6,  x6,  #1
    b       .Labsorb2_byte_loop

    /* Step 4: add domain byte */
.Labsorb2_pad:
    /* domain goes at position inlen; shift = 8*(inlen%8) */
    and     x11, x23, #7
    lsl     x11, x11, #3
    lsl     x9,  x24, x11         /* domain << shift, lane0 */
    dup     v30.2d, x9
    lsr     x12, x23, #3          /* inlen/8 -- word index  */
    add     x13, x19, x12, lsl #4
    ldr     q31, [x13]
    eor     v31.16b, v31.16b, v30.16b
    str     q31, [x13]

    /* Step 5: set bit 63 of word at (rate-1)/8 */
    sub     x11, x20, #1          /* rate - 1         */
    lsr     x12, x11, #3          /* (rate-1)/8       */
    add     x13, x19, x12, lsl #4 /* &state[(rate-1)/8] */
    mov     x9,  #1
    lsl     x9,  x9,  #63         /* 1ULL << 63       */
    dup     v30.2d, x9
    ldr     q31, [x13]
    eor     v31.16b, v31.16b, v30.16b
    str     q31, [x13]

    ldp     x19, x20, [sp, #16]
    ldp     x21, x22, [sp, #32]
    ldp     x23, x24, [sp, #48]
    ldp     d8,  d9,  [sp, #64]
    ldp     d10, d11, [sp, #80]
    ldp     d12, d13, [sp, #96]
    ldp     d14, d15, [sp, #112]
    ldp     x29, x30, [sp], #128
    ret
.size PQCP_AIGIS_SIG_Keccakx2AbsorbArmv8, .-PQCP_AIGIS_SIG_Keccakx2AbsorbArmv8


/**
 * Keccakx2Squeeze - AArch64 NEON implementation
 *
 * void Keccakx2Squeeze(uint8_t *out0, uint8_t *out1,
 *                      size_t nblocks, unsigned int r,
 *                      Keccakx2State s)
 *
 * Register allocation:
 *   x0  = out0
 *   x1  = out1
 *   x2  = nblocks
 *   x3  = r  (rate in bytes)
 *   x4  = s  (pointer to Keccakx2State)
 */
.global PQCP_AIGIS_SIG_Keccakx2SqueezeArmv8
.hidden PQCP_AIGIS_SIG_Keccakx2SqueezeArmv8
.type PQCP_AIGIS_SIG_Keccakx2SqueezeArmv8, %function
PQCP_AIGIS_SIG_Keccakx2SqueezeArmv8:
    stp     x29, x30, [sp, #-128]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     d8,  d9,  [sp, #64]
    stp     d10, d11, [sp, #80]
    stp     d12, d13, [sp, #96]
    stp     d14, d15, [sp, #112]

    mov     x19, x0    /* out0    */
    mov     x20, x1    /* out1    */
    mov     x21, x2    /* nblocks */
    mov     x22, x3    /* r       */
    mov     x23, x4    /* state   */

    ldp     q0,  q1,  [x23]
    ldp     q2,  q3,  [x23, #32]
    ldp     q4,  q5,  [x23, #64]
    ldp     q6,  q7,  [x23, #96]
    ldp     q8,  q9,  [x23, #128]
    ldp     q10, q11, [x23, #160]
    ldp     q12, q13, [x23, #192]
    ldp     q14, q15, [x23, #224]
    ldp     q16, q17, [x23, #256]
    ldp     q18, q19, [x23, #288]
    ldp     q20, q21, [x23, #320]
    ldp     q22, q23, [x23, #352]
    ldr     q24, [x23, #384]

.Lsqueeze2_loop:
    cbz     x21, .Lsqueeze2_done

    bl      .Lx2_permute_regs
    STORE_X2_LANE 0
    STORE_X2_LANE 1
    STORE_X2_LANE 2
    STORE_X2_LANE 3
    STORE_X2_LANE 4
    STORE_X2_LANE 5
    STORE_X2_LANE 6
    STORE_X2_LANE 7
    STORE_X2_LANE 8
    cmp     x22, #72
    b.eq    .Lsqueeze2_block_done
    STORE_X2_LANE 9
    STORE_X2_LANE 10
    STORE_X2_LANE 11
    STORE_X2_LANE 12
    STORE_X2_LANE 13
    STORE_X2_LANE 14
    STORE_X2_LANE 15
    STORE_X2_LANE 16
    cmp     x22, #168
    b.ne    .Lsqueeze2_block_done
    STORE_X2_LANE 17
    STORE_X2_LANE 18
    STORE_X2_LANE 19
    STORE_X2_LANE 20
.Lsqueeze2_block_done:

    sub     x21, x21, #1
    b       .Lsqueeze2_loop

.Lsqueeze2_done:
    stp     q0,  q1,  [x23]
    stp     q2,  q3,  [x23, #32]
    stp     q4,  q5,  [x23, #64]
    stp     q6,  q7,  [x23, #96]
    stp     q8,  q9,  [x23, #128]
    stp     q10, q11, [x23, #160]
    stp     q12, q13, [x23, #192]
    stp     q14, q15, [x23, #224]
    stp     q16, q17, [x23, #256]
    stp     q18, q19, [x23, #288]
    stp     q20, q21, [x23, #320]
    stp     q22, q23, [x23, #352]
    str     q24, [x23, #384]
    ldp     x19, x20, [sp, #16]
    ldp     x21, x22, [sp, #32]
    ldp     x23, x24, [sp, #48]
    ldp     d8,  d9,  [sp, #64]
    ldp     d10, d11, [sp, #80]
    ldp     d12, d13, [sp, #96]
    ldp     d14, d15, [sp, #112]
    ldp     x29, x30, [sp], #128
    ret
.size PQCP_AIGIS_SIG_Keccakx2SqueezeArmv8, .-PQCP_AIGIS_SIG_Keccakx2SqueezeArmv8
.section .note.GNU-stack,"",%progbits
