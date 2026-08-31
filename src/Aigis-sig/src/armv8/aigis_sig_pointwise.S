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
/* 512-coefficient pointwise multiplication with Montgomery reduction. */
    .arch armv8-a
    .text
    .balign 16

    .global PQCP_AIGIS_SIG_PolyPointwise
    .hidden PQCP_AIGIS_SIG_PolyPointwise
    .type PQCP_AIGIS_SIG_PolyPointwise, %function
PQCP_AIGIS_SIG_PolyPointwise:
    mov     w4, #0xa801
    movk    w4, #0x003f, lsl #16
    mov     w5, #0x5801
    movk    w5, #0x1e00, lsl #16
    dup     v30.4s, w4
    dup     v31.4s, w5
    /* M52=round(2^52/q), signed-lane safe unlike round(2^53/q). */
    mov     w6, #0x78a5
    movk    w6, #0x4058, lsl #16
    dup     v29.4s, w6
    mov     x3, #512

.Lpointwise_loop:
    ldr     q0, [x1], #16
    ldr     q1, [x2], #16
    mul     v2.4s, v0.4s, v1.4s
    mul     v3.4s, v2.4s, v31.4s
    smull   v4.2d, v0.2s, v1.2s
    smull2  v5.2d, v0.4s, v1.4s
    smull   v6.2d, v3.2s, v30.2s
    smull2  v7.2d, v3.4s, v30.4s
    sub     v4.2d, v4.2d, v6.2d
    sub     v5.2d, v5.2d, v7.2d
    uzp2    v16.4s, v4.4s, v5.4s
    sqdmulh v17.4s, v16.4s, v29.4s
    srshr   v17.4s, v17.4s, #21
    mls     v16.4s, v17.4s, v30.4s
    str     q16, [x0], #16
    subs    x3, x3, #4
    b.ne    .Lpointwise_loop
    ret

    .size PQCP_AIGIS_SIG_PolyPointwise, .-PQCP_AIGIS_SIG_PolyPointwise
    .section .note.GNU-stack,"",%progbits
