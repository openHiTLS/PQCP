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
#if defined(HITLS_CRYPTO_NEV) && defined(HITLS_CRYPTO_NEV_SVE2_SHA3)

#include "crypt_arm.h"
#include "nev_arm_asm.h"

CRYPT_AARCH64_ARCH_SVE2
.arch_extension sha3

/*
 * FEAT_SHA3 Keccak-f[1600] for the one- and two-stream cases.  AdvSIMD XAR
 * is non-destructive, so this schedule avoids the 24 MOVPRFX instructions
 * required by the SVE2 permutation.  The same round body handles one stream
 * in the low 64-bit lanes or two interleaved streams in both lanes.
 */

.macro NEV_SHA3_NEON_CHI a, b, c, d, e
    mov     v25.16b, \a\().16b
    mov     v26.16b, \b\().16b
    bcax    \a\().16b, \a\().16b, \c\().16b, \b\().16b
    bcax    \b\().16b, \b\().16b, \d\().16b, \c\().16b
    bcax    \c\().16b, \c\().16b, \e\().16b, \d\().16b
    bcax    \d\().16b, \d\().16b, v25.16b, \e\().16b
    bcax    \e\().16b, \e\().16b, v26.16b, v25.16b
.endm

.macro NEV_SHA3_NEON_ROUNDS
    adrp    x2, .Lnev_sha3_neon_rc
    add     x2, x2, :lo12:.Lnev_sha3_neon_rc
    mov     x1, #24
    // Keep the hot backward-branch target on a fetch-line boundary instead
    // of sharing its first line with one-time permutation setup.
    .p2align 6
.Lnev_sha3_neon_round\@:
    // Start the round-constant load before the long vector dependency chain;
    // x3 retains it until Iota, hiding its L1 latency from the next round.
    ldr     x3, [x2], #8
    eor3    v25.16b, v0.16b, v5.16b, v10.16b
    eor3    v26.16b, v1.16b, v6.16b, v11.16b
    eor3    v27.16b, v2.16b, v7.16b, v12.16b
    eor3    v28.16b, v3.16b, v8.16b, v13.16b
    eor3    v29.16b, v4.16b, v9.16b, v14.16b
    // The five first halves are independent.  Issue all of them before their
    // dependent reductions so EOR3 latency is covered by useful work.
    eor3    v25.16b, v25.16b, v15.16b, v20.16b
    eor3    v26.16b, v26.16b, v16.16b, v21.16b
    eor3    v27.16b, v27.16b, v17.16b, v22.16b
    eor3    v28.16b, v28.16b, v18.16b, v23.16b
    eor3    v29.16b, v29.16b, v19.16b, v24.16b

    rax1    v30.2d, v25.2d, v27.2d
    rax1    v31.2d, v26.2d, v28.2d
    rax1    v26.2d, v29.2d, v26.2d
    rax1    v27.2d, v27.2d, v29.2d
    rax1    v28.2d, v28.2d, v25.2d

    eor     v0.16b, v0.16b, v26.16b
    mov     v25.16b, v1.16b
    xar     v1.2d, v6.2d, v30.2d, #20
    xar     v6.2d, v9.2d, v28.2d, #44
    xar     v9.2d, v22.2d, v31.2d, #3
    xar     v22.2d, v14.2d, v28.2d, #25
    xar     v14.2d, v20.2d, v26.2d, #46
    xar     v20.2d, v2.2d, v31.2d, #2
    xar     v2.2d, v12.2d, v31.2d, #21
    xar     v12.2d, v13.2d, v27.2d, #39
    xar     v13.2d, v19.2d, v28.2d, #56
    xar     v19.2d, v23.2d, v27.2d, #8
    xar     v23.2d, v15.2d, v26.2d, #23
    xar     v15.2d, v4.2d, v28.2d, #37
    xar     v4.2d, v24.2d, v28.2d, #50
    xar     v24.2d, v21.2d, v30.2d, #62
    xar     v21.2d, v8.2d, v27.2d, #9
    xar     v8.2d, v16.2d, v30.2d, #19
    xar     v16.2d, v5.2d, v26.2d, #28
    xar     v5.2d, v3.2d, v27.2d, #36
    xar     v3.2d, v18.2d, v27.2d, #43
    xar     v18.2d, v17.2d, v31.2d, #49
    xar     v17.2d, v11.2d, v30.2d, #54
    xar     v11.2d, v7.2d, v31.2d, #58
    xar     v7.2d, v10.2d, v26.2d, #61
    xar     v10.2d, v25.2d, v30.2d, #63

    NEV_SHA3_NEON_CHI v0, v1, v2, v3, v4
    NEV_SHA3_NEON_CHI v5, v6, v7, v8, v9
    NEV_SHA3_NEON_CHI v10, v11, v12, v13, v14
    NEV_SHA3_NEON_CHI v15, v16, v17, v18, v19
    NEV_SHA3_NEON_CHI v20, v21, v22, v23, v24
    dup     v29.2d, x3
    eor     v0.16b, v0.16b, v29.16b
    subs    x1, x1, #1
    b.ne    .Lnev_sha3_neon_round\@
.endm

// void NEV_SHA3_NeonPermute1(uint64_t *state)
#if !defined(__APPLE__)
.hidden CRYPT_AARCH64_SYM(NEV_SHA3_NeonPermute1)
#endif
CRYPT_AARCH64_FUNC_START(NEV_SHA3_NeonPermute1)
AARCH64_PACIASP
    stp     d8, d9, [sp, #-64]!
    stp     d10, d11, [sp, #16]
    stp     d12, d13, [sp, #32]
    stp     d14, d15, [sp, #48]

    ldp     d0, d1, [x0]
    ldp     d2, d3, [x0, #16]
    ldp     d4, d5, [x0, #32]
    ldp     d6, d7, [x0, #48]
    ldp     d8, d9, [x0, #64]
    ldp     d10, d11, [x0, #80]
    ldp     d12, d13, [x0, #96]
    ldp     d14, d15, [x0, #112]
    ldp     d16, d17, [x0, #128]
    ldp     d18, d19, [x0, #144]
    ldp     d20, d21, [x0, #160]
    ldp     d22, d23, [x0, #176]
    ldr     d24, [x0, #192]

    NEV_SHA3_NEON_ROUNDS

    stp     d0, d1, [x0]
    stp     d2, d3, [x0, #16]
    stp     d4, d5, [x0, #32]
    stp     d6, d7, [x0, #48]
    stp     d8, d9, [x0, #64]
    stp     d10, d11, [x0, #80]
    stp     d12, d13, [x0, #96]
    stp     d14, d15, [x0, #112]
    stp     d16, d17, [x0, #128]
    stp     d18, d19, [x0, #144]
    stp     d20, d21, [x0, #160]
    stp     d22, d23, [x0, #176]
    str     d24, [x0, #192]

    ldp     d10, d11, [sp, #16]
    ldp     d12, d13, [sp, #32]
    ldp     d14, d15, [sp, #48]
    ldp     d8, d9, [sp], #64
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_SHA3_NeonPermute1)

// void NEV_SHA3_NeonPermute2(uint64_t *state)
#if !defined(__APPLE__)
.hidden CRYPT_AARCH64_SYM(NEV_SHA3_NeonPermute2)
#endif
CRYPT_AARCH64_FUNC_START(NEV_SHA3_NeonPermute2)
AARCH64_PACIASP
    stp     d8, d9, [sp, #-64]!
    stp     d10, d11, [sp, #16]
    stp     d12, d13, [sp, #32]
    stp     d14, d15, [sp, #48]

    ldp     q0, q1, [x0]
    ldp     q2, q3, [x0, #32]
    ldp     q4, q5, [x0, #64]
    ldp     q6, q7, [x0, #96]
    ldp     q8, q9, [x0, #128]
    ldp     q10, q11, [x0, #160]
    ldp     q12, q13, [x0, #192]
    ldp     q14, q15, [x0, #224]
    ldp     q16, q17, [x0, #256]
    ldp     q18, q19, [x0, #288]
    ldp     q20, q21, [x0, #320]
    ldp     q22, q23, [x0, #352]
    ldr     q24, [x0, #384]

    NEV_SHA3_NEON_ROUNDS

    stp     q0, q1, [x0]
    stp     q2, q3, [x0, #32]
    stp     q4, q5, [x0, #64]
    stp     q6, q7, [x0, #96]
    stp     q8, q9, [x0, #128]
    stp     q10, q11, [x0, #160]
    stp     q12, q13, [x0, #192]
    stp     q14, q15, [x0, #224]
    stp     q16, q17, [x0, #256]
    stp     q18, q19, [x0, #288]
    stp     q20, q21, [x0, #320]
    stp     q22, q23, [x0, #352]
    str     q24, [x0, #384]

    ldp     d10, d11, [sp, #16]
    ldp     d12, d13, [sp, #32]
    ldp     d14, d15, [sp, #48]
    ldp     d8, d9, [sp], #64
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_SHA3_NeonPermute2)

.section .rodata
.balign 8
.Lnev_sha3_neon_rc:
    .quad 0x0000000000000001, 0x0000000000008082
    .quad 0x800000000000808a, 0x8000000080008000
    .quad 0x000000000000808b, 0x0000000080000001
    .quad 0x8000000080008081, 0x8000000000008009
    .quad 0x000000000000008a, 0x0000000000000088
    .quad 0x0000000080008009, 0x000000008000000a
    .quad 0x000000008000808b, 0x800000000000008b
    .quad 0x8000000000008089, 0x8000000000008003
    .quad 0x8000000000008002, 0x8000000000000080
    .quad 0x000000000000800a, 0x800000008000000a
    .quad 0x8000000080008081, 0x8000000000008080
    .quad 0x0000000080000001, 0x8000000080008008

#endif

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
