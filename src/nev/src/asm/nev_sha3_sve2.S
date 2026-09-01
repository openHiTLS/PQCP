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
#if defined(HITLS_CRYPTO_NEV_SVE2_SHA3)
.arch_extension sve2-sha3
#endif

/*
 * VL=256 Keccak-f[1600]. Each z register is one Keccak word and each uint64
 * lane is an independent sponge stream. The state uses a four-lane stride:
 * state[word * 4 + stream].
 */

.macro SHA3_EOR5 dst, a, b, c, d, e
    movprfx \dst, \a
    eor3    \dst\().d, \dst\().d, \b\().d, \c\().d
    eor3    \dst\().d, \dst\().d, \d\().d, \e\().d
.endm

.macro SHA3_XAR_SELF reg, mix, ror
.if \ror == 0
    eor     \reg\().d, \reg\().d, \mix\().d
.else
    xar     \reg\().d, \reg\().d, \mix\().d, #\ror
.endif
.endm

#if !defined(HITLS_CRYPTO_NEV_SVE2_SHA3)
.macro SHA3_ROL1 dst, src
    movprfx \dst, \src
    xar     \dst\().d, \dst\().d, z31.d, #63
.endm

#endif

/* Chi only needs the first two inputs saved: later outputs consume either
 * untouched registers or these two saved values. */
.macro SHA3_CHI_ROW a, b, c, d, e
    mov     z25.d, \a\().d
    mov     z26.d, \b\().d
    bcax    \a\().d, \a\().d, \c\().d, \b\().d
    bcax    \b\().d, \b\().d, \d\().d, \c\().d
    bcax    \c\().d, \c\().d, \e\().d, \d\().d
    bcax    \d\().d, \d\().d, z25.d, \e\().d
    bcax    \e\().d, \e\().d, z26.d, z25.d
.endm

/*
 * Keep every word in its physical register through Rho/Pi.  The m0..m24
 * arguments map the logical pre-round state to those physical registers;
 * Chi names the post-Pi rows directly.  The Pi permutation has order 24,
 * so the 24 unrolled calls below finish in the canonical z0..z24 layout.
 *
 * This turns every non-zero Rho into one destructive XAR of the word with
 * its Theta D value.  The former register-moving Pi cycle needed 24
 * MOVPRFX instructions per round in addition to the XAR instructions.
 */
.macro SHA3_ROUND m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, \
                  m13, m14, m15, m16, m17, m18, m19, m20, m21, m22, m23, m24
    SHA3_EOR5 z25, \m0, \m5, \m10, \m15, \m20
    SHA3_EOR5 z26, \m1, \m6, \m11, \m16, \m21
    SHA3_EOR5 z27, \m2, \m7, \m12, \m17, \m22
    SHA3_EOR5 z28, \m3, \m8, \m13, \m18, \m23
    SHA3_EOR5 z29, \m4, \m9, \m14, \m19, \m24

#if defined(HITLS_CRYPTO_NEV_SVE2_SHA3)
    /* D0->z26, D1->z30, D2->z31, D3->z27, D4->z28. */
    rax1    z30.d, z25.d, z27.d
    rax1    z31.d, z26.d, z28.d
    rax1    z26.d, z29.d, z26.d
    rax1    z27.d, z27.d, z29.d
    rax1    z28.d, z28.d, z25.d

    SHA3_XAR_SELF \m0,  z26, 0
    SHA3_XAR_SELF \m5,  z26, 28
    SHA3_XAR_SELF \m10, z26, 61
    SHA3_XAR_SELF \m15, z26, 23
    SHA3_XAR_SELF \m20, z26, 46
    SHA3_XAR_SELF \m1,  z30, 63
    SHA3_XAR_SELF \m6,  z30, 20
    SHA3_XAR_SELF \m11, z30, 54
    SHA3_XAR_SELF \m16, z30, 19
    SHA3_XAR_SELF \m21, z30, 62
    SHA3_XAR_SELF \m2,  z31, 2
    SHA3_XAR_SELF \m7,  z31, 58
    SHA3_XAR_SELF \m12, z31, 21
    SHA3_XAR_SELF \m17, z31, 49
    SHA3_XAR_SELF \m22, z31, 3
    SHA3_XAR_SELF \m3,  z27, 36
    SHA3_XAR_SELF \m8,  z27, 9
    SHA3_XAR_SELF \m13, z27, 39
    SHA3_XAR_SELF \m18, z27, 43
    SHA3_XAR_SELF \m23, z27, 8
    SHA3_XAR_SELF \m4,  z28, 37
    SHA3_XAR_SELF \m9,  z28, 44
    SHA3_XAR_SELF \m14, z28, 25
    SHA3_XAR_SELF \m19, z28, 56
    SHA3_XAR_SELF \m24, z28, 50
#else
    /* Base SVE2 computes one D at a time and immediately folds it into
     * that column's Rho.  This also removes the old second rotation pass. */
    SHA3_ROL1 z30, z26
    eor     z30.d, z29.d, z30.d
    SHA3_XAR_SELF \m0,  z30, 0
    SHA3_XAR_SELF \m5,  z30, 28
    SHA3_XAR_SELF \m10, z30, 61
    SHA3_XAR_SELF \m15, z30, 23
    SHA3_XAR_SELF \m20, z30, 46

    SHA3_ROL1 z30, z27
    eor     z30.d, z25.d, z30.d
    SHA3_XAR_SELF \m1,  z30, 63
    SHA3_XAR_SELF \m6,  z30, 20
    SHA3_XAR_SELF \m11, z30, 54
    SHA3_XAR_SELF \m16, z30, 19
    SHA3_XAR_SELF \m21, z30, 62

    SHA3_ROL1 z30, z28
    eor     z30.d, z26.d, z30.d
    SHA3_XAR_SELF \m2,  z30, 2
    SHA3_XAR_SELF \m7,  z30, 58
    SHA3_XAR_SELF \m12, z30, 21
    SHA3_XAR_SELF \m17, z30, 49
    SHA3_XAR_SELF \m22, z30, 3

    SHA3_ROL1 z30, z29
    eor     z30.d, z27.d, z30.d
    SHA3_XAR_SELF \m3,  z30, 36
    SHA3_XAR_SELF \m8,  z30, 9
    SHA3_XAR_SELF \m13, z30, 39
    SHA3_XAR_SELF \m18, z30, 43
    SHA3_XAR_SELF \m23, z30, 8

    SHA3_ROL1 z30, z25
    eor     z30.d, z28.d, z30.d
    SHA3_XAR_SELF \m4,  z30, 37
    SHA3_XAR_SELF \m9,  z30, 44
    SHA3_XAR_SELF \m14, z30, 25
    SHA3_XAR_SELF \m19, z30, 56
    SHA3_XAR_SELF \m24, z30, 50
#endif

    /* Pi maps the old logical registers into these five logical rows. */
    SHA3_CHI_ROW \m0, \m6, \m12, \m18, \m24
    ld1rd   z30.d, p0/z, [x2]
    eor     \m0\().d, \m0\().d, z30.d
    SHA3_CHI_ROW \m3, \m9, \m10, \m16, \m22
    SHA3_CHI_ROW \m1, \m7, \m13, \m19, \m20
    SHA3_CHI_ROW \m4, \m5, \m11, \m17, \m23
    SHA3_CHI_ROW \m2, \m8, \m14, \m15, \m21
    add     x2, x2, #8
.endm

// void SHA3_Sve2Permute(uint64_t *state)
#if !defined(__APPLE__)
.hidden CRYPT_AARCH64_SYM(SHA3_Sve2Permute)
#endif
CRYPT_AARCH64_FUNC_START(SHA3_Sve2Permute)
AARCH64_PACIASP
    stp     d8, d9, [sp, #-64]!
    stp     d10, d11, [sp, #16]
    stp     d12, d13, [sp, #32]
    stp     d14, d15, [sp, #48]

    ptrue   p0.d
#if !defined(HITLS_CRYPTO_NEV_SVE2_SHA3)
    mov     z31.d, #0
#endif
    addvl   x5, x0, #8
    addvl   x6, x0, #16
    addvl   x7, x0, #24

    ld1d    z0.d, p0/z, [x0, #0, mul vl]
    ld1d    z1.d, p0/z, [x0, #1, mul vl]
    ld1d    z2.d, p0/z, [x0, #2, mul vl]
    ld1d    z3.d, p0/z, [x0, #3, mul vl]
    ld1d    z4.d, p0/z, [x0, #4, mul vl]
    ld1d    z5.d, p0/z, [x0, #5, mul vl]
    ld1d    z6.d, p0/z, [x0, #6, mul vl]
    ld1d    z7.d, p0/z, [x0, #7, mul vl]
    ld1d    z8.d, p0/z, [x5, #0, mul vl]
    ld1d    z9.d, p0/z, [x5, #1, mul vl]
    ld1d    z10.d, p0/z, [x5, #2, mul vl]
    ld1d    z11.d, p0/z, [x5, #3, mul vl]
    ld1d    z12.d, p0/z, [x5, #4, mul vl]
    ld1d    z13.d, p0/z, [x5, #5, mul vl]
    ld1d    z14.d, p0/z, [x5, #6, mul vl]
    ld1d    z15.d, p0/z, [x5, #7, mul vl]
    ld1d    z16.d, p0/z, [x6, #0, mul vl]
    ld1d    z17.d, p0/z, [x6, #1, mul vl]
    ld1d    z18.d, p0/z, [x6, #2, mul vl]
    ld1d    z19.d, p0/z, [x6, #3, mul vl]
    ld1d    z20.d, p0/z, [x6, #4, mul vl]
    ld1d    z21.d, p0/z, [x6, #5, mul vl]
    ld1d    z22.d, p0/z, [x6, #6, mul vl]
    ld1d    z23.d, p0/z, [x6, #7, mul vl]
    ld1d    z24.d, p0/z, [x7]

    adrp    x2, .Lnev_sha3_rc
    add     x2, x2, :lo12:.Lnev_sha3_rc

    SHA3_ROUND z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15, z16, z17, z18, z19, z20, z21, z22, z23, z24
    SHA3_ROUND z0, z6, z12, z18, z24, z3, z9, z10, z16, z22, z1, z7, z13, z19, z20, z4, z5, z11, z17, z23, z2, z8, z14, z15, z21
    SHA3_ROUND z0, z9, z13, z17, z21, z18, z22, z1, z5, z14, z6, z10, z19, z23, z2, z24, z3, z7, z11, z15, z12, z16, z20, z4, z8
    SHA3_ROUND z0, z22, z19, z11, z8, z17, z14, z6, z3, z20, z9, z1, z23, z15, z12, z21, z18, z10, z7, z4, z13, z5, z2, z24, z16
    SHA3_ROUND z0, z14, z23, z7, z16, z11, z20, z9, z18, z2, z22, z6, z15, z4, z13, z8, z17, z1, z10, z24, z19, z3, z12, z21, z5
    SHA3_ROUND z0, z20, z15, z10, z5, z7, z2, z22, z17, z12, z14, z9, z4, z24, z19, z16, z11, z6, z1, z21, z23, z18, z13, z8, z3
    SHA3_ROUND z0, z2, z4, z1, z3, z10, z12, z14, z11, z13, z20, z22, z24, z21, z23, z5, z7, z9, z6, z8, z15, z17, z19, z16, z18
    SHA3_ROUND z0, z12, z24, z6, z18, z1, z13, z20, z7, z19, z2, z14, z21, z8, z15, z3, z10, z22, z9, z16, z4, z11, z23, z5, z17
    SHA3_ROUND z0, z13, z21, z9, z17, z6, z19, z2, z10, z23, z12, z20, z8, z16, z4, z18, z1, z14, z22, z5, z24, z7, z15, z3, z11
    SHA3_ROUND z0, z19, z8, z22, z11, z9, z23, z12, z1, z15, z13, z2, z16, z5, z24, z17, z6, z20, z14, z3, z21, z10, z4, z18, z7
    SHA3_ROUND z0, z23, z16, z14, z7, z22, z15, z13, z6, z4, z19, z12, z5, z3, z21, z11, z9, z2, z20, z18, z8, z1, z24, z17, z10
    SHA3_ROUND z0, z15, z5, z20, z10, z14, z4, z19, z9, z24, z23, z13, z3, z18, z8, z7, z22, z12, z2, z17, z16, z6, z21, z11, z1
    SHA3_ROUND z0, z4, z3, z2, z1, z20, z24, z23, z22, z21, z15, z19, z18, z17, z16, z10, z14, z13, z12, z11, z5, z9, z8, z7, z6
    SHA3_ROUND z0, z24, z18, z12, z6, z2, z21, z15, z14, z8, z4, z23, z17, z11, z5, z1, z20, z19, z13, z7, z3, z22, z16, z10, z9
    SHA3_ROUND z0, z21, z17, z13, z9, z12, z8, z4, z20, z16, z24, z15, z11, z7, z3, z6, z2, z23, z19, z10, z18, z14, z5, z1, z22
    SHA3_ROUND z0, z8, z11, z19, z22, z13, z16, z24, z2, z5, z21, z4, z7, z10, z18, z9, z12, z15, z23, z1, z17, z20, z3, z6, z14
    SHA3_ROUND z0, z16, z7, z23, z14, z19, z5, z21, z12, z3, z8, z24, z10, z1, z17, z22, z13, z4, z15, z6, z11, z2, z18, z9, z20
    SHA3_ROUND z0, z5, z10, z15, z20, z23, z3, z8, z13, z18, z16, z21, z1, z6, z11, z14, z19, z24, z4, z9, z7, z12, z17, z22, z2
    SHA3_ROUND z0, z3, z1, z4, z2, z15, z18, z16, z19, z17, z5, z8, z6, z9, z7, z20, z23, z21, z24, z22, z10, z13, z11, z14, z12
    SHA3_ROUND z0, z18, z6, z24, z12, z4, z17, z5, z23, z11, z3, z16, z9, z22, z10, z2, z15, z8, z21, z14, z1, z19, z7, z20, z13
    SHA3_ROUND z0, z17, z9, z21, z13, z24, z11, z3, z15, z7, z18, z5, z22, z14, z1, z12, z4, z16, z8, z20, z6, z23, z10, z2, z19
    SHA3_ROUND z0, z11, z22, z8, z19, z21, z7, z18, z4, z10, z17, z3, z14, z20, z6, z13, z24, z5, z16, z2, z9, z15, z1, z12, z23
    SHA3_ROUND z0, z7, z14, z16, z23, z8, z10, z17, z24, z1, z11, z18, z20, z2, z9, z19, z21, z3, z5, z12, z22, z4, z6, z13, z15
    SHA3_ROUND z0, z10, z20, z5, z15, z16, z1, z11, z21, z6, z7, z17, z2, z12, z22, z23, z8, z18, z3, z13, z14, z24, z9, z19, z4

    st1d    z0.d, p0, [x0, #0, mul vl]
    st1d    z1.d, p0, [x0, #1, mul vl]
    st1d    z2.d, p0, [x0, #2, mul vl]
    st1d    z3.d, p0, [x0, #3, mul vl]
    st1d    z4.d, p0, [x0, #4, mul vl]
    st1d    z5.d, p0, [x0, #5, mul vl]
    st1d    z6.d, p0, [x0, #6, mul vl]
    st1d    z7.d, p0, [x0, #7, mul vl]
    st1d    z8.d, p0, [x5, #0, mul vl]
    st1d    z9.d, p0, [x5, #1, mul vl]
    st1d    z10.d, p0, [x5, #2, mul vl]
    st1d    z11.d, p0, [x5, #3, mul vl]
    st1d    z12.d, p0, [x5, #4, mul vl]
    st1d    z13.d, p0, [x5, #5, mul vl]
    st1d    z14.d, p0, [x5, #6, mul vl]
    st1d    z15.d, p0, [x5, #7, mul vl]
    st1d    z16.d, p0, [x6, #0, mul vl]
    st1d    z17.d, p0, [x6, #1, mul vl]
    st1d    z18.d, p0, [x6, #2, mul vl]
    st1d    z19.d, p0, [x6, #3, mul vl]
    st1d    z20.d, p0, [x6, #4, mul vl]
    st1d    z21.d, p0, [x6, #5, mul vl]
    st1d    z22.d, p0, [x6, #6, mul vl]
    st1d    z23.d, p0, [x6, #7, mul vl]
    st1d    z24.d, p0, [x7]

    ldp     d10, d11, [sp, #16]
    ldp     d12, d13, [sp, #32]
    ldp     d14, d15, [sp, #48]
    ldp     d8, d9, [sp], #64
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(SHA3_Sve2Permute)

.section .rodata
.balign 8
.Lnev_sha3_rc:
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
