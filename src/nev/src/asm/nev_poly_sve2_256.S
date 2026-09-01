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
 * ============================================================================
 * NEV polynomial arithmetic - SVE2 kernels for a 256-bit vector length
 * ============================================================================
 *
 * SVE2 twins of the NEON kernels in nev_poly_armv8.S: same C prototypes with
 * an ...Sve2 suffix, same v2 congruence contract, twice the lanes.  An
 * SVE2-enabled pqcp build selects them at compile time and promises a live
 * vector length of exactly 32 bytes.
 *
 * VL contract: EVERY kernel in this file assumes z registers of exactly
 * 32 bytes (16 h lanes).  Loop pointer increments are hard byte offsets
 * (#32 / #64) and the loop counts divide by 16/32 lanes; running at any other
 * vector length would compute garbage. Enabling the SVE2 backend is therefore
 * a compile-time platform promise that every target runs with VL=256; the glue
 * deliberately performs no runtime feature or vector-length checks.
 *
 * Value semantics are IDENTICAL to the NEON twins, not merely congruent:
 * every kernel below reduces exactly the same integer linear combinations
 * with exactly the same proven-exact primitives (Barrett / full-width
 * Montgomery), and 32-bit accumulation of exact integers is associative, so
 * for every input the outputs are BIT-IDENTICAL to the NEON kernels.  The
 * differential harness asserts this equality; the range table and the
 * congruence proofs of nev_poly_armv8.S therefore carry over verbatim.
 *
 * Modular primitives (per-lane equal to the NEON idioms):
 *
 *  NEV_SVE2_MRP (exact Montgomery reduction of 16 int32 accumulator lanes,
 *  even h-lanes' accumulators in \pe\().s, odd in \po\().s, as produced by
 *  smullb/smullt et al.; the 16 reduced int16 lanes land in \out in original
 *  lane order):
 *      trn1   out.h, pe.h, po.h    // lane-ordered low 16 bits of every P
 *      mul    out.h, out.h, qinv   // m = (int16)(lo16(P) * qinv)
 *      smlslb pe.s, out.h, q       // P -= m*q: low 16 bits become zero
 *      smlslt po.s, out.h, q
 *      trn2   out.h, pe.h, po.h    // lane-ordered high 16 bits of every P
 *  trn1 works because a .s lane viewed as two .h lanes is [lo16, hi16] - an
 *  architectural register-lane fact, independent of memory endianness:
 *  trn1 interleaves pe/po's even h-lanes, i.e.
 *  exactly lo16(P_0), lo16(P_1), ... in original order.  smlslb/t then
 *  multiply the matching even/odd m lanes.  Exact NEV_MontReduce(P) for any
 *  |P| <= 2^31 - 2^15*q - 1 (same bound and argument as NEON's NEV_MRP).
 *  5 instructions per 16 lanes vs NEON's 6 per 8.
 *
 *  NEV_SVE2_BR (exact Barrett reduction of 16 int16 lanes in place):
 *      sqdmulh t.h, x.h, barrettV
 *      srshl   t.h, p0/m, t.h, shvec   // shvec = dup(15 - shift), negative
 *      mls     x.h, p0/m, t.h, q
 *  Same constants, same all-int16 exactness proof as the NEON NEV_BR8.
 *
 *  NEV_SVE2_CADDQ:  asr #15 / and / add — identical to the NEON idiom.
 *
 * Memory access: ld1h/st1h with a governing all-true .h predicate.  These are
 * element-order accesses, so unlike the NEON VLDQ/VSTQ macros they need no
 * big-endian rev/ext fixups: the file is endian-clean by construction.
 *
 * Register discipline: z0-z7 and z16-z27 for data (all caller-saved),
 * z28-z31 for broadcast constants (z31 = q, z30 = qinv, z29 = barrettV,
 * z28 = srshl shift), p0 = all-true .h.  z8-z15 are never written, so no
 * callee-saved (d8-d15) spills anywhere in this file; predicates and ffr are
 * caller-saved for base-AAPCS functions.  GPR use mirrors the NEON file
 * (x0-x17, w9/w10 scratch in the constant loaders).
 *
 * Element counts: n % 32 == 0 for the elementwise/fused kernels, dim % 16 == 0
 * for slot kernels (dim is 64 or 128 at every call site) — the same caller
 * guarantees the NEON file relies on.  Elementwise kernels support in-place
 * operation; slot kernels tolerate r == a / r == b (each 16-slot strip loads
 * all of its inputs before its stores).
 * ============================================================================
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_NEV) && defined(HITLS_CRYPTO_NEV_SVE2)

#include "crypt_arm.h"
#include "nev_arm_asm.h"

CRYPT_AARCH64_ARCH_SVE2

/*
 * Exact Montgomery reduction of 16 int32 accumulator lanes (even-lane
 * accumulators in z\pe\().s, odd in z\po\().s); reduced int16 lanes land in
 * z\out\().h in original lane order.  \out must differ from \pe/\po (both are
 * clobbered).  z31.h must hold q, z30.h qinv.
 */
.macro NEV_SVE2_MRP pe, po, out
    trn1    z\out\().h, z\pe\().h, z\po\().h
    mul     z\out\().h, z\out\().h, z30.h
    smlslb  z\pe\().s, z\out\().h, z31.h
    smlslt  z\po\().s, z\out\().h, z31.h
    trn2    z\out\().h, z\pe\().h, z\po\().h
.endm

/*
 * Exact Barrett reduction of 16 int16 lanes of z\zx in place (z\zt scratch).
 * z31.h = q, z29.h = barrettV, z28.h = 15 - barrettShift (srshl amount).
 */
.macro NEV_SVE2_BR zx, zt
    sqdmulh z\zt\().h, z\zx\().h, z29.h
    srshl   z\zt\().h, p0/m, z\zt\().h, z28.h
    mls     z\zx\().h, p0/m, z\zt\().h, z31.h
.endm

/* Conditional add of q: x += (x >> 15) & q  (z31.h = q, z\zt scratch). */
.macro NEV_SVE2_CADDQ zx, zt
    asr     z\zt\().h, z\zx\().h, #15
    and     z\zt\().d, z\zt\().d, z31.d
    add     z\zx\().h, z\zx\().h, z\zt\().h
.endm

/*
 * Broadcast the packed constants of a qbPacked argument in x\rp:
 * z31.h = q, z30.h = qinv, z29.h = barrettV, z28.h = 15 - shift.
 * Clobbers w9/w10 (callers must not alias them with live arguments).
 */
.macro NEV_SVE2_QB_CONSTS rp
    dup     z31.h, w\rp
    lsr     x9, x\rp, #16
    dup     z30.h, w9
    lsr     x9, x\rp, #32
    dup     z29.h, w9
    lsr     x9, x\rp, #48
    mov     w10, #15
    sub     w9, w10, w9
    dup     z28.h, w9
.endm

/* Broadcast the constants of a qPacked argument in x\rp: z31 = q, z30 = qinv. */
.macro NEV_SVE2_QP_CONSTS rp
    dup     z31.h, w\rp
    lsr     x9, x\rp, #16
    dup     z30.h, w9
.endm

// =============================================================================
// void NEV_AddArrSve2(int16_t *r, const int16_t *a, const int16_t *b,
//                        uint64_t n)
//   r[i] = (int16_t)(a[i] + b[i]), n % 32 == 0
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_AddArrSve2)
AARCH64_PACIASP
    ptrue   p0.h
1:
    ld1h    {z0.h}, p0/z, [x1]
    ld1h    {z1.h}, p0/z, [x1, #1, mul vl]
    ld1h    {z2.h}, p0/z, [x2]
    ld1h    {z3.h}, p0/z, [x2, #1, mul vl]
    add     x1, x1, #64
    add     x2, x2, #64
    add     z0.h, z0.h, z2.h
    add     z1.h, z1.h, z3.h
    st1h    {z0.h}, p0, [x0]
    st1h    {z1.h}, p0, [x0, #1, mul vl]
    add     x0, x0, #64
    subs    x3, x3, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_AddArrSve2)

// =============================================================================
// void NEV_NegArrSve2(int16_t *r, const int16_t *a, uint64_t n)
//   r[i] = (int16_t)(-a[i]), n % 32 == 0
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_NegArrSve2)
AARCH64_PACIASP
    ptrue   p0.h
1:
    ld1h    {z0.h}, p0/z, [x1]
    ld1h    {z1.h}, p0/z, [x1, #1, mul vl]
    add     x1, x1, #64
    neg     z0.h, p0/m, z0.h
    neg     z1.h, p0/m, z1.h
    st1h    {z0.h}, p0, [x0]
    st1h    {z1.h}, p0, [x0, #1, mul vl]
    add     x0, x0, #64
    subs    x2, x2, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_NegArrSve2)

// =============================================================================
// void NEV_CaddqArrSve2(int16_t *r, const int16_t *a, uint64_t n, uint64_t q)
//   r[i] = a[i] + ((a[i] >> 15) & q), n % 32 == 0
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_CaddqArrSve2)
AARCH64_PACIASP
    ptrue   p0.h
    dup     z31.h, w3                   // q
1:
    ld1h    {z0.h}, p0/z, [x1]
    ld1h    {z1.h}, p0/z, [x1, #1, mul vl]
    add     x1, x1, #64
    NEV_SVE2_CADDQ 0, 2
    NEV_SVE2_CADDQ 1, 3
    st1h    {z0.h}, p0, [x0]
    st1h    {z1.h}, p0, [x0, #1, mul vl]
    add     x0, x0, #64
    subs    x2, x2, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_CaddqArrSve2)

// =============================================================================
// void NEV_BarrettArrSve2(int16_t *r, const int16_t *a, uint64_t n,
//                            uint64_t bPacked)
//   r[i] = NEV_BarrettReduce(a[i]); bPacked = q | v << 16 | shift << 32,
//   n % 32 == 0.  Exact for all int16 a[i] (same proof as the NEON twin).
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_BarrettArrSve2)
AARCH64_PACIASP
    ptrue   p0.h
    dup     z31.h, w3                   // q
    lsr     x9, x3, #16
    dup     z29.h, w9                   // barrettV
    lsr     x9, x3, #32
    mov     w10, #15
    sub     w9, w10, w9
    dup     z28.h, w9                   // 15 - shift (srshl amount)
1:
    ld1h    {z0.h}, p0/z, [x1]
    ld1h    {z1.h}, p0/z, [x1, #1, mul vl]
    add     x1, x1, #64
    NEV_SVE2_BR 0, 4
    NEV_SVE2_BR 1, 5
    st1h    {z0.h}, p0, [x0]
    st1h    {z1.h}, p0, [x0, #1, mul vl]
    add     x0, x0, #64
    subs    x2, x2, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_BarrettArrSve2)

// =============================================================================
// void NEV_MontArrSve2(int16_t *r, const int16_t *a, uint64_t n,
//                         uint64_t qPacked)
//   r[i] = NEV_MontReduce((int32_t)a[i]); qPacked = q | qinv << 16,
//   n % 32 == 0.  Exact for all int16 a[i]: m = (int16)(a * qinv) via the
//   wrapping .h multiply, P - m*q accumulated widened (sshllb/t #0 =
//   sign-extension), and the >> 16 realized by the shrnb/t narrowing.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_MontArrSve2)
AARCH64_PACIASP
    ptrue   p0.h
    NEV_SVE2_QP_CONSTS 3
1:
    ld1h    {z0.h}, p0/z, [x1]
    ld1h    {z1.h}, p0/z, [x1, #1, mul vl]
    add     x1, x1, #64
    mul     z4.h, z0.h, z30.h           // m = (int16_t)(a * qinv)
    mul     z5.h, z1.h, z30.h
    sshllb  z16.s, z0.h, #0             // P = (int32_t)a
    sshllt  z17.s, z0.h, #0
    sshllb  z18.s, z1.h, #0
    sshllt  z19.s, z1.h, #0
    smlslb  z16.s, z4.h, z31.h          // P - m * q
    smlslt  z17.s, z4.h, z31.h
    smlslb  z18.s, z5.h, z31.h
    smlslt  z19.s, z5.h, z31.h
    shrnb   z0.h, z16.s, #16            // (P - m * q) >> 16
    shrnt   z0.h, z17.s, #16
    shrnb   z1.h, z18.s, #16
    shrnt   z1.h, z19.s, #16
    st1h    {z0.h}, p0, [x0]
    st1h    {z1.h}, p0, [x0, #1, mul vl]
    add     x0, x0, #64
    subs    x2, x2, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MontArrSve2)

// =============================================================================
// void NEV_AddBarrettArrSve2(int16_t *r, const int16_t *a, const int16_t *b,
//                               uint64_t n, uint64_t qbPacked)
//   r[i] = NEV_BarrettReduce((int16_t)(a[i] + b[i])), n % 32 == 0.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_AddBarrettArrSve2)
AARCH64_PACIASP
    ptrue   p0.h
    NEV_SVE2_QB_CONSTS 4
1:
    ld1h    {z0.h}, p0/z, [x1]
    ld1h    {z1.h}, p0/z, [x1, #1, mul vl]
    ld1h    {z2.h}, p0/z, [x2]
    ld1h    {z3.h}, p0/z, [x2, #1, mul vl]
    add     x1, x1, #64
    add     x2, x2, #64
    add     z0.h, z0.h, z2.h
    add     z1.h, z1.h, z3.h
    NEV_SVE2_BR 0, 4
    NEV_SVE2_BR 1, 5
    st1h    {z0.h}, p0, [x0]
    st1h    {z1.h}, p0, [x0, #1, mul vl]
    add     x0, x0, #64
    subs    x3, x3, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_AddBarrettArrSve2)

// =============================================================================
// void NEV_BarrettCaddqArrSve2(int16_t *r, const int16_t *a, uint64_t n,
//                                 uint64_t qbPacked)
//   r[i] = NEV_Caddq(NEV_BarrettReduce(a[i])), n % 32 == 0.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_BarrettCaddqArrSve2)
AARCH64_PACIASP
    ptrue   p0.h
    NEV_SVE2_QB_CONSTS 3
1:
    ld1h    {z0.h}, p0/z, [x1]
    ld1h    {z1.h}, p0/z, [x1, #1, mul vl]
    add     x1, x1, #64
    NEV_SVE2_BR 0, 4
    NEV_SVE2_BR 1, 5
    NEV_SVE2_CADDQ 0, 4
    NEV_SVE2_CADDQ 1, 5
    st1h    {z0.h}, p0, [x0]
    st1h    {z1.h}, p0, [x0, #1, mul vl]
    add     x0, x0, #64
    subs    x2, x2, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_BarrettCaddqArrSve2)

// =============================================================================
// void NEV_AddBarrettCaddqArrSve2(int16_t *r, const int16_t *a,
//                                    const int16_t *b, uint64_t n,
//                                    uint64_t qbPacked)
//   r[i] = NEV_Caddq(NEV_BarrettReduce((int16_t)(a[i] + b[i]))), n % 32 == 0.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_AddBarrettCaddqArrSve2)
AARCH64_PACIASP
    ptrue   p0.h
    NEV_SVE2_QB_CONSTS 4
1:
    ld1h    {z0.h}, p0/z, [x1]
    ld1h    {z1.h}, p0/z, [x1, #1, mul vl]
    ld1h    {z2.h}, p0/z, [x2]
    ld1h    {z3.h}, p0/z, [x2, #1, mul vl]
    add     x1, x1, #64
    add     x2, x2, #64
    add     z0.h, z0.h, z2.h
    add     z1.h, z1.h, z3.h
    NEV_SVE2_BR 0, 4
    NEV_SVE2_BR 1, 5
    NEV_SVE2_CADDQ 0, 4
    NEV_SVE2_CADDQ 1, 5
    st1h    {z0.h}, p0, [x0]
    st1h    {z1.h}, p0, [x0, #1, mul vl]
    add     x0, x0, #64
    subs    x3, x3, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_AddBarrettCaddqArrSve2)

// =============================================================================
// void NEV_MontCaddqArrSve2(int16_t *r, const int16_t *a, uint64_t n,
//                              uint64_t qPacked)
//   r[i] = NEV_Caddq(NEV_MontReduce((int32_t)a[i])), n % 32 == 0.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_MontCaddqArrSve2)
AARCH64_PACIASP
    ptrue   p0.h
    NEV_SVE2_QP_CONSTS 3
1:
    ld1h    {z0.h}, p0/z, [x1]
    ld1h    {z1.h}, p0/z, [x1, #1, mul vl]
    add     x1, x1, #64
    mul     z4.h, z0.h, z30.h           // m = (int16_t)(a * qinv)
    mul     z5.h, z1.h, z30.h
    sshllb  z16.s, z0.h, #0             // P = (int32_t)a
    sshllt  z17.s, z0.h, #0
    sshllb  z18.s, z1.h, #0
    sshllt  z19.s, z1.h, #0
    smlslb  z16.s, z4.h, z31.h          // P - m * q
    smlslt  z17.s, z4.h, z31.h
    smlslb  z18.s, z5.h, z31.h
    smlslt  z19.s, z5.h, z31.h
    shrnb   z0.h, z16.s, #16            // (P - m * q) >> 16
    shrnt   z0.h, z17.s, #16
    shrnb   z1.h, z18.s, #16
    shrnt   z1.h, z19.s, #16
    NEV_SVE2_CADDQ 0, 4
    NEV_SVE2_CADDQ 1, 5
    st1h    {z0.h}, p0, [x0]
    st1h    {z1.h}, p0, [x0, #1, mul vl]
    add     x0, x0, #64
    subs    x2, x2, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MontCaddqArrSve2)

// =============================================================================
// void NEV_Sub2ArrSve2(int16_t *r, const int16_t *a, const int16_t *b,
//                         const int16_t *c, uint64_t n)
//   r[i] = (int16_t)(a[i] - b[i] - c[i]), n % 32 == 0; wrap-free by caller
//   contract (range table of the NEON file).
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_Sub2ArrSve2)
AARCH64_PACIASP
    ptrue   p0.h
1:
    ld1h    {z0.h}, p0/z, [x1]
    ld1h    {z1.h}, p0/z, [x1, #1, mul vl]
    ld1h    {z2.h}, p0/z, [x2]
    ld1h    {z3.h}, p0/z, [x2, #1, mul vl]
    ld1h    {z4.h}, p0/z, [x3]
    ld1h    {z5.h}, p0/z, [x3, #1, mul vl]
    add     x1, x1, #64
    add     x2, x2, #64
    add     x3, x3, #64
    sub     z0.h, z0.h, z2.h
    sub     z1.h, z1.h, z3.h
    sub     z0.h, z0.h, z4.h
    sub     z1.h, z1.h, z5.h
    st1h    {z0.h}, p0, [x0]
    st1h    {z1.h}, p0, [x0, #1, mul vl]
    add     x0, x0, #64
    subs    x4, x4, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Sub2ArrSve2)

// =============================================================================
// void NEV_Comb4Sve2(int16_t *r, const int16_t *a, const int16_t *b,
//                       const int16_t *c, const int16_t *d, uint64_t n)
//   r[i] = (int16_t)(a[i] + b[i] - c[i] - d[i]), n % 32 == 0; wrap-free by
//   caller contract.  In-place with r == any operand is safe.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_Comb4Sve2)
AARCH64_PACIASP
    ptrue   p0.h
1:
    ld1h    {z0.h}, p0/z, [x1]
    ld1h    {z1.h}, p0/z, [x1, #1, mul vl]
    ld1h    {z2.h}, p0/z, [x2]
    ld1h    {z3.h}, p0/z, [x2, #1, mul vl]
    ld1h    {z4.h}, p0/z, [x3]
    ld1h    {z5.h}, p0/z, [x3, #1, mul vl]
    ld1h    {z6.h}, p0/z, [x4]
    ld1h    {z7.h}, p0/z, [x4, #1, mul vl]
    add     x1, x1, #64
    add     x2, x2, #64
    add     x3, x3, #64
    add     x4, x4, #64
    add     z0.h, z0.h, z2.h
    add     z1.h, z1.h, z3.h
    sub     z0.h, z0.h, z4.h
    sub     z1.h, z1.h, z5.h
    sub     z0.h, z0.h, z6.h
    sub     z1.h, z1.h, z7.h
    st1h    {z0.h}, p0, [x0]
    st1h    {z1.h}, p0, [x0, #1, mul vl]
    add     x0, x0, #64
    subs    x5, x5, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Comb4Sve2)

// =============================================================================
// void NEV_MulYCombSve2(int16_t *r, const int16_t *a, const int16_t *a2,
//                          const int16_t *b, const int16_t *b2,
//                          const int16_t *y, uint64_t geom, uint64_t qbPacked)
//   Per block: r[j] = a[j] s2 a2[j] s1 NEV_MontReduce((b[j] s3 b2[j]) * y[j]);
//   geometry word and semantics identical to NEV_MulYCombAsm (see
//   nev_poly_armv8.S).  dim % 16 == 0.  In-place r == a is safe.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_MulYCombSve2)
AARCH64_PACIASP
    ptrue   p0.h
    NEV_SVE2_QB_CONSTS 7
    ubfx    x8, x6, #0, #16             // dim
    ubfx    x9, x6, #16, #8             // blocks
    ubfx    x10, x6, #24, #16           // rStride (elements)
    sub     x10, x10, x8
    lsl     x10, x10, #1                // (rStride - dim) bytes
    mov     w12, #1
    mov     w13, #-1
    tst     x6, #(1 << 40)
    csel    w14, w13, w12, ne
    dup     z27.h, w14                  // s2 (a2 sign)
    tst     x6, #(1 << 41)
    csel    w14, w13, w12, ne
    dup     z26.h, w14                  // s1 (MR-term sign)
    tst     x6, #(1 << 42)
    csel    w14, w13, w12, ne
    dup     z25.h, w14                  // s3 (b2 sign)
1:
    mov     x14, x5                     // y
    mov     x15, x8                     // dim countdown
2:
    ld1h    {z0.h}, p0/z, [x1]          // a
    ld1h    {z1.h}, p0/z, [x2]          // a2
    ld1h    {z2.h}, p0/z, [x3]          // b
    ld1h    {z3.h}, p0/z, [x4]          // b2
    ld1h    {z4.h}, p0/z, [x14]         // y
    add     x1, x1, #32
    add     x2, x2, #32
    add     x3, x3, #32
    add     x4, x4, #32
    add     x14, x14, #32
    mla     z2.h, p0/m, z3.h, z25.h     // b s3 b2
    smullb  z16.s, z2.h, z4.h
    smullt  z17.s, z2.h, z4.h
    NEV_SVE2_MRP 16, 17, 2
    mla     z0.h, p0/m, z1.h, z27.h     // a s2 a2
    mla     z0.h, p0/m, z2.h, z26.h     // ... s1 MR
    st1h    {z0.h}, p0, [x0]
    add     x0, x0, #32
    subs    x15, x15, #16
    b.ne    2b
    add     x0, x0, x10                 // advance r to next output block
    subs    x9, x9, #1
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MulYCombSve2)

/*
 * MontMul4 core: slot-wise Karatsuba product of two degree-3 slot elements
 * for 16 slots.  Inputs: a0..a3 in z0-z3, b0..b3 in z4-z7 (16 h lanes).
 * Same nine products and per-output raw 32-bit linear combinations as the
 * NEON NEV_MM4CORE (see nev_poly_armv8.S for the formulas and range table);
 * accumulator pairs are (even, odd) lanes from smullb/smullt instead of
 * NEON's (low, high) halves, which changes nothing per lane.
 * Results: r0=z20, r1=z26, r2=z3, r3=z17 (Barrett-normalized), r4=z7,
 * r5=z19, r6=z16.  Clobbers z0-z7, z16-z27; preserves z28-z31 and p0.
 */
.macro NEV_SVE2_MM4CORE
    add     z16.h, z0.h, z1.h           // s01a
    add     z17.h, z2.h, z3.h           // s23a
    add     z18.h, z0.h, z2.h           // A0
    add     z19.h, z1.h, z3.h           // A1
    add     z20.h, z18.h, z19.h         // Sa
    add     z21.h, z4.h, z5.h           // s01b
    add     z22.h, z6.h, z7.h           // s23b
    add     z23.h, z4.h, z6.h           // B0
    add     z24.h, z5.h, z7.h           // B1
    add     z25.h, z23.h, z24.h         // Sb
    smullb  z26.s, z0.h, z4.h           // P0   -> (z26, z27)
    smullt  z27.s, z0.h, z4.h
    smullb  z0.s, z1.h, z5.h            // P1   -> (z0, z4)
    smullt  z4.s, z1.h, z5.h
    smullb  z1.s, z2.h, z6.h            // P2   -> (z1, z5)
    smullt  z5.s, z2.h, z6.h
    smullb  z2.s, z3.h, z7.h            // P3   -> (z2, z6)
    smullt  z6.s, z3.h, z7.h
    smullb  z3.s, z16.h, z21.h          // P01  -> (z3, z7)
    smullt  z7.s, z16.h, z21.h
    smullb  z16.s, z17.h, z22.h         // P23  -> (z16, z21)
    smullt  z21.s, z17.h, z22.h
    smullb  z17.s, z18.h, z23.h         // PA0  -> (z17, z22)
    smullt  z22.s, z18.h, z23.h
    smullb  z18.s, z19.h, z24.h         // PA1  -> (z18, z23)
    smullt  z23.s, z19.h, z24.h
    smullb  z19.s, z20.h, z25.h         // PA01 -> (z19, z24)
    smullt  z24.s, z20.h, z25.h
    sub     z3.s, z3.s, z26.s           // D01 = P01 - P0 - P1
    sub     z7.s, z7.s, z27.s
    sub     z3.s, z3.s, z0.s
    sub     z7.s, z7.s, z4.s
    sub     z16.s, z16.s, z1.s          // D23 = P23 - P2 - P3
    sub     z21.s, z21.s, z5.s
    sub     z16.s, z16.s, z2.s
    sub     z21.s, z21.s, z6.s
    sub     z19.s, z19.s, z17.s         // R3 = PA01 - PA0 - PA1 - D01 - D23
    sub     z24.s, z24.s, z22.s
    sub     z19.s, z19.s, z18.s
    sub     z24.s, z24.s, z23.s
    sub     z19.s, z19.s, z3.s
    sub     z24.s, z24.s, z7.s
    sub     z19.s, z19.s, z16.s
    sub     z24.s, z24.s, z21.s
    sub     z17.s, z17.s, z26.s         // R2 = PA0 - P0 - P2 + P1
    sub     z22.s, z22.s, z27.s
    sub     z17.s, z17.s, z1.s
    sub     z22.s, z22.s, z5.s
    add     z17.s, z17.s, z0.s
    add     z22.s, z22.s, z4.s
    sub     z18.s, z18.s, z0.s          // R4 = PA1 - P1 - P3 + P2
    sub     z23.s, z23.s, z4.s
    sub     z18.s, z18.s, z2.s
    sub     z23.s, z23.s, z6.s
    add     z18.s, z18.s, z1.s
    add     z23.s, z23.s, z5.s
    NEV_SVE2_MRP 26, 27, 20             // r0 -> z20
    NEV_SVE2_MRP 3, 7, 26               // r1 -> z26
    NEV_SVE2_MRP 17, 22, 3              // r2 -> z3
    NEV_SVE2_MRP 19, 24, 17             // r3 -> z17 (pre-Barrett)
    NEV_SVE2_MRP 18, 23, 7              // r4 -> z7
    NEV_SVE2_MRP 16, 21, 19             // r5 -> z19
    NEV_SVE2_MRP 2, 6, 16               // r6 -> z16
    NEV_SVE2_BR 17, 2                   // r3 Barrett-normalized
.endm

// =============================================================================
// void NEV_MontMul4Sve2(int16_t *r, const int16_t *a, const int16_t *b,
//                          uint64_t dim, uint64_t qbPacked, uint64_t dbl)
//   SVE2 twin of NEV_MontMul4Asm: 16 slots per iteration, dim % 16 == 0.
//   dbl == 1 shifts the b strips left by 1 before the core.
//   In-place r == a / r == b is safe.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_MontMul4Sve2)
AARCH64_PACIASP
    ptrue   p0.h
    NEV_SVE2_QB_CONSTS 4
    lsl     x4, x3, #1                  // block stride in bytes
    add     x7, x1, x4                  // a1
    add     x8, x7, x4                  // a2
    add     x9, x8, x4                  // a3
    add     x10, x2, x4                 // b1
    add     x11, x10, x4                // b2
    add     x12, x11, x4                // b3
    add     x13, x0, x4                 // r1
    add     x14, x13, x4                // r2
    add     x15, x14, x4                // r3
    add     x16, x15, x4                // r4
    add     x17, x16, x4                // r5
    add     x4, x17, x4                 // r6
1:
    ld1h    {z0.h}, p0/z, [x1]          // a0
    ld1h    {z1.h}, p0/z, [x7]          // a1
    ld1h    {z2.h}, p0/z, [x8]          // a2
    ld1h    {z3.h}, p0/z, [x9]          // a3
    ld1h    {z4.h}, p0/z, [x2]          // b0
    ld1h    {z5.h}, p0/z, [x10]         // b1
    ld1h    {z6.h}, p0/z, [x11]         // b2
    ld1h    {z7.h}, p0/z, [x12]         // b3
    add     x1, x1, #32
    add     x7, x7, #32
    add     x8, x8, #32
    add     x9, x9, #32
    add     x2, x2, #32
    add     x10, x10, #32
    add     x11, x11, #32
    add     x12, x12, #32
    cbz     x5, 2f
    lsl     z4.h, z4.h, #1              // (2b) for the dbl variant
    lsl     z5.h, z5.h, #1
    lsl     z6.h, z6.h, #1
    lsl     z7.h, z7.h, #1
2:
    NEV_SVE2_MM4CORE
    st1h    {z20.h}, p0, [x0]           // r0
    st1h    {z26.h}, p0, [x13]          // r1
    st1h    {z3.h}, p0, [x14]           // r2
    st1h    {z17.h}, p0, [x15]          // r3
    st1h    {z7.h}, p0, [x16]           // r4
    st1h    {z19.h}, p0, [x17]          // r5
    st1h    {z16.h}, p0, [x4]           // r6
    add     x0, x0, #32
    add     x13, x13, #32
    add     x14, x14, #32
    add     x15, x15, #32
    add     x16, x16, #32
    add     x17, x17, #32
    add     x4, x4, #32
    subs    x3, x3, #16
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MontMul4Sve2)

// =============================================================================
// void NEV_PolyMulRed4Sve2(int16_t *r, const int16_t *a, const int16_t *b,
//                             const int16_t *y, uint64_t dim, uint64_t qbPacked)
//   SVE2 twin of NEV_PolyMulRed4Asm: MontMul4 core plus the in-register fold
//   r_j = c_j + MR(c_{4+j} * y) (j = 0..2), r_3 = c_3; 16 slots per iteration.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_PolyMulRed4Sve2)
AARCH64_PACIASP
    ptrue   p0.h
    NEV_SVE2_QB_CONSTS 5
    lsl     x5, x4, #1                  // block stride in bytes
    mov     x17, x4                     // countdown
    add     x7, x1, x5                  // a1
    add     x8, x7, x5                  // a2
    add     x9, x8, x5                  // a3
    add     x10, x2, x5                 // b1
    add     x11, x10, x5                // b2
    add     x12, x11, x5                // b3
    add     x13, x0, x5                 // r1
    add     x14, x13, x5                // r2
    add     x15, x14, x5                // r3
1:
    ld1h    {z0.h}, p0/z, [x1]
    ld1h    {z1.h}, p0/z, [x7]
    ld1h    {z2.h}, p0/z, [x8]
    ld1h    {z3.h}, p0/z, [x9]
    ld1h    {z4.h}, p0/z, [x2]
    ld1h    {z5.h}, p0/z, [x10]
    ld1h    {z6.h}, p0/z, [x11]
    ld1h    {z7.h}, p0/z, [x12]
    add     x1, x1, #32
    add     x7, x7, #32
    add     x8, x8, #32
    add     x9, x9, #32
    add     x2, x2, #32
    add     x10, x10, #32
    add     x11, x11, #32
    add     x12, x12, #32
    NEV_SVE2_MM4CORE
    // c0=z20 c1=z26 c2=z3 c3=z17 c4=z7 c5=z19 c6=z16; fold c4..c6 by y
    ld1h    {z0.h}, p0/z, [x3]          // y
    add     x3, x3, #32
    smullb  z1.s, z7.h, z0.h            // MR(c4 * y)
    smullt  z2.s, z7.h, z0.h
    NEV_SVE2_MRP 1, 2, 7
    add     z20.h, z20.h, z7.h
    smullb  z1.s, z19.h, z0.h           // MR(c5 * y)
    smullt  z2.s, z19.h, z0.h
    NEV_SVE2_MRP 1, 2, 19
    add     z26.h, z26.h, z19.h
    smullb  z1.s, z16.h, z0.h           // MR(c6 * y)
    smullt  z2.s, z16.h, z0.h
    NEV_SVE2_MRP 1, 2, 16
    add     z3.h, z3.h, z16.h
    st1h    {z20.h}, p0, [x0]           // r0
    st1h    {z26.h}, p0, [x13]          // r1
    st1h    {z3.h}, p0, [x14]           // r2
    st1h    {z17.h}, p0, [x15]          // r3
    add     x0, x0, #32
    add     x13, x13, #32
    add     x14, x14, #32
    add     x15, x15, #32
    subs    x17, x17, #16
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_PolyMulRed4Sve2)

// =============================================================================
// void NEV_MontSquare4Sve2(int16_t *r, const int16_t *a, uint64_t dim,
//                             uint64_t qPacked)
//   SVE2 twin of NEV_MontSquare4Asm (same product formulas), 16 slots per
//   iteration, dim % 16 == 0.  In-place r == a is safe.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_MontSquare4Sve2)
AARCH64_PACIASP
    ptrue   p0.h
    NEV_SVE2_QP_CONSTS 3
    lsl     x4, x2, #1                  // block stride in bytes
    add     x5, x1, x4                  // a1
    add     x6, x5, x4                  // a2
    add     x7, x6, x4                  // a3
    add     x8, x0, x4                  // r1
    add     x9, x8, x4                  // r2
    add     x10, x9, x4                 // r3
    add     x11, x10, x4                // r4
    add     x12, x11, x4                // r5
    add     x13, x12, x4                // r6
1:
    ld1h    {z0.h}, p0/z, [x1]          // a0
    ld1h    {z1.h}, p0/z, [x5]          // a1
    ld1h    {z2.h}, p0/z, [x6]          // a2
    ld1h    {z3.h}, p0/z, [x7]          // a3
    add     x1, x1, #32
    add     x5, x5, #32
    add     x6, x6, #32
    add     x7, x7, #32
    lsl     z4.h, z0.h, #1              // 2 a0
    lsl     z5.h, z1.h, #1              // 2 a1
    lsl     z6.h, z2.h, #1              // 2 a2
    add     z7.h, z2.h, z3.h            // a2 + a3
    add     z16.h, z4.h, z5.h           // 2 a0 + 2 a1
    smullb  z17.s, z0.h, z0.h           // o0: a0^2
    smullt  z18.s, z0.h, z0.h
    smullb  z19.s, z4.h, z1.h           // o1: 2 a0 a1
    smullt  z20.s, z4.h, z1.h
    smullb  z21.s, z1.h, z1.h           // o2: a1^2 + 2 a0 a2
    smullt  z22.s, z1.h, z1.h
    smlalb  z21.s, z4.h, z2.h
    smlalt  z22.s, z4.h, z2.h
    smullb  z23.s, z16.h, z7.h          // o3: (2a0+2a1)(a2+a3) - 2a1a3 - 2a0a2
    smullt  z24.s, z16.h, z7.h
    smlslb  z23.s, z5.h, z3.h
    smlslt  z24.s, z5.h, z3.h
    smlslb  z23.s, z4.h, z2.h
    smlslt  z24.s, z4.h, z2.h
    smullb  z25.s, z5.h, z3.h           // o4: 2 a1 a3 + a2^2
    smullt  z26.s, z5.h, z3.h
    smlalb  z25.s, z2.h, z2.h
    smlalt  z26.s, z2.h, z2.h
    smullb  z0.s, z6.h, z3.h            // o5: 2 a2 a3
    smullt  z1.s, z6.h, z3.h
    smullb  z2.s, z3.h, z3.h            // o6: a3^2
    smullt  z4.s, z3.h, z3.h
    NEV_SVE2_MRP 17, 18, 5              // o0 -> z5
    NEV_SVE2_MRP 19, 20, 6              // o1 -> z6
    NEV_SVE2_MRP 21, 22, 16             // o2 -> z16
    NEV_SVE2_MRP 23, 24, 7              // o3 -> z7
    NEV_SVE2_MRP 25, 26, 19             // o4 -> z19
    NEV_SVE2_MRP 0, 1, 21               // o5 -> z21
    NEV_SVE2_MRP 2, 4, 23               // o6 -> z23
    st1h    {z5.h}, p0, [x0]            // o0
    st1h    {z6.h}, p0, [x8]            // o1
    st1h    {z16.h}, p0, [x9]           // o2
    st1h    {z7.h}, p0, [x10]           // o3
    st1h    {z19.h}, p0, [x11]          // o4
    st1h    {z21.h}, p0, [x12]          // o5
    st1h    {z23.h}, p0, [x13]          // o6
    add     x0, x0, #32
    add     x8, x8, #32
    add     x9, x9, #32
    add     x10, x10, #32
    add     x11, x11, #32
    add     x12, x12, #32
    add     x13, x13, #32
    subs    x2, x2, #16
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MontSquare4Sve2)

// =============================================================================
// void NEV_MontMul8TailSve2(int16_t *r, const int16_t *t1, uint64_t dim,
//                              uint64_t qbPacked)
//   SVE2 twin of NEV_MontMul8TailAsm (same row formulas and pass structure),
//   16 lanes per iteration, dim % 16 == 0.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_MontMul8TailSve2)
AARCH64_PACIASP
    ptrue   p0.h
    NEV_SVE2_QB_CONSTS 3
    lsl     x3, x2, #1                  // dim bytes
    // pass A: r7 = Barrett(t1_3 - r3 - r11)
    add     x4, x1, x3, lsl #1
    add     x4, x4, x3                  // t1_3
    add     x5, x0, x3, lsl #1
    add     x5, x5, x3                  // r3
    add     x6, x0, x3, lsl #3
    add     x6, x6, x3, lsl #1
    add     x6, x6, x3                  // r11
    add     x7, x0, x3, lsl #2
    add     x7, x7, x3, lsl #1
    add     x7, x7, x3                  // r7
    mov     x8, x2
1:
    ld1h    {z0.h}, p0/z, [x4]
    ld1h    {z1.h}, p0/z, [x5]
    ld1h    {z2.h}, p0/z, [x6]
    add     x4, x4, #32
    add     x5, x5, #32
    add     x6, x6, #32
    sub     z0.h, z0.h, z1.h
    sub     z0.h, z0.h, z2.h
    NEV_SVE2_BR 0, 4
    st1h    {z0.h}, p0, [x7]
    add     x7, x7, #32
    subs    x8, x8, #16
    b.ne    1b
    // pass B, i = 0..2: r4+i and r8+i rows
    mov     x17, #0                     // i
2:
    madd    x4, x17, x3, x0             // r_i
    add     x5, x4, x3, lsl #2          // r_{4+i}
    add     x6, x5, x3, lsl #2          // r_{8+i}
    add     x7, x6, x3, lsl #2          // r_{12+i}
    madd    x8, x17, x3, x1             // t1_i
    add     x9, x8, x3, lsl #2          // t1_{4+i}
    mov     x10, x2
3:
    ld1h    {z0.h}, p0/z, [x4]          // r_i
    ld1h    {z1.h}, p0/z, [x5]          // r_{4+i}   (read, then written)
    ld1h    {z2.h}, p0/z, [x6]          // r_{8+i}   (read, then written)
    ld1h    {z3.h}, p0/z, [x7]          // r_{12+i}
    ld1h    {z16.h}, p0/z, [x8]         // t1_i
    ld1h    {z17.h}, p0/z, [x9]         // t1_{4+i}
    add     x4, x4, #32
    add     x7, x7, #32
    add     x8, x8, #32
    add     x9, x9, #32
    add     z18.h, z1.h, z16.h          // r4' = r_{4+i} + t1_i - r_i - r_{8+i}
    sub     z18.h, z18.h, z0.h
    sub     z18.h, z18.h, z2.h
    sub     z19.h, z17.h, z1.h          // r8' = t1_{4+i} - r_{4+i} - r_{12+i} + r_{8+i}
    sub     z19.h, z19.h, z3.h
    add     z19.h, z19.h, z2.h
    NEV_SVE2_BR 18, 4
    NEV_SVE2_BR 19, 4
    st1h    {z18.h}, p0, [x5]
    st1h    {z19.h}, p0, [x6]
    add     x5, x5, #32
    add     x6, x6, #32
    subs    x10, x10, #16
    b.ne    3b
    add     x17, x17, #1
    cmp     x17, #3
    b.ne    2b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MontMul8TailSve2)

// =============================================================================
// void NEV_Inv4NormSve2(int16_t *a20, int16_t *a21, int16_t *s,
//                          const int16_t *a, const int16_t *y, uint64_t dim,
//                          uint64_t qbPacked)
//   SVE2 twin of NEV_Inv4NormAsm (same MR chains), 16 slots per iteration.
//   s = Caddq(Barrett(...)) stays bit-identical to the reference (exactness
//   island for the zero-test), exactly as in the NEON kernel.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_Inv4NormSve2)
AARCH64_PACIASP
    ptrue   p0.h
    NEV_SVE2_QB_CONSTS 6
    lsl     x8, x5, #1                  // block stride in bytes
    add     x9, x3, x8                  // a1
    add     x10, x9, x8                 // a2
    add     x11, x10, x8                // a3
1:
    ld1h    {z0.h}, p0/z, [x3]          // t0
    ld1h    {z1.h}, p0/z, [x9]          // t1
    ld1h    {z2.h}, p0/z, [x10]         // t2
    ld1h    {z3.h}, p0/z, [x11]         // t3
    ld1h    {z4.h}, p0/z, [x4]          // y
    add     x3, x3, #32
    add     x9, x9, #32
    add     x10, x10, #32
    add     x11, x11, #32
    add     x4, x4, #32
    lsl     z16.h, z1.h, #1             // 2 t1
    lsl     z17.h, z0.h, #1             // 2 t0
    smullb  z26.s, z2.h, z2.h           // X1 = MR(t2^2 - 2 t1 t3)
    smullt  z27.s, z2.h, z2.h
    smlslb  z26.s, z16.h, z3.h
    smlslt  z27.s, z16.h, z3.h
    NEV_SVE2_MRP 26, 27, 5
    smullb  z26.s, z5.h, z4.h           // X2 = MR(X1 * y)
    smullt  z27.s, z5.h, z4.h
    NEV_SVE2_MRP 26, 27, 6
    smullb  z26.s, z0.h, z0.h           // T00 = MR(t0^2)
    smullt  z27.s, z0.h, z0.h
    NEV_SVE2_MRP 26, 27, 5
    add     z6.h, z6.h, z5.h            // a2_0
    smullb  z26.s, z17.h, z2.h          // Y1 = MR(2 t0 t2 - t1^2)
    smullt  z27.s, z17.h, z2.h
    smlslb  z26.s, z1.h, z1.h
    smlslt  z27.s, z1.h, z1.h
    NEV_SVE2_MRP 26, 27, 5
    smullb  z26.s, z3.h, z3.h           // MR(t3^2)
    smullt  z27.s, z3.h, z3.h
    NEV_SVE2_MRP 26, 27, 7
    smullb  z26.s, z7.h, z4.h           // Y2 = MR(MR(t3^2) * y)
    smullt  z27.s, z7.h, z4.h
    NEV_SVE2_MRP 26, 27, 7
    sub     z5.h, z5.h, z7.h            // a2_1
    smullb  z26.s, z6.h, z6.h           // T6 = MR(a2_0^2)
    smullt  z27.s, z6.h, z6.h
    NEV_SVE2_MRP 26, 27, 7
    smullb  z26.s, z5.h, z5.h           // MR(a2_1^2)
    smullt  z27.s, z5.h, z5.h
    NEV_SVE2_MRP 26, 27, 16
    smullb  z26.s, z16.h, z4.h          // T7 = MR(MR(a2_1^2) * y)
    smullt  z27.s, z16.h, z4.h
    NEV_SVE2_MRP 26, 27, 16
    sub     z7.h, z7.h, z16.h           // s = T6 - T7 (wrap-free)
    NEV_SVE2_BR 7, 17                   // exact Barrett (canonical centered)
    NEV_SVE2_CADDQ 7, 17
    st1h    {z6.h}, p0, [x0]            // a2_0
    st1h    {z5.h}, p0, [x1]            // a2_1
    st1h    {z7.h}, p0, [x2]            // s
    add     x0, x0, #32
    add     x1, x1, #32
    add     x2, x2, #32
    subs    x5, x5, #16
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Inv4NormSve2)

// =============================================================================
// void NEV_Inv4FinishSve2(int16_t *r, const int16_t *a, const int16_t *a20,
//                            const int16_t *a21, const int16_t *sInv,
//                            const int16_t *y, uint64_t dim, uint64_t qbPacked)
//   SVE2 twin of NEV_Inv4FinishAsm (same MR chains and output Barretts),
//   16 slots per iteration, dim % 16 == 0.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_Inv4FinishSve2)
AARCH64_PACIASP
    ptrue   p0.h
    NEV_SVE2_QB_CONSTS 7
    lsl     x8, x6, #1                  // block stride in bytes
    add     x9, x1, x8                  // a1
    add     x10, x9, x8                 // a2
    add     x11, x10, x8                // a3
    add     x12, x0, x8                 // r1
    add     x13, x12, x8                // r2
    add     x14, x13, x8                // r3
1:
    ld1h    {z0.h}, p0/z, [x1]          // t0
    ld1h    {z1.h}, p0/z, [x9]          // t1
    ld1h    {z2.h}, p0/z, [x10]         // t2
    ld1h    {z3.h}, p0/z, [x11]         // t3
    ld1h    {z4.h}, p0/z, [x2]          // a20
    ld1h    {z5.h}, p0/z, [x3]          // a21
    ld1h    {z6.h}, p0/z, [x4]          // sInv
    ld1h    {z7.h}, p0/z, [x5]          // y
    add     x1, x1, #32
    add     x9, x9, #32
    add     x10, x10, #32
    add     x11, x11, #32
    add     x2, x2, #32
    add     x3, x3, #32
    add     x4, x4, #32
    add     x5, x5, #32
    smullb  z26.s, z4.h, z6.h           // t4 = MR(a20 * s)
    smullt  z27.s, z4.h, z6.h
    NEV_SVE2_MRP 26, 27, 16
    smullb  z26.s, z5.h, z6.h           // t5 = MR(a21 * s)
    smullt  z27.s, z5.h, z6.h
    NEV_SVE2_MRP 26, 27, 17
    smullb  z26.s, z0.h, z16.h          // t6 = MR(t0 * t4)
    smullt  z27.s, z0.h, z16.h
    NEV_SVE2_MRP 26, 27, 18
    smullb  z26.s, z1.h, z16.h          // t7 = MR(t1 * t4)
    smullt  z27.s, z1.h, z16.h
    NEV_SVE2_MRP 26, 27, 19
    add     z20.h, z0.h, z2.h           // t0 + t2
    sub     z21.h, z16.h, z17.h         // t4 - t5
    smullb  z26.s, z20.h, z21.h         // u0
    smullt  z27.s, z20.h, z21.h
    NEV_SVE2_MRP 26, 27, 20
    sub     z21.h, z1.h, z3.h           // t1 - t3
    add     z22.h, z16.h, z17.h         // t4 + t5
    smullb  z26.s, z21.h, z22.h         // u1
    smullt  z27.s, z21.h, z22.h
    NEV_SVE2_MRP 26, 27, 21
    smullb  z26.s, z2.h, z17.h          // t2' = MR(t2 * t5)
    smullt  z27.s, z2.h, z17.h
    NEV_SVE2_MRP 26, 27, 22
    smullb  z26.s, z3.h, z17.h          // t3' = MR(t3 * t5)
    smullt  z27.s, z3.h, z17.h
    NEV_SVE2_MRP 26, 27, 23
    smullb  z26.s, z22.h, z7.h          // t4'' = MR(t2' * y)
    smullt  z27.s, z22.h, z7.h
    NEV_SVE2_MRP 26, 27, 24
    smullb  z26.s, z23.h, z7.h          // t5'' = MR(t3' * y)
    smullt  z27.s, z23.h, z7.h
    NEV_SVE2_MRP 26, 27, 25
    sub     z26.h, z18.h, z24.h         // r0 = t6 - t4''
    NEV_SVE2_BR 26, 0
    st1h    {z26.h}, p0, [x0]
    add     x0, x0, #32
    sub     z24.h, z25.h, z19.h         // r1 = t5'' - t7
    NEV_SVE2_BR 24, 0
    st1h    {z24.h}, p0, [x12]
    add     x12, x12, #32
    sub     z27.h, z20.h, z18.h         // r2 = u0 - t6 + t2'
    add     z27.h, z27.h, z22.h
    NEV_SVE2_BR 27, 0
    st1h    {z27.h}, p0, [x13]
    add     x13, x13, #32
    sub     z25.h, z21.h, z19.h         // r3 = u1 - t7 + t3'
    add     z25.h, z25.h, z23.h
    NEV_SVE2_BR 25, 0
    st1h    {z25.h}, p0, [x14]
    add     x14, x14, #32
    subs    x6, x6, #16
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Inv4FinishSve2)

#endif // HITLS_CRYPTO_NEV && HITLS_CRYPTO_NEV_SVE2

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
