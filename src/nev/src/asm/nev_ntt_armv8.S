/*
 * based on https://eprint.iacr.org/2021/986, CC0 1.0 Universal.
 *
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
 * NEV per-block negacyclic NTT — ARMv8 NEON implementation (v2)
 * ============================================================================
 *
 * NEON port of the per-block transforms in crypto/nev/src/nev_ntt.c under the
 * v2 congruence contract: every packed interface byte and every invertibility
 * decision is identical to the generic C backend, while internal
 * representatives only need to be congruent mod q within proven int16 ranges.
 * The synchronization points are the exact Barrett passes (proven, for all
 * 65536 int16 inputs and all three q, to return the unique centered
 * representative of the residue class): the forward kernel ends with one, so
 * its block output is BIT-IDENTICAL to the C forward NTT; the inverse kernel
 * output is congruent with |x| <= 0.91*q < q, which the downstream unique
 * canonicalizers (NEV_PolyGetMontgomery's MontReduce, exact-centering for
 * |x| <= q-1, and NEV_PolyToMsg's FlipAbs/Caddq, unique for |x| < q) map to
 * the same bytes as the C output.
 *
 * One kernel invocation transforms ONE contiguous block of nttDim int16
 * coefficients in place (the C caller loops over the n / nttDim blocks):
 *   - dim 128 (q = 769 and q = 3329): 256 bytes = 16 NEON q-registers
 *   - dim  64 (q = 1409):             128 bytes =  8 NEON q-registers
 * so a whole block is loaded into v16..v31 (or v16..v23), all butterfly
 * layers run fully in registers, and the block is stored once at the end.
 *
 * Kernels (block pointer in x0, twiddle table pointer in x1):
 *   NEV_NTT128_Q769 / NEV_NTT128_Q3329 / NEV_NTT64_Q1409    forward
 *   NEV_INTT128_Q769 / NEV_INTT128_Q3329 / NEV_INTT64_Q1409 inverse
 *
 * Twiddle multiply (the ML-KEM 3-instruction Barrett multiply, see
 * ml_kem_ntt_armv8.S; twiddles are (root, root_hi) pairs, root the centered
 * PLAIN twiddle z_mont * 2^-16 mod q, root_hi = round_even(root*2^16/q)/2):
 *     mul      lo.8h, a.8h, root       // low 16 bits of a * root
 *     sqrdmulh hi.8h, a.8h, root_hi    // hi = round(a * root_hi / 2^15)
 *                                      //    ~ round(a * root / q)
 *     mls      lo.8h, hi.8h, q         // lo = a * root - hi * q  (exact:
 *                                      //    the value fits in int16, below)
 *   Properties (verified exhaustively per table entry over all int16 a by the
 *   generator in asm_nev_ntt.c):
 *     mm3(a) === a * root === NEV_FqMul(z_mont, a)  (mod q)
 *     |mm3(a)| <= q/2 + q*|a|/2^16   (so always < q for |a| < 2^15)
 *     mm3(a) - NEV_FqMul(z_mont, a) in {-q, 0, +q}, non-zero only at
 *     sqrdmulh rounding ties
 *   No sqrdmulh saturation: |root_hi| <= 2^14 + 1, never -2^15.
 *
 * Exact Barrett reduction (unchanged from v1 — the proven synchronization
 * primitive; per-q (barrettV, srshr shift) = (21817,9)/(23814,10)/(20159,11)):
 *   C: t = (int16)((barrettV * a + 2^(shift-1)) >> shift); r = a - t * q.
 *   NEON, with barrettV in v0.h[1] and q in v0.h[0]:
 *     sqdmulh  t.8h, a.8h, barrettV    // (2 * a * v) >> 16 = (a*v) >> 15
 *     srshr    t.8h, t.8h, #(shift-15)
 *     mls      a.8h, t.8h, q
 *   Matches NEV_BarrettReduce bit-for-bit for ALL int16 a (proven by
 *   exhaustive sweep, see asm_nev_ntt.c) and returns the unique centered
 *   representative |r| <= (q-1)/2 of the class of a.
 *
 * Layer scheme, forward dim 128 (dim 64 drops the len=64 layer):
 *   len 64/32/16/8: butterflies pair whole registers; twiddles are scalar
 *     (root, root_hi) lane pairs preloaded in v0.h[2..7], v1, v2, v3.
 *   len 4/2/1: each aligned run of 4 registers (32 coefficients) is passed
 *     through a 32-bit 4x4 transpose (trn1/trn2 .4s/.2d), which turns len=4
 *     and len=2 into whole-register butterflies with per-lane twiddle
 *     vectors; an extra .8h trn1/trn2 pairing splits even/odd lanes for
 *     len=1.  The final exact Barrett pass runs in the transposed domain
 *     (it is lane-wise), then the transposes are undone and the group is
 *     stored.  DO NOT weaken or move this pass: it is the sync point that
 *     makes the forward output bit-identical to C.
 *
 * Forward range chain (per-layer X_k <= X_{k-1} + q/2 + q*X_{k-1}/2^16,
 * inputs |x| <= q - 1: noise, noise + v^-1, or decompressed/unpacked
 * coefficients in [0, q), as for the C backend):
 *   q = 769  (7 layers):  768 -> 1162 -> 1560 -> 1962 -> 2370 -> 2782
 *                             -> 3199 -> 3622
 *   q = 1409 (6 layers): 1408 -> 2143 -> 2894 -> 3661 -> 4444 -> 5244 -> 6061
 *   q = 3329 (7 layers): 3328 -> 5162 -> 7089 -> 9113 -> 11241 -> 13476
 *                             -> 15825 -> 18294
 * All < 2^15: no int16 overflow anywhere, and the Barrett input is inside the
 * exhaustively proven all-int16 domain.
 *
 * Inverse transform (mirrors the lazy Plantard InvNttBlock of nev_ntt.c):
 *   - len 1/2/4 (transposed groups): lazy Gentleman-Sande —
 *     d = b - a; a' = a + b; b' = mm3(d, root) — NO per-butterfly Barrett,
 *     then ONE exact Barrett pass over the whole group while still in the
 *     transposed domain (the C backend's single pass after the first three
 *     layers, restricted to this group's lanes).
 *   - len 8 .. dim/4: lazy GS, no reductions.
 *   - last layer (len dim/2) fused with the mont^2/dim scaling, replacing
 *     both the v1 GS layer and the whole v1 scale pass: per pair,
 *     out_a = mm3(a + b, fP), out_b = mm3(b - a, fzetaP), stores issued here.
 *     fP = mod+-(2^16/dim mod q) and fzetaP = mod+-(fP * zeta1_plain mod q)
 *     are the int16 plain forms of NEV_INTT_F_PLANTARD_* /
 *     NEV_INTT_FZETA_PLANTARD_* (nev_ntt.c); their (root, root_hi) pairs are
 *     materialized with movz/movk immediates into v1.h[0..3] (no table tail).
 *   Inverse range chain (inputs |x| <= M = (q-1)/2: both call sites,
 *   OwPkeEncDet and OwPkeDec in nev_kem.c, invoke NEV_PolyInvNtt immediately
 *   after NEV_PolyReduce):
 *     len 1/2/4 lazy:   sums <= 8M = 4(q-1) <= 13312, mm3 legs <= 0.71*q
 *                       (int16 ok; Barrett input inside the proven domain)
 *     Barrett pass:     |x| <= M
 *     len 8..dim/4:     <= 8M (dim 128; <= 4M for dim 64) after <= 3 layers
 *     fused last layer: |a+b|, |b-a| <= 16M = 8(q-1) <= 26624 (int16 ok)
 *     outputs:          |x| <= q/2 + q*16M/2^16 <= 0.91*q <= q - 1
 *                       (457 / 947 / 3017 for q = 769 / 1409 / 3329)
 *   Every output leg passes through a final mm3, so |out| <= q - 1 holds for
 *   the whole block — exactly the precondition under which the downstream
 *   canonicalizers return unique representatives (identical packed bytes and
 *   recovered messages).
 *
 * Scheduling (wall-clock; identical retired-instruction count):
 *   - EVERY stage of every layer issues 4 independent butterfly chains
 *     (4x mul, 4x sqrdmulh, 4x mls, 4x sub, 4x add) so the multiply latency
 *     is always hidden by independent work, mirroring MLKEM_NTT_top and the
 *     MLDSA_CT4 batched macros: the whole-register layers batch 4 register
 *     pairs, and the transposed len=4/2/1 stages (which expose only 2
 *     independent chains per 4-register run) process TWO data-independent
 *     runs fused per macro (NEV_NTT_GRP2/NEV_INTT_GRP2), as do the Barrett
 *     passes (8-wide) and the fused final scale layer (NEV_GSF4);
 *   - the initial block loads of the b-half registers issue first and the
 *     a-half loads are stuffed into the first layer's multiply shadows
 *     (forward), or ahead of the group pair that consumes them (inverse);
 *   - inside the transposed groups every VLDQ of the next stage's twiddle
 *     vectors is issued in the current stage's multiply shadow, twiddle hi
 *     halves reloading the registers their lo halves occupied;
 *   - the fused group pairs are fully data-independent; stores issue per
 *     group pair.
 *
 * Register allocation (all kernels):
 *   v0.h[0] = q, v0.h[1] = barrettV, v0.h[2..7]/v1/v2/v3 = scalar twiddle
 *   lane pairs (inverse: v1.h[0..3] = fP, fP_hi, fzetaP, fzetaP_hi during the
 *   fused last layer), v4..v7 = stage temporaries, v8..v13 = per-group
 *   twiddle vectors and even/odd split registers, v16..v31 (dim 128) or
 *   v16..v23 (dim 64) = block data.
 *   x0 = block pointer, x1 = table pointer, w9/x9 = immediate scratch.
 * ============================================================================
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_NEV

#include "crypt_arm.h"
#include "nev_arm_asm.h"

CRYPT_AARCH64_ARCH_BASE

// ----------------------------------------------------------------------------
// Building-block macros.  Vector registers are passed as bare numbers so the
// same argument feeds both arithmetic (v\n) and the VLDQ/VSTQ_8H helpers.
// ----------------------------------------------------------------------------

// 32-bit-granularity 4x4 transpose of v\d0..v\d3 in place (rows of 32-bit
// coefficient pairs become columns).  Applying it twice restores the layout.
.macro NEV_TRN4 d0, d1, d2, d3, t0, t1, t2, t3
    trn1    v\t0\().4s, v\d0\().4s, v\d1\().4s
    trn2    v\t1\().4s, v\d0\().4s, v\d1\().4s
    trn1    v\t2\().4s, v\d2\().4s, v\d3\().4s
    trn2    v\t3\().4s, v\d2\().4s, v\d3\().4s
    trn1    v\d0\().2d, v\t0\().2d, v\t2\().2d
    trn2    v\d2\().2d, v\t0\().2d, v\t2\().2d
    trn1    v\d1\().2d, v\t1\().2d, v\t3\().2d
    trn2    v\d3\().2d, v\t1\().2d, v\t3\().2d
.endm

// Same 4x4 transpose with separate source and destination registers (the
// second trn layer reads only the temporaries, so the destinations are a
// free choice).  Same 8-instruction cost as NEV_TRN4.
.macro NEV_TRN4_D s0, s1, s2, s3, t0, t1, t2, t3, d0, d1, d2, d3
    trn1    v\t0\().4s, v\s0\().4s, v\s1\().4s
    trn2    v\t1\().4s, v\s0\().4s, v\s1\().4s
    trn1    v\t2\().4s, v\s2\().4s, v\s3\().4s
    trn2    v\t3\().4s, v\s2\().4s, v\s3\().4s
    trn1    v\d0\().2d, v\t0\().2d, v\t2\().2d
    trn2    v\d2\().2d, v\t0\().2d, v\t2\().2d
    trn1    v\d1\().2d, v\t1\().2d, v\t3\().2d
    trn2    v\d3\().2d, v\t1\().2d, v\t3\().2d
.endm

// Two independent in-place 4x4 transposes with the trn layers interleaved
// 8-wide (group A temps v4-v7, group B temps v8-v11).  2x8 instructions,
// identical to two NEV_TRN4.
.macro NEV_TRN4X2 a0, a1, a2, a3, b0, b1, b2, b3
    trn1    v4.4s, v\a0\().4s, v\a1\().4s
    trn2    v5.4s, v\a0\().4s, v\a1\().4s
    trn1    v6.4s, v\a2\().4s, v\a3\().4s
    trn2    v7.4s, v\a2\().4s, v\a3\().4s
    trn1    v8.4s, v\b0\().4s, v\b1\().4s
    trn2    v9.4s, v\b0\().4s, v\b1\().4s
    trn1    v10.4s, v\b2\().4s, v\b3\().4s
    trn2    v11.4s, v\b2\().4s, v\b3\().4s
    trn1    v\a0\().2d, v4.2d, v6.2d
    trn2    v\a2\().2d, v4.2d, v6.2d
    trn1    v\a1\().2d, v5.2d, v7.2d
    trn2    v\a3\().2d, v5.2d, v7.2d
    trn1    v\b0\().2d, v8.2d, v10.2d
    trn2    v\b2\().2d, v8.2d, v10.2d
    trn1    v\b1\().2d, v9.2d, v11.2d
    trn2    v\b3\().2d, v9.2d, v11.2d
.endm

// Four Cooley-Tukey butterflies with scalar lane twiddles, stage-wise
// (temps v4..v7):  t = mm3(b, root); b' = a - t; a' = a + t
// z*/l*/h* select the (root, root_hi) lane pair of one twiddle register.
.macro NEV_CT4L a0, b0, z0, l0, h0, a1, b1, z1, l1, h1, a2, b2, z2, l2, h2, a3, b3, z3, l3, h3
    mul      v4.8h, v\b0\().8h, v\z0\().h[\l0]
    mul      v5.8h, v\b1\().8h, v\z1\().h[\l1]
    mul      v6.8h, v\b2\().8h, v\z2\().h[\l2]
    mul      v7.8h, v\b3\().8h, v\z3\().h[\l3]
    sqrdmulh v\b0\().8h, v\b0\().8h, v\z0\().h[\h0]
    sqrdmulh v\b1\().8h, v\b1\().8h, v\z1\().h[\h1]
    sqrdmulh v\b2\().8h, v\b2\().8h, v\z2\().h[\h2]
    sqrdmulh v\b3\().8h, v\b3\().8h, v\z3\().h[\h3]
    mls      v4.8h, v\b0\().8h, v0.h[0]
    mls      v5.8h, v\b1\().8h, v0.h[0]
    mls      v6.8h, v\b2\().8h, v0.h[0]
    mls      v7.8h, v\b3\().8h, v0.h[0]
    sub      v\b0\().8h, v\a0\().8h, v4.8h
    sub      v\b1\().8h, v\a1\().8h, v5.8h
    sub      v\b2\().8h, v\a2\().8h, v6.8h
    sub      v\b3\().8h, v\a3\().8h, v7.8h
    add      v\a0\().8h, v\a0\().8h, v4.8h
    add      v\a1\().8h, v\a1\().8h, v5.8h
    add      v\a2\().8h, v\a2\().8h, v6.8h
    add      v\a3\().8h, v\a3\().8h, v7.8h
.endm

// Four lazy Gentleman-Sande butterflies with scalar lane twiddles, stage-wise
// (temps v4..v7; no Barrett — the C lazy inverse):
//   d = b - a; a' = a + b; b' = mm3(d, root)
.macro NEV_GS4L a0, b0, z0, l0, h0, a1, b1, z1, l1, h1, a2, b2, z2, l2, h2, a3, b3, z3, l3, h3
    sub      v4.8h, v\b0\().8h, v\a0\().8h
    sub      v5.8h, v\b1\().8h, v\a1\().8h
    sub      v6.8h, v\b2\().8h, v\a2\().8h
    sub      v7.8h, v\b3\().8h, v\a3\().8h
    add      v\a0\().8h, v\a0\().8h, v\b0\().8h
    add      v\a1\().8h, v\a1\().8h, v\b1\().8h
    add      v\a2\().8h, v\a2\().8h, v\b2\().8h
    add      v\a3\().8h, v\a3\().8h, v\b3\().8h
    mul      v\b0\().8h, v4.8h, v\z0\().h[\l0]
    mul      v\b1\().8h, v5.8h, v\z1\().h[\l1]
    mul      v\b2\().8h, v6.8h, v\z2\().h[\l2]
    mul      v\b3\().8h, v7.8h, v\z3\().h[\l3]
    sqrdmulh v4.8h, v4.8h, v\z0\().h[\h0]
    sqrdmulh v5.8h, v5.8h, v\z1\().h[\h1]
    sqrdmulh v6.8h, v6.8h, v\z2\().h[\h2]
    sqrdmulh v7.8h, v7.8h, v\z3\().h[\h3]
    mls      v\b0\().8h, v4.8h, v0.h[0]
    mls      v\b1\().8h, v5.8h, v0.h[0]
    mls      v\b2\().8h, v6.8h, v0.h[0]
    mls      v\b3\().8h, v7.8h, v0.h[0]
.endm

// Exact-Barrett-reduce eight data registers in place, issued as 8-wide waves
// (see file header).  Same 3 instructions per register as the 2-wide variant.
.macro NEV_BR8 sh, a0, a1, a2, a3, a4, a5, a6, a7, t0, t1, t2, t3, t4, t5, t6, t7
    sqdmulh v\t0\().8h, v\a0\().8h, v0.h[1]
    sqdmulh v\t1\().8h, v\a1\().8h, v0.h[1]
    sqdmulh v\t2\().8h, v\a2\().8h, v0.h[1]
    sqdmulh v\t3\().8h, v\a3\().8h, v0.h[1]
    sqdmulh v\t4\().8h, v\a4\().8h, v0.h[1]
    sqdmulh v\t5\().8h, v\a5\().8h, v0.h[1]
    sqdmulh v\t6\().8h, v\a6\().8h, v0.h[1]
    sqdmulh v\t7\().8h, v\a7\().8h, v0.h[1]
    srshr   v\t0\().8h, v\t0\().8h, #\sh
    srshr   v\t1\().8h, v\t1\().8h, #\sh
    srshr   v\t2\().8h, v\t2\().8h, #\sh
    srshr   v\t3\().8h, v\t3\().8h, #\sh
    srshr   v\t4\().8h, v\t4\().8h, #\sh
    srshr   v\t5\().8h, v\t5\().8h, #\sh
    srshr   v\t6\().8h, v\t6\().8h, #\sh
    srshr   v\t7\().8h, v\t7\().8h, #\sh
    mls     v\a0\().8h, v\t0\().8h, v0.h[0]
    mls     v\a1\().8h, v\t1\().8h, v0.h[0]
    mls     v\a2\().8h, v\t2\().8h, v0.h[0]
    mls     v\a3\().8h, v\t3\().8h, v0.h[0]
    mls     v\a4\().8h, v\t4\().8h, v0.h[0]
    mls     v\a5\().8h, v\t5\().8h, v0.h[0]
    mls     v\a6\().8h, v\t6\().8h, v0.h[0]
    mls     v\a7\().8h, v\t7\().8h, v0.h[0]
.endm

// Four fused final GS butterflies with the mont^2/dim scale folded in
// ((fP, fP_hi, fzetaP, fzetaP_hi) in v1.h[0..3]), 4-way interleaved, results
// stored directly:
//   block[offa] = mm3(a + b, fP); block[offb] = mm3(b - a, fzetaP)
.macro NEV_GSF4 a0, b0, a1, b1, a2, b2, a3, b3, base, offa0, offb0, offa1, offb1, offa2, offb2, offa3, offb3
    sub      v4.8h, v\b0\().8h, v\a0\().8h
    sub      v5.8h, v\b1\().8h, v\a1\().8h
    sub      v6.8h, v\b2\().8h, v\a2\().8h
    sub      v7.8h, v\b3\().8h, v\a3\().8h
    add      v\a0\().8h, v\a0\().8h, v\b0\().8h
    add      v\a1\().8h, v\a1\().8h, v\b1\().8h
    add      v\a2\().8h, v\a2\().8h, v\b2\().8h
    add      v\a3\().8h, v\a3\().8h, v\b3\().8h
    mul      v\b0\().8h, v\a0\().8h, v1.h[0]
    mul      v\b1\().8h, v\a1\().8h, v1.h[0]
    mul      v\b2\().8h, v\a2\().8h, v1.h[0]
    mul      v\b3\().8h, v\a3\().8h, v1.h[0]
    sqrdmulh v\a0\().8h, v\a0\().8h, v1.h[1]
    sqrdmulh v\a1\().8h, v\a1\().8h, v1.h[1]
    sqrdmulh v\a2\().8h, v\a2\().8h, v1.h[1]
    sqrdmulh v\a3\().8h, v\a3\().8h, v1.h[1]
    mls      v\b0\().8h, v\a0\().8h, v0.h[0]
    mls      v\b1\().8h, v\a1\().8h, v0.h[0]
    mls      v\b2\().8h, v\a2\().8h, v0.h[0]
    mls      v\b3\().8h, v\a3\().8h, v0.h[0]
    mul      v\a0\().8h, v4.8h, v1.h[2]
    mul      v\a1\().8h, v5.8h, v1.h[2]
    mul      v\a2\().8h, v6.8h, v1.h[2]
    mul      v\a3\().8h, v7.8h, v1.h[2]
    VSTQ_8H  \b0, \base, #\offa0
    VSTQ_8H  \b1, \base, #\offa1
    VSTQ_8H  \b2, \base, #\offa2
    VSTQ_8H  \b3, \base, #\offa3
    sqrdmulh v4.8h, v4.8h, v1.h[3]
    sqrdmulh v5.8h, v5.8h, v1.h[3]
    sqrdmulh v6.8h, v6.8h, v1.h[3]
    sqrdmulh v7.8h, v7.8h, v1.h[3]
    mls      v\a0\().8h, v4.8h, v0.h[0]
    mls      v\a1\().8h, v5.8h, v0.h[0]
    mls      v\a2\().8h, v6.8h, v0.h[0]
    mls      v\a3\().8h, v7.8h, v0.h[0]
    VSTQ_8H  \a0, \base, #\offb0
    VSTQ_8H  \a1, \base, #\offb1
    VSTQ_8H  \a2, \base, #\offb2
    VSTQ_8H  \a3, \base, #\offb3
.endm

// ----------------------------------------------------------------------------
// Forward transposed stage: layers len=4/2/1 plus the final exact Barrett
// pass for TWO aligned runs of 4 data registers (2 x 32 coefficients),
// processed together so every stage issues 4 independent mul/sqrdmulh/mls
// butterfly chains (4-way interleave; two runs alone only expose 2).
// toffa/toffb are the byte offsets of the two groups' twiddle vectors:
//   +0 Z4lo  +16 Z4hi  +32 ZAlo  +48 ZAhi  +64 ZBlo  +80 ZBhi
//   +96 ZClo +112 ZChi +128 ZDlo +144 ZDhi
// Twiddle VLDQs issue in the preceding stage's multiply shadows; hi halves
// reload the registers their lo halves occupied once those are consumed.
// Uses v4-v13 plus the eight (transiently dead) data registers; v0-v3 and
// v14/v15 are untouched.  Instruction count: exactly 2x the former
// single-group macro.
// ----------------------------------------------------------------------------
.macro NEV_NTT_GRP2 sh, a0, a1, a2, a3, toffa, b0, b1, b2, b3, toffb, tbl
    NEV_TRN4X2 \a0, \a1, \a2, \a3, \b0, \b1, \b2, \b3
    VLDQ_8H 12, \tbl, #(\toffa+0)
    VLDQ_8H 13, \tbl, #(\toffa+16)
    VLDQ_8H 6, \tbl, #(\toffb+0)
    VLDQ_8H 7, \tbl, #(\toffb+16)
    // len=4: (d0,d2)/(d1,d3) of A share Z4_A (v12/v13), of B share Z4_B (v6/v7)
    mul      v4.8h, v\a2\().8h, v12.8h
    mul      v5.8h, v\a3\().8h, v12.8h
    mul      v8.8h, v\b2\().8h, v6.8h
    mul      v9.8h, v\b3\().8h, v6.8h
    VLDQ_8H 10, \tbl, #(\toffa+32)
    sqrdmulh v\a2\().8h, v\a2\().8h, v13.8h
    sqrdmulh v\a3\().8h, v\a3\().8h, v13.8h
    VLDQ_8H 11, \tbl, #(\toffa+64)
    sqrdmulh v\b2\().8h, v\b2\().8h, v7.8h
    sqrdmulh v\b3\().8h, v\b3\().8h, v7.8h
    VLDQ_8H 12, \tbl, #(\toffb+32)
    mls      v4.8h, v\a2\().8h, v0.h[0]
    mls      v5.8h, v\a3\().8h, v0.h[0]
    VLDQ_8H 6, \tbl, #(\toffb+64)
    mls      v8.8h, v\b2\().8h, v0.h[0]
    mls      v9.8h, v\b3\().8h, v0.h[0]
    VLDQ_8H 13, \tbl, #(\toffa+48)
    sub      v\a2\().8h, v\a0\().8h, v4.8h
    sub      v\a3\().8h, v\a1\().8h, v5.8h
    sub      v\b2\().8h, v\b0\().8h, v8.8h
    sub      v\b3\().8h, v\b1\().8h, v9.8h
    add      v\a0\().8h, v\a0\().8h, v4.8h
    add      v\a1\().8h, v\a1\().8h, v5.8h
    add      v\b0\().8h, v\b0\().8h, v8.8h
    add      v\b1\().8h, v\b1\().8h, v9.8h
    // len=2: A (d0,d1) w/ ZA_A (v10 lo), A (d2,d3) w/ ZB_A (v11 lo),
    //        B (d0,d1) w/ ZA_B (v12 lo), B (d2,d3) w/ ZB_B (v6 lo)
    mul      v4.8h, v\a1\().8h, v10.8h
    mul      v5.8h, v\a3\().8h, v11.8h
    mul      v8.8h, v\b1\().8h, v12.8h
    mul      v9.8h, v\b3\().8h, v6.8h
    VLDQ_8H 10, \tbl, #(\toffa+80)
    VLDQ_8H 7, \tbl, #(\toffb+48)
    sqrdmulh v\a1\().8h, v\a1\().8h, v13.8h
    sqrdmulh v\a3\().8h, v\a3\().8h, v10.8h
    VLDQ_8H 12, \tbl, #(\toffb+80)
    sqrdmulh v\b1\().8h, v\b1\().8h, v7.8h
    sqrdmulh v\b3\().8h, v\b3\().8h, v12.8h
    VLDQ_8H 6, \tbl, #(\toffa+96)
    mls      v4.8h, v\a1\().8h, v0.h[0]
    mls      v5.8h, v\a3\().8h, v0.h[0]
    VLDQ_8H 7, \tbl, #(\toffa+128)
    mls      v8.8h, v\b1\().8h, v0.h[0]
    mls      v9.8h, v\b3\().8h, v0.h[0]
    VLDQ_8H 10, \tbl, #(\toffb+96)
    sub      v\a1\().8h, v\a0\().8h, v4.8h
    sub      v\a3\().8h, v\a2\().8h, v5.8h
    sub      v\b1\().8h, v\b0\().8h, v8.8h
    sub      v\b3\().8h, v\b2\().8h, v9.8h
    VLDQ_8H 11, \tbl, #(\toffb+128)
    add      v\a0\().8h, v\a0\().8h, v4.8h
    add      v\a2\().8h, v\a2\().8h, v5.8h
    add      v\b0\().8h, v\b0\().8h, v8.8h
    add      v\b2\().8h, v\b2\().8h, v9.8h
    // len=1: split even/odd lanes (the split pairs migrate into v12/v13 and
    // the freed data registers), butterfly with ZC/ZD of each group:
    //   A: (v12,v13) w/ ZC_A (v6), (a0,a1) w/ ZD_A (v7)
    //   B: (a2,a3)   w/ ZC_B (v10), (b0,b1) w/ ZD_B (v11)
    trn1     v12.8h, v\a0\().8h, v\a1\().8h
    trn2     v13.8h, v\a0\().8h, v\a1\().8h
    trn1     v\a0\().8h, v\a2\().8h, v\a3\().8h
    trn2     v\a1\().8h, v\a2\().8h, v\a3\().8h
    trn1     v\a2\().8h, v\b0\().8h, v\b1\().8h
    trn2     v\a3\().8h, v\b0\().8h, v\b1\().8h
    trn1     v\b0\().8h, v\b2\().8h, v\b3\().8h
    trn2     v\b1\().8h, v\b2\().8h, v\b3\().8h
    mul      v4.8h, v13.8h, v6.8h
    mul      v5.8h, v\a1\().8h, v7.8h
    mul      v8.8h, v\a3\().8h, v10.8h
    mul      v9.8h, v\b1\().8h, v11.8h
    VLDQ_8H 6, \tbl, #(\toffa+112)
    VLDQ_8H 7, \tbl, #(\toffa+144)
    VLDQ_8H 10, \tbl, #(\toffb+112)
    VLDQ_8H 11, \tbl, #(\toffb+144)
    sqrdmulh v13.8h, v13.8h, v6.8h
    sqrdmulh v\a1\().8h, v\a1\().8h, v7.8h
    sqrdmulh v\a3\().8h, v\a3\().8h, v10.8h
    sqrdmulh v\b1\().8h, v\b1\().8h, v11.8h
    mls      v4.8h, v13.8h, v0.h[0]
    mls      v5.8h, v\a1\().8h, v0.h[0]
    mls      v8.8h, v\a3\().8h, v0.h[0]
    mls      v9.8h, v\b1\().8h, v0.h[0]
    sub      v13.8h, v12.8h, v4.8h
    sub      v\a1\().8h, v\a0\().8h, v5.8h
    sub      v\a3\().8h, v\a2\().8h, v8.8h
    sub      v\b1\().8h, v\b0\().8h, v9.8h
    add      v12.8h, v12.8h, v4.8h
    add      v\a0\().8h, v\a0\().8h, v5.8h
    add      v\a2\().8h, v\a2\().8h, v8.8h
    add      v\b0\().8h, v\b0\().8h, v9.8h
    // exact Barrett sync pass over all eight registers (lane-wise, so the
    // layout is irrelevant)
    NEV_BR8 \sh, 12, 13, \a0, \a1, \a2, \a3, \b0, \b1, 4, 5, 6, 7, 8, 9, 10, 11
    // merge even/odd lanes back and undo both 4x4 transposes
    trn1     v4.8h, v12.8h, v13.8h
    trn2     v5.8h, v12.8h, v13.8h
    trn1     v6.8h, v\a0\().8h, v\a1\().8h
    trn2     v7.8h, v\a0\().8h, v\a1\().8h
    trn1     v8.8h, v\a2\().8h, v\a3\().8h
    trn2     v9.8h, v\a2\().8h, v\a3\().8h
    trn1     v10.8h, v\b0\().8h, v\b1\().8h
    trn2     v11.8h, v\b0\().8h, v\b1\().8h
    trn1     v12.4s, v4.4s, v5.4s
    trn2     v13.4s, v4.4s, v5.4s
    trn1     v\b2\().4s, v6.4s, v7.4s
    trn2     v\b3\().4s, v6.4s, v7.4s
    trn1     v4.4s, v8.4s, v9.4s
    trn2     v5.4s, v8.4s, v9.4s
    trn1     v6.4s, v10.4s, v11.4s
    trn2     v7.4s, v10.4s, v11.4s
    trn1     v\a0\().2d, v12.2d, v\b2\().2d
    trn2     v\a2\().2d, v12.2d, v\b2\().2d
    trn1     v\a1\().2d, v13.2d, v\b3\().2d
    trn2     v\a3\().2d, v13.2d, v\b3\().2d
    trn1     v\b0\().2d, v4.2d, v6.2d
    trn2     v\b2\().2d, v4.2d, v6.2d
    trn1     v\b1\().2d, v5.2d, v7.2d
    trn2     v\b3\().2d, v5.2d, v7.2d
.endm

// NEV_NTT_GRP2_ST: NEV_NTT_GRP2 with the eight stores interleaved into the
// final un-transpose section (each store follows the trn1/trn2 pair that
// produced its register).  Spreads the trailing 8-store burst across the
// transpose latency chain; perf on Kunpeng 920 shows the burst head
// (str of a1) stalling.  Store offsets are derived from the data-register
// numbers, which are contiguous v16..v31 by construction: register n maps
// to block offset (n - 16) * 16 bytes — exactly the layout the callers'
// explicit VSTQ_8H sequences used.  In-place safety is unchanged: every
// block load still precedes the first store of the kernel.
.macro NEV_NTT_GRP2_ST sh, a0, a1, a2, a3, toffa, b0, b1, b2, b3, toffb, tbl
    NEV_TRN4X2 \a0, \a1, \a2, \a3, \b0, \b1, \b2, \b3
    VLDQ_8H 12, \tbl, #(\toffa+0)
    VLDQ_8H 13, \tbl, #(\toffa+16)
    VLDQ_8H 6, \tbl, #(\toffb+0)
    VLDQ_8H 7, \tbl, #(\toffb+16)
    // len=4: (d0,d2)/(d1,d3) of A share Z4_A (v12/v13), of B share Z4_B (v6/v7)
    mul      v4.8h, v\a2\().8h, v12.8h
    mul      v5.8h, v\a3\().8h, v12.8h
    mul      v8.8h, v\b2\().8h, v6.8h
    mul      v9.8h, v\b3\().8h, v6.8h
    VLDQ_8H 10, \tbl, #(\toffa+32)
    sqrdmulh v\a2\().8h, v\a2\().8h, v13.8h
    sqrdmulh v\a3\().8h, v\a3\().8h, v13.8h
    VLDQ_8H 11, \tbl, #(\toffa+64)
    sqrdmulh v\b2\().8h, v\b2\().8h, v7.8h
    sqrdmulh v\b3\().8h, v\b3\().8h, v7.8h
    VLDQ_8H 12, \tbl, #(\toffb+32)
    mls      v4.8h, v\a2\().8h, v0.h[0]
    mls      v5.8h, v\a3\().8h, v0.h[0]
    VLDQ_8H 6, \tbl, #(\toffb+64)
    mls      v8.8h, v\b2\().8h, v0.h[0]
    mls      v9.8h, v\b3\().8h, v0.h[0]
    VLDQ_8H 13, \tbl, #(\toffa+48)
    sub      v\a2\().8h, v\a0\().8h, v4.8h
    sub      v\a3\().8h, v\a1\().8h, v5.8h
    sub      v\b2\().8h, v\b0\().8h, v8.8h
    sub      v\b3\().8h, v\b1\().8h, v9.8h
    add      v\a0\().8h, v\a0\().8h, v4.8h
    add      v\a1\().8h, v\a1\().8h, v5.8h
    add      v\b0\().8h, v\b0\().8h, v8.8h
    add      v\b1\().8h, v\b1\().8h, v9.8h
    // len=2: A (d0,d1) w/ ZA_A (v10 lo), A (d2,d3) w/ ZB_A (v11 lo),
    //        B (d0,d1) w/ ZA_B (v12 lo), B (d2,d3) w/ ZB_B (v6 lo)
    mul      v4.8h, v\a1\().8h, v10.8h
    mul      v5.8h, v\a3\().8h, v11.8h
    mul      v8.8h, v\b1\().8h, v12.8h
    mul      v9.8h, v\b3\().8h, v6.8h
    VLDQ_8H 10, \tbl, #(\toffa+80)
    VLDQ_8H 7, \tbl, #(\toffb+48)
    sqrdmulh v\a1\().8h, v\a1\().8h, v13.8h
    sqrdmulh v\a3\().8h, v\a3\().8h, v10.8h
    VLDQ_8H 12, \tbl, #(\toffb+80)
    sqrdmulh v\b1\().8h, v\b1\().8h, v7.8h
    sqrdmulh v\b3\().8h, v\b3\().8h, v12.8h
    VLDQ_8H 6, \tbl, #(\toffa+96)
    mls      v4.8h, v\a1\().8h, v0.h[0]
    mls      v5.8h, v\a3\().8h, v0.h[0]
    VLDQ_8H 7, \tbl, #(\toffa+128)
    mls      v8.8h, v\b1\().8h, v0.h[0]
    mls      v9.8h, v\b3\().8h, v0.h[0]
    VLDQ_8H 10, \tbl, #(\toffb+96)
    sub      v\a1\().8h, v\a0\().8h, v4.8h
    sub      v\a3\().8h, v\a2\().8h, v5.8h
    sub      v\b1\().8h, v\b0\().8h, v8.8h
    sub      v\b3\().8h, v\b2\().8h, v9.8h
    VLDQ_8H 11, \tbl, #(\toffb+128)
    add      v\a0\().8h, v\a0\().8h, v4.8h
    add      v\a2\().8h, v\a2\().8h, v5.8h
    add      v\b0\().8h, v\b0\().8h, v8.8h
    add      v\b2\().8h, v\b2\().8h, v9.8h
    // len=1: split even/odd lanes (the split pairs migrate into v12/v13 and
    // the freed data registers), butterfly with ZC/ZD of each group:
    //   A: (v12,v13) w/ ZC_A (v6), (a0,a1) w/ ZD_A (v7)
    //   B: (a2,a3)   w/ ZC_B (v10), (b0,b1) w/ ZD_B (v11)
    trn1     v12.8h, v\a0\().8h, v\a1\().8h
    trn2     v13.8h, v\a0\().8h, v\a1\().8h
    trn1     v\a0\().8h, v\a2\().8h, v\a3\().8h
    trn2     v\a1\().8h, v\a2\().8h, v\a3\().8h
    trn1     v\a2\().8h, v\b0\().8h, v\b1\().8h
    trn2     v\a3\().8h, v\b0\().8h, v\b1\().8h
    trn1     v\b0\().8h, v\b2\().8h, v\b3\().8h
    trn2     v\b1\().8h, v\b2\().8h, v\b3\().8h
    mul      v4.8h, v13.8h, v6.8h
    mul      v5.8h, v\a1\().8h, v7.8h
    mul      v8.8h, v\a3\().8h, v10.8h
    mul      v9.8h, v\b1\().8h, v11.8h
    VLDQ_8H 6, \tbl, #(\toffa+112)
    VLDQ_8H 7, \tbl, #(\toffa+144)
    VLDQ_8H 10, \tbl, #(\toffb+112)
    VLDQ_8H 11, \tbl, #(\toffb+144)
    sqrdmulh v13.8h, v13.8h, v6.8h
    sqrdmulh v\a1\().8h, v\a1\().8h, v7.8h
    sqrdmulh v\a3\().8h, v\a3\().8h, v10.8h
    sqrdmulh v\b1\().8h, v\b1\().8h, v11.8h
    mls      v4.8h, v13.8h, v0.h[0]
    mls      v5.8h, v\a1\().8h, v0.h[0]
    mls      v8.8h, v\a3\().8h, v0.h[0]
    mls      v9.8h, v\b1\().8h, v0.h[0]
    sub      v13.8h, v12.8h, v4.8h
    sub      v\a1\().8h, v\a0\().8h, v5.8h
    sub      v\a3\().8h, v\a2\().8h, v8.8h
    sub      v\b1\().8h, v\b0\().8h, v9.8h
    add      v12.8h, v12.8h, v4.8h
    add      v\a0\().8h, v\a0\().8h, v5.8h
    add      v\a2\().8h, v\a2\().8h, v8.8h
    add      v\b0\().8h, v\b0\().8h, v9.8h
    // exact Barrett sync pass over all eight registers (lane-wise, so the
    // layout is irrelevant)
    NEV_BR8 \sh, 12, 13, \a0, \a1, \a2, \a3, \b0, \b1, 4, 5, 6, 7, 8, 9, 10, 11
    // merge even/odd lanes back and undo both 4x4 transposes; each output
    // register is stored as soon as its final trn pair retires
    trn1     v4.8h, v12.8h, v13.8h
    trn2     v5.8h, v12.8h, v13.8h
    trn1     v6.8h, v\a0\().8h, v\a1\().8h
    trn2     v7.8h, v\a0\().8h, v\a1\().8h
    trn1     v8.8h, v\a2\().8h, v\a3\().8h
    trn2     v9.8h, v\a2\().8h, v\a3\().8h
    trn1     v10.8h, v\b0\().8h, v\b1\().8h
    trn2     v11.8h, v\b0\().8h, v\b1\().8h
    trn1     v12.4s, v4.4s, v5.4s
    trn2     v13.4s, v4.4s, v5.4s
    trn1     v\b2\().4s, v6.4s, v7.4s
    trn2     v\b3\().4s, v6.4s, v7.4s
    trn1     v4.4s, v8.4s, v9.4s
    trn2     v5.4s, v8.4s, v9.4s
    trn1     v6.4s, v10.4s, v11.4s
    trn2     v7.4s, v10.4s, v11.4s
    trn1     v\a0\().2d, v12.2d, v\b2\().2d
    trn2     v\a2\().2d, v12.2d, v\b2\().2d
    VSTQ_8H \a0, blk, #((\a0-16)*16)
    VSTQ_8H \a2, blk, #((\a2-16)*16)
    trn1     v\a1\().2d, v13.2d, v\b3\().2d
    trn2     v\a3\().2d, v13.2d, v\b3\().2d
    VSTQ_8H \a1, blk, #((\a1-16)*16)
    VSTQ_8H \a3, blk, #((\a3-16)*16)
    trn1     v\b0\().2d, v4.2d, v6.2d
    trn2     v\b2\().2d, v4.2d, v6.2d
    VSTQ_8H \b0, blk, #((\b0-16)*16)
    VSTQ_8H \b2, blk, #((\b2-16)*16)
    trn1     v\b1\().2d, v5.2d, v7.2d
    trn2     v\b3\().2d, v5.2d, v7.2d
    VSTQ_8H \b1, blk, #((\b1-16)*16)
    VSTQ_8H \b3, blk, #((\b3-16)*16)
.endm

// ----------------------------------------------------------------------------
// Inverse transposed stage: lazy layers len=1/2/4 for TWO runs of 4 data
// registers, then the single exact Barrett pass of the lazy schedule (all
// eight registers, in the transposed domain).  Both runs are processed
// together so every lazy layer issues 4 independent mul/sqrdmulh/mls chains
// (4-way interleave).  Group twiddle vector layout:
//   +0 ZClo  +16 ZChi  +32 ZDlo  +48 ZDhi  +64 ZAlo  +80 ZAhi
//   +96 ZBlo +112 ZBhi +128 Z4lo +144 Z4hi
// Twiddle hi halves reload the registers their lo halves occupied.  Group A's
// data migrates to (v4,v5,v12,v13) after the even/odd merge and returns to
// a0..a3 in the final transpose.  Uses v4-v13 plus the transiently dead data
// registers only: v0-v3 (scalar twiddles, still needed by the later layers)
// and v14/v15 are untouched.  Instruction count: exactly 2x the former
// single-group macro.
// ----------------------------------------------------------------------------
.macro NEV_INTT_GRP2 sh, a0, a1, a2, a3, toffa, b0, b1, b2, b3, toffb, tbl
    NEV_TRN4X2 \a0, \a1, \a2, \a3, \b0, \b1, \b2, \b3
    VLDQ_8H 8, \tbl, #(\toffa+0)
    VLDQ_8H 9, \tbl, #(\toffa+32)
    VLDQ_8H 10, \tbl, #(\toffb+0)
    VLDQ_8H 11, \tbl, #(\toffb+32)
    // len=1: split even/odd lanes, lazy GS:
    //   A: (v12,v13) w/ ZC_A (v8), (a0,a1) w/ ZD_A (v9)
    //   B: (a2,a3)   w/ ZC_B (v10), (b0,b1) w/ ZD_B (v11)
    trn1     v12.8h, v\a0\().8h, v\a1\().8h
    trn2     v13.8h, v\a0\().8h, v\a1\().8h
    trn1     v\a0\().8h, v\a2\().8h, v\a3\().8h
    trn2     v\a1\().8h, v\a2\().8h, v\a3\().8h
    trn1     v\a2\().8h, v\b0\().8h, v\b1\().8h
    trn2     v\a3\().8h, v\b0\().8h, v\b1\().8h
    trn1     v\b0\().8h, v\b2\().8h, v\b3\().8h
    trn2     v\b1\().8h, v\b2\().8h, v\b3\().8h
    sub      v4.8h, v13.8h, v12.8h
    sub      v5.8h, v\a1\().8h, v\a0\().8h
    sub      v6.8h, v\a3\().8h, v\a2\().8h
    sub      v7.8h, v\b1\().8h, v\b0\().8h
    add      v12.8h, v12.8h, v13.8h
    add      v\a0\().8h, v\a0\().8h, v\a1\().8h
    add      v\a2\().8h, v\a2\().8h, v\a3\().8h
    add      v\b0\().8h, v\b0\().8h, v\b1\().8h
    mul      v13.8h, v4.8h, v8.8h
    mul      v\a1\().8h, v5.8h, v9.8h
    mul      v\a3\().8h, v6.8h, v10.8h
    mul      v\b1\().8h, v7.8h, v11.8h
    VLDQ_8H 8, \tbl, #(\toffa+16)
    VLDQ_8H 9, \tbl, #(\toffa+48)
    VLDQ_8H 10, \tbl, #(\toffb+16)
    VLDQ_8H 11, \tbl, #(\toffb+48)
    sqrdmulh v4.8h, v4.8h, v8.8h
    sqrdmulh v5.8h, v5.8h, v9.8h
    sqrdmulh v6.8h, v6.8h, v10.8h
    sqrdmulh v7.8h, v7.8h, v11.8h
    mls      v13.8h, v4.8h, v0.h[0]
    mls      v\a1\().8h, v5.8h, v0.h[0]
    mls      v\a3\().8h, v6.8h, v0.h[0]
    mls      v\b1\().8h, v7.8h, v0.h[0]
    // merge even/odd lanes back; group A lands in (v4,v5,v12,v13), group B
    // in (a0,a1,a2,a3)
    trn1     v4.8h, v12.8h, v13.8h
    trn2     v5.8h, v12.8h, v13.8h
    trn1     v12.8h, v\a0\().8h, v\a1\().8h
    trn2     v13.8h, v\a0\().8h, v\a1\().8h
    trn1     v\a0\().8h, v\a2\().8h, v\a3\().8h
    trn2     v\a1\().8h, v\a2\().8h, v\a3\().8h
    trn1     v\a2\().8h, v\b0\().8h, v\b1\().8h
    trn2     v\a3\().8h, v\b0\().8h, v\b1\().8h
    VLDQ_8H 8, \tbl, #(\toffa+64)
    VLDQ_8H 9, \tbl, #(\toffa+96)
    VLDQ_8H 10, \tbl, #(\toffb+64)
    VLDQ_8H 11, \tbl, #(\toffb+96)
    // len=2 (lazy): A (v4,v5) w/ ZA_A (v8), A (v12,v13) w/ ZB_A (v9),
    //               B (a0,a1) w/ ZA_B (v10), B (a2,a3) w/ ZB_B (v11)
    sub      v6.8h, v5.8h, v4.8h
    sub      v7.8h, v13.8h, v12.8h
    sub      v\b0\().8h, v\a1\().8h, v\a0\().8h
    sub      v\b1\().8h, v\a3\().8h, v\a2\().8h
    add      v4.8h, v4.8h, v5.8h
    add      v12.8h, v12.8h, v13.8h
    add      v\a0\().8h, v\a0\().8h, v\a1\().8h
    add      v\a2\().8h, v\a2\().8h, v\a3\().8h
    mul      v5.8h, v6.8h, v8.8h
    mul      v13.8h, v7.8h, v9.8h
    mul      v\a1\().8h, v\b0\().8h, v10.8h
    mul      v\a3\().8h, v\b1\().8h, v11.8h
    VLDQ_8H 8, \tbl, #(\toffa+80)
    VLDQ_8H 9, \tbl, #(\toffa+112)
    VLDQ_8H 10, \tbl, #(\toffb+80)
    VLDQ_8H 11, \tbl, #(\toffb+112)
    sqrdmulh v6.8h, v6.8h, v8.8h
    sqrdmulh v7.8h, v7.8h, v9.8h
    sqrdmulh v\b0\().8h, v\b0\().8h, v10.8h
    sqrdmulh v\b1\().8h, v\b1\().8h, v11.8h
    mls      v5.8h, v6.8h, v0.h[0]
    mls      v13.8h, v7.8h, v0.h[0]
    mls      v\a1\().8h, v\b0\().8h, v0.h[0]
    mls      v\a3\().8h, v\b1\().8h, v0.h[0]
    VLDQ_8H 8, \tbl, #(\toffa+128)
    VLDQ_8H 10, \tbl, #(\toffb+128)
    // len=4 (lazy): A (v4,v12)/(v5,v13) share Z4_A (v8),
    //               B (a0,a2)/(a1,a3) share Z4_B (v10)
    sub      v6.8h, v12.8h, v4.8h
    sub      v7.8h, v13.8h, v5.8h
    sub      v\b0\().8h, v\a2\().8h, v\a0\().8h
    sub      v\b1\().8h, v\a3\().8h, v\a1\().8h
    add      v4.8h, v4.8h, v12.8h
    add      v5.8h, v5.8h, v13.8h
    add      v\a0\().8h, v\a0\().8h, v\a2\().8h
    add      v\a1\().8h, v\a1\().8h, v\a3\().8h
    mul      v12.8h, v6.8h, v8.8h
    mul      v13.8h, v7.8h, v8.8h
    mul      v\a2\().8h, v\b0\().8h, v10.8h
    mul      v\a3\().8h, v\b1\().8h, v10.8h
    VLDQ_8H 9, \tbl, #(\toffa+144)
    VLDQ_8H 11, \tbl, #(\toffb+144)
    sqrdmulh v6.8h, v6.8h, v9.8h
    sqrdmulh v7.8h, v7.8h, v9.8h
    sqrdmulh v\b0\().8h, v\b0\().8h, v11.8h
    sqrdmulh v\b1\().8h, v\b1\().8h, v11.8h
    mls      v12.8h, v6.8h, v0.h[0]
    mls      v13.8h, v7.8h, v0.h[0]
    mls      v\a2\().8h, v\b0\().8h, v0.h[0]
    mls      v\a3\().8h, v\b1\().8h, v0.h[0]
    // the ONE exact Barrett pass of the lazy inverse (sums <= 8M <= 13312,
    // mm3 legs <= 0.71*q: inside the proven all-int16 domain)
    NEV_BR8 \sh, 4, 5, 12, 13, \a0, \a1, \a2, \a3, 6, 7, \b0, \b1, 8, 9, 10, 11
    // undo both 4x4 transposes: B (in a0..a3) back to b0..b3 first, then A
    // (in v4,v5,v12,v13) back to a0..a3
    trn1     v6.4s, v\a0\().4s, v\a1\().4s
    trn2     v7.4s, v\a0\().4s, v\a1\().4s
    trn1     v8.4s, v\a2\().4s, v\a3\().4s
    trn2     v9.4s, v\a2\().4s, v\a3\().4s
    trn1     v\b0\().2d, v6.2d, v8.2d
    trn2     v\b2\().2d, v6.2d, v8.2d
    trn1     v\b1\().2d, v7.2d, v9.2d
    trn2     v\b3\().2d, v7.2d, v9.2d
    trn1     v6.4s, v4.4s, v5.4s
    trn2     v7.4s, v4.4s, v5.4s
    trn1     v8.4s, v12.4s, v13.4s
    trn2     v9.4s, v12.4s, v13.4s
    trn1     v\a0\().2d, v6.2d, v8.2d
    trn2     v\a2\().2d, v6.2d, v8.2d
    trn1     v\a1\().2d, v7.2d, v9.2d
    trn2     v\a3\().2d, v7.2d, v9.2d
.endm

// Materialize the fused-scale pairs (fP, fP_hi, fzetaP, fzetaP_hi) in
// v1.h[0..3] (v1's scalar twiddles are dead by the time this runs).
.macro NEV_LDF fp, fphi, fz, fzhi
    movz    xtmp, #\fp
    movk    xtmp, #\fphi, lsl #16
    movk    xtmp, #\fz, lsl #32
    movk    xtmp, #\fzhi, lsl #48
    mov     v1.d[0], xtmp
.endm

// ----------------------------------------------------------------------------
// Whole-kernel bodies, parameterized by (q, barrettV, srshr shift) and, for
// the inverse kernels, the fused-scale immediates (as 16-bit hex).
// ----------------------------------------------------------------------------

// Forward NTT, dim = 128 (7 layers: len 64,32,16,8 in-register + groups).
.macro NEV_NTT128_BODY qval, mval, sh, fp, fphi, fz, fzhi
    VLDQ_8H 0, table, #0
    VLDQ_8H 1, table, #16
    VLDQ_8H 2, table, #32
    VLDQ_8H 3, table, #48
    movz    wtmp, #\qval
    movk    wtmp, #\mval, lsl #16
    mov     v0.s[0], wtmp
    VLDQ_8H 24, blk, #8*16
    VLDQ_8H 25, blk, #9*16
    VLDQ_8H 26, blk, #10*16
    VLDQ_8H 27, blk, #11*16
    VLDQ_8H 28, blk, #12*16
    VLDQ_8H 29, blk, #13*16
    VLDQ_8H 30, blk, #14*16
    VLDQ_8H 31, blk, #15*16
    // len=64 (zeta_1 = v0.h[2,3]), two 4-way waves; the a-half block loads
    // issue in the multiply latency shadows
    mul      v4.8h, v24.8h, v0.h[2]
    mul      v5.8h, v25.8h, v0.h[2]
    mul      v6.8h, v26.8h, v0.h[2]
    mul      v7.8h, v27.8h, v0.h[2]
    VLDQ_8H 16, blk, #0*16
    sqrdmulh v24.8h, v24.8h, v0.h[3]
    VLDQ_8H 17, blk, #1*16
    sqrdmulh v25.8h, v25.8h, v0.h[3]
    VLDQ_8H 18, blk, #2*16
    sqrdmulh v26.8h, v26.8h, v0.h[3]
    VLDQ_8H 19, blk, #3*16
    sqrdmulh v27.8h, v27.8h, v0.h[3]
    mls      v4.8h, v24.8h, v0.h[0]
    mls      v5.8h, v25.8h, v0.h[0]
    mls      v6.8h, v26.8h, v0.h[0]
    mls      v7.8h, v27.8h, v0.h[0]
    mul      v8.8h, v28.8h, v0.h[2]
    mul      v9.8h, v29.8h, v0.h[2]
    mul      v10.8h, v30.8h, v0.h[2]
    mul      v11.8h, v31.8h, v0.h[2]
    VLDQ_8H 20, blk, #4*16
    sqrdmulh v28.8h, v28.8h, v0.h[3]
    VLDQ_8H 21, blk, #5*16
    sqrdmulh v29.8h, v29.8h, v0.h[3]
    VLDQ_8H 22, blk, #6*16
    sqrdmulh v30.8h, v30.8h, v0.h[3]
    VLDQ_8H 23, blk, #7*16
    sqrdmulh v31.8h, v31.8h, v0.h[3]
    mls      v8.8h, v28.8h, v0.h[0]
    mls      v9.8h, v29.8h, v0.h[0]
    mls      v10.8h, v30.8h, v0.h[0]
    mls      v11.8h, v31.8h, v0.h[0]
    sub      v24.8h, v16.8h, v4.8h
    sub      v25.8h, v17.8h, v5.8h
    sub      v26.8h, v18.8h, v6.8h
    sub      v27.8h, v19.8h, v7.8h
    add      v16.8h, v16.8h, v4.8h
    add      v17.8h, v17.8h, v5.8h
    add      v18.8h, v18.8h, v6.8h
    add      v19.8h, v19.8h, v7.8h
    sub      v28.8h, v20.8h, v8.8h
    sub      v29.8h, v21.8h, v9.8h
    sub      v30.8h, v22.8h, v10.8h
    sub      v31.8h, v23.8h, v11.8h
    add      v20.8h, v20.8h, v8.8h
    add      v21.8h, v21.8h, v9.8h
    add      v22.8h, v22.8h, v10.8h
    add      v23.8h, v23.8h, v11.8h
    // len=32: zeta_2 = v0.h[4,5], zeta_3 = v0.h[6,7]
    NEV_CT4L 16, 20, 0, 4, 5, 17, 21, 0, 4, 5, 18, 22, 0, 4, 5, 19, 23, 0, 4, 5
    NEV_CT4L 24, 28, 0, 6, 7, 25, 29, 0, 6, 7, 26, 30, 0, 6, 7, 27, 31, 0, 6, 7
    // len=16: zeta_4..7 = v1.h[0,1],[2,3],[4,5],[6,7]
    NEV_CT4L 16, 18, 1, 0, 1, 17, 19, 1, 0, 1, 20, 22, 1, 2, 3, 21, 23, 1, 2, 3
    NEV_CT4L 24, 26, 1, 4, 5, 25, 27, 1, 4, 5, 28, 30, 1, 6, 7, 29, 31, 1, 6, 7
    // len=8: zeta_8..15 = v2/v3 lane pairs
    NEV_CT4L 16, 17, 2, 0, 1, 18, 19, 2, 2, 3, 20, 21, 2, 4, 5, 22, 23, 2, 6, 7
    NEV_CT4L 24, 25, 3, 0, 1, 26, 27, 3, 2, 3, 28, 29, 3, 4, 5, 30, 31, 3, 6, 7
    // len=4/2/1 + Barrett, two data-independent groups fused per macro so
    // every stage runs 4-way; stores are interleaved into each group's
    // un-transpose tail (NEV_NTT_GRP2_ST) and overlap the next pair
    NEV_NTT_GRP2_ST \sh, 16, 17, 18, 19, 64, 20, 21, 22, 23, 224, table
    NEV_NTT_GRP2_ST \sh, 24, 25, 26, 27, 384, 28, 29, 30, 31, 544, table
.endm

// Inverse NTT, dim = 128 (lazy groups len 1,2,4 + Barrett; lazy len 8,16,32;
// len 64 fused with the mont^2/dim scale).  Block loads are staggered one
// group ahead so they retire under the previous group's arithmetic.
.macro NEV_INTT128_BODY qval, mval, sh, fp, fphi, fz, fzhi
    VLDQ_8H 0, table, #0
    VLDQ_8H 1, table, #16
    VLDQ_8H 2, table, #32
    VLDQ_8H 3, table, #48
    movz    wtmp, #\qval
    movk    wtmp, #\mval, lsl #16
    mov     v0.s[0], wtmp
    VLDQ_8H 16, blk, #0*16
    VLDQ_8H 17, blk, #1*16
    VLDQ_8H 18, blk, #2*16
    VLDQ_8H 19, blk, #3*16
    VLDQ_8H 20, blk, #4*16
    VLDQ_8H 21, blk, #5*16
    VLDQ_8H 22, blk, #6*16
    VLDQ_8H 23, blk, #7*16
    NEV_INTT_GRP2 \sh, 16, 17, 18, 19, 64, 20, 21, 22, 23, 224, table
    VLDQ_8H 24, blk, #8*16
    VLDQ_8H 25, blk, #9*16
    VLDQ_8H 26, blk, #10*16
    VLDQ_8H 27, blk, #11*16
    VLDQ_8H 28, blk, #12*16
    VLDQ_8H 29, blk, #13*16
    VLDQ_8H 30, blk, #14*16
    VLDQ_8H 31, blk, #15*16
    NEV_INTT_GRP2 \sh, 24, 25, 26, 27, 384, 28, 29, 30, 31, 544, table
    // len=8 (lazy): zeta_15..8 = v0.h[2,3],[4,5],[6,7], v1.h[0,1],[2,3],
    // [4,5],[6,7], v2.h[0,1]
    NEV_GS4L 16, 17, 0, 2, 3, 18, 19, 0, 4, 5, 20, 21, 0, 6, 7, 22, 23, 1, 0, 1
    NEV_GS4L 24, 25, 1, 2, 3, 26, 27, 1, 4, 5, 28, 29, 1, 6, 7, 30, 31, 2, 0, 1
    // len=16 (lazy): zeta_7..4 = v2.h[2,3],[4,5],[6,7], v3.h[0,1]
    NEV_GS4L 16, 18, 2, 2, 3, 17, 19, 2, 2, 3, 20, 22, 2, 4, 5, 21, 23, 2, 4, 5
    NEV_GS4L 24, 26, 2, 6, 7, 25, 27, 2, 6, 7, 28, 30, 3, 0, 1, 29, 31, 3, 0, 1
    // len=32 (lazy): zeta_3 = v3.h[2,3], zeta_2 = v3.h[4,5]
    NEV_GS4L 16, 20, 3, 2, 3, 17, 21, 3, 2, 3, 18, 22, 3, 2, 3, 19, 23, 3, 2, 3
    NEV_GS4L 24, 28, 3, 4, 5, 25, 29, 3, 4, 5, 26, 30, 3, 4, 5, 27, 31, 3, 4, 5
    // len=64 fused with the scale (replaces the v1 GS layer + scale pass)
    NEV_LDF \fp, \fphi, \fz, \fzhi
    NEV_GSF4 16, 24, 17, 25, 18, 26, 19, 27, blk, 0*16, 8*16, 1*16, 9*16, 2*16, 10*16, 3*16, 11*16
    NEV_GSF4 20, 28, 21, 29, 22, 30, 23, 31, blk, 4*16, 12*16, 5*16, 13*16, 6*16, 14*16, 7*16, 15*16
.endm

// Forward NTT, dim = 64 (6 layers: len 32,16,8 in-register + groups).
.macro NEV_NTT64_BODY qval, mval, sh, fp, fphi, fz, fzhi
    VLDQ_8H 0, table, #0
    VLDQ_8H 1, table, #16
    movz    wtmp, #\qval
    movk    wtmp, #\mval, lsl #16
    mov     v0.s[0], wtmp
    VLDQ_8H 20, blk, #4*16
    VLDQ_8H 21, blk, #5*16
    VLDQ_8H 22, blk, #6*16
    VLDQ_8H 23, blk, #7*16
    // len=32 (zeta_1 = v0.h[2,3]): the a-half loads fill the mul shadows
    mul      v4.8h, v20.8h, v0.h[2]
    mul      v5.8h, v21.8h, v0.h[2]
    mul      v6.8h, v22.8h, v0.h[2]
    mul      v7.8h, v23.8h, v0.h[2]
    VLDQ_8H 16, blk, #0*16
    sqrdmulh v20.8h, v20.8h, v0.h[3]
    VLDQ_8H 17, blk, #1*16
    sqrdmulh v21.8h, v21.8h, v0.h[3]
    VLDQ_8H 18, blk, #2*16
    sqrdmulh v22.8h, v22.8h, v0.h[3]
    VLDQ_8H 19, blk, #3*16
    sqrdmulh v23.8h, v23.8h, v0.h[3]
    mls      v4.8h, v20.8h, v0.h[0]
    mls      v5.8h, v21.8h, v0.h[0]
    mls      v6.8h, v22.8h, v0.h[0]
    mls      v7.8h, v23.8h, v0.h[0]
    sub      v20.8h, v16.8h, v4.8h
    sub      v21.8h, v17.8h, v5.8h
    sub      v22.8h, v18.8h, v6.8h
    sub      v23.8h, v19.8h, v7.8h
    add      v16.8h, v16.8h, v4.8h
    add      v17.8h, v17.8h, v5.8h
    add      v18.8h, v18.8h, v6.8h
    add      v19.8h, v19.8h, v7.8h
    // len=16: zeta_2 = v0.h[4,5], zeta_3 = v0.h[6,7]
    NEV_CT4L 16, 18, 0, 4, 5, 17, 19, 0, 4, 5, 20, 22, 0, 6, 7, 21, 23, 0, 6, 7
    // len=8: zeta_4..7 = v1.h[0,1],[2,3],[4,5],[6,7]
    NEV_CT4L 16, 17, 1, 0, 1, 18, 19, 1, 2, 3, 20, 21, 1, 4, 5, 22, 23, 1, 6, 7
    // len=4/2/1 + Barrett, both groups fused (4-way)
    NEV_NTT_GRP2_ST \sh, 16, 17, 18, 19, 32, 20, 21, 22, 23, 192, table
.endm

// Inverse NTT, dim = 64 (lazy groups len 1,2,4 + Barrett; lazy len 8,16;
// len 32 fused with the scale).
.macro NEV_INTT64_BODY qval, mval, sh, fp, fphi, fz, fzhi
    VLDQ_8H 0, table, #0
    VLDQ_8H 1, table, #16
    movz    wtmp, #\qval
    movk    wtmp, #\mval, lsl #16
    mov     v0.s[0], wtmp
    VLDQ_8H 16, blk, #0*16
    VLDQ_8H 17, blk, #1*16
    VLDQ_8H 18, blk, #2*16
    VLDQ_8H 19, blk, #3*16
    VLDQ_8H 20, blk, #4*16
    VLDQ_8H 21, blk, #5*16
    VLDQ_8H 22, blk, #6*16
    VLDQ_8H 23, blk, #7*16
    NEV_INTT_GRP2 \sh, 16, 17, 18, 19, 32, 20, 21, 22, 23, 192, table
    // len=8 (lazy): zeta_7..4 = v0.h[2,3],[4,5],[6,7], v1.h[0,1]
    NEV_GS4L 16, 17, 0, 2, 3, 18, 19, 0, 4, 5, 20, 21, 0, 6, 7, 22, 23, 1, 0, 1
    // len=16 (lazy): zeta_3 = v1.h[2,3], zeta_2 = v1.h[4,5]
    NEV_GS4L 16, 18, 1, 2, 3, 17, 19, 1, 2, 3, 20, 22, 1, 4, 5, 21, 23, 1, 4, 5
    // len=32 fused with the scale
    NEV_LDF \fp, \fphi, \fz, \fzhi
    NEV_GSF4 16, 20, 17, 21, 18, 22, 19, 23, blk, 0*16, 4*16, 1*16, 5*16, 2*16, 6*16, 3*16, 7*16
.endm

// ----------------------------------------------------------------------------
// Kernel entry points.  AAPCS64: v8-v15 halves are callee-saved; only
// d8-d13 are touched (v8..v13 hold group twiddles / split registers).
// ----------------------------------------------------------------------------
.macro NEV_KERNEL_FUNC name, body, qval, mval, sh, fp, fphi, fz, fzhi
CRYPT_AARCH64_FUNC_START(\name)
AARCH64_PACIASP
    sub     sp, sp, #(3*16)
    stp     d8, d9, [sp, #0*16]
    stp     d10, d11, [sp, #1*16]
    stp     d12, d13, [sp, #2*16]
    blk     .req x0
    table   .req x1
    wtmp    .req w9
    xtmp    .req x9
    \body   \qval, \mval, \sh, \fp, \fphi, \fz, \fzhi
    .unreq  blk
    .unreq  table
    .unreq  wtmp
    .unreq  xtmp
    ldp     d8, d9, [sp, #0*16]
    ldp     d10, d11, [sp, #1*16]
    ldp     d12, d13, [sp, #2*16]
    add     sp, sp, #(3*16)
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(\name)
.endm

// Fused-scale immediates (see asm_nev_ntt.c generator):
//   q=769:  fP = (-257, -10951), fzetaP = (215, 9161)
//   q=1409: fP = (-385, -8954),  fzetaP = (696, 16186)
//   q=3329: fP = (512, 5040),    fzetaP = (-266, -2618)

// void NEV_NTT128_Q769(int16_t *block, const int16_t *table)
NEV_KERNEL_FUNC NEV_NTT128_Q769, NEV_NTT128_BODY, 769, 21817, 9, 0, 0, 0, 0

// void NEV_INTT128_Q769(int16_t *block, const int16_t *table)
NEV_KERNEL_FUNC NEV_INTT128_Q769, NEV_INTT128_BODY, 769, 21817, 9, 0xfeff, 0xd539, 0x00d7, 0x23c9

// void NEV_NTT128_Q3329(int16_t *block, const int16_t *table)
NEV_KERNEL_FUNC NEV_NTT128_Q3329, NEV_NTT128_BODY, 3329, 20159, 11, 0, 0, 0, 0

// void NEV_INTT128_Q3329(int16_t *block, const int16_t *table)
NEV_KERNEL_FUNC NEV_INTT128_Q3329, NEV_INTT128_BODY, 3329, 20159, 11, 0x0200, 0x13b0, 0xfef6, 0xf5c6

// void NEV_NTT64_Q1409(int16_t *block, const int16_t *table)
NEV_KERNEL_FUNC NEV_NTT64_Q1409, NEV_NTT64_BODY, 1409, 23814, 10, 0, 0, 0, 0

// void NEV_INTT64_Q1409(int16_t *block, const int16_t *table)
NEV_KERNEL_FUNC NEV_INTT64_Q1409, NEV_INTT64_BODY, 1409, 23814, 10, 0xfe7f, 0xdd06, 0x02b8, 0x3f3a

#endif // HITLS_CRYPTO_NEV

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
