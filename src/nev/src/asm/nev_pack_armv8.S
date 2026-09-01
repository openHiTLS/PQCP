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
 * NEV packing / message codecs — ARMv8 NEON kernels
 * ============================================================================
 *
 * NEON ports of the per-q codecs in crypto/nev/src/nev_pack.c, driven by the
 * dispatchers in asm_nev_pack.c (link-time replacement for nev_pack.c in the
 * ARMv8 build).  Packing sits at the packed-interface boundary of the
 * backend contract, so every kernel here is BIT-EXACT against its C codec:
 *
 *  - decoders (FromBytes / Decompress) are exact for EVERY byte input
 *    (malformed ciphertexts and keys reach them);
 *  - NEV_ToMsg / NEV_Compress are exact for every int16 coefficient (they
 *    replicate the C mod-2^16 / mod-2^32 arithmetic operation by operation);
 *  - encoders (ToBytes) are exact for every int16 coefficient as well: the
 *    q = 3329 encoder reproduces the C byte-OR spill semantics with
 *    shrn/shl/orr, and the q = 1409 / q = 769 encoders replicate the C
 *    uint16-zero-extension and uint32 lane arithmetic (which wraps mod 2^32
 *    identically).  All live call sites pass canonical values in [0, q)
 *    anyway (every NEV_PolyToBytes input is produced by a Caddq-terminated
 *    pass).
 *  All kernels are verified against the C codecs by a differential harness
 *  covering, per parameter set, every (value, position) pair in [0, q) for
 *  the encoders, every (byte, position) pair for the decoders, the full
 *  int16 range for ToMsg/Compress, and random full-range polys/buffers.
 *
 * The 12-bit lane split (uzp1/uzp2 + xtn/shrn + st3) follows the ML-KEM
 * ByteEncode12 idiom in ml_kem_poly_armv8.S; the tbl-based gather/scatter
 * of the base-97 codec follows the shuffle-table style of ml_dsa_armv8.S.
 * Only x0-x17 and v0-v7/v16-v31 are used (no callee-saved registers).
 *
 * Functions (AAPCS64):
 *   NEV_ToBytes3329Asm(r, a, n)      q=3329: 2 coeffs -> 3 bytes; n%16 == 0
 *   NEV_FromBytes3329Asm(r, a, n)    inverse; n%16 == 0
 *   NEV_ToBytes1409Asm(r, a, n)      q=1409: 16 coeffs -> 21 bytes (pairs
 *                                    x0 + 1409*x1, 21-bit fields); n%16 == 0
 *   NEV_FromBytes1409Asm(r, a, n)    inverse (magic-constant division by
 *                                    1409 via umull/shrn); n%16 == 0
 *   NEV_ToBytes769Asm(r, a, g4)      q=769: 5 coeffs -> 6 bytes (base-97
 *                                    high parts with carry spill); g4 =
 *                                    number of 4-group iterations, each
 *                                    consuming 20 coeffs / producing 24
 *                                    bytes (remainder groups + bit tail in
 *                                    the C glue)
 *   NEV_FromBytes769Asm(r, a, x2, single)
 *                                    inverse (two interleaved four-record
 *                                    groups hide the mixed-radix latency)
 *   NEV_ToMsgAsm(msg, a, blocks, dim, q)
 *                                    4-carrier message decode, one byte per
 *                                    8 lanes: FlipAbs x4 (Caddq, - q/2, abs;
 *                                    NEON abs equals the C (r+m)^m trick for
 *                                    all int16 incl. INT16_MIN), 16-bit-wrap
 *                                    sums, - q, sign bit, weighted addv pack
 *   NEV_CompressAsm(c, a, n)         c[i] = ((x*341 + 469) >> 10) & 0xff,
 *                                    sign-extended x (smull); n%8 == 0
 *   NEV_DecompressAsm(r, c, n, q)    r[i] = (c[i]*q + 128) >> 8; n%8 == 0
 * ============================================================================
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_NEV

#include "crypt_arm.h"
#include "nev_arm_asm.h"

CRYPT_AARCH64_ARCH_BASE

// =============================================================================
// void NEV_ToBytes3329Asm(uint8_t *r, const int16_t *a, uint64_t n)
//
// 12-bit pack, 16 coeffs -> 24 bytes per iteration (n % 16 == 0):
//     buf[0] = x0 & 0xff
//     buf[1] = (uint8_t)(((uint16_t)x0 >> 8) | ((uint16_t)x1 << 4))
//     buf[2] = (uint8_t)((uint16_t)x1 >> 4)
// The byte OR in buf[1] is reproduced exactly (shrn #8 | xtn(shl #4)), so the
// kernel matches the C encoder for every int16 input, not only canonical ones.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_ToBytes3329Asm)
AARCH64_PACIASP
1:
    ld1     {v0.8h, v1.8h}, [x1], #32
    uzp1    v2.8h, v0.8h, v1.8h         // x0 = even coefficients
    uzp2    v3.8h, v0.8h, v1.8h         // x1 = odd coefficients
    xtn     v4.8b, v2.8h                // b0 = x0 & 0xff
    shrn    v5.8b, v2.8h, #8            // (x0 >> 8) & 0xff
    shl     v6.8h, v3.8h, #4
    xtn     v6.8b, v6.8h                // (x1 << 4) & 0xff
    orr     v5.8b, v5.8b, v6.8b         // b1
    shrn    v6.8b, v3.8h, #4            // b2 = ((uint16_t)x1 >> 4) & 0xff
    st3     {v4.8b, v5.8b, v6.8b}, [x0], #24
    subs    x2, x2, #16
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_ToBytes3329Asm)

// =============================================================================
// void NEV_FromBytes3329Asm(int16_t *r, const uint8_t *a, uint64_t n)
//
// 12-bit unpack, 24 bytes -> 16 coeffs per iteration (n % 16 == 0):
//     x0 = b0 | (b1 & 0x0f) << 8
//     x1 = (b1 >> 4) | b2 << 4
// Exact for every byte input (the sli insert receives (b1 >> 4) <= 0x0f, so
// it equals the C OR).
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_FromBytes3329Asm)
AARCH64_PACIASP
    movi    v7.8b, #0x0f
1:
    ld3     {v0.8b, v1.8b, v2.8b}, [x1], #24
    and     v3.8b, v1.8b, v7.8b         // b1 & 0x0f
    zip1    v4.16b, v0.16b, v3.16b      // x0 lanes: b0 | (b1 & 0x0f) << 8
    ushr    v5.8b, v1.8b, #4            // b1 >> 4
    sli     v5.8b, v2.8b, #4            // (b2 << 4) | (b1 >> 4): x1 low byte
    ushr    v6.8b, v2.8b, #4            // b2 >> 4: x1 high byte
    zip1    v3.16b, v5.16b, v6.16b      // x1 lanes
    zip1    v0.8h, v4.8h, v3.8h         // interleave (x0, x1) pairs
    zip2    v1.8h, v4.8h, v3.8h
    st1     {v0.8h, v1.8h}, [x0], #32
    subs    x2, x2, #16
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_FromBytes3329Asm)

// =============================================================================
// void NEV_ToBytes1409Asm(uint8_t *r, const int16_t *a, uint64_t n)
//
// 16 coeffs -> 21 bytes per iteration (n % 16 == 0).  Pair words
// t[i] = (uint16_t)x[2i] + 1409 * (uint16_t)x[2i+1] (the uint16 zero
// extension and 32-bit arithmetic match the C encoder for every int16
// input) are built in NEON, then the eight fields (21 bits each for
// canonical inputs; the C encoder relies on the same bound) are packed
// LSB-first through three 64-bit GPR words:
//     A = t0 | t1<<21 | t2<<42 | t3<<63          (bits   0..63)
//     B = t3>>1 | t4<<20 | t5<<41 | t6<<62       (bits  64..127)
//     C = t6>>2 | t7<<19                         (bits 128..167, 40 bits)
// For non-canonical (>= 2^21) t the C byte packing keeps only the t bits its
// per-byte terms name — 24/27/22/25/28/23/26/21 bits of t0..t7 respectively
// — and ORs any overlap; masking each lane to that width first makes the
// 64-bit OR packing byte-identical to the C encoder for every int16 input
// (each output byte then receives exactly the same terms at the same bit
// positions).
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_ToBytes1409Asm)
AARCH64_PACIASP
    mov     w3, #1409
    dup     v6.8h, w3
    CRYPT_AARCH64_GET_RELA(x3, .LNEV_Pack1409_EncMasks)
    ld1     {v16.4s, v17.4s}, [x3]
1:
    ld1     {v0.8h, v1.8h}, [x1], #32
    uzp1    v2.8h, v0.8h, v1.8h         // x[2i]
    uzp2    v3.8h, v0.8h, v1.8h         // x[2i+1]
    ushll   v4.4s, v2.4h, #0            // (uint16_t)x[2i]
    ushll2  v5.4s, v2.8h, #0
    umlal   v4.4s, v3.4h, v6.4h         // + 1409 * (uint16_t)x[2i+1]
    umlal2  v5.4s, v3.8h, v6.8h
    and     v4.16b, v4.16b, v16.16b     // per-lane used-bit masks (see above)
    and     v5.16b, v5.16b, v17.16b
    umov    w4, v4.s[0]                 // t0..t7
    umov    w5, v4.s[1]
    umov    w6, v4.s[2]
    umov    w7, v4.s[3]
    umov    w9, v5.s[0]
    umov    w10, v5.s[1]
    umov    w11, v5.s[2]
    umov    w12, v5.s[3]
    orr     x13, x4, x5, lsl #21        // A
    orr     x13, x13, x6, lsl #42
    orr     x13, x13, x7, lsl #63
    lsr     x14, x7, #1                 // B
    orr     x14, x14, x9, lsl #20
    orr     x14, x14, x10, lsl #41
    orr     x14, x14, x11, lsl #62
    lsr     x15, x11, #2                // C (40 bits)
    orr     x15, x15, x12, lsl #19
    stp     x13, x14, [x0]
    str     w15, [x0, #16]
    lsr     x15, x15, #32
    strb    w15, [x0, #20]
    add     x0, x0, #21
    subs    x2, x2, #16
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_ToBytes1409Asm)

// =============================================================================
// void NEV_FromBytes1409Asm(int16_t *r, const uint8_t *a, uint64_t n)
//
// 21 bytes -> 16 coeffs per iteration (n % 16 == 0).  The eight 21-bit
// fields t are extracted through three 64-bit loads (A = bytes 0-7,
// B = bytes 8-15, C = bytes 13-20; B and C overlap, no overread), then
//     x[2i+1] = (t * 3048238) >> 32   (exact via umull + shrn #32)
//     x[2i]   = t - 1409 * x[2i+1]
// exactly as the C decoder, for every byte input.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_FromBytes1409Asm)
AARCH64_PACIASP
    mov     w3, #0x832e                 // 3048238 = 0x2e832e
    movk    w3, #0x2e, lsl #16
    dup     v6.4s, w3
    mov     w3, #1409
    dup     v7.4s, w3
1:
    ldp     x4, x5, [x1]                // A, B
    ldur    x6, [x1, #13]               // C
    add     x1, x1, #21
    and     x7, x4, #0x1fffff           // t0
    ubfx    x9, x4, #21, #21            // t1
    ubfx    x10, x4, #42, #21           // t2
    lsr     x11, x4, #63                // t3 = A>>63 | (B & 0xfffff) << 1
    ubfx    x12, x5, #0, #20
    orr     x11, x11, x12, lsl #1
    ubfx    x12, x5, #20, #21           // t4
    ubfx    x13, x5, #41, #21           // t5
    ubfx    x14, x6, #22, #21           // t6
    lsr     x15, x6, #43                // t7
    orr     x7, x7, x9, lsl #32
    orr     x10, x10, x11, lsl #32
    orr     x12, x12, x13, lsl #32
    orr     x14, x14, x15, lsl #32
    mov     v0.d[0], x7                 // t0..t3
    mov     v0.d[1], x10
    mov     v1.d[0], x12                // t4..t7
    mov     v1.d[1], x14
    umull   v2.2d, v0.2s, v6.2s         // hi = (t * 3048238) >> 32
    umull2  v3.2d, v0.4s, v6.4s
    shrn    v4.2s, v2.2d, #32
    shrn2   v4.4s, v3.2d, #32
    umull   v2.2d, v1.2s, v6.2s
    umull2  v3.2d, v1.4s, v6.4s
    shrn    v5.2s, v2.2d, #32
    shrn2   v5.4s, v3.2d, #32
    mls     v0.4s, v4.4s, v7.4s         // t - 1409 * hi
    mls     v1.4s, v5.4s, v7.4s
    xtn     v2.4h, v0.4s                // x[2i] lanes
    xtn2    v2.8h, v1.4s
    xtn     v3.4h, v4.4s                // x[2i+1] lanes
    xtn2    v3.8h, v5.4s
    zip1    v0.8h, v2.8h, v3.8h
    zip2    v1.8h, v2.8h, v3.8h
    st1     {v0.8h, v1.8h}, [x0], #32
    subs    x2, x2, #16
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_FromBytes1409Asm)

// =============================================================================
// void NEV_ToBytes769Asm(uint8_t *r, const int16_t *a, uint64_t g4)
//
// Base-97 pack: each of the g4 iterations consumes 4 groups of 5 coeffs
// (40 bytes) and produces 24 output bytes.  Lanes are groups; the whole C
// Encode5 chain runs in uint32 lanes (identical mod-2^32 wrap):
//     wl  = (sum (x[i] & 7) << 3i) << 1
//     wh  = ((x4>>3)*97 + (x3>>3))*97 + (x2>>3))*97 + (x1>>3)
//     t   = wh * 48;  wl |= t >> 31;  t <<= 1
//     wh += (x0 >> 3);  wh = t + wh;  wl |= (t & ~wh) >> 31
//     bytes = wl[0..1] || wh[0..3]
// (x[i] gathered as zero-extended uint16, exactly the C (uint16_t)x[i].)
//
// The chain above is ~20 dependent NEON ops deep and only 4 lanes wide, so one
// group leaves the ASIMD pipes ~40% idle (measured: 45 instructions in 49-64
// cycles, against a port-limited floor of 30-41).  The loop therefore runs TWO
// groups per iteration from disjoint register sets; the out-of-order window
// holds both bodies (90 instructions) so the second chain fills the first one's
// latency shadows.  Neither body's arithmetic changes, so the output bytes are
// identical.  d8-d15 are callee-saved and the second body needs v8-v15, hence
// the frame.
// =============================================================================

// One base-97 group of 4: reads 40 bytes from \p, writes 24 bytes at [x0]+.
// a0/a1/a2 must be consecutive (tbl source triple) and so must wl/wh (tbl
// source pair).  a2 is reused as t and a0 as scratch once the gathers retire.
.macro NEV_ENC769_G4 p, a0, a1, a2, x0r, x1r, x2r, x3r, x4r, wl, wh
    ldr     q\a0, [\p]                  // coeffs 0-7
    ldr     q\a1, [\p, #16]             // coeffs 8-15
    ldr     d\a2, [\p, #32]             // coeffs 16-19
    tbl     v\x0r\().16b, {v\a0\().16b, v\a1\().16b, v\a2\().16b}, v18.16b
    tbl     v\x1r\().16b, {v\a0\().16b, v\a1\().16b, v\a2\().16b}, v19.16b
    tbl     v\x2r\().16b, {v\a0\().16b, v\a1\().16b, v\a2\().16b}, v20.16b
    tbl     v\x3r\().16b, {v\a0\().16b, v\a1\().16b, v\a2\().16b}, v21.16b
    tbl     v\x4r\().16b, {v\a0\().16b, v\a1\().16b, v\a2\().16b}, v22.16b
    // wl = (x0 & 7) | (x1 & 7) << 3 | ... | (x4 & 7) << 12, then << 1
    and     v\wl\().16b, v\x0r\().16b, v27.16b
    and     v\wh\().16b, v\x1r\().16b, v27.16b
    shl     v\wh\().4s, v\wh\().4s, #3
    orr     v\wl\().16b, v\wl\().16b, v\wh\().16b
    and     v\wh\().16b, v\x2r\().16b, v27.16b
    shl     v\wh\().4s, v\wh\().4s, #6
    orr     v\wl\().16b, v\wl\().16b, v\wh\().16b
    and     v\wh\().16b, v\x3r\().16b, v27.16b
    shl     v\wh\().4s, v\wh\().4s, #9
    orr     v\wl\().16b, v\wl\().16b, v\wh\().16b
    and     v\wh\().16b, v\x4r\().16b, v27.16b
    shl     v\wh\().4s, v\wh\().4s, #12
    orr     v\wl\().16b, v\wl\().16b, v\wh\().16b
    shl     v\wl\().4s, v\wl\().4s, #1
    // wh chain on the high parts u[i] = x[i] >> 3 (planes reused in place)
    ushr    v\x0r\().4s, v\x0r\().4s, #3    // u0
    ushr    v\x1r\().4s, v\x1r\().4s, #3    // u1
    ushr    v\x2r\().4s, v\x2r\().4s, #3    // u2
    ushr    v\x3r\().4s, v\x3r\().4s, #3    // u3
    ushr    v\x4r\().4s, v\x4r\().4s, #3    // u4
    mla     v\x3r\().4s, v\x4r\().4s, v25.4s    // u3 + 97 * u4
    mla     v\x2r\().4s, v\x3r\().4s, v25.4s    // u2 + 97 * (...)
    mla     v\x1r\().4s, v\x2r\().4s, v25.4s    // wh = u1 + 97 * (...)
    mul     v\a2\().4s, v\x1r\().4s, v26.4s     // t = wh * 48
    ushr    v\a0\().4s, v\a2\().4s, #31
    orr     v\wl\().16b, v\wl\().16b, v\a0\().16b   // wl |= t >> 31
    shl     v\a2\().4s, v\a2\().4s, #1              // t <<= 1
    add     v\x1r\().4s, v\x1r\().4s, v\x0r\().4s   // wh += u0
    add     v\wh\().4s, v\a2\().4s, v\x1r\().4s     // wh' = t + wh
    bic     v\a0\().16b, v\a2\().16b, v\wh\().16b   // t & ~wh'
    ushr    v\a0\().4s, v\a0\().4s, #31
    orr     v\wl\().16b, v\wl\().16b, v\a0\().16b   // wl |= (t & ~wh') >> 31
    tbl     v\a0\().16b, {v\wl\().16b, v\wh\().16b}, v23.16b    // 24 output bytes
    tbl     v\a1\().8b, {v\wl\().16b, v\wh\().16b}, v24.8b
    st1     {v\a0\().16b}, [x0], #16
    st1     {v\a1\().8b}, [x0], #8
.endm

CRYPT_AARCH64_FUNC_START(NEV_ToBytes769Asm)
AARCH64_PACIASP
    stp     d8, d9, [sp, #-48]!
    stp     d10, d11, [sp, #16]
    stp     d12, d13, [sp, #32]
    CRYPT_AARCH64_GET_RELA(x3, .LNEV_Pack769_EncGatherIdx)
    ld1     {v18.16b, v19.16b, v20.16b, v21.16b}, [x3], #64
    ld1     {v22.16b, v23.16b, v24.16b}, [x3]
    mov     w3, #97
    dup     v25.4s, w3
    mov     w3, #48
    dup     v26.4s, w3
    movi    v27.4s, #7
    lsr     x5, x2, #1                  // pairs
    cbz     x5, 2f
1:
    add     x4, x1, #40                 // ldr q needs a 16-aligned immediate
    NEV_ENC769_G4 x1, 0, 1, 2, 3, 4, 5, 6, 7, 16, 17
    NEV_ENC769_G4 x4, 8, 9, 10, 11, 12, 13, 28, 29, 30, 31
    add     x1, x1, #80
    subs    x5, x5, #1
    b.ne    1b
2:
    tbz     x2, #0, 3f                  // odd group count: one plain body
    NEV_ENC769_G4 x1, 0, 1, 2, 3, 4, 5, 6, 7, 16, 17
3:
    ldp     d10, d11, [sp, #16]
    ldp     d12, d13, [sp, #32]
    ldp     d8, d9, [sp], #48
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_ToBytes769Asm)

// q=769 mixed-radix decode stages. Keeping two independent groups live in the
// main loop covers multiply/shift latency without changing uint32 wraparound.
.macro NEV_DECODE769_X0 bits, wh, t0, t1, t2, out
    ushr    \t0\().4s, \wh\().4s, #19
    and     \t1\().16b, \bits\().16b, v24.16b
    shl     \t1\().4s, \t1\().4s, #13
    orr     \t1\().16b, \t1\().16b, \t0\().16b
    add     \t0\().4s, \t1\().4s, \t1\().4s
    add     \t0\().4s, \t0\().4s, \t1\().4s
    and     \t1\().16b, \wh\().16b, v29.16b
    add     \t0\().4s, \t0\().4s, \t1\().4s
    ushr    \bits\().4s, \bits\().4s, #1
    ushr    \t1\().4s, \t0\().4s, #9
    mul     \t1\().4s, \t1\().4s, v27.4s
    and     \t2\().16b, \t0\().16b, v26.16b
    add     \t0\().4s, \t1\().4s, \t2\().4s
    mul     \t1\().4s, \t0\().4s, v30.4s
    ushr    \t1\().4s, \t1\().4s, #22
    mls     \t0\().4s, \t1\().4s, v31.4s
    and     \t2\().16b, \bits\().16b, v25.16b
    shl     \out\().4s, \t0\().4s, #3
    orr     \out\().16b, \out\().16b, \t2\().16b
    ushr    \bits\().4s, \bits\().4s, #3
.endm

.macro NEV_DECODE769_X1 bits, wh, prev, t0, t1, out
    sub     \wh\().4s, \wh\().4s, \prev\().4s
    mul     \wh\().4s, \wh\().4s, v28.4s
    ushr    \t0\().4s, \wh\().4s, #19
    add     \t1\().4s, \t0\().4s, \t0\().4s
    add     \t0\().4s, \t1\().4s, \t0\().4s
    and     \t1\().16b, \wh\().16b, v29.16b
    add     \t0\().4s, \t0\().4s, \t1\().4s
    ushr    \t1\().4s, \t0\().4s, #9
    mul     \t1\().4s, \t1\().4s, v27.4s
    and     \prev\().16b, \t0\().16b, v26.16b
    add     \t0\().4s, \t1\().4s, \prev\().4s
    mul     \t1\().4s, \t0\().4s, v30.4s
    ushr    \t1\().4s, \t1\().4s, #22
    mls     \t0\().4s, \t1\().4s, v31.4s
    and     \prev\().16b, \bits\().16b, v25.16b
    shl     \out\().4s, \t0\().4s, #3
    orr     \out\().16b, \out\().16b, \prev\().16b
    ushr    \bits\().4s, \bits\().4s, #3
.endm

.macro NEV_DECODE769_X2 bits, wh, prev, t0, t1, out
    sub     \wh\().4s, \wh\().4s, \prev\().4s
    mul     \wh\().4s, \wh\().4s, v28.4s
    ushr    \t1\().4s, \wh\().4s, #9
    mul     \t1\().4s, \t1\().4s, v27.4s
    and     \t0\().16b, \wh\().16b, v26.16b
    add     \prev\().4s, \t1\().4s, \t0\().4s
    mul     \t1\().4s, \prev\().4s, v30.4s
    ushr    \t1\().4s, \t1\().4s, #22
    mls     \prev\().4s, \t1\().4s, v31.4s
    and     \t0\().16b, \bits\().16b, v25.16b
    shl     \out\().4s, \prev\().4s, #3
    orr     \out\().16b, \out\().16b, \t0\().16b
    ushr    \bits\().4s, \bits\().4s, #3
.endm

.macro NEV_DECODE769_X34 bits, wh, prev, t0, out3, out4
    sub     \wh\().4s, \wh\().4s, \prev\().4s
    mul     \wh\().4s, \wh\().4s, v28.4s
    mul     \t0\().4s, \wh\().4s, v30.4s
    ushr    \t0\().4s, \t0\().4s, #22
    mls     \wh\().4s, \t0\().4s, v31.4s
    and     \prev\().16b, \bits\().16b, v25.16b
    shl     \out3\().4s, \wh\().4s, #3
    orr     \out3\().16b, \out3\().16b, \prev\().16b
    ushr    \bits\().4s, \bits\().4s, #3
    shl     \out4\().4s, \t0\().4s, #3
    add     \out4\().4s, \out4\().4s, \bits\().4s
.endm

// =============================================================================
// void NEV_FromBytes769Asm(int16_t *r, const uint8_t *a,
//                          uint64_t x2Groups, uint64_t singleGroups)
//
// An X2 iteration consumes 48 bytes / produces 40 coefficients. The optional
// single iteration consumes 24 bytes / produces 20 coefficients. The C glue
// handles the final one-to-three records and the 10-bit coefficient tail.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_FromBytes769Asm)
AARCH64_PACIASP
    stp     d8, d9, [sp, #-64]!
    stp     d10, d11, [sp, #16]
    stp     d12, d13, [sp, #32]
    stp     d14, d15, [sp, #48]
    mov     w8, w2

    mov     w9, #0x7ffff
    dup     v29.4s, w9
    mov     w9, #43241
    dup     v30.4s, w9
    mov     w9, #97
    dup     v31.4s, w9
    mov     w9, #0xa3a1
    movk    w9, #0x5f02, lsl #16
    dup     v28.4s, w9
    movi    v24.4s, #1
    mov     w9, #27
    dup     v27.4s, w9
    mov     w9, #0x1ff
    dup     v26.4s, w9
    mov     w9, #7
    dup     v25.4s, w9

    cbz     w8, .LNEV_FromBytes769SingleSetup
.LNEV_FromBytes769X2Loop:
    ld3     {v0.8h, v1.8h, v2.8h}, [x1], #48
    uxtl    v3.4s, v0.4h
    uxtl    v4.4s, v1.4h
    uxtl    v5.4s, v2.4h
    shl     v5.4s, v5.4s, #16
    orr     v4.16b, v4.16b, v5.16b
    uxtl2   v18.4s, v0.8h
    uxtl2   v19.4s, v1.8h
    uxtl2   v20.4s, v2.8h
    shl     v20.4s, v20.4s, #16
    orr     v19.16b, v19.16b, v20.16b

    NEV_DECODE769_X0 v3, v4, v5, v6, v7, v8
    NEV_DECODE769_X0 v18, v19, v20, v21, v22, v13
    NEV_DECODE769_X1 v3, v4, v5, v6, v7, v9
    NEV_DECODE769_X1 v18, v19, v20, v21, v22, v14
    NEV_DECODE769_X2 v3, v4, v6, v5, v7, v10
    NEV_DECODE769_X2 v18, v19, v21, v20, v22, v15
    NEV_DECODE769_X34 v3, v4, v6, v7, v11, v12
    NEV_DECODE769_X34 v18, v19, v21, v22, v16, v17

    xtn     v8.4h, v8.4s
    xtn     v9.4h, v9.4s
    xtn     v10.4h, v10.4s
    xtn     v11.4h, v11.4s
    xtn     v12.4h, v12.4s
    xtn     v13.4h, v13.4s
    xtn     v14.4h, v14.4s
    xtn     v15.4h, v15.4s
    xtn     v16.4h, v16.4s
    xtn     v17.4h, v17.4s
    st4     {v8.h, v9.h, v10.h, v11.h}[0], [x0]
    umov    w9, v12.h[0]
    strh    w9, [x0, #8]
    add     x0, x0, #10
    st4     {v8.h, v9.h, v10.h, v11.h}[1], [x0]
    umov    w9, v12.h[1]
    strh    w9, [x0, #8]
    add     x0, x0, #10
    st4     {v8.h, v9.h, v10.h, v11.h}[2], [x0]
    umov    w9, v12.h[2]
    strh    w9, [x0, #8]
    add     x0, x0, #10
    st4     {v8.h, v9.h, v10.h, v11.h}[3], [x0]
    umov    w9, v12.h[3]
    strh    w9, [x0, #8]
    add     x0, x0, #10
    st4     {v13.h, v14.h, v15.h, v16.h}[0], [x0]
    umov    w9, v17.h[0]
    strh    w9, [x0, #8]
    add     x0, x0, #10
    st4     {v13.h, v14.h, v15.h, v16.h}[1], [x0]
    umov    w9, v17.h[1]
    strh    w9, [x0, #8]
    add     x0, x0, #10
    st4     {v13.h, v14.h, v15.h, v16.h}[2], [x0]
    umov    w9, v17.h[2]
    strh    w9, [x0, #8]
    add     x0, x0, #10
    st4     {v13.h, v14.h, v15.h, v16.h}[3], [x0]
    umov    w9, v17.h[3]
    strh    w9, [x0, #8]
    add     x0, x0, #10

    subs    w8, w8, #1
    b.ne    .LNEV_FromBytes769X2Loop

.LNEV_FromBytes769SingleSetup:
    mov     w8, w3
    cbz     w8, .LNEV_FromBytes769Done
.LNEV_FromBytes769SingleLoop:
    ld3     {v0.4h, v1.4h, v2.4h}, [x1], #24
    uxtl    v3.4s, v0.4h
    uxtl    v4.4s, v1.4h
    uxtl    v5.4s, v2.4h
    shl     v5.4s, v5.4s, #16
    orr     v4.16b, v4.16b, v5.16b

    NEV_DECODE769_X0 v3, v4, v5, v6, v7, v8
    NEV_DECODE769_X1 v3, v4, v5, v6, v7, v9
    NEV_DECODE769_X2 v3, v4, v6, v5, v7, v10
    NEV_DECODE769_X34 v3, v4, v6, v7, v11, v12

    xtn     v8.4h, v8.4s
    xtn     v9.4h, v9.4s
    xtn     v10.4h, v10.4s
    xtn     v11.4h, v11.4s
    xtn     v12.4h, v12.4s
    st4     {v8.h, v9.h, v10.h, v11.h}[0], [x0]
    umov    w9, v12.h[0]
    strh    w9, [x0, #8]
    add     x0, x0, #10
    st4     {v8.h, v9.h, v10.h, v11.h}[1], [x0]
    umov    w9, v12.h[1]
    strh    w9, [x0, #8]
    add     x0, x0, #10
    st4     {v8.h, v9.h, v10.h, v11.h}[2], [x0]
    umov    w9, v12.h[2]
    strh    w9, [x0, #8]
    add     x0, x0, #10
    st4     {v8.h, v9.h, v10.h, v11.h}[3], [x0]
    umov    w9, v12.h[3]
    strh    w9, [x0, #8]
    add     x0, x0, #10

    subs    w8, w8, #1
    b.ne    .LNEV_FromBytes769SingleLoop

.LNEV_FromBytes769Done:
    ldp     d14, d15, [sp, #48]
    ldp     d12, d13, [sp, #32]
    ldp     d10, d11, [sp, #16]
    ldp     d8, d9, [sp], #64
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_FromBytes769Asm)

// =============================================================================
// void NEV_ToMsgAsm(uint8_t *msg, const int16_t *a, uint64_t blocks,
//                   uint64_t dim, uint64_t q)
//
// Message decode: for every 8 lanes l of every quarter-block v of every
// block, msg byte = sum over lanes of
//     ((uint16_t)(FA(c[l]) + FA(c[l+d/4]) + FA(c[l+d/2]) + FA(c[l+3d/4]) - q)
//       >> 15) << lane
// with FA(x) = |Caddq(x) - q/2| (the C FlipAbs).  All arithmetic is 16-bit
// lanes wrapping exactly like the C uint16 accumulation; abs matches the C
// (r+m)^m for all int16 (both give 0x8000 for INT16_MIN); the bit pack is
// and-with-weights + addv (the lane sums are distinct powers of two, so the
// sum equals the C OR).  Bit-exact for every int16 input.  blocks = t,
// dim % 32 == 0; writes blocks * dim / 32 message bytes sequentially.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_ToMsgAsm)
AARCH64_PACIASP
    dup     v29.8h, w4                  // q
    lsr     w5, w4, #1
    dup     v30.8h, w5                  // q / 2
    CRYPT_AARCH64_GET_RELA(x6, .LNEV_ToMsg_Weights)
    ld1     {v31.8h}, [x6]
    lsr     x7, x3, #2                  // quarter (elements)
    lsl     x8, x7, #1                  // quarter (bytes)
1:
    mov     x9, x1                      // carrier 0
    add     x10, x9, x8                 // carrier 1
    add     x11, x10, x8                // carrier 2
    add     x12, x11, x8                // carrier 3
    mov     x13, x7
2:
    ld1     {v0.8h}, [x9], #16
    ld1     {v1.8h}, [x10], #16
    ld1     {v2.8h}, [x11], #16
    ld1     {v3.8h}, [x12], #16
    sshr    v4.8h, v0.8h, #15           // FlipAbs(c0): Caddq
    and     v4.16b, v4.16b, v29.16b
    add     v0.8h, v0.8h, v4.8h
    sub     v0.8h, v0.8h, v30.8h        // - q/2
    abs     v0.8h, v0.8h
    sshr    v4.8h, v1.8h, #15           // FlipAbs(c1)
    and     v4.16b, v4.16b, v29.16b
    add     v1.8h, v1.8h, v4.8h
    sub     v1.8h, v1.8h, v30.8h
    abs     v1.8h, v1.8h
    sshr    v4.8h, v2.8h, #15           // FlipAbs(c2)
    and     v4.16b, v4.16b, v29.16b
    add     v2.8h, v2.8h, v4.8h
    sub     v2.8h, v2.8h, v30.8h
    abs     v2.8h, v2.8h
    sshr    v4.8h, v3.8h, #15           // FlipAbs(c3)
    and     v4.16b, v4.16b, v29.16b
    add     v3.8h, v3.8h, v4.8h
    sub     v3.8h, v3.8h, v30.8h
    abs     v3.8h, v3.8h
    add     v0.8h, v0.8h, v1.8h         // t (uint16 wrap)
    add     v2.8h, v2.8h, v3.8h
    add     v0.8h, v0.8h, v2.8h
    sub     v0.8h, v0.8h, v29.8h        // t - q
    sshr    v0.8h, v0.8h, #15           // all-ones iff bit 15 set (== the
                                        // C (uint16_t)(t - q) >> 15 test)
    and     v0.16b, v0.16b, v31.16b     // lane k -> bit k weight
    addv    h0, v0.8h
    st1     {v0.b}[0], [x0], #1
    subs    x13, x13, #8
    b.ne    2b
    add     x1, x1, x3, lsl #1          // next block
    subs    x2, x2, #1
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_ToMsgAsm)

// =============================================================================
// void NEV_CompressAsm(uint8_t *c, const int16_t *a, uint64_t n)
//
// 8-bit ciphertext compression (COMPRESS sets, q = 769; the constants are
// codec-fixed): c[i] = (((uint32_t)a[i] * 341 + 469) >> 10) & 0xff.  smull
// reproduces the C sign-extended uint32 product mod 2^32; shrn #10 + xtn
// select bits 10..17.  Exact for every int16 input.  n % 8 == 0.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_CompressAsm)
AARCH64_PACIASP
    mov     w3, #341
    dup     v6.4h, w3
    mov     w3, #469
    dup     v7.4s, w3
1:
    ld1     {v0.8h}, [x1], #16
    smull   v1.4s, v0.4h, v6.4h
    smull2  v2.4s, v0.8h, v6.h[0]
    add     v1.4s, v1.4s, v7.4s
    add     v2.4s, v2.4s, v7.4s
    shrn    v3.4h, v1.4s, #10
    shrn2   v3.8h, v2.4s, #10
    xtn     v4.8b, v3.8h
    st1     {v4.8b}, [x0], #8
    subs    x2, x2, #8
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_CompressAsm)

// =============================================================================
// void NEV_DecompressAsm(int16_t *r, const uint8_t *c, uint64_t n, uint64_t q)
//
// 8-bit ciphertext decompression: r[i] = (c[i] * q + 128) >> 8, exact for
// every byte input (product < 2^20, shrn #8 selects bits 8..23).  n % 8 == 0.
// =============================================================================
CRYPT_AARCH64_FUNC_START(NEV_DecompressAsm)
AARCH64_PACIASP
    dup     v6.4h, w3
    movi    v7.4s, #128
1:
    ld1     {v0.8b}, [x1], #8
    ushll   v0.8h, v0.8b, #0
    umull   v1.4s, v0.4h, v6.4h
    umull2  v2.4s, v0.8h, v6.h[0]
    add     v1.4s, v1.4s, v7.4s
    add     v2.4s, v2.4s, v7.4s
    shrn    v3.4h, v1.4s, #8
    shrn2   v3.8h, v2.4s, #8
    st1     {v3.8h}, [x0], #16
    subs    x2, x2, #8
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_DecompressAsm)

// ---------------------------------------------------------------------------
// Shuffle tables.
// ---------------------------------------------------------------------------
CRYPT_AARCH64_RODATA_SECTION
.balign 16
// Encode5 gather: plane k lane g <- coefficient 5g + k, as zero-extended
// uint16 in a uint32 lane (source byte 2*(5g+k), 2*(5g+k)+1, then zeros).
.LNEV_Pack769_EncGatherIdx:
    .byte   0, 1, 255, 255, 10, 11, 255, 255, 20, 21, 255, 255, 30, 31, 255, 255   // x0
    .byte   2, 3, 255, 255, 12, 13, 255, 255, 22, 23, 255, 255, 32, 33, 255, 255   // x1
    .byte   4, 5, 255, 255, 14, 15, 255, 255, 24, 25, 255, 255, 34, 35, 255, 255   // x2
    .byte   6, 7, 255, 255, 16, 17, 255, 255, 26, 27, 255, 255, 36, 37, 255, 255   // x3
    .byte   8, 9, 255, 255, 18, 19, 255, 255, 28, 29, 255, 255, 38, 39, 255, 255   // x4
// Encode5 scatter: 24 output bytes from {wl (bytes 0-15), wh (bytes 16-31)}:
// per group g: wl bytes 4g, 4g+1 then wh bytes 16+4g .. 16+4g+3.
    .byte   0, 1, 16, 17, 18, 19, 4, 5, 20, 21, 22, 23, 8, 9, 24, 25
    .byte   26, 27, 12, 13, 28, 29, 30, 31, 255, 255, 255, 255, 255, 255, 255, 255

.balign 16
// ToMsg bit weights: lane k contributes 2^k.
.LNEV_ToMsg_Weights:
    .hword  1, 2, 4, 8, 16, 32, 64, 128

.balign 16
// q = 1409 encoder: bits of t0..t7 the C byte packing keeps (24, 27, 22, 25 /
// 28, 23, 26, 21 bits).
.LNEV_Pack1409_EncMasks:
    .word   0x00ffffff, 0x07ffffff, 0x003fffff, 0x01ffffff
    .word   0x0fffffff, 0x007fffff, 0x03ffffff, 0x001fffff

#endif // HITLS_CRYPTO_NEV

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
