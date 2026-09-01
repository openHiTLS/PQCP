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
 * NEV uniform-ternary rejection sampling — ARMv8 NEON byte compaction
 * ============================================================================
 *
 * tbl-compaction acceptance filter for the base-243 rejection sampler
 * (nev_sample.c poly_bias3_ternary path), following the ML-DSA rejection
 * idiom (MldRejUniformAsm in ml_dsa_armv8.S): unsigned compare -> per-lane
 * bit weights -> bitmap -> indexed shuffle-table row -> tbl compaction ->
 * count-advance.  This kernel only FILTERS the KDF stream: it copies the
 * bytes with value < 243, in order, to dst and returns how many were
 * accepted.  Acceptance and order are exactly those of the scalar sampler,
 * so the downstream base-3 digit extraction (asm_nev_sample.c) reproduces
 * the reference coefficient stream bit for bit.
 *
 * uint64_t NEV_RejTernaryCompactAsm(uint8_t *dst, const uint8_t *src,
 *                                   uint64_t len)
 *   len % 8 == 0 (every caller passes a multiple of the KDF rate, and all
 *   NEV rates are multiples of 8).  dst needs len + 8 bytes of capacity:
 *   each 8-byte group is stored in full before the pointer advances by the
 *   accepted count, so up to 8 - accepted bytes past the final accepted
 *   byte are scratch.  Returns the number of accepted bytes.
 *   Only x0-x17 and v0-v7/v16-v31 are used.
 *
 * ----------------------------------------------------------------------------
 * NEON centered-binomial extractors (the buffer-to-coefficients half of
 * nev_sample.c's CbdDispatch, following the MLKEMCBD2/CBD3 idioms of
 * ml_kem_poly_armv8.S: bit-mask/popcount split into per-position byte
 * vectors, usubl widening, interleaving stores):
 *
 *   void NEV_Cbd1Asm(int16_t *r, const uint8_t *buf, uint32_t n)
 *     byte i yields r[4i+j] = bit(2j) - bit(2j+1); A/B bit vectors per
 *     position, usubl, st4-interleaved (16 bytes -> 64 coeffs per pass).
 *   void NEV_Cbd2Asm(int16_t *r, const uint8_t *buf, uint32_t n)
 *     the ML-KEM eta=2 scheme: s = (b & 0x55) + ((b >> 1) & 0x55), byte k
 *     yields r[2k] = (s & 3) - ((s >> 2) & 3), r[2k+1] from the high nibble;
 *     st2-interleaved (16 bytes -> 32 coeffs per pass).
 *   void NEV_Cbd3Asm(int16_t *r, const uint8_t *buf, uint32_t n)
 *     r = Cbd1(buf[0 .. n/4)) + Cbd2(buf[n/4 ..)): both parts are brought
 *     into linear coefficient order with zip1/zip2 and added before one
 *     linear store (8 + 16 bytes -> 32 coeffs per pass).
 *   void NEV_Cbd4Asm(int16_t *r, const uint8_t *buf, uint32_t n)
 *     r[i] = popcount(buf[i] & 0xf) - popcount(buf[i] >> 4) via cnt
 *     (32 bytes -> 32 coeffs per pass, already in linear order).
 *   void NEV_Cbd7Asm(int16_t *r, const uint8_t *buf, uint32_t n)
 *     r = Cbd4(buf[0 .. n)) + Cbd3(buf[n ..)) fused per 32 coefficients.
 *
 * All five walk the exact byte ranges of the scalar extractors and reproduce
 * their coefficient order lane for lane, so the outputs are BIT-EXACT
 * (verified by the differential harness and the KAT corpus).  n is a
 * multiple of 64 for every parameter set (512/1024/2048).  Only x0-x17 and
 * v0-v7/v16-v31 are used (no callee-saved state anywhere in this file).
 *
 *   void NEV_MaskTernary8Asm(int16_t *r, const uint8_t *mask, uint32_t n)
 *     the masking pass of SampleBias8Ternary: r[8i+j] &= -((mask[i]>>j)&1);
 *     one ld1r-dup + cmtst against the byte-pair weight table per 8
 *     coefficients turns each mask bit into a per-halfword 0/0xffff mask.
 *
 *   void NEV_NoiseMExtractAsm(int16_t *r, const uint8_t *buf,
 *                             uint64_t eta, uint64_t seedLen, uint64_t dim)
 *     the plane-extraction loop nest of nev_sample.c NoiseMExtractE (after
 *     the plane-0 XOR fold, which stays in C): for every plane-byte pair the
 *     8 carried coefficients live in one .8h accumulator, each bit becoming
 *     a 0/-1 halfword mask via the same ld1r + cmtst idiom
 *     (acc += bit_a - bit_b  ==  acc = acc - Ma + Mb with M = cmtst = -bit).
 *     Identical index arithmetic to the C loop nest, hence bit-exact.
 * ============================================================================
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_NEV

#include "crypt_arm.h"
#include "nev_arm_asm.h"

CRYPT_AARCH64_ARCH_BASE

CRYPT_AARCH64_FUNC_START(NEV_RejTernaryCompactAsm)
AARCH64_PACIASP
    CRYPT_AARCH64_GET_RELA(x3, .LNEV_RejCompactTable)
    CRYPT_AARCH64_GET_RELA(x4, .LNEV_RejBitWeights)
    ld1     {v6.8b}, [x4]               // {1, 2, 4, ..., 128}
    movi    v7.8b, #243
    mov     x5, x0                      // dst walk pointer
1:
    ld1     {v0.8b}, [x1], #8
    cmhi    v1.8b, v7.8b, v0.8b         // 0xff where byte < 243
    and     v1.8b, v1.8b, v6.8b         // lane i -> bit i if accepted
    uaddlv  h2, v1.8b                   // bitmap (sum of distinct bits)
    cnt     v3.8b, v1.8b                // 1 per accepted lane
    uaddlv  h3, v3.8b                   // accepted count
    fmov    w6, s2
    add     x6, x3, x6, lsl #3
    ld1     {v4.8b}, [x6]               // compaction row for this bitmap
    tbl     v0.8b, {v0.16b}, v4.8b      // accepted bytes to the front
    st1     {v0.8b}, [x5]
    fmov    w7, s3
    add     x5, x5, x7                  // advance by accepted count
    subs    x2, x2, #8
    b.ne    1b
    sub     x0, x5, x0                  // total accepted
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_RejTernaryCompactAsm)

// ----------------------------------------------------------------------------
// void NEV_Cbd1Asm(int16_t *r, const uint8_t *buf, uint32_t n)
// ----------------------------------------------------------------------------
CRYPT_AARCH64_FUNC_START(NEV_Cbd1Asm)
AARCH64_PACIASP
    mov     w2, w2                      // zero-extend the uint32_t n argument
    movi    v16.16b, #0x01
1:
    ld1     {v0.16b}, [x1], #16
    and     v1.16b, v0.16b, v16.16b     // A0 = bit 0
    ushr    v2.16b, v0.16b, #1
    and     v2.16b, v2.16b, v16.16b     // B0 = bit 1
    ushr    v3.16b, v0.16b, #2
    and     v3.16b, v3.16b, v16.16b     // A1
    ushr    v4.16b, v0.16b, #3
    and     v4.16b, v4.16b, v16.16b     // B1
    ushr    v5.16b, v0.16b, #4
    and     v5.16b, v5.16b, v16.16b     // A2
    ushr    v6.16b, v0.16b, #5
    and     v6.16b, v6.16b, v16.16b     // B2
    ushr    v7.16b, v0.16b, #6
    and     v7.16b, v7.16b, v16.16b     // A3
    ushr    v0.16b, v0.16b, #7          // B3 (top bit, no mask needed)
    usubl   v17.8h, v1.8b, v2.8b        // c0, bytes 0-7
    usubl   v18.8h, v3.8b, v4.8b        // c1
    usubl   v19.8h, v5.8b, v6.8b        // c2
    usubl   v20.8h, v7.8b, v0.8b        // c3
    usubl2  v21.8h, v1.16b, v2.16b      // c0, bytes 8-15
    usubl2  v22.8h, v3.16b, v4.16b
    usubl2  v23.8h, v5.16b, v6.16b
    usubl2  v24.8h, v7.16b, v0.16b
    st4     {v17.8h-v20.8h}, [x0], #64  // r[4i+j] = cj[i]
    st4     {v21.8h-v24.8h}, [x0], #64
    subs    x2, x2, #64
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Cbd1Asm)

// ----------------------------------------------------------------------------
// void NEV_Cbd2Asm(int16_t *r, const uint8_t *buf, uint32_t n)
// ----------------------------------------------------------------------------
CRYPT_AARCH64_FUNC_START(NEV_Cbd2Asm)
AARCH64_PACIASP
    mov     w2, w2                      // zero-extend the uint32_t n argument
    movi    v16.16b, #0x55
    movi    v17.16b, #0x03
1:
    ld1     {v0.16b}, [x1], #16
    ushr    v1.16b, v0.16b, #1
    and     v0.16b, v0.16b, v16.16b
    and     v1.16b, v1.16b, v16.16b
    add     v0.16b, v0.16b, v1.16b      // s = (b & 0x55) + ((b >> 1) & 0x55)
    and     v1.16b, v0.16b, v17.16b     // A0 = s & 3
    ushr    v2.16b, v0.16b, #2
    and     v2.16b, v2.16b, v17.16b     // B0 = (s >> 2) & 3
    ushr    v3.16b, v0.16b, #4
    and     v3.16b, v3.16b, v17.16b     // A1 = (s >> 4) & 3
    ushr    v4.16b, v0.16b, #6          // B1 = s >> 6
    usubl   v18.8h, v1.8b, v2.8b        // c0, bytes 0-7
    usubl   v19.8h, v3.8b, v4.8b        // c1
    usubl2  v20.8h, v1.16b, v2.16b      // c0, bytes 8-15
    usubl2  v21.8h, v3.16b, v4.16b
    st2     {v18.8h, v19.8h}, [x0], #32 // r[2k+m] = cm[k]
    st2     {v20.8h, v21.8h}, [x0], #32
    subs    x2, x2, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Cbd2Asm)

// Shared inner block: one 32-coefficient slice of Cbd3 (8 cbd1 bytes from
// x1, 16 cbd2 bytes from x3), leaving the linear coefficient vectors in
// v20-v23.  Clobbers v0-v7, v19, v24-v31.
.macro NEV_CBD3_SLICE
    ld1     {v0.8b}, [x1], #8
    ld1     {v1.16b}, [x3], #16
    // cbd1 half (8 lanes)
    and     v2.8b, v0.8b, v16.8b
    ushr    v3.8b, v0.8b, #1
    and     v3.8b, v3.8b, v16.8b
    ushr    v4.8b, v0.8b, #2
    and     v4.8b, v4.8b, v16.8b
    ushr    v5.8b, v0.8b, #3
    and     v5.8b, v5.8b, v16.8b
    ushr    v6.8b, v0.8b, #4
    and     v6.8b, v6.8b, v16.8b
    ushr    v7.8b, v0.8b, #5
    and     v7.8b, v7.8b, v16.8b
    ushr    v19.8b, v0.8b, #6
    and     v19.8b, v19.8b, v16.8b
    ushr    v0.8b, v0.8b, #7
    usubl   v2.8h, v2.8b, v3.8b         // c0[i]
    usubl   v4.8h, v4.8b, v5.8b         // c1[i]
    usubl   v6.8h, v6.8b, v7.8b         // c2[i]
    usubl   v19.8h, v19.8b, v0.8b       // c3[i]
    // linearize r[4i+j]: zip pairs then 32-bit zip
    zip1    v24.8h, v2.8h, v4.8h        // c0[0],c1[0],..,c0[3],c1[3]
    zip2    v25.8h, v2.8h, v4.8h
    zip1    v26.8h, v6.8h, v19.8h
    zip2    v27.8h, v6.8h, v19.8h
    zip1    v20.4s, v24.4s, v26.4s      // r[0..7]
    zip2    v21.4s, v24.4s, v26.4s      // r[8..15]
    zip1    v22.4s, v25.4s, v27.4s      // r[16..23]
    zip2    v23.4s, v25.4s, v27.4s      // r[24..31]
    // cbd2 half (16 lanes)
    ushr    v3.16b, v1.16b, #1
    and     v1.16b, v1.16b, v17.16b
    and     v3.16b, v3.16b, v17.16b
    add     v1.16b, v1.16b, v3.16b      // s
    and     v3.16b, v1.16b, v18.16b     // A0
    ushr    v5.16b, v1.16b, #2
    and     v5.16b, v5.16b, v18.16b     // B0
    ushr    v7.16b, v1.16b, #4
    and     v7.16b, v7.16b, v18.16b     // A1
    ushr    v1.16b, v1.16b, #6          // B1
    usubl   v24.8h, v3.8b, v5.8b        // c0, k=0..7
    usubl   v25.8h, v7.8b, v1.8b        // c1, k=0..7
    usubl2  v26.8h, v3.16b, v5.16b      // c0, k=8..15
    usubl2  v27.8h, v7.16b, v1.16b     // c1, k=8..15
    zip1    v28.8h, v24.8h, v25.8h      // r[0..7]
    zip2    v29.8h, v24.8h, v25.8h      // r[8..15]
    zip1    v30.8h, v26.8h, v27.8h      // r[16..23]
    zip2    v31.8h, v26.8h, v27.8h      // r[24..31]
    add     v20.8h, v20.8h, v28.8h
    add     v21.8h, v21.8h, v29.8h
    add     v22.8h, v22.8h, v30.8h
    add     v23.8h, v23.8h, v31.8h
.endm

// ----------------------------------------------------------------------------
// void NEV_Cbd3Asm(int16_t *r, const uint8_t *buf, uint32_t n)
// ----------------------------------------------------------------------------
CRYPT_AARCH64_FUNC_START(NEV_Cbd3Asm)
AARCH64_PACIASP
    mov     w2, w2                      // zero-extend the uint32_t n argument
    movi    v16.16b, #0x01
    movi    v17.16b, #0x55
    movi    v18.16b, #0x03
    add     x3, x1, x2, lsr #2          // cbd2 bytes at buf + n/4
1:
    NEV_CBD3_SLICE
    st1     {v20.8h-v23.8h}, [x0], #64
    subs    x2, x2, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Cbd3Asm)

// ----------------------------------------------------------------------------
// void NEV_Cbd4Asm(int16_t *r, const uint8_t *buf, uint32_t n)
// ----------------------------------------------------------------------------
CRYPT_AARCH64_FUNC_START(NEV_Cbd4Asm)
AARCH64_PACIASP
    mov     w2, w2                      // zero-extend the uint32_t n argument
    movi    v16.16b, #0x0f
1:
    ld1     {v0.16b, v1.16b}, [x1], #32
    and     v2.16b, v0.16b, v16.16b
    ushr    v3.16b, v0.16b, #4
    and     v4.16b, v1.16b, v16.16b
    ushr    v5.16b, v1.16b, #4
    cnt     v2.16b, v2.16b              // a = popcount(low nibble)
    cnt     v3.16b, v3.16b              // b = popcount(high nibble)
    cnt     v4.16b, v4.16b
    cnt     v5.16b, v5.16b
    usubl   v17.8h, v2.8b, v3.8b        // r[i] = a - b (linear order)
    usubl2  v18.8h, v2.16b, v3.16b
    usubl   v19.8h, v4.8b, v5.8b
    usubl2  v20.8h, v4.16b, v5.16b
    st1     {v17.8h-v20.8h}, [x0], #64
    subs    x2, x2, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Cbd4Asm)

// ----------------------------------------------------------------------------
// void NEV_Cbd7Asm(int16_t *r, const uint8_t *buf, uint32_t n)
//   cbd4 bytes at buf, cbd1 bytes at buf + n, cbd2 bytes at buf + n + n/4;
//   x1 walks the cbd1 range and x3 the cbd2 range (NEV_CBD3_SLICE contract),
//   x4 walks the cbd4 range.
// ----------------------------------------------------------------------------
CRYPT_AARCH64_FUNC_START(NEV_Cbd7Asm)
AARCH64_PACIASP
    mov     w2, w2                      // zero-extend the uint32_t n argument
    movi    v16.16b, #0x01
    movi    v17.16b, #0x55
    movi    v18.16b, #0x03
    mov     x4, x1                      // cbd4 walker
    add     x1, x1, x2                  // cbd1 bytes at buf + n
    add     x3, x1, x2, lsr #2          // cbd2 bytes at buf + n + n/4
1:
    NEV_CBD3_SLICE                      // v20-v23 = cbd1 + cbd2 (clobbers v0-v7, v19, v24-v31)
    ld1     {v0.16b, v1.16b}, [x4], #32
    movi    v28.16b, #0x0f
    and     v2.16b, v0.16b, v28.16b
    ushr    v3.16b, v0.16b, #4
    and     v4.16b, v1.16b, v28.16b
    ushr    v5.16b, v1.16b, #4
    cnt     v2.16b, v2.16b
    cnt     v3.16b, v3.16b
    cnt     v4.16b, v4.16b
    cnt     v5.16b, v5.16b
    usubl   v24.8h, v2.8b, v3.8b
    usubl2  v25.8h, v2.16b, v3.16b
    usubl   v26.8h, v4.8b, v5.8b
    usubl2  v27.8h, v4.16b, v5.16b
    add     v20.8h, v20.8h, v24.8h
    add     v21.8h, v21.8h, v25.8h
    add     v22.8h, v22.8h, v26.8h
    add     v23.8h, v23.8h, v27.8h
    st1     {v20.8h-v23.8h}, [x0], #64
    subs    x2, x2, #32
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_Cbd7Asm)

// ----------------------------------------------------------------------------
// void NEV_MaskTernary8Asm(int16_t *r, const uint8_t *mask, uint32_t n)
//   r[8i+j] &= -((mask[i] >> j) & 1)
// ----------------------------------------------------------------------------
CRYPT_AARCH64_FUNC_START(NEV_MaskTernary8Asm)
AARCH64_PACIASP
    mov     w2, w2                      // zero-extend the uint32_t n argument
    CRYPT_AARCH64_GET_RELA(x3, .LNEV_MaskWeights)
    ld1     {v16.16b}, [x3]
1:
    ld1r    {v0.16b}, [x1], #1          // mask byte duplicated to all lanes
    ld1     {v1.8h}, [x0]
    cmtst   v0.16b, v0.16b, v16.16b     // bit j -> halfword mask (byte pairs)
    and     v1.16b, v1.16b, v0.16b
    st1     {v1.8h}, [x0], #16
    subs    x2, x2, #8
    b.ne    1b
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_MaskTernary8Asm)

// ----------------------------------------------------------------------------
// void NEV_NoiseMExtractAsm(int16_t *r, const uint8_t *buf,
//                           uint64_t eta, uint64_t seedLen, uint64_t dim)
//   The extraction loop nest of NoiseMExtractE (plane-0 fold already done):
//   for byteIdx in [0, seedLen): i = byteIdx/bpi, j = byteIdx%bpi (bpi=dim/32)
//     for g in 0..3:
//       pa = buf + (g*2*eta)*seedLen + byteIdx, pb = pa + eta*seedLen
//       out = r + dim*i + (dim/4)*g + 8*j
//       out[k] = sum_t bit_k(pa[t*seedLen]) - bit_k(pb[t*seedLen])
// ----------------------------------------------------------------------------
CRYPT_AARCH64_FUNC_START(NEV_NoiseMExtractAsm)
AARCH64_PACIASP
    CRYPT_AARCH64_GET_RELA(x9, .LNEV_MaskWeights)
    ld1     {v16.16b}, [x9]
    lsr     x9, x4, #5                  // bpi = dim/32 (2 or 4)
    clz     x10, x9
    mov     x12, #63
    sub     x10, x12, x10               // s = log2(bpi)
    mul     x11, x2, x3                 // eta * seedLen
    sub     x12, x9, #1                 // bpi - 1
    lsl     x13, x4, #1                 // 2*dim = byte stride between i rows
    mov     x5, #0                      // byteIdx
.Lnm_byte:
    lsr     x6, x5, x10                 // i
    and     x7, x5, x12                 // j
    mul     x6, x6, x13
    add     x6, x6, x7, lsl #4
    add     x6, x0, x6                  // out pointer, g = 0
    add     x8, x1, x5                  // pa, g = 0
    mov     w14, #4                     // group counter
.Lnm_group:
    mov     x15, x8                     // pa walker
    add     x16, x8, x11                // pb walker
    ld1r    {v0.16b}, [x15]
    ld1r    {v1.16b}, [x16]
    cmtst   v0.16b, v0.16b, v16.16b     // Ma = -bit_a per halfword
    cmtst   v1.16b, v1.16b, v16.16b     // Mb = -bit_b
    sub     v2.8h, v1.8h, v0.8h         // acc = bit_a - bit_b
    subs    x17, x2, #1
    b.eq    .Lnm_store
.Lnm_t:
    add     x15, x15, x3
    add     x16, x16, x3
    ld1r    {v0.16b}, [x15]
    ld1r    {v1.16b}, [x16]
    cmtst   v0.16b, v0.16b, v16.16b
    cmtst   v1.16b, v1.16b, v16.16b
    sub     v2.8h, v2.8h, v0.8h         // acc += bit_a
    add     v2.8h, v2.8h, v1.8h         // acc -= bit_b
    subs    x17, x17, #1
    b.ne    .Lnm_t
.Lnm_store:
    st1     {v2.8h}, [x6]
    add     x6, x6, x13, lsr #2         // out += dim/2 bytes (dim/4 coeffs)
    add     x8, x8, x11, lsl #1         // pa += 2*eta*seedLen (next group)
    subs    w14, w14, #1
    b.ne    .Lnm_group
    add     x5, x5, #1
    cmp     x5, x3
    b.ne    .Lnm_byte
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(NEV_NoiseMExtractAsm)

CRYPT_AARCH64_RODATA_SECTION
.balign 16
.LNEV_RejBitWeights:
    .byte   1, 2, 4, 8, 16, 32, 64, 128

// Byte-pair bit weights: cmtst of a duplicated mask byte against this vector
// yields, for each of the 8 int16 lanes, 0xffff when bit k is set (both bytes
// of lane k test the same weight 1 << k).
.balign 16
.LNEV_MaskWeights:
    .byte   1, 1, 2, 2, 4, 4, 8, 8, 16, 16, 32, 32, 64, 64, 128, 128

// 256 x 8: row b lists the set-bit positions of b in ascending order,
// padded with 255 (tbl yields 0 for out-of-range indices; those output
// bytes are scratch and overwritten by the next group's store).
.balign 16
.LNEV_RejCompactTable:
    .byte   255, 255, 255, 255, 255, 255, 255, 255    // 0x00
    .byte     0, 255, 255, 255, 255, 255, 255, 255    // 0x01
    .byte     1, 255, 255, 255, 255, 255, 255, 255    // 0x02
    .byte     0,   1, 255, 255, 255, 255, 255, 255    // 0x03
    .byte     2, 255, 255, 255, 255, 255, 255, 255    // 0x04
    .byte     0,   2, 255, 255, 255, 255, 255, 255    // 0x05
    .byte     1,   2, 255, 255, 255, 255, 255, 255    // 0x06
    .byte     0,   1,   2, 255, 255, 255, 255, 255    // 0x07
    .byte     3, 255, 255, 255, 255, 255, 255, 255    // 0x08
    .byte     0,   3, 255, 255, 255, 255, 255, 255    // 0x09
    .byte     1,   3, 255, 255, 255, 255, 255, 255    // 0x0a
    .byte     0,   1,   3, 255, 255, 255, 255, 255    // 0x0b
    .byte     2,   3, 255, 255, 255, 255, 255, 255    // 0x0c
    .byte     0,   2,   3, 255, 255, 255, 255, 255    // 0x0d
    .byte     1,   2,   3, 255, 255, 255, 255, 255    // 0x0e
    .byte     0,   1,   2,   3, 255, 255, 255, 255    // 0x0f
    .byte     4, 255, 255, 255, 255, 255, 255, 255    // 0x10
    .byte     0,   4, 255, 255, 255, 255, 255, 255    // 0x11
    .byte     1,   4, 255, 255, 255, 255, 255, 255    // 0x12
    .byte     0,   1,   4, 255, 255, 255, 255, 255    // 0x13
    .byte     2,   4, 255, 255, 255, 255, 255, 255    // 0x14
    .byte     0,   2,   4, 255, 255, 255, 255, 255    // 0x15
    .byte     1,   2,   4, 255, 255, 255, 255, 255    // 0x16
    .byte     0,   1,   2,   4, 255, 255, 255, 255    // 0x17
    .byte     3,   4, 255, 255, 255, 255, 255, 255    // 0x18
    .byte     0,   3,   4, 255, 255, 255, 255, 255    // 0x19
    .byte     1,   3,   4, 255, 255, 255, 255, 255    // 0x1a
    .byte     0,   1,   3,   4, 255, 255, 255, 255    // 0x1b
    .byte     2,   3,   4, 255, 255, 255, 255, 255    // 0x1c
    .byte     0,   2,   3,   4, 255, 255, 255, 255    // 0x1d
    .byte     1,   2,   3,   4, 255, 255, 255, 255    // 0x1e
    .byte     0,   1,   2,   3,   4, 255, 255, 255    // 0x1f
    .byte     5, 255, 255, 255, 255, 255, 255, 255    // 0x20
    .byte     0,   5, 255, 255, 255, 255, 255, 255    // 0x21
    .byte     1,   5, 255, 255, 255, 255, 255, 255    // 0x22
    .byte     0,   1,   5, 255, 255, 255, 255, 255    // 0x23
    .byte     2,   5, 255, 255, 255, 255, 255, 255    // 0x24
    .byte     0,   2,   5, 255, 255, 255, 255, 255    // 0x25
    .byte     1,   2,   5, 255, 255, 255, 255, 255    // 0x26
    .byte     0,   1,   2,   5, 255, 255, 255, 255    // 0x27
    .byte     3,   5, 255, 255, 255, 255, 255, 255    // 0x28
    .byte     0,   3,   5, 255, 255, 255, 255, 255    // 0x29
    .byte     1,   3,   5, 255, 255, 255, 255, 255    // 0x2a
    .byte     0,   1,   3,   5, 255, 255, 255, 255    // 0x2b
    .byte     2,   3,   5, 255, 255, 255, 255, 255    // 0x2c
    .byte     0,   2,   3,   5, 255, 255, 255, 255    // 0x2d
    .byte     1,   2,   3,   5, 255, 255, 255, 255    // 0x2e
    .byte     0,   1,   2,   3,   5, 255, 255, 255    // 0x2f
    .byte     4,   5, 255, 255, 255, 255, 255, 255    // 0x30
    .byte     0,   4,   5, 255, 255, 255, 255, 255    // 0x31
    .byte     1,   4,   5, 255, 255, 255, 255, 255    // 0x32
    .byte     0,   1,   4,   5, 255, 255, 255, 255    // 0x33
    .byte     2,   4,   5, 255, 255, 255, 255, 255    // 0x34
    .byte     0,   2,   4,   5, 255, 255, 255, 255    // 0x35
    .byte     1,   2,   4,   5, 255, 255, 255, 255    // 0x36
    .byte     0,   1,   2,   4,   5, 255, 255, 255    // 0x37
    .byte     3,   4,   5, 255, 255, 255, 255, 255    // 0x38
    .byte     0,   3,   4,   5, 255, 255, 255, 255    // 0x39
    .byte     1,   3,   4,   5, 255, 255, 255, 255    // 0x3a
    .byte     0,   1,   3,   4,   5, 255, 255, 255    // 0x3b
    .byte     2,   3,   4,   5, 255, 255, 255, 255    // 0x3c
    .byte     0,   2,   3,   4,   5, 255, 255, 255    // 0x3d
    .byte     1,   2,   3,   4,   5, 255, 255, 255    // 0x3e
    .byte     0,   1,   2,   3,   4,   5, 255, 255    // 0x3f
    .byte     6, 255, 255, 255, 255, 255, 255, 255    // 0x40
    .byte     0,   6, 255, 255, 255, 255, 255, 255    // 0x41
    .byte     1,   6, 255, 255, 255, 255, 255, 255    // 0x42
    .byte     0,   1,   6, 255, 255, 255, 255, 255    // 0x43
    .byte     2,   6, 255, 255, 255, 255, 255, 255    // 0x44
    .byte     0,   2,   6, 255, 255, 255, 255, 255    // 0x45
    .byte     1,   2,   6, 255, 255, 255, 255, 255    // 0x46
    .byte     0,   1,   2,   6, 255, 255, 255, 255    // 0x47
    .byte     3,   6, 255, 255, 255, 255, 255, 255    // 0x48
    .byte     0,   3,   6, 255, 255, 255, 255, 255    // 0x49
    .byte     1,   3,   6, 255, 255, 255, 255, 255    // 0x4a
    .byte     0,   1,   3,   6, 255, 255, 255, 255    // 0x4b
    .byte     2,   3,   6, 255, 255, 255, 255, 255    // 0x4c
    .byte     0,   2,   3,   6, 255, 255, 255, 255    // 0x4d
    .byte     1,   2,   3,   6, 255, 255, 255, 255    // 0x4e
    .byte     0,   1,   2,   3,   6, 255, 255, 255    // 0x4f
    .byte     4,   6, 255, 255, 255, 255, 255, 255    // 0x50
    .byte     0,   4,   6, 255, 255, 255, 255, 255    // 0x51
    .byte     1,   4,   6, 255, 255, 255, 255, 255    // 0x52
    .byte     0,   1,   4,   6, 255, 255, 255, 255    // 0x53
    .byte     2,   4,   6, 255, 255, 255, 255, 255    // 0x54
    .byte     0,   2,   4,   6, 255, 255, 255, 255    // 0x55
    .byte     1,   2,   4,   6, 255, 255, 255, 255    // 0x56
    .byte     0,   1,   2,   4,   6, 255, 255, 255    // 0x57
    .byte     3,   4,   6, 255, 255, 255, 255, 255    // 0x58
    .byte     0,   3,   4,   6, 255, 255, 255, 255    // 0x59
    .byte     1,   3,   4,   6, 255, 255, 255, 255    // 0x5a
    .byte     0,   1,   3,   4,   6, 255, 255, 255    // 0x5b
    .byte     2,   3,   4,   6, 255, 255, 255, 255    // 0x5c
    .byte     0,   2,   3,   4,   6, 255, 255, 255    // 0x5d
    .byte     1,   2,   3,   4,   6, 255, 255, 255    // 0x5e
    .byte     0,   1,   2,   3,   4,   6, 255, 255    // 0x5f
    .byte     5,   6, 255, 255, 255, 255, 255, 255    // 0x60
    .byte     0,   5,   6, 255, 255, 255, 255, 255    // 0x61
    .byte     1,   5,   6, 255, 255, 255, 255, 255    // 0x62
    .byte     0,   1,   5,   6, 255, 255, 255, 255    // 0x63
    .byte     2,   5,   6, 255, 255, 255, 255, 255    // 0x64
    .byte     0,   2,   5,   6, 255, 255, 255, 255    // 0x65
    .byte     1,   2,   5,   6, 255, 255, 255, 255    // 0x66
    .byte     0,   1,   2,   5,   6, 255, 255, 255    // 0x67
    .byte     3,   5,   6, 255, 255, 255, 255, 255    // 0x68
    .byte     0,   3,   5,   6, 255, 255, 255, 255    // 0x69
    .byte     1,   3,   5,   6, 255, 255, 255, 255    // 0x6a
    .byte     0,   1,   3,   5,   6, 255, 255, 255    // 0x6b
    .byte     2,   3,   5,   6, 255, 255, 255, 255    // 0x6c
    .byte     0,   2,   3,   5,   6, 255, 255, 255    // 0x6d
    .byte     1,   2,   3,   5,   6, 255, 255, 255    // 0x6e
    .byte     0,   1,   2,   3,   5,   6, 255, 255    // 0x6f
    .byte     4,   5,   6, 255, 255, 255, 255, 255    // 0x70
    .byte     0,   4,   5,   6, 255, 255, 255, 255    // 0x71
    .byte     1,   4,   5,   6, 255, 255, 255, 255    // 0x72
    .byte     0,   1,   4,   5,   6, 255, 255, 255    // 0x73
    .byte     2,   4,   5,   6, 255, 255, 255, 255    // 0x74
    .byte     0,   2,   4,   5,   6, 255, 255, 255    // 0x75
    .byte     1,   2,   4,   5,   6, 255, 255, 255    // 0x76
    .byte     0,   1,   2,   4,   5,   6, 255, 255    // 0x77
    .byte     3,   4,   5,   6, 255, 255, 255, 255    // 0x78
    .byte     0,   3,   4,   5,   6, 255, 255, 255    // 0x79
    .byte     1,   3,   4,   5,   6, 255, 255, 255    // 0x7a
    .byte     0,   1,   3,   4,   5,   6, 255, 255    // 0x7b
    .byte     2,   3,   4,   5,   6, 255, 255, 255    // 0x7c
    .byte     0,   2,   3,   4,   5,   6, 255, 255    // 0x7d
    .byte     1,   2,   3,   4,   5,   6, 255, 255    // 0x7e
    .byte     0,   1,   2,   3,   4,   5,   6, 255    // 0x7f
    .byte     7, 255, 255, 255, 255, 255, 255, 255    // 0x80
    .byte     0,   7, 255, 255, 255, 255, 255, 255    // 0x81
    .byte     1,   7, 255, 255, 255, 255, 255, 255    // 0x82
    .byte     0,   1,   7, 255, 255, 255, 255, 255    // 0x83
    .byte     2,   7, 255, 255, 255, 255, 255, 255    // 0x84
    .byte     0,   2,   7, 255, 255, 255, 255, 255    // 0x85
    .byte     1,   2,   7, 255, 255, 255, 255, 255    // 0x86
    .byte     0,   1,   2,   7, 255, 255, 255, 255    // 0x87
    .byte     3,   7, 255, 255, 255, 255, 255, 255    // 0x88
    .byte     0,   3,   7, 255, 255, 255, 255, 255    // 0x89
    .byte     1,   3,   7, 255, 255, 255, 255, 255    // 0x8a
    .byte     0,   1,   3,   7, 255, 255, 255, 255    // 0x8b
    .byte     2,   3,   7, 255, 255, 255, 255, 255    // 0x8c
    .byte     0,   2,   3,   7, 255, 255, 255, 255    // 0x8d
    .byte     1,   2,   3,   7, 255, 255, 255, 255    // 0x8e
    .byte     0,   1,   2,   3,   7, 255, 255, 255    // 0x8f
    .byte     4,   7, 255, 255, 255, 255, 255, 255    // 0x90
    .byte     0,   4,   7, 255, 255, 255, 255, 255    // 0x91
    .byte     1,   4,   7, 255, 255, 255, 255, 255    // 0x92
    .byte     0,   1,   4,   7, 255, 255, 255, 255    // 0x93
    .byte     2,   4,   7, 255, 255, 255, 255, 255    // 0x94
    .byte     0,   2,   4,   7, 255, 255, 255, 255    // 0x95
    .byte     1,   2,   4,   7, 255, 255, 255, 255    // 0x96
    .byte     0,   1,   2,   4,   7, 255, 255, 255    // 0x97
    .byte     3,   4,   7, 255, 255, 255, 255, 255    // 0x98
    .byte     0,   3,   4,   7, 255, 255, 255, 255    // 0x99
    .byte     1,   3,   4,   7, 255, 255, 255, 255    // 0x9a
    .byte     0,   1,   3,   4,   7, 255, 255, 255    // 0x9b
    .byte     2,   3,   4,   7, 255, 255, 255, 255    // 0x9c
    .byte     0,   2,   3,   4,   7, 255, 255, 255    // 0x9d
    .byte     1,   2,   3,   4,   7, 255, 255, 255    // 0x9e
    .byte     0,   1,   2,   3,   4,   7, 255, 255    // 0x9f
    .byte     5,   7, 255, 255, 255, 255, 255, 255    // 0xa0
    .byte     0,   5,   7, 255, 255, 255, 255, 255    // 0xa1
    .byte     1,   5,   7, 255, 255, 255, 255, 255    // 0xa2
    .byte     0,   1,   5,   7, 255, 255, 255, 255    // 0xa3
    .byte     2,   5,   7, 255, 255, 255, 255, 255    // 0xa4
    .byte     0,   2,   5,   7, 255, 255, 255, 255    // 0xa5
    .byte     1,   2,   5,   7, 255, 255, 255, 255    // 0xa6
    .byte     0,   1,   2,   5,   7, 255, 255, 255    // 0xa7
    .byte     3,   5,   7, 255, 255, 255, 255, 255    // 0xa8
    .byte     0,   3,   5,   7, 255, 255, 255, 255    // 0xa9
    .byte     1,   3,   5,   7, 255, 255, 255, 255    // 0xaa
    .byte     0,   1,   3,   5,   7, 255, 255, 255    // 0xab
    .byte     2,   3,   5,   7, 255, 255, 255, 255    // 0xac
    .byte     0,   2,   3,   5,   7, 255, 255, 255    // 0xad
    .byte     1,   2,   3,   5,   7, 255, 255, 255    // 0xae
    .byte     0,   1,   2,   3,   5,   7, 255, 255    // 0xaf
    .byte     4,   5,   7, 255, 255, 255, 255, 255    // 0xb0
    .byte     0,   4,   5,   7, 255, 255, 255, 255    // 0xb1
    .byte     1,   4,   5,   7, 255, 255, 255, 255    // 0xb2
    .byte     0,   1,   4,   5,   7, 255, 255, 255    // 0xb3
    .byte     2,   4,   5,   7, 255, 255, 255, 255    // 0xb4
    .byte     0,   2,   4,   5,   7, 255, 255, 255    // 0xb5
    .byte     1,   2,   4,   5,   7, 255, 255, 255    // 0xb6
    .byte     0,   1,   2,   4,   5,   7, 255, 255    // 0xb7
    .byte     3,   4,   5,   7, 255, 255, 255, 255    // 0xb8
    .byte     0,   3,   4,   5,   7, 255, 255, 255    // 0xb9
    .byte     1,   3,   4,   5,   7, 255, 255, 255    // 0xba
    .byte     0,   1,   3,   4,   5,   7, 255, 255    // 0xbb
    .byte     2,   3,   4,   5,   7, 255, 255, 255    // 0xbc
    .byte     0,   2,   3,   4,   5,   7, 255, 255    // 0xbd
    .byte     1,   2,   3,   4,   5,   7, 255, 255    // 0xbe
    .byte     0,   1,   2,   3,   4,   5,   7, 255    // 0xbf
    .byte     6,   7, 255, 255, 255, 255, 255, 255    // 0xc0
    .byte     0,   6,   7, 255, 255, 255, 255, 255    // 0xc1
    .byte     1,   6,   7, 255, 255, 255, 255, 255    // 0xc2
    .byte     0,   1,   6,   7, 255, 255, 255, 255    // 0xc3
    .byte     2,   6,   7, 255, 255, 255, 255, 255    // 0xc4
    .byte     0,   2,   6,   7, 255, 255, 255, 255    // 0xc5
    .byte     1,   2,   6,   7, 255, 255, 255, 255    // 0xc6
    .byte     0,   1,   2,   6,   7, 255, 255, 255    // 0xc7
    .byte     3,   6,   7, 255, 255, 255, 255, 255    // 0xc8
    .byte     0,   3,   6,   7, 255, 255, 255, 255    // 0xc9
    .byte     1,   3,   6,   7, 255, 255, 255, 255    // 0xca
    .byte     0,   1,   3,   6,   7, 255, 255, 255    // 0xcb
    .byte     2,   3,   6,   7, 255, 255, 255, 255    // 0xcc
    .byte     0,   2,   3,   6,   7, 255, 255, 255    // 0xcd
    .byte     1,   2,   3,   6,   7, 255, 255, 255    // 0xce
    .byte     0,   1,   2,   3,   6,   7, 255, 255    // 0xcf
    .byte     4,   6,   7, 255, 255, 255, 255, 255    // 0xd0
    .byte     0,   4,   6,   7, 255, 255, 255, 255    // 0xd1
    .byte     1,   4,   6,   7, 255, 255, 255, 255    // 0xd2
    .byte     0,   1,   4,   6,   7, 255, 255, 255    // 0xd3
    .byte     2,   4,   6,   7, 255, 255, 255, 255    // 0xd4
    .byte     0,   2,   4,   6,   7, 255, 255, 255    // 0xd5
    .byte     1,   2,   4,   6,   7, 255, 255, 255    // 0xd6
    .byte     0,   1,   2,   4,   6,   7, 255, 255    // 0xd7
    .byte     3,   4,   6,   7, 255, 255, 255, 255    // 0xd8
    .byte     0,   3,   4,   6,   7, 255, 255, 255    // 0xd9
    .byte     1,   3,   4,   6,   7, 255, 255, 255    // 0xda
    .byte     0,   1,   3,   4,   6,   7, 255, 255    // 0xdb
    .byte     2,   3,   4,   6,   7, 255, 255, 255    // 0xdc
    .byte     0,   2,   3,   4,   6,   7, 255, 255    // 0xdd
    .byte     1,   2,   3,   4,   6,   7, 255, 255    // 0xde
    .byte     0,   1,   2,   3,   4,   6,   7, 255    // 0xdf
    .byte     5,   6,   7, 255, 255, 255, 255, 255    // 0xe0
    .byte     0,   5,   6,   7, 255, 255, 255, 255    // 0xe1
    .byte     1,   5,   6,   7, 255, 255, 255, 255    // 0xe2
    .byte     0,   1,   5,   6,   7, 255, 255, 255    // 0xe3
    .byte     2,   5,   6,   7, 255, 255, 255, 255    // 0xe4
    .byte     0,   2,   5,   6,   7, 255, 255, 255    // 0xe5
    .byte     1,   2,   5,   6,   7, 255, 255, 255    // 0xe6
    .byte     0,   1,   2,   5,   6,   7, 255, 255    // 0xe7
    .byte     3,   5,   6,   7, 255, 255, 255, 255    // 0xe8
    .byte     0,   3,   5,   6,   7, 255, 255, 255    // 0xe9
    .byte     1,   3,   5,   6,   7, 255, 255, 255    // 0xea
    .byte     0,   1,   3,   5,   6,   7, 255, 255    // 0xeb
    .byte     2,   3,   5,   6,   7, 255, 255, 255    // 0xec
    .byte     0,   2,   3,   5,   6,   7, 255, 255    // 0xed
    .byte     1,   2,   3,   5,   6,   7, 255, 255    // 0xee
    .byte     0,   1,   2,   3,   5,   6,   7, 255    // 0xef
    .byte     4,   5,   6,   7, 255, 255, 255, 255    // 0xf0
    .byte     0,   4,   5,   6,   7, 255, 255, 255    // 0xf1
    .byte     1,   4,   5,   6,   7, 255, 255, 255    // 0xf2
    .byte     0,   1,   4,   5,   6,   7, 255, 255    // 0xf3
    .byte     2,   4,   5,   6,   7, 255, 255, 255    // 0xf4
    .byte     0,   2,   4,   5,   6,   7, 255, 255    // 0xf5
    .byte     1,   2,   4,   5,   6,   7, 255, 255    // 0xf6
    .byte     0,   1,   2,   4,   5,   6,   7, 255    // 0xf7
    .byte     3,   4,   5,   6,   7, 255, 255, 255    // 0xf8
    .byte     0,   3,   4,   5,   6,   7, 255, 255    // 0xf9
    .byte     1,   3,   4,   5,   6,   7, 255, 255    // 0xfa
    .byte     0,   1,   3,   4,   5,   6,   7, 255    // 0xfb
    .byte     2,   3,   4,   5,   6,   7, 255, 255    // 0xfc
    .byte     0,   2,   3,   4,   5,   6,   7, 255    // 0xfd
    .byte     1,   2,   3,   4,   5,   6,   7, 255    // 0xfe
    .byte     0,   1,   2,   3,   4,   5,   6,   7    // 0xff

#endif // HITLS_CRYPTO_NEV

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
