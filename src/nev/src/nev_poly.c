/* Copyright (c) 2025 LiuRuikang
 * School Of Cyber Engineering, Xidian University
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

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_NEV

#include "nev_local.h"
#include "nev_qdispatch.h"

/*
 * Arithmetic in the incomplete-NTT (CRT) representation of R_q = Z_q[X]/(X^n + 1).
 * A polynomial is split into t = n / nttDim interleaved blocks; block j holds the
 * coefficients of X^{i*t + j}. Slot i of the CRT decomposition works modulo
 * X^t - y_i, where y_i is the i-th entry of the NTT_Y evaluation-point table.
 *
 * The arithmetic bodies are instantiated once per modulus (q = 769 / 1409 /
 * 3329) in nev_poly_q{769,1409,3329}.c from the template nev_poly_core.inc,
 * with everything q-derived as compile-time constants; this file dispatches
 * on info->q. The bodies are the accumulate-then-reduce version of the
 * reference poly.c, the scalar mirror of the proven ARMv8 v2 backend
 * (asm_nev_poly.c + asm/nev_poly_armv8.S, same per-output formulas; read the
 * .S header for the full discussion):
 *
 *  - NEV_PolyAdd / NEV_PolyReduce / NEV_PolyCaddq / NEV_PolyGetMontgomery /
 *    NEV_PolyAddVinv stay BIT-EXACT ports of the reference (they are the
 *    synchronization points every consumer canonicalizes through).
 *  - The Karatsuba slot products exploit the linearity of Montgomery reduction
 *    mod q: raw 32-bit products are combined linearly first and every output
 *    coefficient is reduced ONCE with the exact NEV_MontReduce (nev_local.h),
 *    which equals P * 2^-16 mod q for any |P| <= 2^31 - 2^15*q - 1 (the m*q
 *    correction is < 2^15*q, so P - m*q cannot wrap int32, its low 16 bits are
 *    zero, and the result (P - m*q) >> 16 is bounded by q/2 + |P|/2^16 + 1).
 *    Results are CONGRUENT (not bit-equal) to the reference rows and every
 *    int16 store is provably wrap-free (int16 wrap-around would not be
 *    congruent because 2^16 mod q != 0; see the range script below).
 *  - The multi-pass Karatsuba recombination tails and the wrap-around y-folds
 *    of PolyMontMul are fused into per-row single passes (the scalar
 *    equivalents of NEV_MontMul8TailAsm / NEV_MulYCombAsm / NEV_Comb4Asm).
 *  - Multiplications by the per-slot constants y_i use the Plantard operator
 *    (PlantardMulQ in nev_poly_core.inc; eprint 2022/956, L = 16, alpha = 3,
 *    valid for all three q < 4096): PM(x, yp_i) === x * y_i * 2^-16 (mod q)
 *    with |result| <= (q - 1) / 2, which is congruent to the reference fold
 *    MontReduce(x * y_i) and never above its bound.
 *  - Exactness islands: every value feeding an invertibility '== 0' decision
 *    is canonicalized first. The s array of the Mont2Inverse4 norm map is
 *    Caddq(Barrett(x)) of a wrap-free int16 x that is congruent to the
 *    reference value; the per-q Barrett constants return the unique centered
 *    representative for ALL int16 inputs (proven exhaustively), so s is
 *    BIT-IDENTICAL to the reference s array, and BatchMont2Inv (kept verbatim)
 *    then sees identical inputs: every invertibility decision, retry count and
 *    packed byte of deterministic keygen is unchanged.
 *  - Operand discipline: because the accumulate cores square operand
 *    magnitudes into the int32 accumulator, the PolyMontMul path (operands as
 *    large as the unpack anchor W below - decapsulation keys are importable
 *    raw, so both sides can be W) Barrett-normalizes ONE side of every
 *    Karatsuba operand sum (the a side, redA = 1), leaving the b-side sums
 *    raw: the products of a <= (q-1)/2 side with a b side that doubles per
 *    level stay inside the exact-MR domain. The inverse tower keeps both
 *    sides raw (redA = 0; its operands are <= (q-1)/2 because every
 *    Mont2Inverse level / norm-map output is Barrett-normalized before it
 *    feeds the next level).
 *
 * Range chain (worst case per q). Anchors: NTT-domain operands of PolyMontMul
 * are |x| <= W with W = 1023 (q = 769), 2047 (1409), 4095 (3329), the largest
 * values NEV_PolyFromBytes can unpack (malformed ciphertexts and imported
 * keys included); Mont2Inverse / Judge inputs are keygen-internal NTT outputs
 * <= (q - 1)/2, anchored at q - 1 for headroom. Verifier (python3; asserts
 * abort on any int16 store wrap or any int32 accumulator outside the exact-MR
 * domain; PM(x) models the Plantard fold, |arg| <= 2^19 always holds since
 * every fold argument is a wrap-free int16):
 *
 *   I16 = 1 << 15; I32 = 1 << 31
 *   def MR(q, x):
 *       assert x + I16 * q < I32
 *       return q // 2 + x // (1 << 16) + 1
 *   def BR(q, x):
 *       assert x < I16
 *       return (q - 1) // 2
 *   def PM(q, x):
 *       assert x < (1 << 19)
 *       return (q - 1) // 2
 *   def mm4(q, A, B, dbl=0):          # MontMul4K rows (int32 internal sums)
 *       B *= (2 if dbl else 1)
 *       P, P01, PA, PA01 = A*B, 4*A*B, 4*A*B, 16*A*B
 *       return [MR(q, P), MR(q, P01 + 2*P), MR(q, PA + 3*P),
 *               BR(q, MR(q, PA01 + 2*PA + 2*(P01 + 2*P))),
 *               MR(q, PA + 3*P), MR(q, P01 + 2*P), MR(q, P)]
 *   def sq4(q, A):                    # MontSquare4 rows
 *       return [MR(q, A*A), MR(q, 2*A*A), MR(q, 3*A*A), MR(q, 12*A*A),
 *               MR(q, 3*A*A), MR(q, 2*A*A), MR(q, A*A)]
 *   def mm8(q, A, B, dbl=0, redA=0):  # MontMul8K rows; a-side sum Barrett'd
 *       S = (q - 1) // 2              # when redA=1, b-side sum always raw
 *       sa = S if redA else 2 * A
 *       assert 2 * A < I16 and 2 * B < I16
 *       L = mm4(q, A, B, dbl); H = mm4(q, A, B, dbl); M = mm4(q, sa, 2*B, dbl)
 *       return (L[0:4]
 *           + [BR(q, L[4+i] + M[i] + L[i] + H[i]) for i in range(3)]
 *           + [BR(q, M[3] + L[3] + H[3])]
 *           + [BR(q, M[4+i] + L[4+i] + H[4+i] + H[i]) for i in range(3)]
 *           + H[3:7])
 *   def sq8(q, A):                    # MontSquare8 rows
 *       t1 = mm4(q, A, A, dbl=1); r = sq4(q, A); r2 = sq4(q, A)
 *       return (r[0:4] + [BR(q, r[4+i] + t1[i]) for i in range(3)]
 *           + [t1[3]] + [BR(q, r2[i] + t1[4+i]) for i in range(3)] + r2[3:7])
 *   def sq16(q, A):                   # MontSquare16 rows (q = 1409 only)
 *       t0 = sq8(q, A); t1 = mm8(q, A, A, 1); t2 = sq8(q, A)
 *       out = (t0[0:8] + [t0[8+i] + t1[i] for i in range(7)] + [t1[7]]
 *           + [t1[8+i] + t2[i] for i in range(7)] + t2[7:15])
 *       assert max(out) < I16; return out
 *   def mm16(q, A, B, redA=0):        # MontMul16K rows (q = 1409 only)
 *       S = (q - 1) // 2
 *       sa = S if redA else 2 * A
 *       assert 2 * A < I16 and 2 * B < I16
 *       L = mm8(q, A, B, 0, redA); H = mm8(q, A, B, 0, redA)
 *       M = mm8(q, sa, 2*B, 0, redA)
 *       t1p  = [L[8+i] + M[i] + L[i] + H[i] for i in range(7)]
 *       r16p = [M[8+i] + L[8+i] + H[8+i] + H[i] for i in range(7)]
 *       out = L[0:8] + t1p + [M[7]+L[7]+H[7]] + r16p + H[7:15]
 *       assert max(out) < I16; return out
 *   def comb(q, T0, T1, T2, h):       # PolyMontMulComb rows
 *       t1r = [T1[i] + T0[i] + T2[i] for i in range(len(T0))]
 *       assert max(t1r) < I16
 *       rows = []
 *       for i in range(h - 1):
 *           arg = T2[i] + t1r[h + i]; assert arg < I16
 *           rows.append(T0[i] + PM(q, arg))
 *       rows.append(T0[h-1] + PM(q, T2[h-1]))
 *       rows += [T0[h+i] + t1r[i] + PM(q, T2[h+i]) for i in range(h-1)]
 *       rows.append(t1r[h-1])
 *       m = max(rows); assert m < I16 and m + (q - 1) // 2 < I16
 *   def poly_mul(q, t, W):            # operands W; a-side sums Barrett'd
 *       S = (q - 1) // 2
 *       if t == 4:
 *           D = mm4(q, W, W)
 *           rows = [D[i] + PM(q, D[4+i]) for i in range(3)] + [D[3]]
 *           m = max(rows); assert m < I16 and m + S < I16
 *       elif t == 8:
 *           assert 2 * W < I16
 *           comb(q, mm4(q, W, W), mm4(q, S, 2*W), mm4(q, W, W), 4)
 *       elif t == 16:
 *           comb(q, mm8(q, W, W, 0, 1), mm8(q, S, 2*W, 0, 1),
 *                mm8(q, W, W, 0, 1), 8)
 *       else:
 *           comb(q, mm16(q, W, W, 1), mm16(q, S, 2*W, 1),
 *                mm16(q, W, W, 1), 16)
 *   def inv4norm(q, A):
 *       x1 = MR(q, 3*A*A); a20 = PM(q, x1) + MR(q, A*A)
 *       a21 = MR(q, 3*A*A) + PM(q, MR(q, A*A))
 *       assert a20 < I16 and a21 < I16
 *       s_pre = MR(q, a20*a20) + PM(q, MR(q, a21*a21))
 *       assert s_pre < I16            # exactness island: wrap-free s
 *       return a20, a21
 *   def inv4finish(q, A, a20, a21):
 *       sB = q - 1
 *       t4 = MR(q, a20 * sB); t5 = MR(q, a21 * sB)
 *       t6 = MR(q, A * t4); u0 = MR(q, 2*A * (t4 + t5)); t2p = MR(q, A * t5)
 *       BR(q, t6 + PM(q, t2p)); BR(q, u0 + t6 + t2p)
 *   def norm_rows(q, blk):            # Norm8/16/32 fused rows
 *       b = max(blk); assert 2 * b < I16
 *       row = 2 * b + PM(q, 2 * b); assert row < I16
 *   def inv_final_rows(q, blk):       # Inverse8/16/32 final rows
 *       b = max(blk); assert 2 * b < I16
 *       row = b + PM(q, b); assert row < I16
 *   for q, W in ((769, 1023), (1409, 2047), (3329, 4095)):
 *       S = (q - 1) // 2
 *       # inverse tower anchors (redA = 0, raw sums, operands <= q - 1)
 *       mm4(q, q-1, q-1, 1); sq4(q, q-1)
 *       mm8(q, q-1, q-1); mm8(q, S, q-1); sq8(q, q-1)
 *       a20, a21 = inv4norm(q, q-1); inv4finish(q, q-1, a20, a21)
 *       norm_rows(q, sq4(q, q-1)); norm_rows(q, sq8(q, q-1))
 *       inv_final_rows(q, mm4(q, S, q-1)); inv_final_rows(q, mm8(q, S, q-1))
 *       for t in (4, 8, 16): poly_mul(q, t, W)
 *       if q == 1409:
 *           mm8(q, q-1, q-1, 1); sq16(q, q-1)
 *           poly_mul(q, 32, W)
 *           norm_rows(q, sq16(q, q-1)); inv_final_rows(q, mm16(q, S, q-1))
 *   print("RANGE-VERIFY-C3 OK")
 *
 * Verifier output (q = 3329, W = 4095, the binding case): a20 3498, a21 3836,
 * s_pre 3515, norm8/16 row 9050, inv8/16 final row 3920, poly_mul out max
 * 5120 (t=4) / 14176 (t=8) / 13360 (t=16); q = 1409: norm32 row 4368, inv32
 * final row 4156, poly_mul t=32 out max 13496. All stores < 2^15, and max
 * PolyMontMul row + (q-1)/2 < 2^15, so the int16 add in
 * NevPolyAddReduceCaddq (nev_kem.c) cannot wrap either.
 */

/* NEV_PolyAdd has no q-derived constants (plain int16 adds over runtime n),
 * so it stays a single generic loop instead of a per-q instantiation. */
void NEV_PolyAdd(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b, const CRYPT_NevInfo *info)
{
    int32_t i;
    for (i = 0; i < info->n; i++) {
        r->coeffs[i] = (int16_t)(a->coeffs[i] + b->coeffs[i]);
    }
}

void NEV_PolyReduce(NEV_Poly *r, const CRYPT_NevInfo *info)
{
    if (info->q == 769) {
        NEV_PolyReduce_Q769(r, info->n);
    } else if (info->q == 1409) {
        NEV_PolyReduce_Q1409(r, info->n);
    } else { // q == 3329
        NEV_PolyReduce_Q3329(r, info->n);
    }
}

void NEV_PolyCaddq(NEV_Poly *r, const CRYPT_NevInfo *info)
{
    if (info->q == 769) {
        NEV_PolyCaddq_Q769(r, info->n);
    } else if (info->q == 1409) {
        NEV_PolyCaddq_Q1409(r, info->n);
    } else { // q == 3329
        NEV_PolyCaddq_Q3329(r, info->n);
    }
}

void NEV_PolyReduceCaddqTo(NEV_Poly *r, const NEV_Poly *a, const CRYPT_NevInfo *info)
{
    for (uint32_t i = 0; i < info->n; i++) {
        r->coeffs[i] = NEV_Caddq(NEV_BarrettReduce(a->coeffs[i], info), info);
    }
}

void NEV_PolyCaddqTo(NEV_Poly *r, const NEV_Poly *a, const CRYPT_NevInfo *info)
{
    for (uint32_t i = 0; i < info->n; i++) {
        r->coeffs[i] = NEV_Caddq(a->coeffs[i], info);
    }
}

void NEV_PolyAddVinv(NEV_Poly *f, const CRYPT_NevInfo *info)
{
    if (info->q == 769) {
        NEV_PolyAddVinv_Q769(f);
    } else if (info->q == 1409) {
        NEV_PolyAddVinv_Q1409(f);
    } else { // q == 3329
        NEV_PolyAddVinv_Q3329(f);
    }
}

void NEV_PolyGetMontgomery(NEV_Poly *r, const CRYPT_NevInfo *info)
{
    if (info->q == 769) {
        NEV_PolyGetMontgomery_Q769(r, info->n);
    } else if (info->q == 1409) {
        NEV_PolyGetMontgomery_Q1409(r, info->n);
    } else { // q == 3329
        NEV_PolyGetMontgomery_Q3329(r, info->n);
    }
}

// Fused full-polynomial passes (see nev_local.h): bit-identical to the
// corresponding NEV_Poly* call sequences for every int16 input.

void NEV_PolyReduceCaddq(NEV_Poly *r, const CRYPT_NevInfo *info)
{
    if (info->q == 769) {
        NEV_PolyReduceCaddq_Q769(r, info->n);
    } else if (info->q == 1409) {
        NEV_PolyReduceCaddq_Q1409(r, info->n);
    } else { // q == 3329
        NEV_PolyReduceCaddq_Q3329(r, info->n);
    }
}

void NEV_PolyAddReduceCaddq(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b,
    const CRYPT_NevInfo *info)
{
    if (info->q == 769) {
        NEV_PolyAddReduceCaddq_Q769(r, a, b, info->n);
    } else if (info->q == 1409) {
        NEV_PolyAddReduceCaddq_Q1409(r, a, b, info->n);
    } else { // q == 3329
        NEV_PolyAddReduceCaddq_Q3329(r, a, b, info->n);
    }
}

void NEV_PolyGetMontgomeryCaddq(NEV_Poly *r, const CRYPT_NevInfo *info)
{
    if (info->q == 769) {
        NEV_PolyGetMontgomeryCaddq_Q769(r, info->n);
    } else if (info->q == 1409) {
        NEV_PolyGetMontgomeryCaddq_Q1409(r, info->n);
    } else { // q == 3329
        NEV_PolyGetMontgomeryCaddq_Q3329(r, info->n);
    }
}

void NEV_PolyMontMul(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b, const CRYPT_NevInfo *info)
{
    if (info->q == 769) {
        NEV_PolyMontMul_Q769(r, a, b, info->n);
    } else if (info->q == 1409) {
        NEV_PolyMontMul_Q1409(r, a, b, info->n);
    } else { // q == 3329
        NEV_PolyMontMul_Q3329(r, a, b, info->n);
    }
}

int32_t NEV_PolyMont2Inverse(NEV_Poly *r, const NEV_Poly *a, const CRYPT_NevInfo *info)
{
    if (info->q == 769) {
        return NEV_PolyMont2Inverse_Q769(r, a, info->n);
    }
    if (info->q == 1409) {
        return NEV_PolyMont2Inverse_Q1409(r, a, info->n);
    }
    return NEV_PolyMont2Inverse_Q3329(r, a, info->n); // q == 3329
}

int32_t NEV_PolyMont2InverseJudge(const NEV_Poly *a, const CRYPT_NevInfo *info)
{
    if (info->q == 769) {
        return NEV_PolyMont2InverseJudge_Q769(a, info->n);
    }
    if (info->q == 1409) {
        return NEV_PolyMont2InverseJudge_Q1409(a, info->n);
    }
    return NEV_PolyMont2InverseJudge_Q3329(a, info->n); // q == 3329
}

#endif // HITLS_CRYPTO_NEV
