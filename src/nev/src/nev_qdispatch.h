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

#ifndef NEV_QDISPATCH_H
#define NEV_QDISPATCH_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_NEV

#include <stdint.h>
#include "nev_local.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Per-modulus specialized entry points of the generic C backend
 * (non-HITLS_CRYPTO_NEV_ARMV8 builds only). One instantiation of
 * nev_poly_core.inc per modulus lives in nev_poly_q{769,1409,3329}.c; the
 * public NEV_Poly* contract functions in nev_ntt.c / nev_poly.c / nev_pack.c
 * dispatch here on info->q. Each specialization is BIT-EXACT to the former
 * runtime-parameter code (see nev_poly_core.inc), so the dispatchers preserve
 * the backend contract unchanged.
 *
 * Everything q-derived (q, qinv, Barrett constants, nttDim and the zeta /
 * evaluation-point tables) is a compile-time constant inside these functions;
 * n (and seedLen for ToMsg) stays a runtime argument.
 */
#define NEV_Q_DECLS(S)                                                                          \
    void NEV_PolyNtt_##S(NEV_Poly *r, uint32_t n);                                              \
    void NEV_PolyInvNtt_##S(NEV_Poly *r, uint32_t n);                                           \
    void NEV_PolyReduce_##S(NEV_Poly *r, uint32_t n);                                           \
    void NEV_PolyCaddq_##S(NEV_Poly *r, uint32_t n);                                            \
    void NEV_PolyAddVinv_##S(NEV_Poly *f);                                                      \
    void NEV_PolyGetMontgomery_##S(NEV_Poly *r, uint32_t n);                                    \
    void NEV_PolyReduceCaddq_##S(NEV_Poly *r, uint32_t n);                                      \
    void NEV_PolyAddReduceCaddq_##S(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b,          \
        uint32_t n);                                                                            \
    void NEV_PolyGetMontgomeryCaddq_##S(NEV_Poly *r, uint32_t n);                               \
    void NEV_PolyMontMul_##S(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b, uint32_t n);    \
    int32_t NEV_PolyMont2Inverse_##S(NEV_Poly *r, const NEV_Poly *a, uint32_t n);               \
    int32_t NEV_PolyMont2InverseJudge_##S(const NEV_Poly *a, uint32_t n);                       \
    void NEV_PolyToBytes_##S(uint8_t *r, const NEV_Poly *a, uint32_t n);                        \
    void NEV_PolyFromBytes_##S(NEV_Poly *r, const uint8_t *a, uint32_t n);                      \
    void NEV_PolyDecompress_##S(NEV_Poly *x, const uint8_t *c, uint32_t n);                     \
    void NEV_PolyToMsg_##S(uint8_t *msg, const NEV_Poly *r, uint32_t seedLen);

NEV_Q_DECLS(Q769)
NEV_Q_DECLS(Q1409)
NEV_Q_DECLS(Q3329)
#undef NEV_Q_DECLS

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_NEV
#endif // NEV_QDISPATCH_H
