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
 * Per-block negacyclic NTT of size nttDim, applied to all n / nttDim blocks.
 *
 * The transforms are instantiated once per modulus with all q-derived values
 * (q, qinv, Barrett constants, nttDim, zeta tables, fused inverse-NTT scale)
 * as compile-time constants — see nev_poly_core.inc for the bodies, the
 * Plantard butterfly derivation and the bit-exactness / range arguments —
 * and this file dispatches on info->q, exactly mirroring the reference
 * implementation's per-set compile-time selection while keeping runtime
 * parameter-set agility.
 */

void NEV_PolyNtt(NEV_Poly *r, const CRYPT_NevInfo *info)
{
    if (info->q == 769) {
        NEV_PolyNtt_Q769(r, info->n);
    } else if (info->q == 1409) {
        NEV_PolyNtt_Q1409(r, info->n);
    } else { // q == 3329
        NEV_PolyNtt_Q3329(r, info->n);
    }
}

void NEV_PolyInvNtt(NEV_Poly *r, const CRYPT_NevInfo *info)
{
    if (info->q == 769) {
        NEV_PolyInvNtt_Q769(r, info->n);
    } else if (info->q == 1409) {
        NEV_PolyInvNtt_Q1409(r, info->n);
    } else { // q == 3329
        NEV_PolyInvNtt_Q3329(r, info->n);
    }
}

/* The SVE2 backend folds this normalization into the inverse transform's
 * initial loads.  Other backends retain the two proven-exact operations. */
void NEV_PolyReduceInvNtt(NEV_Poly *r, const CRYPT_NevInfo *info)
{
    NEV_PolyReduce(r, info);
    NEV_PolyInvNtt(r, info);
}

void NEV_PolyReduceInvNttToMsg(uint8_t *msg, NEV_Poly *r, const CRYPT_NevInfo *info)
{
    NEV_PolyReduceInvNtt(r, info);
    NEV_PolyToMsg(msg, r, info);
}

#endif // HITLS_CRYPTO_NEV
