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

#include <stdlib.h>
#include <string.h>
#include "frodo_local.h"
#include "internal/frodo_params.h"

int FrodoPkeKeygenSeeded(const FrodoKemParams* params,
                         uint8_t* pk,
                         uint16_t* matrixSTranspose,
                         const uint8_t* seedA,
                         const uint8_t* seedSE)
{
    const uint16_t n = params->n;
    const uint16_t nbar = params->nBar;
    const size_t count = (size_t)n * nbar;
    const size_t bytes_one = 2 * count;
    const size_t bytes_both = 2 * bytes_one;

    uint8_t* r_all = (uint8_t*)malloc(bytes_both);
    if (!r_all) return -1;
    FrodoExpandShakeDs(r_all, bytes_both, 0x5F, seedSE, params->lenSeedSE, params);

    FrodoCommonSampleNFromR(matrixSTranspose, count, params->cdfTable, params->cdfLen, r_all);

    uint16_t* B = (uint16_t*)malloc(bytes_one);
    if (!B) {
        free(r_all);
        return -1;
    }
    FrodoCommonSampleNFromR(B, count, params->cdfTable, params->cdfLen, r_all + bytes_one);

    free(r_all);

    if (FrodoCommonMulAddAsPlusEPortable(B, matrixSTranspose, seedA, params) != 0) {
        free(B);
        return -1;
    }

    for (int i = 0; i < params->lenSeedA; i++) {
        pk[i] = seedA[i];
    }
    FrodoCommonPack(pk + params->lenSeedA, params->pkSize - params->lenSeedA,
                    B, count, params->logq);
    free(B);
    return 0;
}

int FrodoPkeEncrypt(const FrodoKemParams* params,
                    const uint8_t* pk,
                    const uint8_t* mu,
                    const uint8_t* seedSEp,
                    uint8_t* ct)
{
    const uint16_t n = params->n;
    const uint16_t nbar = params->nBar;
    const uint16_t qmask = (uint16_t)((1u << params->logq) - 1u);

    const uint8_t* pk_seedA = pk;
    const uint8_t* pk_b = pk + params->lenSeedA;
    const size_t len_c1 = ((size_t)n * nbar * params->logq) / 8;
    const size_t len_c2 = ((size_t)nbar * nbar * params->logq) / 8;
    uint8_t* ct_c1 = ct;
    uint8_t* ct_c2 = ct + len_c1;

    const size_t cnt_S = (size_t)n * nbar;
    const size_t cnt_E = (size_t)n * nbar;
    const size_t cnt_Ep = (size_t)nbar * nbar;
    const size_t bytes_S = 2 * cnt_S;
    const size_t bytes_E = 2 * cnt_E;
    const size_t bytes_Ep = 2 * cnt_Ep;

    uint8_t* r96 = (uint8_t*)malloc(bytes_S + bytes_E + bytes_Ep);
    if (!r96) return -1;
    FrodoExpandShakeDs(r96, bytes_S + bytes_E + bytes_Ep,
                       0x96, seedSEp, params->lenSeedSE,
                       params);
    uint8_t* rS = r96;
    uint8_t* rE = r96 + bytes_S;
    uint8_t* rEp = r96 + bytes_S + bytes_E;

    uint16_t* STp = (uint16_t*)malloc(bytes_S);
    uint16_t* Eprime = (uint16_t*)malloc(bytes_E);
    uint16_t* Epp = (uint16_t*)malloc(bytes_Ep);
    if (!STp || !Eprime || !Epp) {
        free(r96);
        free(STp);
        free(Eprime);
        free(Epp);
        return -1;
    }

    FrodoCommonSampleNFromR(STp, cnt_S, params->cdfTable, params->cdfLen, rS);
    FrodoCommonSampleNFromR(Eprime, cnt_E, params->cdfTable, params->cdfLen, rE);
    FrodoCommonSampleNFromR(Epp, cnt_Ep, params->cdfTable, params->cdfLen, rEp);

    free(r96);
    r96 = NULL;

    uint16_t* U = (uint16_t*)malloc(bytes_S);
    if (!U) {
        free(STp);
        free(Eprime);
        free(Epp);
        return -1;
    }

    if (FrodoCommonMulAddSaPlusEPortable(U,
                                         STp,
                                         Eprime,
                                         pk_seedA,
                                         params) != 0) {
        free(STp);
        free(Eprime);
        free(Epp);
        free(U);
        return -1;
    }

    uint16_t* B = (uint16_t*)malloc((size_t)n * nbar * sizeof(uint16_t));
    uint16_t* V0 = (uint16_t*)malloc(bytes_Ep);
    uint16_t* V = (uint16_t*)malloc(bytes_Ep);
    uint16_t* M = (uint16_t*)malloc(bytes_Ep);
    if (!B || !V0 || !V || !M) {
        free(STp);
        free(Eprime);
        free(Epp);
        free(U);
        free(B);
        free(V0);
        free(V);
        free(M);
        return -1;
    }

    FrodoCommonUnpack(B, (size_t)n * nbar,
                      pk_b, params->pkSize - params->lenSeedA,
                      params->logq);

    FrodoCommonMulAddSbPlusEPortable(V0, STp, B, Epp, params);

    FrodoCommonKeyEncode(M, (const uint16_t*)mu, params);

    for (size_t t = 0; t < cnt_Ep; t++) V[t] = (uint16_t)((V0[t] + M[t]) & qmask);

    FrodoCommonPack(ct_c1, len_c1, U, (size_t)nbar * n, params->logq);

    FrodoCommonPack(ct_c2, len_c2, V, (size_t)nbar * nbar, params->logq);

    free(STp);
    free(Eprime);
    free(Epp);
    free(U);
    free(B);
    free(V0);
    free(V);
    free(M);
    return 0;
}

int FrodoPkeDecrypt(const FrodoKemParams* params, const uint8_t* pke_sk, const uint8_t* ct, uint8_t* mu)
{
    const uint8_t* ct_c1 = ct;
    const uint8_t* ct_c2 = ct + (params->n * params->nBar * params->logq) / 8;

    uint16_t* B_prime = (uint16_t*)malloc(params->nBar * params->n * sizeof(uint16_t));
    uint16_t* C = (uint16_t*)malloc(params->nBar * params->nBar * sizeof(uint16_t));
    uint16_t* M = (uint16_t*)malloc(params->nBar * params->nBar * sizeof(uint16_t));

    const uint16_t* S = (const uint16_t*)pke_sk;

    FrodoCommonUnpack(B_prime, params->nBar * params->n, ct_c1, (params->n * params->nBar * params->logq) / 8,
                      params->logq);
    FrodoCommonUnpack(C, params->nBar * params->nBar, ct_c2, (params->nBar * params->nBar * params->logq) / 8,
                      params->logq);

    FrodoCommonMulBsUsingSt(M, B_prime, S, params);
    FrodoCommonSub(M, C, M, params);

    FrodoCommonKeyDecode((uint16_t*)mu, M, params);

    free(B_prime);
    free(C);
    free(M);

    return 0;
}
