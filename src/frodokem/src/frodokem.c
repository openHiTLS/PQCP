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
#include "bsl_params.h"
#include "frodokem.h"
#include "securec.h"
#include "pqcp_err.h"
#include "crypt_eal_rand.h"
#include "securec.h"

int32_t FrodoKemRandombytes(uint8_t* buffer, size_t len)
{
    return CRYPT_EAL_Randbytes(buffer, len);
}

int FrodoKemKeypairInternal(const uint8_t* rnd, const FrodoKemParams* params, uint8_t* pk, uint8_t* sk, size_t lenSk)
{
    const uint16_t n = params->n;
    const uint16_t nbar = params->nBar;
    const size_t SnB = (size_t)n * nbar * sizeof(uint16_t);

    const uint8_t* s = rnd;
    const uint8_t* seedSE = rnd + params->ss;
    const uint8_t* z = rnd + params->ss + params->lenSeedSE;

    // alloc memory
    uint16_t* sTranspose = (uint16_t*)malloc(SnB);
    if (!sTranspose) {
        goto clean;
    }

    uint8_t seedA[FRODOKEM_LEN_A];
    if (n == 640) {
        FrodoKemShake128(seedA, FRODOKEM_LEN_A, z, FRODOKEM_LEN_A);
    } else {
        FrodoKemShake256(seedA, FRODOKEM_LEN_A, z, FRODOKEM_LEN_A);
    }

    if (FrodoPkeKeygenSeeded(params, pk, sTranspose, seedA, seedSE) != 0) {
        goto clean;
    }

    uint8_t* sk_s = sk;
    uint8_t* sk_pk = sk + params->ss;
    uint8_t* sk_S = sk_pk + params->pkSize;
    uint8_t* sk_pkh = sk_S + SnB;

    memcpy_s(sk_s, lenSk, s, params->ss);
    memcpy_s(sk_pk, lenSk - params->ss, pk, params->pkSize);
    memcpy_s(sk_S, lenSk - params->ss - params->pkSize, (uint8_t*)sTranspose, SnB);

    if (n == 640) {
        FrodoKemShake128(sk_pkh, params->lenPkHash, pk, params->pkSize);
    } else {
        FrodoKemShake256(sk_pkh, params->lenPkHash, pk, params->pkSize);
    }

clean:
    free(sTranspose);
    return 0;
}

int FrodoKemKeypair(const FrodoKemParams* params, uint8_t* pk, uint8_t* sk, size_t lenSk)
{
    const size_t need = (size_t)params->ss + params->lenSeedSE + params->lenSeedA;
    uint8_t rnd[112] = {0};
    int32_t ret = FrodoKemRandombytes(rnd, need);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    ret = FrodoKemKeypairInternal(rnd, params, pk, sk, lenSk);
    BSL_SAL_CleanseData(rnd, need);
    return ret;
}

int FrodoKemEncapsInternal(const uint8_t* mu, const FrodoKemParams* params, uint8_t* ct, uint8_t* ss, const uint8_t* pk)
{
    uint8_t pkh[32];
    if (params->lenPkHash > sizeof(pkh)) {
        return PQCP_FRODOKEM_INVALID_ARG;
    }
    if (params->n == 640) {
        FrodoKemShake128(pkh, params->lenPkHash, pk, params->pkSize);
    } else {
        FrodoKemShake256(pkh, params->lenPkHash, pk, params->pkSize);
    }

    const size_t seedk_len = params->lenSeedSE + params->ss;
    uint8_t* seedk = (uint8_t*)malloc(seedk_len);
    if (!seedk) {
        return PQCP_MEM_ALLOC_FAIL;
    }

    const size_t in_len = params->lenPkHash + params->lenMu + params->lenSalt;
    uint8_t* in = (uint8_t*)malloc(in_len);
    if (!in) {
        free(seedk);
        return PQCP_MEM_ALLOC_FAIL;
    }
    memcpy_s(in, in_len, pkh, params->lenPkHash);
    memcpy_s(in + params->lenPkHash, in_len - params->lenPkHash, mu, params->lenMu + params->lenSalt);

    if (params->n == 640) {
        FrodoKemShake128(seedk, seedk_len, in, in_len);
    } else {
        FrodoKemShake256(seedk, seedk_len, in, in_len);
    }
    free(in);

    uint8_t* seedSEp = seedk;
    uint8_t* k = seedk + params->lenSeedSE;

    if (FrodoPkeEncrypt(params, pk, mu, seedSEp, ct) != 0) {
        free(seedk);
        return PQCP_FRODOKEM_ENCRYPT_FAIL;
    }

    for (int i = 0; i < params->lenSalt; i++) {
        ct[params->ctxSize - params->lenSalt + i] = mu[params->lenMu + i];
    }

    size_t ct_k_len = params->ctxSize + params->ss;
    uint8_t* ct_k = (uint8_t*)malloc(ct_k_len);
    if (!ct_k) {
        free(seedk);
        return PQCP_MEM_ALLOC_FAIL;
    }

    memcpy_s(ct_k, ct_k_len, ct, params->ctxSize);
    memcpy_s(ct_k + params->ctxSize, ct_k_len - params->ctxSize, k, params->ss);

    if (params->n == 640) {
        FrodoKemShake128(ss, params->ss, ct_k, ct_k_len);
    } else {
        FrodoKemShake256(ss, params->ss, ct_k, ct_k_len);
    }

    free(ct_k);
    free(seedk);
    return 0;
}

int FrodoKemEncaps(const FrodoKemParams* params, uint8_t* ct, uint8_t* ss, const uint8_t* pk)
{
    uint8_t mu[32 + 64];

    int32_t ret = FrodoKemRandombytes(mu, params->lenMu + params->lenSalt);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }

    ret = FrodoKemEncapsInternal(mu, params, ct, ss, pk);
    BSL_SAL_CleanseData(mu, params->lenMu + params->lenSalt);
    return ret;
}

int FrodoKemDecaps(const FrodoKemParams* params, uint8_t* ss, const uint8_t* ct, const uint8_t* sk)
{
    const uint8_t* sk_s = sk;
    const uint8_t* sk_pk = sk + params->ss;
    const uint8_t* sk_S = sk_pk + params->pkSize;
    const uint8_t* sk_pkh = sk_S + (params->n * params->nBar * sizeof(uint16_t));

    uint8_t mu_prime[params->lenMu];
    int ret = FrodoPkeDecrypt(params, sk_S, ct, mu_prime);
    if (ret != 0) {
        return ret;
    }

    size_t seed_k_len = params->lenSeedSE + params->ss;
    uint8_t* seed_k_bytes_prime = (uint8_t*)malloc(seed_k_len);
    if (!seed_k_bytes_prime) {
        return PQCP_MEM_ALLOC_FAIL;
    }

    size_t pkh_mu_len = params->lenPkHash + params->lenMu + params->lenSalt;
    uint8_t* pkh_mu_bytes_prime = (uint8_t*)malloc(pkh_mu_len);
    if (!pkh_mu_bytes_prime) {
        free(seed_k_bytes_prime);
        return PQCP_MEM_ALLOC_FAIL;
    }
    memcpy_s(pkh_mu_bytes_prime, pkh_mu_len, sk_pkh, params->lenPkHash);
    memcpy_s(pkh_mu_bytes_prime + params->lenPkHash, pkh_mu_len - params->lenPkHash, mu_prime, params->lenMu);
    memcpy_s(pkh_mu_bytes_prime + params->lenPkHash + params->lenMu, pkh_mu_len - params->lenPkHash - params->lenMu,
             ct + params->ctxSize - params->lenSalt,
             params->lenSalt);

    if (params->n == 640) {
        FrodoKemShake128(seed_k_bytes_prime, seed_k_len, pkh_mu_bytes_prime, pkh_mu_len);
    } else {
        FrodoKemShake256(seed_k_bytes_prime, seed_k_len, pkh_mu_bytes_prime, pkh_mu_len);
    }
    uint8_t* seedSE_prime = seed_k_bytes_prime;
    uint8_t* k_prime = seed_k_bytes_prime + params->lenSeedSE;

    uint8_t* ct_prime = (uint8_t*)malloc(params->ctxSize);
    if (!ct_prime) {
        free(seed_k_bytes_prime);
        free(pkh_mu_bytes_prime);
        return PQCP_MEM_ALLOC_FAIL;
    }

    ret = FrodoPkeEncrypt(params, sk_pk, mu_prime, seedSE_prime, ct_prime);
    if (ret != 0) {
        free(seed_k_bytes_prime);
        free(pkh_mu_bytes_prime);
        free(ct_prime);
        return ret;
    }

    int8_t selector = FrodoCommonCtVerify((uint16_t*)ct, (uint16_t*)ct_prime,
                                          (params->ctxSize - params->lenSalt) / sizeof(uint16_t));

    uint8_t final_k[params->ss];
    FrodoCommonCtSelect(final_k, k_prime, sk_s, params->ss, selector);

    size_t ct_k_len = params->ctxSize + params->ss;
    uint8_t* ct_k_bytes = (uint8_t*)malloc(ct_k_len);
    if (!ct_k_bytes) {
        free(seed_k_bytes_prime);
        free(pkh_mu_bytes_prime);
        free(ct_prime);
        return PQCP_MEM_ALLOC_FAIL;
    }
    memcpy_s(ct_k_bytes, ct_k_len, ct, params->ctxSize);
    memcpy_s(ct_k_bytes + params->ctxSize, ct_k_len - params->ctxSize, final_k, params->ss);

    if (params->n == 640) {
        FrodoKemShake128(ss, params->ss, ct_k_bytes, ct_k_len);
    } else {
        FrodoKemShake256(ss, params->ss, ct_k_bytes, ct_k_len);
    }
    free(seed_k_bytes_prime);
    free(pkh_mu_bytes_prime);
    free(ct_prime);
    free(ct_k_bytes);

    return 0;
}
