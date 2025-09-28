#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "frodo_local.h"
#include "internal/frodo_params.h"
#include "bsl_params.h"
#include "frodokem.h"
#include "securec.h"
#include "pqcp_err.h"
#include "crypt_eal_rand.h"

#if FRODO_TRACE
static void dump_hex(const char* tag, const uint8_t* p, size_t len)
{
    fprintf(stderr, "%s (%zu bytes):\n", tag, (size_t)len);
    for (size_t i = 0; i < len; i++) {
        fprintf(stderr, "%02X", p[i]);
        if ((i % 32) == 31) fprintf(stderr, "\n");
    }
    if (len % 32) fprintf(stderr, "\n");
}

static void dump_u16(const char* tag, const uint16_t* p, size_t count)
{
    fprintf(stderr, "%s (first %zu coeffs, hex q-repr):\n", tag, count);
    for (size_t i = 0; i < count; i++) {
        fprintf(stderr, "%04X ", p[i] & 0xFFFF);
        if ((i % 16) == 15) fprintf(stderr, "\n");
    }
    if (count % 16) fprintf(stderr, "\n");
}

#define TRACE_HEX(tag, ptr, len)  dump_hex(tag, (const uint8_t*)(ptr), (len))
#define TRACE_U16(tag, ptr, n16)  dump_u16(tag, (const uint16_t*)(ptr), (n16))
#else
#define TRACE_HEX(tag, ptr, len)  do{}while(0)
#define TRACE_U16(tag, ptr, n16)  do{}while(0)
#endif

int32_t FrodoKemRandombytes(uint8_t *buffer, size_t len)
{
    return CRYPT_EAL_Randbytes(buffer, len);
}

int FrodoKemKeypairInternal(const uint8_t *rnd, const FrodoKemParams* params, uint8_t* pk, uint8_t* sk)
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

#if FRODO_TRACE
    TRACE_HEX("[KEM] s", s, params->ss);
    TRACE_HEX("[KEM] seedSE", seedSE, params->lenSeedSE);
    TRACE_HEX("[KEM] z", z, params->lenSeedA);
#endif

    uint8_t seedA[FRODOKEM_LEN_A];
    if (n == 640) {
        FrodoKemShake128(seedA, FRODOKEM_LEN_A, z, FRODOKEM_LEN_A);
    } else {
        FrodoKemShake256(seedA, FRODOKEM_LEN_A, z, FRODOKEM_LEN_A);
    }

#if FRODO_TRACE
    TRACE_HEX("[KEM] seedA = SHAKE128(z)", seedA, FRODOKEM_LEN_A);
#endif

    if (FrodoPkeKeygenSeeded(params, pk, sTranspose, seedA, seedSE) != 0) {
        goto clean;
    }

#if FRODO_TRACE

    TRACE_HEX("[KEM] pk.seedA (pk[0:len_seed_a])", pk, params->lenSeedA);

    size_t b_len = params->lenPk - params->lenSeedA;
    const uint8_t* pk_b = pk + params->lenSeedA;
    size_t head = b_len < 64 ? b_len : 64;
    size_t tail = b_len < 64 ? 0 : 64;
    TRACE_HEX("[KEM] pk.b head", pk_b, head);
    if (tail)
        TRACE_HEX("[KEM] pk.b tail", pk_b + b_len - tail, tail);

    TRACE_U16("[KEM] S (first 16 coeffs)", sTranspose, 16);
#endif

#if FRODO_TRACE

    {
        const size_t b_bytes = (size_t)params->lenPk - params->lenSeedA;
        const size_t ncoeff = (size_t)params->n * params->nBar;
        uint16_t* B_unp = (uint16_t*)malloc(ncoeff * sizeof(uint16_t));
        uint8_t* B_rep = (uint8_t*)malloc(b_bytes);
        if (B_unp && B_rep) {
            FrodoCommonUnpack(B_unp, ncoeff, pk_b, b_bytes, params->logq);
            FrodoCommonPack(B_rep, b_bytes, B_unp, ncoeff, params->logq);
            size_t k = 0;
            while (k < b_bytes && B_rep[k] == pk_b[k]) k++;
            if (k != b_bytes) {
                fprintf(stderr,
                        "[CHK][keygen pk.b] roundtrip mismatch at byte %zu: pk=%02X repack=%02X\n",
                        k, pk_b[k], B_rep[k]);
            }
        }
        free(B_unp);
        free(B_rep);
    }
#endif

    uint8_t* sk_s = sk;
    uint8_t* sk_pk = sk + params->ss;
    uint8_t* sk_S = sk_pk + params->pkSize;
    uint8_t* sk_pkh = sk_S + SnB;

    memcpy(sk_s, s, params->ss);
    memcpy(sk_pk, pk, params->pkSize);
    memcpy(sk_S, (uint8_t*)sTranspose, SnB);

#if FRODO_TRACE
    TRACE_U16("[DBG] sk.ST first 16 (after write)", (uint16_t*)sk_S, 16);
#endif

    if (n == 640) {
        FrodoKemShake128(sk_pkh, params->lenPkHash, pk, params->pkSize);
    } else {
        FrodoKemShake256(sk_pkh, params->lenPkHash, pk, params->pkSize);
    }
#if FRODO_TRACE
    TRACE_HEX("[KEM] pkh = H(pk)", sk_pkh, params->lenPkHash);
#endif

clean:
    free(sTranspose);
    return 0;
}

int FrodoKemKeypair(const FrodoKemParams* params, uint8_t* pk, uint8_t* sk)
{
    const size_t need = (size_t)params->ss + params->lenSeedSE + params->lenSeedA;
    uint8_t rnd[112] = {0};
    int32_t ret = FrodoKemRandombytes(rnd, need);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    return FrodoKemKeypairInternal(rnd, params, pk, sk);
}

int FrodoKemEncapsInternal(const uint8_t *mu, const FrodoKemParams* params, uint8_t* ct, uint8_t* ss, const uint8_t* pk)
{
    uint8_t pkh[32];
    if (params->lenPkHash > sizeof(pkh)) return -1;
    if (params->n == 640) {
        FrodoKemShake128(pkh, params->lenPkHash, pk, params->pkSize);
    } else {
        FrodoKemShake256(pkh, params->lenPkHash, pk, params->pkSize);
    }
#if FRODO_TRACE
    TRACE_HEX("[ENC] pkh", pkh, params->lenPkHash);
#endif

#if FRODO_TRACE
    TRACE_HEX("[ENC] mu", mu, params->lenMu);
#endif

    const size_t seedk_len = params->lenSeedSE + params->ss;
    uint8_t* seedk = (uint8_t*)malloc(seedk_len);
    if (!seedk) return -1;

    const size_t in_len = params->lenPkHash + params->lenMu + params->lenSalt;
    uint8_t* in = (uint8_t*)malloc(in_len);
    if (!in) {
        free(seedk);
        return -1;
    }
    memcpy(in, pkh, params->lenPkHash);
    memcpy(in + params->lenPkHash, mu, params->lenMu + params->lenSalt);

    if (params->n == 640) {
        FrodoKemShake128(seedk, seedk_len, in, in_len);
    } else {
        FrodoKemShake256(seedk, seedk_len, in, in_len);
    }
#if FRODO_TRACE
    TRACE_HEX("[ENC] SHAKE(pkh||mu) head 32B", seedk, seedk_len < 32 ? seedk_len : 32);
#endif
    free(in);

    uint8_t* seedSEp = seedk;
    uint8_t* k = seedk + params->lenSeedSE;
#if FRODO_TRACE
    TRACE_HEX("[ENC] seedSE'", seedSEp, params->lenSeedSE);
    TRACE_HEX("[ENC] k", k, params->ss);
#endif

    if (FrodoPkeEncrypt(params, pk, mu, seedSEp, ct) != 0) {
        free(seedk);
        return -1;
    }

    memcpy(ct + params->ctxSize - params->lenSalt, mu + params->lenMu, params->lenSalt);

    size_t ct_k_len = params->ctxSize + params->ss;
    uint8_t* ct_k = (uint8_t*)malloc(ct_k_len);
    if (!ct_k) {
        free(seedk);
        return -1;
    }

    memcpy(ct_k, ct, params->ctxSize);
    memcpy(ct_k + params->ctxSize, k, params->ss);

    if (params->n == 640) {
        FrodoKemShake128(ss, params->ss, ct_k, ct_k_len);
    } else {
        FrodoKemShake256(ss, params->ss, ct_k, ct_k_len);
    }
#if FRODO_TRACE
    TRACE_HEX("[ENC] ct head 64B", ct, params->lenCt < 64 ? params->lenCt : 64);
    if (params->lenCt > 64)
        TRACE_HEX("[ENC] ct tail 64B", ct + params->lenCt - 64, 64);

#endif

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

    return FrodoKemEncapsInternal(mu, params, ct, ss, pk);
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
    if (!seed_k_bytes_prime) return -1;

    size_t pkh_mu_len = params->lenPkHash + params->lenMu + params->lenSalt;
    uint8_t* pkh_mu_bytes_prime = (uint8_t*)malloc(pkh_mu_len);
    if (!pkh_mu_bytes_prime) {
        free(seed_k_bytes_prime);
        return -1;
    }
    memcpy(pkh_mu_bytes_prime, sk_pkh, params->lenPkHash);
    memcpy(pkh_mu_bytes_prime + params->lenPkHash, mu_prime, params->lenMu);
    memcpy(pkh_mu_bytes_prime + params->lenPkHash + params->lenMu, ct + params->ctxSize - params->lenSalt,
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
        return -1;
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
        return -1;
    }
    memcpy(ct_k_bytes, ct, params->ctxSize);
    memcpy(ct_k_bytes + params->ctxSize, final_k, params->ss);

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
