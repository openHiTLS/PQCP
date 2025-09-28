#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "frodo_local.h"
#include "internal/frodo_params.h"

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

// === DEBUG TRACE end ===


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

#if FRODO_TRACE
    TRACE_HEX("[DBG] rS(PKE) head 32B", r_all, 32);
#endif

    FrodoCommonSampleNFromR(matrixSTranspose, count, params->cdfTable, params->cdfLen, r_all);

#if FRODO_TRACE
    TRACE_U16("[DBG] ST (first 16)", matrixSTranspose, 16);
#endif

    uint16_t* B = (uint16_t*)malloc(bytes_one);
    if (!B) {
        free(r_all);
        return -1;
    }
    FrodoCommonSampleNFromR(B, count, params->cdfTable, params->cdfLen, r_all + bytes_one);

#if FRODO_TRACE
    TRACE_U16("[DBG] E (first 16)", B, 16);
#endif

    free(r_all);

    if (FrodoCommonMulAddAsPlusEPortable(B, matrixSTranspose, seedA, params) != 0) {
        free(B);
        return -1;
    }
#if FRODO_TRACE
    TRACE_U16("[DBG] B (first 16)", B, 16);
#endif

    memcpy(pk, seedA, params->lenSeedA);
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
#if FRODO_TRACE
    TRACE_HEX("[ENC] r96 head 32B", r96, ((bytes_S + bytes_E + bytes_Ep) < 32 ? (bytes_S + bytes_E + bytes_Ep) : 32));
#endif
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

#if FRODO_TRACE
    TRACE_U16("[ENC] E' (first 16)", Eprime, 16);
    TRACE_U16("[ENC] E''(first 16)", Epp, 16);
#endif
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

#if FRODO_TRACE
    TRACE_U16("[ENC] U (first 16)", U, 16);
#endif

#if FRODO_TRACE
    {
        const size_t n = params->n;
        const size_t nbar = params->nBar;
        const uint16_t qmask = (uint16_t)((1u << params->logq) - 1u);

        uint16_t* U_ref = (uint16_t*)calloc(nbar * n, sizeof(uint16_t));
        uint8_t* row_bytes = (uint8_t*)malloc(2 * n);
        uint8_t in_row[2 + 16];
        memcpy(in_row + 2, pk_seedA, params->lenSeedA);

        for (uint16_t i = 0; i < n; i++) {
            in_row[0] = (uint8_t)(i & 0xFF);
            in_row[1] = (uint8_t)(i >> 8);
            FrodoKemShake128(row_bytes, (size_t)2 * n, in_row, 2 + params->lenSeedA);

            for (uint16_t r = 0; r < nbar; r++) {
                const uint32_t s_ri = (uint32_t)(STp[(size_t)r * n + i] & qmask);
                const size_t base = (size_t)r * n;
                for (uint16_t j = 0; j < n; j++) {
                    uint16_t a_ij = (uint16_t)row_bytes[2 * j]
                        | (uint16_t)((uint16_t)row_bytes[2 * j + 1] << 8);
                    a_ij &= qmask;
                    uint32_t acc = (uint32_t)U_ref[base + j] + s_ri * a_ij;
                    U_ref[base + j] = (uint16_t)(acc & qmask);
                }
            }
        }

        for (size_t t = 0; t < (size_t)nbar * n; t++) {
            U_ref[t] = (uint16_t)((U_ref[t] + (Eprime[t] & qmask)) & qmask);
        }

        size_t bad = (size_t)-1;
        for (size_t t = 0; t < (size_t)nbar * n; t++) {
            if (U_ref[t] != U[t]) {
                bad = t;
                break;
            }
        }
        if (bad != (size_t)-1) {
            size_t r = bad / n, j = bad % n;
            printf("[CHK][U] mismatch at (r=%zu,j=%zu,t=%zu): U=%04X  ref=%04X\n",
                   r, j, bad, U[bad], U_ref[bad]);
        } else {
            printf("[CHK][U] matches reference (%zu coeffs)\n", (size_t)nbar * n);
        }
        free(U_ref);
        free(row_bytes);
    }
#endif

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

#if FRODO_TRACE

    {
        const size_t b_bytes = (size_t)params->pkSize - params->lenSeedA;
        const size_t ncoeff = (size_t)params->n * params->nBar;
        uint8_t* repacked = (uint8_t*)malloc(b_bytes);
        if (repacked) {
            FrodoCommonPack(repacked, b_bytes, B, ncoeff, params->logq);
            size_t k = 0;
            while (k < b_bytes && repacked[k] == pk_b[k]) k++;
            if (k != b_bytes) {
                printf("[CHK][pk.b] repack mismatch at byte %zu: pk=%02X repacked=%02X\n",
                       k, pk_b[k], repacked[k]);
            } else {
                printf("[CHK][pk.b] repack OK (%zu bytes)\n", b_bytes);
            }
            free(repacked);
        } else {
            printf("[CHK][pk.b] alloc fail\n");
        }
    }
#endif

    FrodoCommonMulAddSbPlusEPortable(V0, STp, B, Epp, params);

#if FRODO_TRACE
    {
        const size_t n = params->n;
        const size_t nbar = params->nBar;
        const uint16_t qmask = (uint16_t)((1u << params->logq) - 1u);

        uint16_t* V0_ref = (uint16_t*)malloc(nbar * nbar * sizeof(uint16_t));
        if (!V0_ref) {
            printf("[CHK][V0] alloc fail\n");
        } else {
            for (size_t i = 0; i < nbar; i++) {
                for (size_t j = 0; j < nbar; j++) {
                    uint64_t acc = (uint64_t)(Epp[i * nbar + j] & qmask);
                    for (size_t k = 0; k < n; k++) {
                        uint32_t s = (uint32_t)(STp[i * n + k] & qmask);
                        uint32_t b = (uint32_t)(B[k * nbar + j] & qmask);
                        acc += (uint64_t)s * b;
                    }
                    V0_ref[i * nbar + j] = (uint16_t)(acc & qmask);
                }
            }
            size_t bad0 = (size_t)-1;
            for (size_t t = 0; t < (size_t)nbar * nbar; t++) {
                if (V0_ref[t] != V0[t]) {
                    bad0 = t;
                    break;
                }
            }
            if (bad0 != (size_t)-1) {
                size_t i0 = bad0 / nbar, j0 = bad0 % nbar;
                printf("[CHK][V0] mismatch at (i=%zu,j=%zu,t=%zu): V0=%04X  ref=%04X\n",
                       i0, j0, bad0, V0[bad0], V0_ref[bad0]);
            } else {
                printf("[CHK][V0] matches reference (%zu coeffs)\n", (size_t)nbar * nbar);
            }
            free(V0_ref);
        }
    }
#endif

    FrodoCommonKeyEncode(M, (const uint16_t*)mu, params);

    for (size_t t = 0; t < cnt_Ep; t++) V[t] = (uint16_t)((V0[t] + M[t]) & qmask);

#if FRODO_TRACE
    TRACE_U16("[ENC] V0 (first 16)", V0, 16);
    TRACE_U16("[ENC] V  (first 16)", V, 16);
#endif

#if FRODO_TRACE
    {
        const size_t nbar = params->nBar;
        const size_t ncoeff = (size_t)nbar * nbar;
        const uint16_t qmask = (uint16_t)((1u << params->logq) - 1u);

        size_t bad = (size_t)-1;
        for (size_t t = 0; t < ncoeff; t++) {
            uint16_t expect = (uint16_t)((V0[t] + M[t]) & qmask);
            if (V[t] != expect) {
                bad = t;
                break;
            }
        }
        if (bad != (size_t)-1) {
            size_t i = bad / nbar, j = bad % nbar;
            printf("[CHK][V] mismatch at (i=%zu,j=%zu,t=%zu): V=%04X  V0=%04X  M=%04X  expect=%04X\n",
                   i, j, bad, V[bad], V0[bad], M[bad],
                   (uint16_t)((V0[bad] + M[bad]) & qmask));
        } else {
            printf("[CHK][V] equals (V0+M) mod q for all %zu coeffs\n", ncoeff);
        }

        const size_t len_c2 = (size_t)(ncoeff * params->logq) / 8;
        uint8_t* tmp_c2 = (uint8_t*)malloc(len_c2);
        uint16_t* V_chk = (uint16_t*)malloc(ncoeff * sizeof(uint16_t));
        if (tmp_c2 && V_chk) {
            memset(tmp_c2, 0, len_c2);
            memset(V_chk, 0, ncoeff * sizeof(uint16_t));
            FrodoCommonPack(tmp_c2, len_c2, V, ncoeff, params->logq);
            FrodoCommonUnpack(V_chk, ncoeff, tmp_c2, len_c2, params->logq);

            size_t bad2 = (size_t)-1;
            for (size_t t = 0; t < ncoeff; t++) {
                if (V_chk[t] != V[t]) {
                    bad2 = t;
                    break;
                }
            }
            if (bad2 != (size_t)-1) {
                size_t i2 = bad2 / nbar, j2 = bad2 % nbar;
                printf("[CHK][V-pack] roundtrip mismatch at (i=%zu,j=%zu,t=%zu): V=%04X  rep=%04X\n",
                       i2, j2, bad2, V[bad2], V_chk[bad2]);
            } else {
                printf("[CHK][V-pack] roundtrip OK (%zu coeffs)\n", ncoeff);
            }
        } else {
            printf("[CHK][V-pack] alloc fail\n");
        }
        free(tmp_c2);
        free(V_chk);
    }
#endif

#if FRODO_TRACE
    {
        size_t len_c1 = (size_t)params->n * params->nBar * params->logq / 8;
        size_t len_c2 = (size_t)params->nBar * params->nBar * params->logq / 8;
        size_t expect = len_c1 + len_c2;
        if ((size_t)params->ctxSize != expect) {
            printf("[CHK][ct-len] params->len_ct=%zu  expect=%zu  (c1=%zu, c2=%zu)\n",
                   (size_t)params->ctxSize, expect, len_c1, len_c2);
        } else {
            printf("[CHK][ct-len] OK: len_ct=%zu (c1=%zu, c2=%zu)\n",
                   (size_t)params->ctxSize, len_c1, len_c2);
        }
    }
#endif

#if FRODO_TRACE
    {
        const size_t n = params->n;
        const size_t nbar = params->nBar;
        const uint16_t qmask = (uint16_t)((1u << params->logq) - 1u);
        const size_t ncoeff = nbar * n;
        const size_t len_c1_local = (size_t)(ncoeff * params->logq) / 8;

        uint8_t* tmp_c1 = (uint8_t*)malloc(len_c1_local);
        uint16_t* U_chk = (uint16_t*)malloc(ncoeff * sizeof(uint16_t));
        if (tmp_c1 && U_chk) {
            memset(tmp_c1, 0, len_c1_local);
            memset(U_chk, 0, ncoeff * sizeof(uint16_t));

            FrodoCommonPack(tmp_c1, len_c1_local, U, ncoeff, params->logq);
            FrodoCommonUnpack(U_chk, ncoeff, tmp_c1, len_c1_local, params->logq);

            size_t bad = (size_t)-1;
            for (size_t i = 0; i < ncoeff; i++) {
                if ((U_chk[i] & qmask) != (U[i] & qmask)) {
                    bad = i;
                    break;
                }
            }
            if (bad != (size_t)-1) {
                printf("[CHK][U] roundtrip mismatch at i=%zu: U=%04X U'=%04X\n",
                       bad, U[bad], U_chk[bad]);
            } else {
                printf("[CHK][U] roundtrip OK (%zu coeffs)\n", ncoeff);
            }
        } else {
            printf("[CHK][U] alloc fail\n");
        }
        free(tmp_c1);
        free(U_chk);
    }
#endif

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

#if FRODO_TRACE
    {
        const size_t nbar = params->nBar;
        const size_t total = (size_t)nbar * nbar;
        uint16_t C_ref[64];
        FrodoCommonKeyEncode(C_ref, (const uint16_t*)mu, params);

        const uint16_t qmask = (uint16_t)((1u << params->logq) - 1u);
        const uint16_t qhalf = (uint16_t)(1u << (params->logq - 1));
        int maxabs = 0;
        for (size_t t = 0; t < total; t++) {
            uint16_t diff = (uint16_t)((M[t] - C_ref[t]) & qmask);
            int centered = (diff >= qhalf) ? (int)diff - (int)(qmask + 1) : (int)diff;
            if (centered < 0) { if (-centered > maxabs) maxabs = -centered; } else {
                if (centered > maxabs) maxabs = centered;
            }
            if (t < 16)
                printf("[NOISE] t=%2zu  M=%04X  Cref=%04X  d(centered)=%5d\n",
                       t, M[t], C_ref[t], centered);
        }
        printf("[NOISE] max |d| = %d\n", maxabs);
    }
#endif

    FrodoCommonKeyDecode((uint16_t*)mu, M, params);

    free(B_prime);
    free(C);
    free(M);

    return 0;
}
