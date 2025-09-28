#include <stdlib.h>
#include <string.h>
#include "frodo_local.h"
#include "internal/frodo_params.h"
#include "crypt_eal_cipher.h"
#include "pqcp_err.h"

int FrodoCommonMulAddAsPlusEPortable(uint16_t* out,
                                     const uint16_t* matrixSTranspose, 
                                     const uint8_t*  seedA,
                                     const FrodoKemParams* params)
{
    const int N    = params->n;
    const int NBAR = params->nBar;
    int ret = 0;
    const uint16_t qmask = (uint16_t)((1u << params->logq) - 1u);

    #define FRODO_MAX_N         1344
    #define FRODO_MAX_SEED_A    16   

    ALIGN_HEADER(32) uint16_t A_rows[4 * FRODO_MAX_N] ALIGN_FOOTER(32);
    ALIGN_HEADER(32) uint8_t  AES_PT[4 * 16 * (FRODO_MAX_N/8)] ALIGN_FOOTER(32);
    ALIGN_HEADER(32) uint8_t  INBUF[4 * (2 + FRODO_MAX_SEED_A)] ALIGN_FOOTER(32);

    if (params->prg == FRODO_PRG_AES) {
        // ====================== AES ======================
        CRYPT_EAL_CipherCtx *RandCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_ECB);
        if (RandCtx == NULL) {
            return PQCP_MALLOC_FAIL;
        }

        ret = CRYPT_EAL_CipherInit(RandCtx, seedA, 16, NULL, 0, true);
        if (ret != PQCP_SUCCESS) {
            CRYPT_EAL_CipherFreeCtx(RandCtx);
            return ret;
        }
        ret = CRYPT_EAL_CipherSetPadding(RandCtx, CRYPT_PADDING_NONE);
        if (ret != PQCP_SUCCESS) {
            CRYPT_EAL_CipherFreeCtx(RandCtx);
            return ret;
        }

        const int blocks_per_row = N / 8;

        for (int blk = 0; blk < blocks_per_row; blk++) {
            const uint16_t jj    = (uint16_t)(blk << 3);
            const uint8_t  jj_lo = (uint8_t)(jj & 0xFF);
            const uint8_t  jj_hi = (uint8_t)(jj >> 8);
            for (int r = 0; r < 4; r++) {
                uint8_t* P = &AES_PT[16 * (blk + r * blocks_per_row)];
                P[2] = jj_lo; P[3] = jj_hi;
                for (int t = 4; t < 16; t++) P[t] = 0;
            }
        }

        for (int i = 0; i < N; i += 4) {
            for (int blk = 0; blk < blocks_per_row; blk++) {
                uint8_t* P0 = &AES_PT[16 * (blk + 0 * blocks_per_row)];
                uint8_t* P1 = &AES_PT[16 * (blk + 1 * blocks_per_row)];
                uint8_t* P2 = &AES_PT[16 * (blk + 2 * blocks_per_row)];
                uint8_t* P3 = &AES_PT[16 * (blk + 3 * blocks_per_row)];
                const uint16_t i0 = (uint16_t)(i + 0);
                const uint16_t i1 = (uint16_t)(i + 1);
                const uint16_t i2 = (uint16_t)(i + 2);
                const uint16_t i3 = (uint16_t)(i + 3);
                P0[0] = (uint8_t)(i0 & 0xFF); P0[1] = (uint8_t)(i0 >> 8);
                P1[0] = (uint8_t)(i1 & 0xFF); P1[1] = (uint8_t)(i1 >> 8);
                P2[0] = (uint8_t)(i2 & 0xFF); P2[1] = (uint8_t)(i2 >> 8);
                P3[0] = (uint8_t)(i3 & 0xFF); P3[1] = (uint8_t)(i3 >> 8);
            }

            int outLen = 4 * blocks_per_row * 16;
            ret = CRYPT_EAL_CipherUpdate(RandCtx, AES_PT, (size_t)4 * blocks_per_row * 16, (uint8_t *)A_rows,
                                     &outLen);
            if (ret != PQCP_SUCCESS) {
                CRYPT_EAL_CipherFreeCtx(RandCtx);
                return ret;
            }

            for (int k = 0; k < 4 * N; k++) {
                A_rows[k] = (uint16_t)LE_TO_UINT16(A_rows[k]);
            }

            const uint16_t* row0 = &A_rows[0 * N];
            const uint16_t* row1 = &A_rows[1 * N];
            const uint16_t* row2 = &A_rows[2 * N];
            const uint16_t* row3 = &A_rows[3 * N];

            for (int j = 0; j < NBAR; j++) {
                const uint16_t* ST_row = &matrixSTranspose[j * N];
                uint16_t sum0 = 0, sum1 = 0, sum2 = 0, sum3 = 0;
                for (int k = 0; k < N; k++) {
                    uint16_t sv = ST_row[k];
                    sum0 += (uint16_t)((uint32_t)row0[k] * sv);
                    sum1 += (uint16_t)((uint32_t)row1[k] * sv);
                    sum2 += (uint16_t)((uint32_t)row2[k] * sv);
                    sum3 += (uint16_t)((uint32_t)row3[k] * sv);
                }
                    out[(i+0)*NBAR + j] = (uint16_t)(out[(i+0)*NBAR + j] + sum0);
                    out[(i+1)*NBAR + j] = (uint16_t)(out[(i+1)*NBAR + j] + sum1);
                    out[(i+2)*NBAR + j] = (uint16_t)(out[(i+2)*NBAR + j] + sum2);
                    out[(i+3)*NBAR + j] = (uint16_t)(out[(i+3)*NBAR + j] + sum3);
            }
        }

        CRYPT_EAL_CipherFreeCtx(RandCtx);
        return 0;
    } else {
        // ====================== SHAKE ======================
        const size_t inlen = 2 + (size_t)params->lenSeedA;
        uint8_t* in0 = &INBUF[0 * inlen];
        uint8_t* in1 = &INBUF[1 * inlen];
        uint8_t* in2 = &INBUF[2 * inlen];
        uint8_t* in3 = &INBUF[3 * inlen];

        memcpy(in0 + 2, seedA, params->lenSeedA);
        memcpy(in1 + 2, seedA, params->lenSeedA);
        memcpy(in2 + 2, seedA, params->lenSeedA);
        memcpy(in3 + 2, seedA, params->lenSeedA);

        uint16_t* row0 = &A_rows[0 * N];
        uint16_t* row1 = &A_rows[1 * N];
        uint16_t* row2 = &A_rows[2 * N];
        uint16_t* row3 = &A_rows[3 * N];

        for (int i = 0; i < N; i += 4) {
            in0[0] = (uint8_t)((i + 0) & 0xFF); in0[1] = (uint8_t)((i + 0) >> 8);
            in1[0] = (uint8_t)((i + 1) & 0xFF); in1[1] = (uint8_t)((i + 1) >> 8);
            in2[0] = (uint8_t)((i + 2) & 0xFF); in2[1] = (uint8_t)((i + 2) >> 8);
            in3[0] = (uint8_t)((i + 3) & 0xFF); in3[1] = (uint8_t)((i + 3) >> 8);

            FrodoKemShake128((uint8_t*)row0, (size_t)N * sizeof(uint16_t), in0, inlen);
            FrodoKemShake128((uint8_t*)row1, (size_t)N * sizeof(uint16_t), in1, inlen);
            FrodoKemShake128((uint8_t*)row2, (size_t)N * sizeof(uint16_t), in2, inlen);
            FrodoKemShake128((uint8_t*)row3, (size_t)N * sizeof(uint16_t), in3, inlen);

            for (int j = 0; j < NBAR; j++) {
                const uint16_t* ST_row = &matrixSTranspose[j * N];
                uint16_t sum0 = 0, sum1 = 0, sum2 = 0, sum3 = 0;
                for (int k = 0; k < N; k++) {
                     uint16_t sv = ST_row[k];
                     sum0 += (uint16_t)((uint32_t)row0[k] * sv);
                     sum1 += (uint16_t)((uint32_t)row1[k] * sv);
                     sum2 += (uint16_t)((uint32_t)row2[k] * sv);
                     sum3 += (uint16_t)((uint32_t)row3[k] * sv);
                }
                out[(i+0)*NBAR + j] = (uint16_t)(out[(i+0)*NBAR + j] + sum0);
                out[(i+1)*NBAR + j] = (uint16_t)(out[(i+1)*NBAR + j] + sum1);
                out[(i+2)*NBAR + j] = (uint16_t)(out[(i+2)*NBAR + j] + sum2);
                out[(i+3)*NBAR + j] = (uint16_t)(out[(i+3)*NBAR + j] + sum3);
            }
        }
        return 0;
    }
}


int FrodoCommonMulAddSaPlusEPortable(uint16_t *out,
                                     const uint16_t *s,         
                                     const uint16_t *e,         
                                     const uint8_t  *seed_A,
                                     const FrodoKemParams *params)
{
    const int N    = params->n;
    const int NBAR = params->nBar;

    for (int i = 0; i < NBAR * N; i += 2) {
        *((uint32_t *)&out[i]) = *((const uint32_t *)&e[i]);
    }

    #define FRODO_MAX_N         1344
    #define FRODO_MAX_SEED_A    16   

    ALIGN_HEADER(32) uint16_t A_rows[4 * FRODO_MAX_N] ALIGN_FOOTER(32);
    ALIGN_HEADER(32) uint8_t  AES_PT[4 * 16 * (FRODO_MAX_N/8)] ALIGN_FOOTER(32);
    ALIGN_HEADER(32) uint8_t  INBUF[4 * (2 + FRODO_MAX_SEED_A)] ALIGN_FOOTER(32);

    if (params->prg == FRODO_PRG_AES) {
        // ====================== AES ======================
        CRYPT_EAL_CipherCtx *RandCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_ECB);
        if (RandCtx == NULL) {
            return PQCP_MALLOC_FAIL;
        }

        int ret = CRYPT_EAL_CipherInit(RandCtx, seed_A, 16, NULL, 0, true);
        if (ret != PQCP_SUCCESS) {
            CRYPT_EAL_CipherFreeCtx(RandCtx);
            return ret;
        }
        ret = CRYPT_EAL_CipherSetPadding(RandCtx, CRYPT_PADDING_NONE);
        if (ret != PQCP_SUCCESS) {
            CRYPT_EAL_CipherFreeCtx(RandCtx);
            return ret;
        }

        const int blocks_per_row = N / 8; 

        for (int blk = 0; blk < blocks_per_row; blk++) {
            const uint16_t jj    = (uint16_t)(blk << 3);
            const uint8_t  jj_lo = (uint8_t)(jj & 0xFF);
            const uint8_t  jj_hi = (uint8_t)(jj >> 8);
            for (int r = 0; r < 4; r++) {
                uint8_t *P = &AES_PT[16 * (blk + r * blocks_per_row)];
                P[2] = jj_lo; P[3] = jj_hi;
                for (int t = 4; t < 16; t++) P[t] = 0;
            }
        }

        for (int i = 0; i < N; i += 4) {
            for (int blk = 0; blk < blocks_per_row; blk++) {
                uint8_t *P0 = &AES_PT[16 * (blk + 0 * blocks_per_row)];
                uint8_t *P1 = &AES_PT[16 * (blk + 1 * blocks_per_row)];
                uint8_t *P2 = &AES_PT[16 * (blk + 2 * blocks_per_row)];
                uint8_t *P3 = &AES_PT[16 * (blk + 3 * blocks_per_row)];
                const uint16_t i0 = (uint16_t)(i + 0);
                const uint16_t i1 = (uint16_t)(i + 1);
                const uint16_t i2 = (uint16_t)(i + 2);
                const uint16_t i3 = (uint16_t)(i + 3);
                P0[0] = (uint8_t)(i0 & 0xFF); P0[1] = (uint8_t)(i0 >> 8);
                P1[0] = (uint8_t)(i1 & 0xFF); P1[1] = (uint8_t)(i1 >> 8);
                P2[0] = (uint8_t)(i2 & 0xFF); P2[1] = (uint8_t)(i2 >> 8);
                P3[0] = (uint8_t)(i3 & 0xFF); P3[1] = (uint8_t)(i3 >> 8);
            }

            int outLen = 4 * blocks_per_row * 16;
            ret = CRYPT_EAL_CipherUpdate(RandCtx, AES_PT, (size_t)4 * blocks_per_row * 16, (uint8_t *)A_rows,
                         &outLen);
            if (ret != PQCP_SUCCESS) {
                CRYPT_EAL_CipherFreeCtx(RandCtx);
                return ret;
            }

            for (int k = 0; k < 4 * N; k++) {
                A_rows[k] = (uint16_t)LE_TO_UINT16(A_rows[k]);
            }

            const uint16_t *row0 = &A_rows[0 * N];
            const uint16_t *row1 = &A_rows[1 * N];
            const uint16_t *row2 = &A_rows[2 * N];
            const uint16_t *row3 = &A_rows[3 * N];

            for (int k = 0; k < NBAR; k++) {
                const uint16_t s0 = s[k * N + (i + 0)];
                const uint16_t s1 = s[k * N + (i + 1)];
                const uint16_t s2 = s[k * N + (i + 2)];
                const uint16_t s3 = s[k * N + (i + 3)];

                uint16_t *out_row = &out[k * N];
                for (int j = 0; j < N; j++) {
                    uint16_t acc = out_row[j];
                    acc = (uint16_t)(acc + (uint16_t)(row0[j] * s0));
                    acc = (uint16_t)(acc + (uint16_t)(row1[j] * s1));
                    acc = (uint16_t)(acc + (uint16_t)(row2[j] * s2));
                    acc = (uint16_t)(acc + (uint16_t)(row3[j] * s3));
                    out_row[j] = acc;
                }
            }
        }

        CRYPT_EAL_CipherFreeCtx(RandCtx);
        return 0;
    } else {
        // ====================== SHAKE ======================
        const size_t inlen = 2 + (size_t)params->lenSeedA;
        uint8_t *in0 = &INBUF[0 * inlen];
        uint8_t *in1 = &INBUF[1 * inlen];
        uint8_t *in2 = &INBUF[2 * inlen];
        uint8_t *in3 = &INBUF[3 * inlen];

        memcpy(in0 + 2, seed_A, params->lenSeedA);
        memcpy(in1 + 2, seed_A, params->lenSeedA);
        memcpy(in2 + 2, seed_A, params->lenSeedA);
        memcpy(in3 + 2, seed_A, params->lenSeedA);

        uint16_t *row0 = &A_rows[0 * N];
        uint16_t *row1 = &A_rows[1 * N];
        uint16_t *row2 = &A_rows[2 * N];
        uint16_t *row3 = &A_rows[3 * N];

        for (int i = 0; i < N; i += 4) {
            in0[0] = (uint8_t)((i + 0) & 0xFF); in0[1] = (uint8_t)((i + 0) >> 8);
            in1[0] = (uint8_t)((i + 1) & 0xFF); in1[1] = (uint8_t)((i + 1) >> 8);
            in2[0] = (uint8_t)((i + 2) & 0xFF); in2[1] = (uint8_t)((i + 2) >> 8);
            in3[0] = (uint8_t)((i + 3) & 0xFF); in3[1] = (uint8_t)((i + 3) >> 8);

            FrodoKemShake128((uint8_t *)row0, (size_t)N * sizeof(uint16_t), in0, inlen);
            FrodoKemShake128((uint8_t *)row1, (size_t)N * sizeof(uint16_t), in1, inlen);
            FrodoKemShake128((uint8_t *)row2, (size_t)N * sizeof(uint16_t), in2, inlen);
            FrodoKemShake128((uint8_t *)row3, (size_t)N * sizeof(uint16_t), in3, inlen);

            for (int k = 0; k < NBAR; k++) {
                const uint16_t s0 = s[k * N + (i + 0)];
                const uint16_t s1 = s[k * N + (i + 1)];
                const uint16_t s2 = s[k * N + (i + 2)];
                const uint16_t s3 = s[k * N + (i + 3)];

                uint16_t *out_row = &out[k * N];
                for (int j = 0; j < N; j++) {
                    uint16_t acc = out_row[j];
                    acc = (uint16_t)(acc + (uint16_t)(row0[j] * s0));
                    acc = (uint16_t)(acc + (uint16_t)(row1[j] * s1));
                    acc = (uint16_t)(acc + (uint16_t)(row2[j] * s2));
                    acc = (uint16_t)(acc + (uint16_t)(row3[j] * s3));
                    out_row[j] = acc;
                }
            }
        }
        return 0;
    }
}

int FrodoCommonMulAddSbPlusEPortable(uint16_t* V0,
                                            const uint16_t* STp,
                                            const uint16_t* B,
                                            const uint16_t* Epp,
                                            const FrodoKemParams* params)
{
    const size_t n = params->n;
    const size_t nbar = params->nBar;
    const uint16_t qmask = (uint16_t)((1u << params->logq) - 1u);

    for (size_t i = 0; i < nbar * nbar; i++) V0[i] = (uint16_t)(Epp[i] & qmask);

    for (size_t i = 0; i < nbar; i++) {
        const size_t Si = i * n;
        const size_t Vi = i * nbar;
        for (size_t k = 0; k < n; k++) {
            const uint32_t s = (uint32_t)(STp[Si + k] & qmask);
            const size_t Bk = k * nbar;
            for (size_t j = 0; j < nbar; j++) {
                const uint32_t b = (uint32_t)(B[Bk + j] & qmask);
                uint32_t acc = (uint32_t)V0[Vi + j] + s * b;
                V0[Vi + j] = (uint16_t)(acc & qmask);
            }
        }
    }
    return 0;
}

void FrodoCommonMulBs(uint16_t* out, const uint16_t* b, const uint16_t* s,
                         const FrodoKemParams* params)
{
    const size_t n = params->n, nbar = params->nBar;
    const uint16_t qmask = (uint16_t)((1u << params->logq) - 1u);

    for (size_t i = 0; i < nbar; i++) {
        for (size_t j = 0; j < nbar; j++) {
            uint64_t acc = 0;
            for (size_t k = 0; k < n; k++) {
                acc += (uint32_t)(b[i * n + k] & qmask) * (uint32_t)(s[k * nbar + j] & qmask);
            }
            out[i * nbar + j] = (uint16_t)(acc & qmask);
        }
    }
}

void FrodoCommonMulBsUsingSt(uint16_t* out, const uint16_t* b, const uint16_t* sT,
                                  const FrodoKemParams* params)
{
    const size_t n = params->n, nbar = params->nBar;
    const uint16_t qmask = (uint16_t)((1u << params->logq) - 1u);
    for (size_t i = 0; i < nbar; i++) {
        for (size_t j = 0; j < nbar; j++) {
            uint64_t acc = 0;
            for (size_t k = 0; k < n; k++) {
                uint16_t b_ik = b[i * n + k] & qmask;
                uint16_t s_kj = sT[j * n + k] & qmask;
                acc += (uint32_t)b_ik * s_kj;
            }
            out[i * nbar + j] = (uint16_t)(acc & qmask);
        }
    }
}

void FrodoCommonAdd(uint16_t* out, const uint16_t* a, const uint16_t* b,
                      const FrodoKemParams* params)
{
    const size_t ncoeff = (size_t)params->nBar * params->nBar;
    const uint16_t qmask = (uint16_t)((1u << params->logq) - 1u);
    for (size_t t = 0; t < ncoeff; t++) {
        uint32_t sum = (uint32_t)(a[t] & qmask) + (uint32_t)(b[t] & qmask);
        out[t] = (uint16_t)(sum & qmask);
    }
}

void FrodoCommonSub(uint16_t* out, const uint16_t* a, const uint16_t* b,
                      const FrodoKemParams* params)
{
    const size_t ncoeff = (size_t)params->nBar * params->nBar;
    const uint16_t qmask = (uint16_t)((1u << params->logq) - 1u);
    for (size_t t = 0; t < ncoeff; t++) {
        uint32_t diff = (uint32_t)(a[t] & qmask) - (uint32_t)(b[t] & qmask);
        out[t] = (uint16_t)(diff & qmask); // q=2^k 时，& qmask 等价于 mod q
    }
}

void FrodoCommonKeyEncode(uint16_t* out,
                             const uint16_t* in,
                             const FrodoKemParams* params)
{
    const uint8_t* mu = (const uint8_t*)in;
    const size_t total = (size_t)params->nBar * params->nBar;
    const unsigned b = (unsigned)params->extractedBits;
    const uint16_t factor = (uint16_t)(1u << (params->logq - b));

    size_t bitpos = 0;
    for (size_t t = 0; t < total; t++) {
        uint32_t x = 0;
        for (unsigned r = 0; r < b; r++, bitpos++) {
            uint8_t byte = mu[bitpos >> 3];
            unsigned s = bitpos & 7;
            x |= ((byte >> s) & 1u) << r;
        }
        out[t] = (uint16_t)(x * factor);
    }
}

void FrodoCommonKeyDecode(uint16_t* out,
                             const uint16_t* in,
                             const FrodoKemParams* params)
{
    uint8_t* mu = (uint8_t*)out;

    const size_t total = (size_t)params->nBar * params->nBar;
    const unsigned b = (unsigned)params->extractedBits;
    const unsigned s = (unsigned)(params->logq - b);
    const uint16_t round = (uint16_t)(1u << (s - 1));
    const uint16_t mask = (uint16_t)((1u << b) - 1u);

    memset(mu, 0, params->lenMu);

    size_t bitpos = 0;
    for (size_t t = 0; t < total; t++) {
        uint16_t v = in[t];
        uint16_t piece = (uint16_t)(((uint32_t)v + round) >> s) & mask;

        for (unsigned r = 0; r < b; r++, bitpos++) {
            if ((piece >> r) & 1u) {
                mu[bitpos >> 3] |= (uint8_t)(1u << (bitpos & 7));
            }
        }
    }
}
