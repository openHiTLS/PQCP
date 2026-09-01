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

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_NEV

#include "nev_local.h"
#ifdef HITLS_CRYPTO_NEV_SVE2
#include "nev_sve2.h"
#endif

/*
 * ARMv8 NEON backend for the NEV packing / message codecs: link-time
 * replacement for nev_pack.c.  Whole 16-coefficient (q = 3329 / 1409) and
 * 20-coefficient (q = 769) strips run in the NEON kernels of
 * asm/nev_pack_armv8.S; the q = 769 remainder groups (n mod 20) and the
 * 10-bit coefficient tail (n mod 5) reuse the scalar codec below, copied
 * verbatim from nev_pack.c.
 *
 * Packing is a packed-interface boundary of the backend contract, so every
 * path here is BIT-EXACT against nev_pack.c: decoders for every byte input
 * (malformed ciphertexts included), encoders / ToMsg / Compress for every
 * int16 coefficient (see the kernel headers for the per-op arguments).
 */

/* NEON kernels (asm/nev_pack_armv8.S). */
void NEV_ToBytes3329Asm(uint8_t *r, const int16_t *a, uint64_t n);
void NEV_FromBytes3329Asm(int16_t *r, const uint8_t *a, uint64_t n);
void NEV_ToBytes1409Asm(uint8_t *r, const int16_t *a, uint64_t n);
void NEV_FromBytes1409Asm(int16_t *r, const uint8_t *a, uint64_t n);
void NEV_ToBytes769Asm(uint8_t *r, const int16_t *a, uint64_t g4);
void NEV_FromBytes769Asm(int16_t *r, const uint8_t *a, uint64_t x2Groups, uint64_t singleGroups);
void NEV_ToMsgAsm(uint8_t *msg, const int16_t *a, uint64_t blocks, uint64_t dim, uint64_t q);
void NEV_CompressAsm(uint8_t *c, const int16_t *a, uint64_t n);
void NEV_DecompressAsm(int16_t *r, const uint8_t *c, uint64_t n, uint64_t q);
#ifdef HITLS_CRYPTO_NEV_SVE2
void NEV_ToBytes769Sve2(uint8_t *r, const int16_t *a, uint64_t records);
void NEV_FromBytes769Sve2(int16_t *r, const uint8_t *a, uint64_t records);
void NEV_ToBytes1409Sve2(uint8_t *r, const int16_t *a, uint64_t n);
void NEV_FromBytes1409Sve2(int16_t *r, const uint8_t *a, uint64_t n);
void NEV_ToBytes3329Sve2(uint8_t *r, const int16_t *a, uint64_t n);
void NEV_FromBytes3329Sve2(int16_t *r, const uint8_t *a, uint64_t n);
void NEV_CompressSve2(uint8_t *c, const int16_t *a, uint64_t n);
void NEV_MontCompress769Sve2(uint8_t *c, const int16_t *a, uint64_t n);
void NEV_DecompressSve2(int16_t *r, const uint8_t *c, uint64_t n, uint64_t q);
void NEV_ToMsgSve2(uint8_t *msg, const int16_t *a, uint64_t blocks, uint64_t dim, uint64_t q);
#endif

// ------------------------------------------------------------------
// q = 769 scalar codec (verbatim from nev_pack.c) for the n mod 20
// remainder groups and the 10-bit tail coefficients.

static inline void Encode5(uint8_t *buf, const int16_t x[5])
{
    int32_t i;
    uint32_t wl, wh;
    uint32_t t;

    wl = (uint16_t)x[0] & 0x07;
    for (i = 1; i < 5; i++) {
        wl |= (uint32_t)((uint16_t)x[i] & 0x07) << (3 * i);
    }

    wl <<= 1;
    wh = (uint16_t)x[4] >> 3;
    for (i = 3; i > 0; i--) {
        wh = (wh * 97) + ((uint16_t)x[i] >> 3);
    }

    t = wh * 48;
    wl |= t >> 31;
    t <<= 1;
    wh = wh + ((uint16_t)x[0] >> 3);
    wh = t + wh;
    wl |= ((t & ~wh) >> 31);

    buf[0] = (uint8_t)wl;
    buf[1] = (uint8_t)(wl >> 8);
    buf[2] = (uint8_t)wh;
    for (i = 3; i < 6; i++) {
        wh = wh >> 8;
        buf[i] = (uint8_t)wh;
    }
}

static inline void Decode5(int16_t *x, const uint8_t *buf)
{
    // See nev_pack.c for the constant derivations.
    uint32_t wl, wh, z;
    int32_t i;

    wl = ((uint32_t)buf[1] << 8) | buf[0];
    wh = buf[5];
    for (i = 4; i > 1; i--) {
        wh = (wh << 8) | (uint32_t)buf[i];
    }

    z = (((wl & 0x01) << 13) | (wh >> 19)) * 3;
    z += wh & 0x7FFFF;
    wl >>= 1;

    z = (z >> 9) * 27 + (z & 0x1FF);
    z -= ((z * 43241) >> 22) * 97;

    x[0] = (int16_t)(uint16_t)((z << 3) + (wl & 0x07));
    wl >>= 3;

    wh -= z;
    wh = wh * 1594008481u;

    z = (wh >> 19) * 3 + (wh & 0x7FFFF);
    z = (z >> 9) * 27 + (z & 0x1FF);
    z -= ((z * 43241) >> 22) * 97;

    x[1] = (int16_t)(uint16_t)((z << 3) + (wl & 0x07));
    wl >>= 3;

    wh -= z;
    wh = wh * 1594008481u;

    z = (wh >> 9) * 27 + (wh & 0x1FF);
    z -= ((z * 43241) >> 22) * 97;

    x[2] = (int16_t)(uint16_t)((z << 3) + (wl & 0x07));
    wl >>= 3;

    wh -= z;
    z = wh * 1594008481u;

    wh = (z * 43241) >> 22;
    z -= wh * 97;

    x[3] = (int16_t)(uint16_t)((z << 3) + (wl & 0x07));
    wl >>= 3;

    x[4] = (int16_t)(uint16_t)((wh << 3) + wl);
}

// n mod 5 = 2 (n = 512), 4 (n = 1024) or 3 (n = 2048) tail coefficients, 10 bits each.
static void PolyToBytes769(uint8_t *r, const NEV_Poly *a, uint32_t n)
{
    uint32_t i;
    uint32_t g4 = (n / 5) / 4;
    uint16_t t[4];

    /* The 256-bit SVE2 gather/scatter codec spends most of its time retiring
     * six sparse byte stores per eight records.  The AdvSIMD kernel packs two
     * independent four-record chains and emits each record group through
     * contiguous 16+8-byte stores, which is a better fit for this 5-to-6-byte
     * mixed-radix layout even in an SVE2 build. */
    NEV_ToBytes769Asm(r, a->coeffs, g4);
    for (i = 4 * g4; i < n / 5; i++) {
        Encode5(&r[6 * i], &a->coeffs[5 * i]);
    }

    t[0] = (uint16_t)a->coeffs[5 * i];
    t[1] = (uint16_t)a->coeffs[5 * i + 1];

    if (n == 512) {
        r[6 * i] = (uint8_t)t[0];
        r[6 * i + 1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
        r[6 * i + 2] = (uint8_t)(t[1] >> 6);
    } else if (n == 1024) {
        t[2] = (uint16_t)a->coeffs[5 * i + 2];
        t[3] = (uint16_t)a->coeffs[5 * i + 3];

        r[6 * i] = (uint8_t)t[0];
        r[6 * i + 1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
        r[6 * i + 2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
        r[6 * i + 3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
        r[6 * i + 4] = (uint8_t)(t[3] >> 2);
    } else { // n == 2048
        t[2] = (uint16_t)a->coeffs[5 * i + 2];

        r[6 * i] = (uint8_t)t[0];
        r[6 * i + 1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
        r[6 * i + 2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
        r[6 * i + 3] = (uint8_t)(t[2] >> 4);
    }
}

static void PolyFromBytes769(NEV_Poly *r, const uint8_t *a, uint32_t n)
{
    uint32_t i;
    uint32_t records = n / 5;
    uint32_t x2Groups;
    uint32_t singleGroups;

#ifdef HITLS_CRYPTO_NEV_SVE2
    if (NEV_Sve2Enabled() != 0) {
        NEV_FromBytes769Sve2(r->coeffs, a, records);
        i = records;
    } else
#endif
    {
#ifdef HITLS_BIG_ENDIAN
        /* The optimized ld3/st4 halfword kernel is little-endian only. */
        x2Groups = 0;
        singleGroups = 0;
#else
        x2Groups = records / 8;
        singleGroups = (records - 8 * x2Groups) / 4;
#endif
        NEV_FromBytes769Asm(r->coeffs, a, x2Groups, singleGroups);
        for (i = 8 * x2Groups + 4 * singleGroups; i < records; i++) {
            Decode5(&r->coeffs[5 * i], &a[6 * i]);
        }
    }

    r->coeffs[5 * i] = (int16_t)((uint16_t)a[6 * i] | (((uint16_t)a[6 * i + 1] & 0x03) << 8));
    r->coeffs[5 * i + 1] = (int16_t)(((uint16_t)a[6 * i + 1] >> 2) | (((uint16_t)a[6 * i + 2] & 0x0f) << 6));

    if (n == 1024) {
        r->coeffs[5 * i + 2] = (int16_t)(((uint16_t)a[6 * i + 2] >> 4) | (((uint16_t)a[6 * i + 3] & 0x3f) << 4));
        r->coeffs[5 * i + 3] = (int16_t)(((uint16_t)a[6 * i + 3] >> 6) | ((uint16_t)a[6 * i + 4] << 2));
    } else if (n == 2048) {
        r->coeffs[5 * i + 2] = (int16_t)(((uint16_t)a[6 * i + 2] >> 4) | (((uint16_t)a[6 * i + 3] & 0x3f) << 4));
    }
}

// ------------------------------------------------------------------

void NEV_PolyToBytes(uint8_t *r, const NEV_Poly *a, const CRYPT_NevInfo *info)
{
    uint32_t n = info->n;

    if (info->q == 769) {
        PolyToBytes769(r, a, n);
    } else if (info->q == 1409) {
#ifdef HITLS_CRYPTO_NEV_SVE2
        if (NEV_Sve2Enabled() != 0) {
            NEV_ToBytes1409Sve2(r, a->coeffs, n);
            return;
        }
#endif
        NEV_ToBytes1409Asm(r, a->coeffs, n);
    } else { // q == 3329
#ifdef HITLS_CRYPTO_NEV_SVE2
        if (NEV_Sve2Enabled() != 0) {
            NEV_ToBytes3329Sve2(r, a->coeffs, n);
            return;
        }
#endif
        NEV_ToBytes3329Asm(r, a->coeffs, n);
    }
}

void NEV_PolyFromBytes(NEV_Poly *r, const uint8_t *a, const CRYPT_NevInfo *info)
{
    uint32_t n = info->n;

    if (info->q == 769) {
        PolyFromBytes769(r, a, n);
    } else if (info->q == 1409) {
#ifdef HITLS_CRYPTO_NEV_SVE2
        if (NEV_Sve2Enabled() != 0) {
            NEV_FromBytes1409Sve2(r->coeffs, a, n);
            return;
        }
#endif
        NEV_FromBytes1409Asm(r->coeffs, a, n);
    } else { // q == 3329
#ifdef HITLS_CRYPTO_NEV_SVE2
        if (NEV_Sve2Enabled() != 0) {
            NEV_FromBytes3329Sve2(r->coeffs, a, n);
            return;
        }
#endif
        NEV_FromBytes3329Asm(r->coeffs, a, n);
    }
}

void NEV_PolyCompress(uint8_t *c, const NEV_Poly *x, const CRYPT_NevInfo *info)
{
#ifdef HITLS_CRYPTO_NEV_SVE2
    if (NEV_Sve2Enabled() != 0) {
        NEV_CompressSve2(c, x->coeffs, info->n);
        return;
    }
#endif
    NEV_CompressAsm(c, x->coeffs, info->n);
}

void NEV_PolyMontCompress(uint8_t *c, NEV_Poly *x, const CRYPT_NevInfo *info)
{
#ifdef HITLS_CRYPTO_NEV_SVE2
    if (NEV_Sve2Enabled() != 0) {
        /* Compression is used only by the q=769 parameter family. */
        NEV_MontCompress769Sve2(c, x->coeffs, info->n);
        return;
    }
#endif
    NEV_PolyGetMontgomeryCaddq(x, info);
    NEV_PolyCompress(c, x, info);
}

void NEV_PolyDecompress(NEV_Poly *x, const uint8_t *c, const CRYPT_NevInfo *info)
{
#ifdef HITLS_CRYPTO_NEV_SVE2
    if (NEV_Sve2Enabled() != 0) {
        NEV_DecompressSve2(x->coeffs, c, info->n, info->q);
        return;
    }
#endif
    NEV_DecompressAsm(x->coeffs, c, info->n, info->q);
}

void NEV_PolyToMsg(uint8_t *msg, const NEV_Poly *r, const CRYPT_NevInfo *info)
{
    uint32_t dim = info->nttDim;

    // blocks = seedLen / (dim / 32) = n / dim: every block of the polynomial
    // carries dim / 32 message bytes (see nev_pack.c).
#ifdef HITLS_CRYPTO_NEV_SVE2
    if (NEV_Sve2Enabled() != 0) {
        NEV_ToMsgSve2(msg, r->coeffs, info->seedLen / (dim / 32), dim, info->q);
        return;
    }
#endif
    NEV_ToMsgAsm(msg, r->coeffs, info->seedLen / (dim / 32), dim, info->q);
}

#endif // HITLS_CRYPTO_NEV
