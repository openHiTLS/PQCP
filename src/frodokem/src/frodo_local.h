#ifndef FRODO_INTERNAL_H
#define FRODO_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

#include "internal/frodo_params.h"

int32_t FrodoKemShake128(uint8_t* output, size_t outlen, const uint8_t* input, size_t inlen);
int32_t FrodoKemShake256(uint8_t* output, size_t outlen, const uint8_t* input, size_t inlen);
int32_t FrodoKemRandombytes(uint8_t* buffer, size_t len);

void FrodoExpandShakeDs(uint8_t* out, size_t outlen,
                        uint8_t ds, const uint8_t* seed, size_t seedlen,
                        const FrodoKemParams* params);

int FrodoPkeKeygenSeeded(const FrodoKemParams* params,
                         uint8_t* pk,
                         uint16_t* matrixSTranspose,
                         const uint8_t* seedA,
                         const uint8_t* seedSE);

// =================================================================================
// Function Prototypes from noise.c
// =================================================================================

void FrodoCommonSampleN(uint16_t* samples, const size_t n, const uint16_t* cdf_table, const size_t cdf_len);
void FrodoCommonSampleNFromR(uint16_t* samples, size_t n, const uint16_t* cdf_table, size_t cdf_len,
                             const uint8_t* rbytes);
void FrodoCommonSampleNFromR128(uint16_t* samples, size_t n, const uint16_t* cdf_table, const uint8_t* rbytes);
void FrodoCommonSampleNFromR192(uint16_t* samples, size_t n, const uint16_t* cdf_table, const uint8_t* rbytes);
void FrodoCommonSampleNFromR256(uint16_t* samples, size_t n, const uint16_t* cdf_table, const uint8_t* rbytes);

// =================================================================================
// Function Prototypes from util.c
// =================================================================================

void FrodoCommonPack(uint8_t* out, const size_t out_len, const uint16_t* in, const size_t in_len, const uint8_t lsb);

void FrodoCommonUnpack(uint16_t* out, const size_t out_len, const uint8_t* in, const size_t in_len,
                       const uint8_t lsb);

int8_t FrodoCommonCtVerify(const uint16_t* a, const uint16_t* b, size_t len);

void FrodoCommonCtSelect(uint8_t* r, const uint8_t* a, const uint8_t* b, size_t len, int8_t selector);

// =================================================================================
// Function Prototypes from core_*.c (Matrix Arithmetic)
// =================================================================================

int FrodoCommonMulAddAsPlusEPortable(uint16_t* out, const uint16_t* s, const uint8_t* seed_A,
                                     const FrodoKemParams* params);

int FrodoCommonMulAddAsPlusEAvx2(uint16_t* b, const uint16_t* s, const uint16_t* e, const uint8_t* seed_A);

int FrodoCommonMulAddSaPlusEPortable(uint16_t* b, const uint16_t* s, const uint16_t* e, const uint8_t* seedA,
                                     const FrodoKemParams* params);
int FrodoCommonMulAddSaPlusEAvx2(uint16_t* b, const uint16_t* s, const uint16_t* e, const uint8_t* seed_A);

int FrodoCommonMulAddSbPlusEPortable(
    uint16_t* V0,
    const uint16_t* STp,
    const uint16_t* B,
    const uint16_t* Epp,
    const FrodoKemParams* params
);

void FrodoCommonMulBs(uint16_t* out, const uint16_t* b, const uint16_t* s, const FrodoKemParams* params);
void FrodoCommonMulBsUsingSt(uint16_t* out, const uint16_t* b, const uint16_t* s, const FrodoKemParams* params);

// =================================================================================
// Function Prototypes from core_*.c (Small Matrix and Key Arithmetic)
// =================================================================================

void FrodoCommonAdd(uint16_t* out, const uint16_t* a, const uint16_t* b, const FrodoKemParams* params);
void FrodoCommonSub(uint16_t* out, const uint16_t* a, const uint16_t* b, const FrodoKemParams* params);
void FrodoCommonKeyEncode(uint16_t* out, const uint16_t* in, const FrodoKemParams* params);
void FrodoCommonKeyDecode(uint16_t* out, const uint16_t* in, const FrodoKemParams* params);

// =================================================================================
// Function Prototypes from frodokem_pke.c
// =================================================================================

int FrodoPkeKeygen(const FrodoKemParams* params, uint8_t* pk, uint8_t* pke_sk);
int FrodoPkeEncrypt(const FrodoKemParams* params, const uint8_t* pk, const uint8_t* mu, const uint8_t* seedSE,
                    uint8_t* ct);
int FrodoPkeDecrypt(const FrodoKemParams* params, const uint8_t* pke_sk, const uint8_t* ct, uint8_t* mu);

int FrodoKemKeypairInternal(const uint8_t* rnd, const FrodoKemParams* params, uint8_t* pk, uint8_t* sk, size_t lenSk);
int FrodoKemEncapsInternal(const uint8_t* mu, const FrodoKemParams* params, uint8_t* ct, uint8_t* ss,
                           const uint8_t* pk);

// =================================================================================
// Cross-platform Macros (Endianness and Alignment)
// =================================================================================

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#define LE_TO_UINT16(n) (n)
#define UINT16_TO_LE(n) (n)
#elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define LE_TO_UINT16(n) __builtin_bswap16(n)
#define UINT16_TO_LE(n) __builtin_bswap16(n)
#else
static inline uint16_t le_to_uint16(uint16_t n)
{
    uint8_t bytes[2];
    memcpy(bytes, &n, 2);
    return (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
}

static inline uint16_t uint16_to_le(uint16_t n)
{
    uint8_t bytes[2];
    bytes[0] = n & 0xFF;
    bytes[1] = (n >> 8) & 0xFF;
    uint16_t result;
    memcpy(&result, bytes, 2);
    return result;
}

#define LE_TO_UINT16(n) le_to_uint16(n)
#define UINT16_TO_LE(n) uint16_to_le(n)
#endif


#if defined(_MSC_VER)
#define ALIGN_HEADER(N) __declspec(align(N))
#define ALIGN_FOOTER(N)
#elif defined(__GNUC__) || defined(__clang__)
#define ALIGN_HEADER(N)
#define ALIGN_FOOTER(N) __attribute__((aligned(N)))
#else
#define ALIGN_HEADER(N)
#define ALIGN_FOOTER(N)
#endif

#ifdef __cplusplus
}
#endif

#endif
