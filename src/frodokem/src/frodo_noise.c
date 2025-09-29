#include "frodo_local.h"
#include <string.h>

void FrodoCommonSampleN(uint16_t* samples, const size_t n, const uint16_t* cdf_table, const size_t cdf_len)
{
    for (size_t i = 0; i < n; ++i) {
        const uint16_t prnd = samples[i] >> 1;
        const uint16_t sign = samples[i] & 0x1;

        uint16_t magnitude = 0;

        for (size_t j = 0; j < cdf_len - 1; ++j) {
            magnitude += (uint16_t)(cdf_table[j] - prnd) >> 15;
        }

        samples[i] = (uint16_t)((-sign) ^ magnitude) + sign;
    }
}

static inline int use_shake256(const FrodoKemParams* p)
{
    return (p->n > 640);
}

void FrodoExpandShakeDs(uint8_t* out, size_t outlen,
                        uint8_t ds, const uint8_t* seed, size_t seedlen,
                        const FrodoKemParams* params)
{
    uint8_t in[1 + 64];
    in[0] = ds;
    for (int i = 0; i < seedlen; i++) {
        in[1 + i] = seed[i];
    }
    if (use_shake256(params)) {
        FrodoKemShake256(out, outlen, in, 1 + seedlen);
    } else {
        FrodoKemShake128(out, outlen, in, 1 + seedlen);
    }
}

void FrodoCommonSampleNFromR(uint16_t* samples, const size_t n,
                             const uint16_t* cdf_table, const size_t cdf_len,
                             const uint8_t* rbytes)
{
    if (cdf_len ==13) {
        FrodoCommonSampleNFromR128(samples, n, cdf_table, rbytes);
    }  else if  (cdf_len == 11) {
        FrodoCommonSampleNFromR192(samples, n, cdf_table, rbytes);
    }  else if  (cdf_len == 7) {
        FrodoCommonSampleNFromR256(samples, n, cdf_table, rbytes);
    }
}

void FrodoCommonSampleNFromR128(uint16_t* samples, const size_t n,
                             const uint16_t* cdf_table, const uint8_t* rbytes)
{
    for (size_t i = 0; i < n; i++) {
        uint16_t r = (uint16_t)rbytes[2 * i] | ((uint16_t)rbytes[2 * i + 1] << 8);

        uint16_t prnd = r >> 1;
        uint16_t sign = r & 1;

        uint16_t t = 0;
        for (size_t j = 0; j < 12; j++) {
            t += (uint16_t)(cdf_table[j] - prnd) >> 15;
        }

        samples[i] = ((uint16_t)(-sign) ^ t) + sign;
    }
}

void FrodoCommonSampleNFromR192(uint16_t* samples, const size_t n,
                             const uint16_t* cdf_table, const uint8_t* rbytes)
{
    for (size_t i = 0; i < n; i++) {
        uint16_t r = (uint16_t)rbytes[2 * i] | ((uint16_t)rbytes[2 * i + 1] << 8);

        uint16_t prnd = r >> 1;
        uint16_t sign = r & 1;

        uint16_t t = 0;
        for (size_t j = 0; j < 10; j++) {
            t += (uint16_t)(cdf_table[j] - prnd) >> 15;
        }

        samples[i] = ((uint16_t)(-sign) ^ t) + sign;
    }
}

void FrodoCommonSampleNFromR256(uint16_t* samples, const size_t n,
                             const uint16_t* cdf_table, const uint8_t* rbytes)
{
    for (size_t i = 0; i < n; i++) {
        uint16_t r = (uint16_t)rbytes[2 * i] | ((uint16_t)rbytes[2 * i + 1] << 8);

        uint16_t prnd = r >> 1;
        uint16_t sign = r & 1;

        uint16_t t = 0;
        for (size_t j = 0; j < 6; j++) {
            t += (uint16_t)(cdf_table[j] - prnd) >> 15;
        }

        samples[i] = ((uint16_t)(-sign) ^ t) + sign;
    }
}
