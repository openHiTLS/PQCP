#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "pqcp_err.h"
#include "crypt_eal_md.h"
#include "bsl_errno.h"
#include "frodo_local.h"

void FrodoCommonPack(uint8_t* out, const size_t out_len, const uint16_t* in, const size_t in_len, const uint8_t lsb)
{
    if (lsb == 16) {
        for (size_t i = 0; i < in_len; i++) {
            out[i * 2 + 0] = in[i] >> 8;
            out[i * 2 + 1] = in[i] & 0xFF;
        }
        return;
    }

    // lsb = 15
    for (size_t i = 0; i < in_len; i += 8) {
        uint16_t a0 = in[0] & 0x7FFF;
        uint16_t a1 = in[1] & 0x7FFF;
        uint16_t a2 = in[2] & 0x7FFF;
        uint16_t a3 = in[3] & 0x7FFF;
        uint16_t a4 = in[4] & 0x7FFF;
        uint16_t a5 = in[5] & 0x7FFF;
        uint16_t a6 = in[6] & 0x7FFF;
        uint16_t a7 = in[7] & 0x7FFF;

        a0 = (a0 << 1) | (a1 >> 14);
        a1 = (a1 << 2) | (a2 >> 13);
        a2 = (a2 << 3) | (a3 >> 12);
        a3 = (a3 << 4) | (a4 >> 11);
        a4 = (a4 << 5) | (a5 >> 10);
        a5 = (a5 << 6) | (a6 >> 9);
        a6 = (a6 << 7) | (a7 >> 8);

        out[0] = a0 >> 8;
        out[1] = a0 & 0xFF;
        out[2] = a1 >> 8;
        out[3] = a1 & 0xFF;
        out[4] = a2 >> 8;
        out[5] = a2 & 0xFF;
        out[6] = a3 >> 8;
        out[7] = a3 & 0xFF;
        out[8] = a4 >> 8;
        out[9] = a4 & 0xFF;
        out[10] = a5 >> 8;
        out[11] = a5 & 0xFF;
        out[12] = a6 >> 8;
        out[13] = a6 & 0xFF;
        out[14] = a7;

        in += 8;
        out += 15;
    }
}

void FrodoCommonUnpack(uint16_t* out, const size_t out_len, const uint8_t* in, const size_t in_len, const uint8_t lsb)
{
    if (lsb == 16) {
        for (size_t i = 0; i < out_len; i++) {
            out[i] = (in[i * 2] << 8) | in[i * 2 + 1];
        }
        return;
    }

    // lsb = 15
    for (size_t i = 0; i < in_len; i += 15) {
        out[0] = (in[0] << 7) | (in[1] >> 1);
        out[1] = ((in[1] & 0x01) << 14) | (in[2] << 6) | (in[3] >> 2);
        out[2] = ((in[3] & 0x03) << 13) | (in[4] << 5) | (in[5] >> 3);
        out[3] = ((in[5] & 0x07) << 12) | (in[6] << 4) | (in[7] >> 4);
        out[4] = ((in[7] & 0x0F) << 11) | (in[8] << 3) | (in[9] >> 5);
        out[5] = ((in[9] & 0x1F) << 10) | (in[10] << 2) | (in[11] >> 6);
        out[6] = ((in[11] & 0x3F) << 9) | (in[12] << 1) | (in[13] >> 7);
        out[7] = ((in[13] & 0x7F) << 8) | in[14];

        in += 15;
        out += 8;
    }
}

int8_t FrodoCommonCtVerify(const uint16_t* a, const uint16_t* b, size_t len)
{
    uint16_t diff_accumulator = 0;

    for (size_t i = 0; i < len; i++) {
        diff_accumulator |= a[i] ^ b[i];
    }

    return (int8_t)((-(int16_t)(diff_accumulator >> 1) | -(int16_t)(diff_accumulator & 1)) >> 15);
}

void FrodoCommonCtSelect(uint8_t* r, const uint8_t* a, const uint8_t* b, size_t len, int8_t selector)
{
    for (size_t i = 0; i < len; i++) {
        r[i] = (~(uint8_t)selector & a[i]) | ((uint8_t)selector & b[i]);
    }
}

int32_t FrodoKemMdFunc(const CRYPT_MD_AlgId id, const uint8_t* input1, const uint32_t inLen1, const uint8_t* input2,
                       const uint32_t inLen2, uint8_t* output, uint32_t* outLen)
{
    CRYPT_EAL_MdCTX* MdCtx = CRYPT_EAL_MdNewCtx(id);
    if (MdCtx == NULL) {
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_MdInit(MdCtx);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }
    ret = CRYPT_EAL_MdUpdate(MdCtx, input1, inLen1);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }
    if (input2 != NULL) {
        ret = CRYPT_EAL_MdUpdate(MdCtx, input2, inLen2);
        if (ret != PQCP_SUCCESS) {
            goto EXIT;
        }
    }
    ret = CRYPT_EAL_MdFinal(MdCtx, output, outLen);
EXIT:
    CRYPT_EAL_MdFreeCtx(MdCtx);
    return ret;
}

int32_t FrodoKemShake128(uint8_t* output, size_t outlen, const uint8_t* input, size_t inlen)
{
    uint32_t len = outlen;
    return FrodoKemMdFunc(CRYPT_MD_SHAKE128, input, inlen, NULL, 0, output, &len);
}

int32_t FrodoKemShake256(uint8_t* output, size_t outlen, const uint8_t* input, size_t inlen)
{
    uint32_t len = outlen;
    return FrodoKemMdFunc(CRYPT_MD_SHAKE256, input, inlen, NULL, 0, output, &len);
}
