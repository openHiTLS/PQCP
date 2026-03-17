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
#ifdef PQCP_POLARLAC
#include <stdint.h>

#include "crypt_eal_md.h"
#include "crypt_types.h"
#include "pqcp_err.h"
#include "polarlac_local.h"
#include "securec.h"

typedef struct EAL_MdMethod EAL_MdMethod;

#define SEC_128_VEC_NUM 512
#define SHAKE256_RATE   136
#define SHA3_256_RATE   136

#define SEC_LIGHT_HAMMING_WEIGHT_UPPER 146
#define SEC_LIGHT_HAMMING_WEIGHT_LOWER 110

#define SEC_128_HAMMING_WEIGHT_UPPER 264
#define SEC_128_HAMMING_WEIGHT_LOWER 248

#define SEC_256_HAMMING_WEIGHT_UPPER 270
#define SEC_256_HAMMING_WEIGHT_LOWER 242

int32_t PQCP_POLAR_LAC_PseudoRandomBytes(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen)
{
    (void)libCtx;
    uint32_t len = outLen;
    return CRYPT_EAL_ProviderMd(libCtx, CRYPT_MD_SHAKE256, NULL, in, inLen, out, &len);
}

static int32_t Shake256Absorb(void *libCtx, const uint8_t *in, uint32_t inLen, void **mdCtx, EAL_MdMethod *method)
{
    (void)method;
    CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_SHAKE256, NULL);
    if (ctx == NULL) {
        return PQCP_MEM_ALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_MdInit(ctx);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }
    ret = CRYPT_EAL_MdUpdate(ctx, in, inLen);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }
    *mdCtx = ctx;
    return PQCP_SUCCESS;
EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
    return ret;
}

int32_t PQCP_POLAR_LAC_SamplePolyA(void *libCtx, uint8_t q, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen)
{
    int32_t ret;
    uint8_t buf[SHAKE256_RATE];
    uint32_t index = 0;
    void *mdCtx = NULL;
    RETURN_RET_IF(Shake256Absorb(libCtx, in, inLen, &mdCtx, NULL), ret);
    while (index < outLen) {
        ret = CRYPT_EAL_MdSqueeze(mdCtx, buf, SHAKE256_RATE);
        if (ret != PQCP_SUCCESS) {
            break;
        }
        for (uint32_t i = 0; i < SHAKE256_RATE && index < outLen; ++i) {
            if (buf[i] < q) {
                out[index] = buf[i];
                ++index;
            }
        }
    }
    CRYPT_EAL_MdFreeCtx(mdCtx);
    return ret;
}

static int32_t SampleOnce(uint8_t x, uint8_t q)
{
    uint8_t tmp = x & 7;
    uint8_t t0 = (!tmp) * (q - 1);
    uint8_t t1 = !(tmp - 1);
    return t0 | t1;
}
static int32_t SampleSparseTernaryVectorLight(void *mdCtx, uint8_t q, uint8_t *e, uint32_t eLen)
{
    int32_t ret;
    uint32_t len = eLen / 2;
    while (1) {
        RETURN_RET_IF(CRYPT_EAL_MdSqueeze(mdCtx, e + len, len), ret);
        for (uint32_t i = 0; i < len; ++i) {
            e[i * 2 + 0] = SampleOnce(e[i + len], q);
            e[i * 2 + 1] = SampleOnce(e[i + len] >> 4, q);
        }

        int32_t norm = 0;
        for (uint32_t i = 0; i < eLen; ++i) {
            norm += (e[i] == 0x01 || e[i] == q - 1);
        }
        if (norm >= SEC_LIGHT_HAMMING_WEIGHT_LOWER && norm <= SEC_LIGHT_HAMMING_WEIGHT_UPPER) {
            break;
        }
    }
    return PQCP_SUCCESS;
}
static int32_t SampleSparseTernaryVector128(void *mdCtx, uint8_t q, uint8_t *e, uint32_t eLen)
{
    (void)q;
    int32_t ret;
    uint8_t flag;
    uint8_t r[SHAKE256_RATE * 2], tmp[1024];
    uint16_t i;
    uint16_t j;
    uint16_t t;
    uint16_t mask;
    uint16_t norm;
    uint16_t e1;
    uint16_t e2;
    memset_s(e, eLen, 0, eLen);
    RETURN_RET_IF(CRYPT_EAL_MdSqueeze(mdCtx, r, 64), ret);
    t = 0;
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 64; j++) {
            tmp[i * 64 + j] = (r[t + j] & 1);
            r[t + j] = (r[t + j] >> 1);
        }
    }

    flag = 1;
    while (flag) {
        RETURN_RET_IF(CRYPT_EAL_MdSqueeze(mdCtx, r, 64), ret);
        if (ret != PQCP_SUCCESS) {
            return ret;
        }
        t = 0;
        for (i = 0; i < 8; i++) {
            for (j = 0; j < 64; j++) {
                tmp[i * 64 + j + 512] = (r[t + j] & 1);
                r[t + j] = (r[t + j] >> 1);
            }
        }
        flag = 0;
        norm = 0;
        for (i = 0; i < 512; i++) {
            e[i] = tmp[i] - tmp[i + 512];
            norm += (e[i] & e[i] & 1);
        }
        mask = (norm < 248);
        flag = (1 & (-mask)) | (flag & (~(-mask)));
        mask = (norm > 264);
        flag = (1 & (-mask)) | (flag & (~(-mask)));
    }

    for (i = 0; i < 512; i++) {
        mask = (e[i] > q_half);
        e1 = neg_one;
        e2 = e[i];
        e[i] = (e1 & (-mask)) | (e2 & (~(-mask)));
    }
    return PQCP_SUCCESS;
}

static int32_t SampleSparseTernaryVector256(void *mdCtx, uint8_t q, uint8_t *e, uint32_t eLen)
{
    (void)q;
    int32_t ret;
    uint8_t flag;
    uint8_t r[SHAKE256_RATE * 2], tmp[2048];
    uint16_t i;
    uint16_t j;
    uint16_t t;
    uint16_t mask;
    uint16_t norm;
    uint16_t e1;
    uint16_t e2;
    memset_s(e, eLen, 0, eLen);
    RETURN_RET_IF(CRYPT_EAL_MdSqueeze(mdCtx, r, SHAKE256_RATE * 2), ret);
    t = 0;
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 128 * 2; j++) {
            tmp[i * (128 * 2) + j] = (r[t + j] & 1);
            r[t + j] = (r[t + j] >> 1);
        }
    }
    for (i = 0; i < 1024; i++) {
        tmp[i] = tmp[i] - tmp[i + 1024];
    }

    flag = 1;
    while (flag) {
        RETURN_RET_IF(CRYPT_EAL_MdSqueeze(mdCtx, r, SHAKE256_RATE), ret);
        t = 0;
        for (i = 0; i < 8; i++) {
            for (j = 0; j < 128; j++) {
                tmp[i * 128 + j + 1024] = (r[t + j] & 1);
                r[t + j] = (r[t + j] >> 1);
            }
        }
        flag = 0;
        norm = 0;
        for (i = 0; i < 1024; i++) {
            e[i] = tmp[i] * tmp[i + 1024];
            norm += (e[i] & e[i] & 1);
        }
        mask = (norm < 242);
        flag = (1 & (-mask)) | (flag & (~(-mask)));
        mask = (norm > 270);
        flag = (1 & (-mask)) | (flag & (~(-mask)));
    }

    for (i = 0; i < 1024; i++) {
        mask = (e[i] > q_half);
        e1 = neg_one;
        e2 = e[i];
        e[i] = (e1 & (-mask)) | (e2 & (~(-mask)));
    }
    return PQCP_SUCCESS;
}

int32_t PQCP_POLAR_LAC_SampleSparseTernaryVector(void *libCtx, uint8_t q, const uint8_t *in, uint32_t inLen, uint8_t *e,
                                            uint32_t eLen, int32_t algId)
{
    void *mdCtx = NULL;
    int32_t ret = Shake256Absorb(libCtx, in, inLen, &mdCtx, NULL);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    switch (algId) {
        case PQCP_POLAR_LAC_LIGHT:
            ret = SampleSparseTernaryVectorLight(mdCtx, q, e, eLen);
            break;
        case PQCP_POLAR_LAC_128:
            ret = SampleSparseTernaryVector128(mdCtx, q, e, eLen);
            break;
        case PQCP_POLAR_LAC_256:
            ret = SampleSparseTernaryVector256(mdCtx, q, e, eLen);
            break;
        default:
            break;
    }
    CRYPT_EAL_MdFreeCtx(mdCtx);
    return ret;
}
#endif // PQCP_POLARLAC