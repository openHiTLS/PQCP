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

#include "crypt_eal_md.h"
#include "crypt_eal_rand.h"
#include "polarlac_local.h"
#include "pqcp_err.h"
#include "securec.h"
#include <stdio.h>
#include <string.h>

#define RETURN_RET_IF(FUNC, RET) \
    do {                         \
        RET = FUNC;              \
        if (RET != 0) {          \
            return RET;          \
        }                        \
    } while (0)

static int32_t SHA3_256(const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen)
{
    if (outLen < 32) {
        return PQCP_POLAR_LAC_LEN_NOT_ENOUGH;
    }
    uint32_t len = outLen;
    return CRYPT_EAL_Md(CRYPT_MD_SHA3_256, in, inLen, out, &len);
}

static int32_t PolarLacKemEncFo(const CRYPT_POLAR_LAC_Ctx *ctx, uint8_t *k, uint8_t *c)
{
    const uint8_t *pk = ctx->pk;
    uint32_t msgLen = ctx->info->msgLen;
    uint32_t seedLen = ctx->info->seedLen;
    uint32_t pkLen = ctx->info->pkLen;
    uint32_t ctLen = ctx->info->ctLen;
    uint8_t buf[msgLen + ctLen], seed[seedLen], seed_buf[msgLen + pkLen];
    unsigned long long cLen;

    // generate random message m, stored in buf
    int32_t ret = CRYPT_EAL_Randbytes(buf, msgLen);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    // compute seed=hash(m|pk), add pk for multi key attack protection
    memcpy_s(seed_buf, msgLen + pkLen, buf, msgLen);
    memcpy_s(seed_buf + msgLen, pkLen, pk, pkLen);
    ret = SHA3_256(seed_buf, msgLen + pkLen, seed, seedLen);
    if (ret != 0) {
        return ret;
    }
    // encrypt m with seed
    POLAR_LAC_PkeEncrypt(ctx, buf, msgLen, c, &cLen, seed);

    // compute k=hash(m|c)
    memcpy_s(buf + msgLen, ctLen, c, ctLen);
    return SHA3_256(buf, msgLen + ctLen, k, 32);
}

// decrypt of fo mode
static int32_t PolarLacKemDecFo(const CRYPT_POLAR_LAC_Ctx *ctx, const uint8_t *c, uint8_t *k)
{
    uint8_t *sk = ctx->sk;
    uint8_t *pk = ctx->sk + ctx->info->skLen - ctx->info->pkLen;
    uint32_t msgLen = ctx->info->msgLen;
    uint32_t seedLen = ctx->info->seedLen;
    uint32_t pkLen = ctx->info->pkLen;
    uint32_t ctLen = ctx->info->ctLen;
    uint32_t skLen = ctx->info->skLen;

    uint8_t buf[msgLen + ctLen], seed[seedLen], seed_buf[msgLen + pkLen];
    unsigned long long mLen;
    unsigned long long cLen;
    uint8_t verifyCt[ctLen]; // re-encrypt ciphertext for verification

    // compute m from c
    POLAR_LAC_PkeDecrypt(ctx, c, ctLen, buf, &mLen);
    // compute k=hash(m|c)
    memcpy_s(buf + msgLen, ctLen, c, ctLen);
    int32_t ret = SHA3_256(buf, msgLen + ctLen, k, 32);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    // re-encryption with seed=hash(m|pk), add pk for multi key attack protection
    memcpy_s(seed_buf, msgLen + pkLen, buf, msgLen);
    memcpy_s(seed_buf + msgLen, pkLen, pk, pkLen);
    ret = SHA3_256(seed_buf, msgLen + pkLen, seed, seedLen);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    POLAR_LAC_PkeEncrypt(ctx, buf, msgLen, verifyCt, &cLen, seed);

    // verify
    if (memcmp(c, verifyCt, ctLen) != 0) {
        // k=hash(hash(sk)|c)
        ret = SHA3_256(sk, skLen, buf, msgLen + ctLen);
        if (ret != PQCP_SUCCESS) {
            return ret;
        }
        memcpy_s(buf + msgLen, ctLen, c, ctLen);
        return SHA3_256(buf, msgLen + ctLen, k, 32);
    }

    return 0;
}

int32_t POLAR_LAC_EncapsInternal(const CRYPT_POLAR_LAC_Ctx *ctx, uint8_t *ct, uint8_t *ss)
{
    return PolarLacKemEncFo(ctx, ss, ct);
}

int32_t POLAR_LAC_DeapsInternal(const CRYPT_POLAR_LAC_Ctx *ctx, uint8_t *ss, const uint8_t *ct)
{
    return PolarLacKemDecFo(ctx, ct, ss);
}

int32_t POLAR_LAC_KeyGenInternal(CRYPT_POLAR_LAC_Ctx *ctx)
{
    uint32_t seedLen = ctx->info->seedLen;
    uint8_t seed[seedLen];
    int32_t ret = 0;
    // generate seed
    RETURN_RET_IF(CRYPT_EAL_Randbytes(seed, seedLen), ret);
    // key generation with seed
    POLAR_LAC_PkeKeyGen(ctx, seed);
    return 0;
}