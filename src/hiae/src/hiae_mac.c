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

#ifdef PQCP_HIAE

#include <string.h>

#include "pqcp_provider.h"
#include "pqcp_err.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_hiae.h"
#include "hiae_impl.h"
struct PQCP_HiaeMacCtx {
    DATA128b state[HIAE_STATE_NUM];
    uint8_t key[HIAE_KEY_LEN];
    uint8_t iv[HIAE_IV_LEN];
    uint8_t tag[HIAE_TAG_LEN];
    uint64_t adLen;
    bool ivSet;
    bool inited;
    bool finalized;
    uint8_t dataBuf[HIAE_BLOCK_SIZE];
    uint32_t dataBufLen;
};

static uint32_t MinU32(uint32_t a, uint32_t b)
{
    return (a < b) ? a : b;
}

static int32_t CheckLenLimitU64(uint64_t currentLen, uint32_t addLen, uint64_t maxLen)
{
    if (currentLen > maxLen) {
        BSL_ERR_PUSH_ERROR(PQCP_INVALID_ARG);
        return PQCP_INVALID_ARG;
    }
    if ((uint64_t)addLen > (maxLen - currentLen)) {
        BSL_ERR_PUSH_ERROR(PQCP_INVALID_ARG);
        return PQCP_INVALID_ARG;
    }
    return PQCP_SUCCESS;
}

static int32_t FlushPendingData(PQCP_HIAE_MacCtx *ctx)
{
    uint8_t block[HIAE_BLOCK_SIZE];

    if (ctx->dataBufLen == 0) {
        return PQCP_SUCCESS;
    }
    memset(block, 0, sizeof(block));
    memcpy(block, ctx->dataBuf, ctx->dataBufLen);
    HIAE_Stream_ProcAD(ctx->state, block, sizeof(block));
    BSL_SAL_CleanseData(block, sizeof(block));
    ctx->dataBufLen = 0;
    return PQCP_SUCCESS;
}

PQCP_HIAE_MacCtx *PQCP_HIAE_MacNewCtx(void *provCtx, int32_t algId)
{
    PQCP_HIAE_MacCtx *ctx;

    (void)provCtx;
    if (algId != (int32_t)PQCP_MAC_HIAE) {
        return NULL;
    }

    ctx = BSL_SAL_Calloc(1, sizeof(PQCP_HIAE_MacCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_MEM_ALLOC_FAIL);
        return NULL;
    }
    return ctx;
}

int32_t PQCP_HIAE_MacInit(PQCP_HIAE_MacCtx *c, const uint8_t *key, uint32_t len, BSL_Param *param)
{
    (void)param;
    if (c == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    if (len != sizeof(c->key)) {
        BSL_ERR_PUSH_ERROR(PQCP_INVALID_ARG);
        return PQCP_INVALID_ARG;
    }

    memcpy(c->key, key, sizeof(c->key));

    c->adLen = 0;
    c->dataBufLen = 0;
    c->ivSet = false;
    c->inited = true;
    c->finalized = false;
    BSL_SAL_CleanseData(c->tag, sizeof(c->tag));
    BSL_SAL_CleanseData(c->iv, sizeof(c->iv));
    BSL_SAL_CleanseData(c->dataBuf, sizeof(c->dataBuf));
    BSL_SAL_CleanseData(c->state, sizeof(c->state));
    return PQCP_SUCCESS;
}

int32_t PQCP_HIAE_MacUpdate(PQCP_HIAE_MacCtx *c, const uint8_t *input, uint32_t len)
{
    uint32_t take;
    uint32_t fullBytes;
    const uint8_t *ptr = input;

    if (c == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    if (!c->inited || !c->ivSet || c->finalized) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (c->dataBufLen >= HIAE_BLOCK_SIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (len > 0 && input == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    if (CheckLenLimitU64(c->adLen, len, HIAE_A_MAX) != PQCP_SUCCESS) {
        return PQCP_INVALID_ARG;
    }

    if (len == 0) {
        return PQCP_SUCCESS;
    }
    c->adLen += len;

    if (c->dataBufLen > 0) {
        take = MinU32(HIAE_BLOCK_SIZE - c->dataBufLen, len);
        memcpy(c->dataBuf + c->dataBufLen, ptr, take);
        c->dataBufLen += take;
        ptr += take;
        len -= take;
        if (c->dataBufLen == HIAE_BLOCK_SIZE) {
            HIAE_Stream_ProcAD(c->state, c->dataBuf, HIAE_BLOCK_SIZE);
            c->dataBufLen = 0;
        }
    }

    fullBytes = (len / HIAE_BLOCK_SIZE) * HIAE_BLOCK_SIZE;
    if (fullBytes > 0) {
        HIAE_Stream_ProcAD(c->state, ptr, fullBytes);
        ptr += fullBytes;
        len -= fullBytes;
    }

    if (len > 0) {
        memcpy(c->dataBuf, ptr, len);
        c->dataBufLen = len;
    }
    return PQCP_SUCCESS;
}

int32_t PQCP_HIAE_MacFinal(PQCP_HIAE_MacCtx *c, uint8_t *out, uint32_t *outLen)
{
    int32_t ret;

    if (c == NULL || out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    if (!c->inited || !c->ivSet) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (c->dataBufLen >= HIAE_BLOCK_SIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (*outLen < HIAE_TAG_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_EAL_BUFF_LEN_NOT_ENOUGH;
    }
    if (c->adLen > HIAE_A_MAX) {
        BSL_ERR_PUSH_ERROR(PQCP_INVALID_ARG);
        return PQCP_INVALID_ARG;
    }
    if (!c->finalized) {
        ret = FlushPendingData(c);
        if (ret != PQCP_SUCCESS) {
            return ret;
        }
        HIAE_Finalize(c->state, c->adLen, 0, c->tag);
        c->finalized = true;
    }
    memcpy(out, c->tag, HIAE_TAG_LEN);
    *outLen = HIAE_TAG_LEN;
    return PQCP_SUCCESS;
}

int32_t PQCP_HIAE_MacDeInitCtx(PQCP_HIAE_MacCtx *c)
{
    if (c == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }

    BSL_SAL_CleanseData(c, sizeof(PQCP_HIAE_MacCtx));
    return PQCP_SUCCESS;
}

int32_t PQCP_HIAE_MacReInitCtx(PQCP_HIAE_MacCtx *c)
{
    if (c == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    if (!c->inited || !c->ivSet) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    c->adLen = 0;
    c->dataBufLen = 0;
    c->finalized = false;
    BSL_SAL_CleanseData(c->tag, sizeof(c->tag));
    BSL_SAL_CleanseData(c->dataBuf, sizeof(c->dataBuf));
    HIAE_Init(c->state, c->key, c->iv);
    return PQCP_SUCCESS;
}

static int32_t SetIv(PQCP_HIAE_MacCtx *ctx, const uint8_t *iv, uint32_t ivLen)
{
    if (ctx == NULL || iv == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    if (ivLen != sizeof(ctx->iv)) {
        BSL_ERR_PUSH_ERROR(PQCP_INVALID_ARG);
        return PQCP_INVALID_ARG;
    }
    if (!ctx->inited) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    memcpy(ctx->iv, iv, ivLen);
    ctx->adLen = 0;
    ctx->dataBufLen = 0;
    ctx->ivSet = true;
    ctx->finalized = false;
    BSL_SAL_CleanseData(ctx->tag, sizeof(ctx->tag));
    BSL_SAL_CleanseData(ctx->dataBuf, sizeof(ctx->dataBuf));
    HIAE_Init(ctx->state, ctx->key, ctx->iv);
    return PQCP_SUCCESS;
}

int32_t PQCP_HIAE_MacCtrl(PQCP_HIAE_MacCtx *c, int32_t cmd, void *val, uint32_t valLen)
{
    if (c == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }

    switch (cmd) {
        case CRYPT_CTRL_SET_IV:
            return SetIv(c, val, valLen);
        case CRYPT_CTRL_GET_MACLEN:
            if (val == NULL || valLen != sizeof(uint32_t)) {
                BSL_ERR_PUSH_ERROR(PQCP_INVALID_ARG);
                return PQCP_INVALID_ARG;
            }
            *(uint32_t *)val = HIAE_TAG_LEN;
            return PQCP_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_EAL_MAC_CTRL_TYPE_ERROR);
            return CRYPT_EAL_MAC_CTRL_TYPE_ERROR;
    }
}

void PQCP_HIAE_MacFreeCtx(PQCP_HIAE_MacCtx *c)
{
    if (c != NULL) {
        BSL_SAL_CleanseData(c, sizeof(PQCP_HIAE_MacCtx));
        BSL_SAL_Free(c);
    }
}

PQCP_HIAE_MacCtx *PQCP_HIAE_MacDupCtx(const PQCP_HIAE_MacCtx *c)
{
    PQCP_HIAE_MacCtx *dup;

    if (c == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return NULL;
    }
    dup = BSL_SAL_Dump(c, sizeof(PQCP_HIAE_MacCtx));
    if (dup == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_MEM_ALLOC_FAIL);
        return NULL;
    }

    return dup;
}

#endif /* PQCP_HIAE */
