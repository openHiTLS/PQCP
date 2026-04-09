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

struct PQCP_HiaeCipherCtx {
    DATA128b state[HIAE_STATE_NUM];
    uint8_t key[HIAE_KEY_LEN];
    uint8_t iv[HIAE_IV_LEN];
    uint8_t tag[HIAE_TAG_LEN];
    uint64_t aadLen;
    uint64_t msgLen;
    bool isEnc;
    bool inited;
    bool finalized;
    uint8_t msgBuf[HIAE_BLOCK_SIZE];
    uint32_t msgBufLen;
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

static void ProcessPartialNoCommit(const PQCP_HIAE_CipherCtx *ctx, const uint8_t *in, uint32_t inLen, uint8_t *out)
{
    DATA128b tmpState[HIAE_STATE_NUM];

    memcpy(tmpState, ctx->state, sizeof(ctx->state));
    if (ctx->isEnc) {
        HIAE_Stream_Encrypt(tmpState, out, in, inLen);
    } else {
        HIAE_Stream_Decrypt(tmpState, out, in, inLen);
    }
    BSL_SAL_CleanseData(tmpState, sizeof(tmpState));
}

static void CommitPendingMsg(PQCP_HIAE_CipherCtx *ctx)
{
    uint8_t ignored[HIAE_BLOCK_SIZE];

    if (ctx->msgBufLen == 0) {
        return;
    }
    if (ctx->isEnc) {
        HIAE_Stream_Encrypt(ctx->state, ignored, ctx->msgBuf, ctx->msgBufLen);
    } else {
        HIAE_Stream_Decrypt(ctx->state, ignored, ctx->msgBuf, ctx->msgBufLen);
    }
    BSL_SAL_CleanseData(ignored, sizeof(ignored));
    ctx->msgBufLen = 0;
}

static void CommitPendingAad(PQCP_HIAE_CipherCtx *ctx)
{
    if (ctx->msgBufLen == 0) {
        return;
    }
    HIAE_Stream_ProcAD(ctx->state, ctx->msgBuf, ctx->msgBufLen);
    ctx->msgBufLen = 0;
}

static int32_t FinalizeIfNeeded(PQCP_HIAE_CipherCtx *ctx)
{
    if (ctx->aadLen > HIAE_A_MAX || ctx->msgLen > HIAE_P_MAX) {
        BSL_ERR_PUSH_ERROR(PQCP_INVALID_ARG);
        return PQCP_INVALID_ARG;
    }
    if (ctx->msgLen == 0) {
        CommitPendingAad(ctx);
    } else {
        CommitPendingMsg(ctx);
    }
    HIAE_Finalize(ctx->state, ctx->aadLen, ctx->msgLen, ctx->tag);
    ctx->finalized = true;
    return PQCP_SUCCESS;
}

PQCP_HIAE_CipherCtx *PQCP_HIAE_CipherNewCtx(void *provCtx, int32_t algId)
{
    PQCP_HIAE_CipherCtx *ctx;

    (void)provCtx;
    if (algId != (int32_t)PQCP_CIPHER_HIAE) {
        return NULL;
    }

    ctx = BSL_SAL_Calloc(1, sizeof(PQCP_HIAE_CipherCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_MEM_ALLOC_FAIL);
        return NULL;
    }
    return ctx;
}

int32_t PQCP_HIAE_CipherInitCtx(PQCP_HIAE_CipherCtx *c, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
                                uint32_t ivLen, BSL_Param *param, bool enc)
{
    (void)param;
    if (c == NULL || key == NULL || iv == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    if (keyLen != sizeof(c->key) || ivLen != sizeof(c->iv)) {
        BSL_ERR_PUSH_ERROR(PQCP_INVALID_ARG);
        return PQCP_INVALID_ARG;
    }

    memcpy(c->key, key, keyLen);
    memcpy(c->iv, iv, ivLen);

    c->aadLen = 0;
    c->msgLen = 0;
    c->msgBufLen = 0;
    c->isEnc = enc;
    c->inited = true;
    c->finalized = false;
    BSL_SAL_CleanseData(c->tag, sizeof(c->tag));
    BSL_SAL_CleanseData(c->msgBuf, sizeof(c->msgBuf));

    HIAE_Init(c->state, c->key, c->iv);
    return PQCP_SUCCESS;
}

int32_t PQCP_HIAE_CipherUpdate(PQCP_HIAE_CipherCtx *c, const uint8_t *in, uint32_t inLen, uint8_t *out,
                               uint32_t *outLen)
{
    const uint8_t *inPtr;
    uint8_t *outPtr;
    uint32_t inRemain;
    uint32_t outCap;
    uint32_t produced;
    uint32_t oldLen;
    uint32_t take;
    uint32_t fullBytes;
    uint8_t blockOut[HIAE_BLOCK_SIZE];

    if (c == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    if (!c->inited || c->finalized) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (c->msgBufLen >= HIAE_BLOCK_SIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (inLen > 0 && (in == NULL || out == NULL)) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    if (CheckLenLimitU64(c->msgLen, inLen, HIAE_P_MAX) != PQCP_SUCCESS) {
        return PQCP_INVALID_ARG;
    }

    if (inLen == 0) {
        *outLen = 0;
        return PQCP_SUCCESS;
    }
    if (c->msgLen == 0 && c->msgBufLen > 0) {
        CommitPendingAad(c);
    }

    outCap = *outLen;
    if (outCap < inLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_EAL_BUFF_LEN_NOT_ENOUGH;
    }

    inPtr = in;
    outPtr = out;
    inRemain = inLen;
    produced = 0;

    if (c->msgBufLen > 0) {
        oldLen = c->msgBufLen;
        take = MinU32(HIAE_BLOCK_SIZE - oldLen, inRemain);
        memcpy(c->msgBuf + c->msgBufLen, inPtr, take);
        c->msgBufLen += take;
        inPtr += take;
        inRemain -= take;

        if (c->msgBufLen == HIAE_BLOCK_SIZE && take > 0) {
            if (c->isEnc) {
                HIAE_Stream_Encrypt(c->state, blockOut, c->msgBuf, HIAE_BLOCK_SIZE);
            } else {
                HIAE_Stream_Decrypt(c->state, blockOut, c->msgBuf, HIAE_BLOCK_SIZE);
            }
            memcpy(outPtr, blockOut + oldLen, take);
            outPtr += take;
            produced += take;
            c->msgBufLen = 0;
        } else if (take > 0) {
            ProcessPartialNoCommit(c, c->msgBuf, c->msgBufLen, blockOut);
            memcpy(outPtr, blockOut + oldLen, take);
            outPtr += take;
            produced += take;
        }
    }

    fullBytes = (inRemain / HIAE_BLOCK_SIZE) * HIAE_BLOCK_SIZE;
    if (fullBytes > 0) {
        if (c->isEnc) {
            HIAE_Stream_Encrypt(c->state, outPtr, inPtr, fullBytes);
        } else {
            HIAE_Stream_Decrypt(c->state, outPtr, inPtr, fullBytes);
        }
        inPtr += fullBytes;
        outPtr += fullBytes;
        inRemain -= fullBytes;
        produced += fullBytes;
    }

    if (inRemain > 0) {
        memcpy(c->msgBuf, inPtr, inRemain);
        ProcessPartialNoCommit(c, c->msgBuf, inRemain, blockOut);
        memcpy(outPtr, blockOut, inRemain);
        produced += inRemain;
        c->msgBufLen = inRemain;
    }
    c->msgLen += inLen;
    *outLen = produced;
    return PQCP_SUCCESS;
}

int32_t PQCP_HIAE_CipherFinal(PQCP_HIAE_CipherCtx *c, uint8_t *out, uint32_t *outLen)
{
    int32_t ret;

    (void)out;
    if (c == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    if (!c->inited) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (c->finalized) {
        *outLen = 0;
        return PQCP_SUCCESS;
    }
    ret = FinalizeIfNeeded(c);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    *outLen = 0;
    return PQCP_SUCCESS;
}

int32_t PQCP_HIAE_CipherDeinitCtx(PQCP_HIAE_CipherCtx *c)
{
    if (c == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }

    BSL_SAL_CleanseData(c, sizeof(PQCP_HIAE_CipherCtx));
    return PQCP_SUCCESS;
}

static int32_t SetIv(PQCP_HIAE_CipherCtx *ctx, const uint8_t *iv, uint32_t ivLen)
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
    HIAE_Init(ctx->state, ctx->key, ctx->iv);
    ctx->aadLen = 0;
    ctx->msgLen = 0;
    ctx->msgBufLen = 0;
    ctx->finalized = false;
    BSL_SAL_CleanseData(ctx->tag, sizeof(ctx->tag));
    BSL_SAL_CleanseData(ctx->msgBuf, sizeof(ctx->msgBuf));
    return PQCP_SUCCESS;
}

static int32_t SetAad(PQCP_HIAE_CipherCtx *ctx, const uint8_t *aad, uint32_t aadLen)
{
    const uint8_t *aadPtr;
    uint32_t aadRemain;
    uint32_t take;
    uint32_t fullBytes;

    if (!ctx->inited || ctx->finalized) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (ctx->msgBufLen >= HIAE_BLOCK_SIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (aadLen > 0 && aad == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    if (ctx->msgLen != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (aadLen == 0) {
        return PQCP_SUCCESS;
    }
    if (CheckLenLimitU64(ctx->aadLen, aadLen, HIAE_A_MAX) != PQCP_SUCCESS) {
        return PQCP_INVALID_ARG;
    }

    ctx->aadLen += aadLen;
    aadPtr = aad;
    aadRemain = aadLen;

    if (ctx->msgBufLen > 0) {
        take = MinU32(HIAE_BLOCK_SIZE - ctx->msgBufLen, aadRemain);
        memcpy(ctx->msgBuf + ctx->msgBufLen, aadPtr, take);
        ctx->msgBufLen += take;
        aadPtr += take;
        aadRemain -= take;

        if (ctx->msgBufLen == HIAE_BLOCK_SIZE) {
            HIAE_Stream_ProcAD(ctx->state, ctx->msgBuf, HIAE_BLOCK_SIZE);
            ctx->msgBufLen = 0;
        }
    }

    fullBytes = (aadRemain / HIAE_BLOCK_SIZE) * HIAE_BLOCK_SIZE;
    if (fullBytes > 0) {
        HIAE_Stream_ProcAD(ctx->state, aadPtr, fullBytes);
        aadPtr += fullBytes;
        aadRemain -= fullBytes;
    }

    if (aadRemain > 0) {
        memcpy(ctx->msgBuf, aadPtr, aadRemain);
        ctx->msgBufLen = aadRemain;
    }
    return PQCP_SUCCESS;
}

static int32_t GetTag(PQCP_HIAE_CipherCtx *ctx, uint8_t *tag, uint32_t tagLen)
{
    int32_t ret;

    if (ctx == NULL || tag == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }
    if (tagLen < HIAE_TAG_LEN) {
        BSL_ERR_PUSH_ERROR(PQCP_INVALID_ARG);
        return PQCP_INVALID_ARG;
    }
    if (!ctx->inited) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (!ctx->finalized) {
        ret = FinalizeIfNeeded(ctx);
        if (ret != PQCP_SUCCESS) {
            return ret;
        }
    }
    memcpy(tag, ctx->tag, HIAE_TAG_LEN);
    return PQCP_SUCCESS;
}

int32_t PQCP_HIAE_CipherCtrl(PQCP_HIAE_CipherCtx *c, int32_t cmd, void *val, uint32_t valLen)
{
    if (c == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return PQCP_NULL_INPUT;
    }

    switch (cmd) {
        case CRYPT_CTRL_SET_IV:
        case CRYPT_CTRL_REINIT_STATUS:
            return SetIv(c, val, valLen);
        case CRYPT_CTRL_SET_AAD:
            return SetAad(c, val, valLen);
        case CRYPT_CTRL_GET_TAG:
            return GetTag(c, val, valLen);
        case CRYPT_CTRL_GET_BLOCKSIZE:
            if (val == NULL || valLen != sizeof(uint32_t)) {
                BSL_ERR_PUSH_ERROR(PQCP_INVALID_ARG);
                return PQCP_INVALID_ARG;
            }
            *(uint32_t *)val = HIAE_BLOCK_SIZE;
            return PQCP_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_EAL_CIPHER_CTRL_ERROR);
            return CRYPT_EAL_CIPHER_CTRL_ERROR;
    }
}

void PQCP_HIAE_CipherFreeCtx(PQCP_HIAE_CipherCtx *c)
{
    if (c != NULL) {
        BSL_SAL_CleanseData(c, sizeof(PQCP_HIAE_CipherCtx));
        BSL_SAL_Free(c);
    }
}

PQCP_HIAE_CipherCtx *PQCP_HIAE_CipherDupCtx(const PQCP_HIAE_CipherCtx *c)
{
    PQCP_HIAE_CipherCtx *dup;

    if (c == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_NULL_INPUT);
        return NULL;
    }

    dup = BSL_SAL_Dump(c, sizeof(PQCP_HIAE_CipherCtx));
    if (dup == NULL) {
        BSL_ERR_PUSH_ERROR(PQCP_MEM_ALLOC_FAIL);
        return NULL;
    }

    return dup;
}

#endif /* PQCP_HIAE */
