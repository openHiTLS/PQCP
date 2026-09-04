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

#ifndef CRYPT_COMPOSITE_SIGN_LOCAL_H
#define CRYPT_COMPOSITE_SIGN_LOCAL_H

#include "crypt_composite_sign.h"
#include "sal_atomic.h"
#include "bsl_types.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define COMPOSITE_SIGNATURE_PREFIX_LEN 32
#define COMPOSITE_MAX_CTX_BYTES 255
#define MD_SHA256_SIZE 32
#define MD_SHA512_SIZE 64
#define BITS_TO_BYTES(x) (((x) + 7) >> 3)

typedef struct {
    int32_t (*newCtx)(PQCP_CompositeCtx *ctx);
    void (*freeCtx)(void *ctx);
    void *(*dupCtx)(const void *ctx);
    int32_t (*ctrl)(void *ctx, int32_t opt, void *val, uint32_t len);
    int32_t (*gen)(void *ctx);
    int32_t (*sign)(void *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen, uint8_t *sign,
                    uint32_t *signLen);
    int32_t (*verify)(const void *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen, uint8_t *sign,
                      uint32_t signLen);
    int32_t (*getSigLen)(PQCP_CompositeCtx *ctx, const uint8_t *sign, uint32_t signLen, uint32_t *pqcSigLen);
    int32_t (*getPrv)(const PQCP_CompositeCtx *ctx, BSL_Buffer *encode);
    int32_t (*getPub)(const PQCP_CompositeCtx *ctx, BSL_Buffer *encode);
    int32_t (*setPrv)(PQCP_CompositeCtx *ctx, BSL_Buffer *encode);
    int32_t (*setPub)(PQCP_CompositeCtx *ctx, BSL_Buffer *encode);
} PQCP_COMPOSITE_PQC_METHOD;

typedef struct {
    int32_t paramId;
    const char *label;
    int32_t pqcAlg;
    int32_t pqcParam;
    int32_t tradAlg;
    int32_t tradParam;
    int32_t hashId;
    int32_t tradHashId;
    uint32_t bits;
    uint32_t compPubKeyLen; // composite pubkey len
    uint32_t compPrvKeyLen; // composite prvkey len
    uint32_t pqcPubkeyLen;
    uint32_t pqcPrvkeyLen;
    uint32_t pqcSigLen;
    uint8_t isSetPqcCtxInfo;
    const PQCP_COMPOSITE_PQC_METHOD *pqcMethod;
} PQCP_COMPOSITE_ALG_INFO;

struct CompositeCtx {
    void *pqcCtx;
    void *tradCtx;
    const PQCP_COMPOSITE_ALG_INFO *info;
    uint8_t *ctxInfo;
    uint32_t ctxLen;
    BSL_SAL_RefCount references;
    void *libCtx;
};

extern const PQCP_COMPOSITE_PQC_METHOD g_compositeMldsaPqcMethod;
#ifdef PQCP_AIGIS_SIG
extern const PQCP_COMPOSITE_PQC_METHOD g_compositeAigisPqcMethod;
#endif

int32_t PQCP_CompositeGetMldsaPrvKey(const PQCP_CompositeCtx *ctx, BSL_Buffer *encode);
int32_t PQCP_CompositeGetMldsaPubKey(const PQCP_CompositeCtx *ctx, BSL_Buffer *encode);
int32_t PQCP_CompositeSetMldsaPrvKey(PQCP_CompositeCtx *ctx, BSL_Buffer *encode);
int32_t PQCP_CompositeSetMldsaPubKey(PQCP_CompositeCtx *ctx, BSL_Buffer *encode);
#ifdef PQCP_AIGIS_SIG
int32_t PQCP_CompositeGetAigisPrvKey(const PQCP_CompositeCtx *ctx, BSL_Buffer *encode);
int32_t PQCP_CompositeGetAigisPubKey(const PQCP_CompositeCtx *ctx, BSL_Buffer *encode);
int32_t PQCP_CompositeSetAigisPrvKey(PQCP_CompositeCtx *ctx, BSL_Buffer *encode);
int32_t PQCP_CompositeSetAigisPubKey(PQCP_CompositeCtx *ctx, BSL_Buffer *encode);
#endif
int32_t PQCP_CompositeGetTradPrvKey(const PQCP_CompositeCtx *ctx, BSL_Buffer *encode);
int32_t PQCP_CompositeGetTradPubKey(const PQCP_CompositeCtx *ctx, BSL_Buffer *encode);
int32_t PQCP_CompositeSetTradPrvKey(PQCP_CompositeCtx *ctx, BSL_Buffer *encode);
int32_t PQCP_CompositeSetTradPubKey(PQCP_CompositeCtx *ctx, BSL_Buffer *encode);

#ifdef __cplusplus
}
#endif
#endif // CRYPT_COMPOSITE_SIGN_LOCAL_H
