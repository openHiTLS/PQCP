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

#ifndef SCLOUDPLUS_H
#define SCLOUDPLUS_H

#include <stdint.h>
#include "bsl_params.h"

// 密钥管理上下文结构
typedef struct {
    // 可根据需要添加成员变量
    int32_t placeholder;
    uint8_t *public_key;
    uint8_t *private_key;
} SCLOUDPLUS_Ctx;

// 函数声明
void *PQCP_SCLOUDPLUS_NewCtx(void);
int32_t PQCP_SCLOUDPLUS_Gen(SCLOUDPLUS_Ctx *ctx);
int32_t PQCP_SCLOUDPLUS_SetPrvKey(SCLOUDPLUS_Ctx *ctx, BSL_Param *param);
int32_t PQCP_SCLOUDPLUS_SetPubKey(SCLOUDPLUS_Ctx *ctx, BSL_Param *param);
int32_t PQCP_SCLOUDPLUS_GetPrvKey(SCLOUDPLUS_Ctx *ctx, BSL_Param *param);
int32_t PQCP_SCLOUDPLUS_GetPubKey(SCLOUDPLUS_Ctx *ctx, BSL_Param *param);
SCLOUDPLUS_Ctx *PQCP_SCLOUDPLUS_DupCtx(SCLOUDPLUS_Ctx *src_ctx);
int32_t PQCP_SCLOUDPLUS_Cmp(SCLOUDPLUS_Ctx *ctx1, SCLOUDPLUS_Ctx *ctx2);
int32_t PQCP_SCLOUDPLUS_Ctrl(SCLOUDPLUS_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen);
void PQCP_SCLOUDPLUS_FreeCtx(SCLOUDPLUS_Ctx *ctx);

// 新增KEM函数声明
int32_t PQCP_SCLOUDPLUS_EncapsInit(SCLOUDPLUS_Ctx *ctx, const BSL_Param *params);
int32_t PQCP_SCLOUDPLUS_DecapsInit(SCLOUDPLUS_Ctx *ctx, const BSL_Param *params);
int32_t PQCP_SCLOUDPLUS_Encaps(SCLOUDPLUS_Ctx *ctx, 
                              uint8_t *ciphertext, uint32_t *ctLen,
                              uint8_t *sharedSecret, uint32_t *ssLen);
int32_t PQCP_SCLOUDPLUS_Decaps(SCLOUDPLUS_Ctx *ctx,
                              const uint8_t *ciphertext, uint32_t ctLen,
                              uint8_t *sharedSecret, uint32_t *ssLen);

#endif // SCLOUDPLUS_H