#ifndef FRODOKEM_API_H
#define FRODOKEM_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "internal/frodo_params.h"
#include "bsl_params.h"

// 密钥管理上下文结构
typedef struct
{
    // 可根据需要添加成员变量
    FrodoKemParams* para;
    uint8_t* publicKey;
    uint8_t* privateKey;
} FrodoKEM_Ctx;

// Declare the top-level API functions that your test files will call.
// These names match the ones used in the Microsoft reference tests.

// =================================================================================
// Function Prototypes from frodokem_kem.c
// =================================================================================

int FrodoKemKeypair(const FrodoKemParams* params, uint8_t* pk, uint8_t* sk, size_t lenSk);

int FrodoKemEncaps(const FrodoKemParams* params, uint8_t* ct, uint8_t* ss, const uint8_t* pk);

int FrodoKemDecaps(const FrodoKemParams* params, uint8_t* ss, const uint8_t* ct, const uint8_t* sk);

void* PQCP_FRODOKEM_NewCtx(void);
int32_t PQCP_FRODOKEM_Gen(FrodoKEM_Ctx* ctx);
int32_t PQCP_FRODOKEM_SetPrvKey(FrodoKEM_Ctx* ctx, BSL_Param* param);
int32_t PQCP_FRODOKEM_SetPubKey(FrodoKEM_Ctx* ctx, BSL_Param* param);
int32_t PQCP_FRODOKEM_GetPrvKey(FrodoKEM_Ctx* ctx, BSL_Param* param);
int32_t PQCP_FRODOKEM_GetPubKey(FrodoKEM_Ctx* ctx, BSL_Param* param);
FrodoKEM_Ctx* PQCP_FRODOKEM_DupCtx(FrodoKEM_Ctx* src_ctx);
int32_t PQCP_FRODOKEM_Cmp(FrodoKEM_Ctx* ctx1, FrodoKEM_Ctx* ctx2);
int32_t PQCP_FRODOKEM_Ctrl(FrodoKEM_Ctx* ctx, int32_t cmd, void* val, uint32_t valLen);
void PQCP_FRODOKEM_FreeCtx(FrodoKEM_Ctx* ctx);

// 新增KEM函数声明
int32_t PQCP_FRODOKEM_EncapsInit(FrodoKEM_Ctx* ctx, const BSL_Param* params);
int32_t PQCP_FRODOKEM_DecapsInit(FrodoKEM_Ctx* ctx, const BSL_Param* params);
int32_t PQCP_FRODOKEM_Encaps(FrodoKEM_Ctx* ctx,
                             uint8_t* ciphertext, uint32_t* ctLen,
                             uint8_t* sharedSecret, uint32_t* ssLen);
int32_t PQCP_FRODOKEM_Decaps(FrodoKEM_Ctx* ctx,
                             const uint8_t* ciphertext, uint32_t ctLen,
                             uint8_t* sharedSecret, uint32_t* ssLen);

#ifdef __cplusplus
}
#endif

#endif // FRODOKEM_API_H
