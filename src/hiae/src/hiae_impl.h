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

#ifndef HIAE_IMPL_H
#define HIAE_IMPL_H

#include "hiae_local.h"

#define HIAE_P_MAX   (((uint64_t)1u << 61) - 1u)
#define HIAE_A_MAX   (((uint64_t)1u << 61) - 1u)

#define HIAE_UNROLL_BLOCK_SIZE 256u /* NUM of STATES * HIAE_BLOCK_SIZE */
#define HIAE_BLOCK_SIZE        16u /* 128 bits */
#define HIAE_STATE_NUM         16u /* NUM of STATES */

#if defined(__AES__) && defined(__x86_64__)
#include <immintrin.h>
#include <wmmintrin.h>
typedef __m128i DATA128b;
#elif defined(__ARM_FEATURE_CRYPTO) && defined(__ARM_NEON)
#include <arm_neon.h>
typedef uint8x16_t DATA128b;
#else
typedef uint8_t DATA128b[HIAE_BLOCK_SIZE];
#warning "HiAE currently supports only x86_64+AES-NI and ARMv8+Crypto+NEON."
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the 2048-bit state from key and nonce.
 *
 * @attention Internal interface. Not intended for external direct use.
 * @param state [OUT] State buffer with 16 DATA128b words, must be non-NULL.
 * @param key [IN] Key, 32 bytes, must be non-NULL.
 * @param iv [IN] Nonce/IV, 16 bytes, must be non-NULL.
 */
void HIAE_Init(DATA128b *state, const uint8_t *key, const uint8_t *iv);

/**
 * @brief Absorb associated data stream into state.
 *
 * @attention Internal interface. Not intended for external direct use.
 * Partial final block is zero-padded to 128 bits before update.
 * @param state [IN/OUT] HiAE state, must be non-NULL.
 * @param ad [IN] Associated data input. Must be non-NULL when len > 0.
 * @param len [IN] Associated data length in bytes as uint32_t.
 */
void HIAE_Stream_ProcAD(DATA128b *state, const uint8_t *ad, uint32_t len);

/**
 * @brief Encrypt byte stream with HiAE state.
 *
 * @attention Internal interface. Not intended for external direct use.
 * @param state [IN/OUT] HiAE state, must be non-NULL.
 * @param dst [OUT] Ciphertext output. Must be non-NULL when size > 0.
 * @param src [IN] Plaintext input. Must be non-NULL when size > 0.
 * @param size [IN] Input length in bytes as uint32_t.
 */
void HIAE_Stream_Encrypt(DATA128b *state, uint8_t *dst, const uint8_t *src, uint32_t size);

/**
 * @brief Decrypt byte stream with HiAE state.
 *
 * @attention Internal interface. Not intended for external direct use.
 * @param state [IN/OUT] HiAE state, must be non-NULL.
 * @param dst [OUT] Plaintext output. Must be non-NULL when size > 0.
 * @param src [IN] Ciphertext input. Must be non-NULL when size > 0.
 * @param size [IN] Input length in bytes as uint32_t.
 */
void HIAE_Stream_Decrypt(DATA128b *state, uint8_t *dst, const uint8_t *src, uint32_t size);

/**
 * @brief Finalize state and output authentication tag.
 *
 * @attention Internal interface. Not intended for external direct use.
 * Per draft, adLen and plainLen are converted to bit lengths internally
 * before final diffusion.
 * @param state [IN/OUT] HiAE state, must be non-NULL.
 * @param adLen [IN] Associated data length in bytes as uint64_t.
 * @param plainLen [IN] Message length in bytes as uint64_t.
 * @param tag [OUT] Authentication tag, 16 bytes, must be non-NULL.
 */
void HIAE_Finalize(DATA128b *state, uint64_t adLen, uint64_t plainLen, uint8_t *tag);

#ifdef __cplusplus
}
#endif

#endif /* HIAE_IMPL_H */
