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

#ifndef HIAE_LOCAL_H
#define HIAE_LOCAL_H

#include <stdint.h>

/**
 * @defgroup hiae_local HiAE low-level interfaces
 * @brief HiAE low-level APIs.
 *
 * Public low-level APIs (externally callable, standalone-friendly):
 * - PQCP_HIAE_AEAD_Encrypt
 * - PQCP_HIAE_AEAD_Decrypt
 * - PQCP_HIAE_Mac
 */

#define HIAE_KEY_LEN 32u
#define HIAE_IV_LEN  16u
#define HIAE_TAG_LEN 16u

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup hiae_local
 * @brief One-shot HiAE AEAD encryption API.
 *
 * Processing order follows the draft: Init -> ProcAD -> Encrypt -> Finalize.
 * @param key [IN] Key, 32 bytes.
 * @param keyLen [IN] Key length in bytes as uint32_t, must be 32.
 * @param nonce [IN] Nonce, 16 bytes.
 * @param nonceLen [IN] Nonce length in bytes as uint32_t, must be 16.
 * @param msg [IN] Plaintext. NULL is allowed when msgLen is 0.
 * @param msgLen [IN] Plaintext length in bytes as uint32_t. 0 is allowed.
 * @param ad [IN] Associated data. NULL is allowed when adLen is 0.
 * @param adLen [IN] Associated data length in bytes as uint32_t.
 * @param cipher [OUT] Ciphertext, same length as plaintext. NULL is allowed when msgLen is 0.
 * @param cipherLen [IN] Ciphertext buffer length in bytes as uint32_t, must be >= msgLen.
 * @param tag [OUT] Authentication tag output buffer, must provide 16 bytes.
 * @param tagLen [IN] Authentication tag buffer length in bytes as uint32_t, must be 16.
 *
 * @note The low-level one-shot entry uses uint32_t lengths, so a single call
 *       is limited by uint32_t parameters.
 * @retval #PQCP_SUCCESS, success.
 * @retval #PQCP_INVALID_ARG, invalid input.
 */
int32_t PQCP_HIAE_AEAD_Encrypt(uint8_t *key, uint32_t keyLen, uint8_t *nonce, uint32_t nonceLen, uint8_t *msg,
    uint32_t msgLen, uint8_t *ad, uint32_t adLen, uint8_t *cipher, uint32_t cipherLen, uint8_t *tag, uint32_t tagLen);

/**
 * @ingroup hiae_local
 * @brief One-shot HiAE AEAD decryption path API.
 *
 * This function computes plaintext and expected tag. Tag verification is
 * performed by the caller (provider/control layer).
 * @param key [IN] Key, 32 bytes.
 * @param keyLen [IN] Key length in bytes as uint32_t, must be 32.
 * @param nonce [IN] Nonce, 16 bytes.
 * @param nonceLen [IN] Nonce length in bytes as uint32_t, must be 16.
 * @param msg [OUT] Plaintext output. NULL is allowed when msgLen is 0.
 * @param msgLen [IN] Plaintext output length in bytes as uint32_t. 0 is allowed.
 * @param ad [IN] Associated data. NULL is allowed when adLen is 0.
 * @param adLen [IN] Associated data length in bytes as uint32_t.
 * @param cipher [IN] Ciphertext input. NULL is allowed when msgLen is 0.
 * @param cipherLen [IN] Ciphertext input length in bytes as uint32_t, must equal msgLen.
 * @param tag [OUT] Computed authentication tag output buffer, must provide 16 bytes.
 * @param tagLen [IN] Authentication tag buffer length in bytes as uint32_t, must be 16.
 *
 * @note The low-level one-shot entry uses uint32_t lengths, so a single call
 *       is limited by uint32_t parameters.
 * @retval #PQCP_SUCCESS, success.
 * @retval #PQCP_INVALID_ARG, invalid input.
 */
int32_t PQCP_HIAE_AEAD_Decrypt(uint8_t *key, uint32_t keyLen, uint8_t *nonce, uint32_t nonceLen, uint8_t *msg,
    uint32_t msgLen, uint8_t *ad, uint32_t adLen, uint8_t *cipher, uint32_t cipherLen, uint8_t *tag, uint32_t tagLen);

/**
 * @ingroup hiae_local
 * @brief One-shot HiAE MAC mode API.
 *
 * Processing order follows the draft MAC mode: Init -> ProcAD(data) ->
 * Finalize(dataLen, 0).
 * @param key [IN] Key, 32 bytes.
 * @param keyLen [IN] Key length in bytes as uint32_t, must be 32.
 * @param iv [IN] Nonce/IV, 16 bytes.
 * @param ivLen [IN] Nonce/IV length in bytes as uint32_t, must be 16.
 * @param msg [IN] MAC input data.
 * @param msgLen [IN] MAC input length in bytes as uint32_t.
 * @param tag [OUT] MAC tag output buffer, must provide 16 bytes.
 * @param tagLen [IN] MAC tag buffer length in bytes as uint32_t, must be 16.
 *
 * @note The low-level one-shot entry uses uint32_t lengths, so a single call
 *       is limited by uint32_t parameters.
 * @retval #PQCP_SUCCESS, success.
 * @retval #PQCP_INVALID_ARG, invalid input.
 */
int32_t PQCP_HIAE_Mac(uint8_t *key, uint32_t keyLen, uint8_t *iv, uint32_t ivLen, uint8_t *msg, uint32_t msgLen,
    uint8_t *tag, uint32_t tagLen);

#ifdef __cplusplus
}
#endif

#endif /* HIAE_LOCAL_H */
