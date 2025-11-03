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

#ifndef MCELIECE_RNG_H
#define MCELIECE_RNG_H

#include "mceliece_shake.h"
#include "crypt_eal_init.h"
#include "crypt_eal_cipher.h"

CRYPT_ERROR McElieceRandomBytesInit(const uint8_t *entropyInput, uint8_t *personalizationString, const int32_t securityStrength);
CRYPT_ERROR McElieceRandomBytes(uint8_t *x, uint32_t xlen);

#endif // MCELIECE_RNG_H
