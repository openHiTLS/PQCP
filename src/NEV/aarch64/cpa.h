/* Copyright (c) 2025 LiuRuikang
 * School Of Cyber Engineering, Xidian University
 *
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 * http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef NEV_PKE_H
#define NEV_PKE_H
#include <stdint.h>

void kem_cpa_keygen(uint8_t *pk, uint8_t *sk);

void kem_cpa_enc(uint8_t *c, uint8_t *ss, const uint8_t *pk);

void kem_cpa_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

void pke_cpa_keygen(uint8_t *pk, uint8_t *sk);

void pke_cpa_enc(uint8_t *ct, const uint8_t *m, const uint8_t *pk);

void pke_cpa_dec(uint8_t *m, const uint8_t *ct, const uint8_t *sk);
#endif //NEV_PKE_H