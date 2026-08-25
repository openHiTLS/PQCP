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

#ifndef OWCPA_H
#define OWCPA_H

#include <stdint.h>


void owcpa_keypair(uint8_t *pk, 
                   uint8_t *sk);

void owcpa_enc(uint8_t *c,
               const uint8_t *m,
               const uint8_t *pk,
               const uint8_t *coins);

void owcpa_dec(uint8_t *m,
               const uint8_t *c,
               const uint8_t *sk);

#endif
