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

#ifndef NEV_REF_SAMPLE_H
#define NEV_REF_SAMPLE_H

#include <stdint.h>
#include "poly.h"

void poly_binomial_dist1(poly *r, const uint8_t *seed, uint8_t nonce);
void poly_binomial_dist2(poly *r, const uint8_t *seed, uint8_t nonce);
void poly_binomial_dist3(poly *r, const uint8_t *seed, uint8_t nonce);
void poly_bias8_ternary(poly *r, const uint8_t *seed, uint8_t nonce);
void poly_sample_f(poly *f, uint8_t *seed, uint8_t nonce);
void poly_sample_g(poly *g, uint8_t *seed, uint8_t nonce);
void poly_sample_r(poly *r, uint8_t *coins, uint8_t nonce);
void poly_get_noisem(poly *r, const uint8_t msg[SEED_BYTES], const uint8_t *seed, uint8_t nonce);


#endif //NEV_REF_SAMPLE_H