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

#ifndef PSPM_H
#define PSPM_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

void emulate_cs1(polyvecl *r, const poly *c, const uint8_t s1_table[PARAM_L][PARAM_N * 3]);

void poly_emulate_cs1(poly *r, const poly *c, const uint8_t s1_table[PARAM_N * 3]);
int poly_emulate_z(poly *r, const poly *y, const poly *c, const uint8_t s1_table[PARAM_N * 3]);

#if PARAMS == 1
void emulate_cs2(polyveck *r, const poly *c, const uint16_t s2_table[PARAM_K][PARAM_N * 3]);
void poly_emulate_cs2(poly *r, const poly *c, const uint16_t s2_table[PARAM_N * 3]);
int poly_emulate_w0_cs2(poly *r, const poly *w0, const poly *c, const uint16_t s2_table[PARAM_N * 3]);
#else
void emulate_cs2(polyveck *r, const poly *c, const uint8_t s2_table[PARAM_K][PARAM_N * 3]);
void poly_emulate_cs2(poly *r, const poly *c, const uint8_t s2_table[PARAM_N * 3]);
int poly_emulate_w0_cs2(poly *r, const poly *w0, const poly *c, const uint8_t s2_table[PARAM_N * 3]);
#endif

int emulate_ct(polyveck *r, const poly *c, const polyveck *t0);
int poly_emulate_ct(poly *r, const poly *c, const poly *t);

#endif
