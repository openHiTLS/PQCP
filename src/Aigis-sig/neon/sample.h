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

#ifndef SAMPLE_H
#define SAMPLE_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "api.h"
#include "params.h"
#include "sign.h"
#include "poly.h"
#include "polyvec.h"
#include "packing.h"
#include "randombytes.h"
#include "hashkdf.h"
#include "api.h"
#include "pspm.h"
#include <string.h>

#define REJ_UNIFORM_BYTES 1440 // fail with prob. less than 2^-14
#define REJ_UNIFORM_NBLOCKS  (REJ_UNIFORM_BYTES + KDF128RATE - 1) / KDF128RATE

void expand_mat(polyvecl mat[PARAM_K], const unsigned char rho[SEEDBYTES]);

void challenge(uint8_t *seed, const unsigned char mu[CRHBYTES],
	const polyveck *w1);

void unpack_c(poly *c, const uint8_t seed[SEEDBYTES]);


void expand_matr(polyvecl mat[PARAM_K], const unsigned char rho[SEEDBYTES]);
#endif