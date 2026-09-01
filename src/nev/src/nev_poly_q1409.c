/* Copyright (c) 2025 LiuRuikang
 * School Of Cyber Engineering, Xidian University
 *
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

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_NEV

#include "nev_local.h"
#include "nev_qdispatch.h"

/*
 * q = 1409 instantiation of the NEV generic C backend hot code (all
 * NEV-*-1409 parameter sets): q^-1 mod 2^16 = 14977, Barrett (v, shift) =
 * (23814, 25), nttDim = 64 (values from the parameter table in nev.c). This
 * is the only modulus with the t = 32 tower (NEV-2048-1409). See
 * nev_poly_core.inc for the template contract.
 */
#define NEV_TQ 1409
#define NEV_TQINV_S16 14977
#define NEV_TBARRETT_V 23814
#define NEV_TBARRETT_SHIFT 25
#define NEV_TDIM 64
#define NEV_TFN(name) name##_Q1409

#include "nev_poly_core.inc"

#endif // HITLS_CRYPTO_NEV
