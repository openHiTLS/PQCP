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

#include "api.h"
#include "params.h"
#include "owpke.h"
#include "symmetrics/hashkdf.h"
#include "randombytes.h"

void kem_cpa_keygen(uint8_t *pk, uint8_t *sk) {
    ow_pke_keypair(pk, sk);
}

void kem_cpa_enc(uint8_t *c, uint8_t *ss, const uint8_t *pk) {
    uint8_t buf[SEED_BYTES];
    randombytes(buf, SEED_BYTES);
    Hash(ss, buf, SEED_BYTES);
    ow_pke_enc(c, buf, pk);
}

void kem_cpa_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    uint8_t buf[SEED_BYTES];
    ow_pke_dec(buf, ct, sk);
    Hash(ss, buf, SEED_BYTES);
}

void pke_cpa_keygen(uint8_t *pk, uint8_t *sk) {
    ow_pke_keypair(pk, sk);
}

void pke_cpa_enc(uint8_t *ct, const uint8_t *m, const uint8_t *pk) {
    uint8_t k[SEED_BYTES];
    kem_cpa_enc(ct, k, pk);
    for (int i = 0; i < SEED_BYTES; ++i) {
        ct[PKE_OW_CT_BYTES + i] = m[i] ^ k[i];
    }
}

void pke_cpa_dec(uint8_t *m, const uint8_t *ct, const uint8_t *sk) {
    uint8_t k[SEED_BYTES];
    kem_cpa_dec(k,ct,sk);
    for (int i = 0; i < SEED_BYTES; ++i) {
        m[i] = ct[PKE_OW_CT_BYTES + i] ^ k[i];
    }
}