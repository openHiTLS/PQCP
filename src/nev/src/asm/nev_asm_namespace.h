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

#ifndef PQCP_NEV_ASM_NAMESPACE_H
#define PQCP_NEV_ASM_NAMESPACE_H

#define NEV_PolyNtt pqcp_nev_asm_poly_ntt
#define NEV_PolyInvNtt pqcp_nev_asm_poly_invntt
#define NEV_PolyReduceInvNtt pqcp_nev_asm_poly_reduce_invntt
#define NEV_PolyReduceInvNttToMsg pqcp_nev_asm_poly_reduce_invntt_to_msg
#define NEV_PolyAdd pqcp_nev_asm_poly_add
#define NEV_PolyReduce pqcp_nev_asm_poly_reduce
#define NEV_PolyCaddq pqcp_nev_asm_poly_caddq
#define NEV_PolyReduceCaddqTo pqcp_nev_asm_poly_reduce_caddq_to
#define NEV_PolyCaddqTo pqcp_nev_asm_poly_caddq_to
#define NEV_PolyAddVinv pqcp_nev_asm_poly_add_vinv
#define NEV_PolyGetMontgomery pqcp_nev_asm_poly_get_montgomery
#define NEV_PolyReduceCaddq pqcp_nev_asm_poly_reduce_caddq
#define NEV_PolyAddReduceCaddq pqcp_nev_asm_poly_add_reduce_caddq
#define NEV_PolyGetMontgomeryCaddq pqcp_nev_asm_poly_get_montgomery_caddq
#define NEV_PolyMontMul pqcp_nev_asm_poly_mont_mul
#define NEV_PolyMont2Inverse pqcp_nev_asm_poly_mont2_inverse
#define NEV_PolyMont2InverseJudge pqcp_nev_asm_poly_mont2_inverse_judge
#define NEV_PolySampleEta pqcp_nev_asm_poly_sample_eta
#define NEV_PolySampleEtaLadder pqcp_nev_asm_poly_sample_eta_ladder
#define NEV_PolyGetNoiseM pqcp_nev_asm_poly_get_noise_m
#define NEV_PolyToBytes pqcp_nev_asm_poly_to_bytes
#define NEV_PolyFromBytes pqcp_nev_asm_poly_from_bytes
#define NEV_PolyCompress pqcp_nev_asm_poly_compress
#define NEV_PolyMontCompress pqcp_nev_asm_poly_mont_compress
#define NEV_PolyDecompress pqcp_nev_asm_poly_decompress
#define NEV_PolyToMsg pqcp_nev_asm_poly_to_msg
#define PQCP_NEV_EngineKeyGen pqcp_nev_asm_engine_keygen
#define PQCP_NEV_EngineEncaps pqcp_nev_asm_engine_encaps
#define PQCP_NEV_EngineDecaps pqcp_nev_asm_engine_decaps

#endif
