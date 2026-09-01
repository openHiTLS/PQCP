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

/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

#ifndef DRNG_H
#define DRNG_H

#define SEEDLEN (55)

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct
    {
        unsigned char V[SEEDLEN];
        unsigned char C[SEEDLEN];
        unsigned char reseed_counter[SEEDLEN];
    } DRNG_ctx;

    /// @brief  Initialize Deterministic Random Number Generator (DRNG)
    ///         This function must be called before the first call of the get_random_number()
    /// @param[in,out] drng Unique name of the DRNG
    /// @param[in] seed The base address of input seed
    /// @param[in] seed_len_bytes The valid BYTES of input seed
    /// @return 0 for success, others for error
    int init_random_number(DRNG_ctx *drng, const unsigned char *seed, unsigned long long seed_len_bytes);

    /// @brief Generate Pseudo Random Number (PRN)
    /// @param[in] drng Initialized DRNG
    /// @param[out] random_number The base address to save the generated PRN
    /// @param[in] random_number_len_bits The valid BITS of output PRN
    /// @return 0 for success, others for error
    int get_random_number(DRNG_ctx *drng, unsigned char *random_number, unsigned long long random_number_len_bits);

#ifdef __cplusplus
}
#endif
#endif
