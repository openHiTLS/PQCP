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

#ifndef AIGIS_SIG_SHA3_CACHE_H
#define AIGIS_SIG_SHA3_CACHE_H

#include "crypt_eal_md.h"

struct PQCP_AIGIS_SIG_Sha3Cache {
    CRYPT_EAL_MdCtx *shake128;
    CRYPT_EAL_MdCtx *shake256;
};

#endif
