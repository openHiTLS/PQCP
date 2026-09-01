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

#ifndef NEV_SVE2_H
#define NEV_SVE2_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_NEV_SVE2

/*
 * PQCP_NEV_ENABLE_SVE2 is a compile-time platform contract: when this header
 * is active, every SVE2 dispatch site selects the SVE2 implementation without
 * probing HWCAP or the vector length. The NTT and primary polynomial kernels
 * are specialized for a 256-bit vector length; enabling this backend is also
 * a compile-time promise that the target runs with VL=256.
 *
 * Keep this constant function-like macro so the shared NEON/SVE2 glue remains
 * readable while every compiler can remove the unreachable NEON arm before
 * code generation.
 */
#define NEV_Sve2Enabled() 1U

#endif // HITLS_CRYPTO_NEV_SVE2
#endif // NEV_SVE2_H
