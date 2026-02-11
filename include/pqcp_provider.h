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

#ifndef PQCP_PROVIDER_H
#define PQCP_PROVIDER_H

#include "crypt_eal_provider.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Algorithm IDs */
#define PQCP_PKEY_SCLOUDPLUS 0x88000001
#define PQCP_PKEY_FRODOKEM 0x88000002
#define PQCP_PKEY_MCELIECE 0x88000003
#define PQCP_PKEY_POLAR_LAC 0x88000004
#define PQCP_PKEY_COMPOSITE_SIGN 0x88000005

/* Provider initialization function */
int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx,
                              BSL_Param *param,
                              CRYPT_EAL_Func *capFuncs,
                              CRYPT_EAL_Func **outFuncs,
                              void **provCtx);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_PROVIDER_H */ 