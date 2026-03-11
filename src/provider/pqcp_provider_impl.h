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

#ifndef PQCP_PROVIDER_IMPL_H
#define PQCP_PROVIDER_IMPL_H

#include "crypt_eal_provider.h"

#ifdef PQCP_SCLOUDPLUS
extern const CRYPT_EAL_Func g_pqcpKeyMgmtScloudPlus[];
extern const CRYPT_EAL_Func g_pqcpKemScloudPlus[];
#endif

#ifdef PQCP_POLARLAC
extern const CRYPT_EAL_Func g_pqcpKeyMgmtPolarLac[];
extern const CRYPT_EAL_Func g_pqcpKemPolarLac[];
#endif

#ifdef PQCP_COMPOSITE_SIGN
extern const CRYPT_EAL_Func g_pqcpKeyMgmtCompositeSign[];
extern const CRYPT_EAL_Func g_pqcpCompositeSign[];
#endif
#endif /* PQCP_PROVIDER_IMPL_H */