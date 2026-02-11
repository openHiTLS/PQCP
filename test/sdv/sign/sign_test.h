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

#ifndef SIGN_TEST_H
#define SIGN_TEST_H

#include "pqcp_test.h"

/* Composite Sign API test function declarations */
PqcpTestResult TestCompositeKeyGenNormal(void);
PqcpTestResult TestCompositeGetPrvKey(void);
PqcpTestResult TestCompositeGetPubKey(void);
PqcpTestResult TestCompositeSetPrvKey(void);
PqcpTestResult TestCompositeSetPubKey(void);
PqcpTestResult TestCompositeSignVerify(void);
PqcpTestResult TestCompositeErrNullCtx(void);
PqcpTestResult TestCompositeErrAlgNotSet(void);
PqcpTestResult TestCompositeErrInvalidParams(void);
PqcpTestResult TestCompositeErrBufferTooSmall(void);
PqcpTestResult TestCompositeErrInvalidAlgId(void);
PqcpTestResult TestCompositeGetSignLen(void);
PqcpTestResult TestCompositeDupCtx(void);
PqcpTestResult TestCompositeKeyEx(void);
PqcpTestResult TestCompositeGetSeparateKeyLen(void);
PqcpTestResult TestCompositeGetSeparateSignLen(void);

#endif /* SIGN_TEST_H */
