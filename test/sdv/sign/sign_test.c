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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pqcp_test.h"
#include "sign_test.h"


/* 初始化签名测试套件 */
int32_t PQCP_InitSignTestSuite(void)
{
    /* 创建签名测试套件 */
    PqcpTestSuite *suite = PQCP_TestCreateSuite("sign", "后量子数字签名测试");
    if (suite == NULL) {
        return -1;
    }
    /* Composite Sign API Tests */
    PQCP_TestAddCase(suite, "CompositeSign KeyGen Normal", "composite_sign key generation", TestCompositeKeyGenNormal);
    PQCP_TestAddCase(suite, "CompositeSign Get PrvKey", "composite_sign get private key", TestCompositeGetPrvKey);
    PQCP_TestAddCase(suite, "CompositeSign Get PubKey", "composite_sign get public key", TestCompositeGetPubKey);
    PQCP_TestAddCase(suite, "CompositeSign Set PrvKey", "composite_sign set private key", TestCompositeSetPrvKey);
    PQCP_TestAddCase(suite, "CompositeSign Set PubKey", "composite_sign set public key", TestCompositeSetPubKey);
    PQCP_TestAddCase(suite, "CompositeSign Sign Verify", "composite_sign sign and verify", TestCompositeSignVerify);
    PQCP_TestAddCase(suite, "CompositeSign Err NullCtx", "composite_sign error handling", TestCompositeErrNullCtx);
    PQCP_TestAddCase(suite, "CompositeSign Err AlgNotSet", "composite_sign error handling", TestCompositeErrAlgNotSet);
    PQCP_TestAddCase(suite, "CompositeSign Err InvalidParams", "composite_sign error handling", TestCompositeErrInvalidParams);
    PQCP_TestAddCase(suite, "CompositeSign Err BufferTooSmall", "composite_sign error handling", TestCompositeErrBufferTooSmall);
    PQCP_TestAddCase(suite, "CompositeSign Err InvalidAlgId", "composite_sign error handling", TestCompositeErrInvalidAlgId);
    PQCP_TestAddCase(suite, "CompositeSign GetSignLen", "composite_sign get signature length", TestCompositeGetSignLen);
    PQCP_TestAddCase(suite, "CompositeSign DupCtx", "composite_sign duplicate context", TestCompositeDupCtx);
    PQCP_TestAddCase(suite, "CompositeSign KeyEx", "composite_sign Ex versions of Set/Get", TestCompositeKeyEx);
    PQCP_TestAddCase(suite, "CompositeSign GetSeparateKeyLen", "composite_sign get separate key length", TestCompositeGetSeparateKeyLen);
    PQCP_TestAddCase(suite, "CompositeSign GetSeparateSignLen", "composite_sign get separate sign length", TestCompositeGetSeparateSignLen);
    /* 添加测试套件到测试框架 */
    return PQCP_TestAddSuite(suite);
} 