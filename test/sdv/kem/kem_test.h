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
#include "pqcp_test.h"

#define ASSERT_EQ(v1, v2, msg)                   \
    do {                                    \
        if (v1 != v2) {                      \
            printf("%s%d:expect:0x%x, real: 0x%x, %s\n", __FILE__, __LINE__, v1, v2, msg); \
            goto EXIT;                      \
        }                                   \
    } while (0)

#define ASSERT_TRUE(TEST, msg)                   \
    do {                                    \
        if (!(TEST)) {                      \
            printf("%s%d:%s\n", __FILE__, __LINE__, msg); \
            goto EXIT;                      \
        }                                   \
    } while (0)

PqcpTestResult TestScloudPlusEncapsDecaps(const char *data_path);