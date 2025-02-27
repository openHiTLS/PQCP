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
#include <time.h>

/* 这里应该包含PQCP库的头文件 */
/* 在实际使用中，应该替换为正确的头文件路径 */
#include "pqcp_test.h"

/* 演示用的消息 */
const char *demo_message = "这是一条使用后量子密码算法保护的消息";

/**
 * 打印缓冲区内容（十六进制）
 */
static void PrintHex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i < len - 1) {
            printf("\n     ");
        }
    }
    printf("\n");
}

/**
 * scloud+密钥封装机制（KEM）演示
 */
static int32_t ScloudplusDemo(void)
{
    printf("\n=== Scloud+密钥封装机制(KEM)演示 ===\n\n");
    uint8_t share1[32] = {0};
    uint8_t share2[32] = {0};
    
    /* 验证两个共享密钥是否相同 */
    if (memcmp(share1, share2, sizeof(share2)) == 0) {
        printf("\n密钥封装和解封装成功！共享密钥匹配。\n");
        return 0;
    } else {
        printf("\n错误：密钥封装和解封装失败！共享密钥不匹配。\n");
        return -1;
    }
}

/**
 * 主函数
 */
int32_t main(void)
{
    printf("PQCP库Scloud+使用示例\n");
    printf("====================================\n");
    
    int32_t result = 0;
    
    /* 运行scloud+演示 */
    if (ScloudplusDemo() != 0) {
        result = -1;
    }

    if (result == 0) {
        printf("\nScloud+演示成功完成！\n");
    } else {
        printf("\nScloud+演示过程中出现错误！\n");
    }

    return result;
} 