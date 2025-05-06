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
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "securec.h"
#include "pqcp_test.h"
#include "crypt_eal_pkey.h"
#include "pqcp_provider.h"
#include "pqcp_types.h"
#include "crypt_errno.h"

// 结构体解析增强
typedef struct {
    uint8_t *alpha;
    uint32_t alphaLen;
    uint8_t *randZ;
    uint32_t randZLen;
    uint8_t *sk;
    uint32_t skLen;
    uint8_t *pk;
    uint32_t pkLen;
    uint8_t *cipher;
    uint32_t cipherLen;
    uint8_t *randM;
    uint32_t randMLen;
    uint8_t *sharekey1;
    uint32_t sharekey1Len;
    uint8_t *sharekey2;
    uint32_t sharekey2Len;
    uint32_t key_bits; // 新增字段保存密钥位数
    uint32_t times;
} PQCP_SCLOUDPLUS_TestVector;

// 实现hex转bin函数
static uint8_t* hex2bin(const char *hexstr, size_t *outlen)
{
    size_t len = strlen(hexstr);
    if (len % 2 != 0) return NULL;
    
    *outlen = len / 2;
    uint8_t *bin = malloc(*outlen);
    if (!bin) return NULL;

    for (size_t i = 0; i < *outlen; i++) {
        if (sscanf(hexstr + i*2, "%2hhx", &bin[i]) != 1) {
            free(bin);
            return NULL;
        }
    }
    return bin;
}

// 实现.data文件解析
PQCP_SCLOUDPLUS_TestVector* ParseScloudPlusTestVector(const char *data_path)
{
    int fd = open(data_path, O_RDONLY);
    if (fd == -1) {
        perror("打开测试向量文件失败");
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
        return NULL;
    }

    char *data = malloc(st.st_size + 1);
    if (data == NULL) {
        close(fd);
        return NULL;
    }

    if (read(fd, data, st.st_size) != st.st_size) {
        free(data);
        close(fd);
        return NULL;
    }
    data[st.st_size] = '\0';
    close(fd);

    PQCP_SCLOUDPLUS_TestVector *tv = calloc(1, sizeof(*tv));
    if (tv == NULL) {
        free(data);
        return NULL;
    }

    char *line = strtok(data, "\n");
    while (line != NULL) {
        // 分割键值对
        char *sep = strchr(line, ':');
        if (sep == NULL) {
            line = strtok(NULL, "\n");
            continue;
        }
        
        *sep = '\0';
        char *key = line;
        char *value = sep + 1;

        // 去除值中的引号
        if (*value == '"') value++;
        if (value[strlen(value)-1] == ',') value[strlen(value)-1] = '\0';
        if (value[strlen(value)-1] == '"') value[strlen(value)-1] = '\0';

        // 解析字段
        size_t len;
        uint8_t **target = NULL;
        uint32_t *targetLen = NULL;
        
        if (strcmp(key, "\"alpha\"") == 0) {
            target = &tv->alpha;
            targetLen = &tv->alphaLen;
        } else if (strcmp(key, "\"randz\"") == 0) {
            target = &tv->randZ;
            targetLen = &tv->randZLen;
        } else if (strcmp(key, "\"sk\"") == 0) {
            target = &tv->sk;
            targetLen = &tv->skLen;
        } else if (strcmp(key, "\"pk\"") == 0) {
            target = &tv->pk;
            targetLen = &tv->pkLen;
        } else if (strcmp(key, "\"randm\"") == 0) {
            target = &tv->randM;
            targetLen = &tv->randMLen;
        } else if (strcmp(key, "\"ciphertext\"") == 0) {
            target = &tv->cipher;
            targetLen = &tv->cipherLen;
        } else if (strcmp(key, "\"sharekey1\"") == 0) {
            target = &tv->sharekey1;
            targetLen = &tv->sharekey1Len;
        } else if (strcmp(key, "\"sharekey2\"") == 0) {
            target = &tv->sharekey2;
            targetLen = &tv->sharekey2Len;
        }
        if (target != NULL) {
            *target = hex2bin(value, &len);
            if (!*target) goto ERR;
            *targetLen = len;
            // 根据sk长度推断密钥位数
            if (target == &tv->sharekey1) {
                tv->key_bits = len * 8;
            }
        }

        line = strtok(NULL, "\n");
    }

    
    // 验证必须字段
    if (!tv->alpha || !tv->randZ || !tv->sk || !tv->pk || 
        !tv->cipher || !tv->sharekey1 || !tv->sharekey2) {
        goto ERR;
    }
        
    free(data);
    return tv;

ERR:
    free(data);
    if (tv) {
        free(tv->alpha);
        free(tv->randZ);
        free(tv->sk);
        free(tv->pk);
        free(tv->randM);
        free(tv->cipher);
        free(tv->sharekey1);
        free(tv->sharekey2);
        free(tv);
    }
    return NULL;
}

// 释放函数
void FreeScloudPlusTestVector(PQCP_SCLOUDPLUS_TestVector *tv) {
    if (tv) {
        free(tv->alpha);
        free(tv->randZ);
        free(tv->sk);
        free(tv->pk);
        free(tv->randM);
        free(tv->cipher);
        free(tv->sharekey1);
        free(tv->sharekey2);
        free(tv);
    }
}

static PQCP_SCLOUDPLUS_TestVector *g_tv = NULL;

int32_t RandFuncCbk(uint8_t *rand, uint32_t randLen)
{
    switch(g_tv->times) {
        case 0:
        (void)memcpy_s(rand, randLen, g_tv->randZ, g_tv->randZLen);
            g_tv->times++;
            return 0;
        case 1:
            (void)memcpy_s(rand, randLen, g_tv->alpha, g_tv->alphaLen);
            g_tv->times++;
            return 0;
        case 2:
            (void)memcpy_s(rand, randLen, g_tv->randM, g_tv->randMLen);
            g_tv->times = 0;
            return 0;
        default:
            return -1;
    }
}

int32_t TestGen(CRYPT_EAL_PkeyCtx *ctx, PQCP_SCLOUDPLUS_TestVector *tv)
{
    uint8_t pubdata[37520/2];
    uint8_t prvdata[43808/2];
    int32_t ret = CRYPT_EAL_PkeyGen(ctx);
    if (ret != CRYPT_SUCCESS) {
        printf("密钥生成失败\n");
        return ret;
    }
    BSL_Param pub[2] = {
        {CRYPT_PARAM_SCLOUDPLUS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubdata, sizeof(pubdata), 0},
        BSL_PARAM_END
    };
    BSL_Param prv[2] = {
        {CRYPT_PARAM_SCLOUDPLUS_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvdata, sizeof(prvdata), 0},
        BSL_PARAM_END
    };
    ret = CRYPT_EAL_PkeyGetPrvEx(ctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        printf("获取私钥失败\n");
        return ret;
    }
    ret = CRYPT_EAL_PkeyGetPubEx(ctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        printf("获取公钥失败\n");
        return ret;
    }
    if (pub[0].useLen != g_tv->pkLen || prv[0].useLen != g_tv->skLen) {
        printf("密钥生成长度不符合预期\n");
        return ret;
    }
    if (memcmp(pubdata, g_tv->pk, g_tv->pkLen) != 0 || memcmp(prvdata, g_tv->sk, g_tv->skLen) != 0) {
        printf("密钥生成不符合预期\n");
        return ret;
    }
    return 0;
}

CRYPT_EAL_PkeyCtx *TestEncapsCtx(CRYPT_EAL_PkeyCtx *ctx, PQCP_SCLOUDPLUS_TestVector *tv)
{
    CRYPT_EAL_PkeyCtx *deCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SCLOUDPLUS, 
        CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    if (deCtx == NULL) {
        printf("密钥生成失败\n");
        return NULL;
    }
    // 设置密钥位数
    int32_t ret = CRYPT_EAL_PkeyCtrl(deCtx, PQCP_SCLOUDPLUS_KEY_BITS, &tv->key_bits, sizeof(tv->key_bits));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(deCtx);
        printf("设置密钥位数失败\n");
        return NULL;
    }
    uint8_t pubdata[37520/2];
    BSL_Param pub[2] = {
        {CRYPT_PARAM_SCLOUDPLUS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubdata, sizeof(pubdata), 0},
        BSL_PARAM_END
    };

    ret = CRYPT_EAL_PkeyGetPubEx(ctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(deCtx);
        printf("获取公钥失败\n");
        return ret;
    }
    pub[0].valueLen = pub[0].useLen;
    ret = CRYPT_EAL_PkeySetPubEx(deCtx, &pub);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(deCtx);
        printf("获取公钥失败\n");
        return NULL;
    }

    return deCtx;
}

PqcpTestResult TestScloudPlusEncapsDecaps(const char *data_path)
{
    if (g_tv != NULL) {
        sleep(3);
        if (g_tv != NULL) {
            return PQCP_TEST_SKIP;
        }
    }
    // 加载测试向量
    g_tv = ParseScloudPlusTestVector(data_path);
    if (!g_tv) {
        printf("加载测试向量失败\n");
        return PQCP_TEST_FAILURE;
    }
    CRYPT_EAL_SetRandCallBack(RandFuncCbk);
    uint32_t sharekeyLen = 32;
    uint8_t sharekey[32];
    uint32_t sharekey2Len = 32;
    uint8_t sharekey2[32];
    uint32_t cipherLen = 33832/2;
    CRYPT_EAL_PkeyCtx *enCtx = NULL;
    int32_t ret;
    uint8_t *cipher = malloc(cipherLen);
    if (cipher == NULL) {
        return PQCP_TEST_FAILURE;
    }
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SCLOUDPLUS, 
                                                        CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    if (ctx == NULL) {
        printf("创建句柄失败\n");
        goto EXIT;
    }
    // 设置密钥位数
    ret = CRYPT_EAL_PkeyCtrl(ctx, PQCP_SCLOUDPLUS_KEY_BITS, &g_tv->key_bits, sizeof(g_tv->key_bits));
    if (ret != CRYPT_SUCCESS) {
        printf("设置密钥位数失败\n");
        goto EXIT;
    }
    ret = TestGen(ctx, g_tv);
    if (ret != CRYPT_SUCCESS) {
        printf("密钥生成失败\n");
        goto EXIT;
    }
    enCtx = TestEncapsCtx(ctx, g_tv);
    if (enCtx == NULL) {
        printf("decaps ctx 失败\n");
        ret = PQCP_TEST_FAILURE;
        goto EXIT;
    }
    ret = CRYPT_EAL_PkeyEncaps(enCtx, cipher, &cipherLen, sharekey, &sharekeyLen);
    if (ret != 0) {
        printf("封装失败\n");
        goto EXIT;
    }
    // if (sharekeyLen != g_tv->sharekey1Len || memcmp(sharekey, g_tv->sharekey1, sharekeyLen) != 0) {
    //     printf("共享密钥不匹配\n");
    //     ret = PQCP_TEST_FAILURE;
    //     goto EXIT;
    // }
    // if (cipherLen != g_tv->cipher || memcmp(cipher, g_tv->cipher, cipherLen) != 0) {
    //     printf("cipher不匹配\n");
    //     ret = PQCP_TEST_FAILURE;
    //     goto EXIT;
    // }
    // 执行解封装
    ret = CRYPT_EAL_PkeyDecaps(ctx, cipher, cipherLen, sharekey2, &sharekey2Len);
    // 验证结果
    if (ret != 0) {
        printf("解封装结果不匹配\n");
        goto EXIT;
    }
    if (sharekeyLen != sharekey2Len || memcmp(sharekey, sharekey2, sharekeyLen) != 0) {
        printf("共享密钥不匹配\n");
        ret = PQCP_TEST_FAILURE;
    }
EXIT:
    CRYPT_EAL_SetRandCallBack(NULL);
    FreeScloudPlusTestVector(g_tv);
    g_tv = NULL;
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(enCtx);
    free(cipher);
    if (ret != 0) {
        return PQCP_TEST_FAILURE;
    }
    return PQCP_TEST_SUCCESS;
}