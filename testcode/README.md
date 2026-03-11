# PQCP 测试框架

PQCP测试框架遵循 OpenHiTLS 测试标准，采用统一的测试代码结构和数据文件格式。

## 目录结构

```
pqcp/testcode/
├── sdv/                    # 软件设计验证(SDV)测试
│   ├── scloudplus/         # SCloud+ KEM算法测试
│   │   ├── test_suite_sdv_pqcp_scloudplus.c      # 测试代码
│   │   └── test_suite_sdv_pqcp_scloudplus.data   # 测试数据
│   ├── polarlac/           # Polarlac KEM算法测试
│   │   ├── test_suite_sdv_pqcp_polarlac.c
│   │   └── test_suite_sdv_pqcp_polarlac.data
│   └── composite_sign/     # 复合签名算法测试
│       ├── test_suite_sdv_pqcp_composite_sign.c
│       └── test_suite_sdv_pqcp_composite_sign.data
├── testdata/               # 测试数据文件
│   └── scloudplus/
│       └── scloudplus_testvector/   # 标准测试向量
└── README.md               # 本文档
```

## 测试框架规范

### 1. 测试文件命名规范

测试代码文件：`test_suite_sdv_<module>_<feature>.c`
测试数据文件：`test_suite_sdv_<module>_<feature>.data`

例如：
- `test_suite_sdv_pqcp_scloudplus.c`
- `test_suite_sdv_pqcp_scloudplus.data`

### 2. 测试代码结构

测试代码使用 OpenHiTLS 标准格式：

```c
/* BEGIN_HEADER */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "securec.h"
#include "bsl_sal.h"
#include "pqcp_err.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_provider.h"
/* END_HEADER */

/* @
* @test  SDV_CRYPTO_PQCP_<FEATURE>_TC001
* @spec  -
* @title  测试标题
* @precon  nan
* @brief  1. 测试步骤1
*         2. 测试步骤2
* @expect  期望结果
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_<FEATURE>_TC001(int bits)
{
    TestMemInit();
    // 测试实现
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, algId,
        CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    // ... 测试逻辑

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */
```

### 3. 测试数据文件格式

测试数据文件采用两行的格式：

```
TEST_NAME Description
TEST_NAME:param1:param2:...
```

示例：
```
SDV_CRYPTO_PQCP_SCLOUDPLUS_KEYGEN_API_TC001 SCloud+ 128-bit
SDV_CRYPTO_PQCP_SCLOUDPLUS_KEYGEN_API_TC001:128

SDV_CRYPTO_PQCP_SCLOUDPLUS_VECTOR_TC001 SCloud+ 128-bit
SDV_CRYPTO_PQCP_SCLOUDPLUS_VECTOR_TC001:128:"D20C193C...":"203E865F...":"DC473FB2...":"561CCBC4...":"44C004C0...":"68D056D1...":"92689FB7..."
```

参数类型：
- `int` - 直接写数字，如 `128`
- `Hex*` - 十六进制字符串，用双引号包围，如 `"D20C193C..."`
- `char*` - 字符串，用双引号包围

### 4. 常用测试模式

#### 4.1 API测试

测试基本API功能：

```c
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_<MODULE>_API_TC001(int bits)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_xxx,
        CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    ASSERT_TRUE(ctx != NULL);

    // 设置参数
    uint32_t val = (uint32_t)bits;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, PQCP_SUCCESS);

    // 执行操作
    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, PQCP_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */
```

对应数据文件：
```
SDV_CRYPTO_PQCP_<MODULE>_API_TC001 <Module> 128-bit
SDV_CRYPTO_PQCP_<MODULE>_API_TC001:128
```

#### 4.2 向量测试

使用标准测试向量验证算法正确性：

```c
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_<MODULE>_VECTOR_TC001(int bits, Hex *alpha, Hex *randZ,
    Hex *randM, Hex *expPk, Hex *expSk, Hex *expCipher, Hex *expSharedKey)
{
    TestMemInit();
    // 设置随机数回调
    CRYPT_EAL_SetRandCallBack(TEST_<Module>Random);

    // 复制测试向量到全局缓冲区
    memcpy_s(gRandBuf[1], 64, alpha->x, alpha->len);
    memcpy_s(gRandBuf[0], 64, randZ->x, randZ->len);
    memcpy_s(gRandBuf[2], 64, randM->x, randM->len);

    // 创建上下文并测试
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_xxx,
        CRYPT_EAL_PKEY_KEM_OPERATE, "provider=pqcp");
    ASSERT_NE(ctx, NULL);

    // ... 执行KeyGen, Encaps, Decaps并验证结果

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */
```

对应数据文件：
```
SDV_CRYPTO_PQCP_<MODULE>_VECTOR_TC001 <Module> 128-bit
SDV_CRYPTO_PQCP_<MODULE>_VECTOR_TC001:128:"alpha_hex":"randZ_hex":"randM_hex":"pk_hex":"sk_hex":"cipher_hex":"sharedkey_hex"
```

### 5. 常用断言宏

- `ASSERT_TRUE(expr)` - 断言表达式为真
- `ASSERT_FALSE(expr)` - 断言表达式为假
- `ASSERT_EQ(a, b)` - 断言相等
- `ASSERT_NE(a, b)` - 断言不相等
- `ASSERT_COMPARE(msg, buf1, len1, buf2, len2)` - 比较两个缓冲区

### 6. Provider 初始化

每个测试函数开始前需要初始化 provider：

```c
TestMemInit();
ASSERT_EQ(TestPqcpProviderLoad(), 0);  // 加载 PQCP provider
```

## 添加新的测试用例

### 步骤1：在 .c 文件中添加测试函数

```c
/* @
* @test  SDV_CRYPTO_PQCP_<MODULE>_NEWTEST_TC001
* @spec  -
* @title  新测试用例
* @precon  nan
* @brief  1. 步骤1
*         2. 步骤2
* @expect  期望结果
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_PQCP_<MODULE>_NEWTEST_TC001(int bits)
{
    TestMemInit();
    ASSERT_EQ(TestPqcpProviderLoad(), 0);

    // 测试代码

EXIT:
    return;
}
/* END_CASE */
```

### 步骤2：在 .data 文件中添加测试数据

```
SDV_CRYPTO_PQCP_<MODULE>_NEWTEST_TC001 新测试描述
SDV_CRYPTO_PQCP_<MODULE>_NEWTEST_TC001:128
```

### 步骤3：构建和运行测试

```bash
cd /path/to/pqcp/testcode/script

# 重新构建测试
bash ./build_pqcp_sdv.sh

# 运行测试
bash ./execute_sdv.sh
```