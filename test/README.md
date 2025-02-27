# PQCP测试框架

PQCP测试框架是一个用于测试后量子密码算法库的综合性测试工具集。它包含了软件设计验证(SDV)测试、性能测试、模糊测试和示例程序。

## 目录结构

```
pqcp/test/
├── common/           # 通用测试框架代码
│   ├── pqcp_test.h   # 测试框架头文件
│   ├── pqcp_test.c   # 测试框架实现
│   ├── pqcp_perf.h   # 性能测试框架头文件
│   ├── pqcp_perf.c   # 性能测试框架实现
│   ├── pqcp_fuzz.h   # 模糊测试框架头文件
│   └── pqcp_fuzz.c   # 模糊测试框架实现
├── sdv/              # 软件设计验证测试
│   ├── kem/          # KEM算法测试
│   ├── sign/         # 签名算法测试
│   └── integration/  # 集成测试
├── perf/             # 性能测试
├── fuzz/             # 模糊测试
├── demo/             # 示例程序
├── script/           # 测试脚本
│   ├── build.sh      # 构建脚本
│   ├── run_sdv.sh    # 运行SDV测试脚本
│   ├── run_perf.sh   # 运行性能测试脚本
│   └── run_fuzz.sh   # 运行模糊测试脚本
├── CMakeLists.txt    # CMake构建文件
└── README.md         # 本文档
```

## 构建测试框架

使用以下命令构建测试框架：

```bash
cd pqcp/test
./script/build.sh
```

构建脚本支持以下选项：

- `--help, -h`: 显示帮助信息
- `--release`: 构建发布版本（默认为Debug）
- `--asan`: 启用AddressSanitizer
- `--gcov`: 启用代码覆盖率分析
- `--build-dir=<dir>`: 指定构建目录（默认为build）
- `--install-dir=<dir>`: 指定安装目录（默认为install）
- `--verbose`: 显示详细构建信息
- `--targets=<targets>`: 指定构建目标（可选值: all, sdv, perf, fuzz, demo）

例如，构建带有ASAN的调试版本：

```bash
./script/build.sh --asan
```

## 软件设计验证(SDV)测试

SDV测试用于验证PQCP库的功能正确性。它包含了KEM算法测试、签名算法测试和集成测试。

### 运行SDV测试

使用以下命令运行SDV测试：

```bash
./script/run_sdv.sh
```

运行脚本支持以下选项：

- `--help, -h`: 显示帮助信息
- `--output-dir=<dir>`: 指定输出目录（默认为output/sdv）
- `--verbose`: 显示详细测试信息
- `--list`: 列出所有可用的测试套件和测试用例

例如，运行KEM测试套件：

```bash
./script/run_sdv.sh kem
```

运行特定的测试用例：

```bash
./script/run_sdv.sh kem::scloudplus
```

### 添加新的SDV测试

要添加新的测试套件，请在`sdv`目录下创建新的子目录和测试文件，然后在`sdv/main.c`中注册测试套件初始化函数。

测试套件初始化函数示例：

```c
int init_my_test_suite(void) {
    /* 创建测试套件 */
    PqcpTestSuite *suite = PQCP_TestCreateSuite("my_suite", "我的测试套件");
    if (suite == NULL) {
        return -1;
    }
    
    /* 添加测试用例 */
    PQCP_TestAddCase(suite, "test_case1", "测试用例1", test_case1_func);
    PQCP_TestAddCase(suite, "test_case2", "测试用例2", test_case2_func);
    
    /* 添加测试套件到测试框架 */
    return PQCP_TestAddSuite(suite);
}
```

测试用例函数示例：

```c
static PqcpTestResult test_case1_func(void) {
    /* 测试实现 */
    
    /* 返回测试结果 */
    return PQCP_TEST_SUCCESS;  /* 或 PQCP_TEST_FAILURE, PQCP_TEST_SKIP, PQCP_TEST_ERROR */
}
```

## 性能测试

性能测试用于评估PQCP库的性能特性，包括吞吐量、延迟和资源使用情况。

### 运行性能测试

使用以下命令运行性能测试：

```bash
./script/run_perf.sh
```

运行脚本支持以下选项：

- `--help, -h`: 显示帮助信息
- `--output-dir=<dir>`: 指定输出目录（默认为output/perf）
- `--csv=<file>`: 指定CSV输出文件（默认为perf_results.csv）
- `--iterations=<num>`: 指定迭代次数
- `--verbose`: 显示详细测试信息
- `--list`: 列出所有可用的性能测试组

例如，运行KEM性能测试组，迭代1000次：

```bash
./script/run_perf.sh --iterations=1000 kem
```

### 添加新的性能测试

要添加新的性能测试组，请在`perf/perf_test.c`中添加新的测试函数，并在`init_perf_tests`函数中注册。

性能测试函数示例：

```c
static int run_my_perf_test(int iterations, int verbose, FILE *csv_file) {
    PerfResult result;
    
    /* 测试实现 */
    
    /* 打印和保存结果 */
    print_result(&result, verbose);
    write_csv_result(csv_file, &result);
    
    return 0;
}
```

注册性能测试组：

```c
int init_perf_tests(void) {
    /* 添加性能测试组 */
    add_perf_test_group("my_test", "我的性能测试", run_my_perf_test);
    
    return 0;
}
```

## 模糊测试

模糊测试用于发现PQCP库在处理异常输入时的潜在问题。

### 运行模糊测试

使用以下命令运行模糊测试：

```bash
./script/run_fuzz.sh
```

运行脚本支持以下选项：

- `--help, -h`: 显示帮助信息
- `--output-dir=<dir>`: 指定输出目录（默认为output/fuzz）
- `--iterations=<num>`: 指定迭代次数（默认为1000）
- `--seed=<num>`: 指定随机种子（默认为0，使用时间作为种子）
- `--verbose`: 显示详细测试信息
- `--list`: 列出所有可用的模糊测试目标

例如，运行KEM模糊测试，迭代10000次：

```bash
./script/run_fuzz.sh --iterations=10000 kem
```

### 添加新的模糊测试

要添加新的模糊测试目标，请在`fuzz/fuzz_test.c`中添加新的测试函数，并在`init_fuzz_tests`函数中注册。

模糊测试函数示例：

```c
static int fuzz_my_target(int iterations, unsigned int seed, int verbose, FILE *log_file) {
    /* 初始化随机数生成器 */
    init_random(seed);
    
    /* 测试实现 */
    
    return 0;
}
```

注册模糊测试目标：

```c
int init_fuzz_tests(void) {
    /* 添加模糊测试目标 */
    add_fuzz_target("my_target", "我的模糊测试目标", fuzz_my_target);
    
    return 0;
}
```

## 示例程序

示例程序展示了如何使用PQCP库的各种功能。

### 运行示例程序

示例程序位于`build/bin`目录下，可以直接运行：

```bash
./build/bin/scloudplus_demo
```

### 添加新的示例程序

要添加新的示例程序，请在`demo`目录下创建新的C文件，它将自动被CMake构建系统识别并构建。

## 测试框架API

测试框架提供了一组API，用于创建和运行测试。

### 通用测试框架API

```c
/* 测试框架初始化和清理 */
int pqcp_test_init(void);
void pqcp_test_cleanup(void);

/* 测试套件管理 */
PqcpTestSuite *PQCP_TestCreateSuite(const char *name, const char *description);
int PQCP_TestAddSuite(PqcpTestSuite *suite);
PqcpTestSuite *pqcp_test_find_suite(const char *name);
void pqcp_test_list_suites(void);

/* 测试用例管理 */
int PQCP_TestAddCase(PqcpTestSuite *suite, const char *name, const char *description, PqcpTestResult (*run)(void));
PqcpTestCase *pqcp_test_find_case(PqcpTestSuite *suite, const char *name);
void pqcp_test_list_cases(PqcpTestSuite *suite);

/* 测试执行 */
PqcpTestReport pqcp_test_run_case(PqcpTestSuite *suite, PqcpTestCase *test_case, int verbose);
PqcpTestReport pqcp_test_run_suite(PqcpTestSuite *suite, int verbose);
PqcpTestReport pqcp_test_run_all(int verbose);
PqcpTestReport pqcp_test_run_suite_by_name(const char *suite_name, int verbose);
PqcpTestReport pqcp_test_run_case_by_name(const char *suite_name, const char *case_name, int verbose);

/* 测试报告 */
void pqcp_test_print_report(const PqcpTestReport *report);
int pqcp_test_save_report(const PqcpTestReport *report, const char *filename);
```

### 性能测试框架API

```c
/* 运行性能测试 */
int pqcp_perf_run(
    const char *name,
    int (*setup_func)(void **user_data),
    int (*test_func)(void *user_data),
    void (*teardown_func)(void *user_data),
    const PqcpPerfConfig *config,
    void *user_data,
    PqcpPerfResult *result
);

/* 结果处理 */
void pqcp_perf_print_result(const PqcpPerfResult *result);
int pqcp_perf_write_csv(const PqcpPerfResult *result, const char *csv_file, int append);
```

### 模糊测试框架API

```c
/* 模糊测试数据管理 */
int pqcp_fuzz_init(PqcpFuzzData *fuzz_data, size_t size);
void pqcp_fuzz_free(PqcpFuzzData *fuzz_data);
int pqcp_fuzz_generate(PqcpFuzzData *fuzz_data, const PqcpFuzzConfig *config);
int pqcp_fuzz_mutate(PqcpFuzzData *fuzz_data, float mutation_rate);

/* 运行模糊测试 */
int pqcp_fuzz_run(
    int (*test_func)(const PqcpFuzzData *fuzz_data, void *user_data),
    const PqcpFuzzConfig *config,
    void *user_data
);

/* 文件操作 */
int pqcp_fuzz_load_from_file(PqcpFuzzData *fuzz_data, const char *file_path);
int pqcp_fuzz_save_to_file(const PqcpFuzzData *fuzz_data, const char *file_path);
```

## 测试输出

测试结果将保存在指定的输出目录中：

- SDV测试结果: `output/sdv/`
- 性能测试结果: `output/perf/`
- 模糊测试结果: `output/fuzz/`

每种测试都会生成相应的日志文件和报告文件。 