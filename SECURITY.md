# Security Policy

Canonical URL: https://gitcode.com/openHiTLS/pqcp/blob/main/SECURITY.md

If this English text and the Chinese translation below disagree, the English text is authoritative.

Code from this repository that ships inside an openHiTLS release is covered by the [openHiTLS security policy](https://gitcode.com/openHiTLS/openhitls/blob/main/SECURITY.md). Report those issues through [openHiTLS vulnerability management](https://www.openhitls.net/zh/support/vulnerability-management.html).

## Supported versions

Only the current `main` branch is supported. There is no stable release branch and no security backport.

## Scope

PQCP is an incubation repository for non-standardized algorithms. Parameters, wire formats, and security analyses may change without notice and may be incompatible across versions.

This repository does not give a constant-time or side-channel guarantee. An implementation that documents its own testing or non-constant-time behavior is limited to what that note says. Fuzzing and audit coverage are incomplete.

We do not recommend using this code in a production environment or to protect sensitive data. It is for research, prototyping, and interoperability testing.

## Reporting

Support is best-effort. There is no SLA, no response-time guarantee, and no backport. In-scope private reports are acknowledged. A fix, an investigation, or an individual write-up is not guaranteed.

Report these privately, through [openHiTLS vulnerability management](https://www.openhitls.net/zh/support/vulnerability-management.html):

- memory safety on paths that handle attacker-controlled input
- leakage of key material or other secrets
- cryptographic correctness failures, including signature forgery, verification bypass, and KEM decapsulation that accepts an invalid ciphertext

Open a public issue for:

- the implementation lagging a draft specification
- behavior an implementation already documents as not constant-time
- a scanner finding that only restates the limitations in this file

Defects in algorithm code that openHiTLS has already shipped belong to the openHiTLS policy. Reports that only belong there will be redirected.

## 中文译本

规范地址：https://gitcode.com/openHiTLS/pqcp/blob/main/SECURITY.md

中文与英文不一致时，以英文为准。

进入 openHiTLS 发布物的代码，适用 [openHiTLS 安全政策](https://gitcode.com/openHiTLS/openhitls/blob/main/SECURITY.md)。此类问题通过 [openHiTLS 漏洞管理](https://www.openhitls.net/zh/support/vulnerability-management.html) 报告。

### 支持版本

只支持当前 `main`。没有稳定分支，也不做安全补丁回移。

### 范围

PQCP 是非标准算法的孵化仓。参数、线格式和安全分析可能随时变更，版本之间不保证兼容。

本仓库不提供常数时间或侧信道保证。某个实现如果自行写明测试情况或非常数时间行为，以该说明为限。模糊测试和审计覆盖不完整。

不建议在生产环境中依赖本仓库，也不建议用它保护敏感数据。用途是研究、原型和互通测试。

### 报告

尽力处理。没有服务级别协议，没有响应时限，没有补丁回移。范围内的私密报告会确认收到。不保证修复、调查或逐项书面回复。

下列问题请通过 [openHiTLS 漏洞管理](https://www.openhitls.net/zh/support/vulnerability-management.html) 私下报告：

- 处理攻击者可控输入时的内存安全问题
- 密钥或其他秘密泄漏
- 密码学正确性错误，包括签名伪造、验签绕过，以及 KEM 解封装接受非法密文

下列问题请开公开 issue：

- 实现没有跟上草案规范
- 实现已经写明的非常数时间行为
- 扫描结果只是在重复本文件已经声明的限制

openHiTLS 已经发布的算法代码中的缺陷，适用 openHiTLS 的政策。只属于那里的报告会被转过去。
