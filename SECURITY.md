# Security Policy

## Statement: Experimental Software — Not Recommended for Production Use

PQCP (Pioneer Quotable Crypto Provider) provides **prototype implementations**
of post-quantum and next-generation cryptographic algorithms.

Everything in this repository is **experimental**:

- The code in this repository is **prototype code**. We make a **best effort**
  to avoid security bugs.
- Implementations may **not track the latest revision** of the underlying
  algorithm specifications.
  Parameters, wire formats, and security analyses may change at any time
  without notice, and may be incompatible across versions.
- Code here is **not hardened to production grade**: constant-time guarantees,
  side-channel countermeasures, fuzzing depth, and audit coverage are
  incomplete or unverified.
- Vulnerability reports against this repository — including findings from
  external or automated security scans and requests for explanations —
  should be interpreted in the above context. Such findings are welcome and
  will be considered on a **best-effort basis**; no security support
  commitment, service-level agreement, or backport guarantee applies to
  this code, and we do not guarantee acknowledgement, investigation,
  remediation, a timeline, or an individual response.

**This code is not recommended for production systems, products, or any
deployment where security matters.** Use a mature, standardized, and audited
implementation instead. This repository is intended only for research,
evaluation, interoperability testing, and technical exploration.

---

## 声明：实验性质软件——不推荐用于生产环境

PQCP（Pioneer Quotable Crypto Provider）提供后量子及新一代密码算法的**原型实现**。

本仓库中的一切代码均为**实验性质**：

- 本仓库代码均为**原型实现**。我们尽力避免安全问题。
- 实现**未必跟进算法规范草案的最新修订版本**。参数、编码格式与安全分析可能
  随时变更，且各版本之间不保证兼容。
- 本仓库代码**未达到生产级加固水平**：常数时间保证、侧信道防护、模糊测试
  深度与安全审计覆盖均不完整或未经充分验证。
- 针对本仓库的漏洞报告——包括外部或自动化安全扫描的发现及要求解释说明的
  请求——应结合上述背景理解。我们欢迎相关发现并按**尽力而为（best-effort）**
  原则评估处理；本仓库代码不适用任何安全支持承诺、服务级别协议（SLA）或
  补丁回移保证，亦不保证确认收悉、调查、修复、处理时限或逐项回复。

**不推荐在生产系统、产品或安全敏感部署中使用本仓库代码。**如需使用
相关算法，请选择成熟、已标准化且经审计的实现。本仓库仅供研究、评估、互通
性测试与技术探索使用。
