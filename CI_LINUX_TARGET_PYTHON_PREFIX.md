# 原始 iOS C 前置任务 CI

此工作流只执行 R00-02J9 的原始 SDK、toolchain、mockrt、MetalANGLE 安装与静态 C 前置任务。首轮手动调度 Ubuntu 22.04，覆盖 8.3.7 和 7.8.7 的三个架构。24.04 能力绑定各自原 producer，可随后单独调度。成功也不代表 target Python install、pip、生产 shared dylib、G1/G2 或 Reko 会话通过。

编排与 worker 从 Reko 已提交原件部署；增量包七件来自提交 `6828f4d6f92990b44841ee253e61c6fdb9e9df0b`，总原字节 313190，固定归档 73258 字节、SHA256 `bce012d0b0c9eaf6641d799111fd119e29840fc4712a2ff0e73be02de6a47a7b`，归档名 `j9-c-prefix-runtime-addon-20261102-02.tar.gz`。原 H0 包、H1 CAS 包和已实测 host 分发不重打包。H1 原 ZIP 必须匹配独立 API 大小与完整摘要；两组分别使用计划中的原 producer。

SDK 使用既有发布的加密原件；解密前核密文大小/SHA，解密后核明文大小/SHA及既有 SHA 秘密。AES256CBC/PBKDF2-SHA256/200000/salt8 的密码只通过宿主 stdin，不放 argv 或子进程环境。SDK 与 H0 密码不会发送到构建容器。所有实际 C 任务在固定 C1 同一容器内执行，容器无网络、无宿主挂载、非 privileged；保留原 unshare 的受控 capability 设置。

原任务执行顺序及原 argv 保留。mockrt 是原完整 LDFLAGS 所需的唯一先行 bootstrap。MetalANGLE framework 片段仅从 CFLAGS/CXXFLAGS 移到 LDFLAGS；LLVM15 历史组只补明确平台链接参数。原/候选 driver 必须真实验证，随后才能运行其余 C 家族。失败保存原始 stdout/stderr、config.log 等日志，无成功收据。完整安装前缀回传后逐成员、逐静态库对象检查 CPU、平台、SDK 和部署目标，不执行回传二进制。

完整 SDK 编译诊断和产物只进入 `private-diagnostics`。工作流先实际测试 Linux CMS 的无害 roundtrip、篡改拒绝和公开接收证书加密，再开始源码构建。最终以 CMS AuthEnvelopedData AES256GCM、RSA3072 OAEP-SHA256/MGF1-SHA256、DER 加密完整私有诊断。CI 只有公开证书 `tools/j9-diagnostics-recipient.pem`，SHA256 `db7c3cb23532bf02e51e24ae085fa14049658833469479b75981a1cd574f94f8`；私钥仅保留在本地忽略目录，不提交、不上传。

公开 artifact 白名单只有 `public-summary.json`、前置失败时的 `workflow-status.json`、`cms-selftest.json`、`private-diagnostics.cms` 和登记完整密文/明文字节身份及成员身份的 `private-diagnostics-identity.json`，封装失败时另有固定状态 `diagnostics-transport-status.json`。原始目录和 SDK 原文不能作为 artifact 上传。密文和身份均在私有临时目录完整形成后才发布；异常与超时均不上传部分密文。始终先加密，再清理受控容器、SDK、H1 ZIP 与私有临时输入，最后上传白名单。原诊断目录仅在完整密文再次匹配身份后删除；封装失败保留 runner 私有原诊断并明确记不可取回，不能声称证据已归档。原构建失败状态继续保持红色。

本地取回时先核 GitHub 原 artifact ZIP 的完整 API 摘要/大小，再安全解包白名单，核密文身份。使用已保留的私钥解密到全新私有临时文件；只有 CMS 返回成功且完整明文身份一致后才读取或安全解包。解密失败可能留下部分文件，必须删除该临时文件；保留原密文用于调查。后续独立复核与验收状态由主项目记录，不将工具测试或注册跳过运行计作源码通过。

构建队列按分支和固定 Ubuntu 组分别隔离，同组仍串行且不取消运行中任务。不同组各自独立的容器、APT、host producer 与 artifact 名可以同时推进；同一工作区修改及集成由主代理串行控制。初始历史组与现代组的既有运行保留其原候选与结果。

后续候选按 arm64、sim-arm64、sim-x86_64 三个独立作业验证，每次最多并行三个，失败不取消其他架构；同架构内两route仍在同一固定C1生命周期按原Task顺序执行。每个artifact名称明确Ubuntu组/架构/run/attempt，验收必须聚合三个完整原ZIP的实际cell，缺失或失败不补齐成功。原串行候选及其失败保留原身份。

第二轮诊断后的明确修复：原driver命令成功但SDK元数据拒绝会完整记原失败后继续既定candidate；候选可执行仍严格SDK14。原bzip2两链接已有LDFLAGS，但Makefile的LDFLAGS=覆盖环境，历史派生Makefile仅该一行改?=并保留原/派生SHA与补丁；四已证内部绝对alias经原脚本字节核对后规范为同目录相对link，未知/外部/错误内部仍拒绝。修复21项回归与完整43件fresh根验证仅为工具验收，实际C须新运行；原01包和两失败运行不重标。

增量02发布原件 asset702126156，GitHub API返回73258字节和SHA256 bce012d0b0c9eaf6641d799111fd119e29840fc4712a2ff0e73be02de6a47a7b，与本地完整归档一致。
