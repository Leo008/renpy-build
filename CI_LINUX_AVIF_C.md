# 原 C → NASM / AVIF 八任务首次 Linux CI

本工作流对应 `R00-02J11V1`，只允许 Ubuntu 24.04 / Ren’Py 8.5.3 / sim-arm64 一个先导。`workflow_dispatch` 没有版本或架构输入，三个值写死并再次核验；没有矩阵，也不调用 image/font 控制器的生命周期。工具的四路线支持不代表工作流已运行其它十一 tuple。

## 已提交控制与实际输入

- V1 原源码提交：`ce638e8979ed34bd61bc3532a6e704d642884b68`。部署路径为 `tools/ci_linux_avif_c_tasks.py`（87,970 B，SHA-256 `87c61b193a394a9189afb70fcbd43c1cee90eae0c1a23cb55b1f16a132a706ed`）和 `tools/linux-avif-c-ci-plan.json`（11,420 B，`7446f064fffa951647dcd5bb0636c955f4aebfbc971181de493f8ab175a03cf2`）。部署必须保持 Git blob 原字节。
- fork 两工具已在实际提交 `0a6b1033c3adb6c91d2fe5029c2dc3c5c58c6f43` 保持上述原字节；本工作流身份检查不依赖未来提交号。
- V0 原八任务消费者提交：`03a0f60dec9125665683a9126a2cf9941f8157dc`。source 85,648 B / `26ae9ec0d79a7fe45131310af685a160008ebf55d86470be2e02b01434c6edc9`；plan 63,078 B / `2597b2a551e04e6c70ff444b18b4e2a9d67364995721ed8f388e397b28e00bbe`。
- 十五文本包：Release `406525604`，tag `ci-inputs-8.5.3-20261008`，实际 asset **706653203**，名称 `j11-avif-runtime-addon-20261104-02.tar.gz`，203,456 B / `7c858b01c4003c2d9ba9d0265fd821884eeee4a5f8237d9307b444d4c3736852`。15 个平铺 USTAR `0644` 原件，合计 989,653 B；仅 V0 两文本相对历史 01 包改变，另十三件逐字节不变。下载前核 Release/asset API 的 ID、名称、长度、digest、上传状态及固定下载 URL，下载后重核完整包及全部成员。
- 原十七件依赖保持 SDL 原工作流的强 SHA；加 V1 两件后固定 **19 pins**。其中含原 D、I1D 的宿主准备基础、既有 replay/host 工具和计划、公开 CMS 证书及原有 clang runtime。原 D / I1D 的 main、handoff、旧 image/font 消费周期均不被调用。
- 原完整 APT 分发、H1 ZIP、C03、H0 密文、CAS 和 SDK 密文沿既有固定身份。H1 必须同时通过原 artifact API、run ID、完整 ZIP 长度和 SHA；不从最新成功运行或同名资产猜选。

原生产闭包仍为只读 43 件。唯一物理消费根由既有 pure API 建成 50 件，再加 V0 source/plan 和四份原源码消费文本成为 **56 件：35 scripts + 21 外部 metadata**；原两 C 文本仅在新消费根升级，新增十三件如实记录。原 `runtime-lock.json`（36,693 B / `e26aa71cdefa8adbd17ab20542726539daac72984f1388c6aa7dd5346518af7c`）继续来自原 43，两根都逐 bytes/SHA 核验；它没有塞入十五文本包。最初 34/35 漏项失败和 01 输入包保留为历史记录，修复后真实 43→56 / fresh V0 / 十一 C 函数投影门禁已通过，这些只证明文本闭包，不证明 NASM/AVIF 编译。

## 固定源码缓存与同一 C1 执行

工作流只创建本 job 自有 `$RUNNER_TEMP/reko-j11-avif-inputs-cache/source-cache`，以 `--source-cache` 交给 V1。此目录是唯一宿主源码缓存；V1 从已认证原 43 中的 `remote-sources.lock.json` 选择固定 libyuv、AOM、libavif 三源，使用原 `materialize_source_inputs` 的完整归档/补件/commit/tree 核验。缺件只可从该原锁的官方 URL 或已嵌入 commit 记录取得；输入坏 SHA 不会被联网覆盖。`GH_TOKEN` 不传入 worker 或 C1。

NASM 2.14.02 原包仍是 J1 CAS 中 `source/nasm-2.14.02.tar.gz` 的实际 **plain tar**，不会改名、重包或按后缀误认压缩格式。C1 只接收三源原包、原 commit 记录及必要补件的精确文件集合，逐全 SHA 验证；容器内部离线，没有任意下载或其它源码版本回退。三个下载函数只调用已冻结原 `consume_download`，没有把 J8 全七源 `bind_sources` 伪造成三源成功。四小输入视图来自完整 J1 已验模块及补丁，不能冒充第二完整 Git 工作树。

同一个 `open_environment` 内，原 D 只执行当前单 tuple 的 fresh C；原完整 C 宿主 reader 真通过后才建立外部 SHA/run/nonce/inode 交接并调用 V0。随后原 NASM host unpack/build、libyuv/AOM/libavif 各 download/build 共八个 `Task.run` 依序执行，原函数体、flags、registry、annotators 和 fallback 保持冻结。NASM 必须安装到原 `tmp/host`；完整 H1 原成员保护之外，仅允许两个工具与两份原手册的精确新增 delta。C1 的固定镜像、无网络、无宿主 mount、非 privileged 及原已批准的 `CAP_SYS_ADMIN` / seccomp 合同由原门禁复核，没有额外放宽。

## 返回验收与有限摘要

原 C 导出保留；V0 全部新私有原件有界返回后，由独立宿主进程静态读验：完整最终 prefix / 三份 ar 的每个对象和外部定义符号发生项、32 份原安装头、实际 CMakeCache 与原 generator 控制文件、decoder-only 配置、同 prefix AOM/libyuv 依赖、八原任务命令及 start/exit JSONL、原 source 和四输入视图、NASM 完整 H1 delta / 两份返回 ELF / 版本 stdout 或 stderr / 实际配置及 ELF assembler 探针。返回 ELF 和目标 MachO 都不在宿主执行。

Ninja 展开命令和旧 Unix Makefile recipe 各按原格式验证，只称生成规则来源，不称实际观察到逐条 assembly argv。无平台/minimum/SDK load command 的原 NASM MachO 例外只存在于 AOM sim-x86_64 的精确工具/源码/规则/对象对应合同，字段保留 **null**，不能补写 iOS14 标签；本轮 sim-arm64 没有采用该例外。系统 ELF 依赖按认证 C0 包/版本/架构及原 readelf 图复核，SDK/H1 或系统依赖已清理后的 raw 不声称在 Mac 重算。

公开摘要只读取固定小报告并逐字段筛选；退出 0、实际 scope、19 pins、43/56、三库、32 头、全部 reader 证明和父子清理缺一就不能置阶段通过。原 report、返回成员清单、源码证明、完整日志、ELF 和编译产物不直接搬入公开摘要。`ROOT_independent_acceptance_completed` 始终为 false，CI success 后仍须原 ZIP/API/CMS 全身份和本机静态验收。共享 provider、G1/G2、R00、引擎整编译、pip/Python 安装和 iOS 会话均为 false，人工/真机继续延期。

## 六小时截止、私密运输和回收

先查询本次真实 run/attempt/job 的 `started_at`，据此计算 21,600 秒绝对截止时间，不能以当前时间补默认值。V1 的准备、C、V0 和宿主 reader 共用不超过 18,000 秒且不超过 job 剩余减 **3,330 秒** 的 work：30 秒停组、120 秒精确容器清理、180 秒控制器收尾和 3,000 秒 CMS/upload 余量。各子步骤不把独立 timeout 累加为额外运行时长。

远端入口 **18 GiB = 16 GiB 保守工作估算 + 2 GiB 余量**，记录前后实际 free 点值及观察器结果；`peak_measured=false`，不是实测峰值。本机仍独立遵守 16/4/25 GiB 门禁。每棵返回树先核逻辑字节/成员/类型及分配量再 cp，上限 1 GiB / 32,768；控制器完整私有收集还核 3 GiB 聚合。CMS 封套沿原有限成员/单件 1 GiB/聚合 3 GiB 机制，超限失败保留原诊断，不截断或伪装成功。

SDK 仅宿主 stdin 解密，先核密文再核原 SDK 明文长度和 SHA；密码、SDK SHA secrets、H0 密码或 GitHub token 都不写摘要，不进入容器 argv/环境。H0 父子秘密只经原 FIFO 协议。公开 CMS 接收证书固定，CI 没有实际接收私钥；每 job 先真实验证 Linux AES-256-GCM / RSA-OAEP-SHA256 CMS 加解密及篡改拒绝，再封装完整私有证据。完整返回产物只通过 CMS AuthEnvelopedData DER 公开。

公开目录唯一白名单：`public-summary.json`、`workflow-status.json`、`cms-selftest.json`、`private-diagnostics.cms`、`private-diagnostics-identity.json`、`diagnostics-transport-status.json`。任何非普通文件、链接或额外项都拒上传。清理只按本次 owner 的确切容器 ID/image/run/ticket 和已登记 Temp inode；rename 后仍查询确切 ID，不按名称扩大删除。V0 负责停止整组后按本轮 scratch owner 回收源快照/探针，工作流再清理自身命名空间的 SDK/cache/APT/H1 ZIP。只有完整 CMS 身份复核通过才清除原私有 evidence；封装失败保留原件且绝不上传明文。原 driver rc 保存并原样退出，失败不算验收通过。

## 一次性注册与唯一 dispatch

新工作流初次只允许在分支 `codex/ios-locked-inputs-20261102`、路径 `.github/workflows/linux-avif-c.yml` 的 push 事件注册；job 条件同时要求 `workflow_dispatch` 与 `Leo008/renpy-build`，因此注册 push 的 job 为 skipped，不会下载或编译。主代理在真实注册 run / head / workflow API 核验后只 dispatch 一次首 tuple：

```bash
gh workflow run linux-avif-c.yml --repo Leo008/renpy-build --ref codex/ios-locked-inputs-20261102
```

API 列表可能短暂为空；依据该次命令取得的真实 run ID 或精确 head/事件查 run/jobs，不把列表延迟当未派发后再次 dispatch。注册完成可另原子去掉 push 触发器，保持后续仅显式 dispatch。首原件完整接受前不展开其它 tuple，不将本候选、文本包、门禁或 CI job success 代替功能验收。
