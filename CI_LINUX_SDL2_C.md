# 单 tuple 原 C → SDL2 两原 Task 源码 CI

本工作流部署 Reko 已提交的 S1 控制器，源码提交为 `76382ab4d5e00e7b620b94b81304560ec842c16b`。两件部署工具保持 Git 原字节：

| 文件 | 字节 | SHA-256 |
| --- | ---: | --- |
| `tools/ci_linux_sdl2_c_tasks.py` | 60764 | `0bb05badac68a36edf2e59350ad1b620891acc13f5538411c5a1fc0a74ccb440` |
| `tools/linux-sdl2-c-ci-plan.json` | 9600 | `571628b398ab39a4b02eff154c3b008f1071f151fb06b06f6637f50090b3c34c` |

原 I1D 工作流的 17 件基础工具和输入 pin 逐字保留，另加 S1 两件，共核 19 件。宿主 I1D 基础仍是 `f78e7c1c720afd8cccd6ec68dadf37f76aba27be` 的两件，原 D 仍是 `dbd31f77b45119af0bce15008c1cde424b2e06b0`；只复用已固定的准备和有限纯 API。S1 自己拥有父子监督、handoff、C1 所有权、超时和清理，不调用旧 image/font 控制器的生命周期或 Task。

S0 消费者两件来自真实提交 `3a4b7df3617a5315871ff355d9ddbb7eee36351f`，仅执行四路线原 `sdl2 unpack arch` → `sdl2 build arch`。工作流每次只选一个 tuple，默认 `ubuntu_group=24.04`、`release=8.5.3`、`target_arch=sim-arm64`，没有 all 或 matrix。首次实际调度仅限该默认 tuple；其他版本和 ABI 由主代理依赖与验收安排选择。单个 Actions 成功、部署和微测试均不等于 ROOT/独立原件验收。

## 十一文本发布输入

<!-- RUNTIME_PUBLICATION_BEGIN -->
十一文本输入已真实发布，GitHub API 已核 Release `406525604`、tag `ci-inputs-8.5.3-20261008`、唯一 asset `706204022` 的完整身份：

- 名称：`j11-sdl2-c-runtime-addon-20261104-01.tar.gz`
- 字节：`160469`；SHA-256：`ab6f9a92931a296ee6cc54ba75859cb8637cf111eee3787d4e8f5b67f29998a0`
- URL：[固定十一文本原件](https://github.com/Leo008/renpy-build/releases/download/ci-inputs-8.5.3-20261008/j11-sdl2-c-runtime-addon-20261104-01.tar.gz)
- 原文共 `836654` 字节，11 个平铺普通 `0644` 成员与 S1 catalog 全等，已逐成员 Git 原文核对及 roundtrip。
- 不含 SDK、凭据、私钥、游戏、业务源码或编译产物；此项文本发布不计 SDL2 构建/运行通过。
<!-- RUNTIME_PUBLICATION_END -->

包内容必须为原九文本加 S0 两文本，共 11 个平铺普通 `0644` 原件；逐件 bytes/SHA 与 S1 catalog 一致。原 43 件 producer 元数据保持不变，原 I1D API 在新独立物理根生成 50 件，随后只在同一根追加 S0 两件成为 52 件。I1D 宿主两工具不计入 52，不复制测试或第二份 SDK。

C03 仍为 `j9-c-prefix-runtime-addon-20261102-03.tar.gz`，73548 字节、SHA-256 `1f2c626e882476617d39fc5bc25c02f14bb8bcb3db90a6faa6b4d36d18836f1f`；H1 按原 D profile 选择原 ZIP。APT、SDK14、H0 密文、recipe CAS 和 clang runtime 均使用既有固定原件。显式缓存身份错误立即失败，不能静默联网替换。SDK 运输密码只经宿主 stdin，H0 密码只经父 FIFO/内存；均不进入日志、argv、容器环境或公开输出。SDK 解密只在宿主发生，原 C1 按已有合同消费 SDK；不增加 H2、新 J2、B 或 pip 流程。

父宿主下载保持复用工作流原 `urllib.request.urlopen` 的默认 verified TLS context 行为；不切换 TLS 模式，不使用 `-k`、unverified context 或证书/hostname 校验绕过。私有 transport 记录该实际行为为 `urllib_default_verified_context`。GitHub API 的 Release/tag/唯一 asset ID、名称、bytes、digest、状态与精确 URL 仍全部核对，下载后再核原字节。

## 真实执行与回传边界

原 D 在同一 open C1 内只执行本轮单 tuple fresh C。原 cell 和原完整宿主 C reader 必须通过，才能由 S1 创建独立 `/reko/j11-sdl2-*` 交接。原 C 不从旧 prefix/cache 恢复，不手写成功 marker，不运行 font/image/AVIF/媒体 Task。S0 只接受外部真实 run/attempt/C1 ID/nonce、实际 S1 工具身份、计划与 handoff bytes/SHA；其原 netns、FIFO 和单次 claim 合同不变。

S1 宿主 reader 只解析原字节，完整核以下证据：

- 原 C 导出、收据、双报告、原 reader stdout 和完整 inventory 强关联，最终 SDL2 prefix 保留每个原 C 成员。
- 一份完整 prefix gzip 的所有文件、模式和链接；`libSDL2.a`、`libSDL2main.a`、`libSDL2_test.a` 三库的每个 MachO 对象、CPU、平台、最低版本和 SDK。MH_OBJECT 的 SDK0 保留其原语义，SDK14 消费证据另由真实上下文证明。
- 完整 77 个安装头，实际 configure 前 header 加原 Task literal 后，与最终安装/configure-proof 原字节及 after 源 SHA 相等；同时绑定六份真实 configure/config.status/Makefile/配置头/sdl2-config/sdl2.pc。
- 两项原 Task 的身份、完整操作、真实 rc、原 `nice make -j` 和 configure/ARC/renderer 参数，以及现代 15／旧版 14 份原 patchdir 补丁的准确顺序与原身份。
- 实际 CC、CPPFLAGS、CFLAGS 的原 target 预处理 argv，完整宏/声明 stdout 与原 LLVM nm stdout；四个必要 SDL API 的真实声明/定义，以及原候选 driver 的原对象。
- 完整 H1 和原 J1 source 在 protected-before 中的身份投影，原 source/SDK/H1/marker 的保护由已认证 S0 实际执行在 finally 前完成。宿主不声称清理后重新计算已删除工作树的原字节。

返回 C/SDL2/control/原日志与小收据均保存在私有目录。宿主不执行返回的 Linux ELF 或 iOS 目标程序，不把已有 App SDL 替换或单一 SDL shared provider 算通过。本工作流不会关闭 G1/G2、R00、完整引擎源码或 Reko 会话；人工和真机保持延期验收。

## 时间、空间和保密

总 job 为六小时。工作流按实际 job started_at 计算绝对 UTC deadline；S1 使用 `min(18000, remaining-3330)` 的统一工作时限。3330 秒包含子进程停止、C1 清理、控制器收尾和 CMS/upload 余量。S0 自己的 7200 秒限额仍处于同一 work deadline 内，不累加成额外时长。

远端入口按保守估算 16 GiB work + 2 GiB 余量，共 18 GiB；父进程同时采样 free delta 和保留空间，取回前再核逻辑字节、成员与分配量。估算和两个时点读数不冒充实测峰值。本机的 16 GiB 测试输出、4 GiB 活动临时目录、剩余至少 25 GiB 规则不变。

单返回树上限 1 GiB、32768 成员；CMS 封套限制单文件 1 GiB、73728 普通成员、聚合 3 GiB，覆盖 C/SDL2/control 与原 D/workflow 余量。超额保留原诊断并失败，不删减内容凑成功。SDK、源码和编译正文只能在私有认证封套中返还；密码和原票据不落盘。

CMS 维持 AES-256-GCM AuthEnvelopedData、RSA3072 OAEP-SHA256/MGF1-SHA256 与原接收证书 SHA；CI 不持接收私钥。每轮先做无害明文真实加解密、篡改拒绝和原接收证书加密自检。仅允许有限摘要、完整身份清单和认证密文的原白名单上传；不公开 SDK、命令 stdout、源码正文或编译原件。

always 清理只按本轮实际 controller/run/ticket 与 C1 精确 ID/image，名称为空也再查原 ID；名称被其他 ID 替换则保留并失败。临时输入同时核前缀、父目录、ticket 和设备/inode。只有完整 CMS 强身份通过后才回收私有 evidence，缺封套保留原证据，绝不上传明文。

## 注册与首轮安排

新 workflow 先临时加入仅 `codex/ios-locked-inputs-20261102` 分支且仅 `.github/workflows/linux-sdl2-c.yml` 的 push 注册入口。job 仍只允许 `workflow_dispatch && repository == Leo008/renpy-build`，因此注册 run 应为 skipped；注册 run 不算编译或验收通过。

主代理待 GitHub API 确认真实 workflow 注册后，在后续 workflow/doc 两文件原子中移除该五行 push 入口、更新真实注册记录，再单独 dispatch 首个 8.5.3/sim-arm64。当前离线候选尚未提交、发布、注册或触发真实 CI；登记只能写实际 API 结果，不能填未来 workflow ID、run ID 或通过数。
