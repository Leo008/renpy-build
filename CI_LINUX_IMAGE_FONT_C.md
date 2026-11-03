# 单 tuple 原 C → image → font 源码 CI

本工作流部署 Reko 已提交的 I3 控制器，提交为 `7370e88d36fddb188c79875ba5e0cc19e19ba13a`。两件部署原件保持原字节：

| 文件 | 字节 | SHA-256 |
| --- | ---: | --- |
| `tools/ci_linux_image_font_c_tasks.py` | 62146 | `17884420d85bac47de701a632d31b632374801fc135a3b48376c9fa1c565a992` |
| `tools/linux-image-font-c-ci-plan.json` | 9633 | `5a613ff8ab868b8f44d9d23ff9e2cfc604dcd816c78bba4420260c202be9335c` |

原 image 工作流的 17 件工具/输入 pin 全部保留，另增加这两件，共核 19 件。I1D 宿主基础仍为 `f78e7c1c720afd8cccd6ec68dadf37f76aba27be` 的两件原文，I2 组合消费者 worker 为 `14af937c6287761880e1903f3d694c0a40f91652` 原文，计划仍为 `f2a4376288b7ef07e52a31ec80966d0a892be21c` 原文。I1D 仅提供已固定的必要纯 API，新控制器自行拥有本轮父子监督、handoff、单次 claim 和清理；不调用旧 image 生命周期。

实际 font CI 的前置条件是对应 tuple 的 image 原件已完成 ROOT 和独立验收。部署、微测试及 Actions success 均不代替这项验收；主代理必须先核对应门禁再调度本工作流。首次调度仅为 `ubuntu_group=24.04`、`release=8.5.3`、`target_arch=sim-arm64`。入口仅 `workflow_dispatch`，每次一个明确 tuple，没有 `all` 或 matrix；其他 tuple 必须匹配原 D Ubuntu 组及其前置验收。并发组和产物名包含版本、架构，新工作流使用独立临时命名空间。

十一文本输入已真实发布至 Release `406525604`、asset `705890011`：

- 名称：`j11-image-font-c-runtime-addon-20261103-02.tar.gz`
- 字节：`167193`；SHA-256：`a95510fe5d86dce6e2ce1089109a7d2905a9c64db17bedf80fa7f8cc1efbef98`
- URL：[固定十一文本原件](https://github.com/Leo008/renpy-build/releases/download/ci-inputs-8.5.3-20261008/j11-image-font-c-runtime-addon-20261103-02.tar.gz)
- 11 个平铺普通 `0644` 成员、原文共 `870128` 字节；全成员 bytes/SHA 与 I3 catalog 逐件一致。原九文本加 I2 两文本，不含 SDK、凭据、游戏、业务源码或编译产物。

C03 仍是 `j9-c-prefix-runtime-addon-20261102-03.tar.gz`，73548 字节、SHA-256 `1f2c626e882476617d39fc5bc25c02f14bb8bcb3db90a6faa6b4d36d18836f1f`；H1 仍按原 D 固定 profile 选原 ZIP。APT、SDK14、H0 密文、recipe CAS 和 clang runtime 使用既有固定原件；H0/CAS 缓存只供控制器复用，不设再次下载 fallback。需要既有 `CI_INPUTS_PASSWORD`、两件 SDK SHA 与 `REKO_H0_INPUTS_PASSWORD`，秘密只经宿主 stdin/FIFO/内存，不进入日志或 C1 命令环境。不执行 H2 密码、新 J2、B 或 pip 流程，也不发布任何私有编译输入。

控制器在同一 open C1 执行原 D 单 tuple C，原 cell 和完整宿主 reader 通过后才交接 I2。producer 43 原件不变；原 I1D API 只生成一次独立物理 consumer 50，再在同一根排他增加 I2 两件成为 52，并复验全部 52 与原 43。宿主 I1D 两件不计入 52。前端保持原 H0 scope，8.5 使用 `8.5.3-host-ci-success`，不重放或重选 H0。I2 先执行并验真八 image Task，再执行现代八个或旧路线十二个原 font Task。

完整宿主静态 reader 在新进程认证 52 闭包，流式核最终前缀全部成员、十 image 加四 font 库的每个 Mach-O 对象、原 C/image 成员不变、目标 FriBidi、首 FT 覆盖前原归档及全部特性头。现代四份或旧路线六份特性探针绑定真实头、宏和编译器 argv；旧路线两次 apinames、全部实际保留 native 生成器均核原 ELF/DT_NEEDED 和固定包资格。宿主不执行返回 ELF，系统二进制 SHA 只记本轮认证观测，不声称宿主重算未回传系统二进制。

job 时限为 360 分钟。第一步从本 attempt 唯一当前 job 的 API `started_at` 得真实 UTC 起点并加 21600 秒；缺证据就失败，不以当前时间补默认值。控制器共用 `min(18000, 实际剩余秒数−3330)` 工作时限，覆盖准备/H0/C/image/font/全部 host readers。保留 30 秒子进程退出、120 秒容器清理、180 秒收尾和 3000 秒 CMS/上传，不累加各阶段时限。

远端入口为 18 GiB：16 GiB 工作估算及 2 GiB 余量，分项见 I3 固定计划。保留原采样 watcher，以及下载前和 driver 后可用空间证据；这些是估算和时间点观测，`measured_peak=false`。本机 16/4/25 GiB 规则不变。

I3 每个返回树先核逻辑 1 GiB、32768 成员及分配量，复制后宿主再核。完整 CMS 封套保持固定 AES-256-GCM、RSA3072 OAEP-SHA256/MGF1-SHA256、原公开接收证书和全部原身份。上限为单件 1 GiB、73728 成员、总 3 GiB：给两个 I3 有界返回树各 32768/1 GiB，另给原 D/workflow 8192 成员/1 GiB 余量。超额失败并保留原诊断，不截断清单或回退明文上传。封套身份清理读取限 32 MiB，与完整成员清单匹配，其余所有权小文件仍维持原 1 MiB 上限。CI 不持有真实接收私钥。

公开只允许有限摘要、CMS 自检、完整身份清单和认证密文。摘要只在实际 I3 `TASK=R00-02J11I3`、`RESULT=single_tuple_actual_C_original_image_and_font_verified`、19 pin、consumer 52、14 库与全部 host-reader 证明同时成立时登记本轮有限结果；完整 returned-files 清单仍只在私有日志。`always` 收尾仅按新控制器真实身份、本 job 票据及精确 C1 id/image 和临时根 inode 清理；名称为空仍查精确 id，同名替换拒绝。原私有证据仅在完整 CMS 身份复核后回收。

本工作流部署不计真实 font 编译验收。每次实际原件仍需本机认证、ROOT 和独立静态验收。ROOT 独立验收、shared provider、G1/G2、Cubism、完整引擎与 iOS 会话都保持未通过；人工和真机验收保持 `deferred`。

工作流405746285已通过分支注册，临时push入口已移除，job仅允许workflow_dispatch。注册run41645605249实际completed/skipped，未执行字体编译；实际调度仍须对应image原件先完成ROOT及独审接受。

2026-11-03：首字体先导41648269103保留失败。原C/image、FriBidi与首FT安装rc0后，系统包资格检查拒绝；具体owner未被旧日志记录。14af937仅修Multi-Arch包名/架构规范与诊断，原APT清单与Task不变，40项回归和独审通过；7370e88监督绑定35项通过。本轮02仅换这件已提交worker，随后唯一同tuple重试；部署不计字体构建通过。
