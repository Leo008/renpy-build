# 单 tuple 原 C → image 源码 CI

本工作流部署已提交的 I1D 工具，执行单作用域源码 CI。控制器来自 Reko 提交 `f78e7c1c720afd8cccd6ec68dadf37f76aba27be`，两件部署原件分别为：

| 文件 | 字节 | SHA-256 |
| --- | ---: | --- |
| `tools/ci_linux_image_c_tasks.py` | 48788 | `29ada979f9bf8b50af8026f83928cfdab5ce65233e185d07dc174f5b018cd8d1` |
| `tools/linux-image-c-ci-plan.json` | 6989 | `d6e0b42a54eeff66023080bdd5516c8d372bd7a05d95ea26e0a3446428a59d33` |

首次调度保持默认 `ubuntu_group=24.04`、`release=8.5.3`、`target_arch=sim-arm64`。每次只有一个明确 tuple，不提供 `all` 或 matrix；其他版本仍须符合原 D 的 Ubuntu 组。并发组和产物名称都包含版本、架构。工作流仅接受 `workflow_dispatch`；首次注册所需临时 push 入口已移除，执行时明确指定版本和架构。

原模板 15 件共用依赖保持原 SHA，J9C 工具／计划两件替换为本次 I1D 原件，仍逐一核验 17 件；不携带 J9C 控制器。流程复用 APT 分发、H1 原 ZIP、SDK14 运输、C03、H0 密文和原 recipe CAS 缓存。原 H0/CAS 只下载一份给控制器使用；控制器不设再次下载 fallback。原 D 在同一 C1 内实际执行单 tuple C 阶段，完整宿主 reader 通过后，一次交接到 current 消费器并执行八个原 image Task。producer 43 件与 consumer 50 件保持独立物理根及实际 manifest。8.5 前端沿原 `8.5.3-host-ci-success`，不重选 H0 scope。

九文本输入包已真实发布至 Release `406525604`、asset `705540938`：

- 名称：`j11-image-c-runtime-addon-20261103-02.tar.gz`
- 字节：`141373`；SHA-256：`804eacdc41eb0fd4e602aedefff20fc1fd7fafc721ed308e775b6f923fca77e8`
- URL：[固定九文本原件](https://github.com/Leo008/renpy-build/releases/download/ci-inputs-8.5.3-20261008/j11-image-c-runtime-addon-20261103-02.tar.gz)
- 9 个平铺普通 `0644` 成员，原文共 `743323` 字节；全部逐成员绑定计划 catalog。该包没有 SDK、凭据、游戏、业务源码或编译产物。

C03 使用既有 `j9-c-prefix-runtime-addon-20261102-03.tar.gz`，`73548` 字节、SHA-256 `1f2c626e882476617d39fc5bc25c02f14bb8bcb3db90a6faa6b4d36d18836f1f`，保留原 `07f817` C 身份。H1 按原 D 计划选固定 profile；SDK 密文与明文都核完整大小和 SHA，解密密码只交宿主 OpenSSL stdin。需要已有 `CI_INPUTS_PASSWORD`、两件 SDK SHA 和 `REKO_H0_INPUTS_PASSWORD`；没有 H2 密码、新 J2、B、pip 或 Py2 artifact 流程。

job 时限为 360 分钟。第一步读取本次 attempt 中唯一当前 job 的真实 API `started_at`，转成 UTC epoch 后加 21600 秒；缺证据即失败，不以当前时间补默认起点。控制器收到该绝对截止时间，取 `min(18000, 实际剩余秒数−3330)` 为整个准备/H0/C/image/宿主验证共用 work 时限。保留 30 秒子进程退出、120 秒容器清理、180 秒收尾和 3000 秒 CMS/上传余量，不把原 C 15000 秒与 image 7200 秒相加。

远端使用 14 GiB 入口门禁和既有采样 watcher：12 GiB 为单 tuple 工作估算，2 GiB 为余量；下载前、控制器入口及结束时各自记录真实可用空间。这些数值不是实测峰值。本机 16/4/25 GiB 规则不变。

公开目录只允许有限摘要、CMS 自检、完整身份清单和认证密文。私有控制器报告、完整生成归档、日志和输入身份证据先保留原字节，再沿既有 AES-256-GCM／RSA3072 OAEP-SHA256 CMS 封套上传。CI 只有原公开接收证书；无真实接收私钥。封套有界且不截断成员，失败不回退明文上传。`always` 收尾仅按本 job 所有权中的精确 C1 id/image 和临时根 inode 清理，名称为空仍查原 id，同名替换拒绝；证据仅在完整密文身份复核后回收。

工具与工作流部署不计为 image 编译验收；实际结果须另经原件认证及 ROOT 完整静态读验。公开摘要始终将 ROOT 独立验收、shared provider、G1/G2、Cubism、完整引擎和 iOS 会话保留为未通过；人工和真机验收保留 `deferred`。


首轮41626879702已完成原C依赖与宿主读验，进入image前因控制父目录不存在失败，原诊断保留。控制器现先核现有完整祖先链，再以不沿链接的目录fd建立缺失父目录，叶保持排他创建；拒绝链接、非目录与既有叶，不覆盖旧输入。当次父目录修复经45项回归与独审通过，原失败诊断保留。

第二轮 `41630078001` 已执行完八个原 image Task，但在验收阶段误将 libpng 标准头别名要求为普通文件；该轮仍不计 image 验收通过。四路线实际原件均为 libpng 1.6.43，默认安装三个 `include/libpng16` 非空普通头及相应精确相对别名。I0 提交 `ee30f99e55fd8f9cad64086994deeb9169b063cd` 新增严格纯库存头规则，current 提交 `37179b993ddd881d1b8d0dbe45c2799bd5540923` 绑定真实 I0。当前 I1D 在完整归档逐成员验真后复用同一规则，保留所有原链接、canonical 文件和其他头要求；错误/外逃/循环/缺失目标均拒绝。ROOT 已完成 I1D 50 项微型回归，但微型读取器通过不替代实际 image 编译验收；新的同一 tuple CI 仍须独立认证。addon02 只更新这组已提交工具/计划原文，未增加 SDK 或编译输入。
