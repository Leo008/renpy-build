# 固定 Linux 原图形版本头生成 CI

本工作流仅完成 R00-02J10G：固定 Ubuntu 22.04/C1 环境中恢复完整 H1 CP27 分发，然后分别执行 legacy 原 Python2 生成器和 modern 原 Bash 生成器；两端验证唯一 `commit.h` 及完整派生树。它不执行图形库、引擎或目标 Python 构建，也不关闭 R00 输入总闭包、G1/G2 或产品会话。

## 来源与部署原件

Reko 原件来源提交为 `7680e8f18019fd2ad6868ef7b72f888958173c45`。部署时只将两件原件改名/放到明确位置，字节不改：

| Reko 原路径 | fork 路径 | 完整 SHA-256 |
|---|---|---|
| `scripts/renpy/run_linux_graphics_metadata.py` | `tools/ci_linux_graphics_metadata.py` | `8847753deb9f1d926a1780692aa278b41c9a606507f2beab4c68f190476ebf88` |
| `scripts/renpy/linux-graphics-metadata-ci-plan.json` | `tools/linux-graphics-metadata-ci-plan.json` | `a3cf945e66e340c1ca2a9464a56dc246327b3d5d652f1964bd3b25d48533fdcf` |

本工具的 13 份运行时文本原件逐项身份固定在 companion plan 中，与旧 J9 的 43 份目录隔离。运输包仅允许这 13 个 flat 普通文件，mode0644，无目录/链接/附加文件；包的实际 Release asset 身份须与工作流冻结值一致，随后逐成员核对大小和 SHA。不得给尚未生成的包填写猜测名称、摘要或提交号。

已由ROOT按上述真实Git blobs生成并发布的包为 `j10-graphics-metadata-runtime-20261103-01.tar.gz`，1,029,731 B，SHA `b9895611b60bf08dcfa9c7082db9a3495d03087b26e858712cd7a6491b6a7852`；Release `406525604` / asset `704686340`。其13原件共3,701,459 B，完整平铺成员roundtrip、私钥/token字面扫描通过。本轮发布位置为已授权仓库的[固定Release原件](https://github.com/Leo008/renpy-build/releases/download/ci-inputs-8.5.3-20261008/j10-graphics-metadata-runtime-20261103-01.tar.gz)，工作流先核API中的Release/asset/name/bytes/digest再下载；不消费任何SDK或私有编译产品的公开输入。

## 固定输入与执行边界

- 完整 APT 分发复用 run `41419224335` 的 `renpy-apt-inputs-22.04-41419224335-1`，manifest SHA `d722e3aa9db55925062e70a35486e1e0b1405c064a6dc5a8b7a289900d5c6851`；C0 在容器内重做原签名、离线安装和包差异核验。
- 原 H1 ZIP 复用 run `41446746901` / artifact `13143390321`，101989031 B，SHA `7c22c8e81eae045770f618907961c9b20741b9049cdf82b76af73f30949a5ec8`。完整 CP27 分发恢复到 `/reko/h1-workspaces/7.8.7/tmp/host`，执行原 PRODUCT_PROBE 与全部 ELF 的稳定动态依赖核对；不重新运行 H0、H1 构建或 pip。
- 六个官方 Git 来源、commit/tree 和元数据固定在 13 原件中的 `graphics-inputs.lock.json`；只在宿主阶段补缺失缓存，已有坏缓存直接失败，不换源或重标版本。
- C0 唯一容器 `--network none`，无 host mount、SDK、仓库凭据、SYS_ADMIN 或 privileged。GitHub 自动令牌仅供宿主取回固定 Actions/Release 原件，不传入容器，不需要仓库解密秘密。
- 每个 family 在 `docker cp` 前先固定 Python `lstat` 预核逻辑字节、成员数和类型/链接，再核 `du` 分配量。任一超限不取回完整树，并继续另一 family；普通文件总逻辑大小上限 512 MiB、成员数 32768。
- 生成结果完整压缩归档逐成员流式验真，单包上限 256 MiB；原报告/日志另有 16 MiB 保全上限。runtime/H1 解包/源码物化/返回散树均由本轮 TemporaryDirectory 在成功或失败时回收。

## 远端与本机空间边界

CI 远端独立使用 **8 GiB 工作空间估算 + 2 GiB 余量 = 10 GiB 入口可用空间门禁**。这是保守预算，不是已测峰值；不把本机的 25 GiB 余量要求套用到远端 runner。本机测试目录 16 GiB、活动临时目录 4 GiB、预计峰值后至少剩余 25 GiB 的规则不变，取回产物仍须按真实大小另过本机门禁。

固定 d722 APT 输入包含 413 包，deb 共 298,378,310 B、完整 bundle 454,453,145 B、Installed-Size 合计 1,209,289,728 B。APT、原 H1、六 Git 与四份同时存在的树已约 3.89 GiB，且尚未计入压缩归档和日志；因此不用 4 GiB 作为远端完整工作估算。8 GiB 是加入这些额外工作集的保守工作估算，2 GiB 为单独预留余量；实际空间不足仍据实失败，不扩大通过边界。

工作流将入口的 `storage-before.json` 与 driver 成功或失败返回后的 `storage-after-driver.json` 先落到私有诊断目录，再由既有 CMS 封套一并带回。二者只记录当时可用字节，不能证明过程峰值；driver 未执行时不补造 after-driver 采样。公开摘要仅附预算及两次可用字节数，未观测值为 `null`，并明确 `peak_measured: false`；不公开私有诊断正文。

## 调度与结果

工作流仅手动运行一个固定 job，同时处理两个 family，不提供任意 SDK、命令回调、版本或输入 URL 选项。主代理需先核查最终 workflow/fork commit、13 文本输入包实际身份和公开范围，再调度；此候选说明不表示workflow已部署、注册或实跑。

首次部署保留仅匹配本workflow文件的`push`入口注册工作流，而job明确仅`workflow_dispatch`才执行；ROOT确认注册后再以单文件原子提交移除`push`入口。注册push与移除push均不执行生成器，不能把注册状态当作CI通过。

公开产物严格仅含摘要、无害 CMS 自检记录、密文和身份清单。完整返回树、原始日志及诊断只进入既有 CMS AuthEnvelopedData 封套：AES-256-GCM、RSA3072 OAEP-SHA256/MGF1-SHA256，固定旧公证书 SHA `db7c3cb23532bf02e51e24ae085fa14049658833469479b75981a1cd574f94f8`；私钥只保留在本机，不上传 CI。

CI 先用无害字节真实测试 CMS 加密/解密和篡改拒绝，再仅持原公证书封装真实结果。加密失败则任务失败，不输出明文替代。完整密文与身份检查通过后才清理 runner 私有证据；失败仍保留明确不可取回状态，不伪造 generator 或 R00 通过。

取回时按 GitHub API 的真实 artifact 大小与 digest 估算 ZIP、CMS、认证解密和读取器峰值，通过本机空间门禁后再下载，复用已有完整 ZIP；不保留分块或第二份整树。主代理必须核真实 run/jobs/attempt、原部署和包身份，认证解密、逐成员重核完整结果、读取原命令/收据及完整树证明后才计入 J10G 验收。`CI success` 或输入预检通过均不替代这一步。
