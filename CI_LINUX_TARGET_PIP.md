# 同一 C1 的目标 pip 安装及完整静态验收

该工作流只服务 R00-02J9C。每个作业显式选择一个版本、架构和 pip scope，在同一真实 C1 容器中先重新执行原 C 前置与目标 Python 安装，再运行已提交的原 pip Task 绑定器，最后导出完整前缀并由宿主独立进程重验。旧 B 的 12 个通过 scope 仅提供调度资格，不导入旧 C/B prefix、不预填本轮成功。

首次注册临时允许 `push`，且仅匹配 `codex/ios-locked-inputs-20261102` 分支与 `.github/workflows/linux-target-pip.yml` 路径。作业同时要求 `workflow_dispatch` 事件及仓库 `Leo008/renpy-build`；注册 push 的作业必须 skipped，不下载输入、不构建、不计通过。根代理确认已注册后，另以只修改该工作流的单文件提交移除临时 `on.push`，随后才手动 dispatch 正式验收；说明保留这段真实注册流程。

Linux 完整 pip scope 尚未实测验收通过。工具语法检查、协议回归、候选发布或 GitHub 作业状态均不等于目标通过；最终结果需要主项目绑定原 run/head、原 artifact ZIP/API 摘要、CMS 认证、每成员身份和独立完整链审查。

## 固定输入

Linux 编排和输入计划已按真实09身份更新于主项目提交 `a6f7c495263845a65f571eef8996c66e092fb6a2`，源码30785字节/SHA `148ad31c65aa5118a684afe04ca08e1bac5eb22d8468b86e822f89fa7008e077`，计划5369字节/SHA `76adfb5296f1d0677b6899d655405309247600375ba56ec135c9ab73e6a4ba2e`。九项回归无skip及09真实四成员解回验证通过；函数/类AST在08→09诊断文字归一后完全相同。它们只证明工具协议，不代表Linux实际pip scope通过。

原 D 为提交 `dbd31f77b45119af0bce15008c1cde424b2e06b0` 的 wrapper，SHA `49b7f7c63d604bb0855ccb2125811989b6915230f148142fbce97b8a33784da5`，计划 SHA `d70d6eafcc42eb9460942f140bdc9b89126635a2fea847040c88c139d5263eeb`。编排不修改或 monkeypatch D，使用其原 `execute_cells`；准备阶段按原函数顺序完成 H0、CAS、B43 根和 J1 工作区校验，仅增加显式强身份缓存入口。动作差异写入私有 `input-preparation-actions.json`。

B 继续使用原 06 包：asset `704057775`，102948 字节，SHA `da35ea36e0169563e3b229abe45776c97cac8c269403feac8ee22baf477e0f80`。旧 B43 物理根 `/reko/j9-runtime/root` 保持原依赖；新 J2 输入放 `/reko/j9c-inputs/root`，pip/导出工具另放 `/reko/j9c-code`，三者不得混用。

09 仅含四个普通文本成员，0644、uid/gid/mtime全0，无目录、链接或PAX：`run_locked_target_pip_tasks.py`、`target-pip-binding-plan.json`、`run_target_pip_export.py`、`target-pip-export-plan.json`。原始四件共402752字节；[09归档](https://github.com/Leo008/renpy-build/releases/download/ci-inputs-8.5.3-20261008/j9-target-pip-runtime-addon-20261103-09.tar.gz)为80606字节，release `406525604`、asset `705030280`，SHA `f0006f364b2d2d09c602701c29bab1cb67f40f179b8ac081ecba5a9fccb34f9f`。worker来自真实提交 `3cce70766778b6d126fa0bf1f45d78deb293b019`（76531B/SHA `ab07648691784fd29740a2f65d10c3a29994966ecfd9d41694ca6fc2913fc6ee`），pip计划仍为 `3250769269e67c95ab5c0afb738876f7cf44cb75` 原字节c399，导出两件来自 `613a3f5faeb680031ae9bb83eb527a2ee93bb22f`（39334/9226d368、2523/db197139）。包内不含测试、SDK、轮子、私钥、游戏资源、App业务代码或编译产物。

新 J2 复用既有 H0 密文和 H2 extra33 密文（原 asset `701530517`），通过固定解密、33 成员核验、原 `merge_inputs` 和独立 `verify_current_inputs` 补齐 26 缓存、两份 Py2 轮子及收据和三件 J2 控制文件。原 Py2 producer artifact `13135391038` 的 ZIP 为 849787 字节，SHA `41222fce1a3b291ef5eadfa3b7282e70041563b18b7a11a04a1947cacc4de601`；只流式核对其三项与 H2 内容一致，不重打包或公开发布二进制。

## 执行与验收

22.04 对应 7.8.7、8.3.7，24.04 对应 8.4.1、8.5.3；各版三个独立架构。8.5.3 有 `8.5.3-target-ci-success` 和 `8.5.3-target-recipe` 两个明确范围，其他版本各自只有 `<release>-target-recipe`。`target_arch=all` 只展开三个独立作业，每个进程仍只处理一个 scope；同组按分支排队，取消不会覆盖旧结果。

工作流先校验全部固定部署工具和计划，再进行无害 CMS roundtrip、篡改拒绝及真实接收证书加密自检。APT 原分发、原 H1 ZIP、Py2 ZIP、H0/H2 密文、06/09 和 CAS 均只取得一份；存在的显式缓存必须完整匹配大小/SHA，缺失或调包不能静默联网替换。H1/Py2 另核原 Actions API 的 ID、未过期状态、大小和 digest。未给缓存路径时，编排才可调用对应原固定下载函数。

SDK 原密文/明文及原秘密 SHA 均逐项校验。SDK/H0/H2 密码只保留在宿主，以 stdin 交给固定 OpenSSL 参数；GitHub API token 只在 artifact 取件步骤使用。新 worker 的容器执行环境使用 `env -i`，不传上述秘密。C1 沿用原隔离模型：无网络、无宿主挂载、非 privileged，以及原构建所需的受控 capability 设置。

pip 必须重新验证实际 B/C、完整 SDK、原 H1 和派生 H1，再在真实新增网络 namespace 中完成原 ensurepip 及明确离线 scope 安装。`target_pip_bound` 只在完整 PAX 回传和宿主独立静态验收后才记 true。验收覆盖整个最终 prefix、原 C/B 成员不变、两 producer、完整 RECORD/payload、脚本、CA、最终所有 source/pyc 原字节和原同桥 argv/stdout/SHA。CP39 只接受已明确批准的首个 pre-seed 缺 Linux sysconfig 原失败及后续固定候选，其他失败均拒绝。

历史 seed 阶段绑定真实同桥执行日志和原 wheel 源码；已升级覆盖的历史 pyc 不在宿主重算，字段 `seed_historical_raw_pyc_recomputed_on_host=false`。最终前缀所有 source/pyc 原字节完整重算，并绑定原同桥探针；宿主不执行回传 Linux/iOS 二进制，也不跨版本重算 marshal。

## 空间和证据保留

远端独立 runner 采用 8 GiB 工作估算加 2 GiB 余量，下载前要求实际剩余至少 10 GiB。记录入口和结束的可用空间；两次采样明确为 `point_in_time_free_space`，`peak_measured=false`，不把估算写成实测峰值。此门禁独立于本机 16 GiB 测试输出预算和 25 GiB 剩余要求；本地取回、解密和验收仍须由主代理统一租约及本地空间门禁批准。后续若真实占用显示估算不足，先调整有证据的预算再运行，不能自行降低门槛。

CMS 封套在加入成员清单和 `tar.addfile` 前限定私有普通文件聚合不超过 2 GiB、最多 8192 个成员、单文件不超过 512 MiB。预算依据是旧 12 个真实 B scope 的单 cell 私有诊断为 345–351 个文件、87923548–143733861 字节；新增完整 pip 归档本身硬限 512 MiB，失败原控制日志回收硬限 128 MiB，以 2 GiB 聚合上限留出有限余量，保持远端 8 GiB 工作估算有界。该估算仍不是峰值实测。超限沿用既有封装失败路径，保留原诊断，不删减成员、不生成不完整成功封套。

完整 B 证明、完整 pip prefix、原命令日志及失败白名单证据只进入私有目录。每轮物化、解密、临时 B-copy、解包和 wheelhouse 在 finally 回收；成功回传仅保留一份原归档及小型报告，不长存第二份 copy。CLI 将 SIGTERM 导入回收路径；外部 SIGKILL 或宽限不足不能保证清理或诊断完整，不能因此记成功。

CI 只有既有公开接收证书，SHA `db7c3cb23532bf02e51e24ae085fa14049658833469479b75981a1cd574f94f8`。诊断以 CMS AuthEnvelopedData AES256GCM、RSA3072 OAEP-SHA256/MGF1-SHA256、DER 认证加密。公开 artifact 白名单限摘要、前置失败状态、自检、完整密文及明文/密文和成员身份、必要封装失败状态；原 SDK、轮子、前缀或日志目录不能明文上传。只在完整密文再次匹配身份后删除 runner 原诊断；封装失败保留原诊断并明确不可取回。原构建失败保持失败。

本阶段不声称完整引擎源码 CI、生产 shared dylib、G1/G2、Reko 剧情/存读档/退出重开或同跨 ABI 与三引擎切换通过。人工和真机仍为延期验收；未实现、失败、未运行及延期项目不计实测通过。

首轮先导 `41598931668` 固定 `56979d55c3eb0287a953184c425618016905b3fb` 与07，真实C/B重建及再次重验、scope输入与新增内核netns通过后，原pip两命令尚未执行就因home目录已存在失败；不接受任何pip scope。原网络证明的clean_environment提前在结果根创建home/tmp，和pip独占环境冲突。c1a修复仅把原证明放入独占TemporaryDirectory并自动回收；private_environment的既有目录/链接拒绝、原pip/registry/B验证全不改。新增三项相关回归通过，导出固定身份16项及编排9项通过；旧失败原ZIP、401认证诊断与报告保留。08只更新已提交修复文本及强身份，须重新完成真实先导/完整验收，不凭本说明或工具测试记通过。

第二次真实先导 `41603656124` 固定 `d63bd30f4c2354dcfd2fd06de2a14f4bbd4a448c` 与08，目录碰撞已跨过，原ensurepip真实rc0并安装pip19.2.3/setuptools41.2.0；随后精确入口脚本校验拒绝，scope安装尚未开始。原ZIP80394161B/SHA `30df103c5466b15ef111221dcb148571d662bf67e050b2f21293f57ec10f4543`及412认证成员/独审保留，不接受任何pip scope。

09精确修复固定pip19的实际maker.script_template覆盖、CP27原ensurepip CLI默认generic脚本，以及CP27 marshal.load只接受真实文件的静态确定性错误；不放宽脚本/RECORD/pyc尾字节或B/C门禁。完整32项Mac夹具/固定源码和微型探针回归无skip，16项导出回归、9项编排回归及实际四成员解回通过，所有新临时树finally清理。CP27 marshal修复依据原39508B源码965b463，不声称曾在08实跑到该错误；新Linux先导及完整scope仍须真实执行并独立验收，先导通过后才展开矩阵。

并发组继续按分支与Ubuntu组串行，显式 `queue: max` 与 `cancel-in-progress: false` 保留最多100个等待run；不会因新同组调度替换早先pending。官方规则见 https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax 。先前默认single导致41616058130（CP27/arm64）及41616073657（8.5.3/ci-success三架构）在开始前被后续pending替换取消；原API/调度记录保留，不计构建失败或通过。只重新调度这四个未执行作用域，已运行/等待的8.3.7、8.5.3 recipe、CP27 x86与8.4.1及已验CP27 sim-arm64均不重派。

本机actionlint1.7.12尚不认识官方已提供的concurrency.queue，原始unknown-key失败留存；仅移除该新增一行后其余字节精确等974f356并通过该linter，17原件SHA不变。queue/max与false组合按官方语法核，随后以GitHub实际接收调度作为新字段的服务端校验，不把此工具版本限制记为构建失败。
