# 原始 iOS C 前置与目标 Python 安装 CI

此工作流通过显式 phase 选择 R00-02J9 的原始 C 前置任务或目标 Python 安装。默认 c-prerequisites 保持原 C 路线；历史运行 41471558503 和现代运行 41470949898 的四版×三个架构已由主项目独立验收。target-install 当前只允许 Ubuntu22.04 的 7.8.7 或 8.3.7／sim-arm64，必须明确单版和架构；首轮试跑选择 7.8.7。B 每次在同一个全新 C1 worker 中重新实际执行原 C 与原 Python Task，不导入外部 C 前缀或预填完成状态。B 候选尚待真实 CI 验证；任何工具回归均不代表目标安装、pip、生产 shared dylib、G1/G2 或 Reko 会话通过。

编排与 worker 从 Reko 已提交原件部署；增量包七件来自提交 `07f817962ea074057230c92103ede806db41604c`，总原字节 314750，固定归档 73548 字节、SHA256 `1f2c626e882476617d39fc5bc25c02f14bb8bcb3db90a6faa6b4d36d18836f1f`，归档名 `j9-c-prefix-runtime-addon-20261102-03.tar.gz`。C 默认 profile 使用上述增量03。B 当前 profile 的七件来自提交 `6d6172ec386bfcd6d97f9a3f08f31220edb2907c`，总原字节469104；归档 `j9-target-python-runtime-addon-20261103-06.tar.gz` 为102948字节，SHA256 `da35ea36e0169563e3b229abe45776c97cac8c269403feac8ee22baf477e0f80`。历史05来自4e701cd，为98789字节/SHA256 `8230de1be890d706b2216b5bc119be85dda7a2abe4229f555a75ae6b7acceadf`，保持原身份。各profile固定自己的worker/plan身份，不能互换。历史B增量04来自63dde6，95387字节/SHA256 `1bdda8d22ab4630586a6c6866638557b71d3e371d8d136993c1224939123a565`，保留原身份。B 完整43件元数据根的18来源、9个scope和3份CPython原tar已通过fresh校验，归档发布状态以主项目证据为准。原 H0 包、H1 CAS 包和已实测 host 分发不重打包。H1 原 ZIP 必须匹配独立 API 大小与完整摘要；两组分别使用计划中的原 producer。

SDK 使用既有发布的加密原件；解密前核密文大小/SHA，解密后核明文大小/SHA及既有 SHA 秘密。AES256CBC/PBKDF2-SHA256/200000/salt8 的密码只通过宿主 stdin，不放 argv 或子进程环境。SDK 与 H0 密码不会发送到构建容器。所有实际 C 任务在固定 C1 同一容器内执行，容器无网络、无宿主挂载、非 privileged；保留原 unshare 的受控 capability 设置。

原任务执行顺序及原 argv 保留。mockrt 是原完整 LDFLAGS 所需的唯一先行 bootstrap。MetalANGLE framework 片段仅从 CFLAGS/CXXFLAGS 移到 LDFLAGS；LLVM15 历史组只补明确平台链接参数。原/候选 driver 必须真实验证，随后才能运行其余 C 家族。失败保存原始 stdout/stderr、config.log 等日志，无成功收据。完整安装前缀回传后逐成员、逐静态库对象检查 CPU、平台、SDK 和部署目标，不执行回传二进制。

完整 SDK 编译诊断和产物只进入 `private-diagnostics`。工作流先实际测试 Linux CMS 的无害 roundtrip、篡改拒绝和公开接收证书加密，再开始源码构建。最终以 CMS AuthEnvelopedData AES256GCM、RSA3072 OAEP-SHA256/MGF1-SHA256、DER 加密完整私有诊断。CI 只有公开证书 `tools/j9-diagnostics-recipient.pem`，SHA256 `db7c3cb23532bf02e51e24ae085fa14049658833469479b75981a1cd574f94f8`；私钥仅保留在本地忽略目录，不提交、不上传。

公开 artifact 白名单只有 `public-summary.json`、前置失败时的 `workflow-status.json`、`cms-selftest.json`、`private-diagnostics.cms` 和登记完整密文/明文字节身份及成员身份的 `private-diagnostics-identity.json`，封装失败时另有固定状态 `diagnostics-transport-status.json`。原始目录和 SDK 原文不能作为 artifact 上传。密文和身份均在私有临时目录完整形成后才发布；异常与超时均不上传部分密文。始终先加密，再清理受控容器、SDK、H1 ZIP 与私有临时输入，最后上传白名单。原诊断目录仅在完整密文再次匹配身份后删除；封装失败保留 runner 私有原诊断并明确记不可取回，不能声称证据已归档。原构建失败状态继续保持红色。

本地取回时先核 GitHub 原 artifact ZIP 的完整 API 摘要/大小，再安全解包白名单，核密文身份。使用已保留的私钥解密到全新私有临时文件；只有 CMS 返回成功且完整明文身份一致后才读取或安全解包。解密失败可能留下部分文件，必须删除该临时文件；保留原密文用于调查。后续独立复核与验收状态由主项目记录，不将工具测试或注册跳过运行计作源码通过。

构建队列按分支和固定 Ubuntu 组分别隔离，同组仍串行且不取消运行中任务。不同组各自独立的容器、APT、host producer 与 artifact 名可以同时推进；同一工作区修改及集成由主代理串行控制。初始历史组与现代组的既有运行保留其原候选与结果。

后续候选按 arm64、sim-arm64、sim-x86_64 三个独立作业验证，每次最多并行三个，失败不取消其他架构；同架构内两route仍在同一固定C1生命周期按原Task顺序执行。每个artifact名称明确Ubuntu组/架构/run/attempt，验收必须聚合三个完整原ZIP的实际cell，缺失或失败不补齐成功。原串行候选及其失败保留原身份。

第二轮诊断后的明确修复：原driver命令成功但SDK元数据拒绝会完整记原失败后继续既定candidate；候选可执行仍严格SDK14。原bzip2两链接已有LDFLAGS，但Makefile的LDFLAGS=覆盖环境，历史派生Makefile仅该一行改?=并保留原/派生SHA与补丁；四已证内部绝对alias经原脚本字节核对后规范为同目录相对link，未知/外部/错误内部仍拒绝。修复21项回归与完整43件fresh根验证仅为工具验收，实际C须新运行；原01包和两失败运行不重标。

增量02发布原件 asset702126156，GitHub API返回73258字节和SHA256 bce012d0b0c9eaf6641d799111fd119e29840fc4712a2ff0e73be02de6a47a7b，与本地完整归档一致。

现代旧候选的实际driver也编码SDK13，增量03独立加入LLVM18精确ccache clang-18平台候选，LLVM15原分支/理由保持原文；四版原bzip2 archive/补丁/Makefile身份相同，LDFLAGS?=候选扩至现代。默认每cell缓存与显式共享缓存的24原Context组合、四版make-n及21回归已核；新现代C结果须另行实跑，不重标增量02历史组。

增量03发布原件asset702183169，独立API为73548字节/SHA256 1f2c626e882476617d39fc5bc25c02f14bb8bcb3db90a6faa6b4d36d18836f1f，与本地归档相同。

调度输入为 ubuntu_group、phase、release 和 target_arch；C 可选组内 all 版本及 all 三架构，B 拒绝 all、现代组或其它架构。矩阵每作业只对应一个架构，最多三个并行，组内不取消已有运行。artifact名称含phase、Ubuntu组、架构、run、attempt；不同实际运行分别验收，不按名称或工具测试补齐成功。

目标安装继续执行原 unpack、patch_posix、patch_ios、build_ios/common_post。CP39 只在已锁定 configure 调用处清空原 PYTHON_FOR_BUILD、追加 --with-ensurepip=no，使上游 configure 自行生成原交叉编译包装器；原 Task 函数和包装器源码不改，实际argv/env、Makefile、target sysconfig、原host完整库存不变和无提前pip均须逐项核对。原默认upgrade的历史值与实际no分开保留，不将禁用隐式ensurepip视作显式pip任务通过。

B 成功导出采用仅path/linkpath的严格PAX格式保存完整前缀、stdlib和有限构建证明，支持原stdlib长路径；回传后独立重算全库存、原C子集、stdlib来源、Makefile/pyconfig/sysconfig、libpython所有Mach-O对象、静态模块符号和唯一原H1 hostpython ELF，不在宿主执行回传二进制。原C的USTAR导出协议保持原字节。

B 失败或SIGTERM取消只生成明确标注diagnostic_only的有限私有快照，缺失成员如实登记，链接仅登记而不跟随。CLI中断桥给既有finally提供保全机会；SIGKILL或GitHub宽限不足仍可能截断诊断，不能保证完整或伪报成功。SDK、完整host树和凭据不进入该快照；既有CMS白名单、认证封装与清理规则继续适用。

增量04的两次真实首轮分别为CP27 run41560284924、CP39 run41560729164，均在原make链接解释器时缺MetalANGLE搜索路径而失败；完整原ZIP/CMS已由主项目认证取回并独立审查，未计目标安装通过。新B窄修复只在原build_ios的固定configure入口，逐原Makefile.pre.in/注解/Task和实际已安装框架验真后，对8.4.1/8.3.7/7.8.7的LDFLAGS追加一次精确-F当前install路径；8.5.3原本已有，保持不加。C32函数/计划、原Task模板、SDK及标准不变。

05阶段worker主审39项无skip、CI配套主审28项无skip及完整43根fresh输入校验通过。target-framework-link-binding.json独立绑定原make日志、实际Makefile、展开投影与真实解释器链接argv；CP3原规则的两次LD展开保留。静态reader重取原日志argv并复核原Makefile.pre.in/sidecar/收据SHA，篡改或自签矛盾不能通过。05工具验证仍不计实际Linux目标安装，新CI必须另跑、完整取回验收；04历史失败不改写。


05的CP27 run41564816073和CP39 run41564819755均已完成原make、make install及host复制，新-F闭合已核；完整B后验被原C通用ar唯一成员规则拒绝。原CP27/CP39库分别176/210 occurrences，同名重复与实际LIBRARY_OBJS顺序相同且同字节；旧快照没有全部原build.o，不补称完整布局通过。

06仅对两处原libpython安装路径使用B专属保留occurrence解析，纯展开原Makefile/template/实际GNUmake投影，按原相对.o路径逐个比较实际源对象完整bytes/SHA和MachO CPU/平台/min；同名异字节、顺序/次数/源对象缺失均拒绝，C32及原C唯一规则不变。新增layout/source_objects两份sidecar及receipt SHA；原build.o按明确list只放私有PAX proof，经原CMS运输，绝不进入公开七文本输入包。失败也仅按已写投影和原模板列出现存普通.o，缺或不符如实missing/rejected，不扫描SDK/build/host整树。主审41项/CI31项无skip及完整43根fresh仅是工具/输入验证，完整B成功仍须新CI，旧失败不重标。
