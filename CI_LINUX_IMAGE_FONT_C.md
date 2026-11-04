# 单 tuple 原 C → image → font 源码 CI

本工作流部署 Reko 已提交的 I3 控制器，提交为 `d5edfbee2a8921212e66ca9fb4f6deca72e48567`。两件部署原件保持原字节：

| 文件 | 字节 | SHA-256 |
| --- | ---: | --- |
| `tools/ci_linux_image_font_c_tasks.py` | 89975 | `7ee48c5a3c40247b50f52705e60b9addba5e68980248651b165910b7c2624b9f` |
| `tools/linux-image-font-c-ci-plan.json` | 10731 | `3353f2ca3ce3fce454635bb2cc7a61c2873fb3af595bdf5b8d669e16e5c2d82b` |

原 image 工作流的 17 件工具/输入 pin 全部保留，另增加这两件，共核 19 件。I1D 宿主基础仍为 `f78e7c1c720afd8cccd6ec68dadf37f76aba27be` 的两件原文，I2 组合消费者 worker 和计划均为 `caae7e596b374fc49ffcdb32671ee40ab4437450` 的原文。I1D 仅提供已固定的必要纯 API，新控制器自行拥有本轮父子监督、handoff、单次 claim 和清理；不调用旧 image 生命周期。

常规扩展font矩阵前，须核对应image原件及ROOT/独立接受；本轮I6L另有明确单组先导范围，按下述同C1完整门禁执行。部署、微测试及Actions success均不代替产物验收。工作流最初首个 tuple 为 `ubuntu_group=24.04`、`release=8.5.3`、`target_arch=sim-arm64`；本轮07按I6L仅运行新旧路线先导 `ubuntu_group=22.04`、`release=8.3.7`、`target_arch=sim-arm64`，完整ROOT及独立接受后才扩余五个22.04字体tuple。该先导必须在当次同一C1内通过完整原C及八image门禁后才进入font，不将首8.5.3或已验8.4.1外推为8.3.7事前接受。入口仅 `workflow_dispatch`，每次一个明确 tuple，没有 `all` 或 matrix；其他 tuple 必须匹配原 D Ubuntu 组及其前置验收。并发组和产物名包含版本、架构，新工作流使用独立临时命名空间。

十一文本输入已真实发布至 Release `406525604`、asset `707184616`：

- 名称：`j11-image-font-c-runtime-addon-20261104-07.tar.gz`
- 字节：`184516`；SHA-256：`ae654ac73af57b17709eef444d280339ae69a54d0ac4dd914c11a4ec478c0b08`
- URL：[固定十一文本原件](https://github.com/Leo008/renpy-build/releases/download/ci-inputs-8.5.3-20261008/j11-image-font-c-runtime-addon-20261104-07.tar.gz)
- 11 个平铺普通 `0644` 成员、原文共 `947950` 字节；全成员 bytes/SHA 与 I3 catalog 逐件一致。原九文本加 I2 两文本，不含 SDK、凭据、游戏、业务源码或编译产物。

C03 仍是 `j9-c-prefix-runtime-addon-20261102-03.tar.gz`，73548 字节、SHA-256 `1f2c626e882476617d39fc5bc25c02f14bb8bcb3db90a6faa6b4d36d18836f1f`；H1 仍按原 D 固定 profile 选原 ZIP。APT、SDK14、H0 密文、recipe CAS 和 clang runtime 使用既有固定原件；H0/CAS 缓存只供控制器复用，不设再次下载 fallback。需要既有 `CI_INPUTS_PASSWORD`、两件 SDK SHA 与 `REKO_H0_INPUTS_PASSWORD`，秘密只经宿主 stdin/FIFO/内存，不进入日志或 C1 命令环境。不执行 H2 密码、新 J2、B 或 pip 流程，也不发布任何私有编译输入。

控制器在同一 open C1 执行原 D 单 tuple C，原 cell 和完整宿主 reader 通过后才交接 I2。producer 43 原件不变；原 I1D API 只生成一次独立物理 consumer 50，再在同一根排他增加 I2 两件成为 52，并复验全部 52 与原 43。宿主 I1D 两件不计入 52。前端保持原 H0 scope，8.5 使用 `8.5.3-host-ci-success`，不重放或重选 H0。I2 先执行并验真八 image Task，再执行现代八个或旧路线十二个原 font Task。

完整宿主静态 reader 在新进程认证 52 闭包，流式核最终前缀全部成员、十 image 加五 font 库的每个 Mach-O 对象、原 C/image 成员不变、目标 FriBidi、首 FT 覆盖前原归档及全部特性头。现代四份或旧路线六份特性探针绑定真实头、宏和编译器 argv；旧路线两次 apinames、全部实际保留 native 生成器均核原 ELF/DT_NEEDED 和固定包资格。宿主不执行返回 ELF，系统二进制 SHA 只记本轮认证观测，不声称宿主重算未回传系统二进制。

第五个 font 库是原 HarfBuzz 8.0.1 在 Cairo 禁用时仍按原 Makefile 无条件安装的 `libharfbuzz-cairo.a`。保持原 `--with-cairo=no` 与全部原 Task，不禁掉原安装产物，也不将该库称为已实现 Cairo 功能或空归档。新增私有 `font-harfbuzz-cairo-disabled.json` 绑定八份锁定原源码、三份实际配置及最终安装 `.pc`/`.la`，共十三份原字节；宿主从完整最终归档重算三原对象、安装头 `hb-cairo.h` 与锁定源码的 bytes/SHA 直接相等，以及认证本机 LLVM nm 的真实 argv/stdout和系统包身份。配置必须保持禁用 Cairo，符号中不得出现 Cairo API；`.la` 只核保留目标 HarfBuzz 且拒 Cairo 依赖，其他非 Cairo metadata token 留原观测，不声称完成通用依赖资格。宿主不执行返回目标库。

job 时限为 360 分钟。第一步从本 attempt 唯一当前 job 的 API `started_at` 得真实 UTC 起点并加 21600 秒；缺证据就失败，不以当前时间补默认值。控制器共用 `min(18000, 实际剩余秒数−3330)` 工作时限，覆盖准备/H0/C/image/font/全部 host readers。保留 30 秒子进程退出、120 秒容器清理、180 秒收尾和 3000 秒 CMS/上传，不累加各阶段时限。

远端入口为 18 GiB：16 GiB 工作估算及 2 GiB 余量，分项见 I3 固定计划。保留原采样 watcher，以及下载前和 driver 后可用空间证据；这些是估算和时间点观测，`measured_peak=false`。本机 16/4/25 GiB 规则不变。

I3 每个返回树先核逻辑 1 GiB、32768 成员及分配量，复制后宿主再核。完整 CMS 封套保持固定 AES-256-GCM、RSA3072 OAEP-SHA256/MGF1-SHA256、原公开接收证书和全部原身份。上限为单件 1 GiB、73728 成员、总 3 GiB：给两个 I3 有界返回树各 32768/1 GiB，另给原 D/workflow 8192 成员/1 GiB 余量。超额失败并保留原诊断，不截断清单或回退明文上传。封套身份清理读取限 32 MiB，与完整成员清单匹配，其余所有权小文件仍维持原 1 MiB 上限。CI 不持有真实接收私钥。

公开只允许有限摘要、CMS 自检、完整身份清单和认证密文。摘要只在实际 I3 `TASK=R00-02J11I3`、`RESULT=single_tuple_actual_C_original_image_and_font_verified`、19 pin、consumer 52、15 库与全部 host-reader 证明同时成立时登记本轮有限结果；新增两项 host-reader 正证明 `disabled_HarfBuzz_Cairo_provenance_verified` 与 `installed_HarfBuzz_Cairo_header_source_verified` 必须同时为真，`HarfBuzz_Cairo_feature_enabled` 和 `Cairo_other_metadata_dependencies_generally_qualified` 必须为假；仅这些有限布尔和计数进入公开摘要，不公开十三份原件、metadata token 或 nm stdout。完整 returned-files 清单仍只在私有日志。`always` 收尾仅按新控制器真实身份、本 job 票据及精确 C1 id/image 和临时根 inode 清理；名称为空仍查精确 id，同名替换拒绝。原私有证据仅在完整 CMS 身份复核后回收。

本工作流部署不计真实 font 编译验收。每次实际原件仍需本机认证、ROOT 和独立静态验收。ROOT 独立验收、shared provider、G1/G2、Cubism、完整引擎与 iOS 会话都保持未通过；人工和真机验收保持 `deferred`。

工作流405746285已通过分支注册，临时push入口已移除，job仅允许workflow_dispatch。注册run41645605249实际completed/skipped，未执行字体编译；实际调度仍须对应image原件先完成ROOT及独审接受。

07公开摘要按四个精确组合核辅助资格：8.5.3/24.04为false/false/整数0/整数0；8.4.1/24.04为true/true/整数12/整数805068；8.3.7或7.8.7/22.04为true/true/整数12/整数797809。未知组、缺字段、bool冒充整数或旧805068套22均拒绝；实际helper原件、包查询和系统链仍只进入CMS私有证据。

历史02（2026-11-03）：首字体先导41648269103保留失败。原C/image、FriBidi与首FT安装rc0后，系统包资格检查拒绝；具体owner未被旧日志记录。14af937仅修Multi-Arch包名/架构规范与诊断，原APT清单与Task不变，40项回归和独审通过；7370e88监督绑定35项通过。本轮02仅换这件已提交worker，随后唯一同tuple重试；部署不计字体构建通过。

历史03（2026-11-03）：第二先导41654292030保留失败，原C/image/Fribidi/首FT命令rc0，实际31个man3安装路径未列入旧模型。39c350d仅补原安装规则支持的208文件/6目录及未知路径诊断，47项回归与cc619fbd独审通过；581c7e1监督绑定35项通过。03只替换这件已提交worker，其他10文本/原9不变；原HB预生成HTML与CMake安装仅按源码合同建模，不称已实跑通过。下一仅重试相同8.5.3/sim-arm64，部署/输入发布不计font通过。

历史04（2026-11-04）：第三先导41665830759保留失败，原HB安装后出现原模型未收录的 cairo archive、libtool 和 pkgconfig 三件产物。已认证419成员诊断及原上游8.0.1源码确认该安装规则无条件执行，但实际Cairo配置为禁用。b7be891只补完整原安装闭包、禁用配置/原源码/三对象/安装头绑定；原Task、configure、SDK及image依赖均不改。消费者先55项、后受影响新增9项回归通过，旧47项AST不变，不称为一次56项套件。04只替换这两件已提交I2文本，其他九文本不变；第二I3原子从完整回传原字节重算新证明并要求15库，42项回归及50c212独审通过；该套件仅为协议回归，不是实际Linux字体构建。本轮部署及输入发布均不计font编译验收，下一次仍仅重试同一8.5.3/sim-arm64。

历史05（2026-11-04）：04首8.5.3/sim-arm64实际通过ROOT与独立完整静态验收，其余两现代ABI CI成功待本机接受；不把这些计为App或字体功能运行。旧8.4.1/sim-arm64先导41682908096的378私有成员已认证，原八image Task/17命令rc0，随后整个workspace库存拒绝旧Brotli bootstrap生成的compile symlink，font0/12尚未开始。旧raw缺readlink字面，不假定具体目标或据APT版本猜allowlist。

05仅同一失败tuple诊断重试，属于已有I6矩阵故障调查，不要求将这次尚未完整接受的image标记通过，也不扩展另外八font tuple。18a0870只在原失败handler增加no-follow有界symlink字面/mode/rawSHA及截断证据，原Task/bootstrap/relative source-prefix守卫/finally全部不变；64项完整回归/2.982s及独审1b4eb975通过。d1c9a31只绑定新worker，原I2计划不变，5项绑定回归/.708s与实际原43→唯一physical52及fresh I2合同通过、临时目录清；独审7b490c95通过。包05只替换worker，其他十文本与04相同；仅11构建文本公开，其余诊断继续CMS封装。诊断预期仍可失败，不计font成功；取得完整原链接字面后另按原native包原件作窄资格适配，不泛放任意外部链接。
历史06（2026-11-04）：诊断先导41694447746保留失败，379私有成员全部认证。原八image Task/17命令rc0后，库存仍拒绝旧Brotli1.0.9 bootstrap按原命令生成的绝对helper链接；font0/12尚未开始。诊断已经给出12条精确生成边及其余32条相对边，但旧原件未导出现场helper目标bytes或包owner，不追认它们已通过资格。

I2提交 `c4cc27d9bdd35ed3b9535e8745da4f5c7eaf39ca` 只在8.4.1/Ubuntu24.04两个post-image快照使用自有pure adapter：核12条原literal、14个系统链节点、3个固定APT包版本/owner，以及总805068字节的12个普通helper原件；两个阶段比较模式、raw SHA、inode/device/mtime/ctime/nlink/uid/gid及run/workspace身份。未知、缺件、换owner/版本/原件或链路借道均拒绝。其余相对链接继续走原guard，原Task/bootstrap、baseline/preclaim及source/prefix/ELF门禁全部不变，不对Ubuntu22.04生成允许表。ROOT80项回归及完整源码独审通过；这仅是工具验证。

I3提交 `9787bbfed47e7ba4512affc2bae8d46c26c1a12f` 从返回的12个普通0600 raw、两次完整资格侧证独立重算固定bytes/SHA/14chain/3package查询原stdout，绑定同次handoff、producer-owner、单claim、workspace-cleanup、原C收据/complete前库存及原Task完整命令日志。ROOT58项回归、真实原43→唯一physical52、fresh I2合同与独审通过。系统fingerprint和系统链接字面属于当次认证CI观测；宿主不restat已删除C1，不宣称重算未返回的32相对图或最终image/font marker bodies。最终prefix中的全部链接仍由原完整tar守卫实际重算。

公开摘要增加且只增加四个有限字段：`image_native_helpers_required`、`qualified_image_native_helpers_verified`、`image_native_helper_raw_count`、`image_native_helper_raw_bytes`。8.4.1必须显式true/true/整数12/整数805068；现代8.5.3必须显式false/false/整数0/整数0，其他无例外路线也仅允许false/false/0/0。缺任一字段、bool冒充整数或数值不符都拒绝；失败不填默认资格成功。不公开raw正文、包查询、系统路径或fingerprint；它们仍只随既有CMS私有封套返还。

06包已公开Release406525604/asset706865942，只替换c4cc的I2两件文本，前9件与05逐字相同；包不含805068原生raw、I3控制器、SDK或编译产物。原SDK名称/密文SHA、stdin解密、18GiB入口/6h时限/3330保留、CMS及精确cleanup原体保持；cleanup的expected_tool字节身份同步为88982以匹配真实新控制器。此次部署只允许同8.4.1/sim-arm64先导重试，不扩展其余旧font tuple；当次真实原件仍待ROOT与独立完整验收，不把旧失败、输入发布或微回归计为font通过。

07续推（2026-11-04）：I2 caae7e5明确22.04的原12路径/14节点/3APT/797809B，I3 d5edfbe按真实Ubuntu独立重算；11文本07只替换I2两件，原九件与06相同。已有8.5.3与8.4.1各三架构静态接受，本次不重派它们或已验SDL12。工作流部署、远端发布、先导实际执行和ROOT/独立接受分别记账；在远端身份及授权通道确认前不调度，不将本地验证计CI成功。
