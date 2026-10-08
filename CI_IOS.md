# Ren’Py 8.5.3 iOS 源码构建

本分支 `codex/ios-8.5.3-actions` 从官方构建提交
`7bfab40c1174f622f644b24669afd5fb167fbb79` 创建，搭配引擎提交
`39895c1e017f0b36ffea2447d97eccd69d76ee1c`。保留 SDL2、CPython 3.12.8、
Cython 3.1.4、LLVM 18 和官方 iOS 配方；不能换成已切换 SDL3 的最新 master。

## 构建输入

在本 fork 的 Settings → Secrets and variables → Actions 配置下面六项输入 secrets 和一个 `CI_INPUTS_PASSWORD` 解密 secret。
URL 指向本 fork 的 `ci-inputs-8.5.3-20261008` prerelease 中的 `.enc` 加密附件。
本地使用随机 256 位口令、AES-256-CBC、PBKDF2-SHA256（200000 次，8 字节随机盐）加密；
口令仅经 stdin 写入 GitHub Actions secret，未写入 Git、命令参数或日志。
SHA256 是解密后原文件的实际 SHA-256。工作流在解包前校验完整明文哈希。不能把 access token、私有下载 URL、Apple SDK 或 Cubism SDK 提交进 Git。

| 文件 | 下载地址 secret | SHA-256 secret |
| --- | --- | --- |
| `iPhoneOS14.0.sdk.tar.gz` | `IOS_DEVICE_SDK_URL` | `IOS_DEVICE_SDK_SHA256` |
| `iPhoneSimulator14.0.sdk.tar.gz` | `IOS_SIMULATOR_SDK_URL` | `IOS_SIMULATOR_SDK_SHA256` |
| `CubismSdkForNative-5-r.4.1.zip` | `CUBISM_SDK_URL` | `CUBISM_SDK_SHA256` |

前两项使用 Xcode 12.0 的 SDK，在 `tars` 目录执行官方脚本：

```sh
bash ios_toolchains.sh /path/to/Xcode_12.app
shasum -a 256 iPhoneOS14.0.sdk.tar.gz iPhoneSimulator14.0.sdk.tar.gz
```

路径避免空格（上游提取脚本未完整引用路径）。该脚本还会复制 Xcode 工具链的 libc++ 头文件；
仅压缩 SDK 目录是不完整的。CI 检查归档根目录、`SDKSettings.plist` 的真实 `14.0` 版本和头文件。
Xcode 26.2 的 SDK 不能通过改名替代：使用它需要单独适配并验证官方交叉编译配方。

Cubism 使用用户从官网下载的 5-r.4.1 完整 SDK，仅提供 Cython/原生扩展编译头文件。
GitHub Framework release 不包含 Core。`tasks/live2d.py` 明确更新文件名和目录，不把新版本改名冒充旧版。
Ren’Py 8.5.3 已要求 Live2D 5.3 Core，而 5-r.4.1 Core 缺少 `csmGetRenderOrders`；
本工作流不链接/打包其 Core 二进制，不宣称 Live2D 已可运行。后续必须接入匹配 Core 并验收模型。
本地 `nm` 已确认 5-r.4.1 的 iPhoneOS 和 iPhoneSimulator Core 均缺少此符号；
其 Release 模拟器库仅有 x86_64，后续还需补齐 arm64 模拟器 Core。
依据：[Ren’Py 8.5.3 变更记录](https://www.renpy.org/doc/html/changelog.html)、
[Live2D 官方 Core 分发说明](https://docs.live2d.com/en/cubism-sdk-manual/cubism-sdk-for-native/)。
Steamworks 不用于此 iOS 目标，不要求提供。
独立 iOS 构建不会执行 `steam.build` 的桌面生成步骤，因此 `pythonlib` 在 iOS 上移除
`steamapi` 打包规则，避免最后阶段把本就未生成的桌面专用文件当作必需项；其余缺失模块继续报错。

## 执行与产物

推送到本分支自动执行 `.github/workflows/ios-8.5.3.yml`，使用 Ubuntu 24.04。
首次创建分支即可由 `push` 触发；GitHub 的 `workflow_dispatch` 需要工作流先存在于默认分支，
因此在未合并默认分支时，请使用已有运行的 Re-run 或再次推送。
fork 如果尚未启用 Actions，先在网页 Actions 中启用工作流。

2026-10-08：已完成独立 GitHub 授权、同版 libc++ 头文件补齐、SDK 真实版本和哈希校验、
输入加密与本地解密验证。使用者已明确授权将三个加密输入上传至自己的公开 fork，仅用于自行构建。
首个配置提交使用 `[skip ci]`，待输入附件上传完成后再推送本说明更新来触发首轮源码构建。

工作流从空构建目录开始，顺序编译 device arm64 和 simulator x86_64/arm64。
这三种架构是官方 `renios.lipo` 的固定聚合输入。模拟器切片不会增大真机 App。
不恢复 `tmp/complete`、安装目录或构建目录，每轮仍从头执行官方任务。
只缓存 `.ci-ccache` 中的编译结果（上限 2 GiB），保留 ccache 默认的源码、头文件和编译参数校验，
编译器身份使用内容哈希；不启用 sloppiness。SDK 归档、SDK 目录、Cubism 原包和凭据不进入缓存。
使用独立 restore/save 步骤，失败轮次也保存已完成的编译结果，日志记录命中统计。
缓存按 Ubuntu 24 / LLVM 18 / 8.5.3 分组，每次运行使用新 key；缓存服务故障不会阻止完整构建。
本次新增缓存的首轮没有历史缓存可恢复，后续轮次才可受益；配置、链接、Cython 生成仍会执行，
具体提速以实际命中统计和耗时为准。
依据：[GitHub 缓存说明](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)、
[ccache 校验机制](https://ccache.dev/manual/latest.html)。

CI 从 Ubuntu 仓库安装编译依赖，并使用本提交的 `requirements.txt` 建立宿主 venv，直接调用
`python -m renpybuild`（与 `build.sh` 相同入口）。不执行上游 `prepare.sh` 的分支拉取及桌面启动步骤，
避免它更换已锁定的引擎或要求 Linux 图形界面。目标 CPython 仍由官方任务从 3.12.8 源码编译。
LLVM 15 仅用于上游硬编码的 lipo/otool 检查，编译器为 LLVM 18。

### 已定位的 CI 失败及修复

运行 `37742861468` 在 `build-libavif.ios-arm64` 失败：
`clang-18: error: -framework MetalANGLE: 'linker' input unused [-Werror,-Wunused-command-line-argument]`。
上游 `metalangle.annotate` 将链接参数混入 CFLAGS/CXXFLAGS，libavif 启用 `-Werror`；
较新的 CMake 路径又会移除 CC 中原有的 unused-argument 抑制参数，因此错误在此处暴露。
修复将 `-framework MetalANGLE` 和链接搜索路径移入 LDFLAGS，编译参数保留 `-F` 和 `-DMETALANGLE`。
没有关闭 `-Werror`，也没有移除 AVIF 或 MetalANGLE 功能。

本地使用 Xcode Clang、iOS 14 SDK 和实际 MetalANGLE framework 验证了三架构 × C/C++：
旧参数六组均复现错误；新参数六组编译与链接均通过。该验证不等同于 Linux Clang 18 完整构建通过，
后者以修复提交的新 Actions 结果为准。

运行 `37746797824` 已通过上述 MetalANGLE 修复和三架构依赖构建，源码阶段耗时约 42 分钟，
随后在 `build-librenpy.ios-arm64-py3` 失败：`core.c` 与 `renpysound_core.c` 找不到
`renpy.pygame.surface_api.h`。官方 `gen_static3` 使用 `RENPY_STATIC=1`，输出到
`tmp/gen3-static`，但原生编译任务只添加了 `tmp/gen3` 搜索路径；干净 CI 没有普通构建的历史头文件。
修复 C/C++ 搜索路径为静态生成目录，并在生成结束后立即检查必需 API 头文件，缺失时明确报错。
本地用锁定的 Cython 3.1.4 实际生成 surface API，再编译两个真实失败源文件：
旧路径两项均复现同一缺失头文件错误，新路径两项均通过。
此回归使用 macOS Clang、宿主 Python 3.13 头文件与 SDL2 头文件，只验证路径问题；
Linux Clang 18 / CPython 3.12.8 / 三架构完整结果仍以 Actions 为准。
CPython 安装日志中的 `_multiprocessing` 缺失是上游 `compileall -j0` 的已忽略错误，
相关任务随后完成；它不是此轮使 Actions 退出的原因。

运行 `37754960959` 已完成三架构源码编译、标准库打包和官方 lipo 聚合，
但 `tools/ci_ios.py package` 对普通 `ar` 归档执行 `llvm-lipo-15 -archs` 时 SIGSEGV。
这是校验工具的输入处理缺陷：`printBinaryArchs` 没有普通 Archive 分支，
落入 IRObjectFile 强制转换。已核对 LLVM 15.0.7 和 18.1.8 官方源码中都有同一逻辑，
因此不能假定升级到 LLVM 18 就会修复，也没有证据把它归因于 LTO/bitcode 版本不匹配。
依据：[LLVM 15 的实现](https://github.com/llvm/llvm-project/blob/llvmorg-15.0.7/llvm/tools/llvm-lipo/llvm-lipo.cpp#L382)、
[LLVM 18 的实现](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/llvm/tools/llvm-lipo/llvm-lipo.cpp#L379)。

校验函数识别普通归档后，先用已有且成功执行的 `-create` 路径封装临时单切片 universal，
再用 `-archs` 查询；临时文件随即清理，原始库不改写。原有精确架构集合检查继续保留。
新增 `check-tools`：完整编译前用 Linux Clang 18 / llvm-ar-18 生成真实 arm64/x86_64 归档，
验证普通与双架构归档的查询路径，尽早暴露工具问题。
本地 Xcode lipo 验证三目标归档、双架构聚合、10 个官方核心库和损坏归档拒绝路径通过；
Linux 工具检查和最终 CI 打包结果仍需实际运行确认。
本轮已保存约 250 MB 的 ccache，后续可恢复；不复用完成标记或安装目录。

### 已通过的源码 CI

2026-10-08，修复提交 `37b59c805d481b976b4ceb26fcad0aade52d4783` 对应的
[运行 37760587281](https://github.com/Leo008/renpy-build/actions/runs/37760587281) 已全部成功。
Linux 工具链提前检查、三架构源码编译、标准库打包、核心库精确架构校验、最终打包及 artifact 上传均通过。
产物为 `renpy-8.5.3-ios-source-37760587281-1`，另有日志和构建报告 artifact。
恢复上一轮 ccache 后，可缓存编译调用命中率 96.22%；源码阶段为 884.3 秒，
上一轮为 2037.7 秒（约 34 分钟降至 14 分 44 秒）。此对比不是整个 job 的耗时。
这确认源码 CI 阻塞已解除，macOS XCFramework 封装、Xcode 完整链接和运行验收仍需后续完成。

成功后提供 `renpy-8.5.3-ios-source-<run>-<attempt>` artifact，包含 tar.gz 与 SHA-256：

- `renios/`：官方模板、静态库与 MetalANGLE。
- `lib/python3.12/`：官方配方生成的标准库字节码。
- `engine/renpy/`：匹配此原生模块集的引擎脚本。
- `include/<arch>/`：后续 Xcode 封装使用的头文件。
- `build-report.json`：提交、输入哈希、静态库哈希与验收状态。

日志 artifact 无论成功或失败都会上传，包含完整编译输出、输入哈希、APT 包清单及宿主 pip 清单；
下载地址、SDK 原包和临时环境目录不会作为 artifact 上传。产物保留 14 天。
APT、PyPI 部分传递依赖及上游通过 tag 拉取的源码仍可能变化，清单用于追踪，尚不承诺 bit-for-bit 可复现。

此阶段输出官方静态对照包。上游库最低目标仍为 iOS 13，宿主 App 的 iOS 14 目标可以使用；
不在这个对照步骤强改上游为 C++20。后续需要在 macOS 封装 XCFramework、完整链接并测试真机，
才能替换 Reko 的现有对照产物。源码编译通过不代表共享 C 库、多 Python ABI、旧游戏兼容已完成。

8.4.1、8.3.7/7.8.7 必须使用各自锁定构建提交及 Python/Cython 环境，
不能只在本工作流中替换 `ENGINE_COMMIT`。先验证此分支，再将历史组落到 Ubuntu 22.04 的独立版本分支。

## GitHub 身份隔离

只使用独立 `GH_CONFIG_DIR` 登录 GitHub，不运行全局 `gh auth setup-git`。
提交使用仓库局部 `user.name/user.email`；推送时用命令级 credential helper，
不会覆盖公司 GitLab 的全局用户名、邮箱或凭据助手。授权需具备仓库写权限与 workflow 权限。
