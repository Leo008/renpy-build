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
不恢复 `tmp/complete` 或二进制缓存，避免旧对象被当成本次源码构建。

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
