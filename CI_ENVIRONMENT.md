# 固定 Linux / SDK14 交叉工具预检

本任务只验证新候选环境能离线安装固定 APT 输入并执行 Apple 目标编译、链接和归档检查。它不运行 Ren’Py 源码构建，也不代表历史 GitHub VM、完整 Python 分发闭包或 Reko 会话验收通过。

## 固定输入

- APT 来自 run `41419224335`，candidate `ec6a6aef9e53f15638f71488aa39342f630456fa`；22.04 manifest SHA `d722e3aa9db55925062e70a35486e1e0b1405c064a6dc5a8b7a289900d5c6851`，24.04 为 `5b95f5dbd2490bc262a0d3150211bcc09178b3c452967829590b235314550d6d`。两者来自独立作业日志，实际原件均需逐字节重核。
- `tools/ci_environment.py` 是 Reko `preflight_environment.py` 原件，SHA `0d20cb8d8f01f2c0efc3b232f092256ff863952efe89d48500c8e91bcb74f939`。collector SHA `f0644a862ea95fcafb27e78ab27c8232b5d8c128a1d59cce179f164aa7ddf4ac`。
- `prebuilt/clang_rt.tar.gz` 20,524,009 bytes，SHA `c2c69498077f9e29a6299952be1b11bc02c2d05f3a9174c863a41d87bfbc8c0c`，资源目录由实际 LLVM 查询，并逐成员验证 overlay。
- 两份 SDK14 仅宿主从既有加密输入取得，固定原包大小/SHA 与 repository secret SHA 双重核对。解密密码不进命令参数/日志，凭据不进入容器。私有材料位于 checkout 与 evidence 外的 `runner.temp/reko-j4c-sdk-inputs`，目录权限 0700，always 清理；兜底只删除符合名称、network none/无挂载契约的本轮预检容器。原始 SDK、解包 SDK 和密文均不上传。

## 执行与证据

推送本分支上三个相关文件会执行两组矩阵；也可在本分支手动 dispatch。使用固定 actions 提交、只读权限、关闭 checkout 凭据持久化。先核对部署文件，再核全部 APT 原件；实际新容器固定为 linux/amd64 OCI child digest、无挂载、全程 network none。重新检查 base dpkg/keyring、gpgv、有效 APT 配置，以 no-download/no-remove 安装固定缓存，核对安装包增量和 LLVM15/18 实际可执行身份。

使用 SDK14 对真机 arm64、模拟器 arm64/x86_64 编译 C/C++，检查 Mach-O CPU、平台、SDK14 和最低版本；第三方配方目标13，arm64 模拟器实际最低14，产品最低14不变。链接实际 availability runtime，检查普通归档、同平台 universal 与逐成员回提，并执行损坏归档/错架构拒绝探针。

公开 artifact 仅包含明确白名单中的 JSON 身份/状态、命令及原日志hash、生成的 checksum/脚本及自制探针原码与产物。原始SDK编译/链接诊断可能含头文件片段，因此不直接显示或上传 commands 整目录；只按精确label白名单、原路径/类型/大小/SHA重核后复制公共日志，九份SDK编译/链接原诊断和未知命令均仅保留hash。SDK 字节不会被拷回证据目录。`preflight-report.json` 每个阶段仅在实跑成功后 true，失败/未执行仍 false；commands 的 expected_failure 标注必须来自实际正常非零退出。源码构建、Python 重放、历史 VM 与 Reko runtime 等 limits 保持 false。失败诊断保留原日志，不对下载/编译失败计通过。
