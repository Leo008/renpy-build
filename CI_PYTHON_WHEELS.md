# 固定 Linux Python2 纯 wheel 生成

本任务只在固定 jammy amd64 容器中使用真实系统 CPython2.7.18 生成 future0.18.3 / pefile2019.4.18 两份纯 wheel。系统解释器只承担 producer，不替代 iOS CP27 或精确原版 CPython 输入、J2C 的九个 scope、完整 Ren’Py 构建或运行时验收。

## 原件与边界

完整保留 `scripts/renpy` 下四份原工具/JSON，部署步骤分别为 L1/L2，逐字节SHA与 Reko 原件相同。实际只取两份原 sdist 与六份 builder wheel，八原件共10047371字节；不删原锁的其余 scope，不将未选 py3 job 写成通过。host prepare 只允许官方已锁 files.pythonhosted.org 地址并核完整字节/归档/元数据；run 不含下载回退。

APT 来自 run41419224335 的完整 Ubuntu22.04 bundle，manifest SHA `d722e3aa9db55925062e70a35486e1e0b1405c064a6dc5a8b7a289900d5c6851`。collector SHA `f0644a862ea95fcafb27e78ab27c8232b5d8c128a1d59cce179f164aa7ddf4ac`；C0 安装阶段 SHA `c4584adae0e197c3c934bba0e5d00f08307788ef819707e640e3d12513f74839`。host 编排显式使用 `/usr/bin/python3.10`，记录实际版本，内层系统Python2.7/3.10的版本、真实路径、SHA和基础模块必须实跑核验。

容器固定 OCI child/image ID、全程 network none、无挂载/凭据，非 privileged；只在这个临时容器给予 SYS_ADMIN 和 seccomp=unconfined 供实际 unshare 网络命名空间证明，启动后核对 inspect 的完整约束。重验 base dpkg/keyring/签名、有效 APT 配置和原包传输，离线 no-download/no-remove 安装并核精确包增量。SDK/游戏/机密输入均不参与此任务。

## 验证和证据

B1 原构建器必须证明同一 Python 的回环成功对照及新 netns 的实际拒绝，环境变量或 Docker network none 不替代该证据。builder 在独立无pip环境使用已锁 setuptools/wheel/virtualenv，两个输出核纯Python标签、METADATA/RECORD及完整内容；helper 再将全部实际 payload 与原 sdist 字节直接对照，拒绝源/收据/产物错配。

公开 evidence 只保留完整阶段报告、原命令日志、两个实际wheel及构建器原报告，禁止复制整个 venv/bootstrap/source 目录来冒充已消费。未选的四job保持 not_run；exact-target、导入、J2C、iOS runtime 字段保持 false。always清理本轮生成容器，失败或缺少Python/内核隔离不能计为通过。完成后由 Reko 主代理下载原ZIP独立核SHA、报告/源码/工具/产物身份，再在 J2B2 登记真实结果。
