# 四个 Linux host 前端离线重放

本轮只运行两组固定容器中的四个 host scope；不执行五个精确 target scope、hostpython 自举、完整引擎构建或 Reko 产品会话。每组原 replay 必须返回 exit2，所选两项 offline_replayed，其余七项 not_run；H0 wrapper 仅登记本组成功，J2C_complete 始终 false。

输入使用 Reko H0 原件与固定计划，103个原件137278199B，完整核验原九scope/18来源与Darwin四产物原收据。原receipt及producer平台不改写。C1两组APT取自41419224335，固定OCI child及image ID；在无挂载/network none/非privileged的容器重新验证签名、base和完整no-download安装。SYS_ADMIN及seccomp=unconfined仅用于实际unshare回环成功/隔离失败对照，原任务仍受固定入口限制。

加密输入发布asset701436384，cipher116556720B/SHA 4beeb8544d248c59f7f12216cd11a8d291d0d4edcf660eb854fbc4abcb1b34c5，plain116556690B/SHA 3d33a763aed626af50ab56e7ea07904e3930e26e871bb12a8ed81fd15a3f280a。AES256CBC/PBKDF2-SHA256/200000/salt8；host secret读取后删除环境项，仅通过stdin传OpenSSL。密钥、cipher、明文归档和输入解包目录均不上传；不消费Apple SDK。临时目录在checkout/evidence外0700，finally和always清理。四原件SHA在运行前重核，不依赖pyc或环境同名模块。

每组保存真实 transport/H0/replay报告、原commands和stdout/stderr；不复制venv、输入cache或构建源码。只在实际解释器hash/版本、完整安装RECORD、模块来源、CA资源、requests准备及RSA/ECDSA签名验证均通过后登记selected host成功。实际失败/未执行保持原状态，产物ZIP和日志待主代理完整下载独立复核后验收。
