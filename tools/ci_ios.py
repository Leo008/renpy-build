#!/usr/bin/env python3
"""校验私有构建输入并打包官方 iOS 源码构建结果，不改变上游任务配方。"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parents[1]
BASE_COMMIT = "7bfab40c1174f622f644b24669afd5fb167fbb79"
ENGINE_COMMIT = "39895c1e017f0b36ffea2447d97eccd69d76ee1c"
LIPO = "llvm-lipo-15"
INPUTS = (
    ("IOS_DEVICE_SDK", "iPhoneOS14.0.sdk.tar.gz"),
    ("IOS_SIMULATOR_SDK", "iPhoneSimulator14.0.sdk.tar.gz"),
    ("CUBISM_SDK", "CubismSdkForNative-5-r.4.1.zip"),
)


def log(message):
    """向 Actions 控制台输出可定位阶段的中文日志，禁止输出输入下载地址。"""
    print(f"[RenPyCI] {message}", flush=True)


def sha256(path):
    """流式计算大体积 SDK 或产物的 SHA-256。"""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def git(*args, cwd=ROOT):
    """执行只读 Git 查询，失败时保留退出状态。"""
    return subprocess.check_output(["git", *args], cwd=cwd, text=True).strip()


def validate_sdk(path):
    """检查真实 SDK 版本及官方交叉编译需要的 libc++ 头文件。"""
    root = path.name.removesuffix(".tar.gz")
    with tarfile.open(path) as archive:
        members = {m.name.removeprefix("./"): m for m in archive.getmembers()}
        if any(name.split("/")[0] != root or ".." in name.split("/") for name in members):
            raise ValueError(f"{path.name} 的归档根目录不符合官方配方")
        key = root + "/SDKSettings.plist"
        if key not in members or not members[key].isfile():
            raise ValueError(f"{path.name} 缺少 SDKSettings.plist")
        with archive.extractfile(members[key]) as stream:
            settings = plistlib.load(stream)
        if settings.get("Version") != "14.0":
            raise ValueError(f"{path.name} 的实际版本不是 14.0，禁止改名冒充")
        if root + "/usr/include/c++/vector" not in members:
            raise ValueError(f"{path.name} 缺少 Xcode 工具链的 libc++ 头文件")


def fetch_inputs():
    """先检查所有必需凭据，再下载并校验三个授权输入，缺失即终止。"""
    missing = [f"{prefix}_{suffix}" for prefix, _ in INPUTS
               for suffix in ("URL", "SHA256") if not os.environ.get(f"{prefix}_{suffix}")]
    if not os.environ.get("CI_INPUTS_PASSWORD"):
        missing.append("CI_INPUTS_PASSWORD")
    if missing:
        raise ValueError("缺少仓库 Actions secrets：" + ", ".join(missing))
    hashes = {}
    for prefix, name in INPUTS:
        url = os.environ[f"{prefix}_URL"]
        expected = os.environ[f"{prefix}_SHA256"].strip().lower()
        if not url.startswith("https://") or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError(f"{prefix} 必须提供 HTTPS 下载地址及真实 SHA-256")
        path = ROOT / "tars" / name
        temporary = path.with_suffix(path.suffix + ".part")
        log(f"下载并校验 {name}")
        try:
            with urllib.request.urlopen(url, timeout=120) as response, temporary.open("wb") as output:
                if not response.url.startswith("https://"):
                    raise ValueError("下载被重定向至非 HTTPS 地址")
                shutil.copyfileobj(response, output)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise ValueError(f"{name} 下载失败，请检查私有地址或有效期") from None
        # 密钥经环境传递；解密前不解包，解密后首先校验可信 secret 中的完整 SHA-256。
        plaintext = path.with_suffix(path.suffix + ".decrypted")
        command = ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000",
                   "-md", "sha256", "-pass", "env:CI_INPUTS_PASSWORD",
                   "-in", str(temporary), "-out", str(plaintext)]
        help_text = subprocess.run(["openssl", "enc", "-help"], capture_output=True, text=True).stderr
        if "-saltlen" in help_text:
            command.extend(["-saltlen", "8"])
        result = subprocess.run(command, capture_output=True)
        temporary.unlink(missing_ok=True)
        if result.returncode != 0:
            plaintext.unlink(missing_ok=True)
            raise ValueError(f"{name} 解密失败，请核对 CI_INPUTS_PASSWORD")
        if sha256(plaintext) != expected:
            plaintext.unlink()
            raise ValueError(f"{name} SHA-256 不匹配")
        plaintext.replace(path)
        if name.endswith(".tar.gz"):
            validate_sdk(path)
        else:
            with zipfile.ZipFile(path) as archive:
                header = "CubismSdkForNative-5-r.4.1/Core/include/Live2DCubismCore.h"
                if header not in archive.namelist():
                    raise ValueError("Cubism SDK 缺少官方 5-r.4.1 头文件；Framework 包不能替代")
        hashes[name] = expected
    directory = ROOT / "tmp/ci"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "inputs.json").write_text(json.dumps(hashes, indent=2) + "\n")
    log("全部输入已验证；下载地址不会写入日志或产物")


def check_space():
    """提前检查源码构建可用空间，避免长时间构建后磁盘耗尽。"""
    free = shutil.disk_usage(ROOT).free / 1024 ** 3
    log(f"剩余空间 {free:.1f} GiB")
    if free < 40:
        raise ValueError("准备依赖后至少需要 40 GiB 空闲空间，请使用更大 runner")


def library_architectures(path):
    """将普通静态归档临时封装后读取架构，避开 llvm-lipo 的归档查询崩溃。"""
    with path.open("rb") as stream:
        is_archive = stream.read(8) == b"!<arch>\n"
    with tempfile.TemporaryDirectory(prefix="renpy-lipo-") as directory:
        query = path
        if is_archive:
            query = Path(directory) / "universal.a"
            subprocess.run([LIPO, "-create", str(path), "-output", str(query)], check=True)
        return set(subprocess.check_output([LIPO, "-archs", str(query)], text=True).split())


def check_tools():
    """在完整编译前实际验证普通归档和双架构归档的校验路径。"""
    with tempfile.TemporaryDirectory(prefix="renpy-tool-check-") as directory:
        root = Path(directory)
        libraries = []
        results = {}
        for arch, target in (("arm64", "arm64-apple-ios13.0"),
                             ("x86_64", "x86_64-apple-ios13.0-simulator")):
            obj = root / f"{arch}.o"
            library = root / f"{arch}.a"
            subprocess.run(["clang-18", "-target", target, "-x", "c", "-c", "-",
                            "-o", str(obj)], input="int renpy_ci_probe(void) { return 0; }\n",
                           text=True, check=True)
            subprocess.run(["llvm-ar-18", "rcs", str(library), str(obj)], check=True)
            actual = library_architectures(library)
            if actual != {arch}:
                raise ValueError(f"工具链普通归档架构异常：{arch} / {actual}")
            results[arch] = sorted(actual)
            libraries.append(str(library))
        universal = root / "universal.a"
        subprocess.run([LIPO, "-create", *libraries, "-output", str(universal)], check=True)
        actual = library_architectures(universal)
        if actual != {"arm64", "x86_64"}:
            raise ValueError(f"工具链双架构归档异常：{actual}")
        results["universal"] = sorted(actual)
    (ROOT / "tmp/ci/toolchain-check.json").write_text(json.dumps(results, indent=2) + "\n")
    log("工具链普通归档与双架构归档校验通过")


def package():
    """校验三架构核心静态库、标准库及完成标记，打包可追溯的原始产物。"""
    if git("rev-parse", "HEAD", cwd=ROOT / "renpy") != ENGINE_COMMIT:
        raise ValueError("引擎提交与 8.5.3 锁定版本不一致")
    subprocess.run(["git", "merge-base", "--is-ancestor", BASE_COMMIT, "HEAD"], cwd=ROOT, check=True)
    renios = ROOT / "renpy/renios3"
    stdlib = ROOT / "renpy/lib/python3.12"
    for relative in ("encodings/__init__.pyc", "pickle.pyc", "site.pyc"):
        if not (stdlib / relative).is_file():
            raise ValueError(f"标准库输出不完整：{relative}")
    required = ("libpython3.12.a", "librenpy.a", "librenpython.a", "libSDL2.a", "libavcodec.a")
    for arch, expected in (("arm64", "arm64"), ("sim-arm64", "arm64"), ("sim-x86_64", "x86_64")):
        for name in required:
            path = ROOT / f"tmp/install.ios-{arch}/lib" / name
            actual = library_architectures(path)
            if actual != {expected}:
                raise ValueError(f"{arch}/{name} 架构异常：{actual}")
        marker = ROOT / f"tmp/complete/link_ios-renpython.ios-{arch}-py3"
        if not marker.is_file():
            raise ValueError(f"缺少官方完成标记：{marker.name}")
    for variant, expected in (("release", {"arm64"}), ("debug", {"arm64", "x86_64"})):
        for name in required:
            path = renios / "prototype/prebuilt" / variant / name
            actual = library_architectures(path)
            if actual != expected:
                raise ValueError(f"renios 聚合产物错误：{variant}/{name}")
    if not (renios / "prototype/Frameworks/MetalANGLE.xcframework/Info.plist").is_file():
        raise ValueError("缺少 MetalANGLE.xcframework")
    products = {str(p.relative_to(renios)): sha256(p)
                for p in sorted((renios / "prototype/prebuilt").rglob("*.a")) if not p.is_symlink()}
    report = {
        "renpy_version": "8.5.3", "build_base": BASE_COMMIT,
        "build_commit": git("rev-parse", "HEAD"), "engine_commit": ENGINE_COMMIT,
        "runner": os.environ.get("ImageVersion"), "run_id": os.environ.get("GITHUB_RUN_ID"),
        "inputs": json.loads((ROOT / "tmp/ci/inputs.json").read_text()),
        "libraries": products, "source_build_verified": True,
        "xcode_link_verified": False, "runtime_verified": False,
        "cubism_headers": "5-r.4.1", "cubism_core_bundled": False,
        "live2d_runtime_verified": False,
        "live2d_runtime_requirement": "8.5.3 requires Live2D 5.3 Core with csmGetRenderOrders; 5-r.4.1 Core is insufficient",
        "note": "官方静态对照包；尚未完成共享 C 库、多 ABI 符号隔离或真机验收。",
    }
    report_path = ROOT / "tmp/ci/build-report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    output = ROOT / "dist/renpy-8.5.3-ios-source.tar.gz"
    output.parent.mkdir(exist_ok=True)
    with tarfile.open(output, "w:gz") as archive:
        archive.add(renios, arcname="renios")
        archive.add(stdlib, arcname="lib/python3.12")
        archive.add(ROOT / "renpy/renpy", arcname="engine/renpy")
        for arch in ("arm64", "sim-arm64", "sim-x86_64"):
            archive.add(ROOT / f"tmp/install.ios-{arch}/include", arcname=f"include/{arch}")
        archive.add(report_path, arcname="build-report.json")
    output.with_suffix(output.suffix + ".sha256").write_text(f"{sha256(output)}  {output.name}\n")
    log(f"产物校验完成：{output.name}；仍需 macOS 链接和真机验证")


def main():
    """分派 CI 阶段，向 Actions 返回真实失败状态。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("inputs", "check-space", "check-tools", "package"))
    stage = parser.parse_args().stage
    os.chdir(ROOT)
    try:
        {"inputs": fetch_inputs, "check-space": check_space,
         "check-tools": check_tools, "package": package}[stage]()
    except (ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError, zipfile.BadZipFile) as error:
        log(f"失败：{error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
