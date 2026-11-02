#!/usr/bin/env python3
"""固定APT材料在无网络Linux容器内安装并验证Apple交叉工具；不执行Ren'Py源码构建。"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import uuid


INPUTS = {
    "device_sdk": {"sha256": "2f4bb43a38dc20ec439d366449ff7933262f3767ccfe863f16c5d3a82499d287", "bytes": 27728304, "root": "iPhoneOS14.0.sdk", "canonical": "iphoneos14.0", "platform": "iphoneos"},
    "simulator_sdk": {"sha256": "4fea56f1b4751cfe7eb4ed92416f7e6d9087375c2144c33a5e9dd332d567bba5", "bytes": 21472366, "root": "iPhoneSimulator14.0.sdk", "canonical": "iphonesimulator14.0", "platform": "iphonesimulator"},
    "clang_runtime": {"sha256": "c2c69498077f9e29a6299952be1b11bc02c2d05f3a9174c863a41d87bfbc8c0c", "bytes": 20524009, "root": "darwin", "additional_roots": ["macho_embedded"]},
}
PHASES = ["input_bytes_verified", "container_identity_verified", "signature_reexecuted", "apt_install_verified",
          "resource_overlay_verified", "native_compiler_executed", "basic_cross_compiler_verified",
          "sdk_three_target_compiled", "sdk_three_target_linked", "thin_archive_verified", "simulator_universal_verified"]
LIMITS = ["host_kernel_reproduced", "historical_github_vm_replayed", "python_input_replay_executed",
          "full_source_build_executed", "Reko_runtime_accepted", "complete_input_closure"]
TARGETS = [("arm64", "arm64-apple-ios13.0", "device_sdk", "arm64", 2),
           ("sim-arm64", "arm64-apple-ios13.0-simulator", "simulator_sdk", "arm64", 7),
           ("sim-x86_64", "x86_64-apple-ios13.0-simulator", "simulator_sdk", "x86_64", 7)]
PACKAGE_FORMAT = '${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n'


def require(condition, message):
    """任何未执行、身份错误与异常结果均明确失败，不填默认成功。"""
    if not condition:
        raise ValueError(message)


def guarded(path):
    """拒绝输入/证据文件及全部父目录符号链接。"""
    path = Path(os.path.abspath(path))
    require(not any(p.is_symlink() for p in [path, *path.parents]), "路径包含符号链接：" + str(path))
    return path


def sha256(path):
    """对真实普通文件计算完整摘要，不依赖stat缓存。"""
    path = guarded(path)
    require(path.is_file() and stat.S_ISREG(path.lstat().st_mode), "缺少普通输入文件：" + str(path))
    value = hashlib.sha256()
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_new(path, data):
    """独占创建新证据，拒绝覆盖前轮结果。"""
    path = guarded(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)


def write_json(path, value):
    """以稳定JSON保存真实阶段状态与输入身份。"""
    write_new(path, (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode())


def load_collector(path, expected_sha):
    """独立SHA校验后才加载指定采集器，复用其完整APT字节和引用门禁。"""
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha or "") and sha256(path) == expected_sha, "采集器独立SHA不符")
    spec = importlib.util.spec_from_file_location("reko_locked_apt_collector", path)
    require(spec is not None and spec.loader is not None, "采集器无法加载")
    module = importlib.util.module_from_spec(spec)
    exec(compile(guarded(path).read_bytes(), str(path), "exec"), module.__dict__)
    require(all(callable(getattr(module, name, None)) for name in
                ("verify_bundle", "read_json", "Commands", "command_by_label", "base_packages", "valid_signatures", "check_apt_index_order")), "采集器接口不完整")
    return module


def archive_name(value):
    """归档成员必须为规范相对路径，保留合法树内链接但拒绝写出目录。"""
    value = value.removeprefix("./").rstrip("/")
    require(value and not value.startswith("/") and "\\" not in value
            and all(c not in ("", ".", "..") for c in value.split("/"))
            and not any(ord(c) < 32 for c in value), "归档路径越界")
    return value


def resolve_archive_link(name, entries, root):
    """按tar规则解析相对symlink和根相对hardlink，拒绝循环、逃逸与硬链悬空。"""
    pending, resolved, seen, expansions = name.split("/"), [], set(), 0
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            require(len(resolved) > 1, "归档链接逃逸根目录")
            resolved.pop()
            continue
        resolved.append(part)
        require(resolved[0] == root, "归档链接逃逸根目录")
        current = "/".join(resolved)
        entry = entries.get(current)
        if entry is None or not (entry.issym() or entry.islnk()):
            continue
        state = (current, tuple(pending))
        expansions += 1
        require(state not in seen and expansions <= 40, "归档链接循环或链过长")
        seen.add(state)
        target = entry.linkname
        require(target and not target.startswith("/") and "\\" not in target
                and not any(ord(c) < 32 for c in target), "归档链接目标越界")
        if entry.islnk():
            require(target in entries, "归档硬链接目标缺失")
            resolved = []
        else:
            resolved.pop()
        pending = target.split("/") + pending
    require(bool(resolved) and resolved[0] == root, "归档链接逃逸根目录")
    return "/".join(resolved)


def inspect_archive(path, identity):
    """解包前检查固定SDK/overlay归档结构、合法链接及真实SDK14设置。"""
    root = identity["root"]
    roots = [root, *identity.get("additional_roots", [])]
    with tarfile.open(path, "r:gz") as archive:
        entries = {}
        for member in archive:
            name = archive_name(member.name)
            require(name not in entries and any(name == r or name.startswith(r + "/") for r in roots), "归档根目录错误或成员重复")
            require(member.isfile() or member.isdir() or member.issym() or member.islnk(), "归档包含特殊文件")
            entries[name] = member
        for name, member in entries.items():
            require(not any(entries.get(str(parent)) and (entries[str(parent)].issym() or entries[str(parent)].islnk())
                            for parent in PurePosixPath(name).parents), "归档成员写入链接父目录")
            resolved = resolve_archive_link(name, entries, name.split("/")[0])
            if member.islnk():
                require(entries.get(resolved) and entries[resolved].isfile(), "归档硬链接未指向普通文件")
        result = {"root": root, "members": len(entries), "symlinks": sum(m.issym() for m in entries.values()),
                  "hardlinks": sum(m.islnk() for m in entries.values())}
        if "canonical" in identity:
            setting = entries.get(root + "/SDKSettings.json")
            require(setting is not None and setting.isfile(), "SDK缺少原始SDKSettings.json")
            settings = json.load(archive.extractfile(setting))
            require(settings.get("Version") == "14.0" and settings.get("CanonicalName") == identity["canonical"]
                    and identity["platform"] in settings.get("SupportedTargets", {}), "SDK版本/平台错误，禁止重命名替代")
            arches = settings["SupportedTargets"][identity["platform"]].get("Archs", [])
            required = {"arm64", "x86_64"} if identity["platform"] == "iphonesimulator" else {"arm64"}
            require(required <= set(arches) and root + "/usr/include/c++/vector" in entries, "SDK架构或libc++头文件缺失")
            result.update(version="14.0", canonical_name=settings["CanonicalName"], architectures=arches)
        else:
            result["files"] = [{"path": name, "bytes": member.size,
                                "sha256": hashlib.sha256(archive.extractfile(member).read()).hexdigest()}
                               for name, member in entries.items() if member.isfile()]
            require(bool(result["files"]), "Darwin runtime overlay为空")
        return result


def check_archive(path, role):
    """先固定原包全字节身份，再解析结构；小型fixture不能冒充授权SDK原包。"""
    identity = INPUTS[role]
    require(sha256(path) == identity["sha256"] and path.stat().st_size == identity["bytes"], "原包SHA/大小不符：" + role)
    return {"path": str(path), **identity, "archive": inspect_archive(path, identity)}


def package_map(rows):
    """规范化dpkg多架构名称，所有包必须真实处于完整安装状态。"""
    result = {}
    for row in rows:
        key = (row["package"].split(":")[0], row["architecture"])
        require(key not in result and row["status"] == "ii ", "dpkg包重复或未完成配置")
        result[key] = row["version"]
    require(bool(result), "dpkg包状态为空")
    return result


def check_package_delta(before_rows, after_rows, packages):
    """安装后必须精确等于base加已物化包版本；拒绝遗漏、额外包、降错版本或移除。"""
    before, actual = package_map(before_rows), package_map(after_rows)
    expected = dict(before)
    seen = set()
    for package in packages:
        control = package["control"]
        key = (control["Package"], control["Architecture"])
        require(key not in seen, "APT分发包身份重复")
        seen.add(key)
        expected[key] = control["Version"]
    require(actual == expected, "实际安装包delta不等于固定base与分发闭包")
    return [{"package": key[0], "architecture": key[1], "before": before.get(key), "after": actual[key]}
            for key in sorted(actual) if before.get(key) != actual[key]]


def version_tuple(value):
    """将Mach-O编码版本转为可审核的主次补丁版本。"""
    return [value >> 16, (value >> 8) & 255, value & 255]


def macho_identity(data):
    """直接核对实际64位Mach-O CPU与LC_BUILD_VERSION，不能用同CPU掩盖真机/模拟器差异。"""
    require(len(data) >= 32, "Mach-O头截断")
    fields = struct.unpack_from("<8I", data)
    require(fields[0] == 0xFEEDFACF and fields[1] in (0x100000C, 0x1000007)
            and fields[3] in (1, 2), "不是批准架构/类型的薄Mach-O")
    count, length = fields[4], fields[5]
    require(32 + length <= len(data) and count <= length // 8, "Mach-O load commands越界")
    offset, builds = 32, []
    for _ in range(count):
        require(offset + 8 <= 32 + length, "Mach-O命令头截断")
        command, size = struct.unpack_from("<2I", data, offset)
        require(size >= 8 and size % 4 == 0 and offset + size <= 32 + length, "Mach-O命令大小错误")
        if command == 0x32:
            require(size >= 24, "LC_BUILD_VERSION截断")
            _, _, target, minimum, sdk, tools = struct.unpack_from("<6I", data, offset)
            require(24 + tools * 8 == size, "LC_BUILD_VERSION工具表错误")
            builds.append({"platform": target, "minimum": version_tuple(minimum), "sdk": version_tuple(sdk)})
        offset += size
    require(offset == 32 + length and len(builds) == 1, "Mach-O平台记录缺失/重复")
    return {"architecture": "arm64" if fields[1] == 0x100000C else "x86_64", "file_type": fields[3], **builds[0]}


def check_macho(data, architecture, target_platform, require_sdk=False):
    """每个实际产物精确匹配CPU、iOS平台、配方最低版本及SDK14身份。"""
    result = macho_identity(data)
    # arm64模拟器从iOS14起支持，编译器会将原配方的ios13请求提升到该有效最低版本。
    minimum = [14, 0, 0] if architecture == "arm64" and target_platform == 7 else [13, 0, 0]
    require(result["architecture"] == architecture and result["platform"] == target_platform
            and result["minimum"] == minimum, "Mach-O架构/平台/最低版本不符")
    if require_sdk:
        require(result["sdk"] == [14, 0, 0], "Mach-O实际SDK不是14.0")
    return result


class EnvironmentRun:
    """串行控制唯一断网容器、所有真实命令日志及安全清理。"""

    def __init__(self, collector, output, docker):
        """命令记录复用已独立校验的采集器；不把RTK或凭据带入运行时。"""
        self.apt, self.output, self.docker = collector, output, docker
        self.commands = collector.Commands(output)
        self.name = "reko-preflight-" + uuid.uuid4().hex
        self.active = False

    def host(self, args, label):
        """执行host命令并保留真实返回码和完整原始输出。"""
        print("[RenPyEnvironmentPreflight] 执行：" + label, flush=True)
        return self.commands.run(args, label)

    def run(self, args, label):
        """清空容器进程环境，仅设置明确locale/PATH，不传递host凭据。"""
        return self.host([self.docker, "exec", self.name, "env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                          "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC", "DEBIAN_FRONTEND=noninteractive", *args], label)

    def copy(self, source, target, label):
        """复制明确原件到容器，不挂载主机工作区或Docker socket。"""
        self.host([self.docker, "cp", str(source), self.name + ":" + target], label)

    def script(self, name, text):
        """保留并执行由固定身份生成的短shell输入，所有路径均显式转义。"""
        path = self.output / "generated" / name
        write_new(path, ("#!/bin/sh\nset -eu\n" + text + "\n").encode())
        self.copy(path, "/reko/" + name, "copy-" + name)
        return self.run(["/bin/sh", "/reko/" + name], "execute-" + name)

    def checksum(self, name, entries):
        """在容器内重新核对传输后原字节，校验清单本身也留存到证据目录。"""
        path = self.output / "generated" / (name + ".sha256")
        write_new(path, "".join(digest + "  " + target + "\n" for digest, target in entries).encode())
        self.copy(path, "/reko/" + name + ".sha256", "copy-checksums-" + name)
        self.run(["sha256sum", "--check", "/reko/" + name + ".sha256"], "check-bytes-" + name)

    def reject(self, args, label):
        """负面探针必须实际非零，超时或意外成功不能视为有效拒绝。"""
        try:
            self.run(args, label)
        except self.apt.AptInputError:
            row = self.commands.records[-1]
            require(type(row["returncode"]) is int and 0 < row["returncode"] < 128, "负面探针未正常完成拒绝，崩溃/超时不计通过")
            row["expected_failure"] = True
            return
        raise ValueError("负面探针错误接受输入：" + label)

    def close(self):
        """始终清理本轮容器并落盘命令总表，失败证据不随容器删除。"""
        try:
            if self.active:
                self.host([self.docker, "rm", "--force", self.name], "container-cleanup")
        finally:
            write_json(self.output / "commands.json", {"commands": self.commands.records})


def prepare_container(run, bundle, manifest, report):
    """实际确认base身份、状态与网络隔离，再复制完整已验APT原件。"""
    run.host([run.docker, "pull", "--platform", "linux/amd64", manifest["image"]], "pull-fixed-image")
    image, _ = run.host([run.docker, "image", "inspect", manifest["image"]], "image-inspect")
    identity = json.loads(image)
    require(len(identity) == 1 and identity[0]["Id"] == manifest["image_id"]
            and identity[0]["Architecture"] == "amd64" and identity[0]["Os"] == "linux", "实际OCI身份错误")
    run.host([run.docker, "run", "--detach", "--user", "0:0", "--platform", "linux/amd64", "--network", "none",
              "--name", run.name, manifest["image"], "/bin/sleep", "infinity"], "container-start")
    run.active = True
    state, _ = run.host([run.docker, "inspect", run.name], "container-inspect")
    require(json.loads(state)[0]["HostConfig"]["NetworkMode"] == "none"
            and not json.loads(state)[0].get("Mounts"), "实际容器隔离边界错误")
    run.run(["uname", "-a"], "shared-host-kernel")
    run.host([run.docker, "version"], "docker-version")
    before, _ = run.run(["dpkg-query", "--show", "--showformat=" + PACKAGE_FORMAT], "base-packages")
    status, _ = run.run(["cat", "/var/lib/dpkg/status"], "base-status")
    os_release, _ = run.run(["cat", "/etc/os-release"], "base-os")
    require(before == run.apt.command_by_label(bundle, manifest, manifest["base_package_label"])[1]
            and status == run.apt.command_by_label(bundle, manifest, manifest["base_status_label"])[1]
            and os_release == run.apt.command_by_label(bundle, manifest, manifest["os_release_label"])[1], "重放base状态不等于B1固定输入")
    report["container_identity_verified"] = True
    run.run(["mkdir", "-p", "/reko/repo", "/reko/apt/lists/partial", "/reko/apt/archives/partial", "/reko/private", "/reko/sdk", "/reko/probes"], "prepare-directories")
    run.copy(str(bundle / "repository") + "/.", "/reko/repo", "copy-repository")
    entries = [(row["sha256"], "/reko/repo/" + row["path"].removeprefix("repository/"))
               for row in manifest["files"] if row["path"].startswith("repository/")]
    for name in ("sources.list", "apt.conf", "preferences"):
        run.copy(bundle / name, "/reko/" + name, "copy-" + name)
        entries.append((sha256(bundle / name), "/reko/" + name))
    run.checksum("apt-inputs", entries)
    return run.apt.base_packages(before)


def install_packages(run, bundle, manifest, before, report):
    """容器中重验签名并完全离线安装固定.deb，再精确审计已安装包delta。"""
    keyring, _ = run.run(["cat", "/usr/share/keyrings/ubuntu-archive-keyring.gpg"], "actual-keyring")
    require(hashlib.sha256(keyring).hexdigest() == sha256(bundle / "ubuntu-archive-keyring.gpg"), "base可信keyring变化")
    for row in manifest["signed_metadata"]:
        signatures, _ = run.run(["gpgv", "--status-fd=1", "--keyring", "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
                                 "/reko/repo/dists/" + row["suite"] + "/InRelease"], "gpgv-" + row["suite"])
        require(run.apt.valid_signatures(signatures) == row["valid_signatures"], "重放VALIDSIG身份变化")
    report["signature_reexecuted"] = True
    configuration, _ = run.run(["apt-config", "-c", "/reko/apt.conf", "dump"], "effective-apt-config")
    run.apt.check_apt_index_order(configuration)
    apt = ["apt-get", "-c", "/reko/apt.conf"]
    run.run([*apt, "update"], "apt-update-offline")
    run.run([*apt, "--simulate", "--no-remove", "--no-install-recommends", "install", *manifest["direct_requirements"]], "apt-simulate-offline")
    script = "\n".join("cp -- " + shlex.quote("/reko/repo/" + p["filename"]) + " "
                       + shlex.quote("/reko/apt/archives/" + p["cache_name"]) for p in manifest["packages"])
    run.script("populate-cache.sh", script)
    run.checksum("apt-cache", [(p["deb"]["sha256"], "/reko/apt/archives/" + p["cache_name"]) for p in manifest["packages"]])
    run.run([*apt, "--yes", "--no-download", "--no-remove", "--no-install-recommends", "install", *manifest["direct_requirements"]], "apt-install-offline")
    run.run([*apt, "check"], "apt-check")
    audit, _ = run.run(["dpkg", "--audit"], "dpkg-audit")
    require(not audit.strip(), "dpkg报告未完成安装")
    after, _ = run.run(["dpkg-query", "--show", "--showformat=" + PACKAGE_FORMAT], "installed-packages")
    run.run(["cat", "/var/lib/dpkg/status"], "installed-status")
    report["package_delta"] = check_package_delta(before, run.apt.base_packages(after), manifest["packages"])
    run.run(["locale", "-a"], "available-locales")
    run.run(["locale"], "effective-locale")
    report["apt_install_verified"] = True


def prepare_toolchain(run, inputs, major, report):
    """固定LLVM族及真实可执行文件身份，安全解包SDK14并校验resource overlay落点。"""
    tools = ["clang-", "clang++-", "ld64.lld-", "llvm-ar-", "llvm-nm-", "llvm-readobj-"]
    report["tool_identities"] = {}
    for prefix in tools + ["llvm-lipo-"]:
        name = prefix + ("15" if prefix == "llvm-lipo-" else str(major))
        expected = 15 if prefix == "llvm-lipo-" else major
        text, _ = run.run([name, "-version" if prefix == "llvm-lipo-" else "--version"], "version-" + name)
        require(re.search(r"\b" + str(expected) + r"\.[0-9]+", text.decode()), "实际LLVM版本族不符：" + name)
        binary, _ = run.run(["readlink", "-f", "/usr/bin/" + name], "path-" + name)
        path = binary.decode().strip()
        require(path.startswith("/usr/") and "\n" not in path, "工具路径不受控")
        digest, _ = run.run(["sha256sum", path], "hash-" + name)
        report["tool_identities"][name] = {"path": path, "sha256": digest.decode().split()[0]}
    resource, _ = run.run(["clang-" + str(major), "-print-resource-dir"], "clang-resource-dir")
    resource = resource.decode().strip()
    require(re.fullmatch(r"/usr/lib/(?:llvm-" + str(major) + r"/lib/)?clang/" + str(major) + r"(?:\.[0-9]+)*", resource), "实际resource-dir不属于固定LLVM族")
    report["resource_dir"] = resource
    checksums = []
    for role, identity in inputs.items():
        target = "/reko/private/" + role + ".tar.gz"
        run.copy(identity["path"], target, "copy-" + role)
        checksums.append((identity["sha256"], target))
    run.checksum("sdk-runtime-archives", checksums)
    for role in ("device_sdk", "simulator_sdk"):
        run.run(["tar", "xzf", "/reko/private/" + role + ".tar.gz", "--no-same-owner", "--no-same-permissions", "-C", "/reko/sdk"], "extract-" + role)
    run.run(["mkdir", "-p", resource + "/lib"], "prepare-resource-overlay")
    run.run(["tar", "xzf", "/reko/private/clang_runtime.tar.gz", "--no-same-owner", "--no-same-permissions", "-C", resource + "/lib"], "extract-resource-overlay")
    run.checksum("resource-overlay", [(r["sha256"], resource + "/lib/" + r["path"])
                                       for r in inputs["clang_runtime"]["archive"]["files"]])
    report["resource_overlay_verified"] = True


def probe_sources(major):
    """生成自己的小型C/C++探针，平台宏和availability调用必须实际参与编译链接。"""
    return {
        "native.c": '#include <stdio.h>\nint main(void) { puts("reko-linux-native-ok"); return 0; }\n',
        "minimal.c": 'int reko_basic_probe(void) { return 0; }\n',
        "sdk.c": '#include <TargetConditionals.h>\n#include <stdint.h>\n#include <sys/types.h>\n'
                 f'_Static_assert(__clang_major__ == {major}, "clang family mismatch");\n'
                 '_Static_assert(TARGET_OS_SIMULATOR == EXPECT_SIMULATOR, "Apple platform mismatch");\n'
                 'uint64_t reko_sdk_probe(uint64_t value) { return value + sizeof(off_t); }\n',
        # 查询iOS15使最低版本已为14的arm64模拟器仍必须实际引用availability runtime。
        "sdk.cc": '#include <vector>\n#include <string>\nint main(int argc, char **) {\n'
                  'std::vector<int> values(argc, 3); std::string label("reko");\n'
                  'if (__builtin_available(iOS 15.0, *)) return int(values.size() + label.size());\n'
                  'return int(values.size()); }\n',
        "invalid.a": 'invalid archive bytes\n',
    }


def check_archive_members(run, library, name, architecture, target_platform, major, label):
    """实际取回归档成员字节并与原始对象比较，避免只信lipo头部架构。"""
    members, _ = run.run(["llvm-ar-" + str(major), "t", library], label + "-members")
    names = [name + "-sdk.o", name + "-cxx.o"]
    require(members.decode().splitlines() == names, "静态归档成员集合错误")
    for member in names:
        content, _ = run.run(["llvm-ar-" + str(major), "p", library, member], label + "-" + member)
        original, _ = run.run(["cat", "/reko/probes/" + member], label + "-original-" + member)
        require(content == original, "回提归档成员字节改变")
        require(check_macho(content, architecture, target_platform, True)["file_type"] == 1, "归档成员不是Mach-O对象")


def cross_probes(run, major, inputs, report):
    """执行Linux原生探针、SDK14三个Apple目标编译/链接和同平台归档聚合回提。"""
    sources = run.output / "probes"
    for name, text in probe_sources(major).items():
        write_new(sources / name, text.encode())
    run.copy(str(sources) + "/.", "/reko/probes", "copy-probe-sources")
    cc, cxx, ar, nm, readobj = [tool + str(major) for tool in ("clang-", "clang++-", "llvm-ar-", "llvm-nm-", "llvm-readobj-")]
    run.run([cc, "/reko/probes/native.c", "-o", "/reko/probes/native"], "compile-native-c")
    native, _ = run.run(["/reko/probes/native"], "run-native-c")
    require(native == b"reko-linux-native-ok\n", "Linux原生探针返回异常")
    report["native_compiler_executed"] = True
    identities, compiled, linked, archives = {}, [], [], []
    for name, target, sdk_role, architecture, target_platform in TARGETS:
        prefix = "/reko/probes/" + name
        sdk = "/reko/sdk/" + inputs[sdk_role]["root"]
        flags = ["-target", target, "--sysroot", sdk, "-isysroot", sdk]
        run.run([cc, "-target", target, "-std=gnu17", "-c", "/reko/probes/minimal.c", "-o", prefix + "-basic.o"], name + "-basic-compile")
        basic, _ = run.run(["cat", prefix + "-basic.o"], name + "-basic-object")
        require(check_macho(basic, architecture, target_platform)["file_type"] == 1, "基本探针不是Mach-O对象")
        compiled.append(name + "-basic")
        run.run([cc, *flags, "-std=gnu17", "-DEXPECT_SIMULATOR=" + str(int(target_platform == 7)), "-c", "/reko/probes/sdk.c", "-o", prefix + "-sdk.o"], name + "-sdk-c-compile")
        run.run([cxx, *flags, "-stdlib=libc++", "-I", sdk + "/usr/include/c++", "-std=gnu++17", "-c", "/reko/probes/sdk.cc", "-o", prefix + "-cxx.o"], name + "-sdk-cxx-compile")
        for suffix in ("sdk", "cxx"):
            content, _ = run.run(["cat", prefix + "-" + suffix + ".o"], name + "-" + suffix + "-object")
            identities[name + "-" + suffix] = check_macho(content, architecture, target_platform, True)
            require(identities[name + "-" + suffix]["file_type"] == 1, "SDK编译产物不是Mach-O对象")
        compiled.append(name + "-sdk")
        undefined, _ = run.run([nm, "--undefined-only", prefix + "-cxx.o"], name + "-availability-reference")
        require(re.search(rb"__is(?:Platform|OS)VersionAtLeast", undefined), "探针未实际引用Darwin availability runtime")
        link = [cxx, *flags, "-stdlib=libc++", "-fuse-ld=lld", "--ld-path=/usr/bin/ld64.lld-" + str(major), prefix + "-cxx.o", "-Wl,-t", "-o", prefix + "-linked"]
        # Clang15默认仍生成旧版minimum参数；ld64.lld15要求显式平台/最低版本/SDK，按实际目标补足。
        if major == 15:
            platform_name = "ios" if target_platform == 2 else "ios-simulator"
            minimum = "14.0.0" if target_platform == 7 and architecture == "arm64" else "13.0.0"
            link.append("-Wl,-platform_version," + platform_name + "," + minimum + ",14.0")
        run.run([*link, "-###"], name + "-link-driver")
        trace, _ = run.run(link, name + "-sdk-link")
        runtime = "libclang_rt.iossim.a" if target_platform == 7 else "libclang_rt.ios.a"
        require((report["resource_dir"] + "/lib/darwin/" + runtime).encode() in trace, "实际链接未使用固定resource overlay")
        binary, _ = run.run(["cat", prefix + "-linked"], name + "-linked-bytes")
        identities[name + "-linked"] = check_macho(binary, architecture, target_platform, True)
        require(identities[name + "-linked"]["file_type"] == 2, "SDK链接产物不是Mach-O可执行文件")
        remaining, _ = run.run([nm, "--undefined-only", prefix + "-linked"], name + "-linked-undefined")
        require(not re.search(rb"__is(?:Platform|OS)VersionAtLeast", remaining), "Darwin availability runtime链接未解决")
        run.run([readobj, "--file-header", "--macho-version-min", prefix + "-sdk.o", prefix + "-cxx.o", prefix + "-linked"], name + "-llvm-macho-check")
        linked.append(name)
        run.run([ar, "rcs", prefix + ".a", prefix + "-sdk.o", prefix + "-cxx.o"], name + "-archive")
        run.run(["llvm-lipo-15", "-create", prefix + ".a", "-output", prefix + "-query.fat.a"], name + "-single-slice-wrapper")
        actual, _ = run.run(["llvm-lipo-15", "-archs", prefix + "-query.fat.a"], name + "-thin-arch")
        require(actual.decode().split() == [architecture], "普通归档临时封装架构错误")
        check_archive_members(run, prefix + ".a", name, architecture, target_platform, major, name + "-archive-check")
        archives.append(name)
    report.update(basic_cross_compiler_verified=len(compiled) == 6, sdk_three_target_compiled=len(compiled) == 6,
                  sdk_three_target_linked=len(linked) == 3, thin_archive_verified=len(archives) == 3, macho_identities=identities)
    universal = "/reko/probes/simulator-universal.a"
    run.run(["llvm-lipo-15", "-create", "/reko/probes/sim-arm64.a", "/reko/probes/sim-x86_64.a", "-output", universal], "simulator-universal-create")
    actual, _ = run.run(["llvm-lipo-15", "-archs", universal], "simulator-universal-archs")
    require(set(actual.decode().split()) == {"arm64", "x86_64"} and len(actual.decode().split()) == 2, "模拟器universal架构集合错误")
    for name, _, _, architecture, target_platform in TARGETS[1:]:
        thin = "/reko/probes/reextracted-" + architecture + ".a"
        run.run(["llvm-lipo-15", "-thin", architecture, universal, "-output", thin], "simulator-extract-" + architecture)
        check_archive_members(run, thin, name, architecture, target_platform, major, "simulator-reextracted-" + architecture)
    run.reject(["llvm-lipo-15", "-create", "/reko/probes/invalid.a", "-output", "/reko/probes/invalid-fat.a"], "reject-invalid-archive")
    run.reject(["llvm-lipo-15", "-verify_arch", "x86_64", "/reko/probes/arm64-query.fat.a"], "reject-wrong-architecture")
    report["simulator_universal_verified"] = True
    run.host([run.docker, "cp", run.name + ":/reko/probes/.", str(run.output / "probe-products")], "preserve-own-probe-products")


def execute(args, report):
    """先验证所有外部原件，再执行隔离环境安装及交叉工具链完整预检。"""
    require(platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64"), "预检需要真实Linux amd64 host")
    docker = shutil.which("docker")
    require(docker is not None, "预检需要Docker运行时")
    collector = load_collector(guarded(args.collector), args.collector_sha256)
    bundle = guarded(args.bundle)
    verification = collector.verify_bundle(bundle, args.manifest_sha256)
    write_json(args.output / "apt-byte-verification.json", verification)
    manifest = collector.read_json(bundle / "manifest.json")
    inputs = {role: check_archive(guarded(getattr(args, role)), role) for role in INPUTS}
    report.update(input_bytes_verified=True, input_archives=inputs, collector_sha256=args.collector_sha256,
                  bundle_manifest_sha256=args.manifest_sha256, ubuntu=manifest["ubuntu"], image=manifest["image"],
                  image_id=manifest["image_id"], llvm_major=18 if manifest["ubuntu"] == "24.04" else 15,
                  scope="fixed_candidate_linux_environment_and_cross_toolchain_only")
    run = EnvironmentRun(collector, args.output, docker)
    try:
        before = prepare_container(run, bundle, manifest, report)
        install_packages(run, bundle, manifest, before, report)
        prepare_toolchain(run, inputs, report["llvm_major"], report)
        cross_probes(run, report["llvm_major"], inputs, report)
    finally:
        run.close()
    require(all(report[name] is True for name in PHASES), "预检存在未执行阶段")
    report["result"] = "passed"


def main(argv=None):
    """生成全新阶段报告；失败保留证据，不关闭J4C或完整输入闭包。"""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    run = subparsers.add_parser("run")
    for name in ("bundle", "collector", "device-sdk", "simulator-sdk", "clang-runtime", "output"):
        run.add_argument("--" + name, type=Path, required=True)
    for name in ("manifest-sha256", "collector-sha256"):
        run.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    report = {"schema_version": 1, "result": "failed", "errors": [], **{name: False for name in PHASES + LIMITS}}
    output = None
    try:
        args.output = guarded(args.output)
        require(not args.output.exists(), "预检输出目录必须全新")
        require(not args.output.is_relative_to(guarded(args.bundle)), "预检不能修改原始APT bundle")
        args.output.mkdir(parents=True)
        output = args.output / "preflight-report.json"
        execute(args, report)
    except (OSError, ValueError, KeyError, TypeError, StopIteration, tarfile.TarError, subprocess.SubprocessError) as error:
        report["result"] = "failed"
        report["errors"].append(str(error))
    if output is not None:
        try:
            report["files"] = [{"path": p.relative_to(args.output).as_posix(), "sha256": sha256(p), "bytes": p.stat().st_size}
                               for p in sorted(args.output.rglob("*")) if p.is_file()]
            write_json(output, report)
        except (OSError, ValueError) as error:
            print("[RenPyEnvironmentPreflight] 无法写报告：" + str(error), flush=True)
            return 1
    print("[RenPyEnvironmentPreflight] " + ("通过；仅固定环境与交叉工具预检" if report["result"] == "passed" else "失败：" + "; ".join(report["errors"])), flush=True)
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
