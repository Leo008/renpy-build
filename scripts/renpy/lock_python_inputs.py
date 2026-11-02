#!/usr/bin/env python3
"""物化并核验精确 Python 分发；不安装包、不构建 sdist、不宣布离线运行通过。"""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import email.parser
import hashlib
import importlib
import io
import itertools
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import sys
import tarfile
import urllib.parse
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOCK = ROOT / "scripts/renpy/python-inputs.lock.json"
DEFAULT_CACHE = ROOT / "ThirdParty/build/renpy-tests/goal-input-audit-20261102/versions/python-inputs/materialized"
SHA = re.compile(r"[0-9a-f]{64}")
SCOPE_IDS = {"8.5.3-host-ci-success", "8.5.3-target-ci-success", "8.5.3-target-recipe",
             "8.4.1-host-recipe", "8.4.1-target-recipe", "8.3.7-host-recipe",
             "8.3.7-target-recipe", "7.8.7-host-recipe", "7.8.7-target-recipe"}
MAX_MEMBERS = 30000
MAX_EXPANDED = 1024 * 1024 * 1024


class LockedRedirect(urllib.request.HTTPRedirectHandler):
    """在发出重定向请求前拒绝换源，不访问清单外主机。"""

    def redirect_request(self, request, response, code, message, headers, url):
        """拒绝所有重定向，保留原始官方 URL 作为唯一获取路径。"""
        raise ValueError("锁定分发禁止重定向：" + str(code))


def log(message):
    """输出限定任务的中文阶段日志，保留具体失败原因。"""
    print("[RenPyPythonInputs] " + message, flush=True)


def require(condition, message):
    """不满足显式契约即失败，不用默认成功补齐缺项。"""
    if not condition:
        raise ValueError(message)


def keys(value, expected, label):
    """只接受精确字段集合，拒绝未知或缺失字段。"""
    require(type(value) is dict and set(value) == set(expected), label + " 字段集合错误")


def canonical(name):
    """按分发名称规则归一化大小写与分隔符，不解析依赖表达式。"""
    return re.sub(r"[-_.]+", "-", name).lower()


def safe_name(value, label):
    """校验归档成员的原始 POSIX 路径，拒绝绝对路径、越界、驱动器和歧义。"""
    require(type(value) is str and value and "\\" not in value and "\0" not in value
            and ":" not in value and not value.startswith("/"), label + " 路径非法")
    trimmed = value[:-1] if value.endswith("/") else value
    require(trimmed and all(p not in ("", ".", "..") for p in trimmed.split("/")), label + " 路径越界或不规范")
    require(PurePosixPath(trimmed).as_posix() == trimmed, label + " 路径不规范")
    return trimmed


def regular_path(path):
    """读取缓存前逐级拒绝符号链接，避免哈希校验与实际输入分离。"""
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), "拒绝链接输入：" + str(path))
    return path


def digest(data):
    """对完整字节计算 SHA-256。"""
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    """拒绝 JSON 重复字段，防止解析时静默覆盖。"""
    result = {}
    for key, value in pairs:
        require(key not in result, "JSON 重复字段：" + key)
        result[key] = value
    return result


def metadata(content):
    """读取分发元数据原文，不执行 setup.py 或下载包内代码。"""
    message = email.parser.BytesParser().parsebytes(content)
    for field in ("Name", "Version"):
        require(len(message.get_all(field, [])) == 1, "分发元数据缺失或重复：" + field)
    require(len(message.get_all("Requires-Python", [])) <= 1, "重复 Requires-Python")
    deps = message.get_all("Requires-Dist", [])
    require(len(set(deps)) == len(deps), "重复 Requires-Dist")
    return {"name": canonical(message["Name"]), "version": message["Version"],
            "requires_python": message.get("Requires-Python", ""), "requires_dist": sorted(deps)}


def native_member(name, data):
    """识别真实 ELF/PE/Mach-O 及带原生扩展名的成员，不凭 wheel 文件名判断纯度。"""
    if data.startswith(b"\x7fELF"):
        require(len(data) >= 20 and data[4] in (1, 2) and data[5] in (1, 2), "ELF 头不完整：" + name)
        machine = int.from_bytes(data[18:20], "little" if data[5] == 1 else "big")
        return {"kind": "ELF", "machine": machine, "bits": 64 if data[4] == 2 else 32}
    if data.startswith(b"MZ"):
        return {"kind": "PE", "machine": None, "bits": None}
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                    b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                    b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
        return {"kind": "MachO", "machine": None, "bits": None}
    if name.lower().endswith((".so", ".pyd", ".dll", ".dylib", ".exe", ".a", ".o")):
        return {"kind": "unrecognized_native_suffix", "machine": None, "bits": None}
    return None


def read_wheel(path, filename=None):
    """核对 ZIP 类型/路径、完整 RECORD、元数据和原生成员，不解包到文件系统。"""
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(0 < len(entries) <= MAX_MEMBERS and sum(i.file_size for i in entries) <= MAX_EXPANDED,
                "wheel 成员数量或展开体积超限")
        names = set()
        folded = set()
        files = {}
        native = []
        for entry in entries:
            name = safe_name(entry.filename, "wheel")
            require(name not in names and name.casefold() not in folded, "wheel 重名/大小写冲突：" + name)
            names.add(name)
            folded.add(name.casefold())
            mode = entry.external_attr >> 16
            require(not entry.flag_bits & 1 and not stat.S_ISLNK(mode), "wheel 加密或链接成员：" + name)
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR), "wheel 特殊成员：" + name)
            if entry.is_dir():
                require(stat.S_IFMT(mode) in (0, stat.S_IFDIR), "wheel 目录类型不一致：" + name)
                continue
            require(stat.S_IFMT(mode) != stat.S_IFDIR, "wheel 文件类型不一致：" + name)
            content = archive.read(entry)
            files[name] = content
            kind = native_member(name, content)
            if kind:
                native.append({"path": name, "sha256": digest(content), **kind})
        require(not any(str(parent) in files for name in names for parent in PurePosixPath(name).parents
                        if str(parent) != "."), "wheel 文件/目录前缀冲突")
        infos = {n.split("/")[0] for n in files if n.split("/")[0].endswith(".dist-info")}
        require(len(infos) == 1, "wheel 必须具有唯一 dist-info")
        prefix = next(iter(infos))
        record = prefix + "/RECORD"
        require(all(prefix + "/" + n in files for n in ("METADATA", "WHEEL", "RECORD")), "wheel 身份文件缺失")
        rows = list(csv.reader(io.StringIO(files[record].decode("utf-8"))))
        seen = set()
        for row in rows:
            require(len(row) == 3, "RECORD 列数错误")
            name = safe_name(row[0], "RECORD")
            require(name not in seen and name in files, "RECORD 重复或缺失成员：" + name)
            seen.add(name)
            if name == record:
                require(row[1:] == ["", ""], "RECORD 自身不得伪造 hash/size")
                continue
            require(row[1].startswith("sha256=") and re.fullmatch(r"[A-Za-z0-9_-]+", row[1][7:]) is not None,
                    "RECORD 必须使用实际 SHA256：" + name)
            encoded = row[1][7:]
            actual = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
            require(actual == hashlib.sha256(files[name]).digest() and row[2] == str(len(files[name])),
                    "RECORD hash/size 不符：" + name)
        require(seen == set(files), "RECORD 未完整覆盖 wheel")
        wheel = email.parser.BytesParser().parsebytes(files[prefix + "/WHEEL"])
        require(wheel.get_all("Wheel-Version") == ["1.0"], "不支持的 Wheel-Version")
        require(wheel.get_all("Root-Is-Purelib") in (["true"], ["false"]), "Root-Is-Purelib 不明确")
        tags = wheel.get_all("Tag", [])
        require(tags and len(tags) == len(set(tags)), "WHEEL Tag 缺失或重复")
        py, abi, platform = (filename or Path(path).name)[:-4].rsplit("-", 3)[-3:]
        filename_tags = {"-".join(t) for t in itertools.product(py.split("."), abi.split("."), platform.split("."))}
        require(set(tags) == filename_tags, "WHEEL Tag 与文件名不一致")
        require(all(n.split("/")[0] == prefix or not n.split("/")[0].endswith(".data")
                    or n.split("/")[0] == prefix.removesuffix(".dist-info") + ".data" for n in files), "wheel data 目录身份不符")
        return {"metadata": metadata(files[prefix + "/METADATA"]), "metadata_sha256": digest(files[prefix + "/METADATA"]),
                "root_is_purelib": wheel["Root-Is-Purelib"] == "true", "tags": sorted(tags),
                "native_members": native, "member_count": len(files), "dist_info": prefix}


def read_sdist(path):
    """核对源码 tar 成员边界、唯一顶层和 PKG-INFO，不执行或构建源码。"""
    with tarfile.open(path, mode="r:*") as archive:
        members = archive.getmembers()
        require(0 < len(members) <= MAX_MEMBERS and sum(m.size for m in members) <= MAX_EXPANDED,
                "sdist 成员数量或展开体积超限")
        names = set()
        folded = set()
        roots = set()
        files = set()
        content = None
        for item in members:
            name = safe_name(item.name, "sdist")
            require(name not in names and name.casefold() not in folded and item.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                    and not item.sparse, "sdist 重复、链接或特殊成员：" + name)
            names.add(name)
            folded.add(name.casefold())
            roots.add(name.split("/")[0])
            if item.isfile():
                files.add(name)
            if name.count("/") == 1 and name.endswith("/PKG-INFO"):
                require(item.isfile() and content is None, "sdist PKG-INFO 类型或身份不唯一")
                content = archive.extractfile(item).read()
        require(not any(str(parent) in files for name in names for parent in PurePosixPath(name).parents
                        if str(parent) != "."), "sdist 文件/目录前缀冲突")
        require(len(roots) == 1 and content is not None, "sdist 缺少唯一根目录/PKG-INFO")
        return {"metadata": metadata(content), "metadata_sha256": digest(content), "archive_root": next(iter(roots)),
                "member_count": len(members), "status": "needs_controlled_build"}


def validate_manifest(value):
    """强校验清单 schema、九个作用域、唯一分发和显式包引用。"""
    keys(value, ("schema_version", "task", "date", "tool_dependency", "scopes", "artifacts", "limitations"), "清单")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["task"] == "R00-02J2A", "清单版本或任务错误")
    require(type(value["date"]) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value["date"]), "清单日期错误")
    require(type(value["limitations"]) is list and value["limitations"] and all(type(s) is str for s in value["limitations"]), "清单边界缺失")
    require(type(value["artifacts"]) is dict and value["artifacts"], "清单分发为空")
    filenames = set()
    for ident, item in value["artifacts"].items():
        keys(item, ("name", "version", "filename", "type", "url", "sha256", "size", "metadata", "metadata_sha256",
                    "declared_requires_python", "declared_requires_dist", "metadata_source", "inspection"), "分发")
        require(type(ident) is str and SHA.fullmatch(ident) and item["sha256"] == ident, "分发 hash 身份错误")
        require(type(item["name"]) is str and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", item["name"]), "分发名称未规范化")
        require(type(item["version"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!+_-]*", item["version"]), "分发版本非法")
        require(type(item["filename"]) is str and safe_name(item["filename"], "文件名") == item["filename"]
                and "/" not in item["filename"] and item["filename"] not in filenames, "分发文件名重复或不规范")
        filenames.add(item["filename"])
        require(item["type"] in ("wheel", "sdist") and (item["filename"].endswith(".whl") if item["type"] == "wheel"
                else item["filename"].endswith((".tar.gz", ".tar.bz2", ".tar.xz"))), "分发类型与后缀错误")
        require(type(item["size"]) is int and 0 < item["size"] <= MAX_EXPANDED, "分发大小错误")
        require(type(item["url"]) is str, "分发 URL 类型错误")
        url = urllib.parse.urlsplit(item["url"])
        require(url.scheme == "https" and url.netloc == "files.pythonhosted.org" and not url.query and not url.fragment
                and urllib.parse.unquote(url.path).endswith("/" + item["filename"]), "分发来源不是锁定官方文件")
        keys(item["metadata_source"], ("url", "sha256"), "PyPI 来源")
        require(item["metadata_source"]["url"] == f"https://pypi.org/pypi/{item['name']}/{item['version']}/json"
                and SHA.fullmatch(item["metadata_source"]["sha256"]), "必须固定精确 PyPI 版本元数据")
        keys(item["metadata"], ("name", "version", "requires_python", "requires_dist"), "分发元数据")
        require(item["metadata"]["name"] == item["name"] and item["metadata"]["version"] == item["version"]
                and SHA.fullmatch(item["metadata_sha256"]), "分发元数据身份错误")
        for field in ("metadata",):
            require(type(item[field]["requires_python"]) is str and type(item[field]["requires_dist"]) is list
                    and all(type(r) is str and r for r in item[field]["requires_dist"]), "分发依赖字段错误")
        require(type(item["declared_requires_python"]) is str and type(item["declared_requires_dist"]) is list
                and all(type(r) is str and r for r in item["declared_requires_dist"]), "PyPI 依赖字段错误")
        require(type(item["inspection"]) is dict, "归档检查快照缺失")
        inspection = item["inspection"]
        fields = ("metadata", "metadata_sha256", "root_is_purelib", "tags", "native_members", "member_count", "dist_info") if item["type"] == "wheel" else ("metadata", "metadata_sha256", "archive_root", "member_count", "status")
        keys(inspection, fields, "归档快照")
        require(inspection["metadata"] == item["metadata"] and inspection["metadata_sha256"] == item["metadata_sha256"]
                and type(inspection["member_count"]) is int and 0 < inspection["member_count"] <= MAX_MEMBERS, "归档快照身份/计数错误")
        if item["type"] == "wheel":
            require(type(inspection["root_is_purelib"]) is bool and type(inspection["tags"]) is list and inspection["tags"]
                    and len(set(inspection["tags"])) == len(inspection["tags"]) and all(type(t) is str for t in inspection["tags"])
                    and type(inspection["native_members"]) is list, "wheel 快照字段类型错误")
            for member in inspection["native_members"]:
                keys(member, ("path", "sha256", "kind", "machine", "bits"), "原生成员快照")
                safe_name(member["path"], "原生成员快照")
                require(SHA.fullmatch(member["sha256"]) and member["kind"] in ("ELF", "PE", "MachO", "unrecognized_native_suffix")
                        and (member["machine"] is None or type(member["machine"]) is int)
                        and (member["bits"] is None or type(member["bits"]) is int), "原生成员快照类型错误")
        else:
            require(inspection["status"] == "needs_controlled_build", "sdist 快照不能标记已构建")
            safe_name(inspection["archive_root"], "sdist 根目录")
    keys(value["tool_dependency"], ("name", "version", "artifact", "loading_contract"), "工具解析器")
    tool = value["tool_dependency"]
    require(tool["name"] == "packaging" and tool["version"] == "24.1" and tool["artifact"] in value["artifacts"]
            and value["artifacts"][tool["artifact"]]["name"] == "packaging"
            and value["artifacts"][tool["artifact"]]["version"] == "24.1"
            and value["artifacts"][tool["artifact"]]["type"] == "wheel"
            and type(tool["loading_contract"]) is str and tool["loading_contract"], "工具解析器未固定")
    require(type(value["scopes"]) is list and len(value["scopes"]) == len(SCOPE_IDS), "必须完整保留九个作用域")
    seen = set()
    used = {tool["artifact"]}
    for scope in value["scopes"]:
        keys(scope, ("id", "kind", "release", "python_version", "glibc", "environment_source", "expected_versions",
                     "packages", "evidence", "observed_ci_distributions", "selection_status"), "作用域")
        require(scope["id"] in SCOPE_IDS and scope["id"] not in seen, "作用域身份重复或未知")
        seen.add(scope["id"])
        require(scope["kind"] in ("host", "target") and ("-host-" in scope["id"]) == (scope["kind"] == "host")
                and scope["release"] == scope["id"].split("-")[0], "作用域角色/版本错误")
        require(re.fullmatch(r"\d+\.\d+\.\d+", scope["python_version"]) is not None
                and scope["glibc"] == ({"8.5.3": "2.39", "8.4.1": "2.39", "8.3.7": "2.35", "7.8.7": "2.35"}[scope["release"]]
                                         if scope["kind"] == "host" else None), "作用域 Python/平台不明确")
        require(type(scope["expected_versions"]) is dict and type(scope["packages"]) is list
                and scope["expected_versions"] and len(scope["expected_versions"]) == len(scope["packages"]), "作用域缺包")
        pins = {}
        for package in scope["packages"]:
            keys(package, ("name", "version", "artifact", "status", "origin", "origin_evidence", "usage"), "作用域包")
            require(package["name"] not in pins and package["artifact"] in value["artifacts"], "包重复或缺少分发")
            artifact = value["artifacts"][package["artifact"]]
            require(package["name"] == artifact["name"] and package["version"] == artifact["version"], "包与分发身份不一致")
            require(package["status"] == ("needs_controlled_build" if artifact["type"] == "sdist" else "wheel_bytes_selected"), "不得把 sdist 标为已构建")
            require(package["origin"] in ("observed_ci", "recipe_pin", "sdk_target_candidate", "prospective_build_pin")
                    and type(package["origin_evidence"]) is list and package["origin_evidence"], "包来源证据缺失")
            require(package["usage"] in ("host_runtime", "target_runtime", "host_executed_build_support"), "包职责不明确")
            require((scope["kind"] == "host" and package["usage"] == "host_runtime")
                    or (scope["kind"] == "target" and package["usage"] in ("target_runtime", "host_executed_build_support")), "包职责跨作用域")
            require(package["usage"] != "host_executed_build_support" or (package["name"] == "setuptools"
                    and package["version"] == "74.1.2" and scope["release"] in ("8.5.3", "8.4.1")), "仅已证明的 setuptools 项可标为 host 构建支持")
            pins[package["name"]] = package["version"]
            used.add(package["artifact"])
        require(pins == scope["expected_versions"], "作用域版本集合不完整")
        require(type(scope["evidence"]) is list and scope["evidence"] and type(scope["observed_ci_distributions"]) is list
                and type(scope["selection_status"]) is str and scope["selection_status"]
                and type(scope["environment_source"]) is str and scope["environment_source"], "作用域证据/选择说明缺失")
    require(seen == SCOPE_IDS and used == set(value["artifacts"]), "作用域不完整或存在未引用分发")
    return value


def load_manifest(path):
    """读取实际清单并拒绝重复 JSON 键。"""
    content = regular_path(path).read_bytes()
    return validate_manifest(json.loads(content, object_pairs_hook=unique_object)), digest(content)


def artifact_path(cache, artifact):
    """以完整 hash 分目录，禁止清单控制缓存根或越界文件名。"""
    return regular_path(Path(cache) / artifact["sha256"] / artifact["filename"])


def inspect_artifact(path, artifact):
    """复核完整分发字节及归档身份，任何不符均失败。"""
    content = regular_path(path).read_bytes()
    require(len(content) == artifact["size"] and digest(content) == artifact["sha256"], "分发 hash/size 不符：" + artifact["filename"])
    result = read_wheel(path, artifact["filename"]) if artifact["type"] == "wheel" else read_sdist(path)
    if artifact["type"] == "wheel":
        name, version = result["dist_info"].removesuffix(".dist-info").rsplit("-", 1)
        require(canonical(name) == artifact["name"] and version == artifact["version"], "dist-info 路径身份错误")
    require(result["metadata"] == artifact["metadata"] and result["metadata_sha256"] == artifact["metadata_sha256"],
            "分发元数据与锁定原字节不符：" + artifact["filename"])
    require(result == artifact["inspection"], "归档检查结果与锁定快照不符：" + artifact["filename"])
    return result


def fetch_artifact(cache, artifact):
    """仅从锁定的官方 URL 下载完整字节；旧坏缓存拒绝覆盖，失败保留明确错误。"""
    path = artifact_path(cache, artifact)
    if path.exists():
        inspect_artifact(path, artifact)
        return "cache_verified"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = regular_path(path.with_name(path.name + ".part"))
    require(not temporary.exists(), "拒绝覆盖未完成下载：" + str(temporary))
    try:
        request = urllib.request.Request(artifact["url"], headers={"User-Agent": "Reko-Locked-Python-Inputs/1.0"})
        opener = urllib.request.build_opener(LockedRedirect())
        with opener.open(request, timeout=90) as response, temporary.open("xb") as output:
            require(response.url == artifact["url"], "分发下载被重定向，拒绝替换来源")
            size = 0
            while block := response.read(1024 * 1024):
                size += len(block)
                require(size <= artifact["size"], "分发响应大于锁定大小")
                output.write(block)
        # 先在part上按固定filename核验完整归档，再以hard link进行独占发布，禁止覆盖并发出现的缓存。
        inspect_artifact(temporary, artifact)
        try:
            os.link(temporary, path)
        except FileExistsError:
            raise ValueError("并发缓存发布冲突，已有文件未覆盖：" + str(path)) from None
        temporary.unlink()
        return "downloaded_verified"
    except Exception:
        # 错误下载保留在 .part 以供追溯；下一次不会覆盖或默认为成功。
        raise


def load_parser(cache, manifest):
    """只从已验完 RECORD/身份的官方 packaging24.1 wheel 加载实际解析器。"""
    artifact = manifest["artifacts"][manifest["tool_dependency"]["artifact"]]
    path = artifact_path(cache, artifact)
    info = inspect_artifact(path, artifact)
    require(info["root_is_purelib"] and info["tags"] == ["py3-none-any"] and not info["native_members"]
            and not info["metadata"]["requires_dist"] and not artifact["declared_requires_dist"], "工具解析器不是无外部依赖的独立纯 Python wheel")
    with zipfile.ZipFile(path) as archive:
        require(all(name.split("/")[0] in ("packaging", "packaging-24.1.dist-info") for name in archive.namelist()),
                "工具解析器包含其他顶层模块或执行数据")
    for name, module in tuple(sys.modules.items()):
        if name == "packaging" or name.startswith("packaging."):
            require(str(path) + "/" in str(getattr(module, "__file__", "")), "环境已有其他 packaging 模块，拒绝静默替换")
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
    modules = {name: importlib.import_module("packaging" + ("." + name if name else ""))
               for name in ("", "requirements", "markers", "specifiers", "utils", "tags", "version")}
    require(modules[""].__version__ == "24.1" and all(str(path) + "/" in str(m.__file__) for m in modules.values()),
            "packaging 来源/版本不符")
    return modules


def verify_scope(scope, manifest, inspections, parser):
    """用固定官方解析器核对依赖、Python限制和平台；构建/安装结果保持未执行。"""
    verify_scope_sources(scope, parser)
    python = tuple(map(int, scope["python_version"].split(".")[:2]))
    if scope["kind"] == "host":
        maximum = int(scope["glibc"].split(".")[1])
        platforms = [f"manylinux_2_{i}_x86_64" for i in range(5, maximum + 1)] + ["manylinux1_x86_64", "manylinux2010_x86_64", "manylinux2014_x86_64", "linux_x86_64"]
        allowed = set(parser["tags"].cpython_tags(python, abis=["cp" + "".join(map(str, python))], platforms=platforms))
        allowed.update(parser["tags"].compatible_tags(python, platforms=platforms))
    else:
        allowed = set(parser["tags"].compatible_tags(python, platforms=["any"]))
    env = parser["markers"].default_environment()
    env.update(python_version=".".join(map(str, python)), python_full_version=scope["python_version"],
               sys_platform="linux" if scope["kind"] == "host" else "darwin", os_name="posix", extra="",
               platform_system="Linux" if scope["kind"] == "host" else "Darwin", platform_machine="x86_64" if scope["kind"] == "host" else "arm64",
               implementation_name="cpython", platform_python_implementation="CPython", implementation_version=scope["python_version"])
    deferred = []
    support = []
    for package in scope["packages"]:
        artifact = manifest["artifacts"][package["artifact"]]
        info = inspections[package["artifact"]]
        require(parser["version"].Version(info["metadata"]["version"]) == parser["version"].Version(package["version"]), "元数据版本不符")
        for constraint in (artifact["declared_requires_python"], info["metadata"]["requires_python"]):
            require(parser["specifiers"].SpecifierSet(constraint).contains(scope["python_version"], prereleases=True),
                    scope["id"] + " Python 限制不满足：" + package["name"])
        for text in set(artifact["declared_requires_dist"] + info["metadata"]["requires_dist"]):
            requirement = parser["requirements"].Requirement(text)
            require(not requirement.url, "依赖含未锁定直接 URL：" + text)
            if requirement.marker and not requirement.marker.evaluate(env):
                continue
            dependency = parser["utils"].canonicalize_name(requirement.name)
            require(dependency in scope["expected_versions"] and not requirement.extras
                    and parser["version"].Version(scope["expected_versions"][dependency]) in requirement.specifier,
                    scope["id"] + " 依赖缺失/不兼容/未展开extra：" + text)
        if artifact["type"] == "sdist":
            deferred.append(package["name"] + "==" + package["version"])
            continue
        wheel_name, version, _, tags = parser["utils"].parse_wheel_filename(artifact["filename"])
        require(wheel_name == package["name"] and version == parser["version"].Version(package["version"])
                and bool(tags & allowed), scope["id"] + " wheel 平台/ABI/身份不兼容：" + artifact["filename"])
        if scope["kind"] == "target":
            require(info["root_is_purelib"] and all(t.abi == "none" and t.platform == "any" for t in tags), "目标不接受原生平台 wheel")
            if package["usage"] == "host_executed_build_support":
                validate_launcher_data(package, info)
                support.append({"package": package["name"], "native_members": info["native_members"], "ios_runtime_ready": False})
            else:
                require(not info["native_members"], "iOS 运行包包含原生成员：" + package["name"])
        elif not info["root_is_purelib"]:
            require(info["native_members"] and all(n["kind"] == "ELF" and n["machine"] == 62 and n["bits"] == 64 for n in info["native_members"]), "Linux host 原生成员架构错误")
        elif info["native_members"]:
            validate_launcher_data(package, info)
    return {"id": scope["id"], "result": "distribution_inputs_verified", "package_count": len(scope["packages"]),
            "dependency_metadata_verified": True, "needs_controlled_build": deferred, "host_executed_build_support": support,
            "package_inputs": scope["packages"], "source_evidence": scope["evidence"],
            "observed_ci_distributions": scope["observed_ci_distributions"], "selection_status": scope["selection_status"],
            "environment_source": scope["environment_source"], "actual_runtime_marker_verification": False,
            "offline_install_verified": False, "sdist_build_verified": False}


def validate_launcher_data(package, info):
    """只接纳已锁 setuptools 八个 Windows launcher 数据，不推广成原生文件通行规则。"""
    expected = {"setuptools/" + kind + suffix + ".exe" for kind in ("cli", "gui") for suffix in ("", "-32", "-64", "-arm64")}
    require(package["name"] == "setuptools" and package["version"] in ("74.1.2", "80.9.0")
            and len(info["native_members"]) == 8 and {n["path"] for n in info["native_members"]} == expected
            and all(n["kind"] == "PE" for n in info["native_members"]), "未锁定的构建工具原生数据成员")


def source_bytes(scope, relative):
    """只读该作用域必须绑定的实际来源，不能用清单内自洽的版本表替代来源。"""
    proofs = [item for item in scope["evidence"] if item["path"] == relative]
    require(len(proofs) == 1, scope["id"] + " 缺少必需来源绑定：" + relative)
    content = regular_path(ROOT / relative).read_bytes()
    require(digest(content) == proofs[0]["sha256"], "必需来源字节改变：" + relative)
    return content


def fixed_requirements(lines, parser):
    """由官方packaging读取固定要求；仅certifi可以保留为待明确来源的浮动项。"""
    result = {}
    for text in lines:
        text = text.strip()
        if not text or text.startswith("#"):
            continue
        requirement = parser["requirements"].Requirement(text)
        name = parser["utils"].canonicalize_name(requirement.name)
        require(not requirement.url and not requirement.marker and not requirement.extras and name not in result,
                "来源要求不是唯一直接包：" + text)
        specifiers = list(requirement.specifier)
        if not specifiers:
            require(name == "certifi", "来源具有未锁定浮动包：" + text)
            result[name] = None
        else:
            require(len(specifiers) == 1 and specifiers[0].operator == "==" and "*" not in specifiers[0].version,
                    "来源要求不是精确版本：" + text)
            result[name] = str(parser["version"].Version(specifiers[0].version))
    return result


def target_ci_versions(scope, parser):
    """从成功CI三次实际安装行独立取得完整target包集合，不从新清单反推。"""
    relative = "ThirdParty/build/renpy-source/8.5.3/run-37760587281/renpy-8.5.3-ios-logs-37760587281-1/logs/build.log"
    installs = []
    for line in source_bytes(scope, relative).decode().splitlines():
        if line.startswith("Successfully installed ") and "certifi-" in line:
            pins = [name + "==" + version for token in line.removeprefix("Successfully installed ").split()
                    for name, version in [token.rsplit("-", 1)]]
            installs.append(fixed_requirements(pins, parser))
    require(len(installs) == 3 and all(p == installs[0] for p in installs), "成功CI三架构target集合不一致或缺失")
    return installs[0]


def sdk_version(scope, package, parser):
    """读取官方SDK已有字节中的版本常量，不执行或反序列化字节码。"""
    release = scope["release"]
    python = "2.7" if release == "7.8.7" else "3.9" if release == "8.3.7" else "3.12"
    suffix = "pyo" if python == "2.7" else "pyc"
    module = "version" if package == "chardet" else "__init__"
    relative = f"ThirdParty/renpy/releases/{release}/sdk/renpy-{release}-sdk/lib/python{python}/{package}/{module}.{suffix}"
    candidates = re.findall(rb"(?:20\d\d|\d)\.\d{1,2}\.\d{1,2}", source_bytes(scope, relative))
    require(len(candidates) == 1, "SDK版本常量不唯一：" + relative)
    return str(parser["version"].Version(candidates[0].decode()))


def verify_scope_sources(scope, parser):
    """独立绑定原始freeze/pip配方/SDK及Python版本，拒绝成套删除直接leaf包。"""
    release = scope["release"]
    base = f"ThirdParty/renpy/sources/renpy-build-{release}"
    target_python2 = scope["kind"] == "target" and release == "7.8.7"
    recipe = f"{base}/tasks/python{'2' if target_python2 else '3'}.py"
    tree = ast.parse(source_bytes(scope, recipe).decode())
    version = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == "version" for t in n.targets))
    host = scope["kind"] == "host"
    expected_python = ("3.12.3" if release in ("8.5.3", "8.4.1") else "3.10.0") if host else version
    require(scope["python_version"] == expected_python, scope["id"] + " Python/ABI来源不符")
    freeze = "ThirdParty/build/renpy-source/8.5.3/run-37760587281/renpy-8.5.3-ios-logs-37760587281-1/host-python-requirements.txt"
    origins = {}
    if scope["id"] == "8.5.3-host-ci-success":
        pins = fixed_requirements(source_bytes(scope, freeze).decode().splitlines(), parser)
        origins = dict.fromkeys(pins, "observed_ci")
    elif scope["id"] == "8.5.3-target-ci-success":
        pins = target_ci_versions(scope, parser)
        origins = dict.fromkeys(pins, "observed_ci")
    elif host:
        pins = fixed_requirements(source_bytes(scope, base + "/requirements.txt").decode().splitlines(), parser)
        origins = dict.fromkeys(pins, "recipe_pin")
        if pins.get("certifi") is None:
            pins["certifi"] = fixed_requirements(source_bytes(scope, freeze).decode().splitlines(), parser)["certifi"]
            origins["certifi"] = "prospective_build_pin"
    else:
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "pip")
        commands = [n.value for n in ast.walk(function) if isinstance(n, ast.Constant)
                    and isinstance(n.value, str) and "-m pip install" in n.value]
        require(len(commands) == 1, "target安装要求来源不唯一")
        tokens = shlex.split(commands[0].split("-m pip install", 1)[1])
        pins = fixed_requirements([t for t in tokens if t not in ("--upgrade", "--no-compile")], parser)
        origins = dict.fromkeys(pins, "recipe_pin")
        if pins.get("certifi") is None:
            pins["certifi"] = target_ci_versions(scope, parser)["certifi"] if release == "8.5.3" else sdk_version(scope, "certifi", parser)
            origins["certifi"] = "observed_ci" if release == "8.5.3" else "sdk_target_candidate"
        if release == "7.8.7":
            pins["chardet"] = sdk_version(scope, "chardet", parser)
            origins["chardet"] = "sdk_target_candidate"
    require(pins == scope["expected_versions"], scope["id"] + " 包集合与独立来源不一致")
    require(all(p["origin"] == origins[p["name"]] for p in scope["packages"]), "包来源状态与独立证据不一致")


def verify_evidence(scopes):
    """核对每个作用域的已知配方、CI或SDK来源原字节，避免把新选择伪装为历史结果。"""
    checked = {}
    for scope in scopes:
        for item in scope["evidence"]:
            keys(item, ("path", "sha256", "kind"), "来源证据")
            relative = safe_name(item["path"], "来源证据")
            require(SHA.fullmatch(item["sha256"]) and type(item["kind"]) is str and item["kind"], "来源证据身份错误")
            require(relative not in checked or checked[relative] == item["sha256"], "来源证据重复身份冲突")
            if relative not in checked:
                require(digest(regular_path(ROOT / relative).read_bytes()) == item["sha256"], "来源证据 hash 改变：" + relative)
                checked[relative] = item["sha256"]
    return checked


def run(mode, lock, cache):
    """逐包核验或下载，解析器身份与所有作用域全部通过后才返回材料通过。"""
    manifest, lock_sha = load_manifest(lock)
    evidence = verify_evidence(manifest["scopes"])
    inspections = {}
    downloads = {}
    for ident, artifact in manifest["artifacts"].items():
        if mode == "download":
            downloads[ident] = fetch_artifact(cache, artifact)
        path = artifact_path(cache, artifact)
        inspections[ident] = inspect_artifact(path, artifact)
        log(artifact["filename"] + " 完整字节/归档身份通过")
    parser = load_parser(cache, manifest)
    scopes = [verify_scope(scope, manifest, inspections, parser) for scope in manifest["scopes"]]
    return {"task": "R00-02J2A", "result": "passed", "mode": mode, "lock_sha256": lock_sha,
            "artifact_count": len(inspections), "total_bytes": sum(a["size"] for a in manifest["artifacts"].values()),
            "artifacts": [{"id": ident, "filename": manifest["artifacts"][ident]["filename"], "inspection": info,
                           "path": str(artifact_path(cache, manifest["artifacts"][ident])), "download_status": downloads.get(ident, "not_requested")}
                          for ident, info in inspections.items()], "scopes": scopes,
            "parser": {"version": "24.1", "file": parser[""].__file__, "artifact": manifest["tool_dependency"]["artifact"]},
            "source_evidence": evidence,
            "selection_scope": "保留原CI包版本与Linux wheel选择记录；本轮分发选择是新增强锁，未宣称复现旧CI未记录的wheel字节。setuptools74.1.2由hostpython执行pip使用，pythonlib规则不复制setuptools；8个PE launcher仅锁定为构建工具数据，不是iOS运行包。",
            "complete_python_input_closure": False, "offline_install_verified": False, "sdist_build_verified": False}


def main():
    """提供 download/verify 两个真实入口，以非零状态和新报告保存具体失败。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("download", "verify"))
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        regular_path(args.report)
        require(not args.report.exists(), "拒绝覆盖旧报告")
        args.report.parent.mkdir(parents=True, exist_ok=True)
        try:
            result = run(args.mode, args.lock, args.cache)
        except (OSError, ValueError, KeyError, TypeError, ImportError, zipfile.BadZipFile, tarfile.TarError, csv.Error, UnicodeError) as error:
            result = {"task": "R00-02J2A", "result": "failed", "mode": args.mode, "error_type": type(error).__name__, "error": str(error)}
        with args.report.open("x") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        log("材料校验" + ("通过" if result["result"] == "passed" else "失败：" + result["error"]))
        return 0 if result["result"] == "passed" else 1
    except (OSError, ValueError) as error:
        log("报告入口失败：" + str(error))
        return 1


if __name__ == "__main__":
    sys.exit(main())
