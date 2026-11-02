#!/usr/bin/env python3
"""在隔离Linux容器采集固定APT分发，跨平台仅复核原字节与采集证据引用。"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import errno
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


COMMON_PACKAGES = "git build-essential ccache unzip autoconf autoconf-archive automake libtool-bin pkg-config python3-dev python3-pip python3-venv curl ca-certificates libgmp-dev libmpfr-dev libmpc-dev libssl-dev libbz2-dev liblzma-dev zlib1g-dev libffi-dev bc cmake ninja-build libxml2-dev libavcodec-dev libavformat-dev libswresample-dev libswscale-dev libfreetype6-dev libfribidi-dev libsdl2-dev libsdl2-image-dev libsdl2-gfx-dev libsdl2-mixer-dev libsdl2-ttf-dev libjpeg-dev libharfbuzz-dev".split()
PROFILES = {"24.04": {"codename": "noble", "extra": "clang-18 lld-18 llvm-18 llvm-15 libassimp-dev".split()},
            "22.04": {"codename": "jammy", "extra": "clang-15 lld-15 llvm-15 python2-dev".split()}}
UNVERIFIED = ["packages_installed", "offline_build_environment_verified", "source_build_executed", "complete_closure"]
SCOPE = "apt_candidate_package_materialization"
DOWNLOAD_ATTEMPTS = 4
DOWNLOAD_RETRY_HTTP = {429, 500, 502, 503, 504}


class AptInputError(ValueError):
    """表示环境、签名、求解或分发身份未满足真实采集契约。"""


def require(condition, message):
    """任何缺失和不一致都失败，不补齐成功或跳过关键验证。"""
    if not condition:
        raise AptInputError(message)


def relative(value):
    """只接纳规范POSIX相对路径，防止镜像元数据写出采集目录。"""
    require(type(value) is str and bool(value) and "\\" not in value
            and not PurePosixPath(value).is_absolute()
            and all(p not in ("", ".", "..") for p in value.split("/"))
            and not any(ord(c) < 32 for c in value), "相对路径越界或格式错误")
    return value


def guarded(path):
    """拒绝任何父目录链接，不把证据重定向到其他文件树。"""
    path = Path(os.path.abspath(path))
    require(not any(p.is_symlink() for p in path.parents), "证据父目录包含符号链接")
    return path


def digest(path):
    """流式检查普通文件完整SHA256，适用于大索引和分发包。"""
    path = guarded(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode), "证据不是普通文件：" + str(path))
    h = hashlib.sha256()
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def valid_sha(value):
    """要求完整小写摘要，不能用空值或缩写表示身份。"""
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "SHA256格式错误")
    return value


def unique_pairs(pairs):
    """JSON重复键不得覆盖证据字段。"""
    result = {}
    for key, value in pairs:
        require(key not in result, "JSON重复键")
        result[key] = value
    return result


def reject_constant(value):
    """拒绝非标准JSON数值。"""
    raise AptInputError("JSON非有限值：" + value)


def read_json(path):
    """读取实际普通JSON对象，不跟随文件链接。"""
    digest(path)
    value = json.loads(path.read_bytes(), object_pairs_hook=unique_pairs, parse_constant=reject_constant)
    require(type(value) is dict, "JSON根节点应为对象")
    return value


def write_new(path, data):
    """独占创建新文件，不覆盖旧证据或下载失败残留。"""
    path = guarded(path)
    require(not path.exists() and not path.is_symlink(), "输出已存在：" + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)


def write_json(path, value):
    """以真实JSON状态创建唯一新报告。"""
    write_new(path, (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode())


def file_record(root, path):
    """记录相对位置、实际字节数和整文件摘要。"""
    return {"path": relative(path.relative_to(root).as_posix()), "bytes": path.stat().st_size,
            "sha256": digest(path)}


def check_file(root, record):
    """从记录重读实际文件，错误类型和布尔大小不能放行。"""
    require(type(record) is dict and set(record) == {"path", "bytes", "sha256"}, "文件记录字段错误")
    path = root / relative(record["path"])
    require(type(record["bytes"]) is int and record["bytes"] >= 0
            and path.stat().st_size == record["bytes"]
            and digest(path) == valid_sha(record["sha256"]), "文件hash/大小不符：" + str(path))
    return path


def environment_profile(lock_path, expected_sha, ubuntu):
    """读取独立SHA锚定的A元数据锁，保持候选身份及尚未验收边界。"""
    require(digest(lock_path) == valid_sha(expected_sha), "A环境锁SHA不符")
    lock = read_json(lock_path)
    require(type(lock.get("schema_version")) is int and lock["schema_version"] == 1
            and lock.get("scope") == "environment_candidate_metadata_only"
            and lock.get("metadata_verified") is True, "A环境锁范围错误")
    require(all(lock.get(k) is False for k in ["signature_verified", "install_verified", "historical_replay", "complete_closure"]), "A环境锁伪造更高验收状态")
    require(ubuntu in PROFILES, "未批准的Ubuntu路线")
    snapshot = lock["snapshot_id"]
    require(re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", snapshot), "snapshot格式错误")
    datetime.strptime(snapshot, "%Y%m%dT%H%M%SZ")
    selected = [g for g in lock["oci_candidates"] if g["ubuntu"] == ubuntu]
    require(len(selected) == 1, "A锁候选重复或缺失")
    group = selected[0]
    require(group["codename"] == PROFILES[ubuntu]["codename"]
            and group["platform"] == {"os": "linux", "architecture": "amd64"}, "A锁发行版/架构错误")
    files = group["files"]
    require(len(files) == 3 and files[1]["path"].endswith("-amd64-manifest.json")
            and files[2]["path"].endswith("-amd64-config.json"), "A锁OCI文件顺序错误")
    for role, file in zip(["manifests", "manifests", "blobs"], files):
        require(file["source_url"] == "https://registry-1.docker.io/v2/library/ubuntu/" + role + "/sha256:" + valid_sha(file["sha256"]), "A锁OCI来源错误")
    suites = [group["codename"] + suffix for suffix in ("", "-updates", "-security")]
    rows = [r for r in lock["apt_snapshots"] if r["suite"] in suites]
    require(len(rows) == 3 and {r["suite"] for r in rows} == set(suites), "A锁snapshot缺失或重复")
    for row in rows:
        require(row["codename"] == group["codename"] and row["ubuntu"] == ubuntu
                and row["file"]["source_url"] == "https://snapshot.ubuntu.com/ubuntu/" + snapshot + "/dists/" + row["suite"] + "/InRelease", "A锁snapshot来源错误")
    return {"ubuntu": ubuntu, "snapshot": snapshot, "codename": group["codename"],
            "image": "docker.io/library/ubuntu@sha256:" + files[1]["sha256"],
            "image_id": "sha256:" + files[2]["sha256"], "snapshots": rows,
            "direct_requirements": COMMON_PACKAGES + PROFILES[ubuntu]["extra"]}


class SnapshotOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """HTTPS运输只允许固定snapshot服务内重定向，不向其他来源取包。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """拒绝降级协议、凭据、查询参数和跨站地址。"""
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def validate_url(url):
    """下载源必须为Canonical固定snapshot HTTPS路径，不允许任意网络URL。"""
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.netloc == "snapshot.ubuntu.com"
            and not parsed.query and not parsed.fragment and not parsed.username
            and parsed.path.startswith("/ubuntu/"), "下载URL越界")
    relative(urllib.parse.unquote(parsed.path.removeprefix("/")))


def retryable_download_error(error):
    """仅将明确暂态HTTP、网络超时和连接错误列为可重试，身份错误不降级。"""
    if isinstance(error, urllib.error.HTTPError):
        return error.code in DOWNLOAD_RETRY_HTTP
    cause = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(cause, socket.gaierror):
        return cause.errno == socket.EAI_AGAIN
    return isinstance(cause, (TimeoutError, ConnectionError)) or (
        isinstance(cause, OSError) and cause.errno in {
            errno.ETIMEDOUT, errno.ECONNRESET, errno.ECONNABORTED, errno.ECONNREFUSED,
            errno.ENETDOWN, errno.ENETUNREACH, errno.EHOSTUNREACH})


def download_attempt(url, path, temporary, expected_sha, expected_size, opener):
    """一次TLS运输使用全新临时文件，只有完整固定字节校验通过才独占发布。"""
    with opener.open(urllib.request.Request(url, headers={"User-Agent": "Reko-fixed-apt-inputs"}), timeout=120) as source, temporary.open("xb") as output:
        while block := source.read(1024 * 1024):
            require(output.tell() + len(block) <= expected_size, "下载超过固定大小")
            output.write(block)
    require(temporary.stat().st_size == expected_size and digest(temporary) == expected_sha, "下载SHA/大小不符")
    os.link(temporary, path)


def reuse_cached_download(cache, target, path, expected_sha, expected_size, url, evidence_root):
    """只复用独立缓存中逐字节通过的原件，坏缓存失败，复制后再次核验再独占发布。"""
    source = guarded(cache / target)
    if not source.exists() and not source.is_symlink():
        return False
    require(source.stat().st_size == expected_size and digest(source) == expected_sha, "缓存原件SHA/大小不符：" + str(source))
    temporary = path.with_name(path.name + ".part-" + uuid.uuid4().hex)
    try:
        with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW), "rb") as original, temporary.open("xb") as output:
            shutil.copyfileobj(original, output)
        require(temporary.stat().st_size == expected_size and digest(temporary) == expected_sha, "缓存复制后身份不符")
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    write_json(evidence_root / "downloads" / uuid.uuid4().hex / "cache.json",
               {"result": "verified", "transport": "verified_original_bytes_cache", "url": url,
                "source": str(source), "target": target, "bytes": expected_size, "sha256": expected_sha})
    print("[RenPyAptInputs] 复用已校验原件：" + target, flush=True)
    return True


def download(url, path, expected_sha, expected_size, evidence_root, cache=None):
    """固定源有界重试暂态运输故障，逐次保留证据，身份/路径错误立即失败。"""
    validate_url(url)
    valid_sha(expected_sha)
    require(type(expected_size) is int and expected_size > 0, "下载大小错误")
    path = guarded(path)
    require(not path.exists() and not path.is_symlink(), "拒绝覆盖已有下载")
    evidence_root = guarded(evidence_root)
    target = relative(path.relative_to(evidence_root).as_posix())
    path.parent.mkdir(parents=True, exist_ok=True)
    if cache is not None and reuse_cached_download(cache, target, path, expected_sha, expected_size, url, evidence_root):
        return
    log_dir = evidence_root / "downloads" / uuid.uuid4().hex
    opener = urllib.request.build_opener(SnapshotOnlyRedirect())
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        row = {"url": url, "target": target, "expected_sha256": expected_sha,
               "expected_bytes": expected_size, "attempt": attempt, "max_attempts": DOWNLOAD_ATTEMPTS,
               "started_at_utc": datetime.now(timezone.utc).isoformat()}
        write_json(log_dir / ("%02d-started.json" % attempt), {**row, "result": "started"})
        print(f"[RenPyAptInputs] 下载 {attempt}/{DOWNLOAD_ATTEMPTS}：{url}", flush=True)
        temporary = path.with_name(path.name + ".part-" + uuid.uuid4().hex)
        try:
            download_attempt(url, path, temporary, expected_sha, expected_size, opener)
        except Exception as error:
            retryable = retryable_download_error(error)
            retry = retryable and attempt < DOWNLOAD_ATTEMPTS
            delay = 2 ** (attempt - 1) if retry else 0
            result_path = log_dir / ("%02d-result.json" % attempt)
            write_json(result_path, {**row, "result": "failed", "finished_at_utc": datetime.now(timezone.utc).isoformat(),
                                    "error_type": type(error).__name__,
                                    "error": str(error), "http_status": getattr(error, "code", None),
                                    "received_bytes": temporary.stat().st_size if temporary.exists() else 0,
                                    "retryable": retryable, "retry_planned": retry, "retry_delay_seconds": delay})
            if isinstance(error, urllib.error.HTTPError):
                error.close()
            print(f"[RenPyAptInputs] 下载失败 {attempt}/{DOWNLOAD_ATTEMPTS}：{error}；"
                  + (f"{delay}秒后重试" if retry else "停止"), flush=True)
            if not retry:
                raise AptInputError("固定源下载失败：" + url + "；" + str(error) + "；详见" + str(result_path)) from error
        else:
            write_json(log_dir / ("%02d-result.json" % attempt), {**row, "result": "verified", "finished_at_utc": datetime.now(timezone.utc).isoformat(),
                                                               "actual_bytes": expected_size, "actual_sha256": expected_sha})
            print(f"[RenPyAptInputs] 下载校验通过：{target}（{expected_size}字节）", flush=True)
            return
        finally:
            temporary.unlink(missing_ok=True)
        time.sleep(delay)


def release_fields(data):
    """仅解析已由gpgv验真的Release头和SHA256目录，不实现APT依赖求解。"""
    text = data.decode("utf-8")
    require(text.startswith("-----BEGIN PGP SIGNED MESSAGE-----\n") and text.count("\n-----BEGIN PGP SIGNATURE-----") == 1, "InRelease格式错误")
    body = text.split("\n\n", 1)[1].split("\n-----BEGIN PGP SIGNATURE-----", 1)[0]
    fields, key = {}, None
    for line in body.splitlines():
        if line.startswith(" "):
            require(key is not None, "Release孤立续行")
            fields[key].append(line[1:])
        elif line:
            key, separator, value = line.partition(":")
            require(separator and key not in fields, "Release字段重复或无效")
            fields[key] = [value.strip()]
    hashes = {}
    require(fields.get("SHA256", [None])[0] == "", "Release缺少SHA256目录")
    for line in fields["SHA256"][1:]:
        parts = line.split()
        require(len(parts) == 3 and parts[1].isdigit(), "Release索引记录错误")
        path = relative(parts[2])
        require(path not in hashes, "Release重复索引")
        hashes[path] = {"sha256": valid_sha(parts[0]), "bytes": int(parts[1])}
    return fields, hashes


def valid_signatures(stdout):
    """只接受gpgv实际VALIDSIG状态，未知、坏签名和整数标记不能替代。"""
    lines = stdout.decode("utf-8").splitlines()
    forbidden = ("BADSIG", "ERRSIG", "NO_PUBKEY", "EXPSIG", "EXPKEYSIG", "REVKEYSIG")
    require(not any(any("[GNUPG:] " + bad + " " in line for bad in forbidden) for line in lines), "gpgv报告无效签名")
    fingerprints = []
    for line in lines:
        if line.startswith("[GNUPG:] VALIDSIG "):
            parts = line.split()
            require(len(parts) >= 11 and re.fullmatch(r"(?:[0-9A-F]{40}|[0-9A-F]{64})", parts[2]), "gpgv VALIDSIG字段错误")
            fingerprints.append(parts[2])
    require(bool(fingerprints), "gpgv没有实际VALIDSIG状态")
    return fingerprints


def base_packages(data):
    """保留完整base包状态，不能把空输出或省略架构/状态当成已有包闭包。"""
    result = []
    for line in data.decode("utf-8").splitlines():
        fields = line.split("\t")
        require(len(fields) == 4 and all(fields[:3]) and fields[2] in ("amd64", "all")
                and re.fullmatch(r"[uhipr][ncHUFWTi][R ]", fields[3]), "base包状态字段错误")
        result.append({"package": fields[0], "version": fields[1], "architecture": fields[2], "status": fields[3]})
    require(bool(result) and len(result) == len({r["package"] for r in result}), "base包清单为空或重复")
    return result


def package_stanzas(path):
    """流式读取Deb822控制记录，只做字段解析，APT仍是唯一依赖求解器。"""
    current, key = {}, None
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            line = line.rstrip("\n")
            if not line:
                if current:
                    yield current
                current, key = {}, None
            elif line[0] in " \t":
                require(key is not None, "Deb822孤立续行")
                current[key] += "\n" + line[1:]
            else:
                key, separator, value = line.partition(":")
                require(separator and key not in current, "Deb822重复/错误字段")
                current[key] = value.lstrip()
    if current:
        yield current


def print_uri_requests(stdout):
    """读取APT自己生成的获取清单，拒绝非固定file:仓库和重复包。"""
    result, seen = [], set()
    for line in stdout.decode("utf-8").splitlines():
        if not line.startswith("'"):
            continue
        fields = shlex.split(line)
        require(len(fields) == 4 and fields[2].isdigit(), "APT获取清单格式错误")
        uri = urllib.parse.urlsplit(fields[0])
        require(uri.scheme == "file" and not uri.netloc and not uri.query and not uri.fragment, "APT试图访问非固定file仓库")
        path = urllib.parse.unquote(uri.path)
        require(path.startswith("/reko/repo/pool/"), "APT包路径越界")
        filename = relative(path.removeprefix("/reko/repo/"))
        cache = relative(fields[1])
        require("/" not in cache and cache.endswith(".deb") and filename not in seen and int(fields[2]) > 0, "APT获取包重复或名称错误")
        seen.add(filename)
        result.append({"filename": filename, "cache_name": cache, "bytes": int(fields[2]), "apt_uri": fields[0]})
    require(bool(result), "固定基础镜像未产生任何待获取构建包，拒绝空闭包")
    return result


def package_lookup(indexes, requests):
    """把APT请求绑定到已验签索引的Filename/SHA/Size和完整控制字段。"""
    wanted = {r["filename"]: r for r in requests}
    found = {}
    for index in indexes:
        for row in package_stanzas(index["path"]):
            name = row.get("Filename")
            if name not in wanted:
                continue
            relative(name)
            require(row.get("Architecture") in ("amd64", "all") and row.get("Size", "").isdigit()
                    and int(row["Size"]) == wanted[name]["bytes"], "索引包架构/大小与APT请求不符")
            valid_sha(row.get("SHA256"))
            require(bool(row.get("Package")) and bool(row.get("Version")), "索引包身份缺失")
            origin = {"suite": index["suite"], "component": index["component"]}
            if name in found:
                # security/updates可为同一deb附加不同分阶段发布字段；分发身份必须完全一致。
                require(all(found[name]["control"].get(k) == row.get(k)
                            for k in ("Package", "Version", "Architecture", "Filename", "Size", "SHA256")), "同名分发在索引中身份冲突")
                if origin not in found[name]["origins"]:
                    found[name]["origins"].append(origin)
            else:
                found[name] = {"control": row, "suite": index["suite"], "component": index["component"], "origins": [origin]}
    require(set(found) == set(wanted), "APT请求包未完整匹配已签索引")
    return found


class Commands:
    """逐次保存真实命令、退出码及原始输出，不向容器传递凭据。"""

    def __init__(self, output):
        """为本轮独占目录建立命令记录容器。"""
        self.output, self.records = output, []

    def run(self, args, label, timeout=1800):
        """执行无shell参数数组，非零或超时保留日志后明确失败。"""
        prefix = "commands/%03d-%s" % (len(self.records), label)
        try:
            result = subprocess.run([str(a) for a in args], capture_output=True, timeout=timeout)
            stdout_bytes, stderr_bytes, returncode = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as error:
            stdout_bytes, stderr_bytes, returncode = error.stdout or b"", error.stderr or b"", None
        stdout, stderr = self.output / (prefix + ".stdout"), self.output / (prefix + ".stderr")
        write_new(stdout, stdout_bytes)
        write_new(stderr, stderr_bytes)
        row = {"label": label, "argv": [str(a) for a in args], "returncode": returncode,
               "stdout": file_record(self.output, stdout), "stderr": file_record(self.output, stderr)}
        self.records.append(row)
        require(returncode == 0, "命令失败/超时：" + label + "；详见" + str(stderr))
        return stdout_bytes, row


def apt_configuration(codename):
    """仅启用固定离线file仓库与Packages目标，禁用默认sourceparts和额外索引。"""
    sources = "".join("deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg by-hash=no] file:/reko/repo " + codename + suffix + " main universe\n" for suffix in ("", "-updates", "-security"))
    config = '''Dir::Etc::sourcelist "/reko/sources.list";
Dir::Etc::sourceparts "-";
Dir::Etc::preferences "/reko/preferences";
Dir::Etc::preferencesparts "-";
Dir::State::lists "/reko/apt/lists";
Dir::Cache::archives "/reko/apt/archives";
Acquire::Languages "none";
Acquire::PDiffs "false";
#clear Acquire::CompressionTypes::Order;
Acquire::CompressionTypes::Order { "xz"; };
APT::Install-Recommends "false";
APT::Install-Suggests "false";
#clear Acquire::IndexTargets;
Acquire::IndexTargets::deb::Packages {
 MetaKey "$(COMPONENT)/binary-$(ARCHITECTURE)/Packages";
 ShortDescription "Packages";
 Description "$(RELEASE)/$(COMPONENT) $(ARCHITECTURE) Packages";
};
#clear APT::Update::Post-Invoke;
#clear APT::Update::Post-Invoke-Success;
#clear DPkg::Post-Invoke;
'''
    return sources.encode(), config.encode()


def check_apt_index_order(data):
    """检查容器合并后的压缩优先级，拒绝Docker预置gzip先于已物化xz。"""
    text = data.decode("utf-8")
    order = re.findall(r'^Acquire::CompressionTypes::Order:: "([^"\n]*)";$', text, re.MULTILINE)
    parents = [line for line in text.splitlines() if line.startswith("Acquire::CompressionTypes::Order ")]
    require(order == ["xz"] and parents in ([], ['Acquire::CompressionTypes::Order "";']),
            "APT有效压缩优先级不是独占xz：" + repr(parents + order))


def collect(lock_path, lock_sha, ubuntu, output, cache=None):
    """通过无网络容器验签和APT求解，host运输全部已签索引和分发，不安装软件。"""
    require(platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64"), "采集需要真实Linux amd64 host")
    docker = shutil.which("docker")
    require(docker is not None, "采集需要Docker运行时")
    profile = environment_profile(lock_path, lock_sha, ubuntu)
    if cache is not None:
        cache = guarded(cache)
        require(cache.is_dir() and not cache.is_symlink() and not cache.is_relative_to(output), "缓存必须是输出之外的独立普通目录")
    write_new(output / "environment-inputs.lock.json", lock_path.read_bytes())
    commands = Commands(output)
    name = "reko-apt-" + uuid.uuid4().hex
    active = False
    manifest = None
    try:
        commands.run([docker, "pull", "--platform", "linux/amd64", profile["image"]], "pull-image")
        inspected, inspect_command = commands.run([docker, "image", "inspect", profile["image"]], "image-inspect")
        image = json.loads(inspected)
        require(len(image) == 1 and image[0]["Id"] == profile["image_id"]
                and image[0]["Architecture"] == "amd64" and image[0]["Os"] == "linux", "Docker实际镜像身份不符")
        commands.run([docker, "run", "--detach", "--user", "0:0", "--platform", "linux/amd64", "--network", "none", "--name", name, profile["image"], "/bin/sleep", "infinity"], "container-start")
        active = True
        def execute(args, label):
            """只对本轮唯一无网络容器执行明确参数数组。"""
            return commands.run([docker, "exec", name, *args], label)
        def copy_to(path, target, label):
            """把host已验证文件复制到唯一容器，不挂载工作区和凭据。"""
            commands.run([docker, "cp", str(path), name + ":" + target], label)
        execute(["mkdir", "-p", "/reko/repo", "/reko/apt/lists/partial", "/reko/apt/archives/partial"], "prepare-directories")
        os_release, os_command = execute(["cat", "/etc/os-release"], "base-os")
        os_fields = dict(line.split("=", 1) for line in os_release.decode().splitlines() if "=" in line and not line.startswith("#"))
        require(os_fields.get("ID", "").strip('"') == "ubuntu" and os_fields.get("VERSION_ID", "").strip('"') == ubuntu, "容器实际发行版不符")
        package_format = '${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n'
        base_rows, base_command = execute(["dpkg-query", "--show", "--showformat=" + package_format], "base-packages")
        base_packages(base_rows)
        base_status, status_command = execute(["cat", "/var/lib/dpkg/status"], "base-status")
        commands.run([docker, "cp", name + ":/usr/share/keyrings/ubuntu-archive-keyring.gpg", str(output / "ubuntu-archive-keyring.gpg")], "base-keyring")
        commands.run([docker, "exec", name, "gpgv", "--version"], "gpgv-version")
        commands.run([docker, "exec", name, "apt-get", "--version"], "apt-version")
        signed, indexes = [], []
        repo = output / "repository"
        for row in profile["snapshots"]:
            suite, source = row["suite"], row["file"]
            path = repo / "dists" / suite / "InRelease"
            download(source["source_url"], path, source["sha256"], source["bytes"], output, cache)
            execute(["mkdir", "-p", "/reko/repo/dists/" + suite], "prepare-" + suite)
            copy_to(path, "/reko/repo/dists/" + suite + "/InRelease", "copy-" + suite)
            stdout, command = execute(["gpgv", "--status-fd=1", "--keyring", "/usr/share/keyrings/ubuntu-archive-keyring.gpg", "/reko/repo/dists/" + suite + "/InRelease"], "gpgv-" + suite)
            fingerprints = valid_signatures(stdout)
            fields, hashes = release_fields(path.read_bytes())
            require(all(fields.get(k) == [v] for k, v in {"Origin": "Ubuntu", "Label": "Ubuntu", "Suite": suite, "Codename": profile["codename"], "Version": ubuntu}.items()), "已签Release发行字段不符")
            index_rows = []
            for component in ("main", "universe"):
                relative_index = component + "/binary-amd64/Packages"
                compressed_pin, plain_pin = hashes[relative_index + ".xz"], hashes[relative_index]
                descriptor = next(i for i in row["amd64_index_descriptors"] if i["path"] == relative_index + ".xz")
                require({"sha256": descriptor["sha256"], "bytes": descriptor["bytes"]} == compressed_pin, "A锁索引与实际已签Release不符")
                compressed = path.parent / (relative_index + ".xz")
                url = source["source_url"].removesuffix("InRelease") + relative_index + ".xz"
                download(url, compressed, compressed_pin["sha256"], compressed_pin["bytes"], output, cache)
                plain = path.parent / relative_index
                with lzma.open(compressed, "rb") as stream, plain.open("xb") as target:
                    shutil.copyfileobj(stream, target)
                require(plain.stat().st_size == plain_pin["bytes"] and digest(plain) == plain_pin["sha256"], "解压Packages与已签Release不符")
                indexes.append({"path": plain, "suite": suite, "component": component})
                index_rows.append({"component": component, "compressed": file_record(output, compressed), "plain": file_record(output, plain)})
            signed.append({"suite": suite, "inrelease": file_record(output, path), "gpgv_label": command["label"], "valid_signatures": fingerprints, "indexes": index_rows})
        copy_to(str(repo) + "/.", "/reko/repo", "copy-repository")
        sources, configuration = apt_configuration(profile["codename"])
        for filename, data in [("sources.list", sources), ("apt.conf", configuration), ("preferences", b"")]:
            path = output / filename
            write_new(path, data)
            copy_to(path, "/reko/" + filename, "copy-" + filename)
        apt = ["apt-get", "-c", "/reko/apt.conf"]
        effective_config, _ = execute(["apt-config", "-c", "/reko/apt.conf", "dump"], "apt-effective-config")
        check_apt_index_order(effective_config)
        execute([*apt, "update"], "apt-update")
        execute([*apt, "--simulate", "--no-install-recommends", "install", *profile["direct_requirements"]], "apt-simulate")
        plan, plan_command = execute([*apt, "--print-uris", "--yes", "--download-only", "--no-install-recommends", "install", *profile["direct_requirements"]], "apt-print-uris")
        requests = print_uri_requests(plan)
        found = package_lookup(indexes, requests)
        packages = []
        for index, request in enumerate(requests):
            item = found[request["filename"]]
            control = item["control"]
            path = repo / request["filename"]
            url = "https://snapshot.ubuntu.com/ubuntu/" + profile["snapshot"] + "/" + urllib.parse.quote(request["filename"], safe="/+._~-")
            download(url, path, control["SHA256"], int(control["Size"]), output, cache)
            execute(["mkdir", "-p", "/reko/repo/" + str(PurePosixPath(request["filename"]).parent)], "deb-directory-%04d" % index)
            copy_to(path, "/reko/repo/" + request["filename"], "copy-deb-%04d" % index)
            raw_control, command = execute(["dpkg-deb", "--field", "/reko/repo/" + request["filename"]], "deb-control-%04d" % index)
            control_path = output / command["stdout"]["path"]
            actual = list(package_stanzas(control_path))
            require(len(actual) == 1 and all(actual[0].get(k) == control[k] for k in ("Package", "Version", "Architecture")), "实际deb控制身份不符")
            packages.append({**request, "source_url": url, "suite": item["suite"], "component": item["component"],
                             "origins": item["origins"],
                             "control": control, "deb": file_record(output, path), "control_label": command["label"]})
        execute([*apt, "--yes", "--download-only", "--no-install-recommends", "install", *profile["direct_requirements"]], "apt-download-only")
        after_rows, _ = execute(["dpkg-query", "--show", "--showformat=" + package_format], "base-packages-after")
        after_status, _ = execute(["cat", "/var/lib/dpkg/status"], "base-status-after")
        require(after_rows == base_rows and after_status == base_status, "采集意外改变base已安装包状态")
        manifest = {"schema_version": 1, "scope": SCOPE, "environment_lock_sha256": lock_sha,
                    "ubuntu": ubuntu, "snapshot": profile["snapshot"], "image": profile["image"], "image_id": profile["image_id"],
                    "direct_requirements": profile["direct_requirements"], "recorded_signature_verified": True,
                    "apt_acquisition_complete": True, "apt_container_executed": True, **{k: False for k in UNVERIFIED},
                    "signed_metadata": signed, "packages": packages, "base_package_label": base_command["label"],
                    "base_status_label": status_command["label"], "image_inspect_label": inspect_command["label"],
                    "os_release_label": os_command["label"], "plan_label": plan_command["label"]}
    finally:
        if active:
            commands.run([docker, "rm", "--force", name], "container-cleanup")
        write_json(output / "commands.json", {"commands": commands.records})
    manifest["commands"] = commands.records
    manifest["files"] = [file_record(output, p) for p in sorted(output.rglob("*")) if p.is_file()]
    return manifest


def command_by_label(root, manifest, label):
    """复核实际采集命令的日志引用和成功退出，不能只信成功布尔值。"""
    rows = [r for r in manifest["commands"] if r["label"] == label]
    require(len(rows) == 1 and type(rows[0]["returncode"]) is int and rows[0]["returncode"] == 0, "采集命令缺失/重复/失败：" + label)
    row = rows[0]
    require(type(row["argv"]) is list and all(type(v) is str for v in row["argv"]), "命令参数记录错误")
    return row, check_file(root, row["stdout"]).read_bytes()


def verify_bundle(root, expected_manifest_sha):
    """跨平台复核采集原字节与链路，不在本机重做gpgv、APT或dpkg执行。"""
    require(digest(root / "manifest.json") == valid_sha(expected_manifest_sha), "采集清单独立SHA不符")
    manifest = read_json(root / "manifest.json")
    require(type(manifest.get("schema_version")) is int and manifest["schema_version"] == 1
            and manifest.get("scope") == SCOPE and manifest.get("recorded_signature_verified") is True
            and manifest.get("apt_acquisition_complete") is True and manifest.get("apt_container_executed") is True
            and all(manifest.get(k) is False for k in UNVERIFIED), "采集清单状态/范围错误")
    report = read_json(root / "collect-report.json")
    require(report.get("result") == "passed" and report.get("manifest_sha256") == expected_manifest_sha
            and report.get("recorded_signature_verified") is True
            and report.get("apt_container_executed") is True
            and all(report.get(k) is False for k in UNVERIFIED), "采集报告未实际完成")
    profile = environment_profile(root / "environment-inputs.lock.json", manifest["environment_lock_sha256"], manifest["ubuntu"])
    require(manifest["image"] == profile["image"] and manifest["image_id"] == profile["image_id"]
            and manifest["snapshot"] == profile["snapshot"] and manifest["direct_requirements"] == profile["direct_requirements"], "base/路线/直接APT需求不符")
    rows = manifest["files"]
    require(type(rows) is list and len(rows) == len({r["path"] for r in rows}), "文件清单重复或缺失")
    for row in rows:
        check_file(root, row)
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() or p.is_symlink()}
    require(actual == {r["path"] for r in rows} | {"manifest.json", "collect-report.json"}, "采集文件集合不符")
    require(len(manifest["commands"]) == len({r["label"] for r in manifest["commands"]}), "采集命令标签重复")
    for row in manifest["commands"]:
        command_by_label(root, manifest, row["label"])
    require(read_json(root / "commands.json") == {"commands": manifest["commands"]}, "命令总表与清单不符")
    start, _ = command_by_label(root, manifest, "container-start")
    require("--network" in start["argv"] and start["argv"][start["argv"].index("--network") + 1] == "none"
            and profile["image"] in start["argv"] and not any(v in start["argv"] for v in ["--env", "--env-file", "--volume", "--mount"]), "容器隔离/凭据边界错误")
    _, raw_image = command_by_label(root, manifest, manifest["image_inspect_label"])
    image = json.loads(raw_image)
    require(len(image) == 1 and image[0]["Id"] == profile["image_id"] and image[0]["Architecture"] == "amd64" and image[0]["Os"] == "linux", "实际image记录身份错误")
    for before, after in [(manifest["base_package_label"], "base-packages-after"), (manifest["base_status_label"], "base-status-after")]:
        require(command_by_label(root, manifest, before)[1] == command_by_label(root, manifest, after)[1], "base包记录不一致")
    base_rows = base_packages(command_by_label(root, manifest, manifest["base_package_label"])[1])
    _, os_release = command_by_label(root, manifest, manifest["os_release_label"])
    os_fields = dict(line.split("=", 1) for line in os_release.decode().splitlines() if "=" in line and not line.startswith("#"))
    require(os_fields.get("ID", "").strip('"') == "ubuntu"
            and os_fields.get("VERSION_ID", "").strip('"') == profile["ubuntu"], "base发行版记录不符")
    sources, configuration = apt_configuration(profile["codename"])
    require((root / "sources.list").read_bytes() == sources and (root / "apt.conf").read_bytes() == configuration
            and (root / "preferences").read_bytes() == b"", "APT有效源或配置与固定file仓库不符")
    config_command, effective_config = command_by_label(root, manifest, "apt-effective-config")
    require(config_command["argv"][-4:] == ["apt-config", "-c", "/reko/apt.conf", "dump"], "有效APT配置采集命令不符")
    check_apt_index_order(effective_config)
    require(digest(root / "ubuntu-archive-keyring.gpg"), "缺少采集keyring")
    signed = manifest["signed_metadata"]
    require(len(signed) == 3 and {r["suite"] for r in signed} == {r["suite"] for r in profile["snapshots"]}, "签名元数据缺失/重复")
    indexes = []
    for row in signed:
        anchor = next(a for a in profile["snapshots"] if a["suite"] == row["suite"])
        path = check_file(root, row["inrelease"])
        require(digest(path) == anchor["file"]["sha256"] and path.stat().st_size == anchor["file"]["bytes"], "InRelease与A锁不符")
        command, stdout = command_by_label(root, manifest, row["gpgv_label"])
        require("gpgv" in command["argv"] and "--keyring" in command["argv"]
                and "/usr/share/keyrings/ubuntu-archive-keyring.gpg" in command["argv"]
                and "/reko/repo/dists/" + row["suite"] + "/InRelease" in command["argv"]
                and row["valid_signatures"] == valid_signatures(stdout), "采集gpgv身份/VALIDSIG记录不符")
        _, hashes = release_fields(path.read_bytes())
        require(len(row["indexes"]) == 2 and {i["component"] for i in row["indexes"]} == {"main", "universe"}, "索引component不完整")
        for item in row["indexes"]:
            for key, suffix in [("plain", ""), ("compressed", ".xz")]:
                actual_path = check_file(root, item[key])
                pin = hashes[item["component"] + "/binary-amd64/Packages" + suffix]
                require(item[key]["sha256"] == pin["sha256"] and item[key]["bytes"] == pin["bytes"], "Packages与签名记录不符")
            indexes.append({"path": check_file(root, item["plain"]), "suite": row["suite"], "component": item["component"]})
    _, plan = command_by_label(root, manifest, manifest["plan_label"])
    requests = print_uri_requests(plan)
    found = package_lookup(indexes, requests)
    require(len(manifest["packages"]) == len(requests) and {p["filename"] for p in manifest["packages"]} == set(found), "分发集合与APT计划不符")
    for package in manifest["packages"]:
        request = next(r for r in requests if r["filename"] == package["filename"])
        require(all(package[k] == v for k, v in request.items())
                and package["suite"] == found[package["filename"]]["suite"]
                and package["component"] == found[package["filename"]]["component"]
                and package["origins"] == found[package["filename"]]["origins"]
                and package["deb"]["path"] == "repository/" + package["filename"], "分发引用与APT请求/索引来源不符")
        control = found[package["filename"]]["control"]
        require(package["control"] == control, "分发控制记录与签名索引不符")
        path = check_file(root, package["deb"])
        require(digest(path) == control["SHA256"] and path.stat().st_size == int(control["Size"]), "deb与签名Packages不符")
        expected_url = "https://snapshot.ubuntu.com/ubuntu/" + profile["snapshot"] + "/" + urllib.parse.quote(package["filename"], safe="/+._~-")
        require(package["source_url"] == expected_url, "分发来源越界")
        command, _ = command_by_label(root, manifest, package["control_label"])
        actual_control = list(package_stanzas(check_file(root, command["stdout"])))
        require("dpkg-deb" in command["argv"] and len(actual_control) == 1
                and all(actual_control[0].get(k) == control[k] for k in ["Package", "Version", "Architecture"]), "实际deb控制字段不符")
    command_by_label(root, manifest, "apt-update")
    command_by_label(root, manifest, "apt-simulate")
    command_by_label(root, manifest, "apt-download-only")
    command_by_label(root, manifest, "container-cleanup")
    return {"result": "passed", "scope": "recorded_apt_bytes_and_references", "package_count": len(requests),
            "base_package_record_count": len(base_rows),
            "recorded_signature_verified": True, "local_signature_reexecuted": False,
            "local_apt_reexecuted": False, **{k: False for k in UNVERIFIED}}


def main(argv=None):
    """执行真实Linux采集或跨平台证据复核；失败只保留失败报告。"""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    capture = commands.add_parser("collect")
    capture.add_argument("--environment-lock", type=Path, required=True)
    capture.add_argument("--environment-lock-sha256", required=True)
    capture.add_argument("--ubuntu", choices=PROFILES, required=True)
    capture.add_argument("--output", type=Path, required=True)
    capture.add_argument("--cache", type=Path)
    verify = commands.add_parser("verify")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--manifest-sha256", required=True)
    verify.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    report = {"result": "failed", "mode": args.mode, "errors": [], "local_signature_reexecuted": False,
              "local_apt_reexecuted": False, **{k: False for k in UNVERIFIED}}
    output = None
    try:
        if args.mode == "collect":
            directory = guarded(args.output)
            require(not directory.exists() and not directory.is_symlink(), "采集输出目录必须全新")
            directory.mkdir(parents=True)
            output = directory / "collect-report.json"
            manifest = collect(guarded(args.environment_lock), args.environment_lock_sha256, args.ubuntu, directory, args.cache)
            write_json(directory / "manifest.json", manifest)
            report.update(result="passed", manifest_sha256=digest(directory / "manifest.json"),
                          package_count=len(manifest["packages"]), recorded_signature_verified=True,
                          apt_container_executed=True)
        else:
            output = guarded(args.report)
            require(not output.exists() and not output.is_symlink(), "复核报告必须全新")
            bundle = guarded(args.bundle)
            require(not output.is_relative_to(bundle), "复核报告不能写入原始bundle")
            report.update(verify_bundle(bundle, args.manifest_sha256))
    except (AptInputError, OSError, ValueError, KeyError, TypeError, StopIteration, subprocess.SubprocessError) as error:
        report["errors"].append(str(error))
    if output is not None:
        try:
            write_json(output, report)
        except (AptInputError, OSError) as error:
            report["result"] = "failed"
            report["errors"].append(str(error))
    print("[RenPyAptInputs] " + ("通过；仅APT分发采集/字节复核，未安装或构建" if report["result"] == "passed"
                               else "失败：" + "; ".join(report["errors"])), flush=True)
    if report["result"] == "passed" and "manifest_sha256" in report:
        print("[RenPyAptInputs] manifest_sha256=" + report["manifest_sha256"], flush=True)
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
