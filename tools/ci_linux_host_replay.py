#!/usr/bin/env python3
"""只运输固定 H0 输入并调用冻结原入口；密钥、临时归档和 SDK 不进入公开产物或容器。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import types
import urllib.parse
import urllib.request


DEFAULT_PLAN = Path(__file__).with_name("linux-host-replay-ci-plan.json")
H0_TOOL_SHA256 = "7946c3eb9271263473aecf02ba7dcf48ffc24bd4a2e889cb5185921eb61ddddc"
H0_PLAN_SHA256 = "d7b7288a524ad73cd645c20ba7342586bb00da6a837f43d34a5894496005178d"
SECRET_ENV = "REKO_H0_INPUTS_PASSWORD"
RELEASE_URL = "https://github.com/Leo008/renpy-build/releases/download/ci-inputs-8.5.3-20261008/h0-linux-host-inputs-20261102-01.tar.gz.enc"
TRANSPORT = {
    "url": RELEASE_URL,
    "ciphertext": {"bytes": 116556720, "sha256": "4beeb8544d248c59f7f12216cd11a8d291d0d4edcf660eb854fbc4abcb1b34c5"},
    "plaintext": {"bytes": 116556690, "sha256": "3d33a763aed626af50ab56e7ea07904e3930e26e871bb12a8ed81fd15a3f280a"},
    "encryption": {"cipher": "aes-256-cbc", "kdf": "pbkdf2", "digest": "sha256", "iterations": 200000, "salt_bytes": 8},
    "archive": "ustar-103-regular-mode0644-uid0-gid0-mtime0",
}


class TransportError(ValueError):
    """只携带固定公开错误，避免网络异常或 OpenSSL 输出泄露临时地址/密码。"""


def require(value, message):
    """任何真实输入或阶段条件不足立即失败。"""
    if not value:
        raise TransportError(message)


def log(message):
    """统一输出公开阶段，不输出环境、密码或带查询的重定向。"""
    print("[RenPyCIHostReplay] " + message, flush=True)


def guarded(path):
    """拒绝点段与任意层链接，限定实际普通目录/文件。"""
    path = Path(path)
    require(".." not in path.parts, "路径包含父目录点段")
    path = path.absolute()
    require(not any(p.is_symlink() for p in [path, *path.parents]), "路径包含符号链接")
    return path


def unique(pairs):
    """拒绝 JSON 重复键覆写验收含义。"""
    result = {}
    for key, value in pairs:
        require(key not in result, "JSON字段重复")
        result[key] = value
    return result


def read_json(path):
    """只读取有界普通 JSON，不接受特殊设备或非标准数值。"""
    raw = read_regular(path, 1024**2)
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(TransportError("JSON数值非法")))


def read_regular(path, maximum):
    """不阻塞打开有界普通原件，不沿链接或读取特殊设备。"""
    path = guarded(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, "输入不是有界普通文件")
        raw = stream.read(maximum + 1)
        require(len(raw) == info.st_size, "输入读取期间改变")
    return raw


def write_json(path, value):
    """独占写公开报告，禁止覆盖前次证据。"""
    with guarded(path).open("x") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def verify_bytes(path, identity):
    """完整重算固定长度与 SHA，不沿链接、不信任 stat 缓存。"""
    require(set(identity) == {"bytes", "sha256"} and type(identity["bytes"]) is int and identity["bytes"] > 0
            and isinstance(identity["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", identity["sha256"]), "字节身份非法")
    with os.fdopen(os.open(guarded(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size == identity["bytes"], "实际长度或文件类型不符")
        sha = hashlib.sha256();count = 0
        while block := stream.read(1024**2):
            count += len(block);require(count <= identity["bytes"], "实际长度超出锁定身份");sha.update(block)
    require(count == identity["bytes"] and sha.hexdigest() == identity["sha256"], "实际完整摘要不符")


def load_plan(path):
    """计划必须精确绑定批准附件及冻结 H0 原件，不接纳任意 URL/命令/输入范围。"""
    plan = read_json(path)
    require(set(plan) == {"schema_version", "task", "scope", "h0_tool_sha256", "h0_plan_sha256", "transport", "limitations"}
            and type(plan["schema_version"]) is int and plan["schema_version"] == 1
            and plan["task"] == "R00-02J2C-H0-CI" and plan["scope"] == "fixed_host_transport_and_four_frontend_scopes_only"
            and plan["h0_tool_sha256"] == H0_TOOL_SHA256 and plan["h0_plan_sha256"] == H0_PLAN_SHA256
            and plan["transport"] == TRANSPORT, "CI计划不符合固定批准身份")
    encryption = plan["transport"]["encryption"]
    require(type(encryption["iterations"]) is int and type(encryption["salt_bytes"]) is int
            and all(type(plan["transport"][key]["bytes"]) is int for key in ("ciphertext", "plaintext")), "CI数字字段不能为布尔值")
    require(isinstance(plan["limitations"], list) and plan["limitations"] and all(isinstance(v, str) and v for v in plan["limitations"]), "CI计划缺少范围边界")
    return plan


def validate_url(url, initial):
    """初始地址固定；后续仅允许 GitHub 原址或已知 release-assets HTTPS 域。"""
    require(isinstance(url, str) and not any(ord(c) < 33 or ord(c) == 127 for c in url), "附件地址包含非法字符")
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.username is None and parsed.password is None and parsed.port is None
            and not parsed.fragment and parsed.path.startswith("/"), "附件地址不是受控HTTPS")
    require(url == initial or parsed.hostname == "release-assets.githubusercontent.com", "附件重定向域未批准")


class ReleaseRedirects(urllib.request.HTTPRedirectHandler):
    """在请求发出前阻止降级、凭据与未知域跳转。"""

    def __init__(self, initial):
        """绑定本次唯一公开 release URL。"""
        self.initial = initial
        super().__init__()

    def redirect_request(self, request, fp, code, message, headers, newurl):
        """逐跳检查实际下一地址，不记录临时签名查询。"""
        validate_url(newurl, self.initial)
        return super().redirect_request(request, fp, code, message, headers, newurl)


def download(transport, target):
    """仅宿主下载固定附件；流式限制完整密文，坏字节或网络错误均失败。"""
    initial = transport["url"];validate_url(initial, RELEASE_URL)
    require(initial == RELEASE_URL, "初始下载地址不是固定发布附件")
    identity = transport["ciphertext"]
    try:
        opener = urllib.request.build_opener(ReleaseRedirects(initial))
        request = urllib.request.Request(initial, headers={"Accept-Encoding": "identity", "User-Agent": "Reko-H0-Transport/1"})
        with opener.open(request, timeout=60) as response, guarded(target).open("xb") as stream:
            validate_url(response.url, initial)
            require(response.status == 200 and response.headers.get("Content-Encoding", "identity").lower() == "identity", "附件响应状态或编码错误")
            require(response.headers.get("Content-Length") in (None, str(identity["bytes"])), "密文响应长度错误")
            count = 0;header = b"";sha = hashlib.sha256();deadline = time.monotonic() + 600
            while block := response.read(256 * 1024):
                require(time.monotonic() <= deadline, "固定附件下载超过总时限")
                count += len(block);require(count <= identity["bytes"], "密文响应超长")
                header = (header + block)[:8];sha.update(block);stream.write(block)
        require(count == identity["bytes"] and sha.hexdigest() == identity["sha256"] and header == b"Salted__", "密文完整身份或salt头错误")
    except TransportError:
        raise
    except Exception:
        raise TransportError("固定发布附件下载失败") from None


def decrypt(ciphertext, plaintext, transport, password):
    """以 stdin 单独传密码；使用空白受控环境，固定 AES/PBKDF2 参数，不存盘或输出诊断。"""
    require(isinstance(password, str) and 0 < len(password) <= 8192 and not any(c in password for c in "\r\n\0"), "缺少有效H0运输密钥")
    verify_bytes(ciphertext, transport["ciphertext"])
    executable = shutil.which("openssl");require(executable is not None, "缺少OpenSSL")
    plaintext = guarded(plaintext);require(not plaintext.exists(), "解密目标已存在")
    environment = {"LANG": "C", "LC_ALL": "C"}
    try:
        help_result = subprocess.run([executable, "enc", "-help"], capture_output=True, timeout=30, env=environment)
        command = [executable, "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-md", "sha256",
                   "-pass", "stdin", "-in", str(ciphertext), "-out", str(plaintext)]
        if b"-saltlen" in help_result.stdout + help_result.stderr:
            command += ["-saltlen", "8"]
        result = subprocess.run(command, input=password.encode("utf-8") + b"\n", capture_output=True, timeout=180, env=environment)
        require(result.returncode == 0, "固定H0归档解密失败")
        verify_bytes(plaintext, transport["plaintext"])
    except TransportError:
        raise
    except Exception:
        raise TransportError("固定H0归档解密失败") from None


def extract_payload(archive, destination, catalog):
    """只逐字节写精确 catalog 普通文件，不调用 extractall、不接受链接/额外目录/重复项。"""
    destination = guarded(destination);require(not destination.exists(), "输入解包目录已存在")
    expected = {row["path"]: row for row in catalog}
    require(len(expected) == len(catalog) and all(isinstance(name, str) and not name.startswith("/") and "\\" not in name
            and all(part not in ("", ".", "..", ".git") for part in name.split("/")) for name in expected), "解包清单路径非法或重复")
    with guarded(archive).open("rb") as stream, tarfile.open(fileobj=stream, mode="r:gz") as bundle:
        members = [];seen = set()
        for member in bundle:
            require(len(members) < len(expected), "归档成员数超出固定清单")
            require(member.name in expected and member.name not in seen and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                    and not member.pax_headers and member.mode == 0o644 and member.uid == member.gid == member.mtime == 0
                    and member.size == expected[member.name]["bytes"], "归档含额外/重复/链接/非法成员")
            seen.add(member.name)
            members.append(member)
        require(seen == set(expected), "归档缺少固定输入")
        destination.mkdir(mode=0o700)
        for member in members:
            target = guarded(destination / member.name);target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member);require(source is not None, "归档普通成员不可读")
            sha = hashlib.sha256();count = 0
            with source, target.open("xb") as output:
                while block := source.read(256 * 1024):
                    count += len(block);require(count <= member.size, "归档成员超出锁定长度");sha.update(block);output.write(block)
            require(count == member.size and sha.hexdigest() == expected[member.name]["sha256"], "归档成员完整身份不符")


def load_h0():
    """直接编译同目录已验冻结原件，不导入旧 pyc 或可替换同名模块。"""
    path = guarded(Path(__file__).with_name("run_linux_python_replay.py"))
    raw = read_regular(path, 128 * 1024)
    require(hashlib.sha256(raw).hexdigest() == H0_TOOL_SHA256, "冻结H0原入口SHA错误")
    module = types.ModuleType("reko_ci_frozen_h0");module.__file__ = str(path);module.__package__ = ""
    exec(compile(raw, str(path), "exec"), module.__dict__)
    plan_path = path.with_name("python-linux-host-replay-plan.json")
    plan = module.load_plan(plan_path, H0_PLAN_SHA256)
    return module, plan, plan_path


def main(argv=None):
    """宿主固定运输→完整门禁→冻结H0原CLI；CLI不提供任意执行器或后置钩子。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ubuntu", choices=("22.04", "24.04"), required=True)
    parser.add_argument("--bundle", type=Path, required=True);parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    password = os.environ.pop(SECRET_ENV, None)
    report = {"task": "R00-02J2C-H0-CI", "scope": "fixed_host_transport_and_four_frontend_scopes_only", "result": "failed",
              "ubuntu": args.ubuntu, "errors": [], "ciphertext_verified": False, "plaintext_verified": False,
              "payload_verified": False, "private_inputs_removed": False, "H0_group_complete": False, "J2C_complete": False,
              "ios_runtime_verified": False, "sdk_inputs_consumed": False, "secret_sent_to_container": False}
    created = False;private = None
    try:
        args.output, args.bundle = guarded(args.output), guarded(args.bundle)
        require(not args.output.exists() and args.output.parent.is_dir() and not args.output.is_relative_to(args.bundle)
                and not args.bundle.is_relative_to(args.output), "输出必须全新且与APT输入分离")
        args.output.mkdir();created = True
        require(sys.platform == "linux" and platform.machine() in ("x86_64", "amd64"), "实际H0需要Linux amd64与Docker")
        plan = load_plan(DEFAULT_PLAN);h0, h0_plan, h0_plan_path = load_h0()
        require(isinstance(password, str) and password, "缺少H0运输密钥")
        temporary_root = guarded(os.environ.get("RUNNER_TEMP", ""))
        require(os.environ.get("RUNNER_TEMP") and temporary_root.is_dir() and not temporary_root.is_relative_to(args.output)
                and not temporary_root.is_relative_to(args.bundle), "缺少独立RUNNER_TEMP目录")
        checkout = os.environ.get("GITHUB_WORKSPACE")
        require(not checkout or not temporary_root.is_relative_to(guarded(checkout)), "临时材料不能位于checkout内")
        with tempfile.TemporaryDirectory(prefix="reko-h0-transport-", dir=temporary_root) as temporary:
            private = Path(temporary);os.chmod(private, 0o700)
            encrypted, plaintext, payload = private / "inputs.enc", private / "inputs.tar.gz", private / "payload"
            log("下载固定加密输入")
            download(plan["transport"], encrypted);report["ciphertext_verified"] = True
            decrypt(encrypted, plaintext, plan["transport"], password);password = None
            report["plaintext_verified"] = True
            log("核验并解包103个固定普通成员")
            extract_payload(plaintext, payload, h0_plan["files"])
            plaintext.unlink();encrypted.unlink()
            h0.verify_files(payload, h0_plan["files"]);report["payload_verified"] = True
            report.update(transport=TRANSPORT, h0_tool_sha256=H0_TOOL_SHA256, h0_plan_sha256=H0_PLAN_SHA256, payload_file_count=103)
            log("启动冻结H0原入口，等待真实Linux重放结果")
            code = h0.main(["run", "--plan", str(h0_plan_path), "--plan-sha256", H0_PLAN_SHA256,
                            "--payload", str(payload), "--bundle", str(args.bundle), "--ubuntu", args.ubuntu, "--output", str(args.output / "h0")])
            result = read_json(args.output / "h0/report.json")
            require(code == 0 and result["result"] == "selected_host_group_offline_replayed" and result["H0_group_complete"] is True
                    and result["container_closed"] is True and result["J2C_complete"] is False and result["ios_runtime_verified"] is False,
                    "冻结H0真实重放未完成")
        require(not private.exists(), "私有输入清理未完成")
        report.update(result="fixed_input_transported_and_selected_host_group_replayed", H0_group_complete=True)
    except TransportError as error:
        report["result"] = "failed"
        report["errors"].append(str(error))
    except Exception as error:
        report["result"] = "failed"
        report["errors"].append("固定CI入口失败：" + type(error).__name__)
    finally:
        password = None
        report["private_inputs_removed"] = private is not None and not private.exists()
        if report["result"] == "failed":
            report["H0_group_complete"] = False
        if created:
            write_json(args.output / "transport-report.json", report)
    log("结果=" + report["result"] + "；" + "; ".join(report["errors"]))
    return 0 if report["result"] != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
