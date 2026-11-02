#!/usr/bin/env python3
"""以已验 J2C Linux 前端执行两项原 hostpython Task；不依赖引擎、Apple SDK 或目标 pip。"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import site
import stat
import struct
import subprocess
import sys
import tarfile


HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[1]
DEFAULT_PLAN = HERE / "host-python-bootstrap-plan.json"
PLAN_SHA256 = "352f7af5dbd7f31d6199f1d6b536a99405cf249c7969cbfd69260a455c6b84e0"
SCOPE = "four_approved_routes_original_hostpython_tasks_and_explicit_legacy_native_ssl_candidate"
VERSIONS = {"8.5.3": "3.12.8", "8.4.1": "3.12.8", "8.3.7": "3.9.10", "7.8.7": "2.7.18"}
PRODUCT_PROBE = r'''import sys,os,json,platform,hashlib,ssl,zlib,bz2,ctypes,sysconfig
modules=['_ssl','_hashlib','hashlib','zlib','bz2','_ctypes','ctypes','json','encodings']
if sys.version_info[0]==3:
 import lzma
 assert lzma.decompress(lzma.compress(b'reko-host'))==b'reko-host'
 modules+=['_lzma','lzma']
assert hashlib.sha256(b'reko-host').hexdigest()=='decfbb5c7f809f3d23a1717633e2c564dde2d4f8ecc0c9f9131d242eac2e241d'
assert zlib.decompress(zlib.compress(b'reko-host'))==b'reko-host'
assert bz2.decompress(bz2.compress(b'reko-host'))==b'reko-host'
assert ctypes.sizeof(ctypes.c_void_p)==8
records=[]
for name in modules:
 m=__import__(name);records.append({'name':name,'file':getattr(m,'__file__',None),'builtin':name in sys.builtin_module_names})
print(json.dumps({'version':platform.python_version(),'implementation':platform.python_implementation(),'platform':sys.platform,
 'machine':platform.machine(),'prefix':sys.prefix,'executable':sys.executable,'stdlib':sysconfig.get_path('stdlib'),
 'openssl':ssl.OPENSSL_VERSION,'modules':records,'functional_probes_passed':True}))
'''


def require(condition, message):
    """缺少真实证明即拒绝，不把 fixture 或延期执行计为通过。"""
    if not condition:
        raise ValueError(message)


def sha(data):
    """计算实际原字节 SHA256。"""
    return hashlib.sha256(data).hexdigest()


def no_links(path):
    """拒绝祖先软链接和词法上跳，不用 resolve 掩盖输入路径变更。"""
    require(path.is_absolute() and ".." not in path.parts, "须提供无上跳的绝对路径")
    require(not any(item.is_symlink() for item in (path, *path.parents)), "输入路径含链接：" + str(path))


def raw_file(path, maximum=64 * 1024**2):
    """读取有界普通文件，真实程序链接须先显式解析再调用。"""
    no_links(path)
    require(path.is_file() and stat.S_ISREG(path.lstat().st_mode) and path.stat().st_size <= maximum, "普通文件缺失/超限：" + str(path))
    data = path.read_bytes()
    require(len(data) <= maximum, "读取期间文件超限")
    return data


def unique(rows):
    """拒绝 JSON 重复字段。"""
    result = {}
    for key, value in rows:
        require(key not in result, "JSON 字段重复")
        result[key] = value
    return result


def parse_json(data):
    """拒绝非有限值和多义 JSON。"""
    return json.loads(data, object_pairs_hook=unique, parse_constant=lambda _: require(False, "JSON 非有限数值"))


def checked_json(path, expected, maximum=64 * 1024**2):
    """先核独立 SHA，再读取输入契约。"""
    data = raw_file(path, maximum)
    require(re.fullmatch("[0-9a-f]{64}", expected or "") and sha(data) == expected, "SHA256 与原件不符：" + str(path))
    return parse_json(data)


def write_new(path, value):
    """不覆盖历史收据或失败报告。"""
    no_links(path)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def load_plan(path=DEFAULT_PLAN):
    """独立锚定四路线、原任务投影及实际 J1/J2/J4 工具字节，不要求 J7 输入。"""
    plan = checked_json(path, PLAN_SHA256, 1024 * 1024)
    require(set(plan) == {"schema_version", "scope", "dependencies", "locks", "routes", "limitations"}
            and plan["schema_version"] == 1 and type(plan["schema_version"]) is int and plan["scope"] == SCOPE,
            "host bootstrap 计划范围错误")
    require(len(plan["routes"]) == 4 and {r["release"] for r in plan["routes"]} == set(VERSIONS), "必须固定四条路线")
    for row in plan["routes"]:
        require(row["version"] == VERSIONS[row["release"]] and row["python"] == row["version"].split(".")[0]
                and len(row["tasks"]) == 1 and len(row["tasks"][0]["steps"]) == 2
                and [x["task"] for x in row["tasks"][0]["steps"]] == ["unpack_hostpython", "build_host"], "原 host 任务/版本错误")
        require((row["legacy_ssl_candidate"] is not None) == (row["release"] == "7.8.7"), "legacy host SSL 候选范围错误")
    for name, expected in {**plan["dependencies"], **plan["locks"]}.items():
        require(Path(name).name == name and name not in ("", ".", ".."), "依赖名称错误")
        require(sha(raw_file(HERE / name)) == expected, "固定依赖字节改变：" + name)
    return plan


def command(argv, *, cwd=None, env=None, timeout=120):
    """直接 argv 执行真实程序，完整记录返回码，失败不回退联网或忽略退出。"""
    result = subprocess.run([str(x) for x in argv], cwd=cwd, env=env, capture_output=True, timeout=timeout)
    require(result.returncode == 0, "命令失败：" + str(argv[0]) + " rc=" + str(result.returncode) + " " + result.stderr.decode(errors="replace")[:2000])
    return result.stdout


def frontend_receipt(args, plan, row):
    """重验 J2C 对应 host scope 的真实前端、完整 wheel/RECORD 和当前 venv 来源。"""
    require(args.frontend_report is not None and args.frontend_report_sha256, "缺少强制 J2C host 前端收据及 SHA")
    report = checked_json(args.frontend_report, args.frontend_report_sha256, 16 * 1024**2)
    require(report.get("task") == "R00-02J2C1" and report.get("command") == "replay"
            and report.get("status") in ("all_scopes_offline_replayed", "incomplete_scopes_not_run")
            and report.get("plan_sha256") == plan["locks"]["python-replay-plan.json"]
            and report.get("j2a_manifest_sha256") == plan["locks"]["python-inputs.lock.json"], "J2C 前端收据范围/原锁不符")
    scopes = [scope for scope in report.get("scopes", []) if scope.get("id") == row["frontend_scope"]]
    require(len(scopes) == 1 and scopes[0].get("status") == "offline_replayed", "相应 host scope 未真实重放通过")
    scope = scopes[0]
    require(scope.get("network_isolation", {}).get("kernel_network_isolation_verified") is True, "J2C 缺真实内核隔离证明")
    identity = scope["interpreter"]
    runtime = identity["runtime"]
    require(runtime["platform"] == "linux" and runtime["machine"] == "x86_64" and runtime["implementation"] == "CPython"
            and runtime["version"].split(".")[:2] == row["frontend_minor"].split("."), "J2C 前端不是批准的 Linux CPython minor")
    require(sys.platform == "linux" and platform.machine() == "x86_64" and platform.python_implementation() == "CPython"
            and platform.python_version() == runtime["version"], "当前前端实际平台/版本与 J2C 不符")
    executable = Path(sys.executable).absolute()
    actual_executable = executable.resolve(strict=True)
    require(sha(raw_file(actual_executable)) == identity["sha256"] and actual_executable.stat().st_size == identity["size"]
            and sha(raw_file(Path(identity["realpath"]))) == identity["sha256"], "当前或原始解释器 binary 身份改变")
    environment = scope["environment"]
    prefix = Path(environment["prefix"])
    no_links(prefix)
    require(Path(sys.prefix) == prefix and executable == prefix / "bin/python"
            and environment["user"] is False and environment["pip"] is False, "必须从原 J2C 独立前端 venv/bin/python 执行")
    replay = importlib.import_module("replay_python_inputs")
    replay_plan, builder, manifest, fingerprint = replay.load_plan(HERE / "python-replay-plan.json")
    require(fingerprint == plan["locks"]["python-replay-plan.json"], "J2C 重读计划身份改变")
    parser = replay.inputs.load_parser(args.source_cache, manifest)
    records = report.get("build_receipts", [])
    products, _ = replay.read_build_receipts([Path(value["path"]) for value in records], [value["sha256"] for value in records],
                                            builder, manifest, args.source_cache, args.tool_cache, parser)
    source_scope = next(value for value in manifest["scopes"] if value["id"] == row["frontend_scope"])
    wheels, missing, _ = replay.resolve_scope(source_scope, manifest, args.source_cache, products, parser)
    require(not missing, "J2C 源 wheel 收据缺失")
    sites = environment["sites"]
    require(sites and sites == site.getsitepackages() and site.ENABLE_USER_SITE is False
            and all(".." not in Path(value).parts and Path(value).is_relative_to(prefix) for value in sites),
            "J2C 全部实际 site 路径/用户 site 状态改变")
    installed = replay.verify_installed(wheels, Path(sites[0]), prefix)
    require(installed == scope["installed"], "J2C 实际安装 payload/RECORD 改变")
    contract = next(value for value in replay_plan["scopes"] if value["id"] == row["frontend_scope"])
    probe_contract = {"modules": contract["modules"], "resources": [{"kind": "certifi_ca_bundle"}], "smoke": contract["smoke"]}
    probe = parse_json(command([executable, "-I", "-B", "-X", "pycache_prefix=" + str(args.output / "unused-frontend-probe-pycache"),
                                "-c", replay.PROBE, json.dumps(probe_contract)]))
    require(not probe["errors"] and len(probe["modules"]) == len(contract["modules"]), "J2C 前端模块复查失败")
    for module in probe["modules"]:
        original = next(value for value in scope["probe"]["modules"] if value["module"] == module["module"])
        require(module == original, "当前前端模块 origin/version 与原收据不同")
    require(probe["resources"] == scope["probe"]["resources"] and probe["smoke"] == scope["probe"]["smoke"], "J2C 资源/功能复查与收据不同")
    return {"path": str(args.frontend_report), "sha256": args.frontend_report_sha256, "scope": row["frontend_scope"],
            "executable": str(executable), "interpreter_sha256": identity["sha256"], "prefix": str(prefix),
            "installed_payloads_reverified": len(installed), "linux_frontend_verified": True}


def elf_identity(data):
    """只接纳原生 Linux x86_64 ELF64，小端 ABI；Mach-O/ARM/截断文件明确拒绝。"""
    require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", "产物不是 ELF64 little-endian")
    kind, machine = struct.unpack_from("<HH", data, 16)
    require(kind in (1, 2, 3) and machine == 62 and struct.unpack_from("<I", data, 20)[0] == 1, "ELF 不是原生 x86_64")
    return {"class": 64, "endian": "little", "machine": machine, "type": kind}


def ar_identity(data):
    """逐一核验普通静态 archive 的真实 ELF64 对象，拒绝 thin 外部引用或 Mach-O/ARM 成员。"""
    require(data.startswith(b"!<arch>\n"), "host 静态库不是完整普通 archive")
    position, count = 8, 0
    while position < len(data):
        require(position + 60 <= len(data), "archive 成员头截断")
        header = data[position:position + 60]
        require(header[58:60] == b"`\n", "archive 成员头非法")
        size = int(header[48:58].decode("ascii").strip())
        require(size >= 0 and position + 60 + size <= len(data), "archive 成员长度非法")
        name = header[:16].decode("ascii").strip()
        body = data[position + 60:position + 60 + size]
        if name.startswith("#1/"):
            length = int(name[3:])
            require(0 < length <= len(body), "BSD archive 名称长度非法")
            name, body = body[:length].decode("utf-8").rstrip("\0"), body[length:]
        if name not in ("/", "//", "/SYM64/") and not name.startswith("__.SYMDEF"):
            require(elf_identity(body)["type"] == 1, "静态库成员不是 native relocatable ELF")
            count += 1
        position += 60 + size + (size % 2)
    require(position == len(data) and count > 0, "archive 没有完整 native 对象")
    return {"member_count": count, "native_machine": 62, "thin": False}


def archive_members(path, descriptor):
    """核验 J1 原包并完整读取成员；实际四个固定原包没有链接、特殊成员或重复路径。"""
    data = raw_file(path)
    require(len(data) == descriptor["size"] and sha(data) == descriptor["sha256"], "J1 host 原包字节不符")
    found = {}
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            name = member.name.rstrip("/")
            require(name and not name.startswith("/") and "\\" not in name
                    and all(part not in ("", ".", "..") for part in name.split("/"))
                    and (name == descriptor["root"] or name.startswith(descriptor["root"] + "/"))
                    and name not in found and (member.isfile() or member.isdir()), "原包成员路径/类型/重复错误")
            found[name] = {"directory": member.isdir(), "mode": "100755" if member.mode & 0o111 else "100644"}
            if member.isfile():
                body = archive.extractfile(member).read()
                found[name].update(bytes=len(body), sha256=sha(body))
    require(found and descriptor["root"] in found, "原包根缺失")
    return found


def verify_extracted(build, members):
    """原 unpack Task 完成后逐成员对照完整解包字节及执行模式。"""
    roots = {name.split("/", 1)[0] for name in members}
    require(len(roots) == 1, "原包展开根不唯一")
    observed = set()
    for current, directories, files in os.walk(build / next(iter(roots)), followlinks=False):
        current = Path(current)
        observed.add(current.relative_to(build).as_posix())
        for name in directories + files:
            path = current / name
            require(not path.is_symlink(), "原 unpack 意外出现链接")
            observed.add(path.relative_to(build).as_posix())
    require(observed == set(members), "原 unpack 完整树存在缺失或额外成员")
    for name, item in members.items():
        path = build / name
        no_links(path)
        if item["directory"]:
            require(path.is_dir(), "原 unpack 缺少目录：" + name)
        else:
            raw = raw_file(path)
            require(len(raw) == item["bytes"] and sha(raw) == item["sha256"]
                    and bool(path.stat().st_mode & 0o111) == (item["mode"] == "100755"), "原 unpack 字节/模式错误：" + name)


def package_key(name, architecture):
    """两侧共用严格 package+arch 键；多架构后缀必须等于单独记录的架构。"""
    require(isinstance(name, str) and isinstance(architecture, str)
            and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", architecture) is not None, "dpkg 架构字段非法")
    parts = name.split(":")
    require(len(parts) in (1, 2) and re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", parts[0]) is not None,
            "dpkg 包名非法")
    require(len(parts) == 1 or parts[1] == architecture, "dpkg 包名后缀与显式架构不符")
    return parts[0], architecture


def package_version(value):
    """保留原版本 token，不接受空值、空白或控制字符。"""
    require(isinstance(value, str) and value and not any(char.isspace() or ord(char) < 33 or ord(char) == 127 for char in value),
            "dpkg 版本字段非法")
    return value


def approved_packages(group):
    """分别拒绝 base/必要包的规范键重复，再按已锁必要包更新同键版本。"""
    tables = []
    for label in ("base_packages", "packages"):
        require(isinstance(group[label], list) and group[label], "批准 APT 包集合为空或格式错误")
        table = {}
        for row in group[label]:
            key = package_key(row["package"], row["architecture"])
            require(key not in table, "批准 APT 包规范键重复")
            if label == "base_packages" or "status" in row:
                require(row.get("status") == "ii ", "批准 APT base/包不是完整 ii 状态")
            table[key] = package_version(row["version"])
        tables.append(table)
    expected = dict(tables[0])
    expected.update(tables[1])
    return expected


def installed_packages(stdout):
    """严格解析每条完整 ii 记录，保留显式架构；不丢弃非 ii 项或静默归并重复别名。"""
    result = {}
    for line in stdout.decode().splitlines():
        fields = line.split("\t")
        require(len(fields) == 4, "dpkg 包记录必须是完整四列")
        name, version, arch, status_text = fields
        require(status_text == "ii ", "dpkg 包不是完整 ii 状态")
        key = package_key(name, arch)
        require(key not in result, "dpkg 包规范键重复")
        result[key] = package_version(version)
    require(result, "实际 dpkg 包集合为空")
    return result


def verify_packages(stdout, group):
    """精确比较完整集合/版本/架构；失败仅输出固定字段、各前八项及总数的有界差异。"""
    observed, expected = installed_packages(stdout), approved_packages(group)
    if observed != expected:
        missing = sorted(expected.keys() - observed.keys())
        extra = sorted(observed.keys() - expected.keys())
        changed = sorted(key for key in expected.keys() & observed.keys() if expected[key] != observed[key])
        expected_arches, actual_arches = {}, {}
        for name, arch in expected:
            expected_arches.setdefault(name, set()).add(arch)
        for name, arch in observed:
            actual_arches.setdefault(name, set()).add(arch)
        architectures = sorted(name for name in expected_arches.keys() & actual_arches.keys()
                               if expected_arches[name] != actual_arches[name])
        differences = {
            "missing": {"count": len(missing), "items": [{"package": name[:128], "architecture": arch[:64], "expected_version": expected[name, arch][:128]}
                                                          for name, arch in missing[:8]]},
            "extra": {"count": len(extra), "items": [{"package": name[:128], "architecture": arch[:64], "actual_version": observed[name, arch][:128]}
                                                      for name, arch in extra[:8]]},
            "versions": {"count": len(changed), "items": [{"package": name[:128], "architecture": arch[:64], "expected": expected[name, arch][:128],
                                                           "actual": observed[name, arch][:128]} for name, arch in changed[:8]]},
            "architectures": {"count": len(architectures), "items": [{"package": name[:128], "expected_count": len(expected_arches[name]),
                "actual_count": len(actual_arches[name]), "expected": [arch[:64] for arch in sorted(expected_arches[name])[:8]],
                "actual": [arch[:64] for arch in sorted(actual_arches[name])[:8]]} for name in architectures[:8]]},
        }
        raise ValueError("实际 dpkg 完整集合/版本与批准 APT 候选不同；差异=" + json.dumps(differences, ensure_ascii=False, separators=(",", ":")))
    return observed


def native_environment(plan, row, output):
    """只验证 Linux 已装 APT 和 native LLVM，不解包或读取 Apple SDK。"""
    os_release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    require(os_release.get("ID", "").strip('"') == "ubuntu" and os_release.get("VERSION_ID", "").strip('"') == row["ubuntu"], "不是批准的 Ubuntu 路线")
    apt = checked_json(HERE / "apt-inputs.lock.json", plan["locks"]["apt-inputs.lock.json"])
    group = next(value for value in apt["groups"] if value["ubuntu"] == row["ubuntu"])
    observed = verify_packages(command(["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n"]), group)
    print("[RenPyHostPython] 实际 installed 包数=" + str(len(observed)), flush=True)
    environment = checked_json(HERE / "environment-preflight.lock.json", plan["locks"]["environment-preflight.lock.json"])
    native = next(value for value in environment["groups"] if value["ubuntu"] == row["ubuntu"])
    tools = {}
    for name, identity in native["tool_identities"].items():
        if name.startswith(("clang-", "clang++-", "llvm-ar-", "llvm-nm-")):
            path = Path(identity["path"])
            require(sha(raw_file(path)) == identity["sha256"], "native LLVM 原字节不符：" + name)
            elf_identity(raw_file(path))
            tools[name] = identity
    return {"ubuntu": row["ubuntu"], "installed_package_count": len(observed),
            "installed_projection_sha256": sha(json.dumps(sorted((name, arch, version) for (name, arch), version in observed.items())).encode()),
            "native_tools": tools, "apple_sdk_required": False}


def audited_context(original, row, workspace, events, journal=None):
    """仅添加路径与命令观察，所有原 body、Task.run 与实际 Context 操作仍执行上游实现。"""
    specifications = {item["name"]: item for item in row["tasks"]}
    legacy = row["legacy_ssl_candidate"]
    if legacy:
        specifications.update({item["name"]: item for item in legacy["tasks"]})

    class AuditedHostContext(original.Context):
        """原 Context 的窄审计子类，不改注册 Task.kind 或原函数体。"""

        def set_names(self, kind, task, name):
            """在任何原任务函数执行前绑定完整 native host 路径。"""
            super().set_names(kind, task, name)
            require(name in specifications and task in ("unpack_hostpython", "build_host", "unpack", "build"), "非批准 host Task")
            require(kind == "host" and self.platform == "host" and self.arch == "host" and self.python == row["python"]
                    and self.root == workspace and self.tmp == workspace / "tmp"
                    and self.build == workspace / "tmp/build" / (name + ".host")
                    and self.install == workspace / "tmp/host" and self.cwd == self.build
                    and self.path("{{ host }}") == self.install, "原 host Context 路径/ABI 不符")
            self.audit_spec = next(item for item in specifications[name]["steps"] if item["task"] == task)
            self.audit_archive = legacy["archive"] if name == "openssl_host_bootstrap" else row["python_archive"]
            self.audit_commands = 0

        def path(self, value):
            """保留真实模板展开，所有 Context 路径必须位于独立配方根内。"""
            path = super().path(value)
            require(path.is_absolute() and ".." not in path.parts and path.is_relative_to(workspace), "host Context.path 逃逸")
            no_links(path)
            return path

        def run(self, template, verbose=False, quiet=False, **kwargs):
            """固定原 run 模板顺序，记录展开 argv/cwd/env 并委托真实原 Context.run。"""
            commands = self.audit_spec["commands"]
            require(self.audit_commands < len(commands) and template == commands[self.audit_commands]
                    and not kwargs, "出现未知 host 命令或顺序变化")
            require(self.tmp == workspace / "tmp" and self.build == workspace / "tmp/build" / (self.name + ".host")
                    and self.install == workspace / "tmp/host" and self.platform == "host" and self.arch == "host",
                    "执行时 host Context 路径/ABI 改变")
            expected_cwd = self.build if self.task in ("unpack", "unpack_hostpython") else self.build / self.audit_archive["root"]
            require(self.cwd == expected_cwd and self.path("{{ source }}") == workspace / "source"
                    and self.path("{{ build }}") == self.build and self.path("{{ host }}") == self.install
                    and self.path("{{ install }}") == self.install, "执行时实际模板路径/cwd 不符")
            expanded = self.expand(template)
            event = {"task_name": self.task_name, "template": template, "argv": shlex.split(expanded), "cwd": str(self.cwd),
                     "environment": {key: self.environ[key] for key in ("CC", "CXX", "CFLAGS", "CPPFLAGS", "LDFLAGS", "AR", "RANLIB", "PATH")},
                     "returncode": None}
            events.append(event)
            if journal is not None:
                with journal.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps({"phase": "start", **event}, ensure_ascii=False) + "\n")
            try:
                super().run(template, verbose=verbose, quiet=quiet)
                event["returncode"] = 0
            except SystemExit as error:
                event["returncode"] = error.code
                if journal is not None:
                    with journal.open("a", encoding="utf-8") as stream:
                        stream.write(json.dumps({"phase": "exit", **event}, ensure_ascii=False) + "\n")
                raise
            if journal is not None:
                with journal.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps({"phase": "exit", **event}, ensure_ascii=False) + "\n")
            self.audit_commands += 1

        def clean(self, value="{{build}}"):
            """原 unpack 只能清理自身已绑定 build 目录，拒绝先删除其他目录再报错。"""
            expected = workspace / "tmp/build" / (self.name + ".host")
            require(value == "{{build}}" and self.build == expected and self.path(value) == expected, "host clean 目标不符")
            super().clean(value)

        def chdir(self, value):
            """原函数只能进入对应原源码包根目录。"""
            require(self.path(value) == self.build / self.audit_archive["root"], "host chdir 目的目录不符")
            super().chdir(value)

        def generate(self, source, destination, **kwargs):
            """只用 J1 原模板生成当前源码 Modules 下的原 Setup 文件。"""
            descriptor = row["setup_template"]
            path = self.path(source)
            require(not kwargs and path == workspace / descriptor["path"] and self.cwd == self.build / self.audit_archive["root"]
                    and destination in ("Modules/Setup", "Modules/Setup.stdlib", "Modules/Setup.local"), "host Setup 模板/目的路径不符")
            data = raw_file(path)
            require(len(data) == descriptor["size"] and sha(data) == descriptor["sha256"], "J1 Setup 原模板字节改变")
            super().generate(source, destination)

    return AuditedHostContext


def selected_tasks(tasks, route, row):
    """按原 registry 槽精确选择两个原 hostpython Task，不调用 main/stop 或其他任务。"""
    selected = []
    for item in row["tasks"][0]["steps"]:
        index = item["index"]
        task = tasks.tasks[index]
        require(task.name == "hostpython" + row["python"] and task.task == item["task"] and task.kind == "host"
                and route["registry"][index]["function_sha256"] == item["function_sha256"], "原 hostpython Task 身份/槽/kind 不符")
        selected.append(task)
    require(len(selected) == 2 and [task.task for task in selected] == ["unpack_hostpython", "build_host"], "原 hostpython 选择必须恰好两项")
    return selected


def legacy_tasks(tasks, route, row):
    """明确创建 native SSL 候选，原 openssl arch Task 和原 registry 均保持不变。"""
    candidate = row["legacy_ssl_candidate"]
    if candidate is None:
        return []
    original_registry = list(tasks.tasks)
    selected = []
    for step in candidate["tasks"][0]["steps"]:
        original = tasks.tasks[step["index"]]
        require(original.name == "openssl" and original.task == step["task"] and original.kind == "arch"
                and route["registry"][step["index"]]["function_sha256"] == step["function_sha256"], "原 SSL body/registry_kind 不符")
        explicit = tasks.Task(step["task"], "openssl_host_bootstrap", original.function, kind="host", platforms="all", pythons="2")
        require(tasks.tasks.pop() is explicit and tasks.tasks == original_registry and original.kind == "arch", "候选污染原 registry/kind")
        selected.append(explicit)
    return selected


def native_probe(original, row, workspace, output):
    """先实际执行原 expanded CC/CFLAGS/LDFLAGS 的最小 native 编译与运行，禁止改 driver 凑通过。"""
    context = original.Context("host", "host", row["python"], workspace, argparse.Namespace(nostrip=False, sdl=False, experimental=False))
    context.set_names("host", "probe", "host_native_compiler_probe")
    source, binary = output / "native-probe.c", output / "native-probe"
    source.write_text('#include <stdio.h>\nint main(void){puts("REKO_HOST_NATIVE_PROBE");return sizeof(void*)!=8;}\n')
    argv = [*shlex.split(context.environ["CC"]), *shlex.split(context.environ["CFLAGS"]), str(source), "-o", str(binary),
            *shlex.split(context.environ["LDFLAGS"])]
    write_new(output / "native-driver-request.json", {"argv": argv, "environment": {key: context.environ[key]
              for key in ("CC", "CFLAGS", "LDFLAGS", "PATH")}, "native_source_build_verified": False})
    command(argv, env=context.environ)
    identity = elf_identity(raw_file(binary))
    require(command([binary], env=context.environ).strip() == b"REKO_HOST_NATIVE_PROBE", "native compiler 产物无法正确运行")
    return {"argv": argv, "binary_sha256": sha(raw_file(binary)), "elf": identity, "executed": True}


def host_inventory(prefix):
    """记录完整分发字节/模式/链接，拒绝特殊成员、路径逃逸或非 native ELF。"""
    no_links(prefix)
    records, links = [], {}
    for current, directories, names in os.walk(prefix, followlinks=False):
        current = Path(current)
        for name in list(directories):
            if (current / name).is_symlink():
                directories.remove(name)
                names.append(name)
        for name in sorted(directories + names):
            path = current / name
            relative = path.relative_to(prefix).as_posix()
            mode = path.lstat().st_mode
            item = {"path": relative, "permissions": format(stat.S_IMODE(mode), "04o")}
            if stat.S_ISDIR(mode):
                item["type"] = "directory"
            elif stat.S_ISLNK(mode):
                target = os.readlink(path)
                require(not Path(target).is_absolute(), "host 分发不接受外部绝对链接")
                links[relative] = target
                item.update(type="symlink", target=target, sha256=sha(target.encode()))
            elif stat.S_ISREG(mode):
                data = raw_file(path, 512 * 1024**2)
                item.update(type="file", mode="100755" if mode & 0o111 else "100644", bytes=len(data), sha256=sha(data))
                if data.startswith(b"\x7fELF"):
                    item["elf"] = elf_identity(data)
                if path.suffix == ".a":
                    item["archive"] = ar_identity(data)
                if path.suffix in (".so", ".dylib"):
                    require("elf" in item, "host native 库不是 ELF")
                require(not data.startswith((b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce")),
                        "host 分发混入 Mach-O")
            else:
                raise ValueError("host 分发含特殊成员")
            records.append(item)
    importlib.import_module("inventory_source_inputs").validate_links(links)
    require(records, "host 分发为空")
    return sorted(records, key=lambda item: item["path"])


def verify_product(probe, row, prefix):
    """验证精确 CPython/stdlib/SSL 与功能探针，禁止只凭存在的 python 文件收据通过。"""
    platforms = {("2", "2.7.18"): "linux2", ("3", "3.9.10"): "linux", ("3", "3.12.8"): "linux"}
    version_identity = row["python"], row["version"]
    require(version_identity in platforms, "host Python 未批准的版本/平台组合")
    requested = prefix / "bin" / ("python" + row["python"])
    require(probe["version"] == row["version"] and probe["implementation"] == "CPython" and probe["platform"] == platforms[version_identity]
            and probe["machine"] == "x86_64" and probe["prefix"] == str(prefix)
            and probe["executable"] in {str(requested), str(requested.resolve())}
            and ".." not in Path(probe["stdlib"]).parts and Path(probe["stdlib"]).is_relative_to(prefix)
            and probe["functional_probes_passed"] is True, "host Python 实际版本/prefix/ABI/探针不符")
    require(probe["openssl"].startswith("OpenSSL 1.1.1s ") if row["legacy_ssl_candidate"] else probe["openssl"].startswith("OpenSSL 3."),
            "host Python SSL 实际版本不是批准路线")
    expected = {"_ssl", "_hashlib", "hashlib", "zlib", "bz2", "_ctypes", "ctypes", "json", "encodings"}
    if row["python"] == "3":
        expected |= {"_lzma", "lzma"}
    require(len(probe["modules"]) == len(expected) and {item["name"] for item in probe["modules"]} == expected, "host stdlib 模块不完整")
    for item in probe["modules"]:
        require(item["builtin"] is True if item["file"] is None else
                (".." not in Path(item["file"]).parts and Path(item["file"]).is_relative_to(prefix)), "host stdlib 来自前缀外")


def dynamic_dependencies(binary, prefix):
    """保存真实 ldd 依赖与每个 native ELF 字节身份，缺失库或 iOS/其他 CPU 库拒绝。"""
    data = raw_file(binary, 512 * 1024**2)
    elf = elf_identity(data)
    require(elf["type"] in (2, 3), "只检查 native 可执行/共享 ELF 的动态依赖")
    offset = struct.unpack_from("<Q", data, 32)[0]
    width, count = struct.unpack_from("<HH", data, 54)
    require(width >= 56 and offset + width * count <= len(data) and count > 0, "native ELF program headers 非法")
    if not any(struct.unpack_from("<I", data, offset + index * width)[0] == 2 for index in range(count)):
        return {"static": True, "libraries": []}
    raw = command(["/usr/bin/ldd", str(binary)])
    require(b"not found" not in raw, "native ELF 动态依赖缺失")
    paths = []
    for line in raw.decode().splitlines():
        match = re.search(r"(?:=>\s*)?(/[^\s]+)", line)
        if match:
            path = Path(match.group(1)).resolve(strict=True)
            require(path.is_relative_to(prefix) or path.is_relative_to(Path("/usr/lib")) or path.is_relative_to(Path("/lib"))
                    or path.is_relative_to(Path("/lib64")), "native ELF 依赖来自未批准目录")
            data = raw_file(path)
            paths.append({"path": str(path), "sha256": sha(data), "elf": elf_identity(data)})
        else:
            require("linux-vdso.so.1" in line, "ldd 包含未知依赖格式")
    require(paths, "native 动态依赖记录为空")
    return {"static": False, "stdout": raw.decode(), "libraries": paths}


def run_tasks(original, tasks, route, row, workspace, output):
    """运行显式候选及两项原 Task.run，保持所有原函数对象、kind 和 registry 不变。"""
    require(not tasks.ran_tasks and (not (workspace / "tmp/complete").exists()
            or not list((workspace / "tmp/complete").iterdir())), "拒绝旧/伪造 complete 或会话跳步")
    selected = selected_tasks(tasks, route, row)
    candidates = legacy_tasks(tasks, route, row)
    identity_before = importlib.import_module("run_locked_source_tasks").registry_identity(tasks, workspace)
    functions = [task.function for task in tasks.tasks]
    events, receipts = [], []
    journal = output / "task-events.jsonl"
    with journal.open("x"):
        pass
    context_type = audited_context(original, row, workspace, events, journal)
    for task in [*candidates, *selected]:
        context = context_type("ios", "arm64", row["python"], workspace, argparse.Namespace(nostrip=False, sdl=False, experimental=False))
        task.run(context)
        require(context.audit_commands == len(context.audit_spec["commands"]), "原 host body 未执行全部命令")
        if task.task in ("unpack", "unpack_hostpython"):
            descriptor = row["python_archive"] if task.task == "unpack_hostpython" else row["legacy_ssl_candidate"]["archive"]
            verify_extracted(context.build, archive_members(workspace / descriptor["path"], descriptor))
        if task in candidates and task.task == "build":
            prefix = workspace / "tmp/host"
            require(b'OpenSSL 1.1.1s ' in raw_file(prefix / "include/openssl/opensslv.h"), "legacy host SSL header 版本不符")
            for library in ("libssl.a", "libcrypto.a"):
                ar_identity(raw_file(prefix / "lib" / library, 512 * 1024**2))
        receipts.append({"task_name": context.task_name, "name": task.name, "task": task.task, "kind": task.kind,
                         "build": str(context.build), "install": str(context.install), "python": context.python,
                         "original_registered_task": task in selected, "explicit_native_ssl_candidate": task in candidates})
    require(all(task.function is functions[index] for index, task in enumerate(tasks.tasks))
            and importlib.import_module("run_locked_source_tasks").registry_identity(tasks, workspace) == identity_before,
            "原 registry/function/kind 被改变")
    require(tasks.ran_tasks == {item["task_name"] for item in receipts}
            and {path.name for path in (workspace / "tmp/complete").iterdir()} == tasks.ran_tasks, "原完成标记不符")
    return receipts, events


def worker(args, plan, row, output, fd):
    """只在父进程实际 unshare 的新网络命名空间中执行 native 构建。"""
    require(stat.S_ISFIFO(os.fstat(fd).st_mode), "隔离 worker 必须由真实父管道启动")
    with os.fdopen(fd, "rb") as stream:
        data = stream.read(65537)
    require(len(data) <= 65536, "worker 协议过大")
    protocol = parse_json(data)
    require(isinstance(protocol, dict) and set(protocol) == {"parent_pid", "parent_network_namespace", "plan_sha256", "tool_sha256",
            "release", "workspace", "output", "frontend_report_sha256"}, "worker 协议字段错误")
    require(protocol["parent_pid"] == os.getppid() and protocol["plan_sha256"] == PLAN_SHA256
            and protocol["tool_sha256"] == sha(raw_file(Path(__file__).absolute()))
            and protocol["release"] == args.release and protocol["workspace"] == str(args.workspace)
            and protocol["output"] == str(args.output) and protocol["frontend_report_sha256"] == args.frontend_report_sha256
            and os.readlink("/proc/self/ns/net") != os.readlink("/proc/" + str(os.getppid()) + "/ns/net")
            and os.readlink("/proc/" + str(os.getppid()) + "/ns/net") == protocol["parent_network_namespace"], "worker 无真实新增内核网络隔离")
    frontend = frontend_receipt(args, plan, row)
    environment = native_environment(plan, row, output)
    j8 = importlib.import_module("run_locked_source_tasks")
    binding = checked_json(HERE / "source-task-binding-plan.json", plan["locks"]["source-task-binding-plan.json"])
    route = next(value for value in binding["routes"] if value["release"] == row["release"])
    recipe = j8.repository_row(binding, route)
    j8.verify_repository(recipe, args.workspace)
    original, tasks = j8.import_registry(route, args.workspace)
    probe = native_probe(original, row, args.workspace, output)
    receipts, events = run_tasks(original, tasks, route, row, args.workspace, output)
    prefix = args.workspace / "tmp/host"
    executable = prefix / "bin" / ("python" + row["python"])
    resolved = executable.resolve(strict=True)
    require(resolved.is_relative_to(prefix), "host python 指向分发前缀外")
    elf = elf_identity(raw_file(resolved))
    runtime = parse_json(command([executable, "-E", "-s", "-B", "-c", PRODUCT_PROBE]))
    verify_product(runtime, row, prefix)
    inventory = host_inventory(prefix)
    dependencies = [{"path": item["path"], "dependencies": dynamic_dependencies(prefix / item["path"], prefix)}
                    for item in inventory if item.get("elf", {}).get("type") in (2, 3)]
    require(any(item["path"] == resolved.relative_to(prefix).as_posix() for item in dependencies), "完整 native ELF 依赖缺解释器")
    write_new(output / "host-distribution.json", inventory)
    receipt = {"schema_version": 1, "scope": SCOPE, "release": row["release"], "plan_sha256": PLAN_SHA256,
               "workspace": str(args.workspace), "prefix": str(prefix), "interpreter": str(executable),
               "interpreter_sha256": sha(raw_file(resolved)), "elf": elf, "runtime": runtime,
               "frontend": frontend, "environment": environment, "native_driver_probe": probe,
               "tasks": receipts, "commands": events, "dynamic_dependencies": dependencies,
               "distribution": {"path": str(output / "host-distribution.json"), "sha256": sha(raw_file(output / "host-distribution.json"))},
               "kernel_network_isolation_verified": True, "original_host_task_count": 2,
               "explicit_native_ssl_candidate_count": 2 if row["legacy_ssl_candidate"] else 0,
               "host_bootstrap_verified": True, "target_python_install_verified": False, "target_pip_bound": False,
               "J2C_nine_scopes_complete": False, "source_ci_verified": False, "runtime_consumption_verified": False,
               "complete_input_closure": False}
    write_new(output / "host-receipt.json", receipt)
    return {"host_bootstrap_verified": True, "host_receipt": {"path": str(output / "host-receipt.json"),
                                                              "sha256": sha(raw_file(output / "host-receipt.json"))}}


def clean_environment(output, cache):
    """只传 native 构建必要环境和内容寻址 ccache，不传用户凭据或 Python 注入变量。"""
    home, temporary = output / "home", output / "temporary"
    home.mkdir(exist_ok=True)
    temporary.mkdir(exist_ok=True)
    return {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(temporary), "LANG": "C.UTF-8", "LC_ALL": "C",
            "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
            "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_CONFIG_FILE": os.devnull,
            "CCACHE_DIR": str(cache), "CCACHE_CONFIGPATH": os.devnull, "CCACHE_COMPILERCHECK": "content"}


def main(argv=None):
    """stage 复用完整 J1 配方；run 要求真实 Linux 前端并由强隔离 worker 原样运行 host body。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("stage", "run"))
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--release", choices=sorted(VERSIONS), required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--frontend-report", type=Path)
    parser.add_argument("--frontend-report-sha256")
    parser.add_argument("--source-cache", type=Path, default=ROOT / "ThirdParty/build/renpy-tests/goal-input-audit-20261102/versions/python-inputs/materialized")
    parser.add_argument("--tool-cache", type=Path, default=ROOT / "ThirdParty/build/renpy-tests/goal-input-audit-20261102/versions/python-inputs/wheel-build/tools")
    parser.add_argument("--ccache-dir", type=Path)
    parser.add_argument("--worker-fd", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    report = {"schema_version": 1, "scope": SCOPE, "command": args.command, "release": args.release, "result": "failed", "errors": [],
              "host_bootstrap_verified": False, "linux_native_bootstrap_completed": False, "target_python_install_verified": False,
              "target_pip_bound": False, "source_ci_verified": False, "runtime_consumption_verified": False,
              "complete_input_closure": False, "apple_sdk_required": False, "engine_metadata_overlay_required": False}
    created = False
    try:
        for name in ("plan", "root", "workspace", "output", "frontend_report", "source_cache", "tool_cache", "ccache_dir"):
            if getattr(args, name) is not None:
                no_links(getattr(args, name))
        if args.worker_fd is None:
            require(not args.output.exists() and not args.output.is_relative_to(args.workspace)
                    and not args.workspace.is_relative_to(args.output), "输出必须是工作区外独占新目录")
            args.output.mkdir(parents=True, mode=0o700)
            created = True
        else:
            require(args.command == "run" and args.output.is_dir(), "worker 不能新建/复用其他入口")
        sys.pycache_prefix = str(args.output / ("unused-worker-pycache" if args.worker_fd is not None else "unused-parent-pycache"))
        plan = load_plan(args.plan)
        row = next(value for value in plan["routes"] if value["release"] == args.release)
        sys.path.insert(0, str(HERE))
        j8 = importlib.import_module("run_locked_source_tasks")
        binding = checked_json(HERE / "source-task-binding-plan.json", plan["locks"]["source-task-binding-plan.json"])
        route = next(value for value in binding["routes"] if value["release"] == args.release)
        recipe = j8.repository_row(binding, route)
        for original in checked_json(HERE / "source-inputs.lock.json", plan["locks"]["source-inputs.lock.json"])["repositories"]:
            protected = args.root / original["path"]
            destinations = [args.workspace, args.output, *([args.ccache_dir] if args.ccache_dir is not None else [])]
            require(not any(path == protected or path.is_relative_to(protected) or protected.is_relative_to(path)
                            for path in destinations), "不得写入原始配方树")
        if args.command == "stage":
            require(args.worker_fd is None and args.frontend_report is None and args.frontend_report_sha256 is None, "stage 不消费旧前端收据")
            j8.stage_repository(recipe, args.root / route["recipe"]["path"], args.workspace)
            report.update(recipe_staged=True, recipe=route["recipe"], recipe_file_count=recipe["file_count"])
        else:
            require(sys.platform == "linux" and platform.machine() == "x86_64", "native host 执行只支持实际 Linux x86_64；Mac 不计通过")
            j8.verify_repository(recipe, args.workspace)
            for descriptor in [row["python_archive"], *([row["legacy_ssl_candidate"]["archive"]] if row["legacy_ssl_candidate"] else [])]:
                archive_members(args.workspace / descriptor["path"], descriptor)
            if args.worker_fd is not None:
                report.update(worker(args, plan, row, args.output, args.worker_fd), linux_native_bootstrap_completed=True)
            else:
                report["frontend"] = frontend_receipt(args, plan, row)
                replay = importlib.import_module("replay_python_inputs")
                isolation = replay.build.Isolation("unshare")
                report["network_isolation"] = isolation.prove(sys.executable, args.output)
                cache = args.ccache_dir or args.output / "ccache"
                no_links(cache)
                cache.mkdir(parents=True, exist_ok=True)
                environment = clean_environment(args.output, cache)
                read_fd, write_fd = os.pipe()
                try:
                    protocol = {"parent_pid": os.getpid(), "parent_network_namespace": os.readlink("/proc/self/ns/net"), "plan_sha256": PLAN_SHA256,
                                "tool_sha256": sha(raw_file(Path(__file__).absolute())), "release": args.release,
                                "workspace": str(args.workspace), "output": str(args.output), "frontend_report_sha256": args.frontend_report_sha256}
                    os.write(write_fd, json.dumps(protocol).encode())
                    os.close(write_fd)
                    write_fd = None
                    worker_argv = [sys.executable, "-s", "-B", str(Path(__file__).absolute()), *(argv if argv is not None else sys.argv[1:]),
                                   "--worker-fd", str(read_fd)]
                    with (args.output / "native-build.log").open("xb") as stream:
                        result = subprocess.run(isolation.command(worker_argv), env=environment, pass_fds=(read_fd,),
                                                stdout=stream, stderr=subprocess.STDOUT, timeout=7200)
                    require(result.returncode == 0, "native host worker 失败，见独立 native-build.log；rc=" + str(result.returncode))
                finally:
                    os.close(read_fd)
                    if write_fd is not None:
                        os.close(write_fd)
                child = parse_json(raw_file(args.output / "worker-report.json"))
                require(child["result"] == "passed" and child["host_bootstrap_verified"] is True
                        and child["release"] == args.release and child["scope"] == SCOPE and child["command"] == "run",
                        "native worker 未完成相同路线分发验收")
                require(Path(child["host_receipt"]["path"]) == args.output / "host-receipt.json", "host 收据输出路径改变")
                accepted = checked_json(args.output / "host-receipt.json", child["host_receipt"]["sha256"])
                require(accepted["release"] == args.release and accepted["plan_sha256"] == PLAN_SHA256
                        and accepted["workspace"] == str(args.workspace) and accepted["host_bootstrap_verified"] is True,
                        "host 收据路线/原输入身份不符")
                report.update({key: child[key] for key in ("host_receipt", "host_bootstrap_verified", "linux_native_bootstrap_completed")})
        report["result"] = "passed"
    except (Exception, SystemExit) as error:
        report["errors"].append(type(error).__name__ + ": " + str(error))
    destination = args.output / ("worker-report.json" if args.worker_fd is not None else "report.json")
    report["native_driver_request_recorded"] = (args.output / "native-driver-request.json").is_file()
    if created or args.worker_fd is not None:
        write_new(destination, report)
    print("[RenPyHostPython] " + args.command + " " + args.release + " result=" + report["result"]
          + (" errors=" + "; ".join(report["errors"]) if report["errors"] else ""), flush=True)
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    if os.environ.get("PYTHONHASHSEED") != "0" or not sys.flags.dont_write_bytecode or not sys.flags.no_user_site:
        environment = {key: value for key, value in os.environ.items() if key not in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE")}
        environment.update(PYTHONHASHSEED="0", PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1")
        os.execve(sys.executable, [sys.executable, "-s", "-B", str(Path(__file__).absolute()), *sys.argv[1:]], environment)
    raise SystemExit(main())
