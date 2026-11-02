#!/usr/bin/env python3
"""以完整批准输入执行原 iOS C 前置 Task；目标 Python 安装与 pip 留在后续阶段。"""

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
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import types
import zipfile


HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[1]
DEFAULT_PLAN = HERE / "target-python-prefix-plan.json"
PLAN_SHA256 = "42498a925e9f968048c13ff4d1751bfe75aee3045839f8b9b4760ec68ae48e4e"
SCOPE = "four_approved_routes_original_ios_C_prerequisites_only"
RELEASES = ("8.5.3", "8.4.1", "8.3.7", "7.8.7")
ARCHES = ("arm64", "sim-arm64", "sim-x86_64")
ENV_KEYS = ("CC", "CXX", "CPP", "AR", "RANLIB", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "PATH")
FALSE_BOUNDARIES = {"target_python_install_verified": False, "target_pip_bound": False,
                    "production_shared_dylib_verified": False, "ios_runtime_verified": False,
                    "source_ci_verified": False, "complete_input_closure": False}


def require(value, message):
    """拒绝未证明状态，不以存在的目录或旧 complete 标记替代实际执行。"""
    if not value:
        raise ValueError(message)


def sha(raw):
    """计算完整原字节 SHA256。"""
    return hashlib.sha256(raw).hexdigest()


def guarded(path):
    """只接纳绝对、无上跳且全部祖先无链接的输入路径。"""
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts
            and not any(p.is_symlink() for p in (path, *path.parents)), "路径须绝对且无链接/上跳：" + str(path))
    return path


def raw_file(path, maximum=256 * 1024**2):
    """读取有界普通文件，拒绝 FIFO、路径替换和超限材料。"""
    path = guarded(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, "文件类型或大小错误")
        raw = stream.read(maximum + 1)
    require(len(raw) == info.st_size, "读取期间文件长度变化")
    return raw


def decode(raw):
    """拒绝重复字段及非有限 JSON 数值。"""
    def unique(rows):
        """字段不得被后一个同名字段覆盖。"""
        result = {}
        for key, value in rows:
            require(key not in result, "JSON 字段重复")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: require(False, "JSON 非有限值"))


def checked_json(path, expected, maximum=32 * 1024**2):
    """先核独立全字节 SHA，再解析收据或批准计划。"""
    raw = raw_file(path, maximum)
    require(re.fullmatch("[0-9a-f]{64}", expected or "") and sha(raw) == expected, "SHA256 不符：" + Path(path).name)
    return decode(raw)


def write_new(path, value):
    """保留历史成功和失败证据，不覆盖任何既有报告。"""
    guarded(path)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def log(message):
    """遵循 Python 构建日志前缀；不加载 App 内 RKLogC。"""
    print("[RenPyTargetPrefix] " + message, file=sys.stderr, flush=True)


def load_plan(path=DEFAULT_PLAN):
    """以独立 SHA 固定四路线、原任务命令投影、两 host producer 和窄参数候选。"""
    plan = checked_json(path, PLAN_SHA256, 2 * 1024**2)
    require(set(plan) == {"schema_version", "task", "scope", "dependencies", "locks", "host_producers",
                          "candidate_adaptations", "routes", "limitations"}
            and type(plan["schema_version"]) is int and plan["schema_version"] == 1
            and plan["task"] == "R00-02J9A" and plan["scope"] == SCOPE, "计划范围错误")
    require(len(plan["routes"]) == 4 and {r["release"] for r in plan["routes"]} == set(RELEASES)
            and set(plan["host_producers"]) == set(RELEASES), "必须固定四路线和各自 host 产物")
    for name, expected in {**plan["dependencies"], **plan["locks"]}.items():
        require(Path(name).name == name and name not in ("", ".", ".."), "依赖名称错误")
        require(sha(raw_file(HERE / name)) == expected, "固定依赖字节变化：" + name)
    return plan


def load_helper(plan, name, alias=None):
    """直接编译已锁源码，拒绝同名环境模块或旧 pyc 冒充依赖。"""
    raw = raw_file(HERE / name)
    require(sha(raw) == plan["dependencies"][name], "依赖源码 SHA 不符：" + name)
    module = types.ModuleType(alias or "reko_target_" + name.replace(".", "_"))
    module.__file__ = str(HERE / name)
    if alias is not None:
        require(alias not in sys.modules or Path(sys.modules[alias].__file__).absolute() == HERE / name,
                "依赖已由外部同名模块加载")
        sys.modules[alias] = module
    exec(compile(raw, module.__file__, "exec"), module.__dict__)
    return module


def helpers(plan):
    """只加载固定 J1/J8/H1/C1 门禁，不执行原 main、引擎 import 或 pip。"""
    inventory = load_helper(plan, "inventory_source_inputs.py", "inventory_source_inputs")
    j8 = load_helper(plan, "run_locked_source_tasks.py", "run_locked_source_tasks")
    native = load_helper(plan, "run_locked_host_python_tasks.py", "run_locked_host_python_tasks")
    validator = load_helper(plan, "validate_lock.py")
    common = load_helper(plan, "build_common.py")
    preflight = load_helper(plan, "preflight_environment.py")
    return inventory, j8, native, validator, common, preflight


def route_binding(plan, row, j8):
    """复用 J8 完整 registry/annotators/Task.run 投影，并验证本阶段所选任务。"""
    binding = checked_json(HERE / "source-task-binding-plan.json", plan["locks"]["source-task-binding-plan.json"])
    route = next(r for r in binding["routes"] if r["release"] == row["release"])
    projection = {key: route[key] for key in ("registry", "annotators", "task_run_sha256")}
    require(sha(json.dumps(projection, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
            == row["registry_contract_sha256"] and row["recipe"] == route["recipe"], "完整 registry 投影身份错误")
    return route, j8.repository_row(binding, route)


def selected_tasks(tasks, route, row, arch, workspace):
    """只选原 iOS SDK、mockrt、MetalANGLE 和明确 C 家族，不改 kind/body/注册表。"""
    require(arch in ARCHES, "未知架构")
    j8 = sys.modules["run_locked_source_tasks"]
    observed_registry, observed_annotators, observed_method = j8.registry_identity(tasks, workspace)
    require(observed_registry == route["registry"] and observed_annotators == route["annotators"]
            and observed_method == route["task_run_sha256"], "原完整 registry/annotators/Task.run 身份错误")
    selected = []
    for spec in row["tasks"]:
        if arch not in spec["operations"]:
            continue
        index = spec["index"]
        require(type(index) is int and 0 <= index < len(tasks.tasks), "Task 索引错误")
        task, original = tasks.tasks[index], route["registry"][index]
        require((task.name, task.task, task.kind) == (spec["name"], spec["task"], spec["kind"])
                and original["function_sha256"] == spec["function_sha256"] and not task.always,
                "原 Task 槽/函数/kind 错误")
        selected.append((task, spec))
    require(len(selected) == (11 if row["python"] == "2" else 13)
            and sum(t.name == "toolchain" and t.task == "build" for t, _ in selected) == 1,
            "所选原 Task 集合不完整")
    require([(t.name, t.task) for t, _ in selected[:3]] == [("toolchain", "build"), ("toolchain", "mockrt"), ("metalangle", "install")],
            "原前置任务顺序变化")
    return selected


def candidate_environment(context, row, arch, plan):
    """只按已锁原函数和精确原片段施加两个公开候选，不修改原源码或语言标准。"""
    require(arch in ARCHES and context.platform == "ios" and context.arch == arch, "候选目标不符")
    original = {key: context.environ[key] for key in ENV_KEYS}
    updated, changes = dict(original), []
    if row["release"] in plan["candidate_adaptations"]["legacy_metalangle"]["releases"]:
        fragment = plan["candidate_adaptations"]["legacy_metalangle"]["original_fragment"]
        require(fragment == " -framework MetalANGLE" and all(updated[key].count(fragment) == 1 for key in ("CFLAGS", "CXXFLAGS"))
                and fragment not in updated["LDFLAGS"], "旧 MetalANGLE 原参数片段不符；拒绝猜测替换")
        for key in ("CFLAGS", "CXXFLAGS"):
            updated[key] = updated[key].replace(fragment, "", 1)
        updated["LDFLAGS"] += fragment
        changes.append({"candidate": "legacy_metalangle", "source": row["flag_sources"]["metalangle_annotator"],
                        "reason": plan["candidate_adaptations"]["legacy_metalangle"]["reason"]})
    if row["release"] in plan["candidate_adaptations"]["llvm15_platform"]["releases"]:
        config = plan["candidate_adaptations"]["llvm15_platform"]
        require("clang-15 " in updated["CC"] and "-platform_version" not in " ".join(updated.values()),
                "LLVM15 原 driver 片段错误或候选已被重复施加")
        suffix = " -Wl,-platform_version," + config["platform_by_arch"][arch] + "," + config["minimum_by_arch"][arch] + ",14.0"
        updated["LDFLAGS"] += suffix
        changes.append({"candidate": "llvm15_platform", "source": row["flag_sources"]["run_source"],
                        "append": suffix, "reason": config["reason"]})
    require(all(updated[key] == original[key] for key in ("CC", "CXX", "CPP", "AR", "RANLIB", "CPPFLAGS", "PATH")),
            "候选越界修改工具或语言标准")
    return original, updated, changes


def expected_paths(workspace, row, arch, spec):
    """在创建目录前推导原 Context 的全部目标路径。"""
    require(arch in ARCHES and row["release"] in RELEASES and spec["kind"] in ("cross", "arch", "python"), "未知任务 kind/路线")
    suffix = "cross-ios-" + arch if spec["kind"] == "cross" else "ios-" + arch + ("-py" + row["python"] if spec["kind"] == "python" else "")
    build = workspace / "tmp/build" / (spec["name"] + "." + suffix)
    install = workspace / ("tmp/cross.ios-" + arch if spec["kind"] == "cross" else "tmp/install.ios-" + arch)
    return build, install


def audited_context(original, row, arch, workspace, plan, events, journal=None):
    """以原 Context 窄审计子类执行原 body，路径/模板/操作顺序均精确绑定。"""
    specs = {(s["kind"], s["task"], s["name"]): s for s in row["tasks"] if arch in s["operations"]}

    class AuditedTargetContext(original.Context):
        """保留原环境与命令实现；只在明确候选点改变已记录的参数。"""

        def set_names(self, kind, task, name):
            """原 Task.run 创建 complete 之前拒绝未知任务及错误根/目标。"""
            require((kind, task, name) in specs and self.root == workspace and self.tmp == workspace / "tmp"
                    and self.platform == "ios" and self.arch == arch and self.python == row["python"], "非批准目标 Context/Task")
            self.audit_spec = specs[kind, task, name]
            self.audit_position = 0
            self.audit_adapted = False
            self.audit_environment = None
            super().set_names(kind, task, name)
            if kind == "cross":
                self.var("tars", workspace / "tmp/locked-sdk-tars")
            self.check_paths()

        def check_paths(self):
            """每次有副作用之前重新绑定 build/install/cross/host 和真实模板目的地。"""
            build, install = expected_paths(workspace, row, arch, self.audit_spec)
            require(self.root == workspace and self.tmp == workspace / "tmp" and self.build == build and self.install == install
                    and self.platform == "ios" and self.arch == arch and self.python == row["python"]
                    and super().path("{{build}}") == build and super().path("{{install}}") == install
                    and super().path("{{host}}") == workspace / "tmp/host"
                    and super().path("{{cross}}") == workspace / ("tmp/cross.ios-" + arch), "Context 实际路径/ABI 不符")
            require(super().path("{{tars}}") == workspace / ("tmp/locked-sdk-tars" if self.kind == "cross" else "tars"), "原 SDK 运输变量落点错误")
            require(self.cwd == build or self.cwd.is_relative_to(build)
                    or (self.name == "toolchain" and self.kind == "cross" and self.cwd == install), "Context cwd 越界")

        def operation(self, value):
            """逐项比较原函数操作投影；未知 clean/chdir/patch/命令均在副作用前拒绝。"""
            self.check_paths()
            sequence = self.audit_spec["operations"][arch]
            require(self.audit_position < len(sequence) and value == sequence[self.audit_position], "出现未知目标操作或顺序变化")
            self.audit_position += 1

        def path(self, value):
            """模板路径必须词法和实际解析均处于独立配方根，合法 SDK 链接保留。"""
            path = super().path(value)
            require(path.is_absolute() and ".." not in path.parts and path.is_relative_to(workspace)
                    and path.resolve(strict=False).is_relative_to(workspace), "目标 Context.path 逃逸")
            return path

        def clean(self, value="{{build}}"):
            """只允许原函数已锁的清理目的地，不删除其他前缀或源码。"""
            self.operation(["clean", value])
            destination = self.path(value)
            require(destination in (self.build, self.install, self.install / "MetalANGLE.framework"), "clean 目的地错误")
            super().clean(value)

        def chdir(self, value):
            """只进入原源码包根或明确 cross 目录。"""
            self.operation(["chdir", value])
            super().chdir(value)

        def patch(self, value, p=1):
            """只施加 J1 已逐字节验证的原 bzip2 补丁。"""
            self.operation(["patch", value, p])
            require(value == "bzip2-no-tests.diff" and p == 1, "未知目标补丁")
            super().patch(value, p)

        def run(self, template, verbose=False, quiet=False, **kwargs):
            """审计原模板与原/候选展开 argv 后，委托真正原 Context.run 执行。"""
            self.operation(["run", template])
            require(not kwargs and not verbose and not quiet, "未知目标命令参数")
            if not self.audit_adapted:
                before, after, changes = candidate_environment(self, row, arch, plan)
                self.audit_environment = {"original": before, "candidate": after, "changes": changes}
                self.environ.update(after)
                self.audit_adapted = True
            argv = shlex.split(self.expand(template))
            require(argv and argv[0] not in ("git", "curl", "wget", "pip", "pip3", "python", "python2", "python3"), "拒绝网络/目标 Python 阶段")
            event = {"task_name": self.task_name, "template": template, "argv": argv, "cwd": str(self.cwd),
                     "environment": self.audit_environment, "returncode": None}
            events.append(event)
            if journal is not None:
                with journal.open("a") as stream:
                    stream.write(json.dumps({"phase": "start", **event}, ensure_ascii=False) + "\n")
            try:
                super().run(template)
                event["returncode"] = 0
            except BaseException as error:
                event["returncode"] = error.code if isinstance(error, SystemExit) else "exception"
                raise
            finally:
                if journal is not None:
                    with journal.open("a") as stream:
                        stream.write(json.dumps({"phase": "exit", **event}, ensure_ascii=False) + "\n")

    return AuditedTargetContext


def inventory_tree(prefix, inventory):
    """记录完整目录、权限、文件字节和链接，并验证全部链接图及父目录类型。"""
    guarded(prefix)
    require(prefix.is_dir(), "产物根缺失")
    records, links = [], {}
    for current, directories, names in os.walk(prefix, followlinks=False):
        current = Path(current)
        for name in list(directories):
            if (current / name).is_symlink():
                directories.remove(name)
                names.append(name)
        for name in sorted(directories + names):
            path = current / name
            item = {"path": path.relative_to(prefix).as_posix(), "permissions": format(stat.S_IMODE(path.lstat().st_mode), "04o")}
            if path.is_symlink():
                target = os.readlink(path)
                item.update(type="symlink", target=target, sha256=sha(target.encode()))
                links[item["path"]] = target
            elif path.is_dir():
                item["type"] = "directory"
            else:
                data = raw_file(path, 1024**3)
                item.update(type="file", bytes=len(data), sha256=sha(data))
            records.append(item)
    inventory.validate_links(links)
    require(records, "完整产物清单为空")
    return sorted(records, key=lambda r: r["path"])


def verify_tar_tree(archive, destination, preflight):
    """逐原 tar 成员核验 SDK 解包结果；不只凭 SDKSettings 存在通过。"""
    expected = {}
    with tarfile.open(archive, "r:gz") as source:
        entries = {preflight.archive_name(m.name): m for m in source}
        root = next(iter(entries)).split("/")[0]
        for name, item in entries.items():
            path = destination / name
            require(path.exists() or path.is_symlink(), "SDK 解包缺成员：" + name)
            if item.issym():
                require(path.is_symlink() and os.readlink(path) == item.linkname, "SDK 解包链接不同")
            elif item.isdir():
                require(path.is_dir() and not path.is_symlink(), "SDK 解包目录类型不同")
            else:
                target = entries[preflight.resolve_archive_link(name, entries, root)] if item.islnk() else item
                require(path.is_file() and not path.is_symlink(), "SDK 解包文件类型不同")
                raw = raw_file(path, 1024**3)
                require(raw == source.extractfile(target).read(), "SDK 解包原字节不同")
            if not item.issym():
                require(stat.S_IMODE(path.lstat().st_mode) == stat.S_IMODE(item.mode), "SDK 解包权限不同")
            expected[name] = True
    actual = {path.relative_to(destination).as_posix() for path in (destination / root).rglob("*")}
    actual.add(root)
    require(actual == set(expected), "SDK 解包完整成员集合不同")
    alias = destination / "sdk"
    require(alias.is_symlink() and os.readlink(alias) == root and set(p.name for p in destination.iterdir()) == {root, "sdk"}, "SDK 别名/额外文件错误")
    return {"members": len(expected), "source_sha256": sha(raw_file(archive, 2 * 1024**3)), "complete_original_bytes_verified": True}


def ar_members(raw):
    """解析真实普通 ar，保留每个成员原字节；拒绝 thin、截断、重复及外部成员。"""
    require(raw.startswith(b"!<arch>\n"), "目标静态库必须为普通 ar")
    offset, names, result, longnames = 8, set(), [], None
    while offset < len(raw):
        require(offset + 60 <= len(raw), "ar 成员头截断")
        header = raw[offset:offset + 60]
        require(header[58:] == b"`\n" and re.fullmatch(rb"[0-9]+ *", header[48:58]), "ar 头非法")
        size = int(header[48:58]);start = offset + 60;end = start + size
        require(end <= len(raw), "ar 成员越界")
        name = header[:16].decode("ascii").strip();body = raw[start:end]
        offset = end + size % 2
        require(offset <= len(raw) and (size % 2 == 0 or raw[end:offset] == b"\n"), "ar 对齐错误")
        if name == "//":
            require(longnames is None, "ar 长名称表重复")
            longnames = body;continue
        if name.startswith("#1/"):
            width = int(name[3:]);require(0 < width <= len(body), "BSD ar 名称越界")
            name, body = body[:width].rstrip(b"\0").decode(), body[width:]
        elif re.fullmatch(r"/[0-9]+", name):
            index = int(name[1:]);require(longnames is not None and index < len(longnames), "ar 长名称缺失")
            stop = longnames.find(b"/\n", index);require(stop > index, "ar 长名称未终止")
            name = longnames[index:stop].decode()
        else:
            name = name.rstrip("/")
        if name in ("", "/", "/SYM64", "__.SYMDEF", "__.SYMDEF SORTED"):
            continue
        require(name not in names and name and "/" not in name and "\\" not in name and name not in (".", ".."), "ar 重复或外部成员")
        names.add(name);result.append((name, body))
    require(offset == len(raw) and result, "ar 为空或尾部损坏")
    return result


def verify_c_products(prefix, row, arch, inventory, preflight):
    """完整登记头和来源；每个静态库的每个对象必须匹配实际 iOS CPU/平台/min。"""
    records = inventory_tree(prefix, inventory)
    libraries = {"lib/libmockrt.a", "lib/libz.a", "lib/libbz2.a", "lib/libssl.a", "lib/libcrypto.a", "lib/libffi.a"}
    if row["python"] == "3":
        libraries.add("lib/liblzma.a")
    actual = {r["path"] for r in records if r["type"] == "file" and r["path"].endswith(".a")}
    require(actual == libraries, "C 静态库完整集合不同")
    cpu, target = ("x86_64" if arch == "sim-x86_64" else "arm64"), (2 if arch == "arm64" else 7)
    archives = []
    for name in sorted(libraries):
        objects = []
        for member, body in ar_members(raw_file(prefix / name, 1024**3)):
            identity = preflight.check_macho(body, cpu, target)
            require(identity["file_type"] == 1, "ar 中混入非 MH_OBJECT 成员")
            require(identity["sdk"] in ([0, 0, 0], [14, 0, 0]), "C 对象编码了非批准 SDK")
            objects.append({"name": member, "bytes": len(body), "sha256": sha(body), **identity})
        archives.append({"path": name, "objects": objects, "object_count": len(objects)})
    headers = [r for r in records if r["type"] == "file" and r["path"].endswith(".h") and not r["path"].startswith("MetalANGLE.framework/")]
    require(all(any(r["path"].endswith(suffix) for r in headers) for suffix in ("/zlib.h", "/bzlib.h", "/ssl.h", "/ffi.h"))
            and (row["python"] == "2" or any(r["path"].endswith("/lzma.h") for r in headers)), "C 安装头不完整")
    require(not any(r["type"] == "file" and r["path"].endswith((".dylib", ".so")) for r in records), "前缀混入非批准共享 C 库")
    executables = []
    for record in records:
        if record["type"] != "file" or record["path"].startswith("MetalANGLE.framework/") or record["path"].endswith(".a"):continue
        path = prefix / record["path"]
        with path.open("rb") as stream:magic = stream.read(4)
        require(magic != b"\x7fELF", "iOS C 前缀混入 native ELF")
        if magic == b"\xcf\xfa\xed\xfe":
            identity = preflight.check_macho(raw_file(path), cpu, target, True)
            require(identity["file_type"] == 2, "前缀出现未登记 Mach-O 类型")
            executables.append({**record, **identity})
    return {"inventory": records, "archives": archives, "headers": headers, "sources": row["sources"], "executables": executables,
            "object_sdk_boundary": "MH_OBJECT SDK0 原样保留；其 SDK14 消费由原Context参数、完整SDK字节和真实driver SDK14证明，不将0改标14",
            "all_archive_objects_verified": True}


def framework_slice(raw, arch):
    """从真实 fat 包选唯一 CPU 原切片，不以同 CPU 推断 arm64 的平台。"""
    require(len(raw) >= 8 and raw[:4] == b"\xca\xfe\xba\xbe", "原 MetalANGLE 不是批准 fat 格式")
    count = struct.unpack_from(">I", raw, 4)[0];require(0 < count <= 16 and 8 + count * 20 <= len(raw), "fat 表越界")
    cpu = 0x1000007 if arch == "sim-x86_64" else 0x100000C
    found, ranges = [], []
    for index in range(count):
        kind, _, offset, size, align = struct.unpack_from(">5I", raw, 8 + index * 20)
        require(align <= 30 and offset >= 8 + count * 20 and offset % (1 << align) == 0 and size > 0 and offset + size <= len(raw), "fat 切片范围错误")
        require(all(offset + size <= start or offset >= end for start, end in ranges), "fat 切片重叠")
        ranges.append((offset, offset + size))
        if kind == cpu:found.append(raw[offset:offset + size])
    require(len(found) == 1, "fat 缺少唯一批准 CPU 切片")
    return found[0]


def framework_metadata(raw, arch):
    """核原框架 selected64 切片：旧 LC_MIN 结合原 zip 来源，arm64 模拟器必须 platform7。"""
    body = framework_slice(raw, arch)
    require(len(body) >= 32, "框架 Mach-O 头截断")
    magic, cpu, _, kind, count, length, _, _ = struct.unpack_from("<8I", body)
    require(magic == 0xFEEDFACF and kind == 6 and cpu == (0x1000007 if arch == "sim-x86_64" else 0x100000C)
            and count <= length // 8 and 32 + length <= len(body), "框架 Mach-O 类型/CPU/命令表错误")
    offset, versions = 32, []
    for _ in range(count):
        require(offset + 8 <= 32 + length, "框架命令头截断")
        command, size = struct.unpack_from("<2I", body, offset)
        require(size >= 8 and size % 4 == 0 and offset + size <= 32 + length, "框架 load command 越界")
        if command == 0x32:
            require(size >= 24, "框架 BUILD_VERSION 截断")
            _, _, target, minimum, sdk, tools = struct.unpack_from("<6I", body, offset)
            require(24 + tools * 8 == size, "框架工具表错误")
            versions.append({"load_command": "LC_BUILD_VERSION", "platform": target, "minimum": minimum, "sdk": sdk})
        elif command == 0x25:
            require(size == 16, "框架 MIN_IPHONEOS 截断")
            minimum, sdk = struct.unpack_from("<2I", body, offset + 8)
            versions.append({"load_command": "LC_VERSION_MIN_IPHONEOS", "platform": 2 if arch == "arm64" else 7,
                             "platform_evidence": "原批准 device/simulator zip + CPU；旧 load command 本身不编码平台", "minimum": minimum, "sdk": sdk})
        offset += size
    require(offset == 32 + length and len(versions) == 1, "框架版本记录缺失/重复")
    record = versions[0]
    require(record["sdk"] == 0xE0400 and record["minimum"] == (0xE0000 if arch == "sim-arm64" else 0x90000)
            and record["platform"] == (2 if arch == "arm64" else 7)
            and (arch != "sim-arm64" or record["load_command"] == "LC_BUILD_VERSION"), "框架原平台/SDK/最低版本不同")
    return {"selected_slice_sha256": sha(body), "selected_slice_bytes": len(body), **record}


def verify_framework(archive, prefix, arch, inventory):
    """核安装框架与 J1 原 zip 每个成员字节/权限，完整源包不是源码重建通过。"""
    expected = {}
    with zipfile.ZipFile(archive) as source:
        for item in source.infolist():
            name = item.filename.rstrip("/")
            require(name and not name.startswith("/") and all(p not in ("", ".", "..") for p in name.split("/"))
                    and (name == "MetalANGLE.framework" or name.startswith("MetalANGLE.framework/")) and name not in expected,
                    "framework zip 路径/重复错误")
            mode = item.external_attr >> 16
            require(item.create_system == 3 and (stat.S_ISDIR(mode) if item.is_dir() else stat.S_ISREG(mode)), "框架原 zip 类型不符")
            expected[name] = item
        for name, item in expected.items():
            path = prefix / name
            if item.is_dir():require(path.is_dir() and not path.is_symlink(), "框架目录类型不同")
            else:require(raw_file(path) == source.read(item), "框架安装原字节不同")
            require(stat.S_IMODE(path.lstat().st_mode) == stat.S_IMODE(item.external_attr >> 16), "框架安装权限不同")
    actual = {"MetalANGLE.framework", *(p.relative_to(prefix).as_posix() for p in (prefix / "MetalANGLE.framework").rglob("*"))}
    require(actual == set(expected), "框架完整成员集合不同")
    return {"original_archive_sha256": sha(raw_file(archive)), "members": len(expected), "full_original_framework_bytes_verified": True,
            "source_rebuild_verified": False, **framework_metadata(raw_file(prefix / "MetalANGLE.framework/MetalANGLE"), arch)}


def dependency_projection(rows, prefix):
    """只丢弃 ldd 地址噪声，完整保留库路径/字节/ELF，内部前缀显式相对化。"""
    projected = []
    for row in rows:
        dependencies = row["dependencies"]
        libraries = []
        for library in dependencies["libraries"]:
            path = Path(library["path"])
            libraries.append({"path": "@host/" + path.relative_to(prefix).as_posix() if path.is_relative_to(prefix) else str(path),
                              "sha256": library["sha256"], "elf": library["elf"]})
        projected.append({"path": row["path"], "static": dependencies["static"], "libraries": sorted(libraries, key=lambda r: r["path"])})
    return sorted(projected, key=lambda r: r["path"])


def restore_host(args, plan, row, native, inventory):
    """只消费各路线已实测固定 H1 全前缀，完整复核后独立复制并重跑原生探针。"""
    identity = plan["host_producers"][row["release"]]
    require(args.host_receipt_sha256 == identity["receipt"]["sha256"]
            and args.host_inventory_sha256 == identity["inventory"]["sha256"], "host 原收据不在批准 producer 中")
    receipt = checked_json(args.host_receipt, args.host_receipt_sha256)
    entries = checked_json(args.host_inventory, args.host_inventory_sha256)
    require(args.host_receipt.stat().st_size == identity["receipt"]["bytes"]
            and args.host_inventory.stat().st_size == identity["inventory"]["bytes"]
            and receipt["plan_sha256"] == identity["execution_plan_sha256"]
            and receipt["release"] == row["release"] and receipt["prefix"] == identity["original_prefix"]
            and receipt["host_bootstrap_verified"] is True and receipt["kernel_network_isolation_verified"] is True
            and receipt["interpreter_sha256"] == identity["interpreter_sha256"]
            and receipt["distribution"]["sha256"] == args.host_inventory_sha256
            and all(receipt.get(key) is False for key in FALSE_BOUNDARIES if key in receipt), "原 host 产物身份/范围错误")
    require(native.host_inventory(args.host_prefix) == entries, "完整 host 前缀与原库存不同")
    destination = args.workspace / "tmp/host"
    require(not destination.exists() and not destination.is_symlink(), "派生 host 前缀不得预存")
    destination.mkdir(parents=True)
    for entry in entries:
        if entry["type"] == "symlink":continue
        target = destination / entry["path"];guarded(target)
        if entry["type"] == "directory":target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:stream.write(raw_file(args.host_prefix / entry["path"], 512 * 1024**2))
        target.chmod(int(entry["permissions"], 8))
    for entry in entries:
        if entry["type"] == "symlink":
            target = destination / entry["path"];guarded(target.parent);target.symlink_to(entry["target"])
    require(native.host_inventory(destination) == entries, "派生 host 完整库存不符")
    binary = destination / "bin" / ("python" + row["python"])
    real = binary.resolve(strict=True)
    require(real.is_relative_to(destination) and sha(raw_file(real)) == identity["interpreter_sha256"], "真实 host 解释器字节/链接不符")
    native.elf_identity(raw_file(real))
    probe = decode(native.command([binary, "-E", "-s", "-B", "-c", native.PRODUCT_PROBE]))
    native.verify_product(probe, {**row, "legacy_ssl_candidate": row["python"] == "2"}, destination)
    dependencies = [{"path": entry["path"], "dependencies": native.dynamic_dependencies(destination / entry["path"], destination)}
                    for entry in entries if entry.get("elf", {}).get("type") in (2, 3)]
    require(dependency_projection(receipt["dynamic_dependencies"], Path(receipt["prefix"])) == dependency_projection(dependencies, destination),
            "host 动态库实际身份与批准原分发不同")
    return {"original_producer": identity, "original_receipt": str(args.host_receipt), "source_prefix": str(args.host_prefix),
            "prefix": str(destination), "full_distribution_reverified": True, "members": len(entries), "runtime": probe,
            "dynamic_dependencies": dependencies, "stable_dynamic_dependency_identity_verified": True}


def driver_probe(original, tasks, row, arch, workspace, plan, output, preflight):
    """使用所有原 annotator 的真正 Context 参数先探原 driver，再验证明确候选。"""
    context = original.Context("ios", arch, row["python"], workspace, argparse.Namespace(nostrip=False, sdl=False, experimental=False))
    context.set_names("arch", "probe", "target_c_driver_probe")
    for annotate in tasks.annotators:annotate(context)
    before, after, changes = candidate_environment(context, row, arch, plan)
    source = output / "target-driver.c"
    with source.open("x") as stream:stream.write('#include <stdio.h>\nint main(void){puts("REKO_IOS_C_DRIVER");return 0;}\n')
    records = {"original": {"environment": before, "commands": []}, "candidate": {"environment": after, "commands": []}, "changes": changes}
    write_new(output / "driver-request.json", records)
    cpu, target = ("x86_64" if arch == "sim-x86_64" else "arm64"), (2 if arch == "arm64" else 7)
    for label, environment in (("original", before), ("candidate", after)):
        env = dict(context.environ);env.update(environment)
        obj, executable = output / (label + "-driver.o"), output / (label + "-driver")
        commands = [[*shlex.split(env["CC"]), *shlex.split(env["CFLAGS"]), "-c", str(source), "-o", str(obj)],
                    [*shlex.split(env["CC"]), *shlex.split(env["CFLAGS"]), str(obj), *shlex.split(env["LDFLAGS"]), "-o", str(executable)]]
        for index, argv in enumerate(commands):
            result = subprocess.run(argv, cwd=context.cwd, env=env, capture_output=True, timeout=120)
            stem = label + "-driver-" + str(index)
            (output / (stem + ".stdout")).write_bytes(result.stdout);(output / (stem + ".stderr")).write_bytes(result.stderr)
            records[label]["commands"].append({"argv": argv, "returncode": result.returncode, "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr)})
            if result.returncode != 0:break
        records[label]["passed"] = len(records[label]["commands"]) == 2 and all(c["returncode"] == 0 for c in records[label]["commands"])
        if records[label]["passed"]:
            records[label]["object"] = {"sha256": sha(raw_file(obj)), **preflight.check_macho(raw_file(obj), cpu, target)}
            records[label]["executable"] = {"sha256": sha(raw_file(executable)), **preflight.check_macho(raw_file(executable), cpu, target, True)}
    write_new(output / "driver-result.json", records)
    require(records["candidate"]["passed"], "实际原 Context 候选 driver 未通过；见独占 driver-result.json")
    require(changes or records["original"]["passed"], "原 driver 失败且无批准候选")
    return records


def gate_inputs(args, row, validator, common, commands):
    """逐家族调用稳定输入/环境门禁，保留完整原 SDK/runtime 与派生配方身份。"""
    result = []
    for family in row["families"]:
        selected = argparse.Namespace(root=args.root, recipe_root=args.workspace, route=args.release, family=family, arch=args.arch,
                                      stage="linux-dependencies", deployment_target=args.deployment_target, sdk_version=args.sdk_version,
                                      sdk=args.sdk, clang_runtime=args.clang_runtime)
        inputs = validator.validate_inputs(selected)
        environment = common.check_environment(selected, inputs, validator, commands)
        result.append({"family": family, "selection": inputs["selection"], "task": inputs["task"], "source_archive": inputs["source_archive"],
                       "recipe": inputs["recipe"], "sdk": inputs["sdk"], "clang_runtime": inputs["clang_runtime"], "environment": environment})
    return result


def verify_bootstrap(args, row, context, events, j8, preflight):
    """唯一先行 C Task 必须是原 mockrt，独立核原源码/实际参数和全部 archive 对象。"""
    spec = row["bootstrap"]
    require((context.name, context.task) == (spec["name"], spec["task"]) == ("toolchain", "mockrt"), "未知先行 bootstrap")
    source = args.workspace / spec["source"]["path"]
    j8.verify_bytes(raw_file(source), spec["source"])
    library = context.install / "lib/libmockrt.a"
    raw = raw_file(library)
    members = ar_members(raw)
    require(len(members) == 1 and members[0][0] == "mockrt.o", "原 mockrt bootstrap 对象集合不同")
    objects = []
    for name, body in members:
        metadata = preflight.check_macho(body, "x86_64" if args.arch == "sim-x86_64" else "arm64", 2 if args.arch == "arm64" else 7)
        require(metadata["file_type"] == 1 and metadata["sdk"] in ([0, 0, 0], [14, 0, 0]), "mockrt bootstrap MH_OBJECT/SDK 不符")
        objects.append({"name": name, "bytes": len(body), "sha256": sha(body), **metadata})
    record = {"scope": "only_original_mockrt_bootstrap_before_complete_driver", "task": spec,
              "actual_source_sha256": sha(raw_file(source)), "SDK_archive_sha256": preflight.sha256(args.sdk),
              "commands": [event for event in events if event["task_name"] == context.task_name],
              "archive": {"path": str(library), "bytes": len(raw), "sha256": sha(raw), "objects": objects},
              "bootstrap_verified": True, "C_prerequisites_verified": False, **FALSE_BOUNDARIES}
    write_new(args.output / "mockrt-bootstrap.json", record)
    return record


def stage_sdk(args, preflight):
    """SDK 保留原 tar 全字节，只以已说明的 tmp/tars 变量供原 toolchain 消费。"""
    role = "device_sdk" if args.arch == "arm64" else "simulator_sdk"
    verified = preflight.check_archive(args.sdk, role)
    name = "iPhoneOS14.0.sdk.tar.gz" if args.arch == "arm64" else "iPhoneSimulator14.0.sdk.tar.gz"
    destination = args.workspace / "tmp/locked-sdk-tars" / name
    guarded(destination);destination.parent.mkdir(parents=True)
    with args.sdk.open("rb") as source, destination.open("xb") as target:
        shutil.copyfileobj(source, target, 262144)
    require(destination.stat().st_size == verified["bytes"] and preflight.sha256(destination) == verified["sha256"], "派生 SDK 原 tar 字节不同")
    return {"original_variable": str(args.workspace / "tars"), "execution_variable": str(destination.parent),
            "original_archive": str(args.sdk), "consumed_archive": str(destination), "sha256": verified["sha256"], "bytes": verified["bytes"],
            "original_task_template_unchanged": True}


def execute_tasks(args, plan, row, j8, original, tasks, inventory, preflight):
    """按原注册顺序执行限定 Task.run；完整对象/头/来源验证后才能写 C 成功收据。"""
    selected = selected_tasks(tasks, next(r for r in checked_json(HERE / "source-task-binding-plan.json", plan["locks"]["source-task-binding-plan.json"])["routes"] if r["release"] == row["release"]), row, args.arch, args.workspace)
    require(not tasks.ran_tasks and not (args.workspace / "tmp/complete").exists(), "禁止复用旧 Task/complete")
    before_functions = [t.function for t in tasks.tasks]
    method, annotators = tasks.Task.run, list(tasks.annotators)
    events, receipts, probes, bootstrap = [], [], None, None
    context_type = audited_context(original, row, args.arch, args.workspace, plan, events, args.output / "task-events.jsonl")
    for task, spec in selected:
        require(task.name in ("toolchain", "metalangle") or (probes is not None and probes["candidate"]["passed"]),
                "完整候选 driver 通过前禁止运行其他 C 家族")
        require(task.function is before_functions[spec["index"]] and tasks.Task.run is method and tasks.annotators == annotators,
                "原 Task/body/annotators 被替换")
        context = context_type("ios", args.arch, row["python"], args.workspace, argparse.Namespace(nostrip=False, sdl=False, experimental=False))
        task.run(context)
        require(context.audit_position == len(spec["operations"][args.arch]) and context.task_name in tasks.ran_tasks,
                "原 Task 操作没有完整执行")
        complete = args.workspace / "tmp/complete" / context.task_name
        raw_file(complete, 128)
        receipts.append({"index": spec["index"], "name": task.name, "task": task.task, "kind": task.kind,
                         "function_sha256": spec["function_sha256"], "task_name": context.task_name, "original_task_run_executed": True,
                         "build": str(context.build), "install": str(context.install), "operations": context.audit_position})
        if task.name == "toolchain" and task.kind == "cross":
            sdk = verify_tar_tree(args.sdk, context.install, preflight)
        if task.name == "toolchain" and task.task == "mockrt":
            bootstrap = verify_bootstrap(args, row, context, events, j8, preflight)
        if task.name == "metalangle":
            archive = args.workspace / "source" / ("MetalANGLE.framework.ios.zip" if args.arch == "arm64" else "MetalANGLE.framework.ios.simulator.zip")
            framework = verify_framework(archive, context.install, args.arch, inventory)
            probes = driver_probe(original, tasks, row, args.arch, args.workspace, plan, args.output, preflight)
    require(bootstrap is not None and probes is not None and probes["candidate"]["passed"], "缺实际 bootstrap 或候选 driver")
    require(all(t.function is before_functions[i] for i, t in enumerate(tasks.tasks)) and tasks.Task.run is method
            and tasks.annotators == annotators, "执行过程污染完整原注册表")
    prefix = args.workspace / ("tmp/install.ios-" + args.arch)
    products = verify_c_products(prefix, row, args.arch, inventory, preflight)
    write_new(args.output / "c-prefix-inventory.json", products["inventory"])
    write_new(args.output / "c-archive-objects.json", {"archives": products["archives"], "executables": products["executables"],
                                                       "object_sdk_boundary": products["object_sdk_boundary"]})
    write_new(args.output / "c-headers-and-sources.json", {"headers": products["headers"], "sources": products["sources"], "extra_inputs": row["extra_inputs"]})
    return {"prefix": str(prefix), "tasks": receipts, "commands": events, "SDK_install": sdk, "framework_install": framework,
            "driver_probes": probes, "mockrt_bootstrap": bootstrap, "all_archive_objects_verified": True,
            "inventory_sha256": sha(raw_file(args.output / "c-prefix-inventory.json")),
            "archive_objects_sha256": sha(raw_file(args.output / "c-archive-objects.json")),
            "headers_and_sources_sha256": sha(raw_file(args.output / "c-headers-and-sources.json"))}


def worker(args, plan, row, loaded):
    """仅由父管道启动真实新网络命名空间，执行前重核全部输入和宿主前端。"""
    require(stat.S_ISFIFO(os.fstat(args.worker_fd).st_mode), "worker 必须由父管道启动")
    with os.fdopen(args.worker_fd, "rb") as stream:raw = stream.read(65537)
    require(len(raw) <= 65536, "worker 协议超限")
    protocol = decode(raw)
    expected = {"parent_pid": os.getppid(), "parent_network_namespace": os.readlink("/proc/" + str(os.getppid()) + "/ns/net"),
                "plan_sha256": PLAN_SHA256, "tool_sha256": sha(raw_file(Path(__file__).absolute())),
                "release": args.release, "arch": args.arch, "workspace": str(args.workspace), "output": str(args.output)}
    require(protocol == expected and os.readlink("/proc/self/ns/net") != protocol["parent_network_namespace"], "缺真实新增内核网络隔离")
    inventory, j8, native, validator, common, preflight = loaded
    route, recipe = route_binding(plan, row, j8)
    j8.verify_repository(recipe, args.workspace)
    require(not (args.workspace / "tmp").exists(), "禁止旧 tmp/complete/目标前缀")
    commands = []
    inputs = gate_inputs(args, row, validator, common, commands)
    write_new(args.output / "input-gates.json", {"inputs": inputs, "environment_commands": commands})
    hostplan = native.load_plan(HERE / "host-python-bootstrap-plan.json")
    hostrow = next(r for r in hostplan["routes"] if r["release"] == args.release)
    frontend = native.frontend_receipt(args, hostplan, hostrow)
    host = restore_host(args, plan, row, native, inventory)
    sdk_transport = stage_sdk(args, preflight)
    original, tasks = j8.import_registry(route, args.workspace)
    products = execute_tasks(args, plan, row, j8, original, tasks, inventory, preflight)
    j8.verify_repository(recipe, args.workspace, allow_tmp=True)
    receipt = {"schema_version": 1, "task": "R00-02J9A", "scope": SCOPE, "release": args.release, "arch": args.arch,
               "plan_sha256": PLAN_SHA256, "execution_source_sha256": sha(raw_file(Path(__file__).absolute())),
               "recipe": row["recipe"], "inputs": inputs, "environment_commands": commands, "frontend": frontend, "host": host, "SDK_transport": sdk_transport,
               "kernel_network_isolation_verified": True, "original_C_tasks_verified": True, "C_prerequisites_verified": True,
               **products, **FALSE_BOUNDARIES}
    write_new(args.output / "c-prefix-receipt.json", receipt)
    return {"C_prerequisites_verified": True, "receipt": {"path": str(args.output / "c-prefix-receipt.json"),
                                                          "sha256": sha(raw_file(args.output / "c-prefix-receipt.json"))}}


def parser():
    """明确区分仅完整配方 staging 和真实 Linux C 任务执行。"""
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("command", choices=("stage", "run"))
    result.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    result.add_argument("--root", type=Path, default=ROOT)
    result.add_argument("--release", choices=RELEASES, required=True)
    result.add_argument("--arch", choices=ARCHES, required=True)
    for name in ("workspace", "output"):
        result.add_argument("--" + name, type=Path, required=True)
    for name in ("recipe-repository", "sdk", "clang-runtime", "host-prefix", "host-receipt", "host-inventory", "frontend-report", "source-cache", "tool-cache", "ccache-dir"):
        result.add_argument("--" + name, type=Path)
    for name in ("sdk-version", "deployment-target", "host-receipt-sha256", "host-inventory-sha256", "frontend-report-sha256"):
        result.add_argument("--" + name)
    result.add_argument("--worker-fd", type=int, help=argparse.SUPPRESS)
    return result


def main(argv=None):
    """Linux 缺输入失败、Mac 如实 not_run；仅完整实物 C 验证成功才写前缀收据。"""
    args = parser().parse_args(argv)
    report = {"schema_version": 1, "task": "R00-02J9A", "scope": SCOPE, "release": args.release, "arch": args.arch,
              "command": args.command, "result": "failed", "errors": [], "C_prerequisites_verified": False, **FALSE_BOUNDARIES}
    created, code = False, 1
    try:
        for name in ("plan", "root", "workspace", "output", "recipe_repository", "sdk", "clang_runtime", "host_prefix", "host_receipt", "host_inventory", "frontend_report", "source_cache", "tool_cache", "ccache_dir"):
            if getattr(args, name) is not None:guarded(getattr(args, name))
        require(not args.output.is_relative_to(args.workspace) and not args.workspace.is_relative_to(args.output), "输出与配方必须独立")
        if args.worker_fd is None:
            require(not args.output.exists(), "输出目录必须全新")
            args.output.mkdir(parents=True, mode=0o700);created = True
        else:require(args.command == "run" and args.output.is_dir(), "worker 输出无效")
        sys.pycache_prefix = str(args.output / ("unused-worker-pycache" if args.worker_fd is not None else "unused-parent-pycache"))
        plan = load_plan(args.plan);loaded = helpers(plan)
        inventory, j8, native, validator, common, preflight = loaded
        row = next(r for r in plan["routes"] if r["release"] == args.release)
        route, recipe = route_binding(plan, row, j8)
        manifest = checked_json(HERE / "source-inputs.lock.json", plan["locks"]["source-inputs.lock.json"])
        for item in manifest["repositories"]:
            protected = args.root / item["path"]
            require(not any(p == protected or p.is_relative_to(protected) or protected.is_relative_to(p)
                            for p in (args.workspace, args.output, *([args.ccache_dir] if args.ccache_dir else []))), "禁止改写原配方树")
        if args.command == "stage":
            require(args.worker_fd is None, "stage 不支持 worker")
            repository = args.recipe_repository or args.root / row["recipe"]["path"]
            guarded(repository)
            require(not any(p == repository or p.is_relative_to(repository) or repository.is_relative_to(p) for p in (args.workspace, args.output)), "不得写入显式原 Git 配方")
            j8.stage_repository(recipe, repository, args.workspace)
            report.update(result="complete_J1_recipe_staged", recipe_staged=True, recipe=row["recipe"], file_count=recipe["file_count"]);code = 0
        elif sys.platform != "linux" or platform.machine() != "x86_64":
            report.update(result="not_run", reason="需要真实固定 C1 Linux amd64；未在 Mac 执行 Linux/iOS 编译");code = 3
        else:
            required = ("sdk", "clang_runtime", "host_prefix", "host_receipt", "host_inventory", "frontend_report", "source_cache", "tool_cache",
                        "host_receipt_sha256", "host_inventory_sha256", "frontend_report_sha256")
            require(all(getattr(args, name) is not None for name in required)
                    and args.sdk_version == "14.0" and args.deployment_target == "14.0", "真实 run 缺少明确 SDK14/App14、H1 全前缀或 H0 前端输入")
            if args.worker_fd is not None:
                report.update(worker(args, plan, row, loaded), result="original_ios_C_prerequisites_verified");code = 0
            else:
                j8.verify_repository(recipe, args.workspace)
                native.frontend_receipt(args, native.load_plan(), next(r for r in native.load_plan()["routes"] if r["release"] == args.release))
                replay = importlib.import_module("replay_python_inputs")
                isolation = replay.build.Isolation("unshare")
                report["network_isolation"] = isolation.prove(sys.executable, args.output)
                cache = args.ccache_dir or args.output / "ccache";guarded(cache);cache.mkdir(parents=True, exist_ok=True)
                environment = native.clean_environment(args.output, cache)
                read_fd, write_fd = os.pipe()
                try:
                    protocol = {"parent_pid": os.getpid(), "parent_network_namespace": os.readlink("/proc/self/ns/net"),
                                "plan_sha256": PLAN_SHA256, "tool_sha256": sha(raw_file(Path(__file__).absolute())),
                                "release": args.release, "arch": args.arch, "workspace": str(args.workspace), "output": str(args.output)}
                    os.write(write_fd, json.dumps(protocol).encode());os.close(write_fd);write_fd = None
                    command = [sys.executable, "-s", "-B", str(Path(__file__).absolute()), *(argv if argv is not None else sys.argv[1:]), "--worker-fd", str(read_fd)]
                    with (args.output / "target-build.log").open("xb") as stream:
                        result = subprocess.run(isolation.command(command), env=environment, pass_fds=(read_fd,), stdout=stream, stderr=subprocess.STDOUT, timeout=14400)
                    require(result.returncode == 0, "原 C worker 失败；见独占 target-build.log；rc=" + str(result.returncode))
                finally:
                    os.close(read_fd)
                    if write_fd is not None:os.close(write_fd)
                child = decode(raw_file(args.output / "worker-report.json"))
                require(child.get("C_prerequisites_verified") is True and child.get("result") == "original_ios_C_prerequisites_verified", "worker 无完整 C 成功证明")
                report.update(result=child["result"], C_prerequisites_verified=True, receipt=child["receipt"]);code = 0
    except BaseException as error:
        if isinstance(error, KeyboardInterrupt):raise
        report["errors"].append({"type": type(error).__name__, "message": str(error)[:4000]})
    if created or args.worker_fd is not None:
        write_new(args.output / ("worker-report.json" if args.worker_fd is not None else "report.json"), report)
    log("结果=" + report["result"])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
