#!/usr/bin/env python3
"""执行原 iOS C 前置任务；显式 target-install 在同 worker 衔接原 Python 安装，不运行 pip Task。"""

from __future__ import annotations

import argparse
import ast
import difflib
import fnmatch
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
PLAN_SHA256 = "b8436c30ab5eaa5db96ae232d030a1409556293c2e109330e0d5177d9fea7c0d"
SCOPE = "four_approved_routes_original_ios_C_prerequisites_only"
TARGET_SCOPE = "same_C1_worker_original_four_target_Python_install_tasks_only"
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
                          "candidate_adaptations", "routes", "limitations", "target_install"}
            and type(plan["schema_version"]) is int and plan["schema_version"] == 1
            and plan["task"] == "R00-02J9A" and plan["scope"] == SCOPE, "计划范围错误")
    require(len(plan["routes"]) == 4 and {r["release"] for r in plan["routes"]} == set(RELEASES)
            and set(plan["host_producers"]) == set(RELEASES), "必须固定四路线和各自 host 产物")
    target = plan["target_install"]
    require(set(target) == {"task", "scope", "C_base_provenance", "routes", "limitations", "framework_link_candidate"}
            and target["task"] == "R00-02J9B" and target["scope"] == TARGET_SCOPE
            and len(target["routes"]) == 4 and {r["release"] for r in target["routes"]} == set(RELEASES), "target-install 计划范围错误")
    for row in target["routes"]:
        require([s["task"] for s in row["tasks"]] == ["unpack", "patch_posix", "patch_ios", "build_ios"]
                and row["expected_make_ensurepip"] == ("upgrade" if row["release"] == "8.3.7" else "no"), "原 Python Task/隐含 ensurepip 范围错误")
        candidate = row.get("build_context_candidate")
        if row["release"] == "8.3.7":
            require(isinstance(candidate, dict) and set(candidate) == {"scope", "task_function_sha256", "common_function_sha256",
                    "configure_template", "configure_ac", "original_cross_wrapper_fragment", "original_PYTHON_FOR_BUILD_template",
                    "candidate_PYTHON_FOR_BUILD", "candidate_configure_argument", "effective_make_ensurepip", "configure_discovery_name", "reason",
                    "makefile_template", "original_install_ensurepip_fragment"}
                    and candidate["scope"] == "CP39_original_configure_cross_wrapper_and_explicit_no_implicit_ensurepip"
                    and candidate["task_function_sha256"] == row["tasks"][-1]["function_sha256"]
                    and candidate["common_function_sha256"] == row["original_helper_functions"][0]["function_sha256"]
                    and candidate["candidate_PYTHON_FOR_BUILD"] == "" and candidate["effective_make_ensurepip"] == "no"
                    and candidate["candidate_configure_argument"] == "--with-ensurepip=no"
                    and candidate["configure_discovery_name"] == "python3.9"
                    and candidate["original_PYTHON_FOR_BUILD_template"] == "{{ host }}/bin/python3", "CP39 明确构建上下文候选错误")
            require(all(candidate["configure_template"] == next(o[1] for o in row["tasks"][-1]["operations"][arch] if o[0] == "run")
                        for arch in ARCHES), "CP39 原 configure 模板不同")
        else:
            require(candidate is None, "不允许对其他三路线添加 CP39 上下文候选")
    framework = target["framework_link_candidate"]
    require(set(framework) == {"scope", "releases", "already_complete_releases", "reason", "routes"}
            and framework["scope"] == "B_build_ios_only_exact_MetalANGLE_framework_search"
            and framework["releases"] == ["8.4.1", "8.3.7", "7.8.7"] and framework["already_complete_releases"] == ["8.5.3"]
            and set(framework["routes"]) == set(RELEASES), "B框架搜索候选范围错误")
    for row in plan["routes"]:
        source = framework["routes"][row["release"]]
        specification = next(s for s in target["routes"] if s["release"] == row["release"])
        require(source["annotator"] == row["flag_sources"]["metalangle_annotator"]
                and source["build_task_sha256"] == specification["tasks"][-1]["function_sha256"]
                and all(source["configure_template"] == next(o[1] for o in specification["tasks"][-1]["operations"][arch] if o[0] == "run") for arch in ARCHES),
                "B框架搜索的原注解/Task/命令身份不同")
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
    """按已锁原片段和独立LLVM15/18分组施加候选，不修改原源码或语言标准。"""
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
    if row["release"] in plan["candidate_adaptations"]["llvm18_platform"]["releases"]:
        config = plan["candidate_adaptations"]["llvm18_platform"]
        require(shlex.split(updated["CC"])[:2] == ["ccache", "clang-18"] and "-platform_version" not in " ".join(updated.values()),
                "LLVM18原driver必须是精确ccache clang-18，且不能重复施加候选")
        suffix = " -Wl,-platform_version," + config["platform_by_arch"][arch] + "," + config["minimum_by_arch"][arch] + ",14.0"
        updated["LDFLAGS"] += suffix
        changes.append({"candidate": "llvm18_platform", "source": row["flag_sources"]["run_source"],
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
        records[label]["commands_passed"] = len(records[label]["commands"]) == 2 and all(c["returncode"] == 0 for c in records[label]["commands"])
        records[label]["passed"] = False
        if records[label]["commands_passed"]:
            try:
                for kind, path in (("object", obj), ("executable", executable)):
                    raw = raw_file(path)
                    records[label][kind] = {"sha256": sha(raw), "bytes": len(raw), **preflight.macho_identity(raw)}
                    preflight.check_macho(raw, cpu, target, kind == "executable")
                records[label]["passed"] = True
            except Exception as error:
                # 原命令成功但SDK/min等元数据拒绝仍是原driver失败；保留原值后继续明确候选。
                records[label]["metadata_error"] = {"type": type(error).__name__, "message": str(error)}
                log(label + " driver元数据拒绝；原值和错误保留至driver-result.json")
    write_new(output / "driver-result.json", records)
    require(records["candidate"]["passed"], "实际原 Context 候选 driver 未通过；见独占 driver-result.json")
    require(changes or records["original"]["passed"], "原 driver 失败且无批准候选")
    return records


def bzip2_candidate_sources(workspace, row, plan, j8):
    """只读取J1固定原包的Makefile和三个alias目标脚本，不能用同名自签材料替代。"""
    config = plan["candidate_adaptations"]["bzip2_relative_aliases"]
    require(row["release"] in config["releases"] and config["version"] == "1.0.8", "bzip2 alias路线/版本未批准")
    source = next(item for item in row["sources"] if item["family"] == "bzip2")
    require(source["version"] == config["version"], "bzip2原包版本不符")
    archive = workspace / source["archive"]["path"]
    j8.verify_bytes(raw_file(archive), source["archive"])
    contents = {}
    with tarfile.open(archive, "r:gz") as bundle:
        for descriptor in (config["makefile_member"], *config["target_scripts"]):
            member = bundle.getmember(descriptor["member"])
            require(member.isfile(), "bzip2候选来源不是原普通成员")
            data = bundle.extractfile(member).read()
            require(len(data) == descriptor["bytes"] and sha(data) == descriptor["sha256"], "bzip2候选原成员SHA不符")
            contents[descriptor["member"]] = data
    return source["archive"], contents


def prepare_bzip2_makefile_candidate(args, row, plan, j8):
    """四路线派生Makefile只将唯一LDFLAGS=改为?=，保持原Task及两条原链接行不变。"""
    config = plan["candidate_adaptations"]["bzip2_ldflags_environment"]
    if row["release"] not in config["releases"]:
        return None
    archive, _ = bzip2_candidate_sources(args.workspace, row, plan, j8)
    require(config["makefile_member"] == plan["candidate_adaptations"]["bzip2_relative_aliases"]["makefile_member"], "bzip2候选Makefile来源不一致")
    patch = next(item for item in row["extra_inputs"] if item["path"] == "patches/bzip2-no-tests.diff")
    require(patch == config["original_no_tests_patch"], "bzip2原no-tests补丁身份不符")
    j8.verify_bytes(raw_file(args.workspace / patch["path"]), patch)
    spec = next(item for item in row["tasks"] if (item["name"], item["task"]) == ("bzip2", "build"))
    build, _ = expected_paths(args.workspace, row, args.arch, spec)
    path = build / ("bzip2-" + config["version"]) / "Makefile";before = raw_file(path)
    require({"bytes": len(before), "sha256": sha(before)} == config["after_original_no_tests"], "bzip2原no-tests后Makefile不符")
    original, candidate = config["original_assignment"].encode(), config["candidate_assignment"].encode()
    require(original == b"LDFLAGS=\n" and candidate == b"LDFLAGS?=\n" and before.count(original) == 1
            and all(before.count(line.encode()) == 1 for line in config["link_recipes"]), "bzip2精确赋值/两链接行不同")
    after = before.replace(original, candidate, 1)
    require({"bytes": len(after), "sha256": sha(after)} == config["derived_makefile"], "bzip2派生Makefile身份不符")
    difference = "".join(difflib.unified_diff(before.decode().splitlines(keepends=True), after.decode().splitlines(keepends=True),
                                            fromfile="a/Makefile", tofile="b/Makefile"))
    require(difference == config["derived_patch"] and sha(difference.encode()) == config["derived_patch_sha256"], "bzip2精确候选补丁不符")
    with (args.output / "bzip2-makefile-before-candidate.txt").open("xb") as stream:stream.write(before)
    with (args.output / "bzip2-ldflags-candidate.diff").open("x") as stream:stream.write(difference)
    with path.open("wb") as stream:stream.write(after)
    record = {"candidate": "bzip2_ldflags_environment", "reason": config["reason"], "archive": archive,
              "original_makefile": config["makefile_member"], "original_no_tests_patch": patch,
              "before": config["after_original_no_tests"], "after": config["derived_makefile"],
              "derived_patch_sha256": config["derived_patch_sha256"], "original_Task_body_unchanged": True}
    write_new(args.output / "bzip2-makefile-candidate.json", record)
    log("已应用bzip2派生Makefile唯一LDFLAGS?=候选")
    return record


def normalize_bzip2_aliases(args, row, plan, context, j8, inventory):
    """仅四个原Makefile的精确内部绝对alias改相对，先全核原链接/目标脚本再修改。"""
    config = plan["candidate_adaptations"]["bzip2_relative_aliases"]
    archive, contents = bzip2_candidate_sources(args.workspace, row, plan, j8)
    prefix = guarded(context.install)
    require(prefix == args.workspace / ("tmp/install.ios-" + args.arch) and (context.name, context.task) == ("bzip2", "build"), "bzip2 alias前缀/Task不符")
    sources = {Path(item["member"]).name: item for item in config["target_scripts"]};changes = []
    for item in config["aliases"]:
        path = prefix / item["path"];guarded(path.parent)
        expected = str(prefix / item["target"])
        require(stat.S_ISLNK(path.lstat().st_mode) and os.readlink(path) == expected, "bzip2原alias不是精确已批准内部绝对目标")
        target = prefix / item["target"];data = raw_file(target)
        source = sources[Path(item["target"]).name]
        require(data == contents[source["member"]] and item["relative_target"] == Path(item["target"]).name, "bzip2 alias目标脚本原字节/相对名不符")
        changes.append({"path": item["path"], "original_target": expected, "relative_target": item["relative_target"], "target_source": source})
    require(len(changes) == 4, "bzip2四原alias不完整")
    approved = {item["path"]: item["original_target"] for item in changes}
    for path in prefix.rglob("*"):
        if path.is_symlink() and Path(os.readlink(path)).is_absolute():
            require(approved.get(path.relative_to(prefix).as_posix()) == os.readlink(path), "bzip2候选拒绝未知绝对链接")
    inventory.validate_links({item["path"]: item["relative_target"] for item in changes})
    for item in changes:
        path = prefix / item["path"];path.unlink();path.symlink_to(item["relative_target"])
    record = {"candidate": "bzip2_relative_aliases", "reason": config["reason"], "archive": archive,
              "original_makefile": config["makefile_member"], "links": changes, "only_explicit_internal_aliases_normalized": True,
              "C_prerequisites_verified": False}
    write_new(args.output / "bzip2-alias-normalization.json", record)
    log("已将bzip2四个已批准内部alias规范为相对链接")
    return record


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
    bzip2_makefile, bzip2_aliases = None, None
    context_type = audited_context(original, row, args.arch, args.workspace, plan, events, args.output / "task-events.jsonl")
    for task, spec in selected:
        require(task.name in ("toolchain", "metalangle") or (probes is not None and probes["candidate"]["passed"]),
                "完整候选 driver 通过前禁止运行其他 C 家族")
        require(task.function is before_functions[spec["index"]] and tasks.Task.run is method and tasks.annotators == annotators,
                "原 Task/body/annotators 被替换")
        if (task.name, task.task) == ("bzip2", "build"):
            bzip2_makefile = prepare_bzip2_makefile_candidate(args, row, plan, j8)
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
        if (task.name, task.task) == ("bzip2", "build"):
            bzip2_aliases = normalize_bzip2_aliases(args, row, plan, context, j8, inventory)
    require(bootstrap is not None and probes is not None and probes["candidate"]["passed"], "缺实际 bootstrap 或候选 driver")
    require(bzip2_aliases is not None, "缺四个原bzip2内部alias的明确规范记录")
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
            "bzip2_makefile_candidate": bzip2_makefile, "bzip2_alias_normalization": bzip2_aliases,
            "inventory_sha256": sha(raw_file(args.output / "c-prefix-inventory.json")),
            "archive_objects_sha256": sha(raw_file(args.output / "c-archive-objects.json")),
            "headers_and_sources_sha256": sha(raw_file(args.output / "c-headers-and-sources.json"))}


def selected_python_tasks(tasks, route, specification, workspace, j8):
    """只选原四个 Python Task；保留完整 registry、annotators、body 和 Task.run 身份。"""
    registry, annotators, method = j8.registry_identity(tasks, workspace)
    require(registry == route["registry"] and annotators == route["annotators"] and method == route["task_run_sha256"],
            "Python 阶段原完整 registry 身份不符")
    selected = []
    for spec in specification["tasks"]:
        task = tasks.tasks[spec["index"]]
        require((task.name, task.task, task.kind) == (spec["name"], spec["task"], "python")
                and registry[spec["index"]]["function_sha256"] == spec["function_sha256"] and not task.always,
                "Python 原 Task/kind/函数不符")
        selected.append((task, spec))
    require([t.task for t, _ in selected] == ["unpack", "patch_posix", "patch_ios", "build_ios"], "只允许原四 Task，禁止 pip/其他任务")
    return selected


def verify_cython(frontend, specification, output):
    """从已验 H0 前端选择固定 Cython entrypoint，核脚本、shebang、真实版本和解释器。"""
    require(frontend["linux_frontend_verified"] is True and frontend["scope"] == specification["Cython"]["scope"], "Cython 缺相应真实 H0 前端")
    directory = guarded(Path(frontend["prefix"]) / "bin")
    executable = directory / "cython";raw = raw_file(executable, 65536)
    interpreter = directory / "python"
    require(executable.stat().st_mode & 0o111 and raw.splitlines()[0] == b"#!" + str(interpreter).encode()
            and Path(frontend["executable"]) == interpreter and sha(raw_file(interpreter.resolve(strict=True))) == frontend["interpreter_sha256"],
            "Cython 脚本/shebang/H0 解释器不符")
    result = subprocess.run([str(executable), "--version"], capture_output=True, timeout=120,
                            env={"PATH": str(directory) + ":/usr/bin:/bin", "LANG": "C", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"})
    text = (result.stdout + result.stderr).decode()
    versions = re.findall(r"Cython version ([0-9]+\.[0-9]+\.[0-9]+)", text)
    with (output / "target-cython.stdout").open("xb") as stream:stream.write(result.stdout)
    with (output / "target-cython.stderr").open("xb") as stream:stream.write(result.stderr)
    write_new(output / "target-cython-attempt.json", {"argv": [str(executable), "--version"], "returncode": result.returncode,
              "expected_version": specification["Cython"]["version"], "observed_versions": versions, "source_script_sha256": sha(raw),
              "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr), "target_python_install_verified": False})
    require(result.returncode == 0 and versions and set(versions) == {specification["Cython"]["version"]}, "Cython 实际版本不是该路线批准值")
    record = {**specification["Cython"], "executable": str(executable), "bytes": len(raw), "sha256": sha(raw),
              "interpreter": str(interpreter), "interpreter_sha256": frontend["interpreter_sha256"],
              "installed_RECORD_gate": frontend["sha256"], "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr),
              "actual_entrypoint_version_verified": True}
    write_new(output / "target-cython.json", record)
    return record


def captured_original_run(context, original, template, output, ordinal):
    """委托真正原 Context.run；用独占原始日志保留内部 make/ensurepip 命令与失败。"""
    path = output / ("target-python-command-" + str(ordinal).zfill(3) + ".log")
    sys.stdout.flush();sys.stderr.flush()
    saved_out, saved_error = os.dup(1), os.dup(2)
    try:
        with path.open("xb") as stream:
            os.dup2(stream.fileno(), 1);os.dup2(stream.fileno(), 2)
            original.Context.run(context, template)
    finally:
        sys.stdout.flush();sys.stderr.flush();os.dup2(saved_out, 1);os.dup2(saved_error, 2);os.close(saved_out);os.close(saved_error)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha(raw_file(path, 1024**3))}


def check_target_framework_link_binding(record, row, specification, arch, workspace, plan, makefile_raw=None, projection=None, actual_argv=None):
    """纯字节/值检查B框架候选；供离线D读回使用，不查询宿主PATH或执行回传二进制。"""
    config = plan["target_install"]["framework_link_candidate"]
    require(row["release"] in config["releases"] and arch in ARCHES, "未知B框架候选路线/架构")
    source = config["routes"][row["release"]]
    workspace = Path(workspace);prefix = workspace / ("tmp/install.ios-" + arch)
    require(workspace.is_absolute() and ".." not in workspace.parts and record["scope"] == config["scope"]
            and record["release"] == row["release"] and record["arch"] == arch and record["prefix"] == str(prefix)
            and record["source"] == source and record["reason"] == config["reason"]
            and source["build_task_sha256"] == specification["tasks"][-1]["function_sha256"], "B框架候选source/目标prefix不同")
    before, after = record["original_environment"], record["candidate_environment"]
    require(set(before) == set(after) == set(ENV_KEYS), "B框架候选环境字段不同")
    def search_flags(value):
        """仅允许原分开的-F参数，拒绝拼接、重复及其他框架搜索选项。"""
        words = shlex.split(value)
        require(not any((word.startswith("-F") and word != "-F") or word.startswith("-iframework") for word in words), "未知B框架搜索参数")
        indexes = [i for i, word in enumerate(words) if word == "-F"]
        require(all(i + 1 < len(words) for i in indexes), "B框架搜索参数截断")
        return [words[i + 1] for i in indexes]
    require(all(search_flags(before[key]) == [str(prefix)] for key in ("CFLAGS", "CXXFLAGS"))
            and not search_flags(before["LDFLAGS"]), "原B框架搜索缺失/重复/错误prefix")
    words = shlex.split(before["LDFLAGS"])
    require([words[i + 1] for i, word in enumerate(words) if word == "-framework" and i + 1 < len(words)] == ["MetalANGLE"]
            and words.count("-framework") == 1, "原B框架链接名称/数量不同")
    suffix = " -F " + str(prefix)
    require(record["append"] == suffix and after["LDFLAGS"] == before["LDFLAGS"] + suffix
            and search_flags(after["LDFLAGS"]) == [str(prefix)]
            and all(after[key] == before[key] for key in ENV_KEYS if key != "LDFLAGS"), "B框架候选修改越界或重复施加")
    archive = next(d for d in row["extra_inputs"] if d["path"] == "source/MetalANGLE.framework.ios" + (".simulator" if arch.startswith("sim-") else "") + ".zip")
    require(record["framework"]["original_archive_sha256"] == archive["sha256"]
            and record["framework"]["full_original_framework_bytes_verified"] is True, "B框架来源缺失/不同")
    result = {"candidate_environment_bound": True, "prefix": str(prefix), "source": source}
    if makefile_raw is not None:
        require(projection is not None and actual_argv is not None, "B链接闭合缺实际投影/argv")
        text = makefile_raw.decode();variable = source["configured_ldflags_variable"]
        values = re.findall(r"^" + variable + r"[ \t]*=[ \t]*(.*)$", text, re.M)
        require(values == [after["LDFLAGS"]] and text.count(source["link_recipe"]) == 1,
                "B实际Makefile未消费候选LDFLAGS或原链接规则不同")
        require(projection[variable] == after["LDFLAGS"] and projection["LDFLAGS"] == after["LDFLAGS"]
                and shlex.split(projection["LINKCC"]) == shlex.split(after["CC"]), "B真实Makefile链接变量与候选不同")
        recipe = source["link_recipe"].replace("\\\n", " ").replace("$@", projection["BUILDPYTHON"])
        require(all(key in projection and isinstance(projection[key], str) for key in re.findall(r"\$\(([A-Z_]+)\)", recipe)),
                "B真实Makefile链接投影字段缺失")
        recipe = re.sub(r"\$\(([A-Z_]+)\)", lambda match: projection[match.group(1)], recipe)
        require("$" not in recipe and actual_argv == shlex.split(recipe), "B最终真实链接argv不符合实际Makefile")
        result.update(actual_makefile_sha256=sha(makefile_raw), actual_makefile_variable=variable,
                      actual_link_argv=actual_argv, actual_link_argv_sha256=sha(json.dumps(actual_argv, separators=(",", ":")).encode()),
                      target_link_argument_binding_verified=True)
    return result


def target_framework_link_candidate(context, row, specification, arch, template, plan, j8):
    """仅在原build_ios configure点为三旧注解路线补一次B链接搜索，原C候选完全保留。"""
    config = plan["target_install"]["framework_link_candidate"];source = config["routes"][row["release"]]
    if row["release"] not in config["releases"] or template != source["configure_template"]:
        return None
    require(context.audit_spec["task"] == "build_ios" and context.audit_spec["function_sha256"] == source["build_task_sha256"], "B框架候选不是原build_ios")
    prefix = context.root / ("tmp/install.ios-" + arch)
    require(context.install == prefix and context.path("{{install}}") == prefix, "B框架实际prefix不同")
    raw = raw_file(context.cwd / source["makefile_template"]["path"])
    require(len(raw) == source["makefile_template"]["bytes"] and sha(raw) == source["makefile_template"]["sha256"], "B原Makefile.pre.in字节不同")
    before = {key: context.environ[key] for key in ENV_KEYS};after = dict(before);suffix = " -F " + str(prefix);after["LDFLAGS"] += suffix
    descriptor = next(d for d in row["extra_inputs"] if d["path"] == "source/MetalANGLE.framework.ios" + (".simulator" if arch.startswith("sim-") else "") + ".zip")
    archive = context.root / descriptor["path"];j8.verify_bytes(raw_file(archive), descriptor)
    framework = verify_framework(archive, prefix, arch, None)
    record = {"scope": config["scope"], "release": row["release"], "arch": arch, "source": source, "prefix": str(prefix),
              "original_environment": before, "candidate_environment": after, "append": suffix, "reason": config["reason"], "framework": framework}
    check_target_framework_link_binding(record, row, specification, arch, context.root, plan)
    context.environ.update(after)
    return record


def extract_target_python_link_argv(raw_log, executable):
    """纯解析原make日志中的唯一python链接命令，保留实际每个参数及原规则自然重复。"""
    require(isinstance(raw_log, bytes) and executable == "python", "未知目标Python链接日志/名称")
    commands = []
    for line in raw_log.decode(errors="replace").replace("\\\n", " ").splitlines():
        try:words = shlex.split(line)
        except ValueError:continue
        if any(words[i] == "-o" and words[i + 1] == executable for i in range(len(words) - 1)):commands.append(words)
    require(len(commands) == 1, "B最终真实解释器链接argv缺失/重复")
    return commands[0]


def verify_target_framework_link(events, row, specification, arch, workspace, plan, python_root, projection):
    """读原make实际stdout闭合链接argv；不以configure成功或静态候选存在代替链接执行。"""
    config = plan["target_install"]["framework_link_candidate"]
    if row["release"] not in config["releases"]:return None
    configurations = [e for e in events if e.get("B_framework_link_candidate") is not None]
    require(len(configurations) == 1 and configurations[0]["returncode"] == 0, "B框架候选configure未成功")
    builds = [e for e in events if e.get("operation") == "run" and e.get("template", "").strip() == "{{ make }}"]
    require(len(builds) == 1 and builds[0]["returncode"] == 0, "B缺原make成功链接事件")
    log = builds[0]["raw_command_log"];raw = raw_file(Path(log["path"]), 1024**3)
    require(len(raw) == log["bytes"] and sha(raw) == log["sha256"], "B原make链接日志字节不同")
    argv = extract_target_python_link_argv(raw, projection["BUILDPYTHON"])
    record = configurations[0]["B_framework_link_candidate"]
    binding = check_target_framework_link_binding(record, row, specification, arch, workspace, plan, raw_file(python_root / "Makefile"), projection, argv)
    return {"candidate": record, "binding": binding, "actual_make_log": log}


def cp39_configure_candidate(context, row, specification, template, plan):
    """只对已锁 CP39 原 configure 入口清空发现输入并显式禁用隐含 ensurepip。"""
    candidate = specification.get("build_context_candidate")
    if row["release"] != "8.3.7" or template != (candidate or {}).get("configure_template"):
        return template, None
    require(context.audit_spec["task"] == "build_ios" and context.audit_spec["function_sha256"] == candidate["task_function_sha256"],
            "CP39 候选不是原 build_ios 函数")
    source = raw_file(context.cwd / candidate["configure_ac"]["path"])
    require(len(source) == candidate["configure_ac"]["bytes"] and sha(source) == candidate["configure_ac"]["sha256"]
            and source.decode().count(candidate["original_cross_wrapper_fragment"]) == 1, "CP39 原补丁后 configure.ac/wrapper 字节不同")
    makefile = raw_file(context.cwd / candidate["makefile_template"]["path"])
    require(len(makefile) == candidate["makefile_template"]["bytes"] and sha(makefile) == candidate["makefile_template"]["sha256"]
            and makefile.decode().count(candidate["original_install_ensurepip_fragment"]) == 1, "CP39 原 Makefile ensurepip 条件片段不同")
    host = context.path("{{host}}")
    original = context.environ.get("PYTHON_FOR_BUILD")
    require(original == context.expand(candidate["original_PYTHON_FOR_BUILD_template"])
            and original == str(host / "bin/python3"), "CP39 原 PYTHON_FOR_BUILD 输入不同")
    forbidden = ("PYTHONHOME", "PYTHONPATH", "_PYTHON_PROJECT_BASE", "_PYTHON_HOST_PLATFORM", "_PYTHON_SYSCONFIGDATA_NAME")
    require(not any(name in context.environ for name in forbidden), "CP39 configure 继承未知 Python 交叉环境")
    discovered = shutil.which(candidate["configure_discovery_name"], path=context.environ["PATH"])
    require(discovered == str(host / "bin" / candidate["configure_discovery_name"])
            and Path(discovered).resolve(strict=True).is_relative_to(host)
            and sha(raw_file(Path(discovered).resolve(strict=True))) == plan["host_producers"][row["release"]]["interpreter_sha256"],
            "CP39 原 configure 发现的解释器不是批准 H1 原字节")
    original_argv = shlex.split(context.expand(template))
    require(not any(value.startswith("--with-ensurepip") or value.startswith("--without-ensurepip") for value in original_argv),
            "CP39 原 configure 已含未知 ensurepip 参数")
    execution_template = template + " " + candidate["candidate_configure_argument"]
    context.environ["PYTHON_FOR_BUILD"] = candidate["candidate_PYTHON_FOR_BUILD"]
    record = {"scope": candidate["scope"], "original_argv": original_argv,
              "candidate_argv": shlex.split(context.expand(execution_template)),
              "original_environment": {"PYTHON_FOR_BUILD": original},
              "candidate_environment": {"PYTHON_FOR_BUILD": context.environ["PYTHON_FOR_BUILD"]},
              "configure_ac": candidate["configure_ac"], "reason": candidate["reason"],
              "configure_discovery": {"requested": candidate["configure_discovery_name"], "path": discovered,
                  "realpath": str(Path(discovered).resolve(strict=True)), "sha256": plan["host_producers"][row["release"]]["interpreter_sha256"]},
              "original_argv_executed": False, "original_task_body_modified": False, "original_cross_wrapper_source_modified": False}
    return execution_template, record


def effective_make_ensurepip(specification):
    """原行为始终保留，只有明确 CP39 候选的实际参数采用 no。"""
    candidate = specification.get("build_context_candidate")
    return candidate["effective_make_ensurepip"] if candidate else specification["expected_make_ensurepip"]


def python_context(original, tasks, row, specification, arch, workspace, plan, cython, events, output, j8):
    """Python 原函数的窄审计 Context，逐操作绑定完整路径，不改变 Task.function/kind。"""
    specs = {(s["kind"], s["task"], s["name"]): s for s in specification["tasks"]}
    trusted_initializers = {original.Context.__init__.__code__, original.Context.set_names.__code__, *(a.__code__ for a in tasks.annotators)}
    python_root = workspace / "tmp/build" / ("python" + row["python"] + ".ios-" + arch + "-py" + row["python"]) / specification["archive"]["root"]
    descriptors = {r["path"]: r for r in [specification["template"], specification["scproxy"], *specification["patches"]]}

    class PythonContext(original.Context):
        """只为明确原函数增加身份、操作顺序、候选参数和生成材料证据。"""

        def __init__(self, *args):
            """显式接入已验证 H0 bin；原 set_names 仍按原逻辑优先放置 H1 bin。"""
            super().__init__(*args)
            self.environ["PATH"] = str(Path(cython["executable"]).parent) + ":" + self.environ["PATH"]

        def initializing(self):
            """只豁免固定原初始化/annotator 调用栈，body 的 env/var 均必须匹配计划。"""
            frame = sys._getframe(1)
            for _ in range(24):
                if frame is None:return False
                if frame.f_code in trusted_initializers:return True
                frame = frame.f_back
            return False

        def set_names(self, kind, task, name):
            """创建目录和 complete 之前拒绝未知任务、错误 Python/平台/根。"""
            require((kind, task, name) in specs and self.root == workspace and self.tmp == workspace / "tmp"
                    and self.platform == "ios" and self.arch == arch and self.python == row["python"], "Python Context 身份/根/ABI 不符")
            self.audit_spec = specs[kind, task, name];self.position = 0;self.adapted = False
            super().set_names(kind, task, name)
            self.check_paths()

        def check_paths(self):
            """重核真实 build/install/host/sdk 路径；只准当前 Python 构建目录及 Modules。"""
            build, install = expected_paths(workspace, row, arch, self.audit_spec)
            require(self.build == build and self.install == install and self.root == workspace and self.tmp == workspace / "tmp"
                    and self.platform == "ios" and self.arch == arch and self.python == row["python"]
                    and self.cwd in (build, python_root, python_root / "Modules")
                    and super().path("{{build}}") == build and super().path("{{install}}") == install
                    and super().path("{{host}}") == workspace / "tmp/host"
                    and super().path("{{cross}}") == workspace / ("tmp/cross.ios-" + arch), "Python Context 实际路径不符")

        def operation(self, operation):
            """未知原操作必须在文件写入、删除或进程启动之前拒绝。"""
            self.check_paths();operations = self.audit_spec["operations"][arch]
            require(self.position < len(operations) and operation == operations[self.position], "Python 出现未知操作或原顺序变化")
            self.position += 1

        def path(self, value):
            """所有读写路径词法和解析后均须在独立配方根内。"""
            path = super().path(value)
            require(path.is_absolute() and ".." not in path.parts and path.is_relative_to(workspace)
                    and path.resolve(strict=False).is_relative_to(workspace), "Python Context.path 逃逸")
            return path

        def var(self, name, value, expand=True):
            """body 版本、sysconfig 文件名等必须与实际原分支投影逐字一致。"""
            if hasattr(self, "audit_spec") and not self.initializing():self.operation(["var", name, value, expand])
            super().var(name, value, expand)

        def env(self, name, value):
            """保留原 body 环境投影；CP39 仅在已锁 configure 调用处显式采用候选。"""
            if hasattr(self, "audit_spec") and not self.initializing():self.operation(["env", name, value])
            super().env(name, value)

        def clean(self, value="{{build}}"):
            """unpack 仅清理本次独立 Python build，不触及 C 或 H1 前缀。"""
            self.operation(["clean", value]);require(value == "{{build}}" and self.path(value) == self.build, "Python clean 越界")
            super().clean(value)

        def chdir(self, value):
            """仅按原函数进入原 Python 根和 Modules。"""
            self.operation(["chdir", value]);require(self.path(value) in (python_root, python_root / "Modules"), "Python chdir 越界")
            super().chdir(value)

        def patch(self, value, p=1):
            """每条补丁应用之前重核 J1 blob/原字节，失败由原 patch 实现抛出。"""
            self.operation(["patch", value, p]);path = self.path("{{patches}}") / self.expand(value)
            descriptor = descriptors.get(path.relative_to(workspace).as_posix());require(descriptor is not None and p == 1, "未知 Python patch")
            j8.verify_bytes(raw_file(path), descriptor)
            super().patch(value, p)
            events.append({"operation": "patch", "task_name": self.task_name, "path": str(path), "sha256": descriptor["sha256"], "passed": True})

        def generate(self, source, destination, **kwargs):
            """原 Setup 模板完整验真后调用原 Jinja 渲染，生成文件身份单列。"""
            self.operation(["generate", source, destination]);require(not kwargs, "未知生成参数")
            path = self.path(source);require(path == workspace / specification["template"]["path"], "原 Setup 模板路径不符")
            j8.verify_bytes(raw_file(path), specification["template"]);super().generate(source, destination)
            generated = self.path(destination);body = raw_file(generated)
            events.append({"operation": "generate", "task_name": self.task_name, "source": str(path), "source_sha256": specification["template"]["sha256"],
                           "path": str(generated), "bytes": len(body), "sha256": sha(body)})

        def copy(self, source, destination):
            """只复制批准 H1 的真实解释器或 CP312 原 Linux sysconfig；目标 ELF 例外不能扩大。"""
            self.operation(["copy", source, destination]);path = self.path(source);actual = path.resolve(strict=True)
            require(actual.is_relative_to(workspace / "tmp/host"), "Python copy 来源逃逸 H1")
            body = raw_file(actual)
            expected = plan["host_producers"][row["release"]]["interpreter_sha256"] if destination.endswith("hostpython" + row["python"]) else specification["native_sysconfig_copy"]["sha256"]
            require(sha(body) == expected and self.path(destination).is_relative_to(self.install), "原 H1 copy 字节/目的路径不同")
            super().copy(source, destination)
            require(sha(raw_file(self.path(destination))) == expected, "原 copy 目的字节不同")
            events.append({"operation": "copy", "task_name": self.task_name, "source": str(actual), "destination": str(self.path(destination)), "bytes": len(body), "sha256": expected})

        def run(self, template, verbose=False, quiet=False, **kwargs):
            """保留原模板，实际候选 argv/env 独立留证，不静默改写原函数。"""
            self.operation(["run", template]);require(not verbose and not quiet and not kwargs, "未知 Python run 参数")
            if not self.adapted:
                before, after, changes = candidate_environment(self, row, arch, plan);self.environ.update(after)
                self.adaptation = {"original": before, "candidate": after, "changes": changes};self.adapted = True
            argv = shlex.split(self.expand(template));require(argv and argv[0] not in ("git", "curl", "wget", "pip", "pip3"), "拒绝未知下载或 pip Task")
            if argv[0] == "cython":
                found = shutil.which("cython", path=self.environ["PATH"])
                require(found == cython["executable"] and sha(raw_file(Path(found))) == cython["sha256"], "实际 PATH 选中非批准 Cython")
            framework_candidate = target_framework_link_candidate(self, row, specification, arch, template, plan, j8)
            execution_template, build_candidate = cp39_configure_candidate(self, row, specification, template, plan)
            if build_candidate is not None:argv = build_candidate["candidate_argv"]
            event = {"operation": "run", "task_name": self.task_name, "template": template, "argv": argv, "cwd": str(self.cwd),
                     "environment": {key: self.environ.get(key) for key in (*ENV_KEYS, "CONFIG_SITE", "PYTHON_FOR_BUILD")},
                     "candidate_parameters": self.adaptation, "returncode": None}
            if build_candidate is not None:
                event["execution_template"] = execution_template
                event["CP39_build_context_candidate"] = build_candidate
            if framework_candidate is not None:event["B_framework_link_candidate"] = framework_candidate
            events.append(event)
            with (output / "target-install-events.jsonl").open("a") as journal:journal.write(json.dumps({"phase": "start", **event}, ensure_ascii=False) + "\n")
            try:
                event["raw_command_log"] = captured_original_run(self, original, execution_template, output, len(events));event["returncode"] = 0
            except BaseException as error:
                event["returncode"] = error.code if isinstance(error, SystemExit) else type(error).__name__
                failed_log = output / ("target-python-command-" + str(len(events)).zfill(3) + ".log")
                if failed_log.is_file():event["raw_command_log"] = {"path": str(failed_log), "bytes": failed_log.stat().st_size, "sha256": sha(raw_file(failed_log, 1024**3))}
                raise
            finally:
                with (output / "target-install-events.jsonl").open("a") as journal:journal.write(json.dumps({"phase": "exit", **event}, ensure_ascii=False) + "\n")

    return PythonContext


def assert_existing_members_unchanged(before, after):
    """安装只能新增明确 Python 成员，既有完整 C 库/头/框架/链接/目录权限不可变。"""
    table = {r["path"]: r for r in after}
    require(len(table) == len(after) and all(table.get(r["path"]) == r for r in before), "原 C 前缀成员字节/权限/链接被 Python 安装改变")


def inventory_delta(before, after):
    """完整保留衍生 H1 前后的新增、删除和变化，不把 ensurepip 默认为无副作用。"""
    old, new = {r["path"]: r for r in before}, {r["path"]: r for r in after}
    return {"added": [new[k] for k in sorted(new.keys() - old.keys())], "removed": [old[k] for k in sorted(old.keys() - new.keys())],
            "changed": [{"before": old[k], "after": new[k]} for k in sorted(old.keys() & new.keys()) if old[k] != new[k]]}


def implicit_ensurepip_evidence(events, specification, host_prefix):
    """CP39须在原make成功原日志中同时证明展开调用和pip真实输出，echo本身不算执行。"""
    installs = [e for e in events if e.get("operation") == "run" and e.get("returncode") == 0
                and "install" in e.get("argv", []) and "make" in " ".join(e.get("argv", []))]
    require(len(installs) == 1 and "raw_command_log" in installs[0], "缺原 Python make install 完整日志")
    record = {"expected": specification["expected_make_ensurepip"], "make_install_log": installs[0]["raw_command_log"],
              "bundled_wheels": specification["bundled_ensurepip_wheels"], "actual_make_install_passed": True,
              "implicit_ensurepip_invocation_verified": False, "explicit_pip_Task_executed": False, "target_pip_bound": False}
    candidate = specification.get("build_context_candidate")
    if candidate:
        configurations = [event for event in events if event.get("CP39_build_context_candidate") is not None]
        require(len(configurations) == 1 and configurations[0]["returncode"] == 0
                and configurations[0]["CP39_build_context_candidate"]["candidate_argv"].count("--with-ensurepip=no") == 1,
                "CP39 缺真实成功的明确 no-ensurepip configure 候选")
        raw = raw_file(Path(installs[0]["raw_command_log"]["path"]), 1024**3)
        require(sha(raw) == installs[0]["raw_command_log"]["sha256"] and len(raw) == installs[0]["raw_command_log"]["bytes"],
                "CP39 候选 make install 日志字节不同")
        record.update(effective_expected="no", original_expected="upgrade", original_implicit_ensurepip_behavior_preserved_in_history=True,
                      candidate_configuration=configurations[0]["CP39_build_context_candidate"],
                      disabled_by_explicit_configure_candidate=True,
                      execution_prefix_scope="B 明确禁用隐含ensurepip；后续独立原pip Task尚未执行")
    elif specification["expected_make_ensurepip"] == "upgrade":
        log_path = Path(installs[0]["raw_command_log"]["path"]);raw = raw_file(log_path, 1024**3)
        require(sha(raw) == installs[0]["raw_command_log"]["sha256"] and len(raw) == installs[0]["raw_command_log"]["bytes"], "原make install日志字节变化")
        text = raw.decode(errors="replace")
        require(re.search(re.escape(str(host_prefix / "bin/python3")) + r"\s+-m\s+ensurepip", text)
                and ("Requirement already satisfied:" in text or "Successfully installed " in text or "Installing collected packages:" in text),
                "CP39 隐含 ensurepip 缺实际调用/pip输出证明，不能只信make echo")
        record.update(implicit_ensurepip_invocation_verified=True, execution_prefix_scope="原H1衍生前缀或no-op；不是显式targetpip消费", host_prefix=str(host_prefix))
    return record


def make_projection(python_root, context, output):
    """以额外只读目标导出真实 GNUmake 展开值，不修改原生成 Makefile 或执行 pip。"""
    keys = ("LIBSUBDIRS", "TESTSUBDIRS", "TEST_MODULES", "LIBDEST", "BINLIBDEST", "LIBRARY", "LDLIBRARY", "VERSION", "LDVERSION", "ABIFLAGS", "MACHDEP", "MULTIARCH",
            "SOABI", "CC", "CFLAGS", "LDFLAGS", "LDSHARED", "CONFIG_ARGS", "PYTHON_FOR_BUILD", "ENSUREPIP", "srcdir", "prefix", "PLATDIR",
            "CONFIGURE_LDFLAGS", "PY_CORE_LDFLAGS", "LINKCC", "LINKFORSHARED", "BUILDPYTHON", "BLDLIBRARY", "LINK_PYTHON_OBJS", "LIBS", "MODLIBS", "SYSLIBS", "LDLAST")
    code = "import os,json;print(json.dumps({k:os.environ['REKO_LOCKED_'+k] for k in " + repr(keys) + "}))"
    audit = output / "target-python-make-projection.mk"
    text = ".PHONY: reko_locked_projection\n" + "\n".join("export REKO_LOCKED_" + key + " := $(" + key + ")" for key in keys)
    text += "\nreko_locked_projection:\n\t@" + shlex.join([sys.executable, "-I", "-B", "-c", code]) + "\n"
    with audit.open("x") as stream:stream.write(text)
    result = subprocess.run(["make", "--no-print-directory", "-s", "-f", "Makefile", "-f", str(audit), "reko_locked_projection"],
                            cwd=python_root, env=context.environ, capture_output=True, timeout=120)
    (output / "target-python-make-projection.stdout").write_bytes(result.stdout);(output / "target-python-make-projection.stderr").write_bytes(result.stderr)
    require(result.returncode == 0, "实际 Makefile 投影失败")
    value = decode(result.stdout);require(isinstance(value, dict) and set(value) == set(keys), "Makefile 投影字段不符")
    return value


def target_macho(raw, arch):
    """核目标 archive/object/executable/bundle 的真实薄64位 Mach-O，严格区分 arm64 两平台。"""
    require(len(raw) >= 32, "Python Mach-O 头截断")
    magic, cpu, subtype, kind, count, length, _, _ = struct.unpack_from("<8I", raw)
    require(magic == 0xFEEDFACF and cpu == (0x1000007 if arch == "sim-x86_64" else 0x100000C)
            and subtype == (3 if arch == "sim-x86_64" else 0)
            and kind in (1, 2, 6, 8) and count <= length // 8 and 32 + length <= len(raw), "Python Mach-O 类型/CPU/表错误")
    offset, builds = 32, []
    for _ in range(count):
        require(offset + 8 <= 32 + length, "Python Mach-O 命令头截断")
        command, size = struct.unpack_from("<2I", raw, offset)
        require(size >= 8 and size % 4 == 0 and offset + size <= 32 + length, "Python Mach-O load command 越界")
        if command == 0x32:
            require(size >= 24, "Python BUILD_VERSION 截断")
            _, _, target, minimum, sdk, tools = struct.unpack_from("<6I", raw, offset)
            require(24 + tools * 8 == size, "Python BUILD_VERSION 工具表错误")
            builds.append({"platform": target, "minimum": minimum, "sdk": sdk})
        offset += size
    require(offset == 32 + length and len(builds) == 1, "Python Mach-O 缺唯一真实 BUILD_VERSION")
    identity = builds[0]
    require(identity["platform"] == (2 if arch == "arm64" else 7) and identity["minimum"] == (0xE0000 if arch == "sim-arm64" else 0xD0000)
            and identity["sdk"] in ((0, 0xE0000) if kind == 1 else (0xE0000,)), "Python Mach-O 平台/min/SDK 不符")
    return {"cpu_type": cpu, "cpu_subtype": subtype, "file_type": kind, **identity}


def stdlib_expected_sources(python_root, projection, version):
    """按原 libinstall 规则列完整安装源文件，不以任意抽样代替 stdlib 验收。"""
    source = python_root / "Lib";found = {}
    for path in source.glob("*.py"):found[path.name] = path
    if version == "2.7.18":
        for pattern in ("*.doc", "*.egg-info"):
            for path in source.glob(pattern):
                if path.is_file():found[path.name] = path
    directories = projection["LIBSUBDIRS"].split()
    if projection["TEST_MODULES"] == "yes":directories += projection["TESTSUBDIRS"].split()
    for directory in directories:
        require(directory and not directory.startswith("/") and all(p not in ("", ".", "..") for p in directory.split("/")), "原 libinstall 目录越界")
        parent = source / directory
        if not parent.is_dir():continue
        for path in parent.iterdir():
            if path.name.startswith(".") or not path.is_file() or path.is_symlink():continue
            if any(fnmatch.fnmatch(path.name, pattern) for pattern in ("*CVS", "*.py[co]", "*.orig", "*~")):continue
            if version == "3.9.10" and fnmatch.fnmatch(path.name, "*wininst-*.exe"):continue
            found[path.relative_to(source).as_posix()] = path
    found["LICENSE.txt"] = python_root / "LICENSE"
    if "distutils/tests" in directories:found["distutils/tests/xxmodule.c"] = python_root / "Modules/xxmodule.c"
    require(found and "os.py" in found and "sysconfig.py" in found and "ssl.py" in found, "完整 stdlib 安装源集合缺失")
    return found


def verify_sysconfig_data(raw, projection):
    """只解析原生成字典，不执行目标Python代码；target配置不能被host Linux配置冒充。"""
    tree = ast.parse(raw)
    require(len(tree.body) == 1 and isinstance(tree.body[0], ast.Assign) and len(tree.body[0].targets) == 1
            and isinstance(tree.body[0].targets[0], ast.Name) and tree.body[0].targets[0].id == "build_time_vars", "sysconfig 不是单一原生成字典")
    require(isinstance(tree.body[0].value, ast.Dict), "sysconfig 不是原字典字面量")
    keys = [ast.literal_eval(key) for key in tree.body[0].value.keys]
    require(all(isinstance(key, str) for key in keys) and len(set(keys)) == len(keys), "sysconfig 字段重复/类型错误")
    values = ast.literal_eval(tree.body[0].value)
    require(isinstance(values, dict) and values.get("MACHDEP") == projection["MACHDEP"]
            and values.get("MULTIARCH", "") == projection["MULTIARCH"] and values.get("prefix") == projection["prefix"]
            and values.get("CC") == projection["CC"], "target sysconfig 使用错误host/平台/前缀/编译器配置")
    return {key: values.get(key) for key in ("MACHDEP", "MULTIARCH", "prefix", "CC", "CFLAGS", "LDFLAGS", "SOABI", "LDLIBRARY", "SIZEOF_VOID_P")}


def validate_target_symbols(raw, row):
    """真实 nm 定义集合必须包含Python入口与所有关键静态模块，不能仅验任意Mach-O壳。"""
    names = {line.split()[-1] for line in raw.decode().splitlines() if len(line.split()) >= 2 and line.split()[-1].startswith("_")
             and len(line.split()[-2]) == 1 and line.split()[-2].isalpha() and line.split()[-2].upper() != "U"}
    modules = ("_ssl", "_hashlib", "_ctypes", "_scproxy", "zlib", "bz2") if row["python"] == "2" else ("_ssl", "_hashlib", "_ctypes", "_scproxy", "zlib", "_bz2", "_lzma")
    required = {"_Py_Initialize", "_PyRun_SimpleStringFlags", "_PyImport_AppendInittab"}
    required |= {("_init" if row["python"] == "2" else "_PyInit_") + module for module in modules}
    require(required <= names, "target libpython 缺原Python API/静态模块定义：" + ",".join(sorted(required - names)))
    return {"all_defined_names": sorted(names), "required_names": sorted(required), "nm_stdout_sha256": sha(raw), "required_static_module_symbols_verified": True}


def verify_build_python(projection, context, row, plan, host_prefix):
    """核真实展开的原 cross wrapper；CP39 候选只允许原 configure 自行生成精确四变量。"""
    requested = projection["PYTHON_FOR_BUILD"];words = shlex.split(requested)
    require(words, "PYTHON_FOR_BUILD 为空")
    executable = words[-1];found = shutil.which(executable, path=context.environ["PATH"])
    require(found is not None and Path(found).resolve(strict=True).is_relative_to(host_prefix)
            and sha(raw_file(Path(found).resolve(strict=True))) == plan["host_producers"][row["release"]]["interpreter_sha256"],
            "PYTHON_FOR_BUILD 未使用批准 H1 解释器")
    details = {}
    if row["release"] == "8.3.7":
        specification = next(item for item in plan["target_install"]["routes"] if item["release"] == row["release"])
        candidate = specification.get("build_context_candidate")
        require(candidate is not None and len(words) == 5 and words[-1] == candidate["configure_discovery_name"],
                "CP39 实际 Makefile 未采用原 configure cross wrapper")
        assignments = [word.partition("=") for word in words[:-1]]
        require(all(separator and name in ("_PYTHON_PROJECT_BASE", "_PYTHON_HOST_PLATFORM", "PYTHONPATH", "_PYTHON_SYSCONFIGDATA_NAME")
                    for name, separator, value in assignments) and len({name for name, _, _ in assignments}) == 4,
                "CP39 cross wrapper 变量缺失/重复/未知")
        environment = {name: value for name, _, value in assignments}
        platform = "darwin-x86_64" if context.arch == "sim-x86_64" else "darwin-arm"
        build_dir = raw_file(context.cwd / "pybuilddir.txt", 4096).decode().strip()
        require(build_dir == "build/lib." + platform + "-3.9" and projection["srcdir"] in (".", str(context.cwd)),
                "CP39 实际 pybuilddir/srcdir 不是目标平台")
        expected = {"_PYTHON_PROJECT_BASE": str(context.cwd), "_PYTHON_HOST_PLATFORM": platform,
                    "PYTHONPATH": str(context.cwd / build_dir) + ":" + projection["srcdir"] + "/Lib",
                    "_PYTHON_SYSCONFIGDATA_NAME": "_sysconfigdata_" + projection["ABIFLAGS"] + "_" + projection["MACHDEP"] + "_" + projection["MULTIARCH"]}
        require(environment == expected and projection["MACHDEP"] == "darwin" and projection["ENSUREPIP"] == "no"
                and shlex.split(projection["CONFIG_ARGS"]).count("--with-ensurepip=no") == 1,
                "CP39 实际 cross wrapper/sysconfig/ENSUREPIP 不符合明确候选")
        makefile = raw_file(context.cwd / "Makefile")
        require(makefile.decode().count(candidate["original_install_ensurepip_fragment"]) == 1,
                "CP39 实际 Makefile 未保留原 ensurepip 条件片段")
        require(found == str(host_prefix / "bin" / candidate["configure_discovery_name"]), "CP39 Makefile PATH 换用其他 H1 名称")
        details = {"CP39_original_configure_cross_wrapper_enabled": True, "original_requested": str(host_prefix / "bin/python3"),
                   "effective_requested": requested, "cross_environment": environment, "implicit_ensurepip_disabled": True,
                   "actual_makefile_sha256": sha(makefile), "original_install_ensurepip_fragment_verified": True}
    else:
        keys = {word.split("=", 1)[0] for word in words[:-1] if "=" in word}
        expected = {"_PYTHON_PROJECT_BASE", "_PYTHON_HOST_PLATFORM", "PYTHONPATH"}
        if row["python"] == "3":expected.add("_PYTHON_SYSCONFIGDATA_NAME")
        require(expected <= keys, "原build Python cross环境未按原configure生成")
    return {"original_requested": requested, "resolved_interpreter": str(Path(found).resolve(strict=True)),
            "sha256": plan["host_producers"][row["release"]]["interpreter_sha256"], "CP39_wrapper_added": False, **details}


def verify_target_prefix(args, plan, row, specification, python_root, projection, c_inventory, inventory, native):
    """完整验 target stdlib/sysconfig/headers/libpython；仅原 H1 hostpython 是 native ELF 例外。"""
    prefix = args.workspace / ("tmp/install.ios-" + args.arch)
    records = inventory_tree(prefix, inventory);assert_existing_members_unchanged(c_inventory, records)
    stdlib = prefix / "lib" / ("python" + ".".join(row["version"].split(".")[:2]))
    require(projection["prefix"] == str(prefix) and projection["LIBDEST"] == str(stdlib) and projection["srcdir"] in (".", str(python_root)), "生成 Makefile 安装根/srcdir 不符")
    require(projection["VERSION"] == ".".join(row["version"].split(".")[:2]) and projection["ABIFLAGS"] == "", "实际 Python 版本/ABI 标记不符")
    require(projection["ENSUREPIP"] == effective_make_ensurepip(specification), "实际 make install 隐含 ensurepip 不符合原/明确候选")
    expected_sources = stdlib_expected_sources(python_root, projection, row["version"]);stdlib_records = []
    for name, source in sorted(expected_sources.items()):
        actual = stdlib / name;raw = raw_file(source)
        require(raw_file(actual) == raw, "target stdlib 源码缺失或不同：" + name)
        stdlib_records.append({"path": actual.relative_to(prefix).as_posix(), "source": str(source), "bytes": len(raw), "sha256": sha(raw)})
    config_name = "_sysconfigdata.py" if row["python"] == "2" else "_sysconfigdata_" + "_" + projection["MACHDEP"] + "_" + projection["MULTIARCH"] + ".py"
    build_dir_name = raw_file(python_root / "pybuilddir.txt", 4096).decode().strip()
    require(build_dir_name and not Path(build_dir_name).is_absolute() and ".." not in Path(build_dir_name).parts, "pybuilddir 路径错误")
    target_config = python_root / build_dir_name / config_name;target_config_raw = raw_file(target_config)
    require(raw_file(stdlib / config_name) == target_config_raw, "target sysconfig 原生成模块缺失/不同")
    target_variables = verify_sysconfig_data(target_config_raw, projection)
    header = prefix / "include" / ("python" + ".".join(row["version"].split(".")[:2]))
    require(raw_file(header / "Python.h") == raw_file(python_root / "Include/Python.h")
            and raw_file(header / "pyconfig.h") == raw_file(python_root / "pyconfig.h"), "原 Python headers/pyconfig 安装不同")
    config = raw_file(python_root / "pyconfig.h").decode()
    require(re.search(r"^#define SIZEOF_VOID_P 8$", config, re.M) and re.search(r"^#define SIZEOF_LONG 8$", config, re.M)
            and not re.search(r"^#define WORDS_BIGENDIAN(?:\s+1)?$", config, re.M), "target pyconfig 64位/字节序错误")
    library_name = "libpython" + ".".join(row["version"].split(".")[:2]) + ".a"
    library = prefix / "lib" / library_name;library_raw = raw_file(library, 1024**3)
    require(projection["LIBRARY"] == library_name and library_raw == raw_file(python_root / library_name, 1024**3), "真正 target libpython 未按原 build/install 产生")
    bridge = "bin/hostpython" + row["python"];bridge_sha = plan["host_producers"][row["release"]]["interpreter_sha256"]
    binaries, archives, bridges = [], [], []
    for record in records:
        if record["type"] != "file" or record["path"].startswith("MetalANGLE.framework/"):continue
        path = prefix / record["path"]
        with path.open("rb") as stream:magic = stream.read(8)
        if magic.startswith(b"\x7fELF"):
            require(record["path"] == bridge and record["sha256"] == bridge_sha and path.stat().st_mode & 0o111, "target 前缀出现非批准 H1 native ELF")
            bridges.append({**record, "elf": native.elf_identity(raw_file(path))})
        elif magic == b"!<arch>\n":
            objects = [{"name": name, "bytes": len(body), "sha256": sha(body), **target_macho(body, args.arch)} for name, body in ar_members(raw_file(path, 1024**3))]
            require(all(obj["file_type"] == 1 for obj in objects), "Python archive 混入非 object")
            if record["path"] not in {r["path"] for r in c_inventory}:require(path.name == library_name and record["sha256"] == sha(library_raw), "target 出现未知/错误 libpython archive")
            archives.append({"path": record["path"], "bytes": record["bytes"], "sha256": record["sha256"], "objects": objects})
        elif magic[:4] == b"\xcf\xfa\xed\xfe":binaries.append({**record, **target_macho(raw_file(path), args.arch)})
        elif path.suffix in (".so", ".dylib", ".a", ".o"):require(False, "目标 native 文件未验证：" + record["path"])
    require(len(bridges) == 1 and any(a["path"] == "lib/" + library_name for a in archives), "缺真实 libpython 或唯一 H1 bridge")
    if specification["native_sysconfig_copy"] is not None:
        descriptor = specification["native_sysconfig_copy"];path = prefix / descriptor["path"]
        require(sha(raw_file(path)) == descriptor["sha256"], "CP312 原 Linux sysconfig copy 不同")
    if specification.get("build_context_candidate"):
        require(not any(record["path"].startswith("lib/python3.9/site-packages/")
                        and record["path"] != "lib/python3.9/site-packages/README.txt" for record in records),
                "CP39 B 已出现 pip/第三方目标包，明确 no-ensurepip 候选未保持独立阶段")
    return {"inventory": records, "stdlib": stdlib_records, "target_sysconfig": {"path": str(stdlib / config_name), "sha256": sha(target_config_raw), "source": str(target_config),
            "target_variables": target_variables},
            "archives": archives, "binaries": binaries, "native_bridge": bridges[0], "target_stdlib_source_count": len(stdlib_records), "old_C_members_unchanged": True}


def execute_target_install(args, plan, row, loaded, original, tasks, frontend, c_receipt):
    """同一真实 worker 中 C 成功后执行原四任务，所有实际产物通过才创建 target 成功收据。"""
    inventory, j8, native, _, _, _ = loaded
    require(c_receipt.get("C_prerequisites_verified") is True and c_receipt.get("original_C_tasks_verified") is True
            and c_receipt.get("release") == args.release and c_receipt.get("arch") == args.arch
            and c_receipt.get("task") == "R00-02J9A" and c_receipt.get("scope") == SCOPE and c_receipt.get("recipe") == row["recipe"]
            and c_receipt.get("execution_source_sha256") == sha(raw_file(Path(__file__).absolute()))
            and c_receipt.get("plan_sha256") == PLAN_SHA256 and c_receipt.get("kernel_network_isolation_verified") is True,
            "target-install 缺同worker真实 C 前置收据")
    require(decode(raw_file(args.output / "c-prefix-receipt.json")) == c_receipt, "C 收据原始字节/传递对象不一致")
    specification = next(r for r in plan["target_install"]["routes"] if r["release"] == args.release)
    route, recipe = route_binding(plan, row, j8);j8.verify_repository(recipe, args.workspace, allow_tmp=True)
    for descriptor in (specification["whole_task_source"], specification["template"], specification["scproxy"], *specification["patches"]):
        j8.verify_bytes(raw_file(args.workspace / descriptor["path"]), descriptor)
    members = native.archive_members(args.workspace / specification["archive"]["path"], specification["archive"])
    prefix = args.workspace / ("tmp/install.ios-" + args.arch)
    c_inventory = checked_json(args.output / "c-prefix-inventory.json", c_receipt["inventory_sha256"])
    require(inventory_tree(prefix, inventory) == c_inventory, "C 完整库存未与真实成功原件相符")
    selected = selected_python_tasks(tasks, route, specification, args.workspace, j8)
    build, _ = expected_paths(args.workspace, row, args.arch, selected[0][1]);require(not build.exists(), "禁止旧 Python build/complete")
    for _, spec in selected:
        marker = args.workspace / "tmp/complete" / (spec["task"] + "-" + build.name)
        require(not marker.exists() and marker.name not in tasks.ran_tasks, "禁止伪 Python complete/ran_tasks")
    cython = verify_cython(frontend, specification, args.output)
    host_prefix = args.workspace / "tmp/host";host_before = native.host_inventory(host_prefix)
    write_new(args.output / "target-host-before.json", host_before)
    events, receipts = [], [];method = tasks.Task.run;functions = [t.function for t in tasks.tasks];annotators = list(tasks.annotators)
    Context = python_context(original, tasks, row, specification, args.arch, args.workspace, plan, cython, events, args.output, j8)
    python_root = build / specification["archive"]["root"]
    try:
        for task, spec in selected:
            require(tasks.Task.run is method and tasks.annotators == annotators and task.function is functions[spec["index"]], "原 Python body/Task.run 被改写")
            context = Context("ios", args.arch, row["python"], args.workspace, argparse.Namespace(nostrip=False, sdl=False, experimental=False));task.run(context)
            require(context.position == len(spec["operations"][args.arch]) and context.task_name in tasks.ran_tasks, "Python 原 Task 操作不完整")
            raw_file(args.workspace / "tmp/complete" / context.task_name, 128)
            if task.task == "unpack":native.verify_extracted(build, members)
            if task.task == "patch_ios":
                write_new(args.output / "target-source-after-patches.json", inventory_tree(python_root, inventory))
                generated = raw_file(python_root / "Modules/_scproxy.c")
                require(len(generated) > 1000 and b"Cython" in generated[:1000], "原 Cython 未生成真实 _scproxy.c")
                write_new(args.output / "target-scproxy-generation.json", {"source": specification["scproxy"], "Cython": cython, "generated_bytes": len(generated), "generated_sha256": sha(generated)})
            receipts.append({"index": spec["index"], "name": task.name, "task": task.task, "kind": task.kind, "function_sha256": spec["function_sha256"],
                             "task_name": context.task_name, "operations": context.position, "original_Task_run_executed": True})
        require(raw_file(python_root / "config.site", 4096).decode() == specification["config_site"], "原 config.site 实际字节不同")
        for bundled in specification["bundled_ensurepip_wheels"]:
            raw = raw_file(build / bundled["path"])
            require(len(raw) == bundled["bytes"] and sha(raw) == bundled["sha256"], "原ensurepip bundled wheel在构建中改变")
        generated_c = decode(raw_file(args.output / "target-scproxy-generation.json"))
        require(sha(raw_file(python_root / "Modules/_scproxy.c")) == generated_c["generated_sha256"], "原_scproxy生成C在make阶段改变")
        for event in events:
            if event["operation"] == "generate":require(sha(raw_file(Path(event["path"]))) == event["sha256"], "原Setup渲染被make阶段改变")
        projection = make_projection(python_root, context, args.output);write_new(args.output / "target-make-projection.json", projection)
        framework_link = verify_target_framework_link(events, row, specification, args.arch, args.workspace, plan, python_root, projection)
        if framework_link is not None:write_new(args.output / "target-framework-link-binding.json", framework_link)
        build_python = verify_build_python(projection, context, row, plan, host_prefix)
        ensurepip = implicit_ensurepip_evidence(events, specification, host_prefix)
        write_new(args.output / "target-implicit-ensurepip.json", ensurepip)
        products = verify_target_prefix(args, plan, row, specification, python_root, projection, c_inventory, inventory, native)
        major = "18" if row["release"] in ("8.5.3", "8.4.1") else "15"
        library = python_root / ("libpython" + ".".join(row["version"].split(".")[:2]) + ".a")
        nm_output = native.command(["/usr/bin/llvm-nm-" + major, "-g", "--defined-only", library])
        (args.output / "target-libpython-nm.stdout").write_bytes(nm_output)
        symbols = validate_target_symbols(nm_output, row);write_new(args.output / "target-libpython-symbols.json", symbols)
        require(tasks.Task.run is method and tasks.annotators == annotators and all(t.function is functions[i] for i, t in enumerate(tasks.tasks)), "Python 阶段污染原注册表")
        j8.verify_repository(recipe, args.workspace, allow_tmp=True)
    finally:
        write_new(args.output / "target-python-commands.json", events)
        host_after = native.host_inventory(host_prefix);write_new(args.output / "target-host-after.json", host_after)
        write_new(args.output / "target-host-delta.json", inventory_delta(host_before, host_after))
    if specification.get("build_context_candidate"):
        require(host_before == host_after, "CP39 明确 no-ensurepip 候选改变了完整 H1 衍生前缀")
    for name, value in (("target-prefix-inventory.json", products["inventory"]), ("target-stdlib-sources.json", products["stdlib"]),
                        ("target-native-products.json", {k: products[k] for k in ("archives", "binaries", "native_bridge", "target_sysconfig")})):
        write_new(args.output / name, value)
    c_reference = {"path": str(args.output / "c-prefix-receipt.json"), "sha256": sha(raw_file(args.output / "c-prefix-receipt.json"))}
    target = {"schema_version": 1, "task": "R00-02J9B", "scope": TARGET_SCOPE, "release": args.release, "arch": args.arch,
              "plan_sha256": PLAN_SHA256, "execution_source_sha256": sha(raw_file(Path(__file__).absolute())), "C_receipt": c_reference,
              "Cython": cython, "tasks": receipts, "make_projection": projection, "build_python": build_python, "config_site": specification["config_site"],
              "B_framework_link_candidate": framework_link,
              "B_framework_link_binding_sha256": sha(raw_file(args.output / "target-framework-link-binding.json")) if framework_link is not None else None,
              "original_CP39_cross_wrapper_modified": False, "CP39_build_context_candidate_used": specification.get("build_context_candidate") is not None,
              "implicit_install_ensurepip": {**ensurepip,
              "host_before_sha256": sha(raw_file(args.output / "target-host-before.json")),
              "host_after_sha256": sha(raw_file(args.output / "target-host-after.json")), "host_delta_sha256": sha(raw_file(args.output / "target-host-delta.json")),
              "explicit_pip_Task_executed": False, "target_pip_bound": False}, "old_C_members_unchanged": products["old_C_members_unchanged"],
              "target_stdlib_source_count": products["target_stdlib_source_count"], "inventory_sha256": sha(raw_file(args.output / "target-prefix-inventory.json")),
              "stdlib_sources_sha256": sha(raw_file(args.output / "target-stdlib-sources.json")), "native_products_sha256": sha(raw_file(args.output / "target-native-products.json")),
              "static_module_symbols_sha256": sha(raw_file(args.output / "target-libpython-symbols.json")),
              **FALSE_BOUNDARIES, "target_python_install_verified": True}
    write_new(args.output / "target-install-receipt.json", target)
    return {"target_python_install_verified": True, "target_receipt": {"path": str(args.output / "target-install-receipt.json"),
                                                                       "sha256": sha(raw_file(args.output / "target-install-receipt.json"))}}


def worker(args, plan, row, loaded):
    """仅由父管道启动真实新网络命名空间，执行前重核全部输入和宿主前端。"""
    require(stat.S_ISFIFO(os.fstat(args.worker_fd).st_mode), "worker 必须由父管道启动")
    with os.fdopen(args.worker_fd, "rb") as stream:raw = stream.read(65537)
    require(len(raw) <= 65536, "worker 协议超限")
    protocol = decode(raw)
    expected = {"parent_pid": os.getppid(), "parent_network_namespace": os.readlink("/proc/" + str(os.getppid()) + "/ns/net"),
                "plan_sha256": PLAN_SHA256, "tool_sha256": sha(raw_file(Path(__file__).absolute())),
                "release": args.release, "arch": args.arch, "workspace": str(args.workspace), "output": str(args.output), "phase": args.phase}
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
    result = {"C_prerequisites_verified": True, "receipt": {"path": str(args.output / "c-prefix-receipt.json"),
                                                           "sha256": sha(raw_file(args.output / "c-prefix-receipt.json"))}}
    if args.phase == "target-install":
        result.update(execute_target_install(args, plan, row, loaded, original, tasks, frontend, receipt))
    return result


def parser():
    """明确区分仅完整配方 staging 和真实 Linux C 任务执行。"""
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("command", choices=("stage", "run"))
    result.add_argument("--phase", choices=("c-prerequisites", "target-install"), default="c-prerequisites")
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
              "command": args.command, "phase": args.phase, "result": "failed", "errors": [], "C_prerequisites_verified": False, **FALSE_BOUNDARIES}
    if args.phase == "target-install":report.update(task="R00-02J9B", scope=TARGET_SCOPE)
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
            require(args.worker_fd is None and args.phase == "c-prerequisites", "stage 只消费原C完整配方，不执行target-install")
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
                report.update(worker(args, plan, row, loaded), result="original_target_python_install_verified" if args.phase == "target-install" else "original_ios_C_prerequisites_verified");code = 0
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
                                "release": args.release, "arch": args.arch, "workspace": str(args.workspace), "output": str(args.output), "phase": args.phase}
                    os.write(write_fd, json.dumps(protocol).encode());os.close(write_fd);write_fd = None
                    command = [sys.executable, "-s", "-B", str(Path(__file__).absolute()), *(argv if argv is not None else sys.argv[1:]), "--worker-fd", str(read_fd)]
                    with (args.output / "target-build.log").open("xb") as stream:
                        result = subprocess.run(isolation.command(command), env=environment, pass_fds=(read_fd,), stdout=stream, stderr=subprocess.STDOUT, timeout=14400)
                    require(result.returncode == 0, "原 C worker 失败；见独占 target-build.log；rc=" + str(result.returncode))
                finally:
                    os.close(read_fd)
                    if write_fd is not None:os.close(write_fd)
                child = decode(raw_file(args.output / "worker-report.json"))
                expected_result = "original_target_python_install_verified" if args.phase == "target-install" else "original_ios_C_prerequisites_verified"
                require(child.get("C_prerequisites_verified") is True and child.get("result") == expected_result, "worker 无所选阶段完整成功证明")
                report.update(result=child["result"], C_prerequisites_verified=True, receipt=child["receipt"])
                if args.phase == "target-install":
                    require(child.get("target_python_install_verified") is True and child.get("target_pip_bound") is False, "worker 未证明原安装/错误宣称pip绑定")
                    report.update(target_python_install_verified=True, target_receipt=child["target_receipt"])
                code = 0
    except BaseException as error:
        if isinstance(error, KeyboardInterrupt):raise
        report["errors"].append({"type": type(error).__name__, "message": str(error)[:4000]})
    if created or args.worker_fd is not None:
        write_new(args.output / ("worker-report.json" if args.worker_fd is not None else "report.json"), report)
    log("结果=" + report["result"])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
