#!/usr/bin/env python3
"""复用固定C1与完整H1分发，在禁网Linux容器运行两份原MetalANGLE版本生成器。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import posixpath
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import types


HERE = Path(__file__).absolute().parent
DEFAULT_PLAN = HERE / "linux-graphics-metadata-ci-plan.json"
PLAN_SHA256 = "5575f006a2ddb35c66da0c3d114c933aa1aec2672f7b54bd6d2883b1b86da533"
REMOTE_RUNTIME = "/reko/j10-runtime"
REMOTE_SOURCES = "/reko/j10-sources"
REMOTE_RESULTS = "/reko/j10-results"
REMOTE_HOST = "/reko/j10-host-export"
RUNTIME_NAMES = {"run_locked_graphics_metadata.py", "graphics-metadata-generation-plan.json",
                 "materialize_graphics_inputs.py", "graphics-inputs.lock.json", "materialize_engine_inputs.py",
                 "materialize_source_inputs.py", "run_locked_host_python_tasks.py", "inventory_source_inputs.py",
                 "run_linux_host_python_bootstrap.py", "run_linux_target_python_replay.py", "run_linux_python_replay.py",
                 "preflight_environment.py", "materialize_apt_inputs.py"}


RETURN_TREE_PREFLIGHT = r'''import json,os,posixpath,stat,sys
root=sys.argv[1];member_limit,byte_limit=map(int,sys.argv[2:])
if not root.startswith('/') or root=='/' or '..' in root.split('/') or member_limit<=0 or byte_limit<=0:
 raise ValueError('返回树预检参数无效')
ancestor=root
while ancestor!='/':
 if stat.S_ISLNK(os.lstat(ancestor).st_mode):raise ValueError('返回树祖先含链接')
 ancestor=os.path.dirname(ancestor)
if not stat.S_ISDIR(os.lstat(root).st_mode):raise ValueError('返回树根不是目录')
members,directories,regular_files,symlinks,logical_bytes=1,1,0,0,0
stack=[root]
while stack:
 folder=stack.pop()
 with os.scandir(folder) as entries:
  for entry in entries:
   info=entry.stat(follow_symlinks=False);members+=1
   if members>member_limit:raise ValueError('返回树成员数超出上限')
   if stat.S_ISREG(info.st_mode):
    regular_files+=1;logical_bytes+=info.st_size
    if info.st_size<0 or logical_bytes>byte_limit:raise ValueError('返回树普通文件逻辑字节超出上限')
   elif stat.S_ISDIR(info.st_mode):directories+=1;stack.append(entry.path)
   elif stat.S_ISLNK(info.st_mode):
    symlinks+=1;target=os.readlink(entry.path)
    resolved=posixpath.normpath(posixpath.join(folder,target))
    if target.startswith('/') or not (resolved==root or resolved.startswith(root+'/')):
     raise ValueError('返回树链接逃出根目录')
   else:raise ValueError('返回树包含特殊文件')
print(json.dumps({'result':'bounded_return_tree_preflight_passed','root':root,'members':members,
 'directories':directories,'regular_files':regular_files,'symlinks':symlinks,
 'logical_bytes':logical_bytes,'max_result_members':member_limit,'max_result_bytes':byte_limit,
 'followed_symlinks':False}))
'''


class NotRun(ValueError):
    """必要真实Linux环境缺失时明确未运行，不制造成功执行记录。"""


def require(value, message):
    """输入/原命令/验证缺少证据即失败，不补默认成功。"""
    if not value:raise ValueError(message)


def log(message):
    """输出本轮真实阶段和中文失败原因。"""
    print("[RenPyLinuxGraphicsMetadata] " + message, flush=True)


def guarded(path):
    """绝对化后拒绝所有祖先链接与上跳点段。"""
    path = Path(path);require(".." not in path.parts, "路径不得上跳")
    path = path.absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), "路径含符号链接")
    return path


def raw_file(path, maximum=2 * 1024**3):
    """不跟随链接或特殊文件，按实际有界字节读取原件。"""
    with os.fdopen(os.open(guarded(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, "输入不是有界普通文件")
        raw = stream.read(maximum + 1)
    require(len(raw) == info.st_size, "原件读取期间长度变化")
    return raw


def identity(path):
    """完整实际字节身份，不使用文件名、mtime或内部成功标记代替。"""
    raw = raw_file(path);return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def unique_pairs(pairs):
    """JSON重复字段拒绝，避免身份/状态被后写覆盖。"""
    result = {}
    for key, value in pairs:
        require(key not in result, "JSON字段重复");result[key] = value
    return result


def read_json(path):
    """严格解析原JSON，不接受非有限数。"""
    def invalid(value):
        """拒绝非JSON标准的数值标记。"""
        raise ValueError("JSON非有限数：" + value)
    return json.loads(raw_file(path), object_pairs_hook=unique_pairs, parse_constant=invalid)


def write_json(path, value):
    """独占写报告，历史失败与原件不能被覆盖。"""
    with guarded(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2);stream.write("\n")


def stream_identity(path):
    """流式核普通结果文件，不将完整生成树或压缩包读入内存。"""
    require(stat.S_ISREG(path.lstat().st_mode), "结果不是普通文件")
    digest = hashlib.sha256();size = 0
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(1024**2), b""):
            digest.update(block);size += len(block)
    return {"bytes": size, "sha256": digest.hexdigest()}


def result_entries(source, limits):
    """为本轮返回树建立有界完整清单，保留目录/普通文件/内部链接且不跟随链接。"""
    source = guarded(source);require(source.is_dir(), "返回树缺失")
    paths = [source]
    for folder, directories, names in os.walk(source, followlinks=False):
        directories.sort();names.sort()
        paths.extend(Path(folder) / name for name in directories + names)
    require(len(paths) <= limits["max_result_members"], "返回结果成员超出上限")
    rows = [];total = 0
    for path in paths:
        info = path.lstat();relative = path.relative_to(source).as_posix()
        member = source.name if relative == "." else source.name + "/" + relative
        require(not member.startswith("/") and "\\" not in member
                and all(part not in ("", ".", "..") for part in member.split("/")), "归档成员路径无效")
        row = {"path": member, "mode": stat.S_IMODE(info.st_mode), "mtime": int(info.st_mtime)}
        if stat.S_ISREG(info.st_mode):
            total += info.st_size;require(total <= limits["max_result_bytes"], "返回结果总字节超出上限")
            row.update(type="file", **stream_identity(path))
        elif stat.S_ISDIR(info.st_mode):row.update(type="directory")
        else:
            require(stat.S_ISLNK(info.st_mode), "返回结果包含特殊文件")
            target = os.readlink(path);resolved = posixpath.normpath(posixpath.join(posixpath.dirname(member), target))
            require(not target.startswith("/") and (resolved == source.name or resolved.startswith(source.name + "/")), "返回链接逃出归档根")
            row.update(type="symlink", target=target, sha256=hashlib.sha256(target.encode()).hexdigest())
        rows.append(row)
    require(len({row["path"] for row in rows}) == len(rows), "返回清单成员重复")
    return rows


def verify_result_archive(archive, rows):
    """仅流式解压，校验全部成员、原字节、模式和链接，不重建第二份整树。"""
    import gzip
    expected = {row["path"]:row for row in rows};seen = set()
    with gzip.open(archive, "rb") as raw:
        with tarfile.open(fileobj=raw, mode="r|") as source:
            for item in source:
                require(item.name in expected and item.name not in seen and not item.sparse, "结果归档成员集合不同")
                row = expected[item.name];seen.add(item.name)
                require(item.mode == row["mode"] and item.mtime == row["mtime"], "结果归档元数据不同")
                if row["type"] == "directory":require(item.isdir(), "结果目录类型不同")
                elif row["type"] == "symlink":require(item.issym() and item.linkname == row["target"], "结果链接不同")
                else:
                    require(item.isfile() and item.size == row["bytes"], "结果文件类型/大小不同")
                    digest = hashlib.sha256();size = 0
                    with source.extractfile(item) as stream:
                        for block in iter(lambda:stream.read(1024**2), b""):
                            digest.update(block);size += len(block)
                    require(size == row["bytes"] and digest.hexdigest() == row["sha256"], "结果原字节归档验证失败")
        while raw.read(1024**2):pass
    require(seen == set(expected), "结果归档缺失成员")
    return {"member_count": len(seen), "all_members_stream_verified": True, "full_extraction_tree_created": False}


def archive_result_tree(source, output, family, limits):
    """有界压缩返回完整树并恢复流验真；不公开归档，不删除任何保留输入。"""
    require(re.fullmatch("metalangle-(legacy|modern)", family), "未知归档family")
    rows = result_entries(source, limits);archive = output / (family + "-complete-results.tar.gz")
    partial = archive.with_name(archive.name + ".partial")
    require(not archive.exists() and not partial.exists(), "结果归档不得覆盖")
    try:
        with tarfile.open(partial, "w:gz", compresslevel=6, format=tarfile.PAX_FORMAT) as target:
            for row in rows:
                relative = Path(row["path"]).parts[1:];path = source.joinpath(*relative)
                item = tarfile.TarInfo(row["path"]);item.mode = row["mode"];item.mtime = row["mtime"]
                if row["type"] == "directory":item.type = tarfile.DIRTYPE;target.addfile(item)
                elif row["type"] == "symlink":item.type = tarfile.SYMTYPE;item.linkname = row["target"];target.addfile(item)
                else:
                    item.size = row["bytes"]
                    with path.open("rb") as stream:target.addfile(item, stream)
                require(partial.stat().st_size <= limits["max_archive_bytes"], "压缩结果超出上限")
        require(partial.stat().st_size <= limits["max_archive_bytes"], "完整压缩结果超出上限")
        verified = verify_result_archive(partial, rows)
        with partial.open("r+b") as stream:os.fsync(stream.fileno())
        partial.rename(archive)
        result = {"archive": {"path": str(archive), **stream_identity(archive)}, "verification": verified,
                  "public_upload_performed": False, "entries": rows}
        manifest = output / (family + "-complete-results.json");write_json(manifest, result)
        with manifest.open("r+b") as stream:os.fsync(stream.fileno())
        return {"archive": result["archive"], "manifest": {"path": str(manifest), **stream_identity(manifest)},
                "verification": verified, "public_upload_performed": False}
    finally:
        if partial.exists():partial.unlink()


def preserve_small_diagnostics(source, destination, limits):
    """只保留生成/verify原报告与日志通道；异常树不成为无限制诊断副本。"""
    destination.mkdir();saved = [];total = 0
    for stage in ("generated", "verified"):
        folder = source / stage
        if not folder.is_dir() or folder.is_symlink():continue
        for path in sorted(folder.iterdir()):
            if path.is_dir():continue
            require(re.fullmatch(r"[A-Za-z0-9._-]+\.(json|stdout|stderr)", path.name), "未知诊断通道")
            expected = stream_identity(path);total += expected["bytes"]
            require(total <= limits["max_diagnostic_bytes"], "原始诊断超出保全上限")
            target = destination / (stage + "-" + path.name)
            with path.open("rb") as stream, target.open("xb") as output:shutil.copyfileobj(stream, output, 1024**2)
            require(stream_identity(target) == expected, "诊断保全过程字节不同")
            saved.append({"path": str(target), **expected})
    return saved


def copy_bounded_family_result(run, remote, destination, family, limits):
    """在cp之前核成员数、文件逻辑字节和分配块；稀疏文件及小文件洪泛不能先落盘。"""
    require(re.fullmatch("metalangle-(legacy|modern)", family), "未知取回family")
    raw, _ = run.run(["/usr/bin/python3.10", "-B", "-c", RETURN_TREE_PREFLIGHT, remote,
                      str(limits["max_result_members"]), str(limits["max_result_bytes"])], "bound-result-logical-" + family)
    value = json.loads(raw, object_pairs_hook=unique_pairs)
    keys = {"result", "root", "members", "directories", "regular_files", "symlinks", "logical_bytes",
            "max_result_members", "max_result_bytes", "followed_symlinks"}
    require(set(value) == keys and value["result"] == "bounded_return_tree_preflight_passed"
            and value["root"] == remote and value["followed_symlinks"] is False, "返回树原预检结果字段不同")
    for name in ("members", "directories", "regular_files", "symlinks", "logical_bytes", "max_result_members", "max_result_bytes"):
        require(type(value[name]) is int and value[name] >= 0, "返回树预检计数类型错误")
    require(1 <= value["members"] <= limits["max_result_members"]
            and value["directories"] >= 1
            and value["members"] == value["directories"] + value["regular_files"] + value["symlinks"]
            and value["logical_bytes"] <= limits["max_result_bytes"]
            and value["max_result_members"] == limits["max_result_members"]
            and value["max_result_bytes"] == limits["max_result_bytes"], "返回树成员数/逻辑字节未满足边界")
    raw, _ = run.run(["du", "-sk", remote], "bound-result-size-" + family)
    fields = raw.decode("utf-8").rstrip("\n").split("\t")
    require(len(fields) == 2 and re.fullmatch("[0-9]+", fields[0]) and fields[1] == remote,
            "返回树分配量输出不是原指定目录")
    allocated = int(fields[0]) * 1024
    require(allocated <= limits["max_result_bytes"], "容器返回树分配空间超出保全上限")
    run.host([run.docker, "cp", run.name + ":" + remote, str(destination)], "preserve-complete-family-" + family)
    return {**value, "allocated_bytes": allocated, "all_limits_verified_before_copy": True}


def load_plan(path=DEFAULT_PLAN):
    """只接受当前独立13原件和既有22/H1精确身份，不消费浮动旧43目录。"""
    require(identity(path)["sha256"] == PLAN_SHA256, "固定Linux图形计划字节不同")
    plan = read_json(path);rows = plan["runtime_catalog"]
    require(type(plan["schema_version"]) is int and plan["schema_version"] == 1
            and plan["task"] == "R00-02J10G-Linux" and plan["scope"] == "fixed_C1_jammy_original_two_graphics_generators_only", "计划范围不同")
    require(len(rows) == len(RUNTIME_NAMES) and {row["name"] for row in rows} == RUNTIME_NAMES, "必须是13份明确原件")
    for row in rows:
        require(set(row) == {"name", "bytes", "sha256"} and type(row["bytes"]) is int and row["bytes"] > 0
                and re.fullmatch("[0-9a-f]{64}", row["sha256"]), "工具清单字段错误")
    require(plan["environment"]["ubuntu"] == "22.04" and plan["H1_profile"]["ubuntu"] == "22.04"
            and set(plan["families"]) == {"metalangle-legacy", "metalangle-modern"}, "只允许固定22环境和两main")
    require(plan["legacy_7_8_7_only"] == {"metalangle-legacy": {**plan["families"]["metalangle-legacy"], "release": "7.8.7"}}, "额外补验仅允许7.8.7原legacy路线")
    require(plan["retention_limits"] == {"max_result_members": 32768, "max_result_bytes": 512 * 1024**2,
            "max_archive_bytes": 256 * 1024**2, "max_diagnostic_bytes": 16 * 1024**2}, "结果保全边界不同")
    require(plan["return_tree_preflight"] == {"interpreter": "/usr/bin/python3.10",
            "source_sha256": hashlib.sha256(RETURN_TREE_PREFLIGHT.encode()).hexdigest()}, "容器原返回树预检源码不同")
    return plan


def prepare_runtime(source, destination, catalog):
    """只复制13个独立原件并重新验字节，旁边其他生产工具不进入容器。"""
    source = guarded(source);destination = guarded(destination);require(not destination.exists(), "工具派生目录必须新建")
    destination.mkdir()
    for row in catalog:
        name = row["name"];require(name in RUNTIME_NAMES, "未知工具路径")
        expected = {key:row[key] for key in ("bytes", "sha256")}
        require(identity(source / name) == expected, "固定原工具改变：" + name)
        with (destination / name).open("xb") as stream:stream.write(raw_file(source / name))
        (destination / name).chmod(0o644)
        require(identity(destination / name) == expected, "工具复制期间字节改变")
    require({p.name for p in destination.iterdir()} == RUNTIME_NAMES, "实际工具集合不同")


def load_runtime(directory, plan):
    """只从已核原buffer编译依赖，不沿用宿主sys.modules缓存或任意pyc。"""
    modules = {};pins = {row["name"]:row for row in plan["runtime_catalog"]}
    order = ["inventory_source_inputs", "materialize_source_inputs", "materialize_engine_inputs",
             "materialize_graphics_inputs", "run_locked_host_python_tasks", "run_linux_python_replay",
             "run_linux_host_python_bootstrap", "run_linux_target_python_replay", "preflight_environment",
             "materialize_apt_inputs", "run_locked_graphics_metadata"]
    for name in order:
        path = directory / (name + ".py");row = pins[path.name]
        require(identity(path) == {key:row[key] for key in ("bytes", "sha256")}, "固定执行工具不同")
        raw = raw_file(path);module = types.ModuleType(name);module.__file__ = str(path);module.__package__ = ""
        sys.modules[name] = module;exec(compile(raw, str(path), "exec"), module.__dict__);modules[name] = module
    return modules


def verify_host_export(modules, artifact, plan):
    """用原H1读取器核完整原ZIP内CP27收据、分发和4739成员tar，不执行ELF。"""
    profile = plan["H1_profile"];header = read_json(artifact / "linux-host-python-bootstrap-report.json")
    require(header["ubuntu"] == "22.04" and header["sdk_inputs_consumed"] is False
            and header["execution_h1_tool_sha256"] == profile["execution_source_sha256"]
            and header["execution_h1_plan_sha256"] == profile["execution_plan_sha256"]
            and header["H1_plan_sha256"] == profile["execution_plan_sha256"]
            and header["addon_h1_plan_sha256"] == profile["addon_plan_sha256"], "H1原producer profile不同")
    folder = artifact / "container/host-7.8.7";approved = plan["legacy_H1"]
    require(identity(folder / "host-receipt.json") == approved["receipt"]
            and identity(folder / "host-distribution.json") == approved["inventory"], "H1原receipt/inventory改变")
    frontend_sha = identity(artifact / "container/python-replay/report.json")["sha256"]
    result = modules["run_linux_host_python_bootstrap"].verify_export(modules["run_linux_python_replay"], folder, "7.8.7", frontend_sha)
    export = read_json(folder / "host-export.json");fixed = plan["host_archive"]
    require(result["archive"] == {key:fixed[key] for key in ("path", "bytes", "sha256")}
            and export["member_count"] == fixed["member_count"]
            and result["prefix"] == approved["original_prefix"], "原H1完整分发/配置前缀不同")
    return folder, result


def verify_inputs(args, plan, output, report, scratch):
    """真实复核固定APT、原H1 ZIP与六完整Git源；不将跨平台字节门禁记作Linux执行。"""
    runtime = scratch / "runtime";prepare_runtime(args.runtime_dir, runtime, plan["runtime_catalog"])
    modules = load_runtime(runtime, plan);apt = modules["materialize_apt_inputs"];h2 = modules["run_linux_target_python_replay"]
    verification = apt.verify_bundle(guarded(args.bundle), plan["environment"]["manifest_sha256"])
    require(verification["result"] == "passed", "固定APT原字节复核失败")
    manifest = apt.read_json(guarded(args.bundle) / "manifest.json")
    require(all(manifest[key] == plan["environment"][key] for key in ("ubuntu", "image", "image_id")), "APT不是固定C1历史环境")
    write_json(output / "apt-byte-verification.json", verification)
    approved = plan["H1_profile"]["artifact"]
    h2.verify_h1_artifact(guarded(args.h1_artifact), approved["sha256"], approved["bytes"])
    artifact = scratch / "H1-original";h2.extract_h1_zip(guarded(args.h1_artifact), artifact)
    folder, host = verify_host_export(modules, artifact, plan);write_json(output / "H1-byte-verification.json", host)
    graphics = modules["materialize_graphics_inputs"];lock, _ = graphics.load_lock(runtime / "graphics-inputs.lock.json")
    sources = verify_sources(graphics, guarded(args.source_cache), lock, args.fetch_missing_sources, output)
    write_json(output / "six-original-Git-inputs.json", sources)
    report.update(inputs_verified=True, H1_original_ZIP=approved, runtime_file_count=len(plan["runtime_catalog"]),
                  original_Git_source_count=len(sources), source_cache_modified_only_if_explicit_fetch=args.fetch_missing_sources)
    return modules, manifest, folder, lock, runtime


def verify_sources(graphics, cache, lock, fetch, output):
    """缺项仅显式宿主fetch可获取；已有坏缓存立即拒绝，不联网替换或降级。"""
    if fetch:cache.mkdir(parents=True, exist_ok=True)
    require(cache.is_dir(), "六源实际Git缓存缺失")
    sources = []
    for source in lock["sources"]:
        path = graphics.inputs.cache_path(cache, source["cache_path"])
        if fetch and not path.exists():graphics.fetch_source(path, source, output / (source["id"] + "-transport"))
        sources.append(graphics.verify_source(path, source));log("已核完整Git源：" + source["id"])
    return sources


def require_linux():
    """仅Linux amd64上允许实际Docker/ELF执行，Mac缺环境明确非零。"""
    if sys.platform != "linux" or platform.machine() not in ("x86_64", "amd64"):raise NotRun("真实执行需要Linux amd64 host及Docker")
    docker = shutil.which("docker")
    if docker is None:raise NotRun("真实执行缺少Docker运行时")
    return docker


def restore_host(run, modules, folder, runtime, plan):
    """复用原H2完整恢复/PRODUCT_PROBE/稳定ldd门禁；不复制单个python冒充分发。"""
    names = ("host-receipt.json", "host-distribution.json", "host-export.json", "host-distribution.tar.gz")
    for name in names:run.copy(folder / name, REMOTE_HOST + "/" + name, "copy-original-host-" + name)
    run.checksum("original-host", [(identity(folder / name)["sha256"], REMOTE_HOST + "/" + name) for name in names])
    h2 = modules["run_linux_target_python_replay"];pins = {r["name"]:r["sha256"] for r in plan["runtime_catalog"]}
    raw, _ = run.run(["/usr/bin/python3.10", "-B", "-c", h2.RESTORE_HOST, "7.8.7", REMOTE_HOST, REMOTE_RUNTIME,
                      pins["run_locked_host_python_tasks.py"], pins["inventory_source_inputs.py"]], "restore-original-H1-and-probe")
    value = json.loads(raw);approved = plan["legacy_H1"]
    require(value["full_distribution_reverified"] is True and value["stable_dynamic_dependency_identity_verified"] is True
            and value["sha256"] == approved["interpreter_sha256"] and value["original_receipt_sha256"] == approved["receipt"]["sha256"]
            and value["prefix"] == approved["original_prefix"] and value["distribution_members"] == plan["host_archive"]["member_count"]
            and value["runtime"]["version"] == "2.7.18" and value["runtime"]["platform"] == "linux2"
            and value["runtime"]["machine"] == "x86_64" and value["runtime"]["prefix"] == approved["original_prefix"], "原H1实际恢复/探针/依赖门禁不符")
    return value


def generator_argv(family, row):
    """仅固定两原脚本的既有J10G CLI，不提供任意执行后钩子。"""
    remote = REMOTE_RESULTS + "/" + family
    argv = ["/usr/bin/python3.10", "-B", REMOTE_RUNTIME + "/run_locked_graphics_metadata.py", "generate",
            "--support-dir", REMOTE_RUNTIME, "--release", row["release"], "--pristine", REMOTE_SOURCES + "/" + family + "/MetalANGLE",
            "--output", remote + "/generated"]
    if family == "metalangle-legacy":argv += ["--legacy-prefix", "/reko/h1-workspaces/7.8.7/tmp/host",
        "--legacy-receipt", REMOTE_HOST + "/host-receipt.json", "--legacy-inventory", REMOTE_HOST + "/host-distribution.json"]
    else:require(family == "metalangle-modern", "未知生成family")
    return argv


def selected_families(plan, legacy_7_8_7_only=False):
    """默认完整保留原两family；显式补验只选固定7.8.7 legacy，不开放任意版本。"""
    return plan["legacy_7_8_7_only"] if legacy_7_8_7_only else plan["families"]


def verify_returned(run, runtime, source, directory, release, output, original_receipt_sha256):
    """宿主仅执行固定Python读取器，逐源/全Git/唯一header验证，不执行回传ELF。"""
    receipt = directory / "generated/generation-receipt.json";expected = identity(receipt)["sha256"]
    require(re.fullmatch("[0-9a-f]{64}", original_receipt_sha256) and expected == original_receipt_sha256, "回传receipt与容器原命令SHA不同")
    argv = [sys.executable, "-I", "-B", str(runtime / "run_locked_graphics_metadata.py"), "verify", "--support-dir", str(runtime),
            "--release", release, "--pristine", str(source), "--workspace", str(directory / "generated/derived"),
            "--receipt", str(receipt), "--receipt-sha256", expected, "--output", str(output)]
    run.host(argv, "verify-returned-" + release)
    generated = read_json(directory / "generated/report.json");verified = read_json(output / "report.json")
    remote_verified = read_json(directory / "verified/report.json")
    require(generated["result"] == "selected_original_header_generated" and generated["generator_executed_here"] is True
            and generated["derived_bytes_verified"] is True and generated["R00_ready"] is False
            and verified["result"] == remote_verified["result"] == "selected_derived_header_bytes_verified"
            and verified["derived_bytes_verified"] is True and verified["generator_executed_here"] is False
            and remote_verified["generator_executed_here"] is False, "实际生成/双端只读验证范围错误")
    return {"original_receipt": {"path": str(receipt), **identity(receipt)}, "returned_full_tree_verified": True,
            "host_verifier_executed_returned_ELF": False}


def execute_families(run, modules, runtime, sources, plan, report, scratch, legacy_7_8_7_only=False):
    """按固定选择执行原生成器；默认两family独立推进，补验只保全7.8.7，不制造receipt。"""
    local = scratch / "results";local.mkdir();rows = [];report["families"] = rows
    for family, row in selected_families(plan, legacy_7_8_7_only).items():
        record = {"family": family, "release": row["release"], "result": "failed", "generator_verified": False, "original_results_retrieved": False, "original_results_preserved": False, "errors": []};rows.append(record)
        remote = REMOTE_RESULTS + "/" + family
        try:
            run.run(["mkdir", "-p", remote], "prepare-result-" + family)
            run.run(generator_argv(family, row), "original-generator-" + family)
            raw, _ = run.run(["sha256sum", remote + "/generated/generation-receipt.json"], "original-receipt-hash-" + family)
            digest = raw.decode().split()[0];require(re.fullmatch("[0-9a-f]{64}", digest), "原receipt实际SHA无效")
            record["container_original_receipt_sha256"] = digest
            run.run(["/usr/bin/python3.10", "-B", REMOTE_RUNTIME + "/run_locked_graphics_metadata.py", "verify", "--support-dir", REMOTE_RUNTIME,
                     "--release", row["release"], "--pristine", REMOTE_SOURCES + "/" + family + "/MetalANGLE",
                     "--workspace", remote + "/generated/derived", "--receipt", remote + "/generated/generation-receipt.json",
                     "--receipt-sha256", digest, "--output", remote + "/verified"], "container-verify-" + family)
        except Exception as error:record["errors"].append({"stage": "original-generator-or-container-verify", "kind": type(error).__name__, "message": str(error)})
        finally:
            try:
                record["return_tree_preflight"] = copy_bounded_family_result(run, remote, local / family, family, plan["retention_limits"])
                record["original_results_retrieved"] = True
            except Exception as error:record["errors"].append({"stage": "preserve", "kind": type(error).__name__, "message": str(error)})
        if not record["errors"]:
            try:
                record.update(verify_returned(run, runtime, sources[family], local / family, row["release"], run.output.parent / ("verified-returned-" + family), record["container_original_receipt_sha256"]))
            except Exception as error:record["errors"].append({"stage": "returned-verification", "kind": type(error).__name__, "message": str(error)})
        if (local / family).is_dir():
            try:
                record["diagnostics"] = preserve_small_diagnostics(local / family, run.output.parent / ("diagnostics-" + family), plan["retention_limits"])
                record["complete_results_retention"] = archive_result_tree(local / family, run.output.parent, family, plan["retention_limits"])
                record["original_results_preserved"] = True
            except Exception as error:record["errors"].append({"stage": "archive-and-diagnostics", "kind": type(error).__name__, "message": str(error)})
        if not record["errors"]:
            record.update(result="passed", generator_verified=True)
        log(family + " 结果=" + record["result"])
    report["families"] = rows
    if legacy_7_8_7_only:
        require(len(rows) == 1 and rows[0]["release"] == "7.8.7" and rows[0]["generator_verified"] is True, "7.8.7原legacy生成器未实际验证")
    else:
        require(len(rows) == 2 and all(row["generator_verified"] is True for row in rows), "两原生成器未全部实际验证")


def execute(args, plan, output, report, verified, scratch):
    """同一无网C1 lifetime恢复H1并运行版本脚本；finally保留命令总表且关闭容器。"""
    docker = require_linux();modules, manifest, folder, lock, runtime = verified
    graphics = modules["materialize_graphics_inputs"];source_root = scratch / "sources";source_root.mkdir();sources = {}
    legacy_7_8_7_only = getattr(args, "legacy_7_8_7_only", False)
    for family in selected_families(plan, legacy_7_8_7_only):
        source = source_root / family / "MetalANGLE"
        graphics.materialize_route(guarded(args.source_cache), source, lock, family);sources[family] = source
    container = output / "container";container.mkdir();run = modules["preflight_environment"].EnvironmentRun(modules["materialize_apt_inputs"], container, docker)
    c0 = modules["preflight_environment"]
    try:
        before = c0.prepare_container(run, guarded(args.bundle), manifest, report)
        c0.install_packages(run, guarded(args.bundle), manifest, before, report)
        run.run(["mkdir", "-p", REMOTE_RUNTIME, REMOTE_SOURCES, REMOTE_RESULTS, REMOTE_HOST], "j10-directories")
        run.copy(str(runtime) + "/.", REMOTE_RUNTIME, "copy-thirteen-fixed-tools")
        run.checksum("j10-runtime", [(row["sha256"], REMOTE_RUNTIME + "/" + row["name"]) for row in plan["runtime_catalog"]])
        for family, source in sources.items():
            target = REMOTE_SOURCES + "/" + family
            run.run(["mkdir", "-p", target], "prepare-source-" + family)
            run.copy(source, target + "/MetalANGLE", "copy-complete-original-source-" + family)
        host = restore_host(run, modules, folder, runtime, plan);write_json(output / "actual-restored-H1.json", host)
        report["actual_H1_restored_and_probed"] = True
        execute_families(run, modules, runtime, sources, plan, report, scratch, legacy_7_8_7_only)
    finally:
        original_error_pending = sys.exc_info()[0] is not None
        try:run.close();report["container_closed"] = True
        except Exception as error:
            report["cleanup_error"] = {"kind": type(error).__name__, "message": str(error)}
            if not original_error_pending:raise
    if legacy_7_8_7_only:
        report.update(actual_linux_execution_verified=True, legacy_original_generator_verified=True,
                      legacy_7_8_7_original_generator_verified=True, modern_original_generator_verified=False,
                      two_original_families_verified=False, modern_execution_state="not_run_in_this_invocation")
    else:
        report.update(actual_linux_execution_verified=True, legacy_original_generator_verified=True, modern_original_generator_verified=True)


def parser():
    """只允许输入字节复核或固定22真实执行，无SDK、凭据或命令回调参数。"""
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("command", choices=("verify-inputs", "run"));result.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    result.add_argument("--runtime-dir", type=Path, default=HERE);result.add_argument("--source-cache", type=Path, required=True)
    result.add_argument("--h1-artifact", type=Path, required=True);result.add_argument("--bundle", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True);result.add_argument("--fetch-missing-sources", action="store_true")
    result.add_argument("--legacy-7-8-7-only", action="store_true", help="仅run允许：单独补验固定7.8.7 legacy原生成器，不重复modern")
    return result


def main(argv=None):
    """每轮新报告，输入通过与Linux实际完成分列，缺环境及失败非零。"""
    args = parser().parse_args(argv);created = False;output = None
    report = {"task": "R00-02J10G-Linux", "command": args.command, "result": "failed", "errors": [], "families": [],
              "inputs_verified": False, "actual_linux_execution_verified": False, "actual_H1_restored_and_probed": False,
              "legacy_original_generator_verified": False, "modern_original_generator_verified": False, "container_closed": False,
              "local_temporary_workspaces": "not_created",
              "SDK_inputs_consumed": False, "H0_or_pip_replayed": False, "Xcode_or_engine_or_B_make_executed": False, "R00_ready": False}
    if args.legacy_7_8_7_only:
        report.update(execution_scope="legacy_7_8_7_only", selected_routes=["7.8.7"],
                      legacy_7_8_7_original_generator_verified=False, two_original_families_verified=False,
                      modern_execution_state="not_run_in_this_invocation")
    try:
        require(not args.legacy_7_8_7_only or args.command == "run", "7.8.7单独补验只允许run，不能标记输入预检为执行")
        output = guarded(args.output)
        require(not output.exists() and output.parent.is_dir(), "输出必须独占新目录")
        for path in (args.runtime_dir, args.source_cache, args.h1_artifact, args.bundle):
            path = guarded(path);require(not output.is_relative_to(path) and not path.is_relative_to(output), "输出须与全部原输入分离")
        output.mkdir(mode=0o700);created = True;plan = load_plan(args.plan);report.update(plan_sha256=PLAN_SHA256, execution_tool=identity(Path(__file__)))
        if args.command == "run":require_linux()
        try:
            with tempfile.TemporaryDirectory(prefix=".j10-work-", dir=output) as name:
                report["local_temporary_workspaces"] = "created"
                scratch = guarded(name);verified = verify_inputs(args, plan, output, report, scratch)
                if args.command == "run":execute(args, plan, output, report, verified, scratch)
        finally:
            if report["local_temporary_workspaces"] == "created":
                report["local_temporary_workspaces"] = "cleanup_failed" if any(output.glob(".j10-work-*")) else "removed"
        require(report["local_temporary_workspaces"] == "removed", "本轮临时物化尚未回收")
        if args.command == "run" and args.legacy_7_8_7_only:
            report["result"] = "legacy_7_8_7_original_generator_actually_verified_on_Linux"
        else:
            report["result"] = "two_original_generators_actually_verified_on_Linux" if args.command == "run" else "fixed_input_bytes_verified_only"
    except NotRun as error:report.update(result="not_run");report["errors"].append({"kind": "NotRun", "message": str(error)})
    except Exception as error:report["errors"].append({"kind": type(error).__name__, "message": str(error)})
    if created:write_json(output / "report.json", report)
    log("结果=" + report["result"])
    return 3 if report["result"] == "not_run" else 0 if report["result"] in ("fixed_input_bytes_verified_only", "two_original_generators_actually_verified_on_Linux", "legacy_7_8_7_original_generator_actually_verified_on_Linux") else 1


if __name__ == "__main__":
    raise SystemExit(main())
