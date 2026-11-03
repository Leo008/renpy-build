#!/usr/bin/env python3
"""固定同一C1监督原C→八image→八/十二font，统一交接/截止时间和完整宿主静态读验。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import types

HERE = Path(__file__).absolute().parent
PLAN_SHA256 = "5a613ff8ab868b8f44d9d23ff9e2cfc604dcd816c78bba4420260c202be9335c"
TASK = "R00-02J11I3"
RESULT = "single_tuple_actual_C_original_image_and_font_verified"
FALSE = {"production_shared_provider_verified": False, "G1_verified": False, "G2_verified": False,
         "Cubism_support_verified": False, "complete_engine_source_verified": False,
         "ios_session_verified": False, "R00_ready": False, "target_python_install_verified": False,
         "target_pip_bound": False, "historical_C_cache_restored": False}

# 容器新进程只生成真实C输入的交接；不导入registry，不生成marker，不调用旧消费生命周期。
CREATE_HANDOFF = r'''import hashlib,json,pathlib,sys,types
release,arch,run_id,attempt,container_id,nonce,controller_bytes,controller_sha,consumer_sha=sys.argv[1:]
runtime=pathlib.Path('/reko/j11-image-font-runtime/root/scripts/renpy');source=runtime/'run_locked_current_image_font_c_tasks.py';raw=source.read_bytes()
if hashlib.sha256(raw).hexdigest()!=consumer_sha:raise ValueError('组合消费者原件不同')
m=types.ModuleType('fixed_image_font_handoff');m.__file__=str(source);exec(compile(raw,str(source),'exec'),m.__dict__)
plan,current,current_plan,i0,ip=m.bootstrap(runtime/'current-image-font-c-task-plan.json',runtime);paths=m.fixed_paths(plan,release,arch)
c,cp,helpers=current.runtime_contract(current_plan,i0,ip,paths);inventory=helpers[0]
workspace=paths['workspace'];i0.check_owned_tree(workspace,plan['limits'])
receipt=i0.decode(i0.raw_file(paths['C_receipt']));current.C_baseline_shape(workspace,receipt,arch,i0)
control=paths['control']
if set(p.name for p in control.iterdir())!={'host-C-verification.stdout'}:raise ValueError('组合控制根不全新')
run={'github_run_id':run_id,'attempt':int(attempt),'container_id':container_id,'nonce':nonce};wid=m.root_identity(workspace)
owner={'schema_version':1,'stage':plan['handoff_contract']['stage'],'run':run,'workspace_identity':wid,'producer':plan['producer']}
before={'schema_version':1,'run':run,'workspace_identity':wid,'entries':c.inventory_tree(workspace,inventory)}
i0.write_new(paths['producer_owner'],owner);i0.write_new(paths['protected_before'],before)
controller={'path':str(paths['controller']),'bytes':int(controller_bytes),'sha256':controller_sha}
if i0.identity(paths['controller'])!={k:controller[k] for k in ('bytes','sha256')}:raise ValueError('组合控制器原件不同')
artifacts={key:i0.identity(paths[key]) for key in plan['artifacts']}
handoff={'schema_version':1,'task':plan['handoff_contract']['task'],'stage':plan['handoff_contract']['stage'],
 'release':release,'arch':arch,'run':run,'controller':controller,'consumer':{'tool':i0.identity(source),'plan_sha256':m.PLAN_SHA256,'bases':plan['bases']},
 'workspace_identity':wid,'artifacts':artifacts}
i0.write_new(control/'handoff.json',handoff)
frontend='/reko/h0-replay/'+next(r['frontend_scope'] for r in cp['routes'] if r['release']==release)+'/environment/bin/python'
if receipt['frontend']['executable']!=frontend:raise ValueError('原C前端路径不同')
print(json.dumps({'handoff':i0.identity(control/'handoff.json'),'run':run,'frontend_python':frontend}))
'''

# 宿主读验在新进程加载本控制器及52根，避免D/consumer同名helper混载；绝不执行回传产物。
HOST_READER = r'''import hashlib,pathlib,sys,types
source,source_sha,*arguments=sys.argv[1:];p=pathlib.Path(source);raw=p.read_bytes()
if hashlib.sha256(raw).hexdigest()!=source_sha:raise ValueError('宿主组合控制器身份不同')
m=types.ModuleType('fixed_image_font_host_reader');m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__)
print(__import__('json').dumps(m.verify_returned(*arguments)))
'''


class NotRun(ValueError):
    """缺真实平台或原材料就保留未运行，不能提升为编译/验收通过。"""


class Interrupted(BaseException):
    """父SIGTERM统一进入进程组、精确C1和临时输入的finally。"""


def require(value, message):
    """拒绝证据不足/固定合同不符，不用默认成功填空。"""
    if not value:
        raise ValueError(message)


def log(message):
    """只写中文阶段和结果，原密码/票据不进入日志。"""
    print("[RKLog][RenPyImageFontCI] " + message, file=sys.stderr, flush=True)


def bootstrap_bytes(path):
    """依赖加载前拒绝FIFO、所有祖先链接和超量文本。"""
    require(path.is_absolute() and ".." not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), "bootstrap路径含链接/上跳")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= 1024**2, "bootstrap不是有界普通文件")
        raw = stream.read(1024**2 + 1)
    require(len(raw) == info.st_size, "bootstrap原件读取期间改变")
    return raw


def identity_bytes(raw):
    """原字节强身份，不以重新序列化JSON替代。"""
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def load_fixed(args):
    """认证I1D宿主基础及十一文本；原D/current/I0来源仍由原基础完整门禁确认。"""
    raw = bootstrap_bytes(args.plan); require(identity_bytes(raw)["sha256"] == PLAN_SHA256, "I3计划SHA不同")
    plan = json.loads(raw); require(plan["task"] == TASK, "I3任务不同")
    basis = plan["I1D_base"]; source = bootstrap_bytes(args.image_controller)
    require(identity_bytes(source) == basis["source"] and identity_bytes(bootstrap_bytes(args.image_controller.parent / "linux-image-c-ci-plan.json")) == basis["plan"], "固定I1D宿主source/plan不同")
    base = types.ModuleType("fixed_image_font_I1D_basis"); base.__file__ = str(args.image_controller)
    exec(compile(source, str(args.image_controller), "exec"), base.__dict__)
    base_args = argparse.Namespace(**vars(args)); base_args.plan = args.image_controller.parent / "linux-image-c-ci-plan.json"
    bp, current, i0, image_plan, d, dp = base.load_fixed(base_args)
    require(plan["text_runtime_catalog"][:9] == bp["text_runtime_catalog"] and len(plan["text_runtime_catalog"]) == 11
            and plan["D"] == bp["D"] and plan["C_runtime_addon"] == bp["C_runtime_addon"], "I3改变原D/I1D材料")
    for row in plan["text_runtime_catalog"]:
        require(Path(row["path"]).name == row["path"], "文本路径不是固定basename")
        require(i0.identity(args.text_runtime_dir / row["path"], plan["limits"]["text_bytes"]) == {k: row[k] for k in ("bytes", "sha256")}, "固定十一文本不同：" + row["path"])
    source = args.text_runtime_dir / "run_locked_current_image_font_c_tasks.py"
    consumer = types.ModuleType("fixed_I3_combined_consumer"); consumer.__file__ = str(source)
    exec(compile(i0.raw_file(source), str(source), "exec"), consumer.__dict__)
    cp, _, _, ci0, cip = consumer.bootstrap(args.text_runtime_dir / "current-image-font-c-task-plan.json", args.text_runtime_dir)
    require(consumer.TASK == "R00-02J11I2" and cip == image_plan and ci0.PLAN_SHA256 == i0.PLAN_SHA256, "组合消费者实际基础不同")
    return plan, consumer, cp, current, i0, image_plan, d, dp, base, bp


def consumer_runtime(args, plan, base, bp, h0, h1, i0, metadata, rows, destination):
    """同一个物理50根仅新增I2两件成为真实52；宿主基础不塞入消费闭包。"""
    result = base.consumer_runtime(args, bp, h0, h1, i0, metadata, rows, destination)
    require(len(result) == 50 and plan["contract"]["expected_consumer_members"] == 52, "原消费50/组合52合同不同")
    for item in plan["text_runtime_catalog"][9:]:
        require(item["path"] in ("run_locked_current_image_font_c_tasks.py", "current-image-font-c-task-plan.json"), "未知消费新增原件")
        target = i0.guarded(destination / "scripts/renpy" / item["path"])
        raw = i0.raw_file(args.text_runtime_dir / item["path"], plan["limits"]["text_bytes"])
        require(identity_bytes(raw) == {k: item[k] for k in ("bytes", "sha256")}, "I2复制前原件不同")
        with target.open("xb") as stream: stream.write(raw)
        result.append({"path": "scripts/renpy/" + item["path"], **identity_bytes(raw)})
    result.sort(key=lambda v: v["path"])
    require(len(result) == 52 and len({v["path"] for v in result}) == 52, "组合实际成员数不同")
    h1.verify_runtime_root(h0, destination, result); h1.verify_runtime_root(h0, metadata, rows)
    return result


def task_name(spec, arch):
    """严格区分原host与iOS的真实marker/Task名称。"""
    return spec["task"] + "-" + spec["name"] + (".host" if spec["kind"] == "host" else ".ios-" + arch)


def task_records(specs, arch, image=False):
    """从固定原序列构造完整身份期望，不合成原执行收据。"""
    return [{**{k: spec[k] for k in ("index", "name", "task", "kind", "function_sha256")}, "task_name": task_name(spec, arch),
             "operations": len(spec["operations"][arch] if image else spec["operations"]), "original_Task_run_executed": True} for spec in specs]


def archive_objects(body, name, arch, c, i0, preflight):
    """从原ar所有成员重算CPU/platform/minOS/SDK及原字节身份。"""
    cpu, platform_id = ("x86_64" if arch == "sim-x86_64" else "arm64"), (2 if arch == "arm64" else 7)
    objects = []
    for member, raw in c.ar_members(body):
        info = preflight.check_macho(raw, cpu, platform_id)
        require(info["file_type"] == 1 and info["sdk"] in ([0, 0, 0], [14, 0, 0]), "image/font对象类型或SDK不同")
        objects.append({"name": member, **identity_bytes(raw), **info})
    require(objects, "image/font静态archive为空")
    return {"path": name, **identity_bytes(body), "object_count": len(objects), "objects": objects}


def scan_prefix(archive, entries, wanted, before_names, arch, c, i0, inventory, preflight, limits):
    """流式完整原归档及每个新ar/程序静态读验，不解包第二棵树。"""
    i0.prefix_archive(archive, entries, limits, inventory)
    table = i0.inventory_table(entries, limits); objects, executables = [], []
    cpu, platform_id = ("x86_64" if arch == "sim-x86_64" else "arm64"), (2 if arch == "arm64" else 7)
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            if not member.isfile() or member.name in before_names: continue
            with source.extractfile(member) as stream:
                head = stream.read(4)
                require(head != b"\x7fELF" and not member.name.endswith((".so", ".dylib")), "目标prefix混入host ELF/动态库")
                if member.name in wanted:
                    body = head + stream.read(limits["prefix_logical_bytes"] + 1)
                    require(len(body) == member.size, "ar原成员读取期间改变/超限")
                    objects.append(archive_objects(body, member.name, arch, c, i0, preflight))
                elif head == b"\xcf\xfa\xed\xfe":
                    body = head + stream.read(limits["prefix_logical_bytes"] + 1)
                    info = preflight.check_macho(body, cpu, platform_id, True)
                    require(len(body) == member.size and info["file_type"] == 2, "字体目标可执行类型/完整字节不同")
                    executables.append({**table[member.name], **info})
    require({v["path"] for v in objects} == set(wanted), "新archive完整集合不同")
    return sorted(objects, key=lambda v: v["path"]), executables


def elf_needed(raw, native):
    """只解析原ELF64 program/dynamic表重算NEEDED，不调用/装载回传ELF。"""
    info = native.elf_identity(raw); require(info["type"] in (2, 3), "native原件不是ELF可执行")
    offset = struct.unpack_from("<Q", raw, 32)[0]; size, count = struct.unpack_from("<HH", raw, 54)
    require(size >= 56 and count <= 4096 and offset + size * count <= len(raw), "ELF program表超界")
    loads, dynamic = [], None
    for index in range(count):
        kind, flags, start, address, physical, length, memory, align = struct.unpack_from("<IIQQQQQQ", raw, offset + size * index)
        require(start + length <= len(raw), "ELF segment超界")
        if kind == 1: loads.append((address, start, length))
        if kind == 2:
            require(dynamic is None and length % 16 == 0, "ELF dynamic表不唯一/截断")
            dynamic = raw[start:start + length]
    if dynamic is None: return []
    strings, string_size, indexes, ended = None, None, [], False
    for offset in range(0, len(dynamic), 16):
        tag, value = struct.unpack_from("<QQ", dynamic, offset)
        if tag == 0: ended = True; break
        if tag == 1: indexes.append(value)
        if tag == 5: require(strings is None, "ELF重复STRTAB"); strings = value
        if tag == 10: require(string_size is None, "ELF重复STRSZ"); string_size = value
    require(ended, "ELF dynamic表缺结束")
    if not indexes: return []
    require(strings is not None and string_size is not None, "ELF缺原依赖字符串表")
    candidates = [(start + strings - address, string_size) for address, start, length in loads if address <= strings and strings + string_size <= address + length]
    require(len(candidates) == 1, "ELF字符串表映射缺失/歧义")
    start, length = candidates[0]; strings = raw[start:start + length]; result = []
    for index in indexes:
        require(index < len(strings), "ELF依赖名越界")
        end = strings.find(b"\0", index); require(end != -1, "ELF依赖名缺结束")
        name = strings[index:end].decode("ascii", "strict")
        require(re.fullmatch(r"[A-Za-z0-9_.+-]+", name), "ELF依赖名非法"); result.append(name)
    return result


def package_record(record, group):
    """系统二进制SHA是本轮认证观测；严格核其固定APT版本/架构和系统来源。"""
    packages = {v["package"]: v for v in group["base_packages"] + group["packages"]}
    expected = packages.get(record["package"]); require(expected is not None, "native来源包不在固定APT")
    require(record["version"] == expected["version"] and record["architecture"] == expected["architecture"]
            and record["qualification"] == "fixed_C0_image_and_verified_installed_APT_projection; binary_SHA_observed_this_run", "native包资格不符")
    for key in ("path", "realpath"):
        path = Path(record[key]); require(path.is_absolute() and ".." not in path.parts and (path.is_relative_to("/usr") or path.is_relative_to("/lib")), "native系统来源越界")
    require(type(record["bytes"]) is int and 0 < record["bytes"] <= 64 * 1024**2 and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]), "native原字节观测格式错误")


def native_binary(folder, relative, record, preserved, group, i0, native):
    """核真正保留的原ELF/DT_NEEDED及每项固定包资格，不将metadata当回传原件。"""
    path = i0.guarded(folder / i0.relative(relative)); raw = i0.raw_file(path, 64 * 1024**2)
    require(identity_bytes(raw) == preserved == {k: record[k] for k in ("bytes", "sha256")}, "native保留原件不同")
    info = native.elf_identity(raw); require(all(record[k] == v for k, v in info.items()), "native原ELF头不符")
    needed = elf_needed(raw, native); require(record["needed"] == needed, "native原DT_NEEDED不同")
    readelf = record["readelf"]
    require(readelf["argv"] == ["/usr/bin/readelf", "-d", record["path"]] and type(readelf["returncode"]) is int and readelf["returncode"] == 0
            and re.findall(r"Shared library: \[([^\]]+)\]", readelf["stdout"]) == needed, "native原readelf证明不同")
    require([v["name"] for v in record["resolved_dependencies"]] == needed, "native动态依赖解析集合不同")
    for dependency in record["resolved_dependencies"]: package_record(dependency, group)


def configure_evidence(folder, event, spec, workspace, group, i0):
    """验证每次原configure保留的真实日志原件及实际build compiler来源。"""
    proof = event["configure_proof"]; name = event["task_name"]
    require(proof["task_name"] == name and proof == i0.decode(i0.raw_file(folder / "configure" / name / "proof.json")), "configure收据不符")
    seen = set()
    for document in proof["documents"]:
        relative = i0.relative(document["preserved"]); require(relative.startswith("configure/" + name + "/") and relative not in seen, "configure保留路径不同/重复")
        seen.add(relative)
        require(i0.identity(folder / relative) == {k: document[k] for k in ("bytes", "sha256")}, "configure原日志不同")
        source = Path(document["source"]); require(source.is_relative_to(workspace / "tmp/build" / (spec["name"] + (".host" if spec["kind"] == "host" else ".ios-" + event["task_name"].split(".ios-", 1)[1]))), "configure原日志来源不符")
    require(seen and (proof["native_build_compilers"] or spec["name"] == "harfbuzz"), "原configure缺实际build compiler")
    for compiler in proof["native_build_compilers"]:
        require(compiler["variable"] in ("CC_BUILD", "CC_FOR_BUILD", "CCexe") and shlex.split(compiler["value"]), "native compiler选择字段不同")
        package_record(compiler, group)


def feature_evidence(folder, features, row, arch, consumer, plan, i0, final_table, first_table, commands):
    """按实际kind/Task核四或六份原探针；host仅configure，sidecar仅两target after-build。"""
    expected, actual = {}, []
    specs = [v for v in row["tasks"] if v["name"] in ("freetype", "freetypehb") and v["task"] in ("build", "hostbuild")]
    for spec in specs:
        expected[task_name(spec, arch)] = {"after-configure", "after-build"} if spec["kind"] != "host" else {"after-configure"}
    root = i0.guarded(folder / "features")
    require({p.name for p in root.iterdir()} == set(expected), "FT target/host探针Task集合不同")
    for spec in specs:
        family, host, name = spec["name"], spec["kind"] == "host", task_name(spec, arch)
        task_folder = i0.guarded(root / name)
        require(task_folder.is_dir() and {p.name for p in task_folder.iterdir()} == expected[name], "FT target/host探针阶段集合不同")
        event = next(v for v in commands if v["task_name"] == name and v["operation"] == "run" and v["template"].startswith("{{configure}}"))
        environment = event["environment"]["environment" if host else "candidate"]
        for label in ("after-configure", "after-build") if not host else ("after-configure",):
            directory = i0.guarded(task_folder / label)
            require(directory.is_dir() and {p.name for p in directory.iterdir()} == {"ftoption.h", "macros.stdout", "macros.stderr", "proof.json"}, "FT探针原件不全/多余")
            proof = i0.decode(i0.raw_file(directory / "proof.json"))
            source = Path("/reko/j9-workspaces") / row["release"] / arch / "tmp/build" / (family + (".host" if host else ".ios-" + arch)) / ("freetype-" + row["versions"]["freetype_and_freetypehb"]) / "builds/unix/ftoption.h"
            require(proof["task_name"] == name and proof["label"] == label and proof["source"] == str(source), "FT原特性头路径不同")
            argv = shlex.split(environment["CC"]) + shlex.split(environment.get("CPPFLAGS", "")) + shlex.split(environment.get("CFLAGS", "")) + ["-I", str(source.parents[2] / "include"), "-E", "-dM", "-x", "c", "-include", str(source), "-"]
            require(proof["argv"] == argv and type(proof["returncode"]) is int and proof["returncode"] == 0, "FT原预处理argv/退出码不同")
            header = i0.identity(directory / "ftoption.h", plan["limits"]["feature_file_bytes"])
            macros = i0.raw_file(directory / "macros.stdout", plan["limits"]["feature_file_bytes"])
            stderr = i0.raw_file(directory / "macros.stderr", plan["limits"]["feature_file_bytes"])
            require(header == proof["header"] and identity_bytes(macros) == proof["macro_output"] and len(macros) + len(stderr) <= plan["limits"]["feature_file_bytes"]
                    and proof["enabled"] == consumer.feature_macros(macros, plan["feature_macros"]), "FT真实头/宏原件不符")
            if label == "after-build":
                target = first_table if family == "freetype" else final_table
                require(header == {k: target["include/freetype2/freetype/config/ftoption.h"][k] for k in ("bytes", "sha256")}, "已安装FT头不是实际after-build原件")
                actual.append(proof)
    require(actual == features and sum(len(v) for v in expected.values()) == (4 if row["release"] == "8.5.3" else 6), "target sidecar或完整四/六份FT探针不同")

def verify_returned(metadata, folder, old_products, release, arch, consumer_sha):
    """新宿主进程完整静态验真原最终/首FT归档、image中间态和native provenance。"""
    runtime, folder, old_products = Path(metadata) / "scripts/renpy", Path(folder), Path(old_products)
    source = runtime / "run_locked_current_image_font_c_tasks.py"; raw = bootstrap_bytes(source)
    require(identity_bytes(raw)["sha256"] == consumer_sha, "宿主组合消费者身份不同")
    consumer = types.ModuleType("fixed_image_font_reader_consumer"); consumer.__file__ = str(source)
    exec(compile(raw, str(source), "exec"), consumer.__dict__)
    plan, current, cp, i0, ip = consumer.bootstrap(runtime / "current-image-font-c-task-plan.json", runtime)
    c, cplan, helpers = i0.load_runtime(runtime, ip); inventory, j8, native, validator, common, preflight = helpers
    return verify_product_documents(runtime, folder, old_products, release, arch, consumer, plan, i0, ip, c, helpers)


def verify_product_documents(runtime, folder, old_products, release, arch, consumer, plan, i0, ip, c, helpers):
    """固定runtime已认证后核产品原件；纯解析边界便于微夹具验证，不是可选执行hook。"""
    inventory, j8, native, validator, common, preflight = helpers
    source = runtime / "run_locked_current_image_font_c_tasks.py"
    for path in (folder, old_products): i0.guarded(path)
    row = next(v for v in plan["routes"] if v["release"] == release); image_row = next(v for v in ip["routes"] if v["release"] == release)
    receipt = i0.decode(i0.raw_file(folder / "current-image-font-c-receipt.json"))
    require(receipt["task"] == consumer.TASK and receipt["scope"] == consumer.SCOPE and (receipt["release"], receipt["arch"]) == (release, arch)
            and receipt["plan_sha256"] == consumer.PLAN_SHA256 and receipt["tool"] == i0.identity(source) and receipt["image_font_C_verified"] is True
            and receipt["temporary_workspace"] == "removed" and all(receipt.get(k) is v for k, v in consumer.FALSE.items()), "组合收据范围/源码/清理不同")
    require(receipt["image_and_C_members_unchanged"] is True and receipt["original_H1_members_unchanged"] is True
            and receipt["old_markers_synthesized"] is False and receipt["ran_tasks_seeded"] is False, "原成员/registry保护证明不同")
    old = i0.decode(i0.raw_file(old_products / "c-prefix-inventory.json")); old_names = {v["path"] for v in old}
    require(receipt["current_C_export"] == i0.identity(old_products / "export.json"), "本轮C导出不符")
    wanted_sidecars = {"font-prefix-inventory.json", "font-archive-objects.json", "font-installed-headers.json", "font-commands.json", "font-native-tools.json", "font-features.json", "font-native-generators.json"}
    require(set(receipt["sidecars"]) == wanted_sidecars, "字体固定sidecar集合不同")
    sidecars = {name: i0.decode(i0.raw_file(folder / name)) for name in wanted_sidecars}
    for name in wanted_sidecars: require(receipt["sidecars"][name] == i0.identity(folder / name), "字体sidecar原字节不同")
    entries = sidecars["font-prefix-inventory.json"]; table = i0.inventory_table(entries, plan["limits"])
    checkpoint = i0.decode(i0.raw_file(folder / "image-checkpoint.json")); first = i0.decode(i0.raw_file(folder / "first-freetype.json"))
    require(receipt["image_checkpoint"] == i0.identity(folder / "image-checkpoint.json") and receipt["first_freetype"] == i0.identity(folder / "first-freetype.json"), "image/首次FT原件身份不同")
    font_sources = [v for v in row["sources"] if v["path"].endswith((".tar.gz", ".tar.bz2", ".tar.xz"))]
    require(len(receipt["sources"]) == len(font_sources) == 3
            and all({k: actual[k] for k in expected} == expected and type(actual["members"]) is int and 0 < actual["members"] <= 65536
                    and type(actual["logical_bytes"]) is int and 0 < actual["logical_bytes"] <= 512 * 1024**2 for actual, expected in zip(receipt["sources"], font_sources)), "字体原三tar来源不同")
    require(len(checkpoint["sources"]) == len(image_row["sources"])
            and all(actual["family"] == expected["family"] and actual["version"] == expected["version"] and actual["archive"] == expected["archive"]
                    and actual["full_original_tar_verified"] is True for actual, expected in zip(checkpoint["sources"], image_row["sources"])), "image原tar来源不同")
    image = checkpoint["products"]; image_table = i0.inventory_table(image["inventory"], ip["limits"])
    require(checkpoint["state"] == "live_owned_before_font" and image["old_C_cache_members_unchanged"] is True and image["all_new_archive_objects_verified"] is True
            and all(image_table.get(v["path"]) == v for v in old) and all(table.get(v["path"]) == v for v in image["inventory"]), "最终归档未完整保留原C/image阶段")
    image_new = [v for v in image["inventory"] if v["path"] not in old_names]
    font_new = [v for v in entries if v["path"] not in image_table]
    require({v["path"] for v in image_new if v["type"] == "file" and v["path"].endswith(".a")} == set(ip["expected_new_archives"])
            and {v["path"] for v in font_new if v["type"] == "file" and v["path"].endswith(".a")} == set(plan["expected_font_archives"]), "image/font新增archive集合不同")
    require(all(consumer.font_prefix_allowed(v["path"]) for v in font_new), "字体新增prefix范围不同")
    i0.verify_required_headers(table, ip["required_new_headers"], inventory)
    require(image["new_headers"] == [v for v in image_new if v["type"] == "file" and v["path"].endswith(".h")]
            and sidecars["font-installed-headers.json"] == [v for v in font_new if v["type"] == "file" and v["path"].endswith(".h")], "image/font完整headers不同")
    require(all(table.get(name, {}).get("type") == "file" and table[name]["bytes"] > 0 for name in plan["required_font_headers"]), "字体必要头缺失")
    require(checkpoint["tasks"] == task_records(image_row["tasks"], arch, True) and receipt["font_tasks"] == task_records(row["tasks"], arch), "原8image/8或12font Task身份不同")
    expected_image = [(task_name(spec, arch), op[1]) for spec in image_row["tasks"] for op in spec["operations"][arch] if op[0] == "run"]
    require([(v["task_name"], v["template"]) for v in checkpoint["commands"]] == expected_image
            and all(type(v["returncode"]) is int and v["returncode"] == 0 for v in checkpoint["commands"]), "原image命令顺序/退出码不同")
    archive = folder / "image-font-prefix.tar.gz"
    require(receipt["archive"]["path"] == archive.name and {k: receipt["archive"][k] for k in ("bytes", "sha256")} == i0.identity(archive), "最终完整prefix原件不同")
    objects, executables = scan_prefix(archive, entries, set(ip["expected_new_archives"]) | set(plan["expected_font_archives"]), old_names, arch, c, i0, inventory, preflight, plan["limits"])
    require([v for v in objects if v["path"] in ip["expected_new_archives"]] == image["archives"]
            and [v for v in objects if v["path"] in plan["expected_font_archives"]] == sidecars["font-archive-objects.json"], "14库完整对象不同")
    require([v for v in executables if v["path"] in image_table] == image["executables"] and any(v["path"] == "bin/fribidi" for v in executables), "原image/目标FriBidi可执行不同")
    first_table = i0.inventory_table(first["entries"], plan["limits"]); early = first["products"]; early_table = i0.inventory_table(early["inventory"], plan["limits"])
    require(first["entries"] == consumer.first_ft_entries(early["inventory"], plan)
            and all(early_table.get(v["path"]) == v for v in image["inventory"])
            and all(table.get(v["path"]) == v for v in early["inventory"] if v["path"] not in first_table), "首FT delta或覆盖前完整成员不符")
    delta = folder / "first-freetype-prefix-delta.tar.gz"
    require(first["archive"]["path"] == delta.name and {k: first["archive"][k] for k in ("bytes", "sha256")} == i0.identity(delta), "首FT原始归档身份不同")
    first_objects, unused = scan_prefix(delta, first["entries"], {"lib/libfreetype.a"}, set(), arch, c, i0, inventory, preflight, plan["limits"])
    fribidi = next(v for v in objects if v["path"] == "lib/libfribidi.a")
    require(sorted(first_objects + [fribidi], key=lambda v: v["path"]) == early["archives"]
            and early["headers"] == [v for v in early["inventory"] if v["path"] not in image_table and v["type"] == "file" and v["path"].endswith(".h")]
            and early["executables"] == [v for v in executables if v["path"] in early_table and v["path"] not in image_table], "首次FT/早期FriBidi原对象或头不同")
    host_plan = native.load_plan(runtime / "host-python-bootstrap-plan.json")
    apt = native.checked_json(runtime / "apt-inputs.lock.json", host_plan["locks"]["apt-inputs.lock.json"]); group = next(v for v in apt["groups"] if v["ubuntu"] == row["ubuntu"])
    environment = native.checked_json(runtime / "environment-preflight.lock.json", host_plan["locks"]["environment-preflight.lock.json"]); group_env = next(v for v in environment["groups"] if v["ubuntu"] == row["ubuntu"])
    packages = native.approved_packages(group); llvm = {k: v for k, v in group_env["tool_identities"].items() if k.startswith(("clang-", "clang++-", "llvm-ar-", "llvm-nm-"))}
    native_expected = {"ubuntu": row["ubuntu"], "installed_package_count": len(packages), "installed_projection_sha256": hashlib.sha256(json.dumps(sorted((name, abi, version) for (name, abi), version in packages.items())).encode()).hexdigest(), "native_tools": llvm, "apple_sdk_required": False}
    require(receipt["native_environment"] == native_expected, "完整native环境APT/LLVM投影不同")
    workspace = Path("/reko/j9-workspaces") / release / arch; commands = sidecars["font-commands.json"]
    expected = [(task_name(spec, arch), op[0], op[1]) for spec in row["tasks"] for op in spec["operations"] if op[0] in ("run", "patch")]
    require([(v["task_name"], v["operation"], v["template"]) for v in commands] == expected
            and all(type(v["returncode"]) is int and v["returncode"] == 0 for v in commands), "原font命令/patch顺序或退出码不同")
    for event in commands:
        spec = next(v for v in row["tasks"] if task_name(v, arch) == event["task_name"])
        if event["operation"] == "run" and event["template"].startswith("{{configure}}"):
            configure_evidence(folder, event, spec, workspace, group, i0)
        if event["operation"] == "run" and spec["kind"] == "host":
            proof = event["environment"]; env = proof["environment"]
            require(proof["original_native_environment_preserved"] is True and not any(token in env[key] for key in ("CC", "CXX", "CPP", "CFLAGS", "LDFLAGS") for token in ("-target ", "-isysroot", "-miphoneos", "-mios-simulator", "sdk/usr", "-ld_classic")), "host命令混用iOS环境")
            require(set(proof["native_tools"]) == {"CC", "CXX", "AR", "RANLIB"} and all(v["sha256"] in {v["sha256"] for v in llvm.values()} for v in proof["native_tools"].values()), "host实际编译工具不是固定native LLVM")
            if spec["name"] == "freetypehb" and spec["task"] == "hostbuild":
                hb = proof["harfbuzz"]; require(hb["pkg_config"]["--modversion"] == row["host_harfbuzz_pkg_version"] and Path(hb["pkg_config"]["--variable=pcfiledir"]).is_relative_to("/usr") and hb["target_library_substituted"] is False, "旧host HarfBuzz选择不同")
                package_record(hb["library"], group)
    tools = sidecars["font-native-tools.json"]; wanted_families = [] if release == "8.5.3" else ["freetype", "freetypehb"]
    require([v["family"] for v in tools] == wanted_families and receipt["native_host_delta"] == ("freetype-apinames" if tools else None), "host apinames两次原件不同")
    for tool in tools:
        require(tool["binary"]["path"] == str(workspace / "tmp/host/freetype-apinames"), "apinames源不属本轮H1唯一delta")
        native_binary(folder, tool["family"] + "-native-apinames.elf", tool["binary"], tool["preserved"], group, i0, native)
    generators = sidecars["font-native-generators.json"]; build_specs = [v for v in row["tasks"] if v["task"] in ("build", "hostbuild")]
    require([v["task_name"] for v in generators] == [task_name(v, arch) for v in build_specs], "完整native生成器扫描顺序不同")
    for scan, spec in zip(generators, build_specs):
        require(scan["absence_counted_as_execution"] is False, "缺生成器不能冒称执行过")
        for item in scan["actual_ELF_generators"]:
            relative = i0.relative(item["relative"]); preserved = item["preserved"]; name = task_name(spec, arch)
            require(item["task_name"] == name and preserved["path"] == "native-generators/" + name + "/" + relative
                    and item["binary"]["path"] == str(workspace / "tmp/build" / (spec["name"] + (".host" if spec["kind"] == "host" else ".ios-" + arch)) / relative), "native生成器保留/来源路径不同")
            native_binary(folder, preserved["path"], item["binary"], {k: preserved[k] for k in ("bytes", "sha256")}, group, i0, native)
    feature_evidence(folder, sidecars["font-features.json"], row, arch, consumer, plan, i0, table, first_table, commands)
    require(first["feature"] == sidecars["font-features.json"][0], "首FT特性关联不同")
    returned, count, logical = [], 0, 0
    for directory, dirs, files in os.walk(folder, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name; info = path.lstat()
            count += 1; logical += info.st_size if stat.S_ISREG(info.st_mode) else 0
            require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), "完整私有回传含链接/特殊类型")
            require(count <= 32768 and logical <= 1024**3, "完整私有回传超成员/字节上限")
            if stat.S_ISREG(info.st_mode): returned.append({"path": path.relative_to(folder).as_posix(), **i0.identity(path, 1024**3)})
    return {"release": release, "arch": arch, "all_bound_artifacts_verified": True, "all_returned_regular_files_hashed": True,
            "returned_files": sorted(returned, key=lambda v: v["path"]), "new_archive_count": len(objects), "new_object_count": sum(v["object_count"] for v in objects),
            "first_FT_archive_all_objects_verified": True, "native_apinames_count": len(tools), "native_generators_count": sum(len(v["actual_ELF_generators"]) for v in generators),
            "complete_features_and_native_provenance_verified": True, "original_image_checkpoint_reverified_from_final_archive": True,
            "returned_binary_executed_on_host": False, "system_binary_raw_SHA_independently_recomputed_on_host": False}


def container_owner(args, protocol, state, image_id, i0, base):
    """实际C1产生后立即把父票据和真实id绑定到私有小文件。"""
    value = {"schema_version": 1, "parent_pid": protocol["parent_pid"], "ticket_sha256": base.ticket_hash(protocol),
             "run_id": args.run_id, "attempt": args.attempt, "nonce": protocol["nonce"],
             "controller": i0.identity(Path(__file__).absolute()), **base.verify_container(state, image_id)}
    i0.write_new(args.output / "private-diagnostics/container-ownership.json", value)
    return value


def cleanup_container(args, plan, protocol, i0, docker, base):
    """父finally只按已证精确id删除；pre-yield失败仅接受原C0两份真实命令证据。"""
    diagnostics = args.output / "private-diagnostics"; owner_path = diagnostics / "container-ownership.json"
    if owner_path.exists():
        owner = i0.decode(i0.raw_file(owner_path, 65536))
        require(owner["schema_version"] == 1 and owner["parent_pid"] == protocol["parent_pid"]
                and owner["ticket_sha256"] == base.ticket_hash(protocol) and owner["nonce"] == protocol["nonce"]
                and owner["run_id"] == args.run_id and owner["attempt"] == args.attempt
                and owner["controller"] == i0.identity(Path(__file__).absolute())
                and owner["image_id"] == plan["C1_image_ids"][args.ubuntu], "父清理所有权不属于本轮")
    else:
        # 原open_environment在APT安装后才yield；不据名字猜删，保留未能证明的清理状态。
        commands = diagnostics / "container/commands"
        starts = list(commands.glob("*-producer-container-start.stdout")); inspections = list(commands.glob("*-producer-container-inspect.stdout"))
        if not starts and not inspections:
            return {"state": "not_recorded", "container_removal_verified": False}
        require(len(starts) == len(inspections) == 1, "pre-yield所有权证据不完整；不猜测删除")
        original_id = i0.raw_file(starts[0], 1024).decode().strip()
        states = i0.decode(i0.raw_file(inspections[0], 1024**2)); require(len(states) == 1, "pre-yield inspect数量不同")
        owner = base.verify_container(states[0], plan["C1_image_ids"][args.ubuntu])
        require(owner["id"] == original_id, "原C0 start与inspect id不一致")
    require(re.fullmatch(r"[0-9a-f]{64}", owner["id"]) and re.fullmatch(r"reko-preflight-[0-9a-f]{32}", owner["name"]), "父清理id/name无效")
    listing = subprocess.run([docker, "ps", "-aq", "--no-trunc", "--filter", "name=^/" + owner["name"] + "$"], capture_output=True, timeout=15)
    require(listing.returncode == 0, "无法证明本轮C1是否仍存在")
    ids = listing.stdout.decode().split()
    require(ids in ([], [owner["id"]]), "同名C1已替换；拒绝删除")
    if not ids:
        # 名称可能被rename；不能把名称为空误报为精确所有权id已经消失。
        listing = subprocess.run([docker, "ps", "-aq", "--no-trunc", "--filter", "id=" + owner["id"]], capture_output=True, timeout=15)
        require(listing.returncode == 0, "无法查询本轮精确C1 id")
        ids = listing.stdout.decode().split()
        require(ids in ([], [owner["id"]]), "精确id查询返回其他C1；拒绝删除")
        if ids:
            inspected = subprocess.run([docker, "inspect", owner["id"]], capture_output=True, timeout=15)
            require(inspected.returncode == 0 and len(inspected.stdout) <= 1024**2, "rename后的精确C1 inspect失败/超限")
            states = i0.decode(inspected.stdout)
            require(len(states) == 1 and states[0]["Id"] == owner["id"] and states[0]["Image"] == owner["image_id"], "rename后的精确id/image不同")
    if ids:
        removed = subprocess.run([docker, "rm", "--force", owner["id"]], capture_output=True, timeout=60)
        require(removed.returncode == 0, "父兜底C1清理失败")
        listing = subprocess.run([docker, "ps", "-aq", "--no-trunc", "--filter", "id=" + owner["id"]], capture_output=True, timeout=15)
        require(listing.returncode == 0 and not listing.stdout.strip(), "删除后C1仍存在")
    return {"state": "removed" if ids else "already_absent", "container_removal_verified": True,
            "container_id": owner["id"], "ownership_basis": "owner" if owner_path.exists() else "original_C0_command_bytes"}


def cleanup_inputs(args, protocol, i0, base):
    """父兜底只回收票据绑定的本轮Tempdir，不删除SDK/原ZIP/缓存/输出证据。"""
    record = args.output / "private-diagnostics/input-ownership.json"
    if not record.exists(): return {"state": "not_recorded", "removed": False}
    owner = i0.decode(i0.raw_file(record, 65536)); path = i0.guarded(Path(owner["path"]))
    root = i0.guarded(Path(os.environ["RUNNER_TEMP"]))
    require(path.parent == root and path.name.startswith("reko-j11-image-font-inputs-")
            and owner["parent_pid"] == protocol["parent_pid"] and owner["ticket_sha256"] == base.ticket_hash(protocol)
            and owner["controller"] == i0.identity(Path(__file__).absolute()), "临时输入所有权不属于本轮")
    if path.exists():
        info = path.lstat(); require(stat.S_ISDIR(info.st_mode) and {"device": info.st_dev, "inode": info.st_ino} == owner["identity"], "临时输入根被替换")
        shutil.rmtree(path)
    return {"state": "removed", "removed": True}


def image_font_handoff(args, plan, consumer, consumer_plan, i0, run, owner, runtime, rows, diagnostics, protocol, base):
    """原C完整reader通过后，在同一live C1一次交接I2并保全全部原件后新进程读验。"""
    remote = "/reko/j11-image-font-runtime/root"
    system_python = "/usr/bin/python3.10" if args.ubuntu == "22.04" else "/usr/bin/python3.12"
    run.run(["mkdir", "-p", remote, "/reko/j11-image-font-controller"], "image-font-directories")
    run.copy(str(runtime) + "/.", remote, "image-font-copy-consumer52")
    run.checksum("image-font-consumer52", [(v["sha256"], remote + "/" + v["path"]) for v in rows])
    run.copy(Path(__file__).absolute(), "/reko/j11-image-font-controller/run_linux_image_font_c_tasks.py", "image-font-original-controller")
    paths = consumer.fixed_paths(consumer_plan, args.release, args.arch)
    run.run([system_python, "-B", "-c", base.CREATE_CONTROL_DIRECTORY, str(paths["control"])], "image-font-exclusive-control")
    original = run.output / "private-products" / args.release / args.arch
    original_reader = original / "product-verification.stdout"
    require(i0.decode(i0.raw_file(original_reader))["all_exported_member_bytes_and_MachO_objects_verified"] is True, "原C完整host reader未通过")
    run.copy(original_reader, str(paths["host_verification"]), "image-font-original-C-host-reader")
    tool = i0.identity(Path(__file__).absolute()); consumer_sha = next(v["sha256"] for v in plan["text_runtime_catalog"] if v["path"] == "run_locked_current_image_font_c_tasks.py")
    raw, _ = run.commands.run([run.docker, "exec", run.name, system_python, "-B", "-c", CREATE_HANDOFF,
                              args.release, args.arch, args.run_id, str(args.attempt), owner["id"], protocol["nonce"], str(tool["bytes"]), tool["sha256"], consumer_sha],
                             "image-font-create-actual-C-handoff", timeout=300)
    handoff = i0.decode(raw); expected_run = {"github_run_id": args.run_id, "attempt": args.attempt, "container_id": owner["id"], "nonce": protocol["nonce"]}
    require(handoff["run"] == expected_run and handoff["frontend_python"] == base.frontend_python(args, plan, i0), "组合外部交接run/前端不符")
    proof = handoff["handoff"]
    require(type(proof["bytes"]) is int and 0 < proof["bytes"] <= consumer_plan["limits"]["handoff_bytes"] and re.fullmatch(r"[0-9a-f]{64}", proof["sha256"]), "组合handoff缺外部bytes/SHA")
    argv = [handoff["frontend_python"], "-s", "-B", str(paths["consumer_runtime"] / "run_locked_current_image_font_c_tasks.py"), "run",
            "--release", args.release, "--arch", args.arch, "--output", str(paths["output"]), "--handoff-bytes", str(proof["bytes"]), "--handoff-sha256", proof["sha256"],
            "--run-id", args.run_id, "--attempt", str(args.attempt), "--container-id", owner["id"], "--nonce", protocol["nonce"]]
    failure = None
    try:
        remaining = int(protocol["work_deadline_monotonic"] - time.monotonic())
        require(remaining > 0, "统一工作时限已耗尽，不能启动image/font")
        run.commands.run([run.docker, "exec", run.name, "env", "-i", "PATH=" + str(Path(handoff["frontend_python"]).parent) + ":/usr/bin:/bin",
                          "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC", "PYTHONHASHSEED=0", "PYTHONDONTWRITEBYTECODE=1", *argv],
                         "image-font-original-I2-consumer", timeout=min(consumer_plan["limits"]["work_seconds"] + 300, remaining))
    except BaseException as error:
        failure = error
    finally:
        for source, destination, label in ((paths["output"], "image-font-products", "image-font-return"), (paths["control"], "image-font-control", "image-font-control-return")):
            try: base.bounded_copy(run, system_python, str(source), diagnostics / destination, label, plan, i0)
            except Exception as error:
                i0.write_new(diagnostics / (destination + "-preservation-error.json"), {"kind": type(error).__name__, "message": str(error)[:2000]})
                if failure is None: failure = error
    if failure is not None: raise failure
    folder = diagnostics / "image-font-products"; control = diagnostics / "image-font-control"
    observed = i0.checked(control / "handoff.json", proof)
    receipt = i0.decode(i0.raw_file(folder / "current-image-font-c-receipt.json"))
    require(receipt["run"] == observed["run"] == expected_run and receipt["handoff"] == proof
            and observed["consumer"] == {"tool": i0.identity(args.text_runtime_dir / "run_locked_current_image_font_c_tasks.py"), "plan_sha256": consumer.PLAN_SHA256, "bases": consumer_plan["bases"]}
            and observed["controller"] == {"path": str(paths["controller"]), **tool}, "回传组合收据未绑定真实外部交接")
    remaining = int(protocol["work_deadline_monotonic"] - time.monotonic())
    require(remaining > 0, "统一工作时限不足宿主完整reader")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", HOST_READER, str(Path(__file__).absolute()), tool["sha256"],
                             str(runtime), str(folder), str(original), args.release, args.arch, consumer_sha], capture_output=True, timeout=min(600, remaining))
    (diagnostics / "image-font-host-verification.stdout").write_bytes(result.stdout); (diagnostics / "image-font-host-verification.stderr").write_bytes(result.stderr)
    require(result.returncode == 0 and len(result.stdout) + len(result.stderr) <= plan["limits"]["host_log_bytes"], "组合宿主完整reader拒绝/日志超限")
    verification = i0.decode(result.stdout)
    require(all(verification[k] is True for k in ("all_bound_artifacts_verified", "all_returned_regular_files_hashed", "first_FT_archive_all_objects_verified", "complete_features_and_native_provenance_verified", "original_image_checkpoint_reverified_from_final_archive"))
            and verification["new_archive_count"] == 14 and verification["native_apinames_count"] == (0 if args.release == "8.5.3" else 2)
            and verification["returned_binary_executed_on_host"] is False, "组合完整reader范围不同")
    # 完整文件清单只留私有stdout，公开summary仅放计数/证明，不复制正文。
    return {"handoff": proof, "receipt": i0.identity(folder / "current-image-font-c-receipt.json"),
            "host_verification": {k: v for k, v in verification.items() if k != "returned_files"}, "host_verification_stdout": i0.identity(diagnostics / "image-font-host-verification.stdout"),
            "consumer_members": len(rows), "consumer_bytes": sum(v["bytes"] for v in rows)}


def execute(args, plan, consumer, consumer_plan, current, i0, ip, d, dp, base, bp, protocol, report):
    """同open_environment原D只生产真实单C；通过后统一I2，不调用旧image生命周期。"""
    diagnostics = args.output / "private-diagnostics"
    helpers = d.load_helpers(dp); h2, transport, h0, hp, h1, native, inventory = helpers
    require({g["ubuntu"]: g["image_id"] for g in hp["groups"]} == plan["C1_image_ids"], "原H0固定镜像映射不同")
    args.phase = "c-prerequisites"; args.releases = [args.release]; args.arches = [args.arch]; args.h2 = h2
    d.validate_phase_selection(args, dp)
    root = i0.guarded(Path(os.environ["RUNNER_TEMP"]))
    require(root.is_dir() and not root.is_relative_to(args.output), "独立RUNNER_TEMP无效")
    checkout = os.environ.get("GITHUB_WORKSPACE")
    require(not checkout or not root.is_relative_to(i0.guarded(Path(checkout))), "私密输入不能放checkout")
    with tempfile.TemporaryDirectory(prefix="reko-j11-image-font-inputs-", dir=root) as temporary:
        private = Path(temporary); private.chmod(0o700); info = private.lstat()
        i0.write_new(diagnostics / "input-ownership.json", {"path": str(private), "identity": {"device": info.st_dev, "inode": info.st_ino},
                     "parent_pid": protocol["parent_pid"], "ticket_sha256": base.ticket_hash(protocol), "controller": i0.identity(Path(__file__).absolute())})
        artifact = private / "H1-artifact"; h2.extract_h1_zip(args.h1_artifact, artifact)
        profile = dp["producer_profiles"][args.ubuntu]
        selected = {args.release: d.selected_host_export(h2, h0, h1, artifact, args.release, profile, dp["host_producers"][args.release], dp["auditor_functions"])}
        payload, metadata, rows, workspaces, proof = base.prepare_inputs(args, plan, d, dp, helpers, private, diagnostics, protocol["password"])
        protocol["password"] = None
        runtime = private / "consumer/root"; combined_rows = consumer_runtime(args, plan, base, bp, h0, h1, i0, metadata, rows, runtime)
        i0.write_new(diagnostics / "producer-runtime-manifest.json", rows); i0.write_new(diagnostics / "consumer-runtime-manifest.json", combined_rows)
        container = diagnostics / "container"; container.mkdir(mode=0o700)
        namespace = argparse.Namespace(payload=payload, bundle=args.bundle, ubuntu=args.ubuntu, output=container)
        stage = {"cells": [{"release": args.release, "arch": args.arch, "status": "not_run"}], "container_closed": False}
        report["producer_runtime_members"] = len(rows); report["consumer_runtime_members"] = len(combined_rows)
        try:
            with h0.open_environment(namespace, hp, stage) as run:
                raw, _ = run.host([run.docker, "inspect", run.name], "image-font-controller-container-identity")
                states = i0.decode(raw); require(len(states) == 1, "实际C1 inspect数量不同")
                image_id = next(v["image_id"] for v in hp["groups"] if v["ubuntu"] == args.ubuntu)
                owner = container_owner(args, protocol, states[0], image_id, i0, base)
                d.execute_cells(run, h2, h0, native, inventory, payload, hp, metadata, rows, workspaces, selected, dp, args, stage)
                cell = stage["cells"][0]
                require(cell["status"] == "C_prerequisites_verified" and cell["product_verification"]["all_exported_member_bytes_and_MachO_objects_verified"] is True, "原C实际cell/host reader未通过，不交接image/font")
                report["current_C_dependency_verified"] = True
                report["image_font"] = image_font_handoff(args, plan, consumer, consumer_plan, i0, run, owner, runtime, combined_rows, diagnostics, protocol, base)
                report["image_font_C_verified"] = True
        finally:
            report["container_closed"] = stage.get("container_closed") is True; stage.pop("active_stage", None)
            i0.write_new(diagnostics / "original-D-stage-evidence.json", {"original_D_main_executed": False, "original_D_aggregate_success_claimed": False,
                         "actual_stage_fields": stage, "fresh_runtime_contract": proof})
    require(not private.exists() and report["container_closed"], "C1/本轮解密输入未回收")
    report.update(private_inputs_removed=True, same_open_C1_chain_verified=True, result=RESULT)


def parser():
    """只接受固定单tuple/原缓存/实际宿主基础和job截止时间，没有任意hook或下载fallback。"""
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--plan", type=Path, default=HERE / "linux-image-font-c-ci-plan.json")
    result.add_argument("--ubuntu", choices=("22.04", "24.04"), required=True)
    result.add_argument("--release", choices=("8.5.3", "8.4.1", "8.3.7", "7.8.7"), required=True)
    result.add_argument("--arch", choices=("arm64", "sim-arm64", "sim-x86_64"), required=True)
    for name in ("text-runtime-dir", "image-controller", "d-wrapper", "bundle", "h1-artifact", "runtime-addon", "h0-cipher", "recipe-addon", "device-sdk", "simulator-sdk", "clang-runtime", "output"):
        result.add_argument("--" + name, type=Path, required=True)
    result.add_argument("--run-id", required=True); result.add_argument("--attempt", type=int, required=True)
    result.add_argument("--job-deadline-utc", type=int); result.add_argument("--ccache", action="store_true")
    result.add_argument("--worker-fd", type=int, help=argparse.SUPPRESS)
    return result


def main(argv=None):
    """唯一父监督器控制完整链工作时限/空间/票据与精确清理，成功须父子证据齐全。"""
    args = parser().parse_args(argv); created, trusted, code, i0, protocol, docker, base = False, False, 1, None, None, None, None
    report = {"schema_version": 1, "task": TASK, "scope": "single_tuple_same_C1_actual_C_then_original_image_and_font_tasks", "ubuntu": args.ubuntu,
              "release": args.release, "arch": args.arch, "result": "failed", "image_font_C_verified": False, "current_C_dependency_verified": False,
              "same_open_C1_chain_verified": False, "container_closed": False, "private_inputs_removed": False, "errors": [],
              "manual_device_acceptance": "deferred", "public_artifact_whitelist": ["public-summary.json"], **FALSE}
    try:
        plan, consumer, cp, current, i0, ip, d, dp, base, bp = load_fixed(args); base.selection(args, plan)
        for key, value in vars(args).items():
            if isinstance(value, Path): setattr(args, key, i0.guarded(value))
        for key, value in vars(args).items():
            if isinstance(value, Path) and key != "output":
                require(not value.is_relative_to(args.output) and not args.output.is_relative_to(value), "输入输出路径交叉")
        diagnostics = args.output / "private-diagnostics"
        if args.worker_fd is None:
            require(not args.output.exists() and args.output.parent.is_dir(), "输出须全新且父目录存在")
            args.output.mkdir(mode=0o700); diagnostics.mkdir(mode=0o700); created = True
        require(args.output.is_dir() and diagnostics.is_dir(), "父创建的输出目录缺失")
        if sys.platform != "linux" or platform.machine() != "x86_64" or shutil.which("docker") is None:
            raise NotRun("需要真实Linux amd64及Docker；未执行C/image/font编译")
        docker = shutil.which("docker")
        if args.worker_fd is not None:
            require(stat.S_ISFIFO(os.fstat(args.worker_fd).st_mode), "worker缺父FIFO")
            with os.fdopen(args.worker_fd, "rb") as stream: protocol = i0.decode(stream.read(65537))
            require(protocol["parent_pid"] == os.getppid() and protocol["controller"] == i0.identity(Path(__file__).absolute())
                    and protocol["plan_sha256"] == PLAN_SHA256 and protocol["output"] == str(args.output) and protocol["run_id"] == args.run_id
                    and protocol["attempt"] == args.attempt and re.fullmatch(r"[0-9a-f]{64}", protocol["ticket"]) and re.fullmatch(r"[0-9a-f]{64}", protocol["nonce"])
                    and type(protocol["work_deadline_monotonic"]) in (int, float) and 0 < protocol["work_deadline_monotonic"] - time.monotonic() <= plan["limits"]["total_work_seconds"], "父协议身份/统一deadline不同")
            trusted = True; execute(args, plan, consumer, cp, current, i0, ip, d, dp, base, bp, protocol, report); code = 0
        else:
            before = shutil.disk_usage(args.output).free
            require(before >= plan["limits"]["remote_entry_free_bytes"], "远端image/font入口不足18GiB；估算不是实测峰值")
            budget = base.work_budget(args, plan, time.time())
            if not args.bundle.is_dir(): raise NotRun("必要原APT缓存目录未到齐")
            for key in ("h1_artifact", "runtime_addon", "h0_cipher", "recipe_addon", "device_sdk", "simulator_sdk", "clang_runtime"):
                if not getattr(args, key).is_file(): raise NotRun("必要原缓存/SDK未到齐")
            profile = dp["producer_profiles"][args.ubuntu]
            require(i0.identity(args.h1_artifact) == {k: profile["artifact"][k] for k in ("bytes", "sha256")}
                    and i0.identity(args.runtime_addon) == {k: plan["C_runtime_addon"][k] for k in ("bytes", "sha256")}, "原H1或C03身份不同")
            password = os.environ.pop("REKO_H0_INPUTS_PASSWORD", None)
            if not password: raise NotRun("缺原H0运输密码")
            protocol = {"parent_pid": os.getpid(), "controller": i0.identity(Path(__file__).absolute()), "plan_sha256": PLAN_SHA256,
                        "output": str(args.output), "run_id": args.run_id, "attempt": args.attempt, "ticket": secrets.token_hex(32),
                        "nonce": secrets.token_hex(32), "password": password, "work_deadline_monotonic": time.monotonic() + budget}
            password = None; stop = threading.Event(); observation = {}
            observer = threading.Thread(target=base.watch_space, args=(args.output, before, plan["limits"], stop, observation), daemon=True)
            supervisor = diagnostics / "supervisor"; supervisor.mkdir(); read_fd, write_fd = os.pipe(); failure = None
            observer.start()
            try:
                os.write(write_fd, json.dumps(protocol).encode()); os.close(write_fd); write_fd = None
                env = {key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR", "RUNNER_TEMP", "GITHUB_WORKSPACE") if key in os.environ}
                env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONHASHSEED="0", LANG="C.UTF-8", LC_ALL="C.UTF-8", TZ="UTC")
                command = [sys.executable, "-s", "-B", str(Path(__file__).absolute()), *(argv if argv is not None else sys.argv[1:]), "--worker-fd", str(read_fd)]
                i0.bounded_child(command, env, read_fd, supervisor, plan["limits"]["host_log_bytes"], timeout=budget, owned_workspace=None)
            except BaseException as error: failure = error
            finally:
                stop.set(); observer.join(timeout=3); os.close(read_fd)
                if write_fd is not None: os.close(write_fd)
                protocol["password"] = None
                observation.update(free_before_bytes=before, free_after_driver_bytes=shutil.disk_usage(args.output).free, measured_peak=False, work_timeout_seconds=budget)
                i0.write_new(diagnostics / "space-observation.json", observation)
                for name, action in (("container", lambda: cleanup_container(args, plan, protocol, i0, docker, base)), ("inputs", lambda: cleanup_inputs(args, protocol, i0, base))):
                    try:
                        cleanup = action()
                        report["container_closed" if name == "container" else "private_inputs_removed"] = cleanup.get("container_removal_verified" if name == "container" else "removed") is True
                    except Exception as error:
                        cleanup = {"state": "cleanup_failed", "kind": type(error).__name__, "message": str(error)[:2000]}
                        if failure is None: failure = error
                    i0.write_new(diagnostics / ("parent-" + name + "-cleanup.json"), cleanup)
            if failure is not None: raise failure
            require(not observation["violation"], "空间观察器触发中断")
            child = i0.decode(i0.raw_file(diagnostics / "worker-report.json"))
            require(child["result"] == RESULT and all(child[key] is True for key in ("current_C_dependency_verified", "image_font_C_verified", "same_open_C1_chain_verified", "container_closed", "private_inputs_removed"))
                    and report["container_closed"] and report["private_inputs_removed"], "同C1完整链或父子清理证明不全")
            report.update({key: child[key] for key in ("result", "current_C_dependency_verified", "image_font_C_verified", "same_open_C1_chain_verified", "producer_runtime_members", "consumer_runtime_members", "image_font")}); code = 0
    except BaseException as error:
        report["result"] = "not_run" if isinstance(error, NotRun) else "interrupted" if isinstance(error, (Interrupted, KeyboardInterrupt)) else "failed"
        report["errors"].append({"kind": type(error).__name__, "stage": "same_C1_C_image_font"})
        if i0 is not None and created:
            i0.write_new(args.output / "private-diagnostics/private-failure.json", {"kind": type(error).__name__, "message": str(error)[:2000]})
        code = 3 if report["result"] == "not_run" else 130 if report["result"] == "interrupted" else 1
    finally:
        if protocol is not None: protocol["password"] = None; protocol["ticket"] = None
    if i0 is not None and (created or trusted):
        i0.write_new(args.output / ("private-diagnostics/worker-report.json" if args.worker_fd is not None else "public-summary.json"), report)
    log("结果=" + report["result"])
    return code


if __name__ == "__main__":
    def interrupted(signum, frame):
        """收到中断进入父统一finally，不丢失精确C1清理。"""
        raise Interrupted("收到SIGTERM")
    signal.signal(signal.SIGTERM, interrupted)
    raise SystemExit(main())
