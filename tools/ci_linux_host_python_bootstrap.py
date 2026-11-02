#!/usr/bin/env python3
"""同一固定禁网容器先完成 H0，再从原配方重建两路线完整 host Python；不消费 SDK/引擎。"""
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
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import types
import urllib.request


HERE = Path(__file__).absolute().parent
DEFAULT_PLAN = HERE / "linux-host-python-bootstrap-ci-plan.json"
HELPER_SHA = "bbc38bcbf2cb192d8f0f760d7d5b927df40eda112c28098b84fa884d8b85b011"
ADDON_H1_SHA = "3de9c6597e9028bb2e35c79e4064db46b68a60417516ca77e52728f5002f88e3"
EXECUTION_H1_SHA = "6a367bbb67781258b14720c429ab55cae2f441be97cf74c01872a8e674354612"
EXECUTION_REASON = "按精确CPython保留linux2/linux平台，并以严格多架构包身份核对完整APT环境"
H1_PLAN_SHA = "352f7af5dbd7f31d6199f1d6b536a99405cf249c7969cbfd69260a455c6b84e0"
MANIFEST = {"bytes": 1345712, "sha256": "feec48d352fcdda2668663e9d516abbf29eb4ed23e6f146392395c9980626667"}
ADDON = {"url": "https://github.com/Leo008/renpy-build/releases/download/ci-inputs-8.5.3-20261008/h1-public-recipe-addon-20261102-01.tar.gz",
         "bytes": 264133884, "sha256": "0da8d46083c0c882b1e246a5c7e3df526e20c92246c823abfe3f617271fb5ec2"}
RUNTIME = {
    "run_locked_host_python_tasks.py": ADDON_H1_SHA,
    "host-python-bootstrap-plan.json": H1_PLAN_SHA,
    "run_locked_source_tasks.py": "7b355837494c22ee642f014652ce0b1adc328dd47928126880df320f960a5b45",
    "inventory_source_inputs.py": "2ee4d817243d10dc900bb0834757b80bcafbb64ea066b860ff26be1d3794f824",
    "source-task-binding-plan.json": "32abe3927eef6d0b887e95b6de83bed38b510644c300a88b314bfeb517a791a5",
}
GROUPS = {"24.04": ["8.5.3", "8.4.1"], "22.04": ["8.3.7", "7.8.7"]}
REMOTE_ROOT = "/reko/h1-runtime/root"
REMOTE_RUNTIME = REMOTE_ROOT + "/scripts/renpy"
RUNTIME_LAYOUT = {"scope": "complete_H0_root_plus_14_fixed_runtime_overlays", "base_root_file_count": 28,
                  "base_root_bytes": 82566005, "overlay_subdirectory": "scripts/renpy", "overlay_file_count": 14,
                  "derived_file_count": 35, "container_root": REMOTE_ROOT, "fresh_process_source_evidence_count": 18}
FRESH_RUNTIME_PROBE = r'''import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(root/'scripts/renpy'))
assert not any(name in sys.modules for name in ('replay_python_inputs','build_python_wheels','lock_python_inputs'))
import replay_python_inputs as replay
assert replay.ROOT==replay.inputs.ROOT==replay.build.ROOT==root
plan,builder,manifest,sha=replay.load_plan(root/'scripts/renpy/python-replay-plan.json')
assert sha=='89763ed8ba512a39dd2c63c4e3d871354de300064638ea3b5272294e6428fef4'
evidence=replay.inputs.verify_evidence(manifest['scopes']);assert len(evidence)==18
archives=[]
for row in plan['installers'].values():
 path=root/row['source_archive'];digest=hashlib.sha256()
 with path.open('rb') as stream:
  while True:
   block=stream.read(1048576)
   if not block:break
   digest.update(block)
 assert digest.hexdigest()==row['source_archive_sha256']
 archives.append({'path':row['source_archive'],'sha256':digest.hexdigest(),'bytes':path.stat().st_size})
import run_locked_host_python_tasks as h1
h1.load_plan()
print(json.dumps({'root':str(root),'replay_root':str(replay.ROOT),'inputs_root':str(replay.inputs.ROOT),'build_root':str(replay.build.ROOT),'source_evidence_count':len(evidence),'source_archives':archives,'H1_dependency_contract_verified':True,'native_build_executed':False}))
'''
PRESERVE = r'''import hashlib,json,os,pathlib,stat,sys,tarfile
release=sys.argv[1]
assert release in ('8.5.3','8.4.1','8.3.7','7.8.7')
source=pathlib.Path('/reko/h1-output')/release
target=pathlib.Path('/reko/h1-public')/release;target.mkdir(parents=True)
prefix=pathlib.Path('/reko/h1-workspaces')/release/'tmp/host'
def sha(data):
 """对实际归档、收据和分发原字节计算摘要。"""
 return hashlib.sha256(data).hexdigest()
def copy(path):
 """仅保全明确公开日志/收据，不回传home/cache/源码/venv。"""
 assert not path.is_symlink() and stat.S_ISREG(path.lstat().st_mode)
 with (target/path.name).open('xb') as stream:stream.write(path.read_bytes())
for name in ('report.json','worker-report.json','native-build.log','task-events.jsonl','host-receipt.json','host-distribution.json','native-driver-request.json','native-probe.c','native-probe'):
 path=source/name
 if path.exists():copy(path)
if not (target/'host-receipt.json').is_file():sys.exit(0)
receipt=json.loads((target/'host-receipt.json').read_bytes())
assert receipt['host_bootstrap_verified'] is True and receipt['release']==release and receipt['prefix']==str(prefix)
assert receipt['plan_sha256']=='352f7af5dbd7f31d6199f1d6b536a99405cf249c7969cbfd69260a455c6b84e0'
distribution=target/'host-distribution.json'
assert sha(distribution.read_bytes())==receipt['distribution']['sha256']
sys.path.insert(0,'/reko/h1-runtime/root/scripts/renpy')
import run_locked_host_python_tasks as h1
assert sha(pathlib.Path(h1.__file__).read_bytes())=='6a367bbb67781258b14720c429ab55cae2f441be97cf74c01872a8e674354612'
inventory=h1.host_inventory(prefix)
assert inventory==json.loads(distribution.read_bytes())
archive=target/'host-distribution.tar.gz'
with tarfile.open(archive,'w:gz',format=tarfile.PAX_FORMAT) as bundle:
 for item in inventory:
  path=prefix/item['path'];info=tarfile.TarInfo(item['path']);info.mode=int(item['permissions'],8)
  if item['type']=='directory':info.type=tarfile.DIRTYPE;bundle.addfile(info)
  elif item['type']=='symlink':info.type=tarfile.SYMTYPE;info.linkname=item['target'];bundle.addfile(info)
  else:
   info.size=item['bytes']
   with path.open('rb') as stream:bundle.addfile(info,stream)
record={'release':release,'prefix':str(prefix),'archive':{'path':archive.name,'bytes':archive.stat().st_size,'sha256':sha(archive.read_bytes())},'receipt_sha256':sha((target/'host-receipt.json').read_bytes()),'distribution_sha256':sha(distribution.read_bytes()),'member_count':len(inventory),'complete_distribution_exported':True,'target_python_install_verified':False}
with (target/'host-export.json').open('x') as stream:json.dump(record,stream,indent=2);stream.write('\n')
'''


def require(value, message):
    """缺少实际证据即失败，不产生 native 成功占位。"""
    if not value:
        raise ValueError(message)


def log(message):
    """统一输出固定阶段，不记录密钥或环境。"""
    print("[RenPyLinuxHostBootstrap] " + message, flush=True)


def load_helpers():
    """仅加载两个获准同目录命名之一，原 SHA 相同，不接纳模块路径参数。"""
    candidates = [HERE / name for name in ("run_ci_linux_python_replay.py", "ci_linux_host_replay.py") if (HERE / name).exists()]
    require(candidates, "缺少固定H0运输helper")
    for path in candidates:
        require(not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest() == HELPER_SHA, "运输helper原件SHA错误")
    path = candidates[0];module = types.ModuleType("reko_h1_transport");module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    h0, plan, plan_path = module.load_h0()
    return module, h0, plan, plan_path


def load_plan(transport):
    """锁定现有 H0/H1 原件与公开 addon，拒绝新入口或任意后置任务。"""
    plan = transport.read_json(DEFAULT_PLAN)
    require(set(plan) == {"schema_version", "task", "scope", "transport_helper_sha256", "h0_tool_sha256", "h0_plan_sha256", "addon_h1_tool_sha256", "execution_h1_tool_sha256", "execution_overlay_reason", "H1_plan_sha256", "addon", "addon_manifest", "groups", "runtime_layout", "limitations"}
            and type(plan["schema_version"]) is int and plan["schema_version"] == 1
            and plan["task"] == "R00-02J2C-H1-Linux" and plan["scope"] == "same_lifetime_H0_then_original_host_tasks_no_sdk_or_engine"
            and plan["transport_helper_sha256"] == HELPER_SHA and plan["h0_tool_sha256"] == transport.H0_TOOL_SHA256
            and plan["h0_plan_sha256"] == transport.H0_PLAN_SHA256 and plan["addon_h1_tool_sha256"] == ADDON_H1_SHA
            and plan["execution_h1_tool_sha256"] == EXECUTION_H1_SHA and plan["execution_overlay_reason"] == EXECUTION_REASON
            and plan["H1_plan_sha256"] == H1_PLAN_SHA and plan["addon"] == ADDON and plan["addon_manifest"] == MANIFEST
            and plan["groups"] == GROUPS and plan["runtime_layout"] == RUNTIME_LAYOUT
            and isinstance(plan["limitations"], list) and plan["limitations"], "H1 CI计划不是批准固定身份")
    require(type(plan["addon"]["bytes"]) is int and type(plan["addon_manifest"]["bytes"]) is int, "H1大小字段须为整数")
    return plan


def source_for(sha, h0_plan):
    """从固定103 catalog独立派生可复用原件，未取得者只允许相同SHA的CAS。"""
    matches = sorted(row["path"] for row in h0_plan["files"] if row["sha256"] == sha)
    return {"kind": "h0_payload", "path": matches[0], "all_equivalent_h0_paths": matches} if matches else {"kind": "addon_object", "path": "objects/" + sha}


def check_source(actual, expected):
    """等字节H0别名可显式选择，来源集合必须完整相等。"""
    if expected["kind"] == "h0_payload":
        require(set(actual) == set(expected) and actual["kind"] == expected["kind"]
                and actual["all_equivalent_h0_paths"] == expected["all_equivalent_h0_paths"]
                and actual["path"] in expected["all_equivalent_h0_paths"], "H0复用来源或等价集合错误")
    else:
        require(actual == expected, "addon CAS来源错误")


def derive_addon(transport, h0, payload, addon_manifest, h0_plan, h1_plan):
    """从独立J1及H1原计划重建1793投影/630对象，manifest仅作运输登记。"""
    j1 = h0.decode(h0.read(payload / "root/scripts/renpy/source-inputs.lock.json"))
    require(addon_manifest["schema_version"] == 1 and addon_manifest["scope"] == "H1_complete_J1_recipe_input_addon_only_no_execution", "addon范围错误")
    require(len(addon_manifest["routes"]) == 4 and len(addon_manifest["content_objects"]) == 630, "addon路线或对象数错误")
    routes = {};objects = {}
    for route in h1_plan["routes"]:
        found = [r for r in j1["repositories"] if r["role"] == route["recipe"]["role"] and r["release"] == route["release"]]
        require(len(found) == 1 and all(found[0][key] == route["recipe"][key] for key in ("role", "path", "commit", "tree")), "J1/H1原配方身份不符")
        row = found[0];routes[route["release"]] = row
        supplied = [r for r in addon_manifest["routes"] if r["release"] == route["release"]]
        require(len(supplied) == 1 and supplied[0]["recipe"] == route["recipe"] and supplied[0]["file_count"] == row["file_count"]
                and supplied[0]["total_bytes"] == sum(f["size"] for f in row["files"])
                and len(supplied[0]["files"]) == len(row["files"]), "addon完整路线缺项/错身份")
        for item, supplied_file in zip(row["files"], supplied[0]["files"]):
            require({key: value for key, value in supplied_file.items() if key != "source"} == item, "addon投影与J1完整成员不符")
            expected = source_for(item["sha256"], h0_plan);check_source(supplied_file["source"], expected)
            descriptor = objects.setdefault(item["sha256"], {"bytes": item["size"], "blob_oid": item["blob_oid"], "source": expected, "references": []})
            require((descriptor["bytes"], descriptor["blob_oid"]) == (item["size"], item["blob_oid"]), "同SHA对象声明不一致")
            descriptor["references"].append({"release": route["release"], "path": item["path"], "mode": item["mode"]})
    require(sum(r["file_count"] for r in routes.values()) == 1793 and len(objects) == 630, "J1完整投影数量错误")
    observed = set()
    for item in addon_manifest["content_objects"]:
        sha = item["sha256"];require(sha in objects and sha not in observed, "addon对象多项/重复")
        expected = objects[sha];observed.add(sha)
        require(item["bytes"] == expected["bytes"] and item["blob_oid"] == expected["blob_oid"]
                and item["references"] == expected["references"], "addon对象身份/全部引用不符")
        check_source(item["source"], expected["source"])
    require(observed == set(objects), "addon对象遗漏")
    require(len(addon_manifest["runtime"]) == 5 and {r["name"]: r["sha256"] for r in addon_manifest["runtime"]} == RUNTIME, "H1五原件不符")
    reuse = {**h1_plan["dependencies"], **h1_plan["locks"]};reuse = {n: sha for n, sha in reuse.items() if n not in RUNTIME}
    require(len(reuse) == 9 and len(addon_manifest["runtime_reuse_from_h0"]) == 9
            and {r["runtime_name"]: r["sha256"] for r in addon_manifest["runtime_reuse_from_h0"]} == reuse, "H1依赖复用缺项/漂移")
    for row in addon_manifest["runtime_reuse_from_h0"]:
        expected = source_for(row["sha256"], h0_plan);require(expected["kind"] == "h0_payload", "复用工具未在H0取得")
        check_source(row["source"], expected)
        require(row["bytes"] == next(f["bytes"] for f in h0_plan["files"] if f["path"] == expected["path"]), "复用长度错误")
    catalog = [{"path": "manifest.json", **MANIFEST}]
    catalog += [{"path": "objects/" + sha, "bytes": row["bytes"], "sha256": sha} for sha, row in objects.items() if row["source"]["kind"] == "addon_object"]
    for row in addon_manifest["runtime"]:
        require(row["path"] == "runtime/" + row["name"] and Path(row["name"]).name == row["name"], "runtime路径错误")
        catalog.append({"path": row["path"], "bytes": row["bytes"], "sha256": row["sha256"]})
    require(len(catalog) == 625, "addon完整运输集合应625项")
    return routes, objects, catalog


def download_addon(transport, target):
    """宿主只读取固定公开release附件，保留HTTPS域边界并核完整字节。"""
    try:
        opener = urllib.request.build_opener(transport.ReleaseRedirects(ADDON["url"]))
        request = urllib.request.Request(ADDON["url"], headers={"Accept-Encoding": "identity", "User-Agent": "Reko-H1-Addon/1"})
        with opener.open(request, timeout=60) as response, target.open("xb") as stream:
            transport.validate_url(response.url, ADDON["url"])
            require(response.status == 200 and response.headers.get("Content-Encoding", "identity").lower() == "identity"
                    and response.headers.get("Content-Length") in (None, str(ADDON["bytes"])), "addon响应不符")
            count = 0;deadline = time.monotonic() + 900
            while block := response.read(256 * 1024):
                count += len(block);require(count <= ADDON["bytes"] and time.monotonic() <= deadline, "addon运输超长/超时")
                stream.write(block)
        transport.verify_bytes(target, {key: ADDON[key] for key in ("bytes", "sha256")})
    except Exception:
        raise ValueError("固定公开addon下载或完整身份核验失败") from None


def read_manifest(transport, h0, archive, target):
    """先从完整已锁tar读取唯一manifest原字节，随后整包仍须625成员门禁。"""
    with tarfile.open(archive, "r:gz") as bundle:
        matches = [];count = 0
        for item in bundle:
            count += 1;require(count <= 625, "addon归档多项")
            if item.name == "manifest.json":
                require(item.isfile() and item.size == MANIFEST["bytes"] and not matches, "addon manifest类型/重复/长度错误")
                data = bundle.extractfile(item).read(MANIFEST["bytes"] + 1);matches.append(data)
        require(len(matches) == 1 and len(matches[0]) == MANIFEST["bytes"] and h0.digest(matches[0]) == MANIFEST["sha256"], "addon manifest原字节不符")
    with target.open("xb") as stream:stream.write(matches[0])
    return h0.decode(matches[0])


def raw_object(h0, payload, addon, sha, row):
    """对CAS/H0实际原字节同时核长度、SHA256、Git blobOID，不创建假Git对象。"""
    source = row["source"];path = (payload if source["kind"] == "h0_payload" else addon) / source["path"]
    data = h0.read(path, row["bytes"])
    require(len(data) == row["bytes"] and h0.digest(data) == sha
            and hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == row["blob_oid"], "CAS原字节/blobOID错误")
    return data


def rebuild_workspace(j8, row, destination, get_bytes):
    """从全部J1成员重建派生配方，保留原mode/合法链接；从不初始化或伪造.git。"""
    require(not destination.exists(), "H1配方工作区必须全新")
    table = j8.file_table(row);j8.validate_links(table);destination.mkdir(parents=True, mode=0o700)
    for name, item in table.items():
        path = destination / name;j8.no_links(path.parent);path.parent.mkdir(parents=True, exist_ok=True)
        data = get_bytes(item);j8.verify_bytes(data, item)
        if item["mode"] == "120000":
            require(data.decode() == item["link_target"], "原链接文字错误");path.symlink_to(item["link_target"])
        else:
            with path.open("xb") as stream:stream.write(data)
            path.chmod(0o755 if item["mode"] == "100755" else 0o644)
    j8.verify_repository(row, destination)


def runtime_root_catalog(h0_plan, manifest, *, execution):
    """独立从H0完整root与14批准覆盖派生35文件身份，禁止额外源码或遗漏来源。"""
    base = [{**row, "path": row["path"][5:]} for row in h0_plan["files"] if row["path"].startswith("root/")]
    require(len(base) == RUNTIME_LAYOUT["base_root_file_count"] and sum(row["bytes"] for row in base) == RUNTIME_LAYOUT["base_root_bytes"], "H0完整root集合不符")
    expected = {row["path"]: row for row in base};overlays = {}
    for row in manifest["runtime"]:
        require(row["name"] in RUNTIME and row["sha256"] == RUNTIME[row["name"]], "runtime覆盖不是五固定原件")
        overlays[row["name"]] = {"path": "scripts/renpy/" + row["name"], "bytes": row["bytes"], "sha256": row["sha256"]}
    for row in manifest["runtime_reuse_from_h0"]:
        require(row["runtime_name"] not in overlays, "runtime覆盖名称重复")
        matches = [item for item in h0_plan["files"] if item["path"] == row["source"]["path"]]
        require(len(matches) == 1 and (matches[0]["bytes"], matches[0]["sha256"]) == (row["bytes"], row["sha256"]), "runtime复用身份不是H0已取得原件")
        overlays[row["runtime_name"]] = {"path": "scripts/renpy/" + row["runtime_name"], "bytes": row["bytes"], "sha256": row["sha256"]}
    require(len(overlays) == RUNTIME_LAYOUT["overlay_file_count"], "runtime覆盖须恰好14文件")
    if execution:
        overlays["run_locked_host_python_tasks.py"].update(bytes=51630, sha256=EXECUTION_H1_SHA)
    expected.update({row["path"]: row for row in overlays.values()})
    require(len(expected) == RUNTIME_LAYOUT["derived_file_count"], "派生root完整集合须35文件")
    return sorted(expected.values(), key=lambda row: row["path"])


def verify_runtime_root(h0, destination, catalog):
    """逐件核完整root的实际SHA/size，并拒绝额外目录、链接或特殊文件。"""
    h0.verify_files(destination, catalog)
    directories = {parent.as_posix() for row in catalog for parent in Path(row["path"]).parents if parent.as_posix() != "."}
    for root, names, _ in os.walk(destination, followlinks=False):
        require(all((Path(root) / name).relative_to(destination).as_posix() in directories for name in names), "派生root多出未批准目录")


def prepare_runtime(h0, payload, addon, manifest, destination, h0_plan):
    """先克隆完整28件H0 root，再叠加14固定原件；原103输入不变、不伪造Git。"""
    require(not destination.exists() and not destination.is_relative_to(payload) and not payload.is_relative_to(destination), "派生root必须全新且与原H0分离")
    destination = h0.regular(destination);destination.mkdir(parents=True)
    for row in h0_plan["files"]:
        if not row["path"].startswith("root/"):continue
        data = h0.read(payload / row["path"], row["bytes"])
        require(len(data) == row["bytes"] and h0.digest(data) == row["sha256"], "H0原root实际字节不符")
        target = destination / row["path"][5:];h0.regular(target);target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:stream.write(data)
    scripts = destination / "scripts/renpy"
    for row in manifest["runtime"]:
        data = h0.read(addon / row["path"]);require(h0.digest(data) == RUNTIME[row["name"]] and len(data) == row["bytes"], "新增runtime原件改变")
        require(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == row["source_blob_oid"], "新增runtime Git blob不符")
        with (scripts / row["name"]).open("xb") as stream:stream.write(data)
    for row in manifest["runtime_reuse_from_h0"]:
        data = h0.read(payload / row["source"]["path"]);require(h0.digest(data) == row["sha256"] and len(data) == row["bytes"], "复用runtime原件改变")
        target = scripts / row["runtime_name"]
        if target.exists():require(h0.read(target) == data, "已克隆H0原工具不允许改变")
        else:
            with target.open("xb") as stream:stream.write(data)
    verify_runtime_root(h0, destination, runtime_root_catalog(h0_plan, manifest, execution=False))


def verify_fresh_runtime(h0, destination, output):
    """新隔离子进程实际从派生ROOT读取18来源与3原tar，不复用父进程模块缓存。"""
    require(output.is_dir(), "fresh runtime报告目录不存在")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", FRESH_RUNTIME_PROBE, str(destination)],
                            capture_output=True, timeout=180, env={"LANG": "C", "LC_ALL": "C"})
    for name, data in (("stdout", result.stdout), ("stderr", result.stderr)):
        with (output / ("derived-runtime-probe." + name)).open("xb") as stream:stream.write(data)
    require(result.returncode == 0, "全新进程派生root依赖/来源核验失败，见derived-runtime-probe.stderr")
    proof = h0.decode(result.stdout)
    require(proof["root"] == proof["replay_root"] == proof["inputs_root"] == proof["build_root"] == str(destination)
            and proof["source_evidence_count"] == 18 and len(proof["source_archives"]) == 3
            and proof["H1_dependency_contract_verified"] is True and proof["native_build_executed"] is False, "fresh runtime来源范围不符")
    return proof


def apply_execution_overlay(h0, runtime, expected):
    """先证实旧addon源码，再只替换派生runtime中的固定basename；新旧身份分别保留。"""
    require(expected == EXECUTION_H1_SHA and expected != ADDON_H1_SHA, "H1执行覆盖身份不是批准新原件")
    name = "run_locked_host_python_tasks.py";target = runtime / name
    require(h0.digest(h0.read(target)) == ADDON_H1_SHA, "执行覆盖前不是已验addon旧H1原件")
    source = h0.read(HERE / name, 128 * 1024)
    require(h0.digest(source) == expected, "同目录H1执行原件SHA不符")
    temporary = runtime / "host-task-execution-overlay.tmp"
    with temporary.open("xb") as stream:stream.write(source)
    os.replace(temporary, target)
    require(h0.digest(h0.read(target)) == expected, "派生runtime执行覆盖实际字节不符")
    return {"basename": name, "addon_h1_tool_sha256": ADDON_H1_SHA, "execution_h1_tool_sha256": expected,
            "reason": EXECUTION_REASON, "only_derived_runtime_modified": True}


def preserve_route(run, release):
    """无论原Task成功或失败，关闭容器前尽力保全原日志；成功分发另带完整tar。"""
    script = run.output / "generated/h1-preserve-host.py"
    if not script.exists():
        with script.open("x") as stream:stream.write(PRESERVE)
        run.copy(script, "/reko/h1-preserve-host.py", "h1-copy-host-preserver")
    try:
        run.run(["/usr/bin/python3", "-B", "/reko/h1-preserve-host.py", release], "h1-preserve-host-" + release)
    finally:
        # 即使完整分发导出拒绝，也先拷回已保全的原失败报告和native-build.log。
        run.host([run.docker, "cp", run.name + ":/reko/h1-public/" + release, str(run.output / ("host-" + release))], "h1-copy-host-public-" + release)


def bind_interpreter(receipt, inventory, release):
    """精确runtime与完整tar中的真实可执行ELF条目必须绑定同一解释器SHA。"""
    version = {"8.5.3": "3.12.8", "8.4.1": "3.12.8", "8.3.7": "3.9.10", "7.8.7": "2.7.18"}[release]
    prefix = "/reko/h1-workspaces/" + release + "/tmp/host";runtime = receipt["runtime"]
    name = "bin/python" + ".".join(version.split(".")[:2])
    found = [item for item in inventory if item["path"] == name]
    require(runtime["version"] == version and runtime["platform"] == ("linux2" if release == "7.8.7" else "linux") and runtime["machine"] == "x86_64"
            and runtime["implementation"] == "CPython" and runtime["prefix"] == prefix and runtime["functional_probes_passed"] is True
            and receipt["prefix"] == prefix and receipt["interpreter"] == prefix + "/bin/python" + version[0]
            and runtime["executable"] in (receipt["interpreter"], prefix + "/" + name)
            and len(found) == 1 and found[0]["type"] == "file" and found[0]["mode"] == "100755"
            and int(found[0]["permissions"], 8) & 0o111 and found[0]["sha256"] == receipt["interpreter_sha256"]
            and found[0]["elf"] == receipt["elf"] and receipt["elf"]["class"] == 64 and receipt["elf"]["endian"] == "little"
            and receipt["elf"]["machine"] == 62 and receipt["elf"]["type"] in (2, 3), "host解释器runtime/完整分发binary绑定错误")


def verify_distribution_tar(h0, archive, inventory):
    """不执行native程序，独立核真实tar的全部文件/目录/链接和已声明ELF头。"""
    expected = {item["path"]: item for item in inventory};require(expected and len(expected) == len(inventory), "host分发manifest空或重复")
    links = {}
    for item in inventory:
        h0.safe_name(item["path"])
        require(item["type"] in ("file", "directory", "symlink") and re.fullmatch(r"[0-7]{4}", item["permissions"]), "host分发成员类型/权限错误")
        if item["type"] == "symlink":links[item["path"]] = item["target"]
    inventory_module = sys.modules["inventory_source_inputs"]
    require(h0.digest(h0.read(Path(inventory_module.__file__))) == RUNTIME["inventory_source_inputs.py"], "host链接校验器不是冻结原件")
    inventory_module.validate_links(links)
    seen = set()
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle:
            require(member.name in expected and member.name not in seen, "host tar多项/重复")
            item = expected[member.name];seen.add(member.name)
            require(format(member.mode, "04o") == item["permissions"], "host tar权限不符")
            if item["type"] == "directory":require(member.isdir(), "host tar目录类型错误")
            elif item["type"] == "symlink":require(member.issym() and member.linkname == item["target"] and h0.digest(member.linkname.encode()) == item["sha256"], "host tar链接文字错误")
            else:
                require(member.isfile() and member.size == item["bytes"], "host tar文件类型/长度错误")
                sha = hashlib.sha256();size = 0;header = b""
                with bundle.extractfile(member) as stream:
                    while block := stream.read(256 * 1024):size += len(block);sha.update(block);header = (header + block)[:64]
                require(size == item["bytes"] and sha.hexdigest() == item["sha256"], "host tar成员原字节错误")
                if "elf" in item:
                    require(len(header) >= 64 and header[:7] == b"\x7fELF\x02\x01\x01", "host tar ELF头错误")
                    kind, machine = struct.unpack_from("<HH", header, 16)
                    require(item["elf"] == {"class": 64, "endian": "little", "machine": machine, "type": kind}
                            and machine == 62 and kind in (1, 2, 3), "host tar实际ELF身份与manifest不同")
    require(seen == set(expected), "host tar缺少完整分发成员")


def verify_export(h0, folder, release, frontend_sha):
    """独立复核原收据/全分发manifest及tar每个字节/模式/链接，禁止单binary冒充分发。"""
    receipt_raw = h0.read(folder / "host-receipt.json", 32 * 1024**2);receipt = h0.decode(receipt_raw)
    inventory_raw = h0.read(folder / "host-distribution.json", 32 * 1024**2);inventory = h0.decode(inventory_raw)
    report = h0.decode(h0.read(folder / "report.json"));export = h0.decode(h0.read(folder / "host-export.json"))
    prefix = "/reko/h1-workspaces/" + release + "/tmp/host"
    require(report["result"] == "passed" and report["host_bootstrap_verified"] is True and report["linux_native_bootstrap_completed"] is True
            and receipt["release"] == release and receipt["plan_sha256"] == H1_PLAN_SHA and receipt["prefix"] == prefix
            and receipt["host_bootstrap_verified"] is True and receipt["kernel_network_isolation_verified"] is True
            and receipt["original_host_task_count"] == 2 and receipt["frontend"]["sha256"] == frontend_sha
            and receipt["explicit_native_ssl_candidate_count"] == (2 if release == "7.8.7" else 0)
            and receipt["target_python_install_verified"] is False and receipt["target_pip_bound"] is False
            and receipt["source_ci_verified"] is False and receipt["J2C_nine_scopes_complete"] is False
            and receipt["runtime_consumption_verified"] is False and receipt["complete_input_closure"] is False
            and report["host_receipt"]["sha256"] == h0.digest(receipt_raw)
            and receipt["distribution"]["sha256"] == h0.digest(inventory_raw), "H1真实原收据/完整分发身份不符")
    require(export["release"] == release and export["prefix"] == prefix and export["complete_distribution_exported"] is True
            and export["receipt_sha256"] == h0.digest(receipt_raw) and export["distribution_sha256"] == h0.digest(inventory_raw)
            and export["archive"]["path"] == "host-distribution.tar.gz" and export["member_count"] == len(inventory), "完整host导出记录错误")
    bind_interpreter(receipt, inventory, release)
    archive = folder / "host-distribution.tar.gz";raw = h0.read(archive, 1024**3)
    require(len(raw) == export["archive"]["bytes"] and h0.digest(raw) == export["archive"]["sha256"], "host完整tar原字节不符")
    verify_distribution_tar(h0, archive, inventory)
    return {"release": release, "prefix": prefix, "receipt_sha256": h0.digest(receipt_raw), "distribution_sha256": h0.digest(inventory_raw),
            "archive": export["archive"], "complete_distribution_exported": True, "host_bootstrap_verified": True}


def execute_group(run, h0, payload, h0_plan, manifest, addon_manifest, workspaces, runtime, ubuntu, report):
    """固定同lifetime先H0后两路线原H1，失败保全后继续独立路线；无通用执行钩子。"""
    group = next(g for g in h0_plan["groups"] if g["ubuntu"] == ubuntu)
    original = h0.replay_host_group(run, payload, group, h0_plan, manifest, report)
    source, _ = run.run(["sha256sum", "/reko/h0-replay/report.json"], "h1-original-frontend-report-hash")
    frontend_sha = source.decode().split()[0]
    require(frontend_sha == report["original_replay_report_sha256"], "容器原H0收据SHA与回传原件不同")
    run.run(["mkdir", "-p", REMOTE_ROOT, "/reko/h1-workspaces"], "h1-runtime-directories")
    run.copy(str(runtime) + "/.", REMOTE_ROOT, "h1-copy-derived-runtime-root")
    run.checksum("h1-runtime-root", [(h0.digest(h0.read(path)), REMOTE_ROOT + "/" + path.relative_to(runtime).as_posix())
                                  for path in sorted(runtime.rglob("*")) if path.is_file()])
    report["routes"] = []
    for release in GROUPS[ubuntu]:
        row = {"release": release, "host_bootstrap_verified": False, "errors": []};report["routes"].append(row)
        scope = next(s for s in original["scopes"] if s["id"] == next(r["frontend_scope"] for r in addon_manifest["host_routes"] if r["release"] == release))
        frontend = scope["environment"]["prefix"] + "/bin/python"
        workspace = "/reko/h1-workspaces/" + release;output = "/reko/h1-output/" + release
        try:
            run.copy(workspaces / release, workspace, "h1-copy-pristine-recipe-" + release)
            check = "import sys;sys.path.insert(0,'" + REMOTE_RUNTIME + "');import run_locked_source_tasks as j; p=j.checked_json(j.HERE/'source-task-binding-plan.json',j.PLAN_SHA256);r=next(x for x in p['routes'] if x['release']==sys.argv[1]);j.verify_repository(j.repository_row(p,r),__import__('pathlib').Path(sys.argv[2]))"
            run.run(["/usr/bin/python3", "-B", "-c", check, release, workspace], "h1-reverify-full-recipe-" + release)
            command = [run.docker, "exec", run.name, "env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC",
                       "DEBIAN_FRONTEND=noninteractive", "PYTHONHASHSEED=0", "PYTHONDONTWRITEBYTECODE=1", frontend, "-s", "-B", REMOTE_RUNTIME + "/run_locked_host_python_tasks.py",
                       "run", "--release", release, "--root", "/reko/h1-runtime/root", "--workspace", workspace, "--output", output,
                       "--frontend-report", "/reko/h0-replay/report.json", "--frontend-report-sha256", frontend_sha,
                       "--source-cache", "/reko/h0-inputs/cache", "--tool-cache", "/reko/h0-inputs/cache", "--ccache-dir", "/reko/h1-ccache"]
            try:
                run.commands.run(command, "h1-original-host-tasks-" + release, timeout=7500)
            finally:
                preserve_route(run, release)
            row.update(verify_export(h0, run.output / ("host-" + release), release, frontend_sha))
        except Exception as error:
            row["errors"].append(type(error).__name__ + ": " + str(error))
    require(all(r["host_bootstrap_verified"] is True and not r["errors"] for r in report["routes"]), "本组存在原host Task失败或分发未保全")


def main(argv=None):
    """只接受固定两组参数，宿主材料finally清理且容器close后才确认本组H1。"""
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument("--ubuntu", choices=sorted(GROUPS), required=True)
    parser.add_argument("--bundle", type=Path, required=True);parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv);password = os.environ.pop("REKO_H0_INPUTS_PASSWORD", None)
    report = {"task": "R00-02J2C-H1-Linux", "result": "failed", "ubuntu": args.ubuntu, "errors": [], "H0_group_complete": False,
              "group_host_bootstrap_complete": False, "H1_all_four_routes_complete": False, "J2C_complete": False, "target_pip_bound": False,
              "target_python_install_verified": False, "source_ci_verified": False, "sdk_inputs_consumed": False, "recipe_git_metadata_restored": False,
              "container_closed": False, "private_inputs_removed": False}
    created = False;private = None;transport = None
    try:
        transport, h0, h0_plan, _ = load_helpers();load_plan(transport)
        args.output, args.bundle = transport.guarded(args.output), transport.guarded(args.bundle)
        require(not args.output.exists() and args.output.parent.is_dir() and not args.output.is_relative_to(args.bundle)
                and not args.bundle.is_relative_to(args.output), "输出必须全新且与APT分离")
        args.output.mkdir();created = True
        require(sys.platform == "linux" and platform.machine() == "x86_64", "实际原host构建需要Linux x86_64与Docker")
        require(password, "缺少固定H0运输密钥")
        temporary_root = transport.guarded(os.environ.get("RUNNER_TEMP", ""))
        require(os.environ.get("RUNNER_TEMP") and temporary_root.is_dir() and not temporary_root.is_relative_to(args.output)
                and not temporary_root.is_relative_to(args.bundle), "缺少独立RUNNER_TEMP")
        checkout = os.environ.get("GITHUB_WORKSPACE");require(not checkout or not temporary_root.is_relative_to(transport.guarded(checkout)), "私有输入不能位于checkout")
        with tempfile.TemporaryDirectory(prefix="reko-h1-inputs-", dir=temporary_root) as directory:
            private = Path(directory);os.chmod(private, 0o700)
            encrypted, plain, payload = private / "inputs.enc", private / "inputs.tar.gz", private / "h0-payload"
            transport.download(transport.TRANSPORT, encrypted);transport.decrypt(encrypted, plain, transport.TRANSPORT, password);password = None
            transport.extract_payload(plain, payload, h0_plan["files"]);encrypted.unlink();plain.unlink()
            h0.verify_files(payload, h0_plan["files"]);python_manifest, _ = h0.verify_original_contracts(payload, h0_plan["files"])
            archive = private / "addon.tar.gz";download_addon(transport, archive)
            addon_manifest = read_manifest(transport, h0, archive, private / "addon-manifest.json")
            with tarfile.open(archive, "r:gz") as bundle:
                data = bundle.extractfile("runtime/host-python-bootstrap-plan.json").read(1024**2)
            require(h0.digest(data) == H1_PLAN_SHA, "H1计划原件SHA错误");h1_plan = h0.decode(data)
            routes, objects, catalog = derive_addon(transport, h0, payload, addon_manifest, h0_plan, h1_plan)
            addon = private / "addon";transport.extract_payload(archive, addon, catalog);archive.unlink()
            for sha, row in objects.items():raw_object(h0, payload, addon, sha, row)
            j8 = h0.load_module(addon / "runtime/run_locked_source_tasks.py", RUNTIME["run_locked_source_tasks.py"], "reko_h1_source_tasks")
            h0.load_module(addon / "runtime/inventory_source_inputs.py", RUNTIME["inventory_source_inputs.py"], "inventory_source_inputs")
            workspaces = private / "workspaces";workspaces.mkdir()
            for release in GROUPS[args.ubuntu]:
                rebuild_workspace(j8, routes[release], workspaces / release, lambda item: raw_object(h0, payload, addon, item["sha256"], objects[item["sha256"]]))
            runtime = private / "h1-runtime/root";prepare_runtime(h0, payload, addon, addon_manifest, runtime, h0_plan)
            report["execution_overlay"] = apply_execution_overlay(h0, runtime / "scripts/renpy", EXECUTION_H1_SHA)
            catalog = runtime_root_catalog(h0_plan, addon_manifest, execution=True);verify_runtime_root(h0, runtime, catalog)
            report["derived_runtime_root"] = {"layout": RUNTIME_LAYOUT, "files": catalog}
            report["derived_runtime_fresh_contracts"] = verify_fresh_runtime(h0, runtime, args.output)
            report["derived_H1_dependency_contract_verified"] = True
            container_output = args.output / "container";container_output.mkdir();args_for_h0 = argparse.Namespace(payload=payload, bundle=args.bundle, ubuntu=args.ubuntu, output=container_output)
            report.update(addon_inputs_verified=True, original_recipe_entries=1793, unique_source_objects=630,
                          addon_h1_tool_sha256=ADDON_H1_SHA, execution_h1_tool_sha256=EXECUTION_H1_SHA,
                          H1_plan_sha256=H1_PLAN_SHA, addon_manifest_sha256=MANIFEST["sha256"], addon_sha256=ADDON["sha256"])
            # 此派生字段只向固定编排提供原计划路线，不写回addon原件或原计划。
            execution_manifest = {**addon_manifest, "host_routes": h1_plan["routes"]}
            try:
                with h0.open_environment(args_for_h0, h0_plan, report) as run:
                    execute_group(run, h0, payload, h0_plan, python_manifest, execution_manifest, workspaces, runtime, args.ubuntu, report)
            finally:
                h0.write(container_output / "h0-h1-lifetime-report.json", report)
            require(report["container_closed"] is True, "受控容器未关闭")
        require(not private.exists(), "本轮私有输入未清理")
        report.update(result="same_lifetime_H0_and_selected_original_host_tasks_completed", group_host_bootstrap_complete=True)
    except Exception as error:
        report["errors"].append(type(error).__name__ + ": " + str(error));report["result"] = "failed"
    finally:
        password = None;report["private_inputs_removed"] = private is not None and not private.exists()
        if report["result"] == "failed":report["group_host_bootstrap_complete"] = False
        if created:transport.write_json(args.output / "linux-host-python-bootstrap-report.json", report)
    log("结果=" + report["result"] + "；" + "; ".join(report["errors"]))
    return 0 if report["result"] != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
