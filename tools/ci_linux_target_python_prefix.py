#!/usr/bin/env python3
"""在固定C1同一容器中恢复原host分发并执行原iOS C前置任务；不验收target Python/pip。"""

from __future__ import annotations

import argparse
import ast
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
import types


HERE = Path(__file__).absolute().parent
DEFAULT_PLAN = HERE / "linux-target-python-prefix-ci-plan.json"
PLAN_SHA256 = "0ccd2615dde8d009b25a3e076edfac9dccab33f34d956e42ef4f55ee1105a58b"
GROUPS = {"22.04": ["8.3.7", "7.8.7"], "24.04": ["8.5.3", "8.4.1"]}
ARCHES = ("arm64", "sim-arm64", "sim-x86_64")
REMOTE_ROOT = "/reko/j9-runtime/root"
REMOTE_WORKSPACES = "/reko/j9-workspaces"
REMOTE_OUTPUT = "/reko/j9-results"

# 私有回收只取本阶段输出与build诊断，绝不复制tmp整体、cross SDK树或locked-sdk-tars。
PRESERVE_PRIVATE = r'''import os,pathlib,shutil,stat,sys
target=pathlib.Path('/reko/j9-preserved-private');target.mkdir()
def copy(source,destination):
 """私有诊断仅复制真实普通文件，不沿符号链接回取SDK输入。"""
 if source.is_symlink() or not stat.S_ISREG(source.lstat().st_mode):raise ValueError('unsafe diagnostic')
 destination.parent.mkdir(parents=True,exist_ok=True)
 with source.open('rb') as inp,destination.open('xb') as out:shutil.copyfileobj(inp,out,262144)
def tree(source,destination,only_logs=False):
 """完整保存worker输出；build树仅保存原始日志和明确配置诊断。"""
 if not source.is_dir():return
 for current,directories,files in os.walk(source,followlinks=False):
  current=pathlib.Path(current)
  directories[:]=[name for name in directories if name!='ccache' and not (current/name).is_symlink()]
  for name in files:
   if only_logs and not (name.endswith('.log') or name in ('config.status','CMakeCache.txt','meson-log.txt')):continue
   p=current/name;copy(p,destination/p.relative_to(source))
for key in sys.argv[1:]:
 release,arch=key.split(':');assert release in ('8.5.3','8.4.1','8.3.7','7.8.7') and arch in ('arm64','sim-arm64','sim-x86_64')
 tree(pathlib.Path('/reko/j9-results')/release/arch,target/'workers'/release/arch)
 tree(pathlib.Path('/reko/j9-workspaces')/release/arch/'tmp/build',target/'build-diagnostics'/release/arch,True)
'''

# 先在原容器重核全部产物，再仅打包arch C前缀；cross SDK和SDK tar均不在此目录。
EXPORT_C_PREFIX = r'''import hashlib,json,pathlib,shutil,sys,tarfile,types
metadata,release,arch,worker_sha=sys.argv[1:];metadata=pathlib.Path(metadata)
p=metadata/'scripts/renpy/run_locked_target_python_tasks.py';raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()==worker_sha
m=types.ModuleType('reko_j9_export_worker');m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__)
plan=m.load_plan();inventory,j8,native,validator,common,preflight=m.helpers(plan);row=next(r for r in plan['routes'] if r['release']==release)
folder=pathlib.Path('/reko/j9-results')/release/arch;receipt=json.loads((folder/'c-prefix-receipt.json').read_bytes())
prefix=pathlib.Path('/reko/j9-workspaces')/release/arch/'tmp'/('install.ios-'+arch)
assert receipt['prefix']==str(prefix) and receipt['C_prerequisites_verified'] is True and receipt['plan_sha256']==m.PLAN_SHA256
assert receipt['execution_source_sha256']==worker_sha and all(receipt[k] is False for k in m.FALSE_BOUNDARIES)
products=m.verify_c_products(prefix,row,arch,inventory,preflight);entries=json.loads((folder/'c-prefix-inventory.json').read_bytes())
objects={key:products[key] for key in ('archives','executables','object_sdk_boundary')}
assert products['inventory']==entries and objects==json.loads((folder/'c-archive-objects.json').read_bytes())
target=pathlib.Path('/reko/j9-private-products')/release/arch;target.mkdir(parents=True)
archive=target/'c-prefix.tar.gz'
with tarfile.open(archive,'w:gz',format=tarfile.USTAR_FORMAT) as bundle:
 for item in entries:
  name=item['path'];assert not name.startswith('/') and all(x not in ('','.','..') for x in name.split('/'))
  assert 'SDKSettings.json' not in name and 'locked-sdk-tars' not in name and not any(x.endswith('.sdk') for x in name.split('/'))
  p=prefix/name;info=tarfile.TarInfo(name);info.mode=int(item['permissions'],8)
  if item['type']=='directory':info.type=tarfile.DIRTYPE;bundle.addfile(info)
  elif item['type']=='symlink':info.type=tarfile.SYMTYPE;info.linkname=item['target'];bundle.addfile(info)
  else:
   assert item['type']=='file';info.size=item['bytes']
   with p.open('rb') as stream:bundle.addfile(info,stream)
for name in ('c-prefix-inventory.json','c-archive-objects.json','c-headers-and-sources.json'):
 with (folder/name).open('rb') as inp,(target/name).open('xb') as out:shutil.copyfileobj(inp,out,262144)
result={'release':release,'arch':arch,'original_prefix':str(prefix),'worker_sha256':worker_sha,'plan_sha256':m.PLAN_SHA256,
 'receipt_sha256':hashlib.sha256((folder/'c-prefix-receipt.json').read_bytes()).hexdigest(),
 'inventory_sha256':hashlib.sha256((target/'c-prefix-inventory.json').read_bytes()).hexdigest(),
 'archive':{'path':archive.name,'bytes':archive.stat().st_size,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest()},
 'member_count':len(entries),'C_prerequisites_verified':True,'target_python_install_verified':False,'target_pip_bound':False,'ios_runtime_verified':False}
(target/'export.json').write_text(json.dumps(result,sort_keys=True)+'\n');print(json.dumps(result))
'''

# 宿主只解码原字节/静态对象，不执行Linux或iOS产物；所有提取先验证再写且链接最后恢复。
VERIFY_C_EXPORT = r'''import hashlib,json,os,pathlib,shutil,sys,tarfile,types
metadata,folder,workspace,worker_sha=sys.argv[1:];metadata=pathlib.Path(metadata);folder=pathlib.Path(folder);workspace=pathlib.Path(workspace)
p=metadata/'scripts/renpy/run_locked_target_python_tasks.py';raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()==worker_sha
m=types.ModuleType('reko_j9_host_product_reader');m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__)
plan=m.load_plan();inventory,j8,native,validator,common,preflight=m.helpers(plan)
export=json.loads((folder/'export.json').read_bytes());release,arch=export['release'],export['arch'];row=next(r for r in plan['routes'] if r['release']==release)
assert export['worker_sha256']==worker_sha and export['plan_sha256']==m.PLAN_SHA256 and export['C_prerequisites_verified'] is True
entries=json.loads((folder/'c-prefix-inventory.json').read_bytes());assert hashlib.sha256((folder/'c-prefix-inventory.json').read_bytes()).hexdigest()==export['inventory_sha256']
expected={x['path']:x for x in entries};assert len(expected)==len(entries)==export['member_count'] and expected
inventory.validate_links({x['path']:x['target'] for x in entries if x['type']=='symlink'})
folded=set()
for name in expected:
 assert not name.startswith('/') and '\\' not in name and all(x not in ('','.','..') for x in name.split('/')) and name.casefold() not in folded
 folded.add(name.casefold())
 for parent in pathlib.PurePosixPath(name).parents:
  if str(parent)!='.':assert expected[str(parent)]['type']=='directory'
archive=folder/export['archive']['path'];assert export['archive']['path']=='c-prefix.tar.gz' and archive.stat().st_size==export['archive']['bytes']
assert hashlib.sha256(archive.read_bytes()).hexdigest()==export['archive']['sha256'];seen=set()
with tarfile.open(archive,'r:gz') as source:
 for member in source:
  assert member.name in expected and member.name not in seen and not member.pax_headers and not member.sparse;seen.add(member.name);item=expected[member.name]
  assert format(member.mode,'04o')==item['permissions']
  if item['type']=='directory':assert member.isdir()
  elif item['type']=='symlink':assert member.issym() and member.linkname==item['target'] and hashlib.sha256(member.linkname.encode()).hexdigest()==item['sha256']
  else:
   assert item['type']=='file' and member.isfile() and member.size==item['bytes']
   with source.extractfile(member) as stream:
    digest=hashlib.sha256();size=0
    while block:=stream.read(262144):digest.update(block);size+=len(block)
   assert size==item['bytes'] and digest.hexdigest()==item['sha256']
assert seen==set(expected);destination=folder/'verified-prefix';assert not destination.exists();destination.mkdir()
# 无论解包/产物核验在哪一步拒绝，均只清理本轮临时展开树；原tar和诊断通道保留。
try:
 with tarfile.open(archive,'r:gz') as source:
  for member in source:
   item=expected[member.name];target=destination/member.name
   if item['type']=='symlink':continue
   target.parent.mkdir(parents=True,exist_ok=True)
   if item['type']=='directory':target.mkdir(exist_ok=True)
   else:
    with source.extractfile(member) as inp,target.open('xb') as out:shutil.copyfileobj(inp,out,262144)
    target.chmod(int(item['permissions'],8))
 for item in entries:
  if item['type']=='symlink':(destination/item['path']).symlink_to(item['target'])
 for item in sorted(entries,key=lambda r:r['path'].count('/'),reverse=True):
  if item['type']=='directory':(destination/item['path']).chmod(int(item['permissions'],8))
 actual=m.verify_c_products(destination,row,arch,inventory,preflight)
 objects={key:actual[key] for key in ('archives','executables','object_sdk_boundary')}
 assert actual['inventory']==entries and objects==json.loads((folder/'c-archive-objects.json').read_bytes())
 headers=json.loads((folder/'c-headers-and-sources.json').read_bytes());assert headers=={'headers':actual['headers'],'sources':row['sources'],'extra_inputs':row['extra_inputs']}
 framework=next(x for x in row['extra_inputs'] if x['path']==('source/MetalANGLE.framework.ios.zip' if arch=='arm64' else 'source/MetalANGLE.framework.ios.simulator.zip'))
 source=workspace/framework['path'];assert source.stat().st_size==framework['size'] and hashlib.sha256(source.read_bytes()).hexdigest()==framework['sha256']
 m.verify_framework(source,destination,arch,inventory)
finally:
 shutil.rmtree(destination)
print(json.dumps({'release':release,'arch':arch,'inventory_members':len(entries),'static_archive_count':len(actual['archives']),
 'MachO_object_count':sum(a['object_count'] for a in actual['archives']),'all_exported_member_bytes_and_MachO_objects_verified':True,'MetalANGLE_original_binary_verified_not_source_rebuilt':True,'returned_binary_executed_on_host':False}))
'''


class InputUnavailable(ValueError):
    """必要实物或运行条件不存在时记未运行，不伪造本阶段成功。"""


def require(condition, message):
    """拒绝错误原件或协议，调用者不能将实际失败提升为未运行。"""
    if not condition:
        raise ValueError(message)


def log(message):
    """仅输出固定阶段和状态，不打印SDK诊断正文或运输秘密。"""
    print("[RenPyTargetPythonPrefix] " + message, flush=True)


def guarded(path):
    """拒绝上跳及任一层符号链接，保持原输入与本轮输出边界。"""
    path = Path(path).absolute()
    require(".." not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), "路径含链接或上跳")
    return path


def file_identity(path, maximum=2 * 1024**3):
    """有界读取真实普通文件，全字节计算SHA并拒绝设备/FIFO/叶链接。"""
    path = guarded(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= maximum, "原件不是有界普通文件")
        count = 0;digest = hashlib.sha256()
        while block := stream.read(256 * 1024):
            count += len(block);digest.update(block)
    require(count == info.st_size, "原件读取期间长度改变")
    return {"bytes": count, "sha256": digest.hexdigest()}


def regular_bytes(path, maximum=32 * 1024**2):
    """同一有界普通文件描述符读取小原件，校验和编译共用同份buffer。"""
    path = guarded(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= maximum, "小原件类型/大小错误")
        raw = stream.read(maximum + 1)
    require(len(raw) == info.st_size, "小原件读取期间长度改变")
    return raw


def unique_pairs(pairs):
    """拒绝JSON重复键，不允许后项覆盖固定身份。"""
    result = {}
    for key, value in pairs:
        require(key not in result, "JSON字段重复")
        result[key] = value
    return result


def reject_nonfinite(value):
    """拒绝非JSON有限数值，不以NaN绕过显式状态。"""
    raise ValueError("JSON含非有限数值")


def read_json(path):
    """从已验普通小文件严格解码，不接受隐式宽松JSON。"""
    return json.loads(regular_bytes(path), object_pairs_hook=unique_pairs, parse_constant=reject_nonfinite)


def write_json(path, value):
    """独占写本轮新证据，不覆盖原报告或其他运行。"""
    with guarded(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2);stream.write("\n")


def verify_external_file(path, expected_sha, expected_bytes):
    """强制外部明确大小/SHA，不能只读取同包自签manifest作身份。"""
    require(type(expected_bytes) is int and 0 < expected_bytes <= 2 * 1024**3
            and isinstance(expected_sha, str) and re.fullmatch("[0-9a-f]{64}", expected_sha), "外部身份格式错误")
    require(file_identity(path) == {"bytes": expected_bytes, "sha256": expected_sha}, "外部原件字节身份不符")


def load_verified(aliases, expected_sha, name):
    """直接编译同一份已核源码buffer，拒绝同名模块/未锁pyc替换。"""
    require(name not in sys.modules, "固定helper已被外部加载")
    paths = [HERE / candidate for candidate in aliases if (HERE / candidate).exists()]
    require(paths, "固定helper未部署")
    sources = []
    for path in paths:
        raw = regular_bytes(path, 256 * 1024)
        require(hashlib.sha256(raw).hexdigest() == expected_sha, "固定helper源码改变")
        sources.append(raw)
    module = types.ModuleType(name);module.__file__ = str(paths[0]);module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(compile(sources[0], str(paths[0]), "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None);raise
    return module


def function_identity(source_path, name):
    """固定已验审计函数原文，记录有界producer profile绑定而不改原生产报告。"""
    raw = regular_bytes(source_path, 256 * 1024);text = raw.decode("utf-8")
    nodes = [n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == name]
    require(len(nodes) == 1, "审计函数缺失或重复")
    return hashlib.sha256(ast.get_source_segment(text, nodes[0]).encode("utf-8")).hexdigest()


def bind_export_checker(wrapper, expected_function_sha, producer_plan_sha):
    """仅给已锁verify_export函数绑定批准的352/9e合同，保留原producer与函数身份。"""
    approved = {"352f7af5dbd7f31d6199f1d6b536a99405cf249c7969cbfd69260a455c6b84e0",
                "9e07264629245df5ab2692485b6342222cf458cdcab3f31b802e80bf895e5a32"}
    require(producer_plan_sha in approved and function_identity(Path(wrapper.__file__), "verify_export") == expected_function_sha,
            "producer profile或审计函数不是批准身份")
    namespace = dict(wrapper.__dict__);namespace["EXECUTION_H1_PLAN_SHA"] = producer_plan_sha
    original = wrapper.verify_export
    return types.FunctionType(original.__code__, namespace, "verify_export_bound_to_approved_producer", original.__defaults__, original.__closure__)


def validate_addon_catalog(catalog):
    """增量包只允许固定runtime普通文件，拒绝自定路径/重复项/缺少强身份。"""
    require(isinstance(catalog, list) and catalog, "增量包清单为空")
    seen = set()
    for row in catalog:
        require(set(row) == {"path", "bytes", "sha256"} and isinstance(row["path"], str), "增量包字段错误")
        parts = row["path"].split("/")
        require(len(parts) == 2 and parts[0] == "runtime" and parts[1] not in ("", ".", "..")
                and "\\" not in parts[1] and row["path"] not in seen, "增量包路径重复或越界")
        require(type(row["bytes"]) is int and 0 < row["bytes"] <= 32 * 1024**2
                and re.fullmatch("[0-9a-f]{64}", row["sha256"]), "增量包身份错误")
        seen.add(row["path"])


def extract_runtime_addon(h2, archive, destination, catalog):
    """复用已验逐成员USTAR校验，只接受本计划的精确普通文件投影。"""
    validate_addon_catalog(catalog)
    h2.extract_extra(guarded(archive), guarded(destination), catalog)


def public_failure(error, stage):
    """公开失败只含固定阶段和异常类别，SDK原文留给私有通道。"""
    allowed = {"inputs", "transport", "environment", "host_frontend", "host_restore", "sdk_toolchain", "c_prerequisites", "preserve"}
    require(stage in allowed, "失败阶段未知")
    return {"stage": stage, "kind": type(error).__name__, "code": "missing_required_input" if isinstance(error, InputUnavailable) else "stage_failed"}


def selected_host_export(h2, h0, wrapper, artifact, release, profile, producer, projection):
    """逐route核固定producer和完整原导出；旧352与新9e各自绑定，不重标原记录。"""
    header = read_json(artifact / "linux-host-python-bootstrap-report.json")
    require(header["task"] == "R00-02J2C-H1-Linux" and header["ubuntu"] == profile["ubuntu"]
            and header["sdk_inputs_consumed"] is False
            and header["execution_h1_tool_sha256"] == profile["execution_source_sha256"]
            and header["H1_plan_sha256"] == profile["execution_plan_sha256"], "H1原producer profile不符")
    if profile["require_explicit_plan_fields"]:
        require(header["execution_h1_plan_sha256"] == profile["execution_plan_sha256"]
                and header["addon_h1_plan_sha256"] == profile["addon_plan_sha256"], "新H1显式原/执行计划不符")
    for field, expected in (("execution_h1_plan_sha256", profile["execution_plan_sha256"]),
                            ("addon_h1_plan_sha256", profile["addon_plan_sha256"])):
        require(field not in header or header[field] == expected, "H1显式计划字段与原producer矛盾")
    require(producer["execution_source_sha256"] == profile["execution_source_sha256"]
            and producer["execution_plan_sha256"] == profile["execution_plan_sha256"], "route与producer映射不符")
    folder = artifact / "container" / ("host-" + release)
    names = ["report.json", "host-receipt.json", "host-distribution.json", "host-export.json", "host-distribution.tar.gz"]
    if not all((folder / name).is_file() for name in names):
        raise InputUnavailable("该route尚无完整H1分发")
    require(file_identity(folder / "host-receipt.json") == producer["receipt"]
            and file_identity(folder / "host-distribution.json") == producer["inventory"], "H1原收据/库存不在批准集合")
    frontend_sha = file_identity(artifact / "container/python-replay/report.json")["sha256"]
    checker = bind_export_checker(wrapper, projection["verify_export"], profile["execution_plan_sha256"])
    verified = checker(h0, folder, release, frontend_sha)
    require(verified["prefix"] == producer["original_prefix"]
            and read_json(folder / "host-receipt.json")["interpreter_sha256"] == producer["interpreter_sha256"], "H1原前缀/解释器不符")
    return {"release": release, "folder": str(folder), "export": verified, "producer": producer}


def prepare_runtime(h0, h1, payload, recipe_addon, recipe_manifest, h0_plan, runtime_addon, catalog, destination):
    """保留完整H0根和18来源，叠加既有H1旧deps及固定J9新原件；不修改原103输入。"""
    h1.prepare_runtime(h0, payload, recipe_addon, recipe_manifest, destination, h0_plan)
    h1.apply_execution_overlay(h0, destination / "scripts/renpy", h1.EXECUTION_H1_SHA)
    expected = {row["path"]: dict(row) for row in h1.runtime_root_catalog(h0_plan, recipe_manifest, execution=True)}
    for row in catalog:
        source = runtime_addon / row["path"];relative = "scripts/renpy/" + Path(row["path"]).name
        require(file_identity(source) == {k:row[k] for k in ("bytes", "sha256")} and relative not in expected, "J9增量不得覆盖既有H1依赖")
        target = guarded(destination / relative)
        with target.open("xb") as output:output.write(source.read_bytes())
        expected[relative] = {"path": relative, "bytes": row["bytes"], "sha256": row["sha256"]}
    source = payload / "c1-runtime/preflight_environment.py";relative = "scripts/renpy/preflight_environment.py"
    require(relative not in expected and file_identity(source)["sha256"] == h0.PINS["c1-runtime/preflight_environment.py"], "C0复用原件错误")
    target = guarded(destination / relative)
    with target.open("xb") as output:output.write(source.read_bytes())
    expected[relative] = {"path": relative, **file_identity(source)}
    rows = sorted(expected.values(), key=lambda row:row["path"])
    h1.verify_runtime_root(h0, destination, rows)
    return rows


def fresh_runtime_check(destination, output, worker_sha):
    """独立新进程核21个J9依赖/旧H1合同和稳定主锁投影；不构建或执行目标。"""
    code = r'''import hashlib,json,pathlib,sys,types
root=pathlib.Path(sys.argv[1]);p=root/'scripts/renpy/run_locked_target_python_tasks.py';raw=p.read_bytes()
assert hashlib.sha256(raw).hexdigest()==sys.argv[2];sys.dont_write_bytecode=True;sys.pycache_prefix=str(root/'unused-j9-check-pycache')
m=types.ModuleType('reko_j9_fresh_runtime');m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__)
plan=m.load_plan();inventory,j8,native,validator,common,preflight=m.helpers(plan)
host=native.load_plan(root/'scripts/renpy/host-python-bootstrap-plan.json')
for name in ('lock_python_inputs','build_python_wheels','replay_python_inputs'):
 m.load_helper(plan,name+'.py',name)
inputs=sys.modules['lock_python_inputs'];replay=sys.modules['replay_python_inputs']
replay_plan,builder,manifest,fingerprint=replay.load_plan(replay.DEFAULT_PLAN)
evidence=inputs.verify_evidence(manifest['scopes']);assert len(evidence)==18 and len(replay_plan['scopes'])==9
installers=replay.materialize_installers(replay_plan,pathlib.Path(sys.argv[3])/'installer-byte-check');assert len(installers)==3
source=json.loads((root/'scripts/renpy/source-inputs.lock.json').read_bytes());main=json.loads((root/'scripts/renpy/runtime-lock.json').read_bytes())
assert validator.runtime_anchor(main)==source['runtime_anchor_sha256']
print(json.dumps({'J9_dependencies_and_locks_verified':True,'H1_old_dependency_contract_verified':True,'source_evidence_count':18,'replay_scope_count':9,'original_CPython_archive_installers_verified':3,'runtime_anchor_sha256':source['runtime_anchor_sha256'],'C_tasks_executed':False}))
'''
    result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(destination), worker_sha, str(output)], capture_output=True, timeout=180)
    (output / "fresh-runtime.stdout").write_bytes(result.stdout);(output / "fresh-runtime.stderr").write_bytes(result.stderr)
    require(result.returncode == 0, "J9派生root独立合同失败")
    value = json.loads(result.stdout)
    require(value["J9_dependencies_and_locks_verified"] is True and value["H1_old_dependency_contract_verified"] is True
            and value["source_evidence_count"] == 18 and value["replay_scope_count"] == 9
            and value["original_CPython_archive_installers_verified"] == 3 and value["C_tasks_executed"] is False, "J9派生root验证范围错误")
    return value


def worker_argv(release, arch, metadata, workspace, output, sdk, clang_runtime, host, frontend_sha, producer, ccache=None):
    """构造固定J9A run入口，无任意后置命令或record-only生产选项。"""
    argv = [metadata + "/scripts/renpy/run_locked_target_python_tasks.py", "run", "--root", metadata,
            "--release", release, "--arch", arch, "--workspace", workspace, "--output", output,
            "--sdk", sdk, "--clang-runtime", clang_runtime, "--sdk-version", "14.0", "--deployment-target", "14.0",
            "--host-prefix", host, "--host-receipt", "/reko/j9-host-exports/" + release + "/host-receipt.json",
            "--host-receipt-sha256", producer["receipt"]["sha256"],
            "--host-inventory", "/reko/j9-host-exports/" + release + "/host-distribution.json",
            "--host-inventory-sha256", producer["inventory"]["sha256"],
            "--frontend-report", "/reko/h0-replay/report.json", "--frontend-report-sha256", frontend_sha,
            "--source-cache", "/reko/h0-inputs/cache", "--tool-cache", "/reko/h0-inputs/cache"]
    if ccache is not None:argv += ["--ccache-dir", ccache]
    return argv


def restore_original_host(run, h2, native, inventory, selected, system_python):
    """完整恢复原生产前缀并实际运行其探针；producer与审计函数投影分别记录。"""
    release = selected["release"];folder = Path(selected["folder"]);remote = "/reko/j9-host-exports/" + release
    run.run(["mkdir", "-p", remote], "j9-host-directory-" + release)
    checks = []
    for name in ("host-receipt.json", "host-distribution.json", "host-export.json", "host-distribution.tar.gz"):
        run.copy(folder / name, remote + "/" + name, "j9-copy-host-" + release + "-" + name)
        checks.append((file_identity(folder / name)["sha256"], remote + "/" + name))
    run.checksum("j9-host-" + release, checks)
    stdout, _ = run.run([system_python, "-B", "-c", h2.RESTORE_HOST, release, remote, REMOTE_ROOT + "/scripts/renpy",
                         file_identity(Path(native.__file__))["sha256"], file_identity(Path(inventory.__file__))["sha256"]], "j9-restore-host-" + release)
    value = json.loads(stdout)
    require(value["full_distribution_reverified"] is True and value["sha256"] == selected["producer"]["interpreter_sha256"]
            and value["original_receipt_sha256"] == selected["producer"]["receipt"]["sha256"], "恢复后的H1解释器/完整收据不符")
    return value


def preserve_private(run, system_python, cells):
    """关闭容器前回收原worker/Task/config诊断；SDK/cross/tmp整体不回传。"""
    path = run.output / "generated/j9-preserve-private.py"
    with path.open("x", encoding="utf-8") as stream:stream.write(PRESERVE_PRIVATE)
    run.copy(path, "/reko/j9-preserve-private.py", "j9-copy-private-preserver")
    run.run([system_python, "-B", "/reko/j9-preserve-private.py", *[r + ":" + a for r,a in cells]], "j9-preserve-private-diagnostics")
    run.host([run.docker, "cp", run.name + ":/reko/j9-preserved-private", str(run.output / "worker-diagnostics")], "j9-copy-private-diagnostics")


def verify_returned_products(metadata, directory, workspace, worker_sha, output):
    """新宿主进程读取全成员和每个MachO对象；不执行任何回传Linux/iOS二进制。"""
    result = subprocess.run([sys.executable, "-I", "-B", "-c", VERIFY_C_EXPORT, str(metadata), str(directory), str(workspace), worker_sha],
                            capture_output=True, timeout=300)
    (output / "product-verification.stdout").write_bytes(result.stdout)
    (output / "product-verification.stderr").write_bytes(result.stderr)
    require(result.returncode == 0, "回传C前缀完整字节/MachO/归档身份未通过")
    value = json.loads(result.stdout)
    require(value["all_exported_member_bytes_and_MachO_objects_verified"] is True
            and value["returned_binary_executed_on_host"] is False, "C产物验证覆盖异常")
    return value


def execute_cells(run, h2, h0, native, inventory, payload, h0_plan, metadata, metadata_rows, workspaces, selected, plan, args, report):
    """同lifetime先H0真venv，再恢复H1/SDK，逐独立arch调用原C任务并保留失败证据。"""
    system_python = "/usr/bin/python3.10" if args.ubuntu == "22.04" else "/usr/bin/python3.12"
    report["active_stage"] = "host_frontend"
    group = next(g for g in h0_plan["groups"] if g["ubuntu"] == args.ubuntu)
    python_manifest, _ = h0.verify_original_contracts(payload, h0_plan["files"])
    frontend = h0.replay_host_group(run, payload, group, h0_plan, python_manifest, report)
    frontend_sha = report["original_replay_report_sha256"]
    # 原C0仅复制/解包SDK，不建立其父目录；H0容器须显式补齐原C1私有与SDK输入根。
    run.run(["mkdir", "-p", REMOTE_ROOT, REMOTE_WORKSPACES, REMOTE_OUTPUT, "/reko/j9-private-products", "/reko/private", "/reko/sdk"], "j9-directories")
    run.copy(str(metadata) + "/.", REMOTE_ROOT, "j9-copy-complete-runtime")
    run.checksum("j9-complete-runtime", [(r["sha256"], REMOTE_ROOT + "/" + r["path"]) for r in metadata_rows])
    report["active_stage"] = "host_restore"
    restored = {}
    for release, host in selected.items():
        restored[release] = restore_original_host(run, h2, native, inventory, host, system_python)
    report["restored_host_releases"] = sorted(restored)
    c0 = sys.modules["reko_h0_c0"]
    require(file_identity(Path(c0.__file__))["sha256"] == h0.PINS["c1-runtime/preflight_environment.py"], "C0实际工具不是原冻结输入")
    report["active_stage"] = "sdk_toolchain"
    sdk_inputs = {role: c0.check_archive(getattr(args, name), role) for role,name in
                  (("device_sdk", "device_sdk"), ("simulator_sdk", "simulator_sdk"), ("clang_runtime", "clang_runtime"))}
    report["input_bytes_verified"] = True
    c0.prepare_toolchain(run, sdk_inputs, 15 if args.ubuntu == "22.04" else 18, report)
    report["SDK14_and_clang_runtime_bytes_and_resource_overlay_verified"] = True
    report["active_stage"] = "c_prerequisites"
    cells = [(release, arch) for release in args.releases for arch in args.arches]
    try:
        for release, arch in cells:
            row = next(r for r in report["cells"] if r["release"] == release and r["arch"] == arch)
            if release not in restored:
                row.update(status="not_run", reason_code="missing_complete_host_export");continue
            local_workspace = workspaces / release / arch
            remote_workspace = REMOTE_WORKSPACES + "/" + release + "/" + arch
            remote_output = REMOTE_OUTPUT + "/" + release + "/" + arch
            try:
                run.run(["mkdir", "-p", remote_workspace], "j9-workspace-directory-" + release + "-" + arch)
                run.copy(str(local_workspace) + "/.", remote_workspace, "j9-copy-full-recipe-" + release + "-" + arch)
                scope = next(s for s in frontend["scopes"] if s["id"] == plan["frontend_scopes"][release])
                require(scope["status"] == "offline_replayed", "当前H0前端未真实通过")
                frontend_python = scope["environment"]["prefix"] + "/bin/python"
                sdk = "/reko/private/" + ("device_sdk" if arch == "arm64" else "simulator_sdk") + ".tar.gz"
                command = [frontend_python, "-s", "-B", *worker_argv(release, arch, REMOTE_ROOT, remote_workspace, remote_output,
                           sdk, "/reko/private/clang_runtime.tar.gz", restored[release]["prefix"], frontend_sha,
                           plan["host_producers"][release], "/reko/j9-ccache" if args.ccache else None)]
                run.commands.run([run.docker, "exec", run.name, "env", "-i", "PATH=" + str(Path(frontend_python).parent) + ":/usr/sbin:/usr/bin:/sbin:/bin",
                                  "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC", "DEBIAN_FRONTEND=noninteractive", "PYTHONHASHSEED=0",
                                  "PYTHONDONTWRITEBYTECODE=1", *command], "j9-original-C-tasks-" + release + "-" + arch, timeout=15000)
                run.run([system_python, "-B", "-c", EXPORT_C_PREFIX, REMOTE_ROOT, release, arch, plan["worker"]["sha256"]], "j9-export-C-prefix-" + release + "-" + arch)
                local = run.output / "private-products" / release;local.mkdir(parents=True, exist_ok=True)
                run.host([run.docker, "cp", run.name + ":/reko/j9-private-products/" + release + "/" + arch, str(local / arch)], "j9-copy-private-C-products-" + release + "-" + arch)
                verification = verify_returned_products(metadata, local / arch, local_workspace, plan["worker"]["sha256"], local / arch)
                row.update(status="C_prerequisites_verified", product_verification=verification,
                           export=file_identity(local / arch / "export.json"), producer_plan_sha256=selected[release]["producer"]["execution_plan_sha256"])
            except Exception as error:
                row.update(status="failed", failure=public_failure(error, "c_prerequisites"))
                failure = run.output / ("failure-" + release + "-" + arch + ".json")
                write_json(failure, {"type": type(error).__name__, "private_message": str(error)})
    finally:
        preserve_private(run, system_python, cells)


def load_plan(path=DEFAULT_PLAN):
    """独立SHA锚定两producer、七增量和21原worker依赖，不接受未知profile或stage。"""
    raw = regular_bytes(path, 1024 * 1024)
    require(hashlib.sha256(raw).hexdigest() == PLAN_SHA256, "J9D固定计划字节改变")
    plan = json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=reject_nonfinite)
    require(set(plan) == {"schema_version", "task", "scope", "groups", "architectures", "helpers", "producer_profiles",
                          "host_producers", "frontend_scopes", "worker", "metadata_addon", "metadata_source_commit", "auditor_functions", "limitations"}
            and type(plan["schema_version"]) is int and plan["schema_version"] == 1 and plan["task"] == "R00-02J9D"
            and plan["scope"] == "same_C1_H0_H1_original_iOS_C_prerequisites_only_no_target_python_or_pip"
            and plan["groups"] == GROUPS and plan["architectures"] == list(ARCHES)
            and re.fullmatch("[0-9a-f]{40}", plan["metadata_source_commit"]), "J9D固定阶段/范围错误")
    validate_addon_catalog(plan["metadata_addon"])
    expected = {"run_locked_target_python_tasks.py", "target-python-prefix-plan.json", "validate_lock.py", "build_common.py",
                "materialize_source_inputs.py", "remote-sources.lock.json", "runtime-lock.json"}
    require(len(plan["metadata_addon"]) == 7 and {Path(r["path"]).name for r in plan["metadata_addon"]} == expected
            and set(plan["host_producers"]) == set(sum(GROUPS.values(), []))
            and set(plan["producer_profiles"]) == set(GROUPS), "J9D完整增量/producer集合错误")
    return plan


def load_helpers(plan):
    """复用已部署H2/H1/H0/C1原件，函数投影只服务两个已明确批准producer。"""
    selected = plan["helpers"]["h2"]
    h2 = load_verified(selected["aliases"], selected["sha256"], "reko_j9_h2")
    transport, h0, h0_plan, h1, native, inventory = h2.load_helpers(h2.load_plan())
    require(function_identity(Path(h1.__file__), "verify_export") == plan["auditor_functions"]["verify_export"], "H1导出审计函数改变")
    for name, expected in plan["auditor_functions"]["native_functions_equal_between_exact_6a_and_5abab"].items():
        require(function_identity(Path(native.__file__), name) == expected, "native审计函数投影改变")
    return h2, transport, h0, h0_plan, h1, native, inventory


def prepare_private_inputs(h0, h1, transport, h0_plan, plan, args, private, password, diagnostics):
    """取得固定H0/CAS，保留原件并建立全43件元数据根和完整原J1工作区。"""
    encrypted, plaintext, payload = private / "h0.enc", private / "h0.tar.gz", private / "h0"
    transport.download(transport.TRANSPORT, encrypted)
    transport.decrypt(encrypted, plaintext, transport.TRANSPORT, password)
    transport.extract_payload(plaintext, payload, h0_plan["files"]);encrypted.unlink();plaintext.unlink()
    h0.verify_files(payload, h0_plan["files"]);h0.verify_original_contracts(payload, h0_plan["files"])
    recipe_archive = args.recipe_addon
    if recipe_archive is None:
        recipe_archive = private / "recipes.tar.gz";h1.download_addon(transport, recipe_archive)
    else:
        require(file_identity(recipe_archive) == {k:h1.ADDON[k] for k in ("bytes", "sha256")}, "原CAS addon字节不符")
    recipe_manifest = h1.read_manifest(transport, h0, recipe_archive, private / "recipe-manifest.json")
    with tarfile.open(recipe_archive, "r:gz") as source:
        old_plan = source.extractfile("runtime/host-python-bootstrap-plan.json").read(1024 * 1024)
    routes, objects, catalog = h1.derive_addon(transport, h0, payload, recipe_manifest, h0_plan, old_plan)
    recipe_addon = private / "recipe-addon";transport.extract_payload(recipe_archive, recipe_addon, catalog)
    runtime_addon = private / "runtime-addon";extract_runtime_addon(args.h2, args.runtime_addon, runtime_addon, plan["metadata_addon"])
    metadata = private / "metadata/root"
    rows = prepare_runtime(h0, h1, payload, recipe_addon, recipe_manifest, h0_plan, runtime_addon, plan["metadata_addon"], metadata)
    worker_plan = read_json(metadata / "scripts/renpy/target-python-prefix-plan.json")
    require(worker_plan["host_producers"] == plan["host_producers"]
            and file_identity(metadata / "scripts/renpy/run_locked_target_python_tasks.py") == {k:plan["worker"][k] for k in ("bytes", "sha256")}, "worker/source producer合同不符")
    fresh = diagnostics / "fresh-runtime";fresh.mkdir()
    proof = fresh_runtime_check(metadata, fresh, plan["worker"]["sha256"])
    j8 = h0.load_module(recipe_addon / "runtime/run_locked_source_tasks.py", h1.RUNTIME["run_locked_source_tasks.py"], "reko_j9_J1_stager")
    workspaces = private / "workspaces";workspaces.mkdir();cache = {}
    def get_bytes(item):
        """复用已校验CAS原buffer；每次J1写入仍由原byte/blob/mode门禁复核。"""
        sha = item["sha256"]
        if sha not in cache:cache[sha] = h1.raw_object(h0, payload, recipe_addon, sha, objects[sha])
        return cache[sha]
    for release in args.releases:
        (workspaces / release).mkdir()
        for arch in args.arches:h1.rebuild_workspace(j8, routes[release], workspaces / release / arch, get_bytes)
    return payload, metadata, rows, workspaces, proof


def parser():
    """只公开本阶段固定输入，不提供任意执行后钩子或未实现的target install/pip阶段。"""
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--ubuntu", choices=sorted(GROUPS), required=True)
    result.add_argument("--release", choices=sum(GROUPS.values(), []), action="append")
    result.add_argument("--arch", choices=ARCHES, action="append")
    for name in ("bundle", "h1-artifact", "runtime-addon", "device-sdk", "simulator-sdk", "clang-runtime", "output"):
        result.add_argument("--" + name, type=Path, required=True)
    for name in ("h1-artifact-sha256", "runtime-addon-sha256"):
        result.add_argument("--" + name, required=True)
    for name in ("h1-artifact-bytes", "runtime-addon-bytes"):
        result.add_argument("--" + name, type=int, required=True)
    result.add_argument("--recipe-addon", type=Path)
    result.add_argument("--ccache", action="store_true", help="只用本容器固定/reko/j9-ccache，无host挂载")
    return result


def main(argv=None):
    """真实缺环境记未运行，原C失败保留私密诊断；SDKkey不读取，容器/本轮解密输入最终清理。"""
    args = parser().parse_args(argv);password = os.environ.pop("REKO_H0_INPUTS_PASSWORD", None)
    args.releases = args.release or list(GROUPS[args.ubuntu]);args.arches = args.arch or list(ARCHES)
    report = {"task":"R00-02J9D", "scope":"original_iOS_static_C_prerequisites_only", "result":"failed", "ubuntu":args.ubuntu,
              "C_prerequisites_verified":False, "target_python_install_verified":False, "target_pip_bound":False,
              "production_shared_dylib_verified":False, "ios_runtime_verified":False, "source_ci_verified":False,
              "full_engine_session_verified":False, "full_input_closure":False, "SDK_secret_read":False,
              "secret_sent_to_container":False, "container_closed":False, "private_inputs_removed":False,
              "input_bytes_verified":False, "errors":[], "cells":[{"release":r,"arch":a,"status":"not_run"} for r in args.releases for a in args.arches]}
    created = False;private = None;stage = "inputs";diagnostics = None
    try:
        args.output = guarded(args.output)
        require(not args.output.exists() and args.output.parent.is_dir(), "输出必须全新且父目录存在")
        for name in ("bundle", "h1_artifact", "runtime_addon", "device_sdk", "simulator_sdk", "clang_runtime"):
            value = guarded(getattr(args, name));setattr(args, name, value)
            require(not value.is_relative_to(args.output) and not args.output.is_relative_to(value), "输入输出路径交叉")
        if args.recipe_addon is not None:
            args.recipe_addon = guarded(args.recipe_addon)
            require(not args.recipe_addon.is_relative_to(args.output) and not args.output.is_relative_to(args.recipe_addon), "原CAS与输出路径交叉")
        args.output.mkdir();created = True;diagnostics = args.output / "private-diagnostics";diagnostics.mkdir(mode=0o700)
        plan = load_plan()
        require(set(args.releases) <= set(GROUPS[args.ubuntu]) and len(set(args.releases)) == len(args.releases)
                and len(set(args.arches)) == len(args.arches), "所选route/group/arch重复或不符")
        if sys.platform != "linux" or platform.machine() != "x86_64" or shutil.which("docker") is None:
            raise InputUnavailable("需要真实Linux x86_64和Docker")
        for name in ("bundle", "h1_artifact", "runtime_addon", "device_sdk", "simulator_sdk", "clang_runtime"):
            if not getattr(args, name).exists():raise InputUnavailable("必要原件未到齐")
        if not password:raise InputUnavailable("缺少固定H0运输密码")
        profile = plan["producer_profiles"][args.ubuntu]
        require(args.h1_artifact_sha256 == profile["artifact"]["sha256"] and args.h1_artifact_bytes == profile["artifact"]["bytes"], "外部H1 API身份与固定producer不符")
        verify_external_file(args.h1_artifact, args.h1_artifact_sha256, args.h1_artifact_bytes)
        verify_external_file(args.runtime_addon, args.runtime_addon_sha256, args.runtime_addon_bytes)
        report["H1_external_identity"] = {"bytes":args.h1_artifact_bytes,"sha256":args.h1_artifact_sha256}
        report["runtime_addon_external_identity"] = {"bytes":args.runtime_addon_bytes,"sha256":args.runtime_addon_sha256}
        report["plan_sha256"] = PLAN_SHA256
        h2, transport, h0, h0_plan, h1, native, inventory = load_helpers(plan);args.h2 = h2
        temporary_root = guarded(os.environ.get("RUNNER_TEMP", ""))
        require(os.environ.get("RUNNER_TEMP") and temporary_root.is_dir() and not temporary_root.is_relative_to(args.output)
                and not temporary_root.is_relative_to(args.bundle), "缺少独立临时输入根")
        checkout = os.environ.get("GITHUB_WORKSPACE")
        require(not checkout or not temporary_root.is_relative_to(guarded(checkout)), "解密输入不能放checkout")
        with tempfile.TemporaryDirectory(prefix="reko-j9-inputs-", dir=temporary_root) as directory:
            private = Path(directory);private.chmod(0o700);artifact = private / "H1-artifact";h2.extract_h1_zip(args.h1_artifact, artifact)
            selected = {}
            for release in args.releases:
                selected[release] = selected_host_export(h2,h0,h1,artifact,release,profile,plan["host_producers"][release],plan["auditor_functions"])
            stage = "transport"
            payload, metadata, rows, workspaces, proof = prepare_private_inputs(h0,h1,transport,h0_plan,plan,args,private,password,diagnostics)
            password = None
            report.update(fixed_H0_J1_and_J9_metadata_inputs_verified=True,complete_metadata_root_files=len(rows),fresh_runtime_contract=proof,
                          original_H0_payload_unchanged=True,original_recipe_addon_unchanged=True)
            container_output = diagnostics / "container";container_output.mkdir()
            namespace = argparse.Namespace(payload=payload,bundle=args.bundle,ubuntu=args.ubuntu,output=container_output)
            stage = "environment"
            with h0.open_environment(namespace,h0_plan,report) as run:
                execute_cells(run,h2,h0,native,inventory,payload,h0_plan,metadata,rows,workspaces,selected,plan,args,report)
            require(report["container_closed"], "本轮容器未关闭")
        require(not private.exists(), "本轮解密输入未清理")
        if all(row["status"] == "C_prerequisites_verified" for row in report["cells"]):
            report.update(result="selected_original_C_prerequisites_verified",C_prerequisites_verified=True)
        else:report["result"] = "failed_C_prerequisites" if any(row["status"] == "failed" for row in report["cells"]) else "not_run"
    except Exception as error:
        report["result"] = "not_run" if isinstance(error,InputUnavailable) else "failed"
        report["errors"].append(public_failure(error,report.get("active_stage",stage)))
        if diagnostics is not None:write_json(diagnostics / "private-failure.json", {"kind":type(error).__name__,"private_message":str(error)})
    finally:
        password = None;report.pop("active_stage",None)
        report["private_inputs_removed"] = private is not None and not private.exists()
        if created:
            report["private_files"] = [{"path":p.relative_to(args.output).as_posix(),**file_identity(p)}
                                       for p in sorted(diagnostics.rglob("*")) if p.is_file()]
            report["public_artifact_whitelist"] = ["public-summary.json"]
            report["private_diagnostics_transport"] = "由根CI使用既定公证书加密后取回；不得直接上传private-diagnostics或完整安装树。"
            write_json(args.output / "public-summary.json", report)
    log("结果=" + report["result"])
    return 0 if report["C_prerequisites_verified"] else 3 if report["result"] == "not_run" else 1


if __name__ == "__main__":
    raise SystemExit(main())
