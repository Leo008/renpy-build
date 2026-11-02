#!/usr/bin/env python3
"""恢复已验H1完整原前缀，以五个精确Linux解释器重放原九scope计划；不验收iOS会话。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import types
import urllib.request
import zipfile


HERE = Path(__file__).absolute().parent
DEFAULT_PLAN = HERE / "linux-target-python-replay-ci-plan.json"
PLAN_SHA256 = "a5b75b33514cf5778f9eda2b1d4f55edd6b6736d885e5e53c961c6b63810a9fb"
ALL_SCOPES = {"8.5.3-host-ci-success", "8.5.3-target-ci-success", "8.5.3-target-recipe", "8.4.1-host-recipe",
              "8.4.1-target-recipe", "8.3.7-host-recipe", "8.3.7-target-recipe", "7.8.7-host-recipe", "7.8.7-target-recipe"}
TARGETS = {"24.04": ["8.5.3-target-ci-success", "8.5.3-target-recipe", "8.4.1-target-recipe"],
           "22.04": ["8.3.7-target-recipe", "7.8.7-target-recipe"]}
VERSIONS = {"8.5.3": "3.12.8", "8.4.1": "3.12.8", "8.3.7": "3.9.10", "7.8.7": "2.7.18"}
RUNTIME = {"lock_python_inputs.py": "690ba4f9401987f5a2c459605195904a2fad03e239a48181e1e44e0ad50b6779",
           "build_python_wheels.py": "829712b376ce71ccd39f36299ba2f5e09eb92ba7c21a21f9134ec11e2f2391a6",
           "replay_python_inputs.py": "d955cd1fbf1dfaf88e19cfcad5e66f20d58b02ab473b205bf107605ec13ae84c"}
RECEIPTS = {"py3": "1807c50c946a46b17fc0ae83e362caaffdb94191086f8f39a63d64d9f74534cd",
            "py2": "4545fe543553e961e4dae4343d04baa32619a16c5cff59ec751e4cb24c277a0c"}
SIX_LOCK = "aca801ab1c1d5f83793ada79957655ec3de1c90dd6a62a3309acdc896df16987"
EXTRA_MANIFEST = {"bytes": 39023, "sha256": "06bb4fe782d9ac734c43df6d88077dd07570dbfdc6b418bed38fba4f88729dfc"}
REMOTE = "/reko/h2-inputs"
REPLAY_OUTPUT = "/reko/h2-replay"

# 子进程只执行已核原字节的三个工具，避免宿主旧H0同名模块或pyc混入当前J2C身份。
VERIFY_CURRENT = r'''import hashlib,json,pathlib,sys,types
root=pathlib.Path(sys.argv[1]);pins=json.loads(sys.argv[2]);sys.dont_write_bytecode=True
sys.pycache_prefix=str(root/'unused-verification-pycache')
for name in ('lock_python_inputs','build_python_wheels','replay_python_inputs'):
 p=root/'root/scripts/renpy'/(name+'.py');raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()==pins[name+'.py']
 m=types.ModuleType(name);m.__file__=str(p);m.__package__='';sys.modules[name]=m;exec(compile(raw,str(p),'exec'),m.__dict__)
r=sys.modules['replay_python_inputs'];i=sys.modules['lock_python_inputs'];b=sys.modules['build_python_wheels']
p,bp,m,f=r.load_plan(r.DEFAULT_PLAN);e=i.verify_evidence(m['scopes']);assert len(e)==18 and len(p['scopes'])==9
parser=i.load_parser(root/'cache',m)
products,receipts=r.read_build_receipts([root/'receipts'/k/'report.json' for k in ('py3','py2')],json.loads(sys.argv[3]),bp,m,root/'cache',root/'cache',parser)
assert len(products)==6
for s in m['scopes']:
 wheels,missing,proof=r.resolve_scope(s,m,root/'cache',products,parser)
 assert not missing and len(wheels)==len(s['packages']) and proof['dependency_metadata_verified'] is True
print(json.dumps({'original_scope_count':9,'evidence_count':18,'built_products':6,'all_scope_input_metadata_verified':True,'actual_target_replay_executed':False}))
'''

# 宿主回归与恢复子进程共用同一原文；raw ldd含ASLR地址，仅稳定身份参与比较。
DEPENDENCY_PROJECTION = r'''def stable_dependency_identity(records):
 """逐ELF保留静态标记与完整库身份，稳定排序保留重复数，不改原stdout或原记录。"""
 if not isinstance(records,list):raise ValueError('动态依赖记录不是列表')
 result=[]
 for record in records:
  if set(record)!={'path','dependencies'}:raise ValueError('动态依赖外层字段错误')
  path=record['path'];dependency=record['dependencies']
  if not isinstance(path,str) or not path or path.startswith('/') or any(p in ('','.','..') for p in path.split('/')):raise ValueError('动态ELF相对路径错误')
  if type(dependency.get('static')) is not bool or not isinstance(dependency.get('libraries'),list):raise ValueError('动态依赖静态标记或库字段错误')
  if set(dependency)!=({'static','libraries'} if dependency['static'] else {'static','stdout','libraries'}):raise ValueError('动态依赖字段集合错误')
  if dependency['static'] and dependency['libraries']:raise ValueError('静态ELF不能声明动态库')
  if not dependency['static'] and (not dependency['libraries'] or not isinstance(dependency['stdout'],str) or not dependency['stdout']):raise ValueError('动态ELF缺库或缺原stdout')
  libraries=[]
  for library in dependency['libraries']:
   if set(library)!={'path','sha256','elf'}:raise ValueError('动态库身份字段错误')
   name=library['path'];elf=library['elf']
   if not isinstance(name,str) or not name.startswith('/') or '..' in name.split('/') or not re.fullmatch('[0-9a-f]{64}',library['sha256']):raise ValueError('动态库完整路径或SHA错误')
   if set(elf)!={'class','endian','machine','type'} or elf['class']!=64 or elf['endian']!='little' or elf['machine']!=62 or elf['type'] not in (2,3):raise ValueError('动态库ELF架构错误')
   libraries.append({'path':name,'sha256':library['sha256'],'elf':dict(elf)})
  libraries.sort(key=lambda x:json.dumps(x,sort_keys=True,separators=(',',':')))
  result.append({'path':path,'static':dependency['static'],'libraries':libraries})
 result.sort(key=lambda x:json.dumps(x,sort_keys=True,separators=(',',':')))
 return result

def verify_dependency_identity(original,current):
 """仅ASLR/raw输出变化可复用相同身份，库路径/字节/架构/静态性/重复数量变化拒绝。"""
 expected=stable_dependency_identity(original);observed=stable_dependency_identity(current)
 if expected!=observed:raise ValueError('恢复后的完整动态依赖身份与H1不符')
 return observed
'''
exec(compile(DEPENDENCY_PROJECTION, "<fixed-H2-dependency-identity>", "exec"), globals())

# 所有成员先核验再创建；最后恢复已验链接，完整复核分发后才执行原生解释器。
RESTORE_HOST = DEPENDENCY_PROJECTION + r'''import hashlib,json,os,pathlib,re,stat,subprocess,sys,tarfile,types
release,folder,runtime_dir,host_sha,inventory_sha=sys.argv[1:];folder=pathlib.Path(folder);runtime_dir=pathlib.Path(runtime_dir)
def load(name,filename,expected):
 """直接编译已核H1校验器原字节，不读取其他模块或旧pyc。"""
 p=runtime_dir/filename;raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()==expected
 m=types.ModuleType(name);m.__file__=str(p);sys.modules[name]=m;exec(compile(raw,str(p),'exec'),m.__dict__);return m
inventory_module=load('inventory_source_inputs','inventory_source_inputs.py',inventory_sha)
h=load('reko_h2_native_host','run_locked_host_python_tasks.py',host_sha)
receipt=json.loads((folder/'host-receipt.json').read_bytes());entries=json.loads((folder/'host-distribution.json').read_bytes())
export=json.loads((folder/'host-export.json').read_bytes());archive=folder/'host-distribution.tar.gz'
assert hashlib.sha256(archive.read_bytes()).hexdigest()==export['archive']['sha256'] and archive.stat().st_size==export['archive']['bytes']
assert hashlib.sha256((folder/'host-distribution.json').read_bytes()).hexdigest()==receipt['distribution']['sha256']==export['distribution_sha256']
assert hashlib.sha256((folder/'host-receipt.json').read_bytes()).hexdigest()==export['receipt_sha256']
prefix=pathlib.Path('/reko/h1-workspaces')/release/'tmp/host';assert receipt['prefix']==str(prefix) and not prefix.exists()
expected={x['path']:x for x in entries};assert expected and len(expected)==len(entries)
links={x['path']:x['target'] for x in entries if x['type']=='symlink'};inventory_module.validate_links(links)
seen=set()
with tarfile.open(archive,'r:gz') as t:
 for member in t:
  assert member.name in expected and member.name not in seen;seen.add(member.name);item=expected[member.name]
  assert member.name and not member.name.startswith('/') and all(p not in ('','.','..') for p in member.name.split('/'))
  assert format(member.mode,'04o')==item['permissions']
  if item['type']=='directory':assert member.isdir()
  elif item['type']=='symlink':assert member.issym() and member.linkname==item['target'] and hashlib.sha256(member.linkname.encode()).hexdigest()==item['sha256']
  else:
   assert item['type']=='file' and member.isfile() and member.size==item['bytes']
   with t.extractfile(member) as stream:
    digest=hashlib.sha256();size=0
    while True:
     block=stream.read(262144)
     if not block:break
     size+=len(block);digest.update(block)
   assert size==item['bytes'] and digest.hexdigest()==item['sha256']
assert seen==set(expected)
h.no_links(prefix);prefix.mkdir(parents=True)
with tarfile.open(archive,'r:gz') as t:
 for member in t:
  item=expected[member.name];target=prefix/member.name
  if item['type']=='symlink':continue
  h.no_links(target);target.parent.mkdir(parents=True,exist_ok=True)
  if item['type']=='directory':target.mkdir(exist_ok=True)
  else:
   with t.extractfile(member) as stream,target.open('xb') as output:
    while True:
     block=stream.read(262144)
     if not block:break
     output.write(block)
   target.chmod(int(item['permissions'],8))
for item in sorted(entries,key=lambda x:x['path'].count('/'),reverse=True):
 target=prefix/item['path']
 if item['type']=='directory':target.chmod(int(item['permissions'],8))
for item in entries:
 if item['type']=='symlink':
  target=prefix/item['path'];h.no_links(target.parent);target.symlink_to(item['target'])
assert h.host_inventory(prefix)==entries
binary=pathlib.Path(receipt['interpreter']);real=binary.resolve(strict=True);assert real.is_relative_to(prefix)
assert hashlib.sha256(real.read_bytes()).hexdigest()==receipt['interpreter_sha256']
row={'release':release,'version':{'8.5.3':'3.12.8','8.4.1':'3.12.8','8.3.7':'3.9.10','7.8.7':'2.7.18'}[release],
 'python':'2' if release=='7.8.7' else '3','legacy_ssl_candidate':True if release=='7.8.7' else None}
result=subprocess.run([str(binary),'-E','-s','-B','-c',h.PRODUCT_PROBE],capture_output=True,check=True,timeout=120)
probe=json.loads(result.stdout);h.verify_product(probe,row,prefix)
dependencies=[{'path':item['path'],'dependencies':h.dynamic_dependencies(prefix/item['path'],prefix)} for item in entries if item.get('elf',{}).get('type') in (2,3)]
verify_dependency_identity(receipt['dynamic_dependencies'],dependencies)
original_ldd=[{'path':item['path'],'static':item['dependencies']['static'],
 'stdout_sha256':hashlib.sha256(item['dependencies']['stdout'].encode()).hexdigest() if 'stdout' in item['dependencies'] else None} for item in receipt['dynamic_dependencies']]
print(json.dumps({'release':release,'prefix':str(prefix),'interpreter':str(binary),'realpath':str(real),
 'sha256':receipt['interpreter_sha256'],'runtime':probe,'distribution_members':len(entries),'full_distribution_reverified':True,
 'original_receipt_sha256':export['receipt_sha256'],'original_ldd_stdout_hashes':original_ldd,
 'current_dynamic_dependencies':dependencies,'stable_dynamic_dependency_identity_verified':True}))
'''

PRESERVE = r'''import pathlib,re,stat,sys
source=pathlib.Path('/reko/h2-replay');target=pathlib.Path('/reko/h2-results');target.mkdir()
def copy(p):
 """只复制原报告和固定命令通道，排除环境与私有输入。"""
 if p.is_symlink() or not stat.S_ISREG(p.lstat().st_mode):raise ValueError('unsafe replay result')
 q=target/p.relative_to(source);q.parent.mkdir(parents=True,exist_ok=True)
 with q.open('xb') as output:output.write(p.read_bytes())
if (source/'report.json').is_file():copy(source/'report.json')
for name in sys.argv[1:]:
 for folder in (source/name,source/name/'identity-probe'):
  if not folder.is_dir():continue
  if folder.is_symlink():raise ValueError('unsafe result folder')
  for p in folder.iterdir():
   if p.name=='commands.json' or re.fullmatch(r'command-[0-9]+-(stdout|stderr)\.log',p.name):copy(p)
'''


def require(value, message):
    """真实条件不足立即拒绝，不用成功默认值掩盖未执行。"""
    if not value:
        raise ValueError(message)


def log(message):
    """输出本阶段中文日志，不打印密钥或解密材料。"""
    print("[RenPyLinuxTargetReplay] " + message, flush=True)


def guarded(path):
    """拒绝链接祖先和父目录跳转，限定输入输出为显式绝对路径。"""
    path = Path(path).absolute()
    require(".." not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), "拒绝链接或上跳路径")
    return path


def file_identity(path, maximum=2 * 1024**3):
    """流式核对实际普通文件，限制体积且不沿叶链接读取。"""
    path = guarded(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= maximum, "普通文件缺失或超限")
        sha = hashlib.sha256();size = 0
        while block := stream.read(256 * 1024):size += len(block);sha.update(block)
    require(size == info.st_size, "读取期间文件长度改变")
    return {"bytes": size, "sha256": sha.hexdigest()}


def write_json(path, value):
    """只写独占新报告，不覆盖原输入和历史失败。"""
    with guarded(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2);stream.write("\n")


def load_plan(path=DEFAULT_PLAN):
    """以工具内独立SHA锚定运输身份、原版本合同和最小固定依赖。"""
    raw = guarded(path).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == PLAN_SHA256, "H2计划原字节改变")
    plan = json.loads(raw)
    require(set(plan) == {"schema_version", "task", "scope", "helpers", "H1_ci_plan_sha256", "H1_host_plan_sha256", "H1_addon_host_plan_sha256",
                          "extra", "extra_manifest", "groups", "versions", "runtime", "six_wheel_lock_sha256", "limitations"}
            and type(plan["schema_version"]) is int and plan["schema_version"] == 1
            and plan["task"] == "R00-02J2C-H2-Linux" and plan["groups"] == TARGETS and plan["versions"] == VERSIONS
            and plan["scope"] == "five_exact_target_version_linux_scopes_only_no_ios_acceptance"
            and plan["runtime"] == RUNTIME and plan["extra_manifest"] == EXTRA_MANIFEST
            and plan["H1_addon_host_plan_sha256"] == "352f7af5dbd7f31d6199f1d6b536a99405cf249c7969cbfd69260a455c6b84e0"
            and plan["six_wheel_lock_sha256"] == SIX_LOCK, "H2固定范围/输入身份错误")
    return plan


def load_verified(aliases, expected, name):
    """直接编译已核工具源码，拒绝已有模块和未锁pyc。"""
    paths = [HERE / n for n in aliases if (HERE / n).exists()]
    require(paths and name not in sys.modules, "固定helper缺失或模块已被外部加载")
    sources = []
    for path in paths:
        with os.fdopen(os.open(guarded(path), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as stream:
            info = os.fstat(stream.fileno());require(stat.S_ISREG(info.st_mode) and info.st_size <= 256 * 1024, "helper不是有界普通源码")
            raw = stream.read(256 * 1024 + 1)
        require(len(raw) == info.st_size and hashlib.sha256(raw).hexdigest() == expected, "helper原字节改变：" + path.name)
        sources.append(raw)
    module = types.ModuleType(name);module.__file__ = str(paths[0]);module.__package__ = "";sys.modules[name] = module
    try:exec(compile(sources[0], str(paths[0]), "exec"), module.__dict__)
    except BaseException:sys.modules.pop(name, None);raise
    return module


def load_helpers(plan):
    """加载现有固定H0运输/C1和H1导出校验器，不执行H1构建入口。"""
    helper = plan["helpers"]
    transport = load_verified(helper["transport"]["aliases"], helper["transport"]["sha256"], "reko_h2_transport")
    h0, h0_plan, _ = transport.load_h0()
    h1 = load_verified(helper["H1_wrapper"]["aliases"], helper["H1_wrapper"]["sha256"], "reko_h2_h1_checker")
    require(file_identity(HERE / "linux-host-python-bootstrap-ci-plan.json")["sha256"] == plan["H1_ci_plan_sha256"], "H1 CI计划身份改变")
    h1.load_plan(transport)
    native = load_verified(helper["H1_execution"]["aliases"], helper["H1_execution"]["sha256"], "reko_h2_native_checker")
    inventory = load_verified(helper["inventory"]["aliases"], helper["inventory"]["sha256"], "inventory_source_inputs")
    return transport, h0, h0_plan, h1, native, inventory


def verify_h1_artifact(path, expected_sha, expected_bytes):
    """必须先有根从真实API取得的独立ZIP SHA/大小，拒绝只信内部收据的循环自证。"""
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha or "") and type(expected_bytes) is int and expected_bytes > 0,
            "必须显式提供H1原ZIP的独立SHA256及真实大小")
    identity = file_identity(path)
    require(identity == {"bytes": expected_bytes, "sha256": expected_sha}, "H1原ZIP外部身份不符")
    return identity


def extract_h1_zip(path, destination):
    """仅手工创建有界普通ZIP成员，不执行其文件，不沿链接解包。"""
    guarded(destination).mkdir();seen = set();folded = set();total = 0
    with zipfile.ZipFile(path) as archive:
        require(len(archive.infolist()) <= 20000, "H1 ZIP成员过多")
        for item in archive.infolist():
            name = item.filename.rstrip("/");parts = name.split("/")
            require(name and not name.startswith("/") and "\\" not in name and ":" not in name
                    and all(x not in ("", ".", "..", ".git") for x in parts)
                    and name not in seen and name.casefold() not in folded, "H1 ZIP路径重复或逃逸")
            seen.add(name);folded.add(name.casefold());kind = stat.S_IFMT(item.external_attr >> 16)
            require(not item.flag_bits & 1 and kind in ((0, stat.S_IFDIR) if item.is_dir() else (0, stat.S_IFREG)), "H1 ZIP含链接/特殊/加密成员")
            total += item.file_size;require(total <= 4 * 1024**3 and item.file_size <= 1024**3, "H1 ZIP展开超限")
            target = guarded(destination / name)
            if item.is_dir():target.mkdir(parents=True, exist_ok=True);continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(item) as source,target.open("xb") as output:
                count = 0
                while block := source.read(256 * 1024):count += len(block);require(count <= item.file_size, "ZIP成员超长");output.write(block)
            require(count == item.file_size, "ZIP成员截断")


def classify_exports(h0, h1, artifact, ubuntu, plan):
    """不以H1 aggregate失败否定独立成功route；缺实物记未运行，坏实物记失败。"""
    header = h0.decode(h0.read(artifact / "linux-host-python-bootstrap-report.json"))
    require(header["task"] == "R00-02J2C-H1-Linux" and header["ubuntu"] == ubuntu and header["sdk_inputs_consumed"] is False,
            "H1原artifact范围不符")
    source_matches = (header.get("execution_h1_tool_sha256") == plan["helpers"]["H1_execution"]["sha256"]
                      and header.get("H1_plan_sha256") == plan["H1_host_plan_sha256"]
                      and header.get("execution_h1_plan_sha256") == plan["H1_host_plan_sha256"]
                      and header.get("addon_h1_plan_sha256") == plan["H1_addon_host_plan_sha256"])
    replay_path = artifact / "container/python-replay/report.json"
    frontend_sha = file_identity(replay_path)["sha256"]
    frontend = h0.decode(h0.read(replay_path))
    require(frontend["task"] == "R00-02J2C1" and frontend["J2C_complete"] is False, "H1原host前端收据错误")
    rows = []
    for release in dict.fromkeys(s.split("-")[0] for s in TARGETS[ubuntu]):
        row = {"release": release, "status": "not_run", "reason": "H1尚未生成完整成功导出"};rows.append(row)
        folder = artifact / "container" / ("host-" + release)
        required = ["report.json", "host-receipt.json", "host-distribution.json", "host-export.json", "host-distribution.tar.gz"]
        if not all((folder / n).is_file() for n in required):continue
        try:
            require(source_matches, "完整H1导出的原执行源/计划不是本轮固定身份")
            verified = h1.verify_export(h0, folder, release, frontend_sha)
            require(verified["prefix"] == "/reko/h1-workspaces/" + release + "/tmp/host", "H1原prefix改变")
            row.update(status="export_verified", folder=str(folder), export=verified);row.pop("reason")
        except Exception as error:row.update(status="failed", reason=type(error).__name__ + ": " + str(error))
    return rows


def download_extra(transport, descriptor, target):
    """只下载本轮固定密文URL，限定重定向/时限/完整SHA，无其他版本回退。"""
    initial = descriptor["url"];transport.validate_url(initial, initial);identity = descriptor["ciphertext"]
    opener = urllib.request.build_opener(transport.ReleaseRedirects(initial));deadline = time.monotonic() + 600
    request = urllib.request.Request(initial, headers={"Accept-Encoding": "identity", "User-Agent": "Reko-H2-Inputs/1"})
    with opener.open(request, timeout=60) as response,guarded(target).open("xb") as stream:
        transport.validate_url(response.url, initial)
        require(response.status == 200 and response.headers.get("Content-Encoding", "identity").lower() == "identity"
                and response.headers.get("Content-Length") in (None, str(identity["bytes"])), "H2密文响应错误")
        size = 0;sha = hashlib.sha256();header = b""
        while block := response.read(256 * 1024):
            require(time.monotonic() <= deadline, "H2密文下载超时")
            size += len(block);require(size <= identity["bytes"], "H2密文超长");sha.update(block);header = (header + block)[:8];stream.write(block)
    require(size == identity["bytes"] and sha.hexdigest() == identity["sha256"] and header == b"Salted__", "H2密文完整身份不符")


def extra_catalog(h0, payload, h0_plan, archive):
    """从原J2A/B1集合和固定新收据派生32输入，不用运输manifest自证遗漏集合。"""
    with tarfile.open(archive, "r:gz") as source:
        entries = [m for m in source if m.name == "manifest.json"]
        require(len(entries) == 1 and entries[0].isfile() and entries[0].size == EXTRA_MANIFEST["bytes"], "H2 manifest缺失/重复")
        raw = source.extractfile(entries[0]).read();require(h0.digest(raw) == EXTRA_MANIFEST["sha256"], "H2 manifest SHA不符")
    manifest = h0.decode(raw);old = {x["sha256"] for x in h0_plan["files"]}
    original = h0.decode(h0.read(payload / "root/scripts/renpy/python-inputs.lock.json"))
    builder = h0.decode(h0.read(payload / "root/scripts/renpy/python-wheel-build-plan.json"))
    expected = {}
    for sha,a in {**original["artifacts"], **builder["tools"]}.items():
        if sha not in old:expected["cache/" + sha + "/" + a["filename"]] = {"bytes": a["size"], "sha256": sha}
    expected.update({"receipts/py2/report.json": {"bytes": 55026, "sha256": RECEIPTS["py2"]},
                     "receipts/py2/future-0.18.3-py2/output/future-0.18.3-py2-none-any.whl": {"bytes": 503539, "sha256": "c63ea97d0d1b4c862119f4df291a67cea98b887663dfd0ab1062de58dd4d576c"},
                     "receipts/py2/pefile-2019.4.18-py2/output/pefile-2019.4.18-py2-none-any.whl": {"bytes": 60822, "sha256": "285bfc3d24e8471a8825ac9bf46d1c3b6d2b29bd2cfe7d7c90545eea09583354"},
                     "runtime/lock_python_inputs.py": {"bytes": 40851, "sha256": RUNTIME["lock_python_inputs.py"]},
                     "runtime/replay_python_inputs.py": {"bytes": 36051, "sha256": RUNTIME["replay_python_inputs.py"]},
                     "runtime/python-wheel-builds.lock.json": {"bytes": 30426, "sha256": SIX_LOCK}})
    actual = {r["path"]: {k: r[k] for k in ("bytes", "sha256")} for r in manifest["files"]}
    require(len(expected) == len(manifest["files"]) == 32 and actual == expected
            and sum(r["bytes"] for r in actual.values()) == 10545201, "H2原输入闭包不完整或工具身份改变")
    return [{"path": k, **v} for k,v in sorted(expected.items())] + [{"path": "manifest.json", **EXTRA_MANIFEST}]


def extract_extra(archive, destination, catalog):
    """本固定小包严格33普通成员，无目录/链接，精确模式uid/gid/mtime及全字节。"""
    guarded(destination).mkdir();expected = {x["path"]: x for x in catalog};seen = set()
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            require(member.name in expected and member.name not in seen and member.type in (tarfile.REGTYPE,tarfile.AREGTYPE)
                    and not member.sparse and not member.pax_headers
                    and member.mode == 0o644 and member.uid == member.gid == member.mtime == 0, "H2归档成员/模式/身份非法")
            seen.add(member.name);row = expected[member.name];require(member.size == row["bytes"], "H2成员大小错误")
            target = guarded(destination / member.name);target.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as stream,target.open("xb") as output:
                size = 0;sha = hashlib.sha256()
                while block := stream.read(256 * 1024):size += len(block);require(size <= row["bytes"], "H2成员超长");sha.update(block);output.write(block)
            require(size == row["bytes"] and sha.hexdigest() == row["sha256"], "H2成员完整SHA错误")
    require(seen == set(expected), "H2归档缺项")


def merge_inputs(h0, payload, extra, h0_plan, extra_rows, destination, helpers):
    """新root完整保留原18证据/3tar，仅显式替换两源码，原H0输入不写入。"""
    guarded(destination).mkdir();sources = {r["path"]: (payload / r["path"],r) for r in h0_plan["files"]}
    for row in extra_rows:
        if row["path"] == "manifest.json":continue
        name = row["path"]
        if name.startswith("runtime/"):name = "root/scripts/renpy/" + Path(name).name
        sources[name] = (extra / row["path"],row)
    for filename,module in helpers.items():
        path = Path(module.__file__);sources["root/scripts/renpy/" + filename] = (path,{**file_identity(path),"path": filename})
    catalog = []
    for name,(source,row) in sorted(sources.items()):
        require(file_identity(source) == {k:row[k] for k in ("bytes","sha256")}, "合并前原输入改变")
        target = guarded(destination / name);target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as output:output.write(source.read_bytes())
        catalog.append({"path": name, "bytes": row["bytes"], "sha256": row["sha256"]})
    return catalog


def verify_current_inputs(merged, output):
    """用独立真实子进程重验当前工具/18证据/九依赖/六产物，尚不执行target包。"""
    command = [sys.executable,"-I","-B","-c",VERIFY_CURRENT,str(merged),json.dumps(RUNTIME),json.dumps([RECEIPTS[k] for k in ("py3","py2")])]
    result = subprocess.run(command,capture_output=True,timeout=300)
    (output / "input-verification.stdout").write_bytes(result.stdout);(output / "input-verification.stderr").write_bytes(result.stderr)
    require(result.returncode == 0, "当前H2输入/完整证据复查失败，见原日志")
    value = json.loads(result.stdout);require(value == {"original_scope_count":9,"evidence_count":18,"built_products":6,"all_scope_input_metadata_verified":True,"actual_target_replay_executed":False}, "当前输入复查覆盖错误")
    return value


def preserve_results(run, scopes, python):
    """成功或失败均只保全原报告/通道，不回传venv、私有输入或密钥。"""
    path = run.output / "generated/h2-preserve-results.py";path.parent.mkdir(exist_ok=True)
    with path.open("x") as stream:stream.write(PRESERVE)
    run.copy(path,"/reko/h2-preserve-results.py","h2-copy-result-preserver")
    run.run([python,"-B","/reko/h2-preserve-results.py",*scopes],"h2-preserve-selected-results")
    run.host([run.docker,"cp",run.name+":/reko/h2-results",str(run.output/"target-replay")],"h2-copy-public-results")


def verify_result(h0, result, ubuntu, restored, exit_code, directory, manifest, replay_plan, merged):
    """独立校验五target子范围及原九行/未选状态，不将原exit2提升完整J2C。"""
    require(result["task"] == "R00-02J2C1" and result["command"] == "replay" and result["J2C_complete"] is False
            and result["ios_runtime_verified"] is False and len(result["scopes"]) == 9
            and {s["id"] for s in result["scopes"]} == ALL_SCOPES
            and result["plan_sha256"] == "89763ed8ba512a39dd2c63c4e3d871354de300064638ea3b5272294e6428fef4"
            and result["j2a_manifest_sha256"] == "4a9a85b719dd1ef3fb5ded2fcd383f5c9bd8925c0e537bd8f5db0a1132602935", "原九scope报告范围错误")
    require([r["sha256"] for r in result["build_receipts"]] == [RECEIPTS[k] for k in ("py3","py2")], "原两producer收据身份变化")
    failed = any(s["status"] == "failed" for s in result["scopes"])
    require(exit_code == (1 if failed else 2) and result["status"] == ("failed" if failed else "incomplete_scopes_not_run"), "原部分重放退出码/状态错误")
    passed = []
    for row in result["scopes"]:
        if row["id"] not in TARGETS[ubuntu]:
            require(row["status"] == "not_run" and row["reason"] == "本次未选择", "未选scope被伪称执行");continue
        release = row["id"].split("-")[0]
        if release not in restored:require(row["status"] == "not_run", "无H1实物的scope不得执行");continue
        if row["status"] == "failed":continue
        require(row["status"] == "offline_replayed" and row["ios_runtime_verified"] is False
                and row["interpreter"]["sha256"] == restored[release]["sha256"], "有效H1 scope未真实重放或解释器改变")
        runtime = row["interpreter"]["runtime"]
        require(runtime["version"] == VERSIONS[release] and runtime["platform"] == ("linux2" if release == "7.8.7" else "linux")
                and runtime["machine"] == "x86_64" and runtime["implementation"] == "CPython", "精确target runtime不符")
        original = next(s for s in manifest["scopes"] if s["id"] == row["id"])
        contract = next(s for s in replay_plan["scopes"] if s["id"] == row["id"])
        environment = row["environment"];prefix = Path(REPLAY_OUTPUT) / row["id"] / "environment"
        require(environment["prefix"] == str(prefix) and environment["sites"] and environment["user"] is False
                and environment["pip"] is False and all(Path(p).is_absolute() and ".." not in Path(p).parts
                    and Path(p).is_relative_to(prefix) for p in environment["sites"]), "target实际独立环境边界错误")
        require({p["name"]:p["version"] for p in row["installed"]} == original["expected_versions"]
                and {p["name"]:p["usage"] for p in row["installed"]} == {p["name"]:p["usage"] for p in original["packages"]}
                and row["source_evidence"]["id"] == row["id"] and row["source_evidence"]["dependency_metadata_verified"] is True,
                "target安装版本/职责/原来源集合错误")
        proof = row["network_isolation"]
        require(proof["backend"] == "unshare" and proof["kernel_network_isolation_verified"] is True and proof["control"]["connected"] is True
                and proof["isolated"]["connected"] is False and proof["control"]["network_namespace"] != proof["isolated"]["network_namespace"], "缺真实内核隔离对照")
        require(proof["prefix"] == [proof["program"]["realpath"],"--net","--"]
                and proof["isolated_command"] == proof["prefix"] + proof["control_command"], "target内核隔离argv不符")
        require(not row["probe"]["errors"] and len(row["installed"]) == (14 if release in ("8.3.7","7.8.7") else 15)
                and len(row["probe"]["modules"]) == len(row["installed"]) and len(row["probe"]["resources"]) == 1
                and row["probe"]["resources"][0]["ca_count"] > 0
                and row["probe"]["smoke"] == [{"kind":"requests_prepare","passed":True},{"kind":"rsa_ecdsa_sign_verify","passed":True}], "target安装/模块/资源/smoke覆盖不完整")
        require([{k:m[k] for k in ("distribution","module","origin")} for m in row["probe"]["modules"]] == contract["modules"]
                and all(m["file"] and Path(m["file"]).is_absolute() and ".." not in Path(m["file"]).parts
                    and Path(m["file"]).is_relative_to(prefix) for m in row["probe"]["modules"]), "target实际模块来源/完整导入契约错误")
        certifi = next(p for p in original["packages"] if p["name"] == "certifi");artifact = manifest["artifacts"][certifi["artifact"]]
        with zipfile.ZipFile(merged/"cache"/artifact["sha256"]/artifact["filename"]) as archive:ca_sha = hashlib.sha256(archive.read("certifi/cacert.pem")).hexdigest()
        resource = row["probe"]["resources"][0]
        require(resource["kind"] == "certifi_ca_bundle" and resource["sha256"] == ca_sha
                and Path(resource["file"]) == Path(environment["sites"][0])/"certifi/cacert.pem", "target真实CA资源来源/摘要错误")
        folder = directory / row["id"];require(h0.decode(h0.read(folder/"commands.json")) == row["commands"], "原命令表改变")
        for command in row["commands"]:
            require(command["returncode"] == 0 and command["argv"][:len(proof["prefix"])] == proof["prefix"], "实际target命令未成功或未隔离")
            for channel in ("stdout","stderr"):require(re.fullmatch(r"command-[0-9]+-"+channel+r"\.log",command[channel]), "通道路径异常");h0.read(folder/command[channel],32*1024**2)
        probe_commands = [c for c in row["commands"] if "'modules':[]" in " ".join(c["argv"])]
        require(len(probe_commands) == 1 and h0.decode(h0.read(folder/probe_commands[0]["stdout"])) == row["probe"], "实际target probe原stdout不符")
        identity = h0.decode(h0.read(folder/"identity-probe/commands.json"))
        require(len(identity) == 1 and identity[0]["returncode"] == 0
                and identity[0]["stdout"] == "command-01-stdout.log" and identity[0]["stderr"] == "command-01-stderr.log"
                and h0.decode(h0.read(folder/"identity-probe"/identity[0]["stdout"])) == runtime, "实际target identity原stdout不符")
        passed.append(row["id"])
    return passed


def execute_group(run, h0, merged, catalog, artifact, rows, native, inventory, ubuntu, report):
    """只恢复本组独立有效route并运行固定原replay，无任意后置命令入口。"""
    python = "/usr/bin/python3.10" if ubuntu == "22.04" else "/usr/bin/python3.12"
    run.run(["mkdir","-p",REMOTE,"/reko/h2-host-exports"],"h2-directories")
    run.copy(str(merged)+"/.",REMOTE,"h2-copy-merged-inputs")
    run.checksum("h2-inputs",[(r["sha256"],REMOTE+"/"+r["path"]) for r in catalog])
    restored = {}
    for row in rows:
        if row["status"] != "export_verified":continue
        release = row["release"];folder = Path(row["folder"])
        try:
            run.run(["mkdir","-p","/reko/h2-host-exports/"+release],"h2-host-export-directory-"+release)
            checks = []
            for name in ("host-receipt.json","host-distribution.json","host-export.json","host-distribution.tar.gz"):
                target = "/reko/h2-host-exports/"+release+"/"+name;run.copy(folder/name,target,"h2-copy-"+release+"-"+name);checks.append((file_identity(folder/name)["sha256"],target))
            run.checksum("h2-host-export-"+release,checks)
            raw,_ = run.run([python,"-B","-c",RESTORE_HOST,release,"/reko/h2-host-exports/"+release,
                             REMOTE+"/root/scripts/renpy",file_identity(Path(native.__file__))["sha256"],file_identity(Path(inventory.__file__))["sha256"]],"h2-restore-and-probe-"+release)
            restored[release] = h0.decode(raw);require(restored[release]["full_distribution_reverified"] is True, "恢复分发未验完")
            row["status"] = "restored_and_probed"
        except Exception as error:row.update(status="failed",reason=type(error).__name__+": "+str(error))
    report["restored_host_releases"] = sorted(restored)
    argv = [python,"-B",REMOTE+"/root/scripts/renpy/replay_python_inputs.py","replay","--source-cache",REMOTE+"/cache","--tool-cache",REMOTE+"/cache",
            "--installer-cache","/reko/h2-installers","--report",REPLAY_OUTPUT,"--isolation","unshare"]
    for family in ("py3","py2"):argv += ["--build-report",REMOTE+"/receipts/"+family+"/report.json","--build-report-sha256",RECEIPTS[family]]
    for scope in TARGETS[ubuntu]:
        argv += ["--scope",scope];release = scope.split("-")[0]
        if release in restored:argv += ["--interpreter",scope+"="+restored[release]["interpreter"],"--interpreter-sha256",scope+"="+restored[release]["sha256"]]
    exit_code = None
    try:
        try:run.run(argv,"h2-original-target-replay");exit_code = 0
        except run.apt.AptInputError:
            command = run.commands.records[-1];require(command["label"] == "h2-original-target-replay", "非原replay错误不能当exit2")
            exit_code = command["returncode"]
            if exit_code == 2:command["expected_partial_result"] = True
    finally:preserve_results(run,TARGETS[ubuntu],python)
    result = h0.decode(h0.read(run.output/"target-replay/report.json",16*1024**2))
    report["original_replay_executed"] = True;report["target_replay_executed"] = bool(restored);report["original_replay_exit_code"] = exit_code
    report["scopes"] = [{"id":s["id"],"status":s["status"]} for s in result["scopes"]]
    manifest = h0.decode(h0.read(merged/"root/scripts/renpy/python-inputs.lock.json"))
    replay_plan = h0.decode(h0.read(merged/"root/scripts/renpy/python-replay-plan.json"))
    report["passed_target_scopes"] = verify_result(h0,result,ubuntu,restored,exit_code,run.output/"target-replay",manifest,replay_plan,merged)
    report["original_replay_report_sha256"] = file_identity(run.output/"target-replay/report.json")["sha256"]
    require(not any(s["status"] == "failed" for s in result["scopes"]) and not any(r["status"] == "failed" for r in rows), "存在实际target或host恢复失败，独立结果已保留")
    return len(report["passed_target_scopes"]) == len(TARGETS[ubuntu])


def main(argv=None):
    """外部ZIP身份必填；两密钥只在宿主解密，缺实物保留未运行，finally清理本轮容器/输入。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ubuntu",choices=sorted(TARGETS),required=True);parser.add_argument("--bundle",type=Path,required=True)
    parser.add_argument("--h1-artifact",type=Path,required=True);parser.add_argument("--h1-artifact-sha256",required=True)
    parser.add_argument("--h1-artifact-bytes",type=int,required=True);parser.add_argument("--output",type=Path,required=True)
    args = parser.parse_args(argv);password0 = os.environ.pop("REKO_H0_INPUTS_PASSWORD",None);password2 = os.environ.pop("REKO_H2_INPUTS_PASSWORD",None)
    report = {"task":"R00-02J2C-H2-Linux","result":"failed","ubuntu":args.ubuntu,"errors":[],"H2_group_complete":False,"target_replay_executed":False,"original_replay_executed":False,
              "passed_target_scopes":[],"routes":[],"container_closed":False,"private_inputs_removed":False,"J2C_complete":False,"ios_runtime_verified":False,
              "sdk_inputs_consumed":False,"secret_sent_to_container":False,"source_ci_verified":False,"target_pip_bound":False,"full_engine_session_verified":False,
              "scopes":[{"id":s,"status":"not_run","reason":"依赖前置尚未通过"} for s in sorted(ALL_SCOPES)]}
    created = False;private = None;transport = None
    try:
        args.output,args.bundle,args.h1_artifact = guarded(args.output),guarded(args.bundle),guarded(args.h1_artifact)
        require(not args.output.exists() and args.output.parent.is_dir() and not args.output.is_relative_to(args.bundle)
                and not args.bundle.is_relative_to(args.output) and not args.h1_artifact.is_relative_to(args.output), "输出必须全新且与输入分离")
        args.output.mkdir();created = True
        report["H1_external_ZIP_identity"] = verify_h1_artifact(args.h1_artifact,args.h1_artifact_sha256,args.h1_artifact_bytes)
        plan = load_plan();transport,h0,h0_plan,h1,native,inventory = load_helpers(plan)
        report.update(plan_sha256=PLAN_SHA256,H1_execution_sha256=plan["helpers"]["H1_execution"]["sha256"],
                      H1_wrapper_sha256=plan["helpers"]["H1_wrapper"]["sha256"],H2_extra_manifest_sha256=EXTRA_MANIFEST["sha256"])
        require(os.environ.get("RUNNER_TEMP"), "缺少独立RUNNER_TEMP")
        temporary_root = guarded(os.environ["RUNNER_TEMP"])
        require(temporary_root.is_dir() and not temporary_root.is_relative_to(args.output)
                and not temporary_root.is_relative_to(args.bundle), "临时输入根无效")
        checkout = os.environ.get("GITHUB_WORKSPACE")
        require(not checkout or not temporary_root.is_relative_to(guarded(checkout)), "解密输入不能位于checkout")
        with tempfile.TemporaryDirectory(prefix="reko-h2-inputs-",dir=temporary_root) as directory:
            private = Path(directory);private.chmod(0o700);artifact = private/"H1-artifact";extract_h1_zip(args.h1_artifact,artifact)
            report["routes"] = classify_exports(h0,h1,artifact,args.ubuntu,plan)
            if not any(r["status"] == "export_verified" for r in report["routes"]):
                require(not any(r["status"] == "failed" for r in report["routes"]), "H1原导出存在实际失败")
                report["result"] = "not_run_no_complete_H1_export"
            else:
                require(sys.platform == "linux" and platform.machine() == "x86_64", "真实H2重放需要Linux x86_64与Docker，Mac不计执行")
                require(password0 and password2, "缺少各自固定输入运输密钥")
                encrypted,plain,payload = private/"h0.enc",private/"h0.tar.gz",private/"h0"
                transport.download(transport.TRANSPORT,encrypted);transport.decrypt(encrypted,plain,transport.TRANSPORT,password0);password0 = None
                transport.extract_payload(plain,payload,h0_plan["files"]);encrypted.unlink();plain.unlink()
                h0.verify_files(payload,h0_plan["files"]);h0.verify_original_contracts(payload,h0_plan["files"])
                report["H0_input_bytes_and_original_contracts_verified"] = True
                encrypted,plain,extra = private/"h2.enc",private/"h2.tar.gz",private/"extra"
                download_extra(transport,plan["extra"],encrypted);transport.decrypt(encrypted,plain,plan["extra"],password2);password2 = None
                catalog = extra_catalog(h0,payload,h0_plan,plain);extract_extra(plain,extra,catalog);encrypted.unlink();plain.unlink()
                report["H2_extra_all_33_regular_inputs_verified"] = True
                merged = private/"merged";merged_catalog = merge_inputs(h0,payload,extra,h0_plan,catalog,merged,
                    {"run_locked_host_python_tasks.py":native,"inventory_source_inputs.py":inventory})
                report["current_input_verification"] = verify_current_inputs(merged,args.output)
                container_output = args.output/"container";container_output.mkdir()
                namespace = argparse.Namespace(payload=payload,bundle=args.bundle,ubuntu=args.ubuntu,output=container_output)
                with h0.open_environment(namespace,h0_plan,report) as run:
                    complete = execute_group(run,h0,merged,merged_catalog,artifact,report["routes"],native,inventory,args.ubuntu,report)
                report.update(H2_group_complete=complete,result="selected_exact_target_group_offline_replayed" if complete else "incomplete_missing_H1_routes")
                original = h0.decode(h0.read(container_output/"target-replay/report.json",16*1024**2));report["scopes"] = [{"id":s["id"],"status":s["status"]} for s in original["scopes"]]
        require(not private.exists(), "本轮私有输入没有清理")
    except Exception as error:report["errors"].append(type(error).__name__+": "+str(error));report["result"] = "failed"
    finally:
        password0 = password2 = None;report["private_inputs_removed"] = private is not None and not private.exists()
        if report["result"] == "failed":report["H2_group_complete"] = False
        if created:
            report["files"] = [{"path":str(p.relative_to(args.output)),**file_identity(p)} for p in sorted(args.output.rglob("*")) if p.is_file()]
            write_json(args.output/"linux-target-python-replay-report.json",report)
    log("结果="+report["result"]+"；"+"；".join(report["errors"]))
    return 1 if report["result"] == "failed" else 0 if report["H2_group_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
