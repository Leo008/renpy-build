#!/usr/bin/env python3
"""在同一个真实C1生命周期内依次执行冻结C/B、原pip任务和完整静态验收。"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import types
import zipfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
DEFAULT_PLAN = HERE / "linux-target-pip-ci-plan.json"
# 独立SHA绑定真实09运输、原D及已提交pip/导出工具，不接受浮动输入。
PLAN_SHA256 = "76adfb5296f1d0677b6899d655405309247600375ba56ec135c9ab73e6a4ba2e"
REMOTE_J2 = "/reko/j9c-inputs"
REMOTE_CODE = "/reko/j9c-code"
REMOTE_RESULTS = "/reko/j9c-results"
REMOTE_EXPORT = "/reko/j9c-export"
ARCHES = ("arm64", "sim-arm64", "sim-x86_64")

REMOTE_IDENTITIES = r'''import hashlib,json,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]);result={}
for name in ('target-pip-export.json','target-pip-prefix-and-proof.tar.gz'):
 p=root/name;assert stat.S_ISREG(p.lstat().st_mode);h=hashlib.sha256();size=0
 with p.open('rb') as f:
  while b:=f.read(262144):size+=len(b);h.update(b)
 result[name]={'bytes':size,'sha256':h.hexdigest()}
print(json.dumps(result,sort_keys=True))
'''

# 只在原worker完整成功后清理已锁CP39 seed资源残留；不扩导出器证据白名单。
CLEANUP_SEED_CERTIFI_CA = r'''import hashlib,io,json,os,pathlib,re,stat,sys,zipfile
code,root,prefix,release,arch,scope,worker_sha,plan_sha=sys.argv[1:]
code=pathlib.Path(code);root=pathlib.Path(root);prefix=pathlib.Path(prefix)
def require(value,message):
 # 仅已证本轮CP39成功后的单个seed CA残留可以删除，任一不符均保留失败。
 if not value:raise ValueError(message)
def guarded(path):
 # 保持实际路径，拒绝叶/父链接和上跳，不resolve隐藏来源。
 require(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in (path,*path.parents)),'CA cleanup unsafe path')
 return path
def regular(path,maximum):
 # 固定源也以普通文件有界读取，FIFO不会在核类型前阻塞。
 guarded(path)
 with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
  info=os.fstat(stream.fileno());require(stat.S_ISREG(info.st_mode) and 0<=info.st_size<=maximum,'CA cleanup file type/size')
  raw=stream.read(maximum+1);require(len(raw)==info.st_size and len(raw)<=maximum,'CA cleanup read changed')
 return raw,info
def pairs(items):
 # 原成功JSON也拒绝重复键，避免两种身份解释。
 result={}
 for key,value in items:
  require(key not in result,'CA cleanup duplicate JSON key');result[key]=value
 return result
def nonfinite(value):
 # 成功证明不得包含非有限数。
 raise ValueError('CA cleanup nonfinite JSON')
def decode(raw):
 # 只解析原证据，不执行wheel或回传目标代码。
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=nonfinite)
def digest(raw):
 # 全原字节SHA同时绑定seed、实际prefix和待删文件。
 return hashlib.sha256(raw).hexdigest()
def directory(path):
 # 本轮worker以独占mkdir创建tmp，成功收据的TMPDIR另作关联。
 guarded(path);info=path.lstat()
 require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and not stat.S_IMODE(info.st_mode)&0o022,'CA cleanup directory ownership')
 return info
def same_file(info):
 # 验证至unlink前保持同一单link对象，不能删除替换物。
 return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
require(release=='8.3.7' and arch in ('arm64','sim-arm64','sim-x86_64') and scope=='8.3.7-target-recipe','CA cleanup route not approved')
require(re.fullmatch(r'[0-9a-f]{64}',worker_sha) and re.fullmatch(r'[0-9a-f]{64}',plan_sha),'CA cleanup source identities missing')
worker_raw,_=regular(code/'run_locked_target_pip_tasks.py',1048576);plan_raw,_=regular(code/'target-pip-binding-plan.json',1048576)
require(digest(worker_raw)==worker_sha and digest(plan_raw)==plan_sha,'CA cleanup worker/plan identity')
plan=decode(plan_raw);require(plan['task']=='R00-02J9C','CA cleanup plan task')
route=next(v for v in plan['routes'] if v['release']==release)
require(route['version']=='3.9.10' and route['original_installer_version']=='21.2.4' and scope in route['allowed_scopes'],'CA cleanup seed route differs')
root_info=directory(root);temporary=root/'tmp';tmp_info=directory(temporary)
require(tmp_info.st_dev==root_info.st_dev and prefix.name=='install.ios-'+arch and prefix.parent.name=='tmp','CA cleanup prefix/tmp ownership')
receipt_raw,_=regular(root/'target-pip-receipt.json',65536);receipt=decode(receipt_raw)
expected_receipt={'path':str(root/'target-pip-receipt.json'),'sha256':digest(receipt_raw)}
for name in ('worker-report.json','report.json'):
 body,_=regular(root/name,32768);report=decode(body)
 require(report['task']=='R00-02J9C' and (report['release'],report['arch'],report['target_scope'])==(release,arch,scope)
  and report['result']=='original_target_pip_Task_offline_verified' and report['errors']==[] and report['target_pip_bound'] is True
  and report['receipt']==expected_receipt,'CA cleanup original worker did not fully succeed')
require(receipt['task']=='R00-02J9C' and (receipt['release'],receipt['arch'],receipt['target_scope'])==(release,arch,scope)
 and receipt['execution_source_sha256']==worker_sha and receipt['plan_sha256']==plan_sha
 and all(receipt[k] is True for k in ('target_pip_bound','original_Task_run_verified','original_ensurepip_executed','kernel_network_isolation_verified'))
 and receipt['original_pip_task']==route['pip_task'],'CA cleanup original receipt differs')
commands=receipt['commands'];bridge=str(prefix/'bin/hostpython3')
require(len(commands)==2,'CA cleanup original Task commands missing')
for index,command in enumerate(commands):
 actual=command['actual_command']
 require(command['ordinal']==index and command['template']==route['commands'][index] and command['validated'] is True
  and type(command['actual_command_returncode']) is int and command['actual_command_returncode']==0
  and type(actual['returncode']) is int and actual['returncode']==0 and actual['environment']['TMPDIR']==str(temporary)
  and actual['argv'][0]==bridge,'CA cleanup original Task/TMPDIR binding differs')
require(commands[0]['original_argv_executed'] is True and commands[0]['actual_command']['argv']==[bridge,'-s','-m','ensurepip'],'CA cleanup original ensurepip not executed')
seed=next(v for v in route['bundled_wheels'] if pathlib.Path(v['path']).name=='pip-21.2.4-py3-none-any.whl')
wheel_path=root/'locked-inputs/seed-wheels'/pathlib.Path(seed['path']).name
wheel_raw,_=regular(wheel_path,4194304)
require(len(wheel_raw)==seed['bytes'] and digest(wheel_raw)==seed['sha256'],'CA cleanup locked seed wheel differs')
ca_member='pip/_vendor/certifi/cacert.pem';core_member='pip/_vendor/certifi/core.py'
with zipfile.ZipFile(io.BytesIO(wheel_raw)) as archive:
 require(archive.namelist().count(ca_member)==archive.namelist().count(core_member)==1,'CA cleanup seed member duplicate/missing')
 require(archive.getinfo(ca_member).file_size==259465 and archive.getinfo(core_member).file_size==2840,'CA cleanup seed member length')
 ca=archive.read(ca_member);core=archive.read(core_member)
require(digest(ca)=='de2fa17c4d8ae68dc204a1b6b58b7a7a12569367cfeb8a3a4e1f377c73e83e9e'
 and digest(core)=='80e15dd331d8971e24aeb2c49fdf367ac3ad9b3ddd8e21b40454838608e5bdc2','CA cleanup known seed CA/source differs')
site=prefix/'lib/python3.9/site-packages';installed=site/ca_member;installed_core=site/core_member
actual_ca,_=regular(installed,1048576);actual_core,_=regular(installed_core,32768)
require(actual_ca==ca and actual_core==core,'CA cleanup actual prefix seed CA/source differs')
removed=[]
tmp_fd=os.open(temporary,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 require((os.fstat(tmp_fd).st_dev,os.fstat(tmp_fd).st_ino)==(tmp_info.st_dev,tmp_info.st_ino),'CA cleanup tmp replaced')
 names=[]
 with os.scandir(tmp_fd) as entries:
  for entry in entries:
   names.append(entry.name);require(len(names)<=1,'CA cleanup unexpected multiple tmp members')
 if names:
  name=names[0];require(re.fullmatch(r'tmp[a-z0-9_]{8}cacert[.]pem',name),'CA cleanup unknown tmp basename')
  before=os.stat(name,dir_fd=tmp_fd,follow_symlinks=False)
  require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.geteuid()
   and before.st_dev==tmp_info.st_dev and before.st_size==len(ca),'CA cleanup tmp is not owned single-link CA')
  with os.fdopen(os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=tmp_fd),'rb') as stream:
   require(same_file(os.fstat(stream.fileno()))==same_file(before),'CA cleanup tmp replaced before read')
   body=stream.read(len(ca)+1)
   require(body==ca and digest(body)==digest(actual_ca),'CA cleanup tmp CA bytes/SHA differ')
   require(same_file(os.fstat(stream.fileno()))==same_file(before),'CA cleanup tmp changed during read')
  require((directory(temporary).st_dev,directory(temporary).st_ino)==(tmp_info.st_dev,tmp_info.st_ino)
   and same_file(os.stat(name,dir_fd=tmp_fd,follow_symlinks=False))==same_file(before),'CA cleanup tmp replaced before unlink')
  os.unlink(name,dir_fd=tmp_fd)
  removed.append({'path':'tmp/'+name,'bytes':len(body),'sha256':digest(body),'device':before.st_dev,'inode':before.st_ino,'nlink':before.st_nlink,'uid':before.st_uid,'source_mtime_ns':before.st_mtime_ns})
 require(os.listdir(tmp_fd)==[],'CA cleanup tmp not empty after exact unlink')
finally:os.close(tmp_fd)
print(json.dumps({'result':'bounded_original_seed_CA_tmp_cleanup','release':release,'arch':arch,'target_scope':scope,
 'original_worker_receipt':expected_receipt,'worker_sha256':worker_sha,'plan_sha256':plan_sha,
 'seed_wheel':{'path':str(wheel_path),'bytes':len(wheel_raw),'sha256':digest(wheel_raw)},
 'seed_CA':{'member':ca_member,'bytes':len(ca),'sha256':digest(ca)},'seed_certifi_source':{'member':core_member,'bytes':len(core),'sha256':digest(core)},
 'actual_prefix_CA':{'path':str(installed),'bytes':len(actual_ca),'sha256':digest(actual_ca)},
 'owned_tmp':{'path':str(temporary),'device':tmp_info.st_dev,'inode':tmp_info.st_ino,'uid':tmp_info.st_uid},
 'removed':removed,'tmp_empty_after':True,'unknown_members_skipped':False,'prefix_modified':False,'full_static_acceptance_claimed':False},sort_keys=True))
'''

PRESERVE_PIP_FAILURE = r'''import hashlib,json,os,pathlib,stat,sys,types
source,destination,tool,toolsha,planpath,export_root=sys.argv[1:]
source=pathlib.Path(source);destination=pathlib.Path(destination);export_root=pathlib.Path(export_root)
def require(value,message):
 # 失败诊断也必须拒绝路径链接、特殊文件及无界读取。
 if not value:raise ValueError(message)
def guarded(path):
 # 不resolve掩盖链接或上跳，所有父级都必须是真实路径。
 require(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in (path,*path.parents)),'unsafe diagnostic path')
 return path
def regular(path,maximum):
 # 只读同一个普通文件描述符，先核大小，FIFO不打开阻塞。
 guarded(path)
 with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
  info=os.fstat(stream.fileno());require(stat.S_ISREG(info.st_mode) and 0<=info.st_size<=maximum,'diagnostic type or size')
  raw=stream.read(maximum+1);require(len(raw)==info.st_size and len(raw)<=maximum,'diagnostic length changed')
 return raw,info
def write_raw(path,raw):
 # 只向本轮独占目的地写新文件，不覆盖原材料或既有诊断。
 guarded(path)
 with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb') as stream:stream.write(raw)
raw,_=regular(pathlib.Path(tool),1048576);require(hashlib.sha256(raw).hexdigest()==toolsha,'exporter source differs')
m=types.ModuleType('j9c_failure_allowlist');m.__file__=tool;exec(compile(raw,tool,'exec'),m.__dict__)
plan_raw,_=regular(pathlib.Path(planpath),1048576);require(hashlib.sha256(plan_raw).hexdigest()==m.PLAN_SHA256,'exporter plan differs')
plan=m.decode(plan_raw);guarded(source);guarded(destination)
require(not destination.is_relative_to(source) and not source.is_relative_to(destination) and not destination.is_relative_to(export_root) and not export_root.is_relative_to(destination),'diagnostic roots overlap')
require(not destination.exists(),'diagnostic output exists');destination.mkdir(mode=0o700)
# 导出器捕获的真实异常只存在固定export根，先保全它再扫描结果目录。
export_status={'source':'verification-report.json','status':'missing'}
try:
 raw,info=regular(export_root/'verification-report.json',32768)
 document=m.decode(raw);require(isinstance(document,dict),'export report is not object')
 write_raw(destination/'export-verification-report.json',raw)
 export_status.update(status='captured',path='export-verification-report.json',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),source_mtime_ns=info.st_mtime_ns)
except FileNotFoundError:pass
except (ValueError,OSError,TypeError) as error:
 export_status.update(status='rejected',error_type=type(error).__name__)
rows=[];total=0;skipped=[];skipped_count=0;metadata_bytes=0;metadata_truncated=False;scanned=0;scan_complete=True
pending=[source] if source.is_dir() else []
require(not source.exists() or source.is_dir(),'result root is not directory')
def record_skip(name,info,reason):
 # 未收取项只留原lstat元数据；不打开未知文件、不读取链接目标或内容。
 global skipped_count,metadata_bytes,metadata_truncated
 skipped_count+=1
 kind='directory' if stat.S_ISDIR(info.st_mode) else 'file' if stat.S_ISREG(info.st_mode) else 'symlink' if stat.S_ISLNK(info.st_mode) else 'fifo' if stat.S_ISFIFO(info.st_mode) else 'other'
 row={'path':name,'type':kind,'bytes':info.st_size,'mtime_ns':info.st_mtime_ns,'reason':reason}
 size=len(json.dumps(row,ensure_ascii=True,indent=2).encode())+64
 if len(skipped)<256 and metadata_bytes+size<=1048576:skipped.append(row);metadata_bytes+=size
 else:metadata_truncated=True
while pending:
 folder=guarded(pending.pop())
 with os.scandir(folder) as entries:
  for entry in entries:
   if scanned>=20000:scan_complete=False;break
   scanned+=1;p=pathlib.Path(entry.path);name=p.relative_to(source).as_posix();info=entry.stat(follow_symlinks=False)
   if stat.S_ISDIR(info.st_mode):pending.append(p);record_skip(name,info,'directory');continue
   if not stat.S_ISREG(info.st_mode):record_skip(name,info,'not_regular');continue
   if not m.result_allowed(name,plan):record_skip(name,info,'not_allowlisted');continue
   if info.st_size>33554432 or total+info.st_size>134217728 or len(rows)>=1000:record_skip(name,info,'copy_limit');continue
   body,observed=regular(p,33554432);target=destination/name;guarded(target);target.parent.mkdir(parents=True,exist_ok=True);write_raw(target,body)
   total+=len(body);rows.append({'path':name,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'source_mtime_ns':observed.st_mtime_ns})
 if not scan_complete:break
result={'diagnostic_only':True,'target_pip_bound':False,'files':sorted(rows,key=lambda row:row['path']),'export_verification_report':export_status,
 'not_preserved':sorted(skipped,key=lambda row:row['path']),'not_preserved_count':skipped_count,'not_preserved_metadata_complete':not metadata_truncated,
 'result_scan_complete':scan_complete,'result_scanned_members':scanned,'result_root_present':source.exists(),
 'limits':{'export_report_bytes':32768,'skipped_metadata_members':256,'skipped_metadata_bytes':1048576,'result_scan_members':20000}}
write_raw(destination/'failure-preservation.json',(json.dumps(result,ensure_ascii=True,indent=2)+'\n').encode())
'''


class InputUnavailable(ValueError):
    """真正缺少环境或必要输入时如实标记未运行。"""


def require(condition, message):
    """拒绝不符合固定输入合同的条件，不提供容错成功默认值。"""
    if not condition:
        raise ValueError(message)


def log(message):
    """统一输出阶段日志，秘密和SDK内容永不进入公共通道。"""
    print("[RKLog][RenPyLinuxTargetPip] " + message, flush=True)


def guarded(value):
    """输入必须是显式无链接绝对路径，拒绝上跳和链接祖先。"""
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), "路径不是无链接绝对路径")
    return path


def identity(path, maximum=2 * 1024**3):
    """逐块计算实际普通文件身份，拒绝链接、设备和超大文件。"""
    path = guarded(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= maximum, "输入不是有界普通文件")
        digest = hashlib.sha256(); size = 0
        while block := stream.read(262144):
            digest.update(block); size += len(block)
    require(size == info.st_size, "输入在读取期间改变长度")
    return {"bytes": size, "sha256": digest.hexdigest()}


def checked(path, expected):
    """强绑定独立给定的大小和SHA，不仅信任包内收据。"""
    require(identity(path) == {key: expected[key] for key in ("bytes", "sha256")}, "输入完整身份错误：" + Path(path).name)


def unique_pairs(pairs):
    """拒绝JSON重复键，防止控制计划出现两个解释。"""
    result = {}
    for key, value in pairs:
        require(key not in result, "JSON重复键"); result[key] = value
    return result


def reject_nonfinite(value):
    """固定控制数据不接受JSON非有限数。"""
    raise ValueError("JSON非有限数：" + value)


def read(path):
    """只读取有界控制JSON，原字节身份由调用处独立绑定。"""
    require(identity(path)["bytes"] <= 4 * 1024**2, "控制JSON过大")
    return json.loads(path.read_bytes(), object_pairs_hook=unique_pairs, parse_constant=reject_nonfinite)


def write(path, value):
    """只创建本轮新报告，禁止覆写历史证据。"""
    with guarded(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2); stream.write("\n")


def load_plan(path=DEFAULT_PLAN):
    """计划由工具内固定SHA锚定，候选与最终发布都只接受实际原字节。"""
    require(identity(path)["sha256"] == PLAN_SHA256, "编排计划原字节改变")
    plan = read(path)
    require(plan["schema_version"] == 1 and plan["task"] == "R00-02J9C-CI"
            and plan["scope"] == "same_open_C1_original_C_then_B_then_real_pip_full_prefix_static_proof", "编排范围错误")
    require(len(plan["text_runtime_catalog"]) == 4 and len({row["path"] for row in plan["text_runtime_catalog"]}) == 4, "文本工具不唯一")
    require(all(Path(row["path"]).name == row["path"] and re.fullmatch(r"[A-Za-z0-9_-]+\.(py|json)", row["path"]) for row in plan["text_runtime_catalog"]), "文本工具路径错误")
    require(plan["limits"]["max_selected_cells"] == 1 and plan["boundaries"]["secret_sent_to_container"] is False, "编排隔离边界改变")
    return plan


def load_D(path, plan):
    """执行原D控制工具原字节，不修改其源码、函数或固定计划。"""
    checked(path, plan["D"]["wrapper"])
    module = types.ModuleType("j9c_frozen_D"); module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    checked(path.parent / "linux-target-python-prefix-ci-plan.json", plan["D"]["plan"])
    return module


def validate_selection(args, plan):
    """每次只运行一个已验B资格和明确pip范围，避免一个进程累积多树。"""
    require(args.release in plan["groups"][args.ubuntu] and args.arch in ARCHES and args.scope in plan["pip_scopes"][args.release], "route/group/arch/scope不对应")
    require({"release": args.release, "arch": args.arch} in plan["B_eligible_scopes"], "该scope没有已锁定B资格")


def extract_text(archive, destination, catalog):
    """09只有四个普通文本成员，逐字节核对且禁止目录、链接或PAX。"""
    expected = {row["path"]: row for row in catalog}; seen = set(); destination.mkdir(mode=0o700)
    with tarfile.open(archive, "r:gz") as source:
        for item in source:
            require(item.name in expected and item.name not in seen and item.isfile() and not item.sparse and not item.pax_headers
                    and item.mode == 0o644 and item.uid == item.gid == item.mtime == 0, "09文本包成员或模式错误")
            row = expected[item.name]; require(item.size == row["bytes"], "09文本成员大小错误"); seen.add(item.name)
            with source.extractfile(item) as stream, (destination / item.name).open("xb") as output:
                body = stream.read(row["bytes"] + 1); require(len(body) == row["bytes"], "09文本成员长度错误"); output.write(body)
            checked(destination / item.name, row)
    require(seen == set(expected), "09文本包缺项")


def verify_py2_zip(path, extra, plan):
    """原Py2 ZIP强身份再逐个核对三份收据/轮子，只读取缓存不解包第二份。"""
    checked(path, plan["Py2_original_artifact"])
    with zipfile.ZipFile(path) as source:
        members = source.infolist(); names = [member.filename for member in members]
        require(len(names) == len(set(names)), "Py2 ZIP成员重复")
        for old, current in plan["Py2_receipt_cross_checks"].items():
            require(names.count(old) == 1, "Py2 ZIP缺原成员")
            item = source.getinfo(old); require(not item.flag_bits & 1 and stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG), "Py2 ZIP原成员不是普通文件")
            expected = identity(extra / current); require(item.file_size == expected["bytes"], "Py2 ZIP原成员大小错误")
            with source.open(item) as stream:
                body = stream.read(expected["bytes"] + 1)
            require(len(body) == expected["bytes"] and hashlib.sha256(body).hexdigest() == expected["sha256"], "H2内Py2成员与原artifact不同")


def prepare_inputs(d, h2, transport, h0, h0_plan, h1, native, inventory, args, dplan, plan, private, diagnostics, passwords):
    """按原D顺序准备固定输入，仅新增强身份缓存入口和物理分离的新J2根。"""
    encrypted = args.h0_cipher or private / "h0.enc"
    if args.h0_cipher is None: transport.download(transport.TRANSPORT, encrypted)
    checked(encrypted, transport.TRANSPORT["ciphertext"])
    plaintext = private / "h0.tar.gz"; payload = private / "h0"
    transport.decrypt(encrypted, plaintext, transport.TRANSPORT, passwords[0])
    transport.extract_payload(plaintext, payload, h0_plan["files"]); plaintext.unlink()
    if args.h0_cipher is None: encrypted.unlink()
    h0.verify_files(payload, h0_plan["files"]); h0.verify_original_contracts(payload, h0_plan["files"])
    recipe = args.recipe_addon or private / "recipes.tar.gz"
    if args.recipe_addon is None: h1.download_addon(transport, recipe)
    else: checked(recipe, h1.ADDON)
    manifest = h1.read_manifest(transport, h0, recipe, private / "recipe-manifest.json")
    with tarfile.open(recipe, "r:gz") as source:
        old_plan = source.extractfile("runtime/host-python-bootstrap-plan.json").read(1024**2)
    routes, objects, catalog = h1.derive_addon(transport, h0, payload, manifest, h0_plan, old_plan)
    addon = private / "recipe-addon"; transport.extract_payload(recipe, addon, catalog)
    profile = d.phase_profile(dplan, "target-install")
    runtime = private / "B-runtime-addon"; d.extract_runtime_addon(h2, args.runtime_addon, runtime, profile["metadata_addon"])
    metadata = private / "metadata/root"
    rows = d.prepare_runtime(h0, h1, payload, addon, manifest, h0_plan, runtime, profile["metadata_addon"], metadata)
    fresh = diagnostics / "fresh-runtime"; fresh.mkdir()
    proof = d.fresh_runtime_check(metadata, fresh, profile["worker"]["sha256"], "target-install")
    stager = h0.load_module(addon / "runtime/run_locked_source_tasks.py", h1.RUNTIME["run_locked_source_tasks.py"], "j9c_original_J1_stager")
    workspaces = private / "workspaces"; (workspaces / args.release).mkdir(parents=True); cache = {}
    def get_bytes(item):
        """复用原CAS对象且仍让原J1逐blob/模式/路径验证。"""
        digest = item["sha256"]
        if digest not in cache: cache[digest] = h1.raw_object(h0, payload, addon, digest, objects[digest])
        return cache[digest]
    h1.rebuild_workspace(stager, routes[args.release], workspaces / args.release / args.arch, get_bytes)
    extra_cipher = args.h2_cipher or private / "extra.enc"
    if args.h2_cipher is None: h2.download_extra(transport, plan["H2_extra"], extra_cipher)
    checked(extra_cipher, plan["H2_extra"]["ciphertext"])
    extra_archive = private / "extra.tar.gz"
    transport.decrypt(extra_cipher, extra_archive, plan["H2_extra"], passwords[1])
    extra_rows = h2.extra_catalog(h0, payload, h0_plan, extra_archive)
    extra = private / "extra"; h2.extract_extra(extra_archive, extra, extra_rows); extra_archive.unlink()
    if args.h2_cipher is None: extra_cipher.unlink()
    verify_py2_zip(args.py2_artifact, extra, plan)
    merged = private / "J2-inputs"
    merged_rows = h2.merge_inputs(h0, payload, extra, h0_plan, extra_rows, merged,
                                 {"run_locked_host_python_tasks.py": native, "inventory_source_inputs.py": inventory})
    j2proof = h2.verify_current_inputs(merged, diagnostics)
    code = private / "pip-code"; extract_text(args.pip_addon, code, plan["text_runtime_catalog"])
    require(not merged.is_relative_to(metadata) and not metadata.is_relative_to(merged) and merged != payload, "新J2与原B根必须物理分离")
    # 明确记录与原D准备顺序的差异；缓存命中只改变运输取件，不改执行或验收函数。
    write(diagnostics / "input-preparation-actions.json", {
        "original_D_source_sha256": plan["D"]["wrapper"]["sha256"],
        "original_preparation_sequence_preserved": ["transport.decrypt", "transport.extract_payload", "h0.verify_files", "h0.verify_original_contracts",
            "h1.read_manifest", "h1.derive_addon", "transport.extract_payload", "D.extract_runtime_addon", "D.prepare_runtime", "D.fresh_runtime_check", "h1.rebuild_workspace"],
        "transport_changes_only": {"H0": "explicit_verified_cache" if args.h0_cipher else "original_fixed_download",
                                  "H2": "explicit_verified_cache" if args.h2_cipher else "original_fixed_download",
                                  "Py2": "required_external_original_artifact_verified_then_streamed_three_members"},
        "new_separate_J2_sequence": ["h2.extra_catalog", "h2.extract_extra", "verify_py2_zip", "h2.merge_inputs", "h2.verify_current_inputs"],
        "D_source_or_functions_modified": False, "old_B_runtime_overwritten": False,
        "same_open_C1_execution_function": "D.execute_cells"})
    return payload, metadata, rows, workspaces, proof, merged, merged_rows, j2proof, code


def producer_paths(pip_plan, root):
    """固定两producer路径分别映射原Mac证据和已有Py2收据，不使用任意扫描。"""
    receipts = pip_plan["producer_receipts"]
    return [(root / "receipts/py3/report.json", receipts["mac-py3"]["sha256"]),
            (root / "receipts/py2/report.json", receipts["linux-py2"]["sha256"])]


def pip_argv(args, dplan, pip_plan, b_receipt_sha, frontend_sha):
    """创建固定真实worker入口，SDK和secret均只按已有宿主控制的私有路径使用。"""
    root = Path(REMOTE_J2); producer = dplan["host_producers"][args.release]
    argv = [REMOTE_CODE + "/run_locked_target_pip_tasks.py", "run", "--plan", REMOTE_CODE + "/target-pip-binding-plan.json",
            "--release", args.release, "--arch", args.arch, "--scope", args.scope,
            "--b-root", "/reko/j9-runtime/root", "--payload-root", str(root / "root"),
            "--workspace", "/reko/j9-workspaces/" + args.release + "/" + args.arch, "--output", REMOTE_RESULTS,
            "--b-receipt", "/reko/j9-results/" + args.release + "/" + args.arch + "/target-install-receipt.json",
            "--b-receipt-sha256", b_receipt_sha, "--sdk", "/reko/private/" + ("device_sdk" if args.arch == "arm64" else "simulator_sdk") + ".tar.gz",
            "--clang-runtime", "/reko/private/clang_runtime.tar.gz", "--host-prefix", producer["original_prefix"],
            "--host-receipt", "/reko/j9-host-exports/" + args.release + "/host-receipt.json",
            "--host-inventory", "/reko/j9-host-exports/" + args.release + "/host-distribution.json",
            "--host-receipt-sha256", producer["receipt"]["sha256"], "--host-inventory-sha256", producer["inventory"]["sha256"],
            "--frontend-report", "/reko/h0-replay/report.json", "--frontend-report-sha256", frontend_sha,
            "--source-cache", str(root / "cache"), "--tool-cache", str(root / "cache"), "--sdk-version", "14.0", "--deployment-target", "14.0"]
    for path, digest in producer_paths(pip_plan, root): argv += ["--build-receipt", str(path), "--build-receipt-sha256", digest]
    return argv


def export_argv(command, args, code, payload_root, b_products, output):
    """导出器和静态读取器共用固定四文本工具，不把导出成功当验收成功。"""
    return [str(code / "run_target_pip_export.py"), command, "--plan", str(code / "target-pip-export-plan.json"),
            "--pip-worker", str(code / "run_locked_target_pip_tasks.py"), "--pip-plan", str(code / "target-pip-binding-plan.json"),
            "--release", args.release, "--arch", args.arch, "--scope", args.scope, "--payload-root", str(payload_root),
            "--b-products", str(b_products), "--output", str(output)]


def cleanup_seed_certifi_ca(run, system_python, args, plan, diagnostics, prefix):
    """仅CP39固定scope核原seed/实际prefix后精确unlink，证明留在结果树外。"""
    if args.release != "8.3.7":
        return None
    source = next(row for row in plan["text_runtime_catalog"] if row["path"] == "run_locked_target_pip_tasks.py")
    frozen = next(row for row in plan["text_runtime_catalog"] if row["path"] == "target-pip-binding-plan.json")
    stdout, _ = run.run([system_python, "-B", "-c", CLEANUP_SEED_CERTIFI_CA, REMOTE_CODE, REMOTE_RESULTS, str(prefix),
                         args.release, args.arch, args.scope, source["sha256"], frozen["sha256"]], "j9c-cleanup-original-seed-certifi-CA")
    require(len(stdout) <= 32768, "CA精确清理证明超限")
    proof = json.loads(stdout, object_pairs_hook=unique_pairs, parse_constant=reject_nonfinite)
    require(proof["result"] == "bounded_original_seed_CA_tmp_cleanup"
            and (proof["release"], proof["arch"], proof["target_scope"]) == (args.release, args.arch, args.scope)
            and proof["worker_sha256"] == source["sha256"] and proof["plan_sha256"] == frozen["sha256"]
            and proof["tmp_empty_after"] is True and proof["unknown_members_skipped"] is False
            and proof["prefix_modified"] is False and proof["full_static_acceptance_claimed"] is False
            and isinstance(proof["removed"], list) and len(proof["removed"]) <= 1, "CA精确清理证明不完整")
    write(diagnostics / "pip-seed-certifi-CA-cleanup.json", proof)
    log("已核原seed CA临时目录；精确删除=" + str(len(proof["removed"])))
    return proof


def preserve_failure(run, system_python, plan, diagnostics):
    """失败只回收有限白名单原控制日志，不扫描SDK/工作区或回传完整目标。"""
    worker = next(row for row in plan["text_runtime_catalog"] if row["path"] == "run_target_pip_export.py")
    destination = "/reko/j9c-failure-evidence"
    run.run([system_python, "-B", "-c", PRESERVE_PIP_FAILURE, REMOTE_RESULTS, destination,
             REMOTE_CODE + "/run_target_pip_export.py", worker["sha256"], REMOTE_CODE + "/target-pip-export-plan.json", REMOTE_EXPORT], "j9c-preserve-failure-controls")
    run.host([run.docker, "cp", run.name + ":" + destination, str(diagnostics / "pip-failure-evidence")], "j9c-return-failure-controls")


def run_pip(run, d, args, dplan, plan, metadata, workspaces, merged, merged_rows, code, diagnostics, report):
    """在原C/B尚未关闭的同一个C1内实际安装、导出，再由宿主新进程完整读取。"""
    system_python = "/usr/bin/python3.10" if args.ubuntu == "22.04" else "/usr/bin/python3.12"
    pip_plan = read(code / "target-pip-binding-plan.json")
    run.run(["mkdir", "-p", REMOTE_J2, REMOTE_CODE], "j9c-directories")
    run.copy(str(merged) + "/.", REMOTE_J2, "j9c-copy-separated-J2-inputs")
    run.checksum("j9c-complete-J2-inputs", [(row["sha256"], REMOTE_J2 + "/" + row["path"]) for row in merged_rows])
    run.copy(str(code) + "/.", REMOTE_CODE, "j9c-copy-text-runtime")
    run.checksum("j9c-text-runtime", [(row["sha256"], REMOTE_CODE + "/" + row["path"]) for row in plan["text_runtime_catalog"]])
    b_products = run.output / "private-products" / args.release / args.arch
    checked(b_products / "target-install-receipt.json", read(b_products / "target-export.json")["files"]["target-install-receipt.json"])
    frontend = read(run.output / "python-replay/report.json")
    scope = next(row for row in frontend["scopes"] if row["id"] == dplan["frontend_scopes"][args.release])
    require(scope["status"] == "offline_replayed", "本轮H0前端未真实成功")
    python = scope["environment"]["prefix"] + "/bin/python"
    argv = pip_argv(args, dplan, pip_plan, identity(b_products / "target-install-receipt.json")["sha256"], report["original_replay_report_sha256"])
    report["active_stage"] = "target_pip"
    try:
        run.commands.run([run.docker, "exec", run.name, "env", "-i", "PATH=" + str(Path(python).parent) + ":/usr/sbin:/usr/bin:/sbin:/bin",
                          "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC", "PYTHONHASHSEED=0", "PYTHONDONTWRITEBYTECODE=1",
                          python, "-s", "-B", *argv], "j9c-real-original-pip-Task", timeout=5000)
        remote_b = Path("/reko/j9-private-products") / args.release / args.arch
        remote_prefix = Path("/reko/j9-workspaces") / args.release / args.arch / ("tmp/install.ios-" + args.arch)
        cleanup_seed_certifi_ca(run, system_python, args, plan, diagnostics, remote_prefix)
        command = export_argv("export", args, Path(REMOTE_CODE), Path(REMOTE_J2) / "root", remote_b, Path(REMOTE_EXPORT))
        command += ["--prefix", str(remote_prefix), "--pip-results", REMOTE_RESULTS]
        run.run([system_python, "-B", *command], "j9c-export-complete-prefix")
        stdout, _ = run.run([system_python, "-B", "-c", REMOTE_IDENTITIES, REMOTE_EXPORT], "j9c-original-export-identities")
        external = json.loads(stdout, object_pairs_hook=unique_pairs, parse_constant=reject_nonfinite)
        require(set(external) == {"target-pip-export.json", "target-pip-prefix-and-proof.tar.gz"}, "回传导出身份集合不完整")
        returned = diagnostics / "pip-products"
        run.host([run.docker, "cp", run.name + ":" + REMOTE_EXPORT, str(returned)], "j9c-return-complete-prefix")
        for name, expected in external.items(): checked(returned / name, expected)
        verification_output = diagnostics / "pip-static-verification"
        command = export_argv("verify", args, code, merged / "root", b_products, verification_output)
        command += ["--export-dir", str(returned), "--manifest-sha256", external["target-pip-export.json"]["sha256"],
                    "--archive-sha256", external["target-pip-prefix-and-proof.tar.gz"]["sha256"], "--archive-bytes", str(external["target-pip-prefix-and-proof.tar.gz"]["bytes"]),
                    "--d-wrapper", str(args.d_wrapper), "--b-root", str(metadata), "--recipe", str(workspaces / args.release / args.arch),
                    "--source-cache", str(merged / "cache"), "--tool-cache", str(merged / "cache")]
        for path, digest in producer_paths(pip_plan, merged): command += ["--build-receipt", str(path), "--build-receipt-sha256", digest]
        report["active_stage"] = "full_prefix_static_verification"
        with (diagnostics / "pip-static-verification.stdout").open("xb") as out, (diagnostics / "pip-static-verification.stderr").open("xb") as error:
            result = subprocess.run([sys.executable, "-I", "-B", *command], stdout=out, stderr=error, timeout=600)
        require(result.returncode == 0, "完整prefix/RECORD/scripts/CA/同桥pyc证明未通过")
        proof = read(verification_output / "verification-report.json")
        require(proof["target_pip_static_verified"] is True and proof["target_pip_bound"] is True and proof["returned_binary_executed_on_host"] is False
                and proof["seed_historical_raw_pyc_recomputed_on_host"] is False and proof["temporary_inputs_and_extracted_trees_removed"] is True, "静态证明缺完整覆盖或越界")
        return {"status": "target_pip_full_prefix_verified", "export": external, "proof": identity(verification_output / "verification-report.json"), "verification": proof}
    except BaseException:
        try: preserve_failure(run, system_python, plan, diagnostics)
        except Exception as error: write(diagnostics / "pip-diagnostic-failure.json", {"kind": type(error).__name__, "private_message": str(error), "target_pip_bound": False})
        raise


def parser():
    """只允许固定版本/架构/范围和强身份输入，不允许任意构建hook。"""
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    result.add_argument("--ubuntu", choices=("22.04", "24.04"), required=True)
    result.add_argument("--release", choices=("8.5.3", "8.4.1", "8.3.7", "7.8.7"), required=True)
    result.add_argument("--arch", choices=ARCHES, required=True)
    result.add_argument("--scope", required=True)
    for name in ("d-wrapper", "bundle", "h1-artifact", "runtime-addon", "pip-addon", "py2-artifact", "device-sdk", "simulator-sdk", "clang-runtime", "output"):
        result.add_argument("--" + name, type=Path, required=True)
    for name in ("h0-cipher", "h2-cipher", "recipe-addon"):
        result.add_argument("--" + name, type=Path)
    result.add_argument("--ccache", action="store_true", help="复用同一C1内原D固定ccache")
    return result


def main(argv=None):
    """仅完整真实链成功才记pip通过，失败/取消始终清理本轮解密树和C1。"""
    args = parser().parse_args(argv)
    passwords = [os.environ.pop("REKO_H0_INPUTS_PASSWORD", None), os.environ.pop("REKO_H2_INPUTS_PASSWORD", None)]
    report = {"task": "R00-02J9C-CI", "result": "failed", "ubuntu": args.ubuntu, "release": args.release, "arch": args.arch, "target_scope": args.scope,
              "target_pip_bound": False, "C_prerequisites_verified": False, "target_python_install_verified": False,
              "same_open_C1_actual_chain_verified": False, "container_closed": False, "private_inputs_removed": False,
              "full_engine_source_CI_verified": False, "production_shared_dylib_verified": False, "ios_runtime_verified": False,
              "G1_G2_Reko_verified": False, "complete_input_closure": False, "SDK_secret_read": False, "secret_sent_to_container": False,
              "seed_historical_raw_pyc_recomputed_on_host": False, "manual_device_acceptance": "deferred", "errors": [],
              "cells": [{"release": args.release, "arch": args.arch, "status": "not_run"}]}
    created = False; private = None; diagnostics = None; d = None
    try:
        for key, value in vars(args).items():
            if isinstance(value, Path): setattr(args, key, guarded(value))
        require(not args.output.exists() and args.output.parent.is_dir(), "输出必须全新且父目录存在")
        for key, value in vars(args).items():
            if isinstance(value, Path) and key != "output": require(not value.is_relative_to(args.output) and not args.output.is_relative_to(value), "输入输出路径交叉")
        args.output.mkdir(mode=0o700); created = True; diagnostics = args.output / "private-diagnostics"; diagnostics.mkdir(mode=0o700)
        plan = load_plan(args.plan); validate_selection(args, plan); report["plan_sha256"] = PLAN_SHA256
        require("pip_runtime_addon" in plan, "计划尚未绑定实际09公开运输身份，禁止执行")
        require(identity(args.pip_addon, plan["limits"]["text_addon_bytes"])["bytes"] > 0, "09文本包为空或超限")
        checked(args.runtime_addon, plan["B_runtime_addon"]); checked(args.pip_addon, plan["pip_runtime_addon"]); checked(args.py2_artifact, plan["Py2_original_artifact"])
        d = load_D(args.d_wrapper, plan); dplan = d.load_plan()
        profile = dplan["producer_profiles"][args.ubuntu]; checked(args.h1_artifact, profile["artifact"])
        if sys.platform != "linux" or platform.machine() != "x86_64" or shutil.which("docker") is None: raise InputUnavailable("需要真实Linux amd64和Docker")
        if not all(passwords): raise InputUnavailable("缺少固定H0/H2宿主运输密码")
        temporary_root = guarded(os.environ.get("RUNNER_TEMP", ""))
        require(temporary_root.is_dir() and not temporary_root.is_relative_to(args.output), "缺少独立RUNNER_TEMP")
        checkout = os.environ.get("GITHUB_WORKSPACE")
        require(not checkout or not temporary_root.is_relative_to(guarded(checkout)), "私密解包目录不能放checkout")
        h2, transport, h0, h0_plan, h1, native, inventory = d.load_helpers(dplan)
        require(identity(Path(h2.__file__))["sha256"] == plan["H2_source_sha256"], "不是原H2工具")
        args.phase = "target-install"; args.releases = [args.release]; args.arches = [args.arch]; args.h2 = h2
        d.validate_phase_selection(args, dplan)
        with tempfile.TemporaryDirectory(prefix="reko-j9c-inputs-", dir=temporary_root) as directory:
            private = Path(directory); private.chmod(0o700)
            artifact = private / "H1-artifact"; h2.extract_h1_zip(args.h1_artifact, artifact)
            selected = {args.release: d.selected_host_export(h2, h0, h1, artifact, args.release, profile, dplan["host_producers"][args.release], dplan["auditor_functions"])}
            inputs = prepare_inputs(d, h2, transport, h0, h0_plan, h1, native, inventory, args, dplan, plan, private, diagnostics, passwords)
            passwords[:] = [None, None]
            payload, metadata, rows, workspaces, proof, merged, merged_rows, j2proof, code = inputs
            report.update(fresh_runtime_contract=proof, new_J2_inputs=j2proof, original_B_root_files=len(rows), new_J2_root_is_physically_separate=True)
            container = diagnostics / "container"; container.mkdir(mode=0o700)
            namespace = argparse.Namespace(payload=payload, bundle=args.bundle, ubuntu=args.ubuntu, output=container)
            with h0.open_environment(namespace, h0_plan, report) as run:
                d.execute_cells(run, h2, h0, native, inventory, payload, h0_plan, metadata, rows, workspaces, selected, dplan, args, report)
                require(report["cells"][0]["status"] == "target_python_install_verified", "原C/B未真实通过，禁止启动pip")
                report.update(C_prerequisites_verified=True, target_python_install_verified=True)
                proof = run_pip(run, d, args, dplan, plan, metadata, workspaces, merged, merged_rows, code, diagnostics, report)
                report["cells"][0].update(pip=proof)
            require(report["container_closed"], "同一C1未关闭")
        require(not private.exists(), "本轮解密输入未回收")
        report.update(result="selected_same_C1_original_target_pip_full_prefix_verified", target_pip_bound=True, same_open_C1_actual_chain_verified=True)
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)) or (d is not None and isinstance(error, d.RunInterrupted)):
            report["result"] = "interrupted"
        else: report["result"] = "not_run" if isinstance(error, InputUnavailable) else "failed"
        report["errors"].append({"stage": report.get("active_stage", "inputs"), "kind": type(error).__name__})
        if diagnostics is not None: write(diagnostics / "private-failure.json", {"kind": type(error).__name__, "private_message": str(error)})
    finally:
        passwords[:] = [None, None]; report.pop("active_stage", None)
        report["private_inputs_removed"] = private is not None and not private.exists()
        if created:
            report["private_files"] = [{"path": p.relative_to(args.output).as_posix(), **identity(p, 512 * 1024**2)} for p in sorted(diagnostics.rglob("*")) if p.is_file()]
            report["public_artifact_whitelist"] = ["public-summary.json"]
            report["private_diagnostics_transport"] = "由根CI使用既定公证书CMS加密；不得直接公开私密目录、轮子、SDK或prefix。"
            write(args.output / "public-summary.json", report)
    log("结果=" + report["result"])
    return 0 if report["target_pip_bound"] else 130 if report["result"] == "interrupted" else 3 if report["result"] == "not_run" else 1


def cli_main(argv=None):
    """SIGTERM走既有finally保全和容器退出；外部SIGKILL仍不能保证清理完成。"""
    previous = signal.getsignal(signal.SIGTERM)
    def terminate(signum, frame):
        """取消只进入一次，避免回收过程中被同一信号重入。"""
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, terminate)
    try:
        return main(argv)
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(cli_main())
