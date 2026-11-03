#!/usr/bin/env python3
"""单tuple原D生产真实C，在同一C1内一次交接current image消费者，私有结果完整验真。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import types

HERE = Path(__file__).absolute().parent
PLAN_SHA256 = "396744fccc0086b6cc54d5759828670d0a798598ade140e6786e5fc74d1a6014"
TASK = "R00-02J11I1D"
FALSE = {"production_shared_provider_verified": False, "G1_verified": False, "G2_verified": False,
         "Cubism_support_verified": False, "complete_engine_source_verified": False,
         "ios_session_verified": False, "R00_ready": False, "target_python_install_verified": False,
         "target_pip_bound": False, "historical_C_cache_restored": False}

# 容器内只记录原C真实根和外部固定身份；不生成成功marker，不导入原registry。
CREATE_HANDOFF = r'''import argparse,hashlib,json,pathlib,sys,types
release,arch,run_id,attempt,container_id,nonce,controller_bytes,controller_sha,consumer_sha=sys.argv[1:]
runtime=pathlib.Path('/reko/j11-image-runtime/root/scripts/renpy');source=runtime/'run_locked_current_image_c_tasks.py';raw=source.read_bytes()
if hashlib.sha256(raw).hexdigest()!=consumer_sha:raise ValueError('消费器原件不同')
m=types.ModuleType('fixed_current_handoff');m.__file__=str(source);exec(compile(raw,str(source),'exec'),m.__dict__)
plan,i0,ip=m.bootstrap(runtime/'current-image-c-task-plan.json',runtime);paths=m.fixed_paths(plan,release,arch)
c,cp,helpers=m.runtime_contract(plan,i0,ip,paths);inventory=helpers[0]
workspace=paths['workspace'];i0.check_owned_tree(workspace,ip['limits'])
receipt=i0.decode(i0.raw_file(paths['C_receipt']));m.C_baseline_shape(workspace,receipt,arch,i0)
control=paths['control']
if set(p.name for p in control.iterdir())!={'host-C-verification.stdout'}:raise ValueError('交接控制根不全新')
run={'github_run_id':run_id,'attempt':int(attempt),'container_id':container_id,'nonce':nonce};wid=m.workspace_identity(workspace)
owner={'schema_version':1,'stage':plan['handoff_contract']['stage'],'run':run,'workspace_identity':wid,'producer':plan['producer']}
before={'schema_version':1,'run':run,'workspace_identity':wid,'entries':c.inventory_tree(workspace,inventory)}
i0.write_new(paths['producer_owner'],owner);i0.write_new(paths['protected_before'],before)
controller={'path':str(paths['controller']),'bytes':int(controller_bytes),'sha256':controller_sha}
if i0.identity(paths['controller'])!={k:controller[k] for k in ('bytes','sha256')}:raise ValueError('控制器原件不同')
artifacts={key:i0.identity(paths[key]) for key in plan['artifacts']}
handoff={'schema_version':1,'task':plan['handoff_contract']['task'],'stage':plan['handoff_contract']['stage'],
 'release':release,'arch':arch,'run':run,'controller':controller,'consumer':{'tool':i0.identity(source),'plan_sha256':m.PLAN_SHA256,'i0':plan['i0']},
 'workspace_identity':wid,'artifacts':artifacts}
i0.write_new(control/'handoff.json',handoff)
frontend='/reko/h0-replay/'+cp['routes'][next(i for i,r in enumerate(cp['routes']) if r['release']==release)]['frontend_scope']+'/environment/bin/python'
if receipt['frontend']['executable']!=frontend:raise ValueError('原C前端路径不同')
print(json.dumps({'handoff':i0.identity(control/'handoff.json'),'run':run,'frontend_python':frontend}))
'''

# 取回之前按逻辑字节/数量拒绝稀疏文件及特殊类型；不跟随链接。
RETURN_PREFLIGHT = r'''import json,os,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]);maximum,count_limit=map(int,sys.argv[2:]);count=0;size=0
if not root.is_absolute() or '..' in root.parts or any(p.is_symlink() for p in (root,*root.parents)):raise ValueError('返回根含链接或上跳')
if not root.is_dir():raise ValueError('返回根缺失')
for folder,dirs,files in os.walk(root,followlinks=False):
 for name in dirs+files:
  p=pathlib.Path(folder)/name;s=p.lstat();count+=1
  if not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)):raise ValueError('返回树含链接或特殊类型')
  if stat.S_ISREG(s.st_mode):size+=s.st_size
  if count>count_limit or size>maximum:raise ValueError('返回树逻辑字节/成员超限')
print(json.dumps({'root':str(root),'members':count,'logical_bytes':size,'regular_and_directory_only':True}))
'''

# 新宿主进程只读完整gzip和十个新archive每个对象；不运行回传二进制或展开第二棵树。
VERIFY_IMAGE_EXPORT = r'''import ast,hashlib,json,pathlib,sys,tarfile,types
metadata,folder,old_products,release,arch,current_sha=sys.argv[1:];runtime=pathlib.Path(metadata)/'scripts/renpy';folder=pathlib.Path(folder);old_products=pathlib.Path(old_products)
p=runtime/'run_locked_current_image_c_tasks.py';raw=p.read_bytes()
if hashlib.sha256(raw).hexdigest()!=current_sha:raise ValueError('宿主消费器原件不同')
m=types.ModuleType('fixed_image_host_reader');m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__)
plan,i0,ip=m.bootstrap(runtime/'current-image-c-task-plan.json',runtime);c,cp,helpers=i0.load_runtime(runtime,ip);inventory,j8,native,validator,common,preflight=helpers
receipt=i0.decode(i0.raw_file(folder/'current-image-c-receipt.json'));row=next(r for r in ip['routes'] if r['release']==release)
if receipt['task']!=m.TASK or receipt['scope']!=m.SCOPE or (receipt['release'],receipt['arch'])!=(release,arch) or receipt['image_C_verified'] is not True:raise ValueError('image收据范围不同')
if receipt['plan_sha256']!=m.PLAN_SHA256 or receipt['tool']!=i0.identity(p) or any(receipt.get(k) is not v for k,v in m.FALSE.items()):raise ValueError('image收据源码/边界不同')
if receipt['temporary_workspace']!='removed' or receipt['all_previous_workspace_members_unchanged'] is not True or receipt['all_new_archive_objects_verified'] is not True:raise ValueError('缺前后保护/清理证明')
entries=i0.decode(i0.raw_file(folder/'image-prefix-inventory.json'));objects=i0.decode(i0.raw_file(folder/'image-archive-objects.json'));old=i0.decode(i0.raw_file(old_products/'c-prefix-inventory.json'))
table=i0.inventory_table(entries,ip['limits'])
if not all(table.get(v['path'])==v for v in old):raise ValueError('旧C完整成员改变')
for key,name in (('inventory','image-prefix-inventory.json'),('objects','image-archive-objects.json'),('headers','image-installed-headers.json'),('commands','image-commands.json')):
 if receipt[key]!=i0.identity(folder/name):raise ValueError('image sidecar身份不同')
archive=folder/'image-prefix.tar.gz'
if receipt['archive']['path']!=archive.name or {k:receipt['archive'][k] for k in ('bytes','sha256')}!=i0.identity(archive):raise ValueError('image归档身份不同')
i0.prefix_archive(archive,entries,ip['limits'],inventory)
wanted=set(ip['expected_new_archives']);cpu='x86_64' if arch=='sim-x86_64' else 'arm64';platform=2 if arch=='arm64' else 7;actual=[]
old_names={v['path'] for v in old};new=[v for v in entries if v['path'] not in old_names]
if {v['path'] for v in new if v['type']=='file' and v['path'].endswith('.a')}!=wanted:raise ValueError('新增archive集合不同')
if any(table.get(name,{}).get('type')!='file' or table[name]['bytes']<=0 for name in ip['required_new_headers']):raise ValueError('新增必需headers缺失')
if i0.decode(i0.raw_file(folder/'image-installed-headers.json'))!=[v for v in new if v['type']=='file' and v['path'].endswith('.h')]:raise ValueError('完整新增headers清单不同')
commands=i0.decode(i0.raw_file(folder/'image-commands.json'));expected_commands=[]
for spec in row['tasks']:expected_commands.extend((spec['task']+'-'+spec['name']+'.ios-'+arch,op[1]) for op in spec['operations'][arch] if op[0]=='run')
if [(v['task_name'],v['template']) for v in commands]!=expected_commands or any(type(v['returncode']) is not int or v['returncode']!=0 for v in commands):raise ValueError('完整原image命令顺序/退出码不同')
with tarfile.open(archive,'r:gz') as source:
 for member in source:
  if member.name not in wanted:continue
  body=source.extractfile(member).read();members=[]
  for name,raw in c.ar_members(body):
   info=preflight.check_macho(raw,cpu,platform)
   if info['file_type']!=1 or info['sdk'] not in ([0,0,0],[14,0,0]):raise ValueError('image对象类型/SDK错误')
   members.append({'name':name,'bytes':len(raw),'sha256':i0.sha(raw),**info})
  actual.append({'path':member.name,'bytes':len(body),'sha256':i0.sha(body),'object_count':len(members),'objects':members})
if sorted(actual,key=lambda a:a['path'])!=objects or {v['path'] for v in actual}!=wanted:raise ValueError('十archive全部对象不符')
if len(receipt['tasks'])!=8:raise ValueError('原八Task不全')
for observed,spec in zip(receipt['tasks'],row['tasks']):
 wanted_task={**{k:spec[k] for k in ('index','name','task','kind','function_sha256')},'task_name':spec['task']+'-'+spec['name']+'.ios-'+arch,'operations':len(spec['operations'][arch]),'original_Task_run_executed':True}
 if observed!=wanted_task:raise ValueError('原Task身份/完整操作不同')
if receipt['current_C_export']!=i0.identity(old_products/'export.json'):raise ValueError('本轮C导出关联不同')
print(json.dumps({'release':release,'arch':arch,'all_returned_members_verified':True,'new_archive_count':len(actual),'new_object_count':sum(v['object_count'] for v in actual),'all_new_archive_objects_verified':True,'returned_binary_executed_on_host':False}))
'''


class NotRun(ValueError):
    """真实Linux/材料未到齐时记录未运行，不能提升为成功。"""


class Interrupted(BaseException):
    """让父监督器进入进程组、C1和临时输入的finally。"""


def require(value, message):
    """所有真实边界均须有证据，不写默认成功状态。"""
    if not value:
        raise ValueError(message)


def log(message):
    """控制器只输出阶段和中文结果，密码/票据不进入日志。"""
    print("[RenPy] Linux-image-C：" + message, file=sys.stderr, flush=True)


def bootstrap_plan_bytes(path):
    """I0加载前有界读取计划，FIFO/超长/任一祖先链接均在读入前拒绝。"""
    require(path.is_absolute() and ".." not in path.parts
            and not any(p.is_symlink() for p in (path, *path.parents)), "bootstrap计划路径含链接或上跳")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= 1024**2, "bootstrap计划不是有界普通文件")
        raw = stream.read(1024**2 + 1)
    require(len(raw) == info.st_size, "bootstrap计划读取期间长度变化")
    return raw


def load_fixed(args):
    """认证已提交九件文本及原D，复用I0有界IO/监督器，不执行历史缓存功能。"""
    raw = bootstrap_plan_bytes(args.plan); require(hashlib.sha256(raw).hexdigest() == PLAN_SHA256, "I1计划SHA不同")
    plan = json.loads(raw); table = {v["path"]: v for v in plan["text_runtime_catalog"]}
    require(plan["task"] == TASK and len(table) == 9, "I1限定文本闭包不同")
    for name, row in table.items():
        path = args.text_runtime_dir / name
        require(path.is_absolute() and path.is_file() and not any(p.is_symlink() for p in (path, *path.parents))
                and path.stat().st_size == row["bytes"] <= plan["limits"]["text_bytes"], "文本原件类型/长度不同")
        data = path.read_bytes(); require(hashlib.sha256(data).hexdigest() == row["sha256"], "文本原件SHA不同：" + name)
    p = args.text_runtime_dir / "run_locked_current_image_c_tasks.py"; source = p.read_bytes()
    current = types.ModuleType("fixed_I1_current"); current.__file__ = str(p)
    exec(compile(source, str(p), "exec"), current.__dict__)
    _, i0, ip = current.bootstrap(args.text_runtime_dir / "current-image-c-task-plan.json", args.text_runtime_dir)
    for path in (args.plan, args.d_wrapper): i0.guarded(path)
    require(i0.identity(args.d_wrapper) == plan["D"]["wrapper"]
            and i0.identity(args.d_wrapper.parent / "linux-target-python-prefix-ci-plan.json") == plan["D"]["plan"], "原D source/plan不同")
    source = i0.raw_file(args.d_wrapper); d = types.ModuleType("I1_original_D"); d.__file__ = str(args.d_wrapper)
    exec(compile(source, str(args.d_wrapper), "exec"), d.__dict__)
    return plan, current, i0, ip, d, d.load_plan()


def selection(args, plan):
    """只允许对应Ubuntu组的单tuple和唯一C阶段，不暴露B/pip或任意hook。"""
    require(args.release in plan["groups"][args.ubuntu] and args.arch in ("arm64", "sim-arm64", "sim-x86_64"), "tuple/group不同")
    require(re.fullmatch(r"[1-9][0-9]*", args.run_id) and type(args.attempt) is int and args.attempt > 0, "缺真实run/attempt")
    limits = plan["limits"]
    require(sum(limits[k] for k in ("total_work_seconds", "child_shutdown_seconds", "container_cleanup_seconds", "controller_finalization_seconds", "CMS_upload_reserved_seconds")) <= limits["job_seconds"], "工作/清理/加密上传时限超出job")


def prepare_inputs(args, plan, d, dp, helpers, private, diagnostics, password):
    """复用J9C已证H0/CAS缓存准备顺序，原D建43闭包及真实单J1树。"""
    h2, transport, h0, hp, h1, native, inventory = helpers
    require(d.file_identity(args.h0_cipher) == {k: transport.TRANSPORT["ciphertext"][k] for k in ("bytes", "sha256")}, "原H0密文缓存不同")
    require(d.file_identity(args.recipe_addon) == {k: h1.ADDON[k] for k in ("bytes", "sha256")}, "原CAS缓存不同")
    plaintext, payload = private / "h0.tar.gz", private / "h0"
    transport.decrypt(args.h0_cipher, plaintext, transport.TRANSPORT, password)
    transport.extract_payload(plaintext, payload, hp["files"]); plaintext.unlink()
    h0.verify_files(payload, hp["files"]); h0.verify_original_contracts(payload, hp["files"])
    manifest = h1.read_manifest(transport, h0, args.recipe_addon, private / "recipe-manifest.json")
    with tarfile.open(args.recipe_addon, "r:gz") as archive:
        old_plan = archive.extractfile("runtime/host-python-bootstrap-plan.json").read(1024**2)
    routes, objects, catalog = h1.derive_addon(transport, h0, payload, manifest, hp, old_plan)
    addon = private / "recipe-addon"; transport.extract_payload(args.recipe_addon, addon, catalog)
    runtime = private / "C-runtime-addon"; d.extract_runtime_addon(h2, args.runtime_addon, runtime, dp["metadata_addon"])
    metadata = private / "producer/root"
    rows = d.prepare_runtime(h0, h1, payload, addon, manifest, hp, runtime, dp["metadata_addon"], metadata)
    require(len(rows) == plan["contract"]["expected_producer_members"], "原producer真实成员数不同")
    fresh = diagnostics / "fresh-runtime"; fresh.mkdir()
    proof = d.fresh_runtime_check(metadata, fresh, dp["worker"]["sha256"], "c-prerequisites")
    stager = h0.load_module(addon / "runtime/run_locked_source_tasks.py", h1.RUNTIME["run_locked_source_tasks.py"], "I1_original_J1_stager")
    workspace = private / "workspaces"; (workspace / args.release).mkdir(parents=True); cache = {}
    def get_bytes(item):
        """共享已验CAS原buffer，原J1写入仍逐blob/模式复核。"""
        sha = item["sha256"]
        if sha not in cache: cache[sha] = h1.raw_object(h0, payload, addon, sha, objects[sha])
        return cache[sha]
    h1.rebuild_workspace(stager, routes[args.release], workspace / args.release / args.arch, get_bytes)
    return payload, metadata, rows, workspace, proof


def consumer_runtime(args, plan, h0, h1, i0, metadata, rows, destination):
    """另建物理消费闭包；只在新根替换两件/新增七件，原43全树前后不写。"""
    h1.verify_runtime_root(h0, metadata, rows)
    expected = {v["path"]: dict(v) for v in rows}
    require(not destination.exists() and destination != metadata, "消费根不全新/混用producer")
    destination.mkdir(parents=True)
    for row in rows:
        source = i0.guarded(metadata / row["path"]); target = i0.guarded(destination / row["path"])
        require(i0.identity(source) == {k: row[k] for k in ("bytes", "sha256")}, "producer复制前身份不同")
        target.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as inp, target.open("xb") as out: shutil.copyfileobj(inp, out, 262144)
    for item in plan["text_runtime_catalog"]:
        relative = "scripts/renpy/" + item["path"]; target = destination / relative
        if relative in expected:
            require(item["path"] in ("run_locked_target_python_tasks.py", "target-python-prefix-plan.json"), "消费增量试图改另一原依赖")
            target.unlink()
        with (args.text_runtime_dir / item["path"]).open("rb") as inp, target.open("xb") as out: shutil.copyfileobj(inp, out, 262144)
        expected[relative] = {"path": relative, **{k: item[k] for k in ("bytes", "sha256")}}
    result = sorted(expected.values(), key=lambda v: v["path"])
    require(len(result) == plan["contract"]["expected_consumer_members"], "消费闭包真实成员数不同")
    h1.verify_runtime_root(h0, destination, result); h1.verify_runtime_root(h0, metadata, rows)
    return result


def work_budget(args, plan, now):
    """按job真实剩余时限缩短总work，清理及CMS/upload余量不能被原C/image吃掉。"""
    limits = plan["limits"]
    require(type(args.job_deadline_utc) is int and args.job_deadline_utc > now, "缺真实job绝对截止时间")
    reserve = sum(limits[key] for key in ("child_shutdown_seconds", "container_cleanup_seconds", "controller_finalization_seconds", "CMS_upload_reserved_seconds"))
    budget = min(limits["total_work_seconds"], int(args.job_deadline_utc - now) - reserve)
    require(budget > 0, "job剩余时间不足清理和CMS/upload保留量")
    return budget


def ticket_hash(protocol):
    """磁盘只留随机票据单向摘要，原票据只经父FIFO和进程内存传递。"""
    require(isinstance(protocol.get("ticket"), str) and re.fullmatch(r"[0-9a-f]{64}", protocol["ticket"]), "父票据格式错误")
    return hashlib.sha256(bytes.fromhex(protocol["ticket"])).hexdigest()


def verify_container(state, image_id):
    """真实inspect必须匹配原C0的无mount/无特权/禁网C1及固定镜像。"""
    require(isinstance(state, dict) and re.fullmatch(r"[0-9a-f]{64}", state.get("Id", ""))
            and re.fullmatch(r"/reko-preflight-[0-9a-f]{32}", state.get("Name", "")) and state["Image"] == image_id, "实际C1 id/name/image不同")
    host = state["HostConfig"]
    # 原C0的unshare显式需要SYS_ADMIN；Docker inspect实际采用CAP_规范名称。
    expected = {"NetworkMode": "none", "Privileged": False, "Binds": None, "CapAdd": ["CAP_SYS_ADMIN"],
                "CapDrop": None, "SecurityOpt": ["seccomp=unconfined"], "ReadonlyRootfs": False,
                "Devices": [], "DeviceRequests": None}
    require(all(key in host and type(host[key]) is type(value) and host[key] == value for key, value in expected.items())
            and state["Mounts"] == [] and state["Config"].get("User") == "0:0", "实际C1原C0 capability/security/user模型不同")
    return {"id": state["Id"], "name": state["Name"].removeprefix("/"), "image_id": image_id}


def container_owner(args, protocol, state, image_id, i0):
    """实际C1产生后立即把父票据和真实id绑定到私有小文件。"""
    value = {"schema_version": 1, "parent_pid": protocol["parent_pid"], "ticket_sha256": ticket_hash(protocol),
             "run_id": args.run_id, "attempt": args.attempt, "nonce": protocol["nonce"],
             "controller": i0.identity(Path(__file__).absolute()), **verify_container(state, image_id)}
    i0.write_new(args.output / "private-diagnostics/container-ownership.json", value)
    return value


def cleanup_container(args, plan, protocol, i0, docker):
    """父finally只按已证精确id删除；pre-yield失败仅接受原C0两份真实命令证据。"""
    diagnostics = args.output / "private-diagnostics"; owner_path = diagnostics / "container-ownership.json"
    if owner_path.exists():
        owner = i0.decode(i0.raw_file(owner_path, 65536))
        require(owner["schema_version"] == 1 and owner["parent_pid"] == protocol["parent_pid"]
                and owner["ticket_sha256"] == ticket_hash(protocol) and owner["nonce"] == protocol["nonce"]
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
        owner = verify_container(states[0], plan["C1_image_ids"][args.ubuntu])
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


def bounded_copy(run, system_python, source, destination, label, plan, i0):
    """cp前固定Python先lstat核逻辑字节/成员，再核分配块；超额绝不复制。"""
    limits = plan["limits"]
    raw, _ = run.commands.run([run.docker, "exec", run.name, system_python, "-B", "-c", RETURN_PREFLIGHT,
                               source, str(limits["return_logical_bytes"]), str(limits["return_members"])], label + "-preflight", timeout=60)
    proof = i0.decode(raw)
    require(proof["root"] == source and type(proof["members"]) is int and 0 <= proof["members"] <= limits["return_members"]
            and type(proof["logical_bytes"]) is int and 0 <= proof["logical_bytes"] <= limits["return_logical_bytes"]
            and proof["regular_and_directory_only"] is True, "返回预检合同不同")
    raw, _ = run.commands.run([run.docker, "exec", run.name, "du", "-sk", "--", source], label + "-allocated", timeout=60)
    require(int(raw.split()[0]) * 1024 <= limits["return_logical_bytes"], "返回树分配量超限")
    require(not destination.exists(), "返回目录不全新")
    run.commands.run([run.docker, "cp", run.name + ":" + source, str(destination)], label + "-copy", timeout=300)
    # Host不跟随链接，重核复制后全树；即使cp失败也不把partial当验真成功。
    count, logical = 0, 0
    for folder, dirs, files in os.walk(destination, followlinks=False):
        for name in dirs + files:
            info = (Path(folder) / name).lstat(); count += 1
            require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), "回传树类型不同")
            if stat.S_ISREG(info.st_mode): logical += info.st_size
    require((count, logical) == (proof["members"], proof["logical_bytes"]), "cp后逻辑字节/成员不同")
    return proof


def frontend_python(args, plan, i0):
    """从已认证原D及C同一scope派生前端，8.5沿用真实ci-success而不重放H0。"""
    Dplan = i0.checked(args.text_runtime_dir / "linux-target-python-prefix-ci-plan.json", plan["D"]["plan"])
    descriptor = next(v for v in plan["text_runtime_catalog"] if v["path"] == "target-python-prefix-plan.json")
    Cplan = i0.checked(args.text_runtime_dir / descriptor["path"], {k: descriptor[k] for k in ("bytes", "sha256")})
    scope = Dplan["frontend_scopes"][args.release]
    row = next(v for v in Cplan["routes"] if v["release"] == args.release)
    require(scope == row["frontend_scope"] == plan["frontend_scopes"][args.release], "原D/C前端scope不同")
    return "/reko/h0-replay/" + scope + "/environment/bin/python"


def image_handoff(args, plan, current, i0, run, owner, consumer, consumer_rows, diagnostics, protocol):
    """原D host reader成功后，同一live C1只交接唯一current消费者一次。"""
    remote = "/reko/j11-image-runtime/root"; system_python = "/usr/bin/python3.10" if args.ubuntu == "22.04" else "/usr/bin/python3.12"
    run.run(["mkdir", "-p", remote, "/reko/j11-controller"], "image-directories")
    run.copy(str(consumer) + "/.", remote, "image-copy-consumer")
    run.checksum("image-consumer-runtime", [(row["sha256"], remote + "/" + row["path"]) for row in consumer_rows])
    run.copy(Path(__file__).absolute(), "/reko/j11-controller/run_linux_image_c_tasks.py", "image-copy-original-controller")
    consumer_plan = i0.decode(i0.raw_file(args.text_runtime_dir / "current-image-c-task-plan.json"))
    paths = current.fixed_paths(consumer_plan, args.release, args.arch)
    run.run(["mkdir", "-m", "700", str(paths["control"])], "image-exclusive-control")
    original = run.output / "private-products" / args.release / args.arch
    host_stdout = original / "product-verification.stdout"
    require(i0.decode(i0.raw_file(host_stdout))["all_exported_member_bytes_and_MachO_objects_verified"] is True, "原host C reader尚未成功")
    run.copy(host_stdout, str(paths["host_verification"]), "image-original-host-reader")
    tool = i0.identity(Path(__file__).absolute())
    command = [run.docker, "exec", run.name, system_python, "-B", "-c", CREATE_HANDOFF, args.release, args.arch, args.run_id, str(args.attempt),
               owner["id"], protocol["nonce"], str(tool["bytes"]), tool["sha256"],
               next(v["sha256"] for v in plan["text_runtime_catalog"] if v["path"] == "run_locked_current_image_c_tasks.py")]
    raw, _ = run.commands.run(command, "image-create-actual-C-handoff", timeout=300)
    handoff = i0.decode(raw)
    require(handoff["run"] == {"github_run_id": args.run_id, "attempt": args.attempt, "container_id": owner["id"], "nonce": protocol["nonce"]}
            and handoff["frontend_python"] == frontend_python(args, plan, i0), "外部交接身份不同")
    proof = handoff["handoff"]
    require(type(proof["bytes"]) is int and 0 < proof["bytes"] <= 1024**2 and re.fullmatch(r"[0-9a-f]{64}", proof["sha256"]), "外部交接bytes/SHA错误")
    argv = [handoff["frontend_python"], "-s", "-B", str(paths["consumer_runtime"] / "run_locked_current_image_c_tasks.py"), "run",
            "--release", args.release, "--arch", args.arch, "--output", str(paths["output"]), "--handoff-bytes", str(proof["bytes"]),
            "--handoff-sha256", proof["sha256"], "--run-id", args.run_id, "--attempt", str(args.attempt), "--container-id", owner["id"], "--nonce", protocol["nonce"]]
    error = None; result = None
    try:
        remaining = int(protocol["work_deadline_monotonic"] - time.monotonic())
        require(remaining > 0, "总工作时限耗尽；不启动image")
        run.commands.run([run.docker, "exec", run.name, "env", "-i", "PATH=" + str(Path(handoff["frontend_python"]).parent) + ":/usr/bin:/bin",
                          "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC", "PYTHONHASHSEED=0", "PYTHONDONTWRITEBYTECODE=1", *argv],
                         "image-original-current-consumer", timeout=min(7500, remaining))
    except BaseException as failure:
        error = failure
    finally:
        try:
            bounded_copy(run, system_python, str(paths["output"]), diagnostics / "image-products", "image-return", plan, i0)
            bounded_copy(run, system_python, str(paths["control"]), diagnostics / "image-control", "image-control-return", plan, i0)
        except Exception as preservation_error:
            i0.write_new(diagnostics / "image-preservation-error.json", {"kind": type(preservation_error).__name__, "message": str(preservation_error)[:2000]})
            if error is None: error = preservation_error
    if error is not None: raise error
    folder = diagnostics / "image-products"
    observed_handoff = i0.checked(diagnostics / "image-control/handoff.json", proof)
    receipt = i0.decode(i0.raw_file(folder / "current-image-c-receipt.json"))
    require(receipt["run"] == handoff["run"] == observed_handoff["run"] and receipt["handoff"] == proof, "回传image关联外部handoff不同")
    raw = subprocess.run([sys.executable, "-I", "-B", "-c", VERIFY_IMAGE_EXPORT, str(consumer), str(folder), str(original), args.release, args.arch,
                          next(v["sha256"] for v in plan["text_runtime_catalog"] if v["path"] == "run_locked_current_image_c_tasks.py")], capture_output=True, timeout=300)
    (diagnostics / "image-host-verification.stdout").write_bytes(raw.stdout); (diagnostics / "image-host-verification.stderr").write_bytes(raw.stderr)
    require(raw.returncode == 0, "image回传完整归档/对象host reader拒绝")
    result = i0.decode(raw.stdout)
    require(result["all_returned_members_verified"] is True and result["all_new_archive_objects_verified"] is True
            and result["new_archive_count"] == 10 and result["returned_binary_executed_on_host"] is False, "image host reader范围错误")
    return {"handoff": proof, "receipt": i0.identity(folder / "current-image-c-receipt.json"), "host_verification": result,
            "consumer_members": len(consumer_rows), "consumer_bytes": sum(v["bytes"] for v in consumer_rows)}


def cleanup_inputs(args, protocol, i0):
    """父兜底只回收票据绑定的本轮Tempdir，不删除SDK/原ZIP/缓存/输出证据。"""
    record = args.output / "private-diagnostics/input-ownership.json"
    if not record.exists(): return {"state": "not_recorded", "removed": False}
    owner = i0.decode(i0.raw_file(record, 65536)); path = i0.guarded(Path(owner["path"]))
    root = i0.guarded(Path(os.environ["RUNNER_TEMP"]))
    require(path.parent == root and path.name.startswith("reko-j11-image-inputs-")
            and owner["parent_pid"] == protocol["parent_pid"] and owner["ticket_sha256"] == ticket_hash(protocol)
            and owner["controller"] == i0.identity(Path(__file__).absolute()), "临时输入所有权不属于本轮")
    if path.exists():
        info = path.lstat(); require(stat.S_ISDIR(info.st_mode) and {"device": info.st_dev, "inode": info.st_ino} == owner["identity"], "临时输入根被替换")
        shutil.rmtree(path)
    return {"state": "removed", "removed": True}


def execute(args, plan, current, i0, ip, d, dp, protocol, report):
    """只复用原D阶段API，不调用或改写D.main整体summary；本轮C成功后才交接。"""
    diagnostics = args.output / "private-diagnostics"
    helpers = d.load_helpers(dp); h2, transport, h0, hp, h1, native, inventory = helpers
    require({g["ubuntu"]: g["image_id"] for g in hp["groups"]} == plan["C1_image_ids"], "实际原H0镜像映射不同")
    args.phase = "c-prerequisites"; args.releases = [args.release]; args.arches = [args.arch]; args.h2 = h2
    d.validate_phase_selection(args, dp)
    root = i0.guarded(Path(os.environ["RUNNER_TEMP"]))
    require(root.is_dir() and not root.is_relative_to(args.output), "独立RUNNER_TEMP无效")
    checkout = os.environ.get("GITHUB_WORKSPACE")
    require(not checkout or not root.is_relative_to(i0.guarded(Path(checkout))), "私密输入不能放checkout")
    with tempfile.TemporaryDirectory(prefix="reko-j11-image-inputs-", dir=root) as temporary:
        private = Path(temporary); private.chmod(0o700); info = private.lstat()
        i0.write_new(diagnostics / "input-ownership.json", {"path": str(private), "identity": {"device": info.st_dev, "inode": info.st_ino},
                     "parent_pid": protocol["parent_pid"], "ticket_sha256": ticket_hash(protocol), "controller": i0.identity(Path(__file__).absolute())})
        artifact = private / "H1-artifact"; h2.extract_h1_zip(args.h1_artifact, artifact)
        profile = dp["producer_profiles"][args.ubuntu]
        selected = {args.release: d.selected_host_export(h2, h0, h1, artifact, args.release, profile, dp["host_producers"][args.release], dp["auditor_functions"])}
        payload, metadata, rows, workspaces, proof = prepare_inputs(args, plan, d, dp, helpers, private, diagnostics, protocol["password"])
        protocol["password"] = None
        consumer = private / "consumer/root"; consumer_rows = consumer_runtime(args, plan, h0, h1, i0, metadata, rows, consumer)
        i0.write_new(diagnostics / "producer-runtime-manifest.json", rows)
        i0.write_new(diagnostics / "consumer-runtime-manifest.json", consumer_rows)
        container = diagnostics / "container"; container.mkdir(mode=0o700)
        namespace = argparse.Namespace(payload=payload, bundle=args.bundle, ubuntu=args.ubuntu, output=container)
        # D只收到其真实cell状态与C0环境字段；不能把本控制器summary伪称D.main结果。
        Dstage = {"cells": [{"release": args.release, "arch": args.arch, "status": "not_run"}], "container_closed": False}
        report["producer_runtime_members"] = len(rows); report["consumer_runtime_members"] = len(consumer_rows)
        try:
            with h0.open_environment(namespace, hp, Dstage) as run:
                raw, _ = run.host([run.docker, "inspect", run.name], "image-controller-container-identity")
                states = i0.decode(raw); require(len(states) == 1, "实际C1 inspect数量不同")
                image_id = next(group["image_id"] for group in hp["groups"] if group["ubuntu"] == args.ubuntu)
                owner = container_owner(args, protocol, states[0], image_id, i0)
                d.execute_cells(run, h2, h0, native, inventory, payload, hp, metadata, rows, workspaces, selected, dp, args, Dstage)
                cell = Dstage["cells"][0]
                require(cell["status"] == "C_prerequisites_verified" and cell["product_verification"]["all_exported_member_bytes_and_MachO_objects_verified"] is True, "原C实际cell/host reader未通过，不能交接image")
                report["current_C_dependency_verified"] = True
                report["image"] = image_handoff(args, plan, current, i0, run, owner, consumer, consumer_rows, diagnostics, protocol)
                report["image_C_verified"] = True
        finally:
            report["container_closed"] = Dstage.get("container_closed") is True
            Dstage.pop("active_stage", None)
            i0.write_new(diagnostics / "original-D-stage-evidence.json", {"original_D_main_executed": False,
                         "original_D_aggregate_success_claimed": False, "actual_stage_fields": Dstage, "fresh_runtime_contract": proof})
    require(not private.exists() and report["container_closed"], "C1/本轮解密输入未回收")
    report.update(private_inputs_removed=True, same_open_C1_chain_verified=True, result="single_tuple_actual_C_and_original_image_tasks_verified")


def watch_space(output, before, limits, stop, state):
    """父进程采样新增磁盘占用；超工作预算即中断监督器并进入固定清理。"""
    state.update(samples=0, minimum_sampled_free_bytes=before, violation=None)
    while not stop.wait(limits["watch_interval_seconds"]):
        try:
            free = shutil.disk_usage(output).free
            state["samples"] += 1; state["minimum_sampled_free_bytes"] = min(free, state["minimum_sampled_free_bytes"])
            if free < limits["remote_reserve_bytes"] or before - free > limits["remote_work_delta_bytes"]:
                state["violation"] = "remote_work_or_reserve_exceeded"
                os.kill(os.getpid(), signal.SIGTERM); return
        except Exception as error:
            state["violation"] = "space_observer_failed:" + type(error).__name__
            os.kill(os.getpid(), signal.SIGTERM); return


def parser():
    """仅单tuple、固定原输入缓存、九文本和真实job截止时间；没有下载/任意hook。"""
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--plan", type=Path, default=HERE / "linux-image-c-ci-plan.json")
    result.add_argument("--ubuntu", choices=("22.04", "24.04"), required=True)
    result.add_argument("--release", choices=("8.5.3", "8.4.1", "8.3.7", "7.8.7"), required=True)
    result.add_argument("--arch", choices=("arm64", "sim-arm64", "sim-x86_64"), required=True)
    for name in ("text-runtime-dir", "d-wrapper", "bundle", "h1-artifact", "runtime-addon", "h0-cipher", "recipe-addon", "device-sdk", "simulator-sdk", "clang-runtime", "output"):
        result.add_argument("--" + name, type=Path, required=True)
    result.add_argument("--run-id", required=True); result.add_argument("--attempt", type=int, required=True)
    result.add_argument("--job-deadline-utc", type=int)
    result.add_argument("--ccache", action="store_true")
    result.add_argument("--worker-fd", type=int, help=argparse.SUPPRESS)
    return result


def main(argv=None):
    """父监督器只收经过C1关闭/私有输入回收后的真实worker成功；所有产物留私有目录。"""
    args = parser().parse_args(argv); created, worker_output_trusted, code, i0, protocol, docker = False, False, 1, None, None, None
    report = {"schema_version": 1, "task": TASK, "scope": "single_tuple_same_C1_actual_C_then_original_image_tasks", "ubuntu": args.ubuntu,
              "release": args.release, "arch": args.arch, "result": "failed", "image_C_verified": False, "current_C_dependency_verified": False,
              "same_open_C1_chain_verified": False, "container_closed": False, "private_inputs_removed": False, "errors": [],
              "manual_device_acceptance": "deferred", "public_artifact_whitelist": ["public-summary.json"], **FALSE}
    try:
        plan, current, i0, ip, d, dp = load_fixed(args); selection(args, plan)
        for key, value in vars(args).items():
            if isinstance(value, Path): setattr(args, key, i0.guarded(value))
        for key, value in vars(args).items():
            if isinstance(value, Path) and key != "output":
                require(not value.is_relative_to(args.output) and not args.output.is_relative_to(value), "输入输出路径交叉")
        diagnostics = args.output / "private-diagnostics"
        if args.worker_fd is None:
            require(not args.output.exists() and args.output.parent.is_dir(), "输出必须全新且父目录存在")
            args.output.mkdir(mode=0o700); diagnostics.mkdir(mode=0o700); created = True
        require(args.output.is_dir() and diagnostics.is_dir(), "父创建的输出目录缺失")
        if sys.platform != "linux" or platform.machine() != "x86_64" or shutil.which("docker") is None:
            raise NotRun("需要真实Linux amd64和Docker；没有执行C/image编译")
        docker = shutil.which("docker")
        if args.worker_fd is not None:
            require(stat.S_ISFIFO(os.fstat(args.worker_fd).st_mode), "worker缺父FIFO")
            with os.fdopen(args.worker_fd, "rb") as stream: protocol = i0.decode(stream.read(65537))
            require(protocol["parent_pid"] == os.getppid() and protocol["controller"] == i0.identity(Path(__file__).absolute())
                    and protocol["plan_sha256"] == PLAN_SHA256 and protocol["output"] == str(args.output)
                    and protocol["run_id"] == args.run_id and protocol["attempt"] == args.attempt
                    and re.fullmatch(r"[0-9a-f]{64}", protocol["ticket"]) and re.fullmatch(r"[0-9a-f]{64}", protocol["nonce"]), "父协议身份不同")
            worker_output_trusted = True
            execute(args, plan, current, i0, ip, d, dp, protocol, report)
            code = 0
        else:
            before = shutil.disk_usage(args.output).free
            require(before >= plan["limits"]["remote_entry_free_bytes"], "远端单tuple空间入口不足14GiB；估算不是实测峰值")
            budget = work_budget(args, plan, time.time())
            if not args.bundle.is_dir(): raise NotRun("必要原APT缓存目录未到齐")
            for key in ("h1_artifact", "runtime_addon", "h0_cipher", "recipe_addon", "device_sdk", "simulator_sdk", "clang_runtime"):
                if not getattr(args, key).is_file(): raise NotRun("必要原缓存/SDK未到齐")
            profile = dp["producer_profiles"][args.ubuntu]
            require(i0.identity(args.h1_artifact) == {k: profile["artifact"][k] for k in ("bytes", "sha256")}
                    and i0.identity(args.runtime_addon) == {k: plan["C_runtime_addon"][k] for k in ("bytes", "sha256")}, "原H1或C03输入身份不同")
            password = os.environ.pop("REKO_H0_INPUTS_PASSWORD", None)
            if not password: raise NotRun("缺原H0运输密码")
            protocol = {"parent_pid": os.getpid(), "controller": i0.identity(Path(__file__).absolute()), "plan_sha256": PLAN_SHA256,
                        "output": str(args.output), "run_id": args.run_id, "attempt": args.attempt, "ticket": secrets.token_hex(32),
                        "nonce": secrets.token_hex(32), "password": password, "work_deadline_monotonic": time.monotonic() + budget}
            password = None; stop = threading.Event(); observation = {}
            observer = threading.Thread(target=watch_space, args=(args.output, before, plan["limits"], stop, observation), daemon=True)
            supervisor = diagnostics / "supervisor"; supervisor.mkdir(); read_fd, write_fd = os.pipe(); error = None
            observer.start()
            try:
                os.write(write_fd, json.dumps(protocol).encode()); os.close(write_fd); write_fd = None
                env = {key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR", "RUNNER_TEMP", "GITHUB_WORKSPACE") if key in os.environ}
                env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONHASHSEED="0", LANG="C.UTF-8", LC_ALL="C.UTF-8", TZ="UTC")
                command = [sys.executable, "-s", "-B", str(Path(__file__).absolute()), *(argv if argv is not None else sys.argv[1:]), "--worker-fd", str(read_fd)]
                i0.bounded_child(command, env, read_fd, supervisor, plan["limits"]["host_log_bytes"], timeout=budget, owned_workspace=None)
            except BaseException as failure:
                error = failure
            finally:
                stop.set(); observer.join(timeout=3); os.close(read_fd)
                if write_fd is not None: os.close(write_fd)
                protocol["password"] = None
                observation.update(free_before_bytes=before, free_after_driver_bytes=shutil.disk_usage(args.output).free,
                                   measured_peak=False, work_timeout_seconds=budget)
                i0.write_new(diagnostics / "space-observation.json", observation)
                for name, action in (("container", lambda: cleanup_container(args, plan, protocol, i0, docker)), ("inputs", lambda: cleanup_inputs(args, protocol, i0))):
                    try:
                        cleanup = action()
                        if name == "container": report["container_closed"] = cleanup.get("container_removal_verified") is True
                        else: report["private_inputs_removed"] = cleanup.get("removed") is True
                    except Exception as failure:
                        cleanup = {"state": "cleanup_failed", "kind": type(failure).__name__, "message": str(failure)[:2000]}
                        if error is None: error = failure
                    i0.write_new(diagnostics / ("parent-" + name + "-cleanup.json"), cleanup)
            if error is not None: raise error
            require(not observation["violation"], "空间观察器触发中断")
            child = i0.decode(i0.raw_file(diagnostics / "worker-report.json"))
            require(child["result"] == "single_tuple_actual_C_and_original_image_tasks_verified"
                    and all(child[key] is True for key in ("current_C_dependency_verified", "image_C_verified", "same_open_C1_chain_verified", "container_closed", "private_inputs_removed"))
                    and report["container_closed"] and report["private_inputs_removed"], "同C1实际链/父子清理证明不全")
            report.update({key: child[key] for key in ("result", "current_C_dependency_verified", "image_C_verified", "same_open_C1_chain_verified", "producer_runtime_members", "consumer_runtime_members", "image")})
            code = 0
    except BaseException as error:
        report["result"] = "not_run" if isinstance(error, NotRun) else "interrupted" if isinstance(error, (Interrupted, KeyboardInterrupt)) else "failed"
        report["errors"].append({"kind": type(error).__name__, "stage": "same_C1_C_then_image"})
        if i0 is not None and created:
            i0.write_new(args.output / "private-diagnostics/private-failure.json", {"kind": type(error).__name__, "message": str(error)[:2000]})
        code = 3 if report["result"] == "not_run" else 130 if report["result"] == "interrupted" else 1
    finally:
        if protocol is not None: protocol["password"] = None; protocol["ticket"] = None
    if i0 is not None and (created or worker_output_trusted):
        i0.write_new(args.output / ("private-diagnostics/worker-report.json" if args.worker_fd is not None else "public-summary.json"), report)
    log("结果=" + report["result"])
    return code


if __name__ == "__main__":
    def interrupted(signum, frame):
        """超空间或外部SIGTERM进入父有界监督/精确C1清理，而非伪成功。"""
        raise Interrupted("收到SIGTERM")
    signal.signal(signal.SIGTERM, interrupted)
    raise SystemExit(main())
