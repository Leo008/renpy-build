#!/usr/bin/env python3
"""固定同一C1监督原C→NASM/AVIF八原Task，独立交接/资源清理与完整宿主静态读验。"""
from __future__ import annotations
import argparse,ast,struct,hashlib,json,os,platform,re,secrets,shlex,shutil,signal,stat,subprocess,sys,tarfile,tempfile,threading,time,types
from pathlib import Path,PurePosixPath
HERE=Path(__file__).absolute().parent
PLAN_SHA256="7446f064fffa951647dcd5bb0636c955f4aebfbc971181de493f8ab175a03cf2"
TASK="R00-02J11V1"
RESULT="single_tuple_actual_C_and_original_eight_NASM_AVIF_tasks_verified"
FALSE={"production_shared_provider_verified":False,"single_AVIF_provider_verified":False,"G1_verified":False,"G2_verified":False,
 "Cubism_support_verified":False,"complete_engine_source_verified":False,"ios_session_verified":False,"R00_ready":False,
 "target_python_install_verified":False,"target_pip_bound":False,"historical_C_cache_restored":False}

# 容器新进程只认证本轮C与交接，不导入原registry或生成成功marker。
BACKUP_ARTIFACTS = ("C_receipt", "C_parent_report", "C_worker_report", "H1_receipt", "H1_inventory", "H0_report", "source_delivery")
CREATE_HANDOFF = r'''import hashlib,json,pathlib,sys,types
release,arch,run_id,attempt,container_id,nonce,controller_bytes,controller_sha,consumer_sha,source_files_json=sys.argv[1:]
runtime=pathlib.Path('/reko/j11-avif-runtime/root/scripts/renpy');source=runtime/'run_locked_avif_c_tasks.py';raw=source.read_bytes()
if hashlib.sha256(raw).hexdigest()!=consumer_sha:raise ValueError('V0消费者原件不同')
m=types.ModuleType('fixed_V1_V0_handoff');m.__file__=str(source);exec(compile(raw,str(source),'exec'),m.__dict__)
plan,current,current_plan,i0,ip=m.bootstrap(runtime/'avif-c-task-plan.json',runtime);paths=m.fixed_paths(plan,release,arch)
c,cp,helpers=m.runtime_contract(plan,current,current_plan,i0,ip,paths);inventory=helpers[0]
workspace=paths['workspace'];i0.check_owned_tree(workspace,ip['limits'])
receipt=i0.decode(i0.raw_file(paths['C_receipt']));current.C_baseline_shape(workspace,receipt,arch,i0)
control=paths['control']
if set(p.name for p in control.iterdir())!={'host-C-verification.stdout'}:raise ValueError('V1交接控制根不全新')
run={'github_run_id':run_id,'attempt':int(attempt),'container_id':container_id,'nonce':nonce};wid=m.workspace_identity(workspace)
files=i0.decode(source_files_json.encode());delivery={'schema_version':1,'task':m.TASK,'run':run,'cache':str(paths['source_cache']),'files':files}
i0.write_new(paths['source_delivery'],delivery)
owner={'schema_version':1,'stage':plan['handoff_contract']['stage'],'run':run,'workspace_identity':wid,'producer':plan['producer']}
before={'schema_version':1,'run':run,'workspace_identity':wid,'entries':c.inventory_tree(workspace,inventory)}
i0.write_new(paths['producer_owner'],owner);i0.write_new(paths['protected_before'],before)
controller={'path':str(paths['controller']),'bytes':int(controller_bytes),'sha256':controller_sha}
if i0.identity(paths['controller'])!={k:controller[k] for k in ('bytes','sha256')}:raise ValueError('V1控制器原件不同')
artifacts={key:i0.identity(paths[key]) for key in plan['artifacts']}
handoff={'schema_version':1,'task':plan['handoff_contract']['task'],'stage':plan['handoff_contract']['stage'],
 'release':release,'arch':arch,'run':run,'controller':controller,'consumer':{'tool':i0.identity(source),'plan_sha256':m.PLAN_SHA256,'basis':plan['basis'],'extra_runtime':plan['extra_runtime']},
 'workspace_identity':wid,'artifacts':artifacts}
i0.write_new(control/'handoff.json',handoff)
for key in ('C_receipt','C_parent_report','C_worker_report','H1_receipt','H1_inventory','H0_report','source_delivery'):
 raw=i0.raw_file(paths[key],plan['limits']['metadata_bytes'])
 if {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}!=artifacts[key]:raise ValueError('V1小原件备份前身份改变')
 with (control/('input-proof-'+key+'.json')).open('xb') as stream:stream.write(raw)
frontend='/reko/h0-replay/'+next(r['frontend_scope'] for r in cp['routes'] if r['release']==release)+'/environment/bin/python'
if receipt['frontend']['executable']!=frontend:raise ValueError('原C前端路径不同')
print(json.dumps({'handoff':i0.identity(control/'handoff.json'),'run':run,'frontend_python':frontend}))
'''

# 新宿主进程只加载本控制器和实际56文本根，不执行任何返回程序或SDK工具。
HOST_READER = r'''import hashlib,pathlib,sys,types,json
source,source_sha,*arguments=sys.argv[1:];p=pathlib.Path(source);raw=p.read_bytes()
if hashlib.sha256(raw).hexdigest()!=source_sha:raise ValueError('V1宿主控制器身份不同')
m=types.ModuleType('fixed_V1_avif_reader');m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__)
print(json.dumps(m.verify_returned(*arguments)))
'''


def hash_returned(folder, i0, maximum=1024**3):
    """全树只接受普通文件和目录，逐原件SHA且限制逻辑字节，不保留第二棵树。"""
    returned, count, logical = [], 0, 0
    i0.guarded(folder)
    for directory, dirs, files in os.walk(folder, followlinks=False):
        for name in dirs + files:
            path=Path(directory)/name;info=path.lstat();count+=1
            require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), "V1返回树含链接/特殊类型")
            if stat.S_ISREG(info.st_mode):logical+=info.st_size
            require(count<=32768 and logical<=maximum, "V1完整返回树超界")
            if stat.S_ISREG(info.st_mode):returned.append({"path":path.relative_to(folder).as_posix(),**i0.identity(path,maximum)})
    return sorted(returned,key=lambda v:v["path"])










def verify_original_before(table, host_entries, recipe):
    """从原保护快照重算完整H1投影及全部J1原文件身份，不冒称重算清理后的树。"""
    host={}
    for item in host_entries:
        keys={"path","permissions","type"}
        if item["type"]=="file":keys|={"bytes","sha256"}
        elif item["type"]=="symlink":keys|={"target","sha256"}
        else:require(item["type"]=="directory","V1原H1库存特殊成员")
        projected={k:item[k] for k in keys};projected["path"]="tmp/host/"+item["path"]
        require(projected["path"] not in host,"V1原H1库存重复")
        host[projected["path"]]=projected
    require(host and {n:v for n,v in table.items() if n.startswith("tmp/host/") }==host,"V1完整H1与保护前快照不同")
    expected={};directories=set()
    for item in recipe["files"]:
        name=item["path"];directories.update(str(p) for p in Path(name).parents if str(p)!=".")
        observed=table.get(name,{})
        require(observed.get("sha256")==item["sha256"],"V1 J1原source SHA不同")
        if item["mode"]=="120000":
            require(observed.get("type")=="symlink" and observed.get("permissions")=="0777"
                    and identity_bytes(observed["target"].encode())=={"bytes":item["size"],"sha256":item["sha256"]},"V1 J1原链接不同")
        else:
            require(item["mode"] in ("100644","100755") and observed.get("type")=="file"
                    and observed.get("permissions")==("0755" if item["mode"]=="100755" else "0644")
                    and observed.get("bytes")==item["size"],"V1 J1原文件模式/大小不同")
        expected[name]=observed
    require(len(expected)==recipe["file_count"] and all(table.get(n,{}).get("type")=="directory" for n in directories)
            and {n for n in table if n!="tmp" and not n.startswith("tmp/")}==set(expected)|directories,"V1完整J1 source集合不同")


def verify_control(control, old_products, receipt, consumer, plan, runtime, release, arch, i0, inventory, cplan, recipe, image_plan):
    """核外部handoff/原C与H1小原件、原保护库存和真实claim清理；不假称重算已删旧树。"""
    handoff=i0.decode(i0.raw_file(control/"handoff.json"));contract=plan["handoff_contract"]
    proof=i0.identity(control/"handoff.json")
    require(receipt["handoff"]==proof and handoff["run"]==receipt["run"]
            and set(handoff)==set(contract["handoff_fields"]) and handoff["task"]==contract["task"]
            and handoff["stage"]==contract["stage"] and (handoff["release"],handoff["arch"])==(release,arch)
            and handoff["consumer"]=={"tool":i0.identity(runtime/"run_locked_avif_c_tasks.py"),"plan_sha256":consumer.PLAN_SHA256,"basis":plan["basis"],"extra_runtime":plan["extra_runtime"]}, "V1外部handoff范围或消费者身份不同")
    require(set(handoff["artifacts"])==set(plan["artifacts"]), "V1外部原件集合不同")
    backups={key:i0.decode(i0.raw_file(control/("input-proof-"+key+".json"))) for key in BACKUP_ARTIFACTS}
    for key in BACKUP_ARTIFACTS:require(i0.identity(control/("input-proof-"+key+".json"))==handoff["artifacts"][key], "V1原C/H1/H0小原件SHA不同")
    for key,name in (("export","export.json"),("prefix_archive","c-prefix.tar.gz"),("prefix_inventory","c-prefix-inventory.json"),("prefix_objects","c-archive-objects.json"),("prefix_headers","c-headers-and-sources.json")):
        require(i0.identity(old_products/name)==handoff["artifacts"][key], "V1原C完整导出和handoff不同")
    require(i0.identity(control/"host-C-verification.stdout")==handoff["artifacts"]["host_verification"], "V1原C host reader身份不同")
    old_host=i0.decode(i0.raw_file(control/"host-C-verification.stdout"))
    require(old_host==i0.decode(i0.raw_file(old_products/"product-verification.stdout"))
            and old_host["all_exported_member_bytes_and_MachO_objects_verified"] is True
            and old_host["returned_binary_executed_on_host"] is False, "V1本轮原C host reader不同")
    for key,name in (("producer_owner","producer-owner.json"),("protected_before","protected-before.json")):
        require(i0.identity(control/name)==handoff["artifacts"][key], "V1原所有权/前快照SHA不同")
    owner=i0.decode(i0.raw_file(control/"producer-owner.json"));before=i0.decode(i0.raw_file(control/"protected-before.json"))
    require(set(owner)==set(contract["owner_fields"]) and set(before)==set(contract["protected_before_fields"])
            and owner["run"]==before["run"]==handoff["run"] and owner["workspace_identity"]==before["workspace_identity"]==handoff["workspace_identity"]
            and owner["stage"]==contract["stage"] and owner["producer"]==plan["producer"], "V1原C保护库存/所有权不同")
    limits={"prefix_members":image_plan["limits"]["temporary_members"],"prefix_logical_bytes":image_plan["limits"]["temporary_logical_bytes"]}
    table=i0.inventory_table(before["entries"],limits);old=i0.decode(i0.raw_file(old_products/"c-prefix-inventory.json"))
    prefix="tmp/install.ios-"+arch+"/"
    require(all(table.get(prefix+v["path"])=={**v,"path":prefix+v["path"]} for v in old), "V1完整原C前快照与导出不同")
    h1=cplan["host_producers"][release];host=backups["H1_receipt"];host_entries=backups["H1_inventory"]
    require(handoff["artifacts"]["H1_receipt"]==h1["receipt"] and handoff["artifacts"]["H1_inventory"]==h1["inventory"]
            and host["host_bootstrap_verified"] is True and host["kernel_network_isolation_verified"] is True
            and host["release"]==release and host["prefix"]==h1["original_prefix"]
            and host["plan_sha256"]==h1["execution_plan_sha256"] and host["interpreter_sha256"]==h1["interpreter_sha256"], "V1原完整H1来源不同")
    require(isinstance(host_entries,list) and host_entries, "V1原完整H1库存缺失")
    verify_original_before(table,host_entries,recipe)
    claim=i0.decode(i0.raw_file(control/"consumer-claim.json",65536))
    require(claim["run"]==handoff["run"] and claim["workspace_identity"]==handoff["workspace_identity"] and claim["handoff"]==proof
            and claim["tool"]==handoff["consumer"]["tool"] and type(claim["parent_pid"]) is int and type(claim["worker_pid"]) is int
            and re.fullmatch("[0-9a-f]{64}",claim["ticket_sha256"]), "V1实际V0 claim不同")
    workspace=str(Path("/reko/j9-workspaces")/release/arch)
    for name in ("workspace-cleanup.json","parent-workspace-cleanup.json"):
        clean=i0.decode(i0.raw_file(Path(receipt["_folder"])/name))
        require(clean["state"]=="removed" and clean["owned_workspace"]==workspace and clean["claim_retained"] is True, "V1原V0子父finally缺清理证明")
    scratch=i0.decode(i0.raw_file(control/'scratch-owner.json',65536))
    require(scratch['run']==handoff['run'] and scratch['handoff']==proof and scratch['tool']==handoff['consumer']['tool']
            and scratch['plan_sha256']==consumer.PLAN_SHA256 and scratch['ticket_sha256']==claim['ticket_sha256']
            and scratch['parent_pid']==claim['parent_pid'] and scratch['output']['path']==str(Path('/reko/j11-avif-results')/release/arch)
            and scratch['scratch']['path']==str(Path('/reko/j11-avif-results')/release/arch/'.avif-worker-scratch'),'V1本轮scratch所有权不同')
    clean=i0.decode(i0.raw_file(Path(receipt['_folder'])/'parent-scratch-cleanup.json'))
    require(clean['state']=='removed' and clean['owned_scratch']==scratch['scratch']['path'],'V1父scratch清理证明缺失')
    require(backups['source_delivery']['run']==handoff['run'] and handoff['artifacts']['source_delivery']==i0.identity(control/'source-input-delivery.json'),'V1原source交付未绑定')
    return handoff,backups,table



def verify_returned(metadata,folder,old_products,control,release,arch,consumer_sha,source_cache):
    """独立宿主进程只读完整56及原件流核，不执行返回ELF/MachO或SDK工具。"""
    runtime=Path(metadata)/'scripts/renpy';source=runtime/'run_locked_avif_c_tasks.py';raw=bootstrap_bytes(source)
    require(identity_bytes(raw)['sha256']==consumer_sha,'V1宿主V0原件不同')
    consumer=types.ModuleType('fixed_V1_host_V0');consumer.__file__=str(source);exec(compile(raw,str(source),'exec'),consumer.__dict__)
    plan,current,cp,i0,ip=consumer.bootstrap(runtime/'avif-c-task-plan.json',runtime)
    c,cplan,helpers=i0.load_runtime(runtime,ip)
    return verify_product_documents(runtime,Path(folder),Path(old_products),Path(control),release,arch,consumer,plan,i0,c,cplan,helpers,ip,Path(source_cache))



def verify_boundaries(receipt, expected):
    """JSON往返的延期字符串按类型和值比较，布尔边界不接受整数冒充。"""
    require(all(type(receipt.get(k)) is type(v) and receipt[k]==v for k,v in expected.items()),"V1原V0边界类型/值不同")


def verify_product_documents(runtime,folder,old_products,control,release,arch,consumer,plan,i0,c,cplan,helpers,image_plan,source_cache):
    """原C后完整AVIF prefix/三ar每对象/32头/配置/NASM及原保护链静态验收。"""
    inventory,j8,native,validator,common,preflight=helpers
    for path in (folder,old_products,control,source_cache):i0.guarded(path)
    row=next(v for v in plan['routes'] if v['release']==release)
    receipt=i0.decode(i0.raw_file(folder/'avif-c-receipt.json'))
    require(receipt['task']==consumer.TASK and receipt['scope']==consumer.SCOPE and (receipt['release'],receipt['arch'])==(release,arch)
            and receipt['plan_sha256']==consumer.PLAN_SHA256 and receipt['tool']==i0.identity(runtime/'run_locked_avif_c_tasks.py')
            and receipt['avif_C_verified'] is True and receipt['temporary_workspace']=='removed','V1原V0收据范围/身份不同')
    verify_boundaries(receipt,{**consumer.FALSE,"manual_device_acceptance":"deferred"})
    require(all(receipt[k] is True for k in ('current_C_reexecuted_by_controller','historical_C_lock_used_only_for_source_eligibility','old_C_source_objects_SDK_H1_members_unchanged','NASM_exact_native_delta_verified','kernel_network_isolation_verified','all_new_archive_objects_verified','decoder_only_configuration_verified'))
            and all(receipt[k] is False for k in ('original_C_Task_run_executed_by_consumer','old_completion_markers_synthesized','ran_tasks_seeded','whole_host_tree_unchanged_claimed')),'V1原C/八Task边界不同')
    names={'inventory':'avif-prefix-inventory.json','objects':'avif-archive-objects.json','headers':'avif-installed-headers.json','commands':'avif-commands.json','NASM':'nasm-native-proof.json','configuration':'avif-configuration-proof.json','source_view':'source-input-view.json','source_downloads':'source-download-results.json'}
    sidecars={}
    for key,name in names.items():
        require(receipt[key]==i0.identity(folder/name),'V1 sidecar原字节不同：'+name);sidecars[key]=i0.decode(i0.raw_file(folder/name))
    entries=sidecars['inventory'];table=i0.inventory_table(entries,image_plan['limits']);old=i0.decode(i0.raw_file(old_products/'c-prefix-inventory.json'))
    delta=consumer.permitted_delta(entries,old,plan['target']['archives']+list(plan['target']['headers'])+plan['target']['other_files'],'V1 AVIF target')
    headers=[table[n] for n in sorted(plan['target']['headers'])]
    require(headers==sidecars['headers'] and len(headers)==32 and all({k:v[k] for k in ('bytes','sha256')}==plan['target']['headers'][v['path']] for v in headers),'V1原32安装头不同')
    archive=folder/'avif-prefix.tar.gz';require(receipt['archive']=={'path':archive.name,**i0.identity(archive),'members':len(entries),'logical_bytes':sum(v.get('bytes',0) for v in entries if v['type']=='file'),'all_members_stream_verified':True},'V1完整prefix归档身份不同')
    i0.prefix_archive(archive,entries,image_plan['limits'],inventory)
    nasm_records=verify_NASM_mapping(folder,row,arch,consumer,plan,i0,source_cache,runtime)
    objects=scan_archives(archive,entries,set(plan['target']['archives']),set(v['path'] for v in old),arch,c,i0,preflight,consumer,plan,nasm_records)
    require(objects==sidecars['objects'] and len(objects)==receipt['new_archive_count']==3 and sum(v['object_count'] for v in objects)==receipt['object_count'],'V1三库所有对象或symbols不同')
    expected_tasks=[]
    workspace=Path('/reko/j9-workspaces')/release/arch
    for spec in row['tasks']:
        suffix='.host' if spec['kind']=='host' else '.ios-'+arch
        expected_tasks.append({**{k:spec[k] for k in ('index','name','task','kind','function_sha256')},'task_name':spec['task']+'-'+spec['name']+suffix,'original_Task_run_executed':True,
                               'build':str(workspace/'tmp/build'/(spec['name']+suffix)),'install':str(workspace/('tmp/host' if spec['kind']=='host' else 'tmp/install.ios-'+arch)),'operations':len(spec['operations'])})
    require(receipt['tasks']==expected_tasks and len(expected_tasks)==8,'V1八原Task完整身份/操作不同')
    verify_commands(sidecars['commands'],row,arch,c,cplan,receipt['native_environment'])
    verify_event_journal(folder/'avif-task-events.jsonl',sidecars['commands'],i0)
    verify_configuration(folder,sidecars['configuration'],row,arch,consumer,plan,i0)
    binding=i0.decode(i0.raw_file(runtime/'source-task-binding-plan.json'));route=next(v for v in binding['routes'] if v['release']==release);recipe=j8.repository_row(binding,route)
    require(row['recipe']==route['recipe'],'V1原J1配方不同')
    handoff,backups,before=verify_control(control,old_products,{**receipt,'_folder':str(folder)},consumer,plan,runtime,release,arch,i0,inventory,cplan,recipe,image_plan)
    C=backups['C_receipt']
    require(receipt['current_C_receipt']==handoff['artifacts']['C_receipt'] and receipt['current_C_export']==handoff['artifacts']['export']
            and receipt['current_C_producer']==plan['producer'] and receipt['basis']==plan['basis'] and receipt['extra_runtime']==plan['extra_runtime']
            and receipt['frontend']==C['frontend'] and receipt['SDK_install']==C['SDK_install'],'V1实际C/H0/SDK/基础来源不同')
    verify_sources(runtime,source_cache,row,receipt,sidecars,handoff,i0)
    verify_NASM_native(folder,sidecars['NASM'],receipt,row,arch,plan,before,native,i0,runtime,cplan)
    driver=i0.decode(i0.raw_file(folder/'driver-result.json'));require(receipt['driver']==driver and driver['candidate']['passed'] is True,'V1实际driver不同')
    cpu,target=('x86_64' if arch=='sim-x86_64' else 'arm64'),(2 if arch=='arm64' else 7)
    for kind,name in (('object','candidate-driver.o'),('executable','candidate-driver')):
        raw=i0.raw_file(folder/name);require({k:driver['candidate'][kind][k] for k in ('bytes','sha256')}==identity_bytes(raw),'V1实际driver原字节不同');preflight.check_macho(raw,cpu,target,kind=='executable')
    for name in ('report.json','worker-report.json'):
        report=i0.decode(i0.raw_file(folder/name));require(report['result']=='current_C_to_original_eight_NASM_AVIF_tasks_verified' and report['errors']==[] and report['avif_C_verified'] is True and report['current_C_dependency_verified'] is True and report['temporary_workspace']=='removed','V1原V0真实父子报告不同')
    return {'release':release,'arch':arch,'all_bound_artifacts_verified':True,'all_returned_regular_files_hashed':True,'returned_files':hash_returned(folder,i0),'returned_control_files':hash_returned(control,i0),
            'new_archive_count':3,'new_object_count':sum(v['object_count'] for v in objects),'complete_target_header_count':32,'all_new_archive_objects_verified':True,
            'complete_configuration_and_API_raw_proofs_verified':True,'NASM_raw_ELF_version_and_native_delta_verified':True,'original_C_H1_source_SDK_marker_protection_bound_to_actual_V0':True,
            'deleted_workspace_raw_rehashed_after_cleanup':False,'system_ELF_dependency_raw_rehashed_on_host':False,'generated_NASM_recipes_are_execution_trace':False,'returned_binary_executed_on_host':False}


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
    print("[RKLog][RenPyNASM/AVIFCI] " + message, file=sys.stderr, flush=True)

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
    """强锁原I1D宿主基础和十五文本，V0实际7ca版本及全部pure基础不漂移。"""
    raw=bootstrap_bytes(args.plan);require(identity_bytes(raw)['sha256']==PLAN_SHA256,'V1计划SHA不同')
    plan=json.loads(raw);require(plan['task']==TASK,'V1任务不同');basis=plan['I1D_base'];source=bootstrap_bytes(args.c_controller)
    require(identity_bytes(source)==basis['source'] and identity_bytes(bootstrap_bytes(args.c_controller.parent/'linux-image-c-ci-plan.json'))==basis['plan'],'固定I1D宿主source/plan不同')
    base=types.ModuleType('fixed_V1_I1D_basis');base.__file__=str(args.c_controller);exec(compile(source,str(args.c_controller),'exec'),base.__dict__)
    ba=argparse.Namespace(**vars(args));ba.plan=args.c_controller.parent/'linux-image-c-ci-plan.json'
    bp,current,i0,ip,d,dp=base.load_fixed(ba)
    require(plan['text_runtime_catalog'][:9]==bp['text_runtime_catalog'] and len(plan['text_runtime_catalog'])==15 and plan['D']==bp['D'] and plan['C_runtime_addon']==bp['C_runtime_addon'],'V1改变原D/I1D材料')
    for row in plan['text_runtime_catalog']:
        require(Path(row['path']).name==row['path'] and i0.identity(args.text_runtime_dir/row['path'],plan['limits']['text_bytes'])=={k:row[k] for k in ('bytes','sha256')},'固定十五文本不同：'+row['path'])
    source=args.text_runtime_dir/'run_locked_avif_c_tasks.py';consumer=types.ModuleType('fixed_V1_V0_consumer');consumer.__file__=str(source)
    exec(compile(i0.raw_file(source),str(source),'exec'),consumer.__dict__)
    cp,_,current_plan,ci0,cip=consumer.bootstrap(args.text_runtime_dir/'avif-c-task-plan.json',args.text_runtime_dir)
    require(consumer.TASK=='R00-02J11V0' and cip==ip and ci0.PLAN_SHA256==i0.PLAN_SHA256,'V0实际基础不同')
    require({v['path']:{k:v[k] for k in ('bytes','sha256')} for v in plan['text_runtime_catalog'][11:]}==cp['extra_runtime'],'V0四消费文本闭包不同')
    return plan,consumer,cp,current,i0,ip,d,dp,base,bp


def consumer_runtime(args,plan,base,bp,h0,h1,i0,metadata,rows,destination):
    """原43只读；唯一physical50上加V0两文本和四消费文本，逐件验证真实56。"""
    result=base.consumer_runtime(args,bp,h0,h1,i0,metadata,rows,destination)
    require(len(result)==50 and plan['contract']['expected_consumer_members']==56,'原50/V0-56合同不同')
    wanted={'run_locked_avif_c_tasks.py','avif-c-task-plan.json','consume_source_inputs.py','source-consumption-plan.json','restore_source_git.py','source-git.lock.json'}
    require({v['path'] for v in plan['text_runtime_catalog'][9:]}==wanted,'消费新增六文本不同')
    for item in plan['text_runtime_catalog'][9:]:
        target=i0.guarded(destination/'scripts/renpy'/item['path']);raw=i0.raw_file(args.text_runtime_dir/item['path'],plan['limits']['text_bytes'])
        require(identity_bytes(raw)=={k:item[k] for k in ('bytes','sha256')},'V0复制前原件不同')
        with target.open('xb') as stream:stream.write(raw)
        result.append({'path':'scripts/renpy/'+item['path'],**identity_bytes(raw)})
    result.sort(key=lambda v:v['path']);require(len(result)==56 and len({v['path'] for v in result})==56,'实际消费成员数不同')
    h1.verify_runtime_root(h0,destination,result);h1.verify_runtime_root(h0,metadata,rows)
    return result








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
    require(path.parent == root and path.name.startswith("reko-j11-avif-inputs-")
            and owner["parent_pid"] == protocol["parent_pid"] and owner["ticket_sha256"] == base.ticket_hash(protocol)
            and owner["controller"] == i0.identity(Path(__file__).absolute()), "临时输入所有权不属于本轮")
    if path.exists():
        info = path.lstat(); require(stat.S_ISDIR(info.st_mode) and {"device": info.st_dev, "inode": info.st_ino} == owner["identity"], "临时输入根被替换")
        shutil.rmtree(path)
    return {"state": "removed", "removed": True}

def avif_handoff(args, plan, consumer, consumer_plan, i0, run, owner, runtime, rows, diagnostics, protocol, base, source_proof):
    """原C完整reader通过后，在同一live C1一次交接V0并保全全部原件后新进程读验。"""
    remote = "/reko/j11-avif-runtime/root"
    system_python = "/usr/bin/python3.10" if args.ubuntu == "22.04" else "/usr/bin/python3.12"
    run.run(["mkdir", "-p", remote, "/reko/j11-avif-controller"], "avif-directories")
    run.copy(str(runtime) + "/.", remote, "avif-copy-consumer56")
    run.checksum("avif-consumer56", [(v["sha256"], remote + "/" + v["path"]) for v in rows])
    run.copy(Path(__file__).absolute(), "/reko/j11-avif-controller/run_linux_avif_c_tasks.py", "avif-original-controller")
    paths = consumer.fixed_paths(consumer_plan, args.release, args.arch)
    run.run([system_python, "-B", "-c", base.CREATE_CONTROL_DIRECTORY, str(paths["control"])], "avif-exclusive-control")
    original = run.output / "private-products" / args.release / args.arch
    original_reader = original / "product-verification.stdout"
    require(i0.decode(i0.raw_file(original_reader))["all_exported_member_bytes_and_MachO_objects_verified"] is True, "原C完整host reader未通过")
    run.copy(original_reader, str(paths["host_verification"]), "avif-original-C-host-reader")
    copy_sources(run,args.source_cache,paths['source_cache'],source_proof['files'],system_python)
    tool = i0.identity(Path(__file__).absolute()); consumer_sha = next(v["sha256"] for v in plan["text_runtime_catalog"] if v["path"] == "run_locked_avif_c_tasks.py")
    raw, _ = run.commands.run([run.docker, "exec", run.name, system_python, "-B", "-c", CREATE_HANDOFF,
                              args.release, args.arch, args.run_id, str(args.attempt), owner["id"], protocol["nonce"], str(tool["bytes"]), tool["sha256"], consumer_sha, json.dumps(source_proof["files"],sort_keys=True)],
                             "avif-create-actual-C-handoff", timeout=300)
    handoff = i0.decode(raw); expected_run = {"github_run_id": args.run_id, "attempt": args.attempt, "container_id": owner["id"], "nonce": protocol["nonce"]}
    require(handoff["run"] == expected_run and handoff["frontend_python"] == base.frontend_python(args, plan, i0), "NASM/AVIF外部交接run/前端不符")
    proof = handoff["handoff"]
    require(type(proof["bytes"]) is int and 0 < proof["bytes"] <= consumer_plan["limits"]["handoff_bytes"] and re.fullmatch(r"[0-9a-f]{64}", proof["sha256"]), "NASM/AVIFhandoff缺外部bytes/SHA")
    argv = [handoff["frontend_python"], "-s", "-B", str(paths["consumer_runtime"] / "run_locked_avif_c_tasks.py"), "run",
            "--release", args.release, "--arch", args.arch, "--output", str(paths["output"]), "--handoff-bytes", str(proof["bytes"]), "--handoff-sha256", proof["sha256"],
            "--run-id", args.run_id, "--attempt", str(args.attempt), "--container-id", owner["id"], "--nonce", protocol["nonce"]]
    failure = None
    try:
        remaining = int(protocol["work_deadline_monotonic"] - time.monotonic())
        require(remaining > 0, "统一工作时限已耗尽，不能启动NASM/AVIF")
        run.commands.run([run.docker, "exec", run.name, "env", "-i", "PATH=" + str(Path(handoff["frontend_python"]).parent) + ":/usr/bin:/bin",
                          "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC", "PYTHONHASHSEED=0", "PYTHONDONTWRITEBYTECODE=1", *argv],
                         "avif-original-V0-consumer", timeout=min(consumer_plan["limits"]["worker_seconds"] + 300, remaining))
    except BaseException as error:
        failure = error
    finally:
        for source, destination, label in ((paths["output"], "avif-products", "avif-return"), (paths["control"], "avif-control", "avif-control-return")):
            try: base.bounded_copy(run, system_python, str(source), diagnostics / destination, label, plan, i0)
            except Exception as error:
                i0.write_new(diagnostics / (destination + "-preservation-error.json"), {"kind": type(error).__name__, "message": str(error)[:2000]})
                if failure is None: failure = error
    if failure is not None: raise failure
    folder = diagnostics / "avif-products"; control = diagnostics / "avif-control"
    observed = i0.checked(control / "handoff.json", proof)
    receipt = i0.decode(i0.raw_file(folder / "avif-c-receipt.json"))
    require(receipt["run"] == observed["run"] == expected_run and receipt["handoff"] == proof
            and observed["consumer"] == {"tool": i0.identity(args.text_runtime_dir / "run_locked_avif_c_tasks.py"), "plan_sha256": consumer.PLAN_SHA256, "basis":consumer_plan["basis"],"extra_runtime":consumer_plan["extra_runtime"]}
            and observed["controller"] == {"path": str(paths["controller"]), **tool}, "回传NASM/AVIF收据未绑定真实外部交接")
    remaining = int(protocol["work_deadline_monotonic"] - time.monotonic())
    require(remaining > 0, "统一工作时限不足宿主完整reader")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", HOST_READER, str(Path(__file__).absolute()), tool["sha256"],
                             str(runtime), str(folder), str(original), str(control), args.release, args.arch, consumer_sha,str(args.source_cache)], capture_output=True, timeout=min(600, remaining))
    (diagnostics / "avif-host-verification.stdout").write_bytes(result.stdout); (diagnostics / "avif-host-verification.stderr").write_bytes(result.stderr)
    require(result.returncode == 0 and len(result.stdout) + len(result.stderr) <= plan["limits"]["host_log_bytes"], "NASM/AVIF宿主完整reader拒绝/日志超限")
    verification = i0.decode(result.stdout)
    require(all(verification[k] is True for k in ("all_bound_artifacts_verified", "all_returned_regular_files_hashed", "all_new_archive_objects_verified", "complete_configuration_and_API_raw_proofs_verified", "original_C_H1_source_SDK_marker_protection_bound_to_actual_V0"))
            and verification["new_archive_count"] == 3 and verification["complete_target_header_count"] == 32
            and verification["returned_binary_executed_on_host"] is False, "NASM/AVIF完整reader范围不同")
    # 完整文件清单只留私有stdout，公开summary仅放计数/证明，不复制正文。
    return {"handoff": proof, "receipt": i0.identity(folder / "avif-c-receipt.json"),
            "host_verification": {k: v for k, v in verification.items() if k not in ("returned_files", "returned_control_files")}, "host_verification_stdout": i0.identity(diagnostics / "avif-host-verification.stdout"),
            "consumer_members": len(rows), "consumer_bytes": sum(v["bytes"] for v in rows)}


def execute(args, plan, consumer, consumer_plan, current, i0, ip, d, dp, base, bp, protocol, report):
    """同open_environment原D只生产真实单C；通过后统一V0，不调用旧image生命周期。"""
    diagnostics = args.output / "private-diagnostics"
    helpers = d.load_helpers(dp); h2, transport, h0, hp, h1, native, inventory = helpers
    require({g["ubuntu"]: g["image_id"] for g in hp["groups"]} == plan["C1_image_ids"], "原H0固定镜像映射不同")
    args.phase = "c-prerequisites"; args.releases = [args.release]; args.arches = [args.arch]; args.h2 = h2
    d.validate_phase_selection(args, dp)
    root = i0.guarded(Path(os.environ["RUNNER_TEMP"]))
    require(root.is_dir() and not root.is_relative_to(args.output), "独立RUNNER_TEMP无效")
    checkout = os.environ.get("GITHUB_WORKSPACE")
    require(not checkout or not root.is_relative_to(i0.guarded(Path(checkout))), "私密输入不能放checkout")
    with tempfile.TemporaryDirectory(prefix="reko-j11-avif-inputs-", dir=root) as temporary:
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
        row=next(v for v in consumer_plan['routes'] if v['release']==args.release)
        source_proof=source_contract(runtime/'scripts/renpy',args.source_cache,row,i0,allow_fetch=True)
        i0.write_new(diagnostics/'source-input-host-verification.json',source_proof)
        container = diagnostics / "container"; container.mkdir(mode=0o700)
        namespace = argparse.Namespace(payload=payload, bundle=args.bundle, ubuntu=args.ubuntu, output=container)
        stage = {"cells": [{"release": args.release, "arch": args.arch, "status": "not_run"}], "container_closed": False}
        report["producer_runtime_members"] = len(rows); report["consumer_runtime_members"] = len(combined_rows)
        try:
            with h0.open_environment(namespace, hp, stage) as run:
                raw, _ = run.host([run.docker, "inspect", run.name], "avif-controller-container-identity")
                states = i0.decode(raw); require(len(states) == 1, "实际C1 inspect数量不同")
                image_id = next(v["image_id"] for v in hp["groups"] if v["ubuntu"] == args.ubuntu)
                owner = container_owner(args, protocol, states[0], image_id, i0, base)
                d.execute_cells(run, h2, h0, native, inventory, payload, hp, metadata, rows, workspaces, selected, dp, args, stage)
                cell = stage["cells"][0]
                require(cell["status"] == "C_prerequisites_verified" and cell["product_verification"]["all_exported_member_bytes_and_MachO_objects_verified"] is True, "原C实际cell/host reader未通过，不交接NASM/AVIF")
                report["current_C_dependency_verified"] = True
                report["avif"] = avif_handoff(args, plan, consumer, consumer_plan, i0, run, owner, runtime, combined_rows, diagnostics, protocol, base, source_proof)
                report["avif_C_verified"] = True
        finally:
            report["container_closed"] = stage.get("container_closed") is True; stage.pop("active_stage", None)
            i0.write_new(diagnostics / "original-D-stage-evidence.json", {"original_D_main_executed": False, "original_D_aggregate_success_claimed": False,
                         "actual_stage_fields": stage, "fresh_runtime_contract": proof})
    require(not private.exists() and report["container_closed"], "C1/本轮解密输入未回收")
    all_files=hash_returned(diagnostics,i0,plan['limits']['sealed_aggregate_bytes'])
    require(all(v['bytes']<=plan['limits']['sealed_member_bytes'] for v in all_files) and len(all_files)<=plan['limits']['sealed_members'],'V1完整私有回收超过3GiB/单件1GiB/成员上限')
    i0.write_new(diagnostics/'private-files-before-manifest.json',{'files':all_files,'self_manifest_excluded':True,'CMS_still_required_before_upload':True})
    report.update(private_inputs_removed=True, same_open_C1_chain_verified=True, result=RESULT)


def parser():
    """只接受固定单tuple/原缓存/实际宿主基础和job截止时间，没有任意hook或下载fallback。"""
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--plan", type=Path, default=HERE / "linux-avif-c-ci-plan.json")
    result.add_argument("--ubuntu", choices=("22.04", "24.04"), required=True)
    result.add_argument("--release", choices=("8.5.3", "8.4.1", "8.3.7", "7.8.7"), required=True)
    result.add_argument("--arch", choices=("arm64", "sim-arm64", "sim-x86_64"), required=True)
    for name in ("text-runtime-dir", "c-controller", "d-wrapper", "bundle", "h1-artifact", "runtime-addon", "h0-cipher", "recipe-addon", "device-sdk", "simulator-sdk", "clang-runtime", "source-cache", "output"):
        result.add_argument("--" + name, type=Path, required=True)
    result.add_argument("--run-id", required=True); result.add_argument("--attempt", type=int, required=True)
    result.add_argument("--job-deadline-utc", type=int); result.add_argument("--ccache", action="store_true")
    result.add_argument("--worker-fd", type=int, help=argparse.SUPPRESS)
    return result

def preserve_worker_exception(args, protocol, error, report, i0):
    """仅已认证worker将原异常留私有有界JSON；不导出locals/env/SDK，也不覆盖父诊断。"""
    secrets_to_remove = sorted({v for k in ("password", "ticket") if isinstance((v := protocol.get(k)), str) and v}, key=len, reverse=True)
    def bounded(value, maximum):
        """先剔除本轮秘密及URL凭据/查询，再按UTF8字节截断。"""
        text = str(value)
        for secret in secrets_to_remove: text = text.replace(secret, "[REDACTED]")
        text = re.sub(r"(https?://)[^/@\s]+@", r"\1[REDACTED]@", text)
        text = re.sub(r"(https?://[^\s?#]+)[?#][^\s]*", r"\1?[REDACTED]", text)
        raw = text.encode("utf-8", "replace")
        return raw[:maximum].decode("utf-8", "ignore"), len(raw) > maximum
    chain, seen, current, frames_left, truncated = [], set(), error, 24, False
    while current is not None and id(current) not in seen and len(chain) < 4:
        seen.add(id(current)); message, message_clipped = bounded(current, 4096); truncated |= message_clipped
        frames = []; tb = current.__traceback__
        while tb is not None and frames_left:
            filename, cut1 = bounded(tb.tb_frame.f_code.co_filename, 512); function, cut2 = bounded(tb.tb_frame.f_code.co_name, 128)
            frames.append({"file": filename, "line": tb.tb_lineno, "function": function}); truncated |= cut1 or cut2
            tb = tb.tb_next; frames_left -= 1
        truncated |= tb is not None
        kind, clipped = bounded(type(current).__name__, 128); truncated |= clipped
        relation = "cause" if current.__cause__ is not None else "context" if not current.__suppress_context__ and current.__context__ is not None else None
        chain.append({"kind": kind, "message": message, "message_truncated": message_clipped,
                      "traceback_frames": frames, "next_relation": relation})
        current = current.__cause__ if relation == "cause" else current.__context__ if relation == "context" else None
    truncated |= current is not None
    run_id, clipped = bounded(args.run_id, 64); truncated |= clipped
    record = {"schema_version": 1, "task": TASK, "stage": "same_C1_C_avif", "run_id": run_id, "attempt": args.attempt,
              "controller": i0.identity(Path(__file__).absolute()), "plan_sha256": PLAN_SHA256,
              "authenticated_worker_branch": True, "exception_chain": chain, "truncated": truncated,
              "limits": {"JSON_bytes": 65536, "chain": 4, "total_frames": 24, "message_bytes_each": 4096},
              "traceback_source_lines_or_locals_captured": False, "environment_captured": False, "diagnostic_only": True,
              "successful_stage_flags_at_failure": {k: report[k] for k in ("current_C_dependency_verified", "avif_C_verified", "same_open_C1_chain_verified")}}
    def encoded_size():
        """按真实JSON编码核硬上限，控制字符转义也计入。"""
        return len((json.dumps(record, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8"))
    while encoded_size() > 65536:
        record["truncated"] = True
        for item in chain:
            item["message"] = item["message"][:len(item["message"]) // 2]; item["message_truncated"] = True
            for frame in item["traceback_frames"]:
                for key in ("file", "function"): frame[key] = frame[key][:len(frame[key]) // 2]
    target = i0.guarded(args.output / "private-diagnostics/worker-original-exception.json")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write((json.dumps(record, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8"))
    log("已保存本轮worker有界原异常私有原件；未导出环境/秘密/SDK")


def main(argv=None):
    """唯一父监督器控制完整链工作时限/空间/票据与精确清理，成功须父子证据齐全。"""
    args = parser().parse_args(argv); created, trusted, code, i0, protocol, docker, base = False, False, 1, None, None, None, None
    report = {"schema_version": 1, "task": TASK, "scope": "single_tuple_same_C1_actual_C_then_original_eight_NASM_AVIF_tasks", "ubuntu": args.ubuntu,
              "release": args.release, "arch": args.arch, "result": "failed", "avif_C_verified": False, "current_C_dependency_verified": False,
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
            raise NotRun("需要真实Linux amd64及Docker；未执行C/NASM/AVIF编译")
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
            require(before >= plan["limits"]["remote_entry_free_bytes"], "远端NASM/AVIF入口不足18GiB；估算不是实测峰值")
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
            require(child["result"] == RESULT and all(child[key] is True for key in ("current_C_dependency_verified", "avif_C_verified", "same_open_C1_chain_verified", "container_closed", "private_inputs_removed"))
                    and report["container_closed"] and report["private_inputs_removed"], "同C1完整链或父子清理证明不全")
            report.update({key: child[key] for key in ("result", "current_C_dependency_verified", "avif_C_verified", "same_open_C1_chain_verified", "producer_runtime_members", "consumer_runtime_members", "avif")}); code = 0
    except BaseException as error:
        report["result"] = "not_run" if isinstance(error, NotRun) else "interrupted" if isinstance(error, (Interrupted, KeyboardInterrupt)) else "failed"
        report["errors"].append({"kind": type(error).__name__, "stage": "same_C1_C_avif"})
        if i0 is not None and trusted:
            try: preserve_worker_exception(args, protocol, error, report, i0)
            except Exception:
                log("worker原异常私有保存未完成；保留首异常及原失败状态")
        if i0 is not None and created:
            i0.write_new(args.output / "private-diagnostics/private-failure.json", {"kind": type(error).__name__, "message": str(error)[:2000]})
        code = 3 if report["result"] == "not_run" else 130 if report["result"] == "interrupted" else 1
    finally:
        if protocol is not None: protocol["password"] = None; protocol["ticket"] = None
    if i0 is not None and (created or trusted):
        i0.write_new(args.output / ("private-diagnostics/worker-report.json" if args.worker_fd is not None else "public-summary.json"), report)
    log("结果=" + report["result"])
    return code



def source_contract(runtime,cache,row,i0,allow_fetch=False):
    """仅固定三个官方原包/内嵌commit/补件可取回，原source verifier全树核完再交C1。"""
    runtime=i0.guarded(Path(runtime));cache=i0.guarded(Path(cache));require(cache.is_dir(),'原source cache目录缺失')
    source=runtime/'materialize_source_inputs.py';raw=i0.raw_file(source)
    module=types.ModuleType('fixed_V1_original_source_inputs');module.__file__=str(source);exec(compile(raw,str(source),'exec'),module.__dict__)
    lock,lock_sha=module.load_lock(runtime/'remote-sources.lock.json')
    require(lock_sha=='7515fb7b12608d3911fbebcbbd4d38d9e65044bfbd2fd03a63020cd51dacbfbf','原七源锁不同')
    selected=[next(v for v in lock['sources'] if v['id']==e['source_id']) for e in row['source_consumers']]
    require([v['component'] for v in selected]==['libyuv','aom','libavif'],'固定三source范围不同')
    files={};proofs={}
    for original in selected:
        require(row['release'] in original['releases'],'source不属于当前路线')
        for descriptor in [original['archive'],original['commit_record'],*original['supplements']]:
            name=i0.relative(descriptor['path']);spec={k:descriptor[k] for k in ('bytes','sha256')}
            require(name not in files or files[name]==spec,'原source路径冲突');files[name]=spec
            if allow_fetch:module.fetch_file(cache,descriptor)
            module.check_file(cache,descriptor)
        proofs[original['id']]=module.verify_source(cache,original)
    return {'files':files,'sources':proofs,'official_locked_inputs_only':True,'network_fetch_allowed_on_host':allow_fetch,'C1_network_fallback':False}


def copy_sources(run,cache,remote,files,system_python):
    """C1内排他创建唯一缓存，逐固定普通文件复制并全SHA，不复制另一整树。"""
    script="import pathlib,sys; p=pathlib.Path(sys.argv[1]); assert p.is_absolute() and not any(v.is_symlink() for v in (p,*p.parents)); p.parent.mkdir(parents=True,exist_ok=True); p.mkdir(mode=0o700)"
    run.run([system_python,'-B','-c',script,str(remote)],'avif-exclusive-source-cache')
    for name in sorted(files):
        target=remote/name
        run.run(['mkdir','-p',str(target.parent)],'avif-source-cache-parent')
        run.copy(cache/name,str(target),'avif-source-original')
    run.checksum('avif-source-cache-full',[(files[n]['sha256'],str(remote/n)) for n in sorted(files)])


def verify_commands(commands,row,arch,c,cplan,native_proof):
    """核八原Task真实run顺序与只允许失败主build立即原fallback，完整原候选环境关联。"""
    cursor=0;workspace=Path('/reko/j9-workspaces')/row['release']/arch
    crow=next(v for v in cplan['routes'] if v['release']==row['release'])
    for spec in row['tasks']:
        suffix='.host' if spec['kind']=='host' else '.ios-'+arch;name=spec['task']+'-'+spec['name']+suffix
        build=workspace/'tmp/build'/(spec['name']+suffix);cwd=build
        for operation in spec['operations']:
            if operation[0]=='chdir':cwd=build/'nasm-2.14.02';continue
            if operation[0]!='run':continue
            require(cursor<len(commands),'V1缺原run');event=commands[cursor];cursor+=1
            require(event['task_name']==name and event['template']==operation[1] and event['cwd']==str(cwd) and event['original_serial_retry'] is False,'V1原run顺序/cwd不同')
            check_command_context(event,spec,row,arch,c,cplan,crow,native_proof)
            rc=event['returncode'];require(type(rc) is int,'V1原run缺真实整数退出码')
            if rc!=0:
                require(operation[1]==spec['primary_build_template'] and spec['fallback'] is not None and cursor<len(commands),'V1非原主build失败被当成功')
                retry=commands[cursor];cursor+=1
                require(retry['task_name']==name and retry['cwd']==str(cwd) and retry['template']==spec['fallback'] and retry['original_serial_retry'] is True and type(retry['returncode']) is int and retry['returncode']==0,'V1缺原serial fallback或失败被掩盖')
                check_command_context(retry,spec,row,arch,c,cplan,crow,native_proof)
    require(cursor==len(commands),'V1出现额外原run')


def check_command_context(event,spec,row,arch,c,cplan,crow,native_proof):
    """原native/C候选flags完整保留；配置argv及原安装/构建模板必须对应固定Task。"""
    proof=event['Context'];argv=event['argv'];template=event['template'];workspace=Path('/reko/j9-workspaces')/row['release']/arch
    require(isinstance(argv,list) and argv and all(isinstance(v,str) and '\x00' not in v for v in argv),'V1真实argv不同')
    if spec['kind']=='arch':
        original,candidate,changes=c.candidate_environment(argparse.Namespace(platform='ios',arch=arch,environ=proof['original']),crow,arch,cplan)
        require(proof=={'original':original,'candidate':candidate,'changes':changes},'V1原C候选flags变化不同')
    else:
        require(proof['original_host_prefix_not_redirected'] is True and set(proof['native_tools'])=={'CC','CXX','CPP','AR','RANLIB'},'V1 NASM原host环境不全')
        allowed={v['sha256'] for v in native_proof['native_tools'].values()}
        require(all(v['sha256'] in allowed for v in proof['native_tools'].values()),'V1 NASM native工具未资格')
        major='18' if native_proof['ubuntu']=='24.04' else '15'
        stems={'CC':'clang-','CXX':'clang++-','CPP':'clang-','AR':'llvm-ar-','RANLIB':'llvm-ranlib-'}
        tails={'CC':['-fuse-ld=lld','-Wno-unused-command-line-argument','-std=gnu17'],'CXX':['-fuse-ld=lld','-Wno-unused-command-line-argument','-std=gnu++17'],'CPP':['-fuse-ld=lld','-Wno-unused-command-line-argument','-E'],'AR':[],'RANLIB':[]}
        for key in stems:
            expected=(['ccache'] if key in ('CC','CXX','CPP') or major=='15' else [])+[stems[key]+major]+tails[key]
            require(shlex.split(proof['environment'][key])==expected,'V1 NASM完整原native flags不同：'+key)

        require(not any(token in proof['environment'].get(k,'') for k in ('CC','CXX','CPP','CFLAGS','CXXFLAGS','CPPFLAGS','LDFLAGS') for token in ('-target ','-isysroot','-miphoneos','-mios-simulator','-framework MetalANGLE')),'V1 NASM host混入iOS flags')
    if template.startswith('tar '):require(argv==['tar','xaf',str(workspace/'source/nasm-2.14.02.tar.gz')],'V1 NASM原plain tar调用不同')
    elif '{{configure}}' in template:
        require(argv[0]=='./configure' and '--prefix='+str(workspace/'tmp/host') in argv,'V1 NASM原configure prefix不同')
    elif '{{ cmake' in template or '{{cmake' in template:
        prefix=workspace/('tmp/install.ios-'+arch)
        require(argv[0]=='cmake' and '-DCMAKE_INSTALL_PREFIX='+str(prefix) in argv and argv[-1]==str(workspace/'tmp/source'/spec['name']),'V1原CMake source/prefix不同')
        for flag,wanted in {'libyuv':{'BUILD_SHARED_LIBS':'0'},'aom':{'CONFIG_AV1_ENCODER':'0','ENABLE_EXAMPLES':'0','ENABLE_TOOLS':'0','ENABLE_TESTS':'0','CONFIG_PIC':'1','CONFIG_RUNTIME_CPU_DETECT':'0'},'libavif':{'AVIF_CODEC_AOM':'1','AVIF_CODEC_AOM_ENCODE':'0','BUILD_SHARED_LIBS':'0'}}[spec['name']].items():
            require('-D'+flag+'='+wanted in argv,'V1原CMake flag不同：'+flag)
    elif template=='{{ make }}':require(len(argv)==4 and argv[:3]==['nice','make','-j'] and re.fullmatch('[1-9][0-9]*',argv[3]),'V1原nice/make不同')
    else:require(argv==shlex.split(template),'V1原build/install/fallback argv不同')


def verify_configuration(folder,proof,row,arch,consumer,plan,i0):
    """从全部实际raw cache/生成规则/宏重新核三库静态decoder-only和同prefix依赖。"""
    workspace=Path('/reko/j9-workspaces')/row['release']/arch;prefix=workspace/('tmp/install.ios-'+arch);generator=row['build_contract']['generator']
    require(len(proof['cmake'])==3 and proof['AOM_libyuv_same_prefix_verified'] is True and proof['encoder_enabled'] is False,'V1 CMake配置范围不同')
    for item,(family,wanted) in zip(proof['cmake'],plan['target']['cmake_flags'].items()):
        raw=i0.raw_file(folder/'configuration'/(family+'-CMakeCache.txt'));cache=consumer.cmake_cache(raw);target=row['build_contract']['targets'][family]
        require(item['family']==family and item['generator']==generator and item['cache']==identity_bytes(raw) and item['verified_flags']==wanted,'V1 CMake原件身份不同')
        require(cache.get('CMAKE_INSTALL_PREFIX',{}).get('value')==str(prefix) and cache.get('CMAKE_GENERATOR',{}).get('value')==generator,'V1实际generator/prefix不同')
        for name,value in wanted.items():require(cache.get(name,{}).get('value') in (('1','ON','TRUE','YES') if value else ('0','OFF','FALSE','NO')),'V1实际CMake特性不同：'+name)
        original=['build.ninja'] if generator=='Ninja' else ['Makefile']+['CMakeFiles/'+target+'.dir/'+n for n in ('build.make','flags.make','link.txt')]
        require([v['original_path'] for v in item['original_control_files']]==original,'V1原控制文件集合不同')
        raws={}
        for entry,name in zip(item['original_control_files'],original):
            dest='configuration/'+family+'-'+Path(name).name;raws[name]=i0.raw_file(folder/dest,8388608)
            require(entry=={'original_path':name,'returned_path':dest,**identity_bytes(raws[name])},'V1原控制文件SHA不同')
        definitions=raws['build.ninja'] if generator=='Ninja' else raws['CMakeFiles/'+target+'.dir/flags.make']
        if family=='aom':
            require('BUILD_SHARED_LIBS' not in cache or cache['BUILD_SHARED_LIBS']['value'] in ('0','OFF','FALSE','NO'),'V1 AOM开启shared')
            require(item['BUILD_SHARED_LIBS_cache_state']==cache.get('BUILD_SHARED_LIBS') and item['absent_cache_not_assigned_default'] is True and item['CONFIG_SHARED_required']=='0','V1 AOM absent cache资格不同')
            if generator=='Ninja':
                require(len(re.findall(r'^build libaom\.a: C(?:XX)?_STATIC_LIBRARY_LINKER[^\s]*\s',definitions.decode(),re.M))==1 and item['static_proof']=={'origin':'original_Ninja_generated_static_rule_not_execution_trace'},'V1原Ninja静态规则不同')
            else:require(item['static_proof']==consumer.make_static_link(raws['CMakeFiles/aom.dir/link.txt'],workspace/'tmp/build'/('aom.ios-'+arch),'libaom.a','15',i0),'V1旧Make静态规则不同')
        if family=='libavif':
            for key,name in [('AOM','aom'),('LIBYUV','yuv')]:
                require(cache.get(key+'_LIBRARY',{}).get('value')==str(prefix/('lib/lib'+name+'.a')) and cache.get(key+'_INCLUDE_DIR',{}).get('value')==str(prefix/'include'),'V1 AVIF依赖不是本轮prefix')
            defines=set(re.findall(r'-D([A-Za-z_][A-Za-z0-9_]*(?:=[^\s]+)?)',definitions.decode()))
            require(set(plan['target']['avif_compile_definitions'])<=defines and not set(plan['target']['avif_forbidden_definitions'])&defines,'V1 AVIF codec defines不同')
    config=i0.raw_file(folder/'configuration/aom_config.h');version=i0.raw_file(folder/'configuration/aom_version.h')
    macros=dict(re.findall(r'^#define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(\S+)\s*$',config.decode(),re.M))
    require({k:macros.get(k) for k in plan['target']['aom_config_macros']}==plan['target']['aom_config_macros'] and proof['aom_config']==identity_bytes(config) and proof['aom_version']==identity_bytes(version),'V1 AOM实际config/version raw不同')
    require('#define VERSION_STRING_NOSP "3.5.0"' in version.decode().splitlines() and '#define VERSION_STRING " 3.5.0"' in version.decode().splitlines(),'V1 AOM真实tag版本不同')


def scan_archives(archive,entries,wanted,before_names,arch,c,i0,preflight,consumer,plan,nasm_records):
    """每ar成员原字节重核，唯一无平台例外必须与AOM sim-x86本轮NASM全来源匹配。"""
    records=[];cpu,target=('x86_64' if arch=='sim-x86_64' else 'arm64'),(2 if arch=='arm64' else 7)
    with tarfile.open(archive,'r:gz') as source:
        for member in source:
            if not member.isfile() or member.name in before_names:continue
            with source.extractfile(member) as stream:
                head=stream.read(4);require(head!=b'\x7fELF' and not member.name.endswith(('.dylib','.so')),'V1 target混入hostELF/动态库')
                if member.name not in wanted:continue
                body=head+stream.read(536870913);require(len(body)==member.size<=536870912,'V1 ar成员过大/截断')
            objects=[];symbols=[]
            for name,raw in c.ar_members(body):
                require(len(raw)>=32 and raw[:4]==b'\xcf\xfa\xed\xfe','V1 ar非薄MachO64对象')
                ncmds,sizeofcmds=struct.unpack_from('<II',raw,16);position=32;tags=[]
                require(ncmds<=4096 and 32+sizeofcmds<=len(raw),'V1 MachO loadcommands超限')
                for _ in range(ncmds):
                    command,length=struct.unpack_from('<II',raw,position);require(length>=8 and position+length<=32+sizeofcmds,'V1 loadcommand截断');tags.append(command);position+=length
                require(position==32+sizeofcmds,'V1 loadcommands总长不同')
                if not any(v in (0x24,0x25,0x2F,0x30,0x32) for v in tags):
                    require(member.name=='lib/libaom.a' and arch=='sim-x86_64','V1未知无平台对象')
                    matches=[v for v in nasm_records if v['member']==name and v['object']==identity_bytes(raw)];require(len(matches)==1,'V1 NASM对象非唯一原来源')
                    info=consumer.nasm_macho_object(raw);require(info==matches[0]['MachO'],'V1 NASM完整MachO结构不同')
                    info['original_NASM_output']={k:v for k,v in matches[0].items() if k!='MachO'}
                    defined=[v['name'] for v in info['symbols'] if not v['type']&0xE0 and v['type']&1 and v['type']&0xE in (2,0xE)]
                else:
                    info=preflight.check_macho(raw,cpu,target);require(info['file_type']==1 and info['sdk'] in ([0,0,0],[14,0,0]),'V1 target对象类型/SDK不同');defined=consumer.defined_symbols(raw)
                symbols.extend(defined);objects.append({'name':name,**identity_bytes(raw),**info,'defined_external_symbols':defined})
            require(objects and set(plan['target']['required_API'][member.name])<=set(symbols),'V1缺必要decoder API')
            records.append({'path':member.name,**identity_bytes(body),'object_count':len(objects),'objects':objects,'complete_defined_symbols':sorted(set(symbols)),'required_API':plan['target']['required_API'][member.name]})
    require({v['path'] for v in records}==wanted and len(records)==len(wanted),'V1三ar完整集合不同');return sorted(records,key=lambda v:v['path'])


def verify_sources(runtime,cache,row,receipt,sidecars,handoff,i0):
    """原三个完整source tree重算与四小视图/离线download原函数证据分别绑定。"""
    actual=source_contract(runtime,cache,row,i0)
    delivery={'schema_version':1,'task':'R00-02J11V0','run':handoff['run'],'cache':'/reko/j11-avif-inputs/cache','files':actual['files']}
    require(receipt['sources']['remote_prepared']==actual['sources'] and receipt['sources']['source_delivery']==delivery,'V1实际source准备/交付不等原件')
    nasm=receipt['sources']['NASM'];spec=row['nasm_archive']
    require(nasm['archive']==spec and nasm['actual_compression']=='plain_tar' and nasm['original_tar_xaf_command_unchanged'] is True and nasm['all_member_paths_types_links_verified'] is True and 0<nasm['members']<=32768 and 0<nasm['logical_bytes']<=268435456,'V1 NASM输入格式/原SHA/成员合同不同')
    views=sidecars['source_view'];wanted={v['recipe_path']:row['modules'][v['component']] for v in row['source_consumers']}
    for entry in row['source_consumers']:
        for patch in entry['patches']:wanted['patches/'+patch['path']]={'size':patch['bytes'],'sha256':patch['sha256'],'mode':'100644'}
    require(views['scope']=='three original download module blobs and one locked patch, not a complete Git repository','V1小视图范围不同')
    require(len(views['files'])==len(wanted)==4 and len({v['path'] for v in views['files']})==4,'V1四小视图集合不同')
    workspace=Path('/reko/j9-workspaces')/row['release']/receipt['arch']
    for entry in views['files']:
        expected=wanted[entry['path']];require(entry=={'path':entry['path'],'bytes':expected['size'],'sha256':expected['sha256'],'origin':str(workspace/entry['path']),'mode':expected['mode']},'V1小视图不等原J1字节/mode')
    downloads=sidecars['source_downloads'];require([v['component'] for v in downloads]==['libyuv','aom','libavif'],'V1三download集合不同')
    for result,entry in zip(downloads,row['source_consumers']):
        for key in ('component','source_id','function','kind','recipe_sha256','function_sha256','preserved_functions','patched_git_tree'):require(result[key]==entry[key],'V1原download字段不同：'+key)
        require(result['arch']=='host' and result['python']==row['python'] and result['destination']==str(workspace/'tmp/source'/entry['component']) and result['original_function_body_executed'] is True and result['original_Task_run_executed'] is True and result['network_used'] is False and result['build_functions_executed'] is False and result['result']=='passed','V1原download未真实离线执行')
        require(result['original_task_name']=='download-'+entry['component']+'.host' and result['original_context_build']==str(workspace/'tmp/build'/(entry['component']+'.host')),'V1原download Context路径不同')
        mapping={v['template']:v['operation'] for v in entry['commands']}
        for event in result['events']:
            require(event['call'] in ('var','chdir','clean','run','patch'),'V1 download未知操作')
            if event['call']=='run':require(mapping.get(event['original_template'])==event['operation'] and event['original_command_executed'] is False and event['network_used'] is False,'V1 download网络旁路')
            if event['call']=='patch':require(event['returncode']==0 and any(event['path']==v['path'] and event['sha256']==v['sha256'] for v in entry['patches']),'V1原patch未成功')


def verify_NASM_mapping(folder,row,arch,consumer,plan,i0,source_cache,runtime):
    """仅AOM sim-x86把原Ninja/Make生成规则、原asm字节及本轮NASM输出精确对应。"""
    path=folder/'aom-nasm-objects.json'
    if arch!='sim-x86_64':require(not path.exists(),'V1非x86出现无平台NASM例外');return []
    proof=i0.decode(i0.raw_file(path));generator=row['build_contract']['generator'];records=proof['objects']
    require(proof['scope']==plan['target']['platformless_NASM_model'] and proof['each_object_iOS14_tag_verified'] is False and proof['original_generator']==generator and records,'V1 NASM窄资格范围不同')
    workspace=Path('/reko/j9-workspaces')/row['release']/arch;build=workspace/'tmp/build'/('aom.ios-'+arch);source=workspace/'tmp/source/aom';nasm=workspace/'tmp/host/bin/nasm'
    parsed=[]
    if generator=='Ninja':
        command=proof['readonly_expansion_command'];raw=i0.raw_file(folder/'configuration/aom-ninja-commands.stdout',16777216)
        require(command['argv']==['/usr/bin/ninja','-C',str(build),'-t','commands','libaom.a'] and type(command['returncode']) is int and command['returncode']==0 and raw==command['stdout'].encode('utf8'),'V1原Ninja展开raw/argv不同')
        for line in raw.decode().splitlines():
            argv=shlex.split(line)
            if argv[:3]==['cd',str(build),'&&']:argv=argv[3:]
            if argv and argv[0]==str(nasm):parsed.append((None,argv,None))
            else:require(not any(Path(v).name=='nasm' for v in argv),'V1 Ninja用了另一NASM')
    else:
        require(proof['actual_expansion_or_assembly_argv_observed'] is False,'V1旧Make规则伪称执行argv')
        names=['Makefile','CMakeFiles/aom.dir/build.make','CMakeFiles/aom.dir/flags.make','CMakeFiles/aom.dir/link.txt'];controls={n:i0.raw_file(folder/'configuration'/('aom-'+Path(n).name),8388608) for n in names}
        require(proof['generated_control_file_identity']=={n:identity_bytes(v) for n,v in controls.items()},'V1旧Make控制raw不同')
        consumer.make_static_link(controls[names[-1]],build,'libaom.a','15',i0)
        rules={};current=None;commands=[]
        for line in controls[names[1]].decode().splitlines():
            if line.startswith('\t'):
                argv=shlex.split(line[1:])
                if current is not None and any(Path(v).name=='nasm' for v in argv):commands.append((current,argv))
                continue
            if not line or line.startswith('#') or ':' not in line:current=None;continue
            current,dependencies=line.split(':',1);current=current.strip();require('..' not in Path(current).parts,'V1 Make目标上跳');rules.setdefault(current,[]).extend(shlex.split(dependencies))
        for target,argv in commands:
            if argv[:3]==['cd',str(build),'&&']:argv=argv[3:]
            require(argv and argv[0]==str(nasm),'V1 Make另一NASM工具')
            parsed.append((target,argv,rules.get(target,[])))
    require(len(parsed)==len(records) and len({v['member'] for v in records})==len(records) and len({v['object_path'] for v in records})==len(records),'V1 NASM规则/产物数量或唯一性不同')
    needed={}
    for record,(rule,argv,dependencies) in zip(records,parsed):
        require(record['argv']==argv and record['cwd']==str(build) and record['actual_assembly_argv_observed'] is False,'V1 NASM生成规则或执行边界不同')
        require(argv[0]==str(nasm) and argv.count('-o')==argv.count('-f')==1 and argv[argv.index('-f')+1]=='macho64' and not any(v in ('&&',';','|') for v in argv),'V1 NASM flags旁路')
        output=Path(argv[argv.index('-o')+1]);src=Path(argv[-1]);require('..' not in output.parts and '..' not in src.parts and output.is_relative_to(build/'asm_objects') and src.is_relative_to(source) and src.suffix=='.asm' and output.name==src.name+'.o','V1 NASM输出/源码边界不同')
        require(record['object_path']==str(output) and record['source_path']==str(src) and record['member']==output.name and record['NASM']==i0.identity(folder/'native/nasm'),'V1 NASM实际工具/对象关联不同')
        if generator=='Ninja':require(record['origin']=='original_Ninja_expanded_generated_command_not_execution_trace','V1 Ninja来源标签不同')
        else:
            relative=output.relative_to(build).as_posix();require(rule in (relative,str(output)) and str(src) in dependencies and (relative in rules.get('libaom.a',[]) or str(output) in rules.get('libaom.a',[]))
                and record['origin']=='original_CMake_Unix_Makefiles_recipe_not_execution_trace' and record['generated_rule_target']==rule and record['generated_rule_dependencies']==dependencies,'V1旧Make NASM依赖不完整')
        name=src.relative_to(source).as_posix();require(name not in needed,'V1 NASM源码重名');needed[name]=record['source']
    lock=i0.decode(i0.raw_file(runtime/'remote-sources.lock.json'));aom=next(v for v in lock['sources'] if v['component']=='aom');found={}
    with tarfile.open(source_cache/aom['archive']['path'],'r:gz') as original:
        for member in original:
            prefix=aom['archive']['root_prefix'];name=member.name[len(prefix):] if member.name.startswith(prefix) else ''
            if name not in needed:continue
            require(member.isfile() and member.size<=1048576 and name not in found,'V1 AOM原asm类型/大小/重复不同')
            raw=original.extractfile(member).read(1048577);require(identity_bytes(raw)==needed[name],'V1 AOM原asm字节不同');found[name]=True
    require(set(found)==set(needed),'V1 NASM原asm缺少');return records


def ELF_dynamic(raw,native):
    """宿主直接解析返回ELF64程序头及动态依赖，不调用ldd/readelf或执行程序。"""
    header=native.elf_identity(raw);require(header['type'] in (2,3),'V1 NASM原生程序类型不同')
    phoff=struct.unpack_from('<Q',raw,32)[0];size,count=struct.unpack_from('<HH',raw,54)
    require(size==56 and 0<count<=256 and phoff+size*count<=len(raw),'V1 ELF程序头截断/数量异常')
    loads=[];dynamic=None;interpreter=None
    for n in range(count):
        kind,flags,offset,address,physical,filesz,memsz,align=struct.unpack_from('<II6Q',raw,phoff+n*size)
        require(offset+filesz<=len(raw) and memsz>=filesz,'V1 ELF segment截断')
        if kind==1:loads.append((address,offset,filesz))
        elif kind==2:require(dynamic is None and filesz%16==0,'V1 ELF动态表重复/截断');dynamic=(offset,filesz)
        elif kind==3:
            body=raw[offset:offset+filesz];require(interpreter is None and body.endswith(b'\0') and b'\0' not in body[:-1],'V1 ELF解释器重复/截断');interpreter=body[:-1].decode()
    require(loads,'V1 ELF缺load segment');needed=[];strings=None;strsz=None
    if dynamic:
        terminated=False
        for n in range(dynamic[0],sum(dynamic),16):
            tag,value=struct.unpack_from('<qQ',raw,n)
            if tag==0:terminated=True;break
            require(tag not in (15,29),'V1 ELF含RPATH/RUNPATH')
            if tag==1:needed.append(value)
            elif tag==5:require(strings is None,'V1 ELF重复strtab');strings=value
            elif tag==10:require(strsz is None,'V1 ELF重复strsz');strsz=value
        require(terminated,'V1 ELF动态表缺结束标记')
    names=[]
    if needed:
        require(strings is not None and strsz is not None and 0<strsz<=len(raw),'V1 ELF动态字符串表缺失')
        mappings=[offset+strings-address for address,offset,filesz in loads if address<=strings and strings+strsz<=address+filesz];require(len(mappings)==1,'V1 ELF动态字符串表映射歧义')
        table=raw[mappings[0]:mappings[0]+strsz]
        for offset in needed:
            require(offset<len(table) and b'\0' in table[offset:],'V1 ELF依赖名截断');name=table[offset:].split(b'\0',1)[0].decode();require(re.fullmatch('[A-Za-z0-9_.+-]+',name),'V1 ELF依赖名越界');names.append(name)
    require(len(names)==len(set(names)) and interpreter in (None,'/lib64/ld-linux-x86-64.so.2'),'V1 ELF依赖重复/解释器未知')
    return {'header':header,'needed':names,'interpreter':interpreter}


def verify_native_graph(graph,raw,native,group,expected_root):
    """NASM根raw重算，完整系统依赖图按C0原包/版本/架构认证，明确不冒称系统raw重算。"""
    require(graph['root']==expected_root and graph['all_transitive_dependencies_qualified'] is True and graph['returned_ELF_executed_on_host'] is False,'V1原native图范围不同')
    loader=graph['ldconfig'];require(loader['argv']==['/sbin/ldconfig','-p'] and type(loader['returncode']) is int and loader['returncode']==0,'V1原ldconfig命令/退出不同')
    nodes=graph['ELF_graph'];table={v['path']:v for v in nodes};require(len(table)==len(nodes) and expected_root in table and 0<len(nodes)<=64,'V1 native图缺根/重复/超限')
    root=table[expected_root];dynamic=ELF_dynamic(raw,native)
    require({k:root[k] for k in ('bytes','sha256')}==identity_bytes(raw) and all(root[k]==v for k,v in dynamic['header'].items()),'V1 NASM原ELF字节/头不同')
    approved=native.approved_packages(group);reachable={expected_root};pending=[expected_root]
    while pending:
        path=pending.pop();node=table[path];proof=node['readelf']
        require(node['class']==64 and node['endian']=='little' and node['machine']==62 and node['type'] in (2,3),'V1 native依赖图ELF头未知')
        require(proof['argv']==['/usr/bin/readelf','-l','-d',path] and type(proof['returncode']) is int and proof['returncode']==0 and not re.search(r'\((?:RPATH|RUNPATH)\)',proof['stdout']),'V1原readelf实际命令/边界不同')
        needed=re.findall(r'Shared library: \[([^\]]+)\]',proof['stdout']);interpreters=re.findall(r'Requesting program interpreter: ([^\]]+)\]',proof['stdout'])
        deps=node['dependencies'];require([d['needed'] for d in deps if 'needed' in d]==needed and [d['interpreter'] for d in deps if 'interpreter' in d]==interpreters and len(needed)==len(set(needed)) and len(interpreters)<=1,'V1 native依赖图不等原readelf')
        if path==expected_root:require(needed==dynamic['needed'] and interpreters==([] if dynamic['interpreter'] is None else [dynamic['interpreter']]),'V1 NASM raw动态依赖不等原readelf')
        for dep in deps:
            if 'needed' in dep:
                candidates={line.split('=>',1)[1].strip() for line in loader['stdout'].splitlines() if line.strip().startswith(dep['needed']+' ') and 'x86-64' in line and '=>' in line}
                require(dep['path'] in candidates,'V1原ldconfig没有此needed路径')
            require((dep['package'],dep['architecture']) in approved and approved[(dep['package'],dep['architecture'])]==dep['version'],'V1系统ELF依赖未资格APT')
            target=dep['realpath'];require(target in table and (Path(target).is_relative_to('/usr') or Path(target).is_relative_to('/lib')) and {k:table[target][k] for k in ('bytes','sha256')}=={k:dep[k] for k in ('bytes','sha256')},'V1 native传递依赖目标/SHA不同')
            if target not in reachable:reachable.add(target);pending.append(target)
    require(reachable==set(table),'V1 native图存在未达节点')


def verify_NASM_native(folder,proof,receipt,row,arch,plan,before,native,i0,runtime,cplan):
    """完整H1旧成员保护和NASM四新文件严格delta，重核返回ELF/version/探针及native工具。"""
    host=[]
    for name,item in before.items():
        if name.startswith('tmp/host/'):host.append({**item,'path':name[len('tmp/host/'):]})
    consumer=types.ModuleType('V1_native_delta_model');source=runtime/'run_locked_avif_c_tasks.py';consumer.__file__=str(source);exec(compile(i0.raw_file(source),str(source),'exec'),consumer.__dict__)
    files=plan['NASM']['executables']+list(plan['NASM']['data']);delta=consumer.permitted_delta(proof['after'],host,files,'V1 NASM host')
    require(proof['before_members']==len(host) and proof['new_members']==list(delta.values()) and proof['old_H1_members_unchanged'] is True and proof['whole_host_tree_unchanged_claimed'] is False,'V1 NASM完整native delta不同')
    table={v['path']:v for v in proof['after']}
    for name,spec in plan['NASM']['data'].items():require({k:table[name][k] for k in ('bytes','sha256')}==spec,'V1原NASM manpage不同')
    ubuntu=receipt['native_environment']['ubuntu'];apt=i0.decode(i0.raw_file(runtime/'apt-inputs.lock.json'));group=next(v for v in apt['groups'] if v['ubuntu']==ubuntu)
    hostplan=i0.decode(i0.raw_file(runtime/'host-python-bootstrap-plan.json'));hrow=next(v for v in hostplan['routes'] if v['release']==row['release']);require(hrow['ubuntu']==ubuntu,'V1 native Ubuntu不等原路线')
    environment=i0.checked(runtime/'environment-preflight.lock.json',hostplan['locks']['environment-preflight.lock.json']);approved=next(v for v in environment['groups'] if v['ubuntu']==ubuntu)
    tools={n:v for n,v in approved['tool_identities'].items() if n.startswith(('clang-','clang++-','llvm-ar-','llvm-nm-'))}
    require(receipt['native_environment']['native_tools']==tools and receipt['native_environment']['apple_sdk_required'] is False,'V1原C0 native工具资格不同')
    require([v['installed'] for v in proof['executables']]==plan['NASM']['executables'],'V1 NASM两程序集合不同')
    workspace=Path('/reko/j9-workspaces')/row['release']/arch;prefix=workspace/'tmp/host'
    for item in proof['executables']:
        name=Path(item['installed']).name;raw=i0.raw_file(folder/'native'/name,67108864)
        require(item['raw_returned_file']==name and {k:table[item['installed']][k] for k in ('bytes','sha256')}==identity_bytes(raw) and table[item['installed']]['permissions'] in ('0755','0775'),'V1 NASM返回原字节/权限不同')
        consumer.verify_nasm_version(item['version'],name);require(item['version']['argv']==[str(prefix/item['installed']),'-v'],'V1 NASM version argv不同')
        verify_native_graph(item['ELF'],raw,native,group,str(prefix/item['installed']))
    assembly=proof['assembly'];raw=i0.raw_file(folder/'native/assembler-probe.o',1048576)
    require(assembly['source']==plan['NASM']['assembly_probe'] and assembly['object']=={**identity_bytes(raw),**native.elf_identity(raw)} and assembly['object']['type']==1,'V1 NASM实际asm探针原件不同')
    command=assembly['command'];argv=command['argv'];scratch=Path('/reko/j11-avif-results')/row['release']/arch/'.avif-worker-scratch'
    require(type(command['returncode']) is int and command['returncode']==0 and len(argv)==6 and argv[:4]==[str(prefix/'bin/nasm'),'-f','elf64','-o'] and '..' not in Path(argv[4]).parts and '..' not in Path(argv[5]).parts and Path(argv[4]).is_relative_to(scratch) and Path(argv[5]).is_relative_to(scratch) and Path(argv[4]).name=='probe.o' and Path(argv[5]).name=='probe.asm','V1 NASM probe argv不同')
    names=['Makefile','config/config.h','config.status','config.log'];require([v['path'] for v in proof['actual_build_configuration']]==names,'V1 NASM完整配置集合不同')
    for item in proof['actual_build_configuration']:require({k:item[k] for k in ('bytes','sha256')}==i0.identity(folder/'native'/item['path'].replace('/','-')),'V1 NASM实际配置原字节不同')
    text=i0.raw_file(folder/'native/Makefile',2097152).decode();require(re.findall(r'^prefix\s*=\s*(.*?)\s*$',text,re.M)==[str(prefix)],'V1 NASM真实prefix配置不同')
    events=i0.decode(i0.raw_file(folder/'avif-commands.json'));host_context=next(v['Context'] for v in events if v['task_name']=='build-nasm.host')
    cc=re.findall(r'^CC\s*=\s*(.*?)\s*$',text,re.M);require(len(cc)==1 and shlex.split(cc[0])==shlex.split(host_context['environment']['CC']),'V1 NASM实际Makefile compiler不同')
    if arch=='sim-x86_64' and row['build_contract']['generator']=='Ninja':
        evidence=i0.decode(i0.raw_file(folder/'aom-nasm-objects.json'));tool=evidence['native_ninja'];approved=native.approved_packages(group)
        require((tool['package'],tool['architecture']) in approved and approved[(tool['package'],tool['architecture'])]==tool['version'] and tool['path']=='/usr/bin/ninja','V1原Ninja native包资格不同')


def verify_event_journal(path,commands,i0):
    """开始/退出原JSONL逐事件重核，不把失败主命令覆盖成成功或遗漏raw。"""
    raw=i0.raw_file(path,33554432);lines=raw.splitlines();require(len(lines)==2*len(commands),'V1原Task JSONL事件数量不同')
    for n,event in enumerate(commands):
        start={k:v for k,v in event.items() if k not in ('exception_type','interrupted')};start['returncode']=None
        require(i0.decode(lines[2*n])=={'phase':'start',**start} and i0.decode(lines[2*n+1])=={'phase':'exit',**event},'V1真实Task JSONL与原命令不同')

if __name__ == "__main__":
    def interrupted(signum, frame):
        """外部SIGTERM进入本V1统一finally，保留失败并精确清理C1。"""
        raise Interrupted("收到SIGTERM")
    signal.signal(signal.SIGTERM,interrupted)
    raise SystemExit(main())
