#!/usr/bin/env python3
"""固定同一C1监督原C→SDL2两原Task，独立交接/资源清理与完整宿主静态读验。"""
from __future__ import annotations
import argparse,ast,hashlib,json,os,platform,re,secrets,shlex,shutil,signal,stat,subprocess,sys,tarfile,tempfile,threading,time,types
from pathlib import Path
HERE=Path(__file__).absolute().parent
PLAN_SHA256="571628b398ab39a4b02eff154c3b008f1071f151fb06b06f6637f50090b3c34c"
TASK="R00-02J11S1"
RESULT="single_tuple_actual_C_and_original_two_SDL2_static_tasks_verified"
FALSE={"production_shared_provider_verified":False,"single_SDL_provider_verified":False,"G1_verified":False,"G2_verified":False,
 "Cubism_support_verified":False,"complete_engine_source_verified":False,"ios_session_verified":False,"R00_ready":False,
 "target_python_install_verified":False,"target_pip_bound":False,"historical_C_cache_restored":False}

# 容器新进程只认证本轮C与交接，不导入原registry或生成成功marker。
BACKUP_ARTIFACTS = ("C_receipt", "C_parent_report", "C_worker_report", "H1_receipt", "H1_inventory", "H0_report")
CREATE_HANDOFF = r'''import hashlib,json,pathlib,sys,types
release,arch,run_id,attempt,container_id,nonce,controller_bytes,controller_sha,consumer_sha=sys.argv[1:]
runtime=pathlib.Path('/reko/j11-sdl2-runtime/root/scripts/renpy');source=runtime/'run_locked_sdl2_c_tasks.py';raw=source.read_bytes()
if hashlib.sha256(raw).hexdigest()!=consumer_sha:raise ValueError('S0消费者原件不同')
m=types.ModuleType('fixed_S1_S0_handoff');m.__file__=str(source);exec(compile(raw,str(source),'exec'),m.__dict__)
plan,current,i0,ip=m.bootstrap(runtime/'sdl2-c-task-plan.json',runtime);paths=m.fixed_paths(plan,release,arch)
c,cp,helpers=current.runtime_contract(plan,i0,ip,paths);inventory=helpers[0]
workspace=paths['workspace'];i0.check_owned_tree(workspace,plan['limits'])
receipt=i0.decode(i0.raw_file(paths['C_receipt']));current.C_baseline_shape(workspace,receipt,arch,i0)
control=paths['control']
if set(p.name for p in control.iterdir())!={'host-C-verification.stdout'}:raise ValueError('S1交接控制根不全新')
run={'github_run_id':run_id,'attempt':int(attempt),'container_id':container_id,'nonce':nonce};wid=m.workspace_identity(workspace)
owner={'schema_version':1,'stage':plan['handoff_contract']['stage'],'run':run,'workspace_identity':wid,'producer':plan['producer']}
before={'schema_version':1,'run':run,'workspace_identity':wid,'entries':c.inventory_tree(workspace,inventory)}
i0.write_new(paths['producer_owner'],owner);i0.write_new(paths['protected_before'],before)
controller={'path':str(paths['controller']),'bytes':int(controller_bytes),'sha256':controller_sha}
if i0.identity(paths['controller'])!={k:controller[k] for k in ('bytes','sha256')}:raise ValueError('S1控制器原件不同')
artifacts={key:i0.identity(paths[key]) for key in plan['artifacts']}
handoff={'schema_version':1,'task':plan['handoff_contract']['task'],'stage':plan['handoff_contract']['stage'],
 'release':release,'arch':arch,'run':run,'controller':controller,'consumer':{'tool':i0.identity(source),'plan_sha256':m.PLAN_SHA256,'bases':plan['bases']},
 'workspace_identity':wid,'artifacts':artifacts}
i0.write_new(control/'handoff.json',handoff)
for key in ('C_receipt','C_parent_report','C_worker_report','H1_receipt','H1_inventory','H0_report'):
 raw=i0.raw_file(paths[key],plan['limits']['metadata_bytes'])
 if {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}!=artifacts[key]:raise ValueError('S1小原件备份前身份改变')
 with (control/('input-proof-'+key+'.json')).open('xb') as stream:stream.write(raw)
frontend='/reko/h0-replay/'+next(r['frontend_scope'] for r in cp['routes'] if r['release']==release)+'/environment/bin/python'
if receipt['frontend']['executable']!=frontend:raise ValueError('原C前端路径不同')
print(json.dumps({'handoff':i0.identity(control/'handoff.json'),'run':run,'frontend_python':frontend}))
'''

# 新宿主进程只加载本控制器和已验52文本根，不执行任何返回程序或SDK工具。
HOST_READER = r'''import hashlib,pathlib,sys,types,json
source,source_sha,*arguments=sys.argv[1:];p=pathlib.Path(source);raw=p.read_bytes()
if hashlib.sha256(raw).hexdigest()!=source_sha:raise ValueError('S1宿主控制器身份不同')
m=types.ModuleType('fixed_S1_sdl2_reader');m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__)
print(json.dumps(m.verify_returned(*arguments)))
'''


def hash_returned(folder, i0, maximum=1024**3):
    """全树只接受普通文件和目录，逐原件SHA且限制逻辑字节，不保留第二棵树。"""
    returned, count, logical = [], 0, 0
    i0.guarded(folder)
    for directory, dirs, files in os.walk(folder, followlinks=False):
        for name in dirs + files:
            path=Path(directory)/name;info=path.lstat();count+=1
            require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), "S1返回树含链接/特殊类型")
            if stat.S_ISREG(info.st_mode):logical+=info.st_size
            require(count<=32768 and logical<=maximum, "S1完整返回树超界")
            if stat.S_ISREG(info.st_mode):returned.append({"path":path.relative_to(folder).as_posix(),**i0.identity(path,maximum)})
    return sorted(returned,key=lambda v:v["path"])


def verify_commands(commands, row, arch, plan, c, cplan):
    """核两原Task的全部run及真实patchdir事件、原候选环境和固定路径顺序。"""
    workspace=Path("/reko/j9-workspaces")/row["release"]/arch
    build=workspace/("tmp/build/sdl2.ios-"+arch);source=build/"SDL2-2.0.20"
    wanted=[]
    for spec in row["tasks"]:
        for op in spec["operations"][arch]:
            if op[0] in ("run","patchdir"):
                wanted.append((op[0],spec["task"]+"-sdl2.ios-"+arch,op[1]))
    observed=[(v.get("kind","run"),v["task_name"],v.get("template","SDL2-{{version}}")) for v in commands]
    require(observed==wanted, "S1两原Task命令/patchdir顺序不同")
    crow=next(v for v in cplan["routes"] if v["release"]==row["release"])
    for event,(kind,name,template) in zip(commands,wanted):
        require(type(event["returncode"]) is int and event["returncode"]==0, "S1原SDL命令真实退出码不同")
        cwd=build if kind=="run" and template.startswith("tar ") else source
        require(event["cwd"]==str(cwd), "S1原SDL命令cwd不同")
        if kind=="patchdir":
            require(set(event)=={"kind","task_name","cwd","original_argv_per_patch","patches","returncode"}
                    and event["original_argv_per_patch"]==["patch","-p1"]
                    and event["patches"]==[{"bytes":p["size"],"sha256":p["sha256"]} for p in row["patches"]], "S1原patchdir完整固定补丁不同")
            continue
        require(set(event)=={"task_name","template","argv","cwd","C_context","returncode"}, "S1原run事件字段不同")
        proof=event["C_context"]
        require(set(proof)=={"original","candidate","changes"}, "S1原C Context字段不同")
        context=argparse.Namespace(platform="ios",arch=arch,environ=proof["original"])
        original,candidate,changes=c.candidate_environment(context,crow,arch,cplan)
        require(proof=={"original":original,"candidate":candidate,"changes":changes}, "S1原C候选差异不同")
        argv=event["argv"];require(isinstance(argv,list) and argv and all(isinstance(v,str) for v in argv), "S1真实argv无效")
        if template.startswith("tar "):
            require(argv==["tar","xzf",str(workspace/"source/SDL2-2.0.20.tar.gz")], "S1原tar argv不同")
        elif template=="./autogen.sh":require(argv==["./autogen.sh"], "S1原autogen argv不同")
        elif "{{configure}}" in template:
            require("-fobjc-arc" in shlex.split(candidate["CFLAGS"]) and argv[0]=="./configure"
                    and "--disable-shared" in argv and "--disable-render-metal" in argv
                    and "--prefix="+str(workspace/("tmp/install.ios-"+arch)) in argv, "S1原configure/ARC/renderer参数不同")
        elif template=="make install":require(argv==["make","install"], "S1原install argv不同")
        else:require(template=="{{ make }}" and len(argv)==4 and argv[:3]==["nice","make","-j"]
                     and re.fullmatch(r"[1-9][0-9]*",argv[3]), "S1非原两Task nice/make命令")
    return next(v for v in commands if v.get("template","").find("{{configure}}")>=0)


def verify_configuration_api(folder, receipt, sidecars, row, arch, consumer, plan, table, i0):
    """重核配置前后真实原字节、原追加literal、实际同target预处理argv与nm日志。"""
    configure=sidecars["sdl2-configure.json"];evidence=configure["evidence"]
    require(evidence["original_config_append_verified"] is True, "S1缺原Task配置追加证明")
    command=next(v for v in sidecars["sdl2-commands.json"] if "{{configure}}" in v.get("template",""))
    require(evidence["configure"]["command"]==command and evidence["configure"]["CFLAGS_has_original_ObjC_ARC"] is True, "S1实际配置命令关联不同")
    workspace=Path("/reko/j9-workspaces")/row["release"]/arch
    source_root=workspace/("tmp/build/sdl2.ios-"+arch)/"SDL2-2.0.20"
    files=configure["files"];names=("config.log","config.status","Makefile","include/SDL_config.h","sdl2-config","sdl2.pc")
    require([v["source"] for v in files]==[str(source_root/n) for n in names], "S1完整配置文件集合不同")
    for item,name in zip(files,names):
        require(item["preserved"]=="configure-proof/"+name
                and {k:item[k] for k in ("bytes","sha256")}==i0.identity(folder/item["preserved"]), "S1实际配置原件身份不同")
    before=i0.raw_file(folder/"SDL_config-before-original-append.h",1024**2)
    after=before+plan["SDL_config_original_append"].encode()
    require(i0.raw_file(folder/"configure-proof/include/SDL_config.h",1024**2)==after
            and {k:table["include/SDL2/SDL_config.h"][k] for k in ("bytes","sha256")}==identity_bytes(after), "S1原配置追加或最终安装原字节不同")
    config_identity={"source":str(source_root/"include/SDL_config.h"),**identity_bytes(after)}
    require(i0.decode(i0.raw_file(folder/"SDL_config-after-original-append.json"))==config_identity
            and evidence["configure"]["source_header"]==config_identity["source"]
            and {k:evidence["configure"][k] for k in ("bytes","sha256")}==identity_bytes(before), "S1原before/after源header身份不同")
    api=sidecars["sdl2-API-proof.json"]
    require(api["actual_same_target_header_preprocessor_and_static_nm"] is True and api["returned_binary_executed"] is False
            and len(api["commands"])==3, "S1实际API证明范围不同")
    prefix=workspace/("tmp/install.ios-"+arch);remote=Path("/reko/j11-sdl2-results")/row["release"]/arch
    environment=command["C_context"]["candidate"]
    common=shlex.split(environment["CC"])+shlex.split(environment["CPPFLAGS"])+shlex.split(environment["CFLAGS"])+["-I",str(prefix/"include/SDL2"),"-x","objective-c","-E"]
    require(i0.raw_file(folder/"sdl2-api-probe.m",1024)==b"#include <SDL.h>\n", "S1原API探针源码不同")
    for event,kind,flags in zip(api["commands"],("macros","declarations","LLVM_nm_static_only"),(["-dM"],["-P"],None)):
        require(event["kind"]==kind and type(event["returncode"]) is int and event["returncode"]==0, "S1真实API命令退出不同")
        stem="SDL2-api-"+kind if kind!="LLVM_nm_static_only" else "SDL2-defined-API"
        for channel in ("stdout","stderr"):
            require(event[channel]==i0.identity(folder/(stem+"."+channel),plan["limits"]["api_output_bytes"]), "S1实际API日志身份不同")
        if flags is not None:
            require(event["argv"]==common+flags+[str(remote/"sdl2-api-probe.m")], "S1实际CC/CPPFLAGS/CFLAGS预处理argv不同")
        else:
            version="18" if row["release"] in ("8.5.3","8.4.1") else "15"
            require(event["argv"]==["/usr/bin/llvm-nm-"+version,"--defined-only","-g",str(prefix/"lib/libSDL2.a")], "S1实际nm argv不同")
    consumer.verify_feature_macros(i0.raw_file(folder/"SDL2-api-macros.stdout",plan["limits"]["api_output_bytes"]),plan)
    declarations=i0.raw_file(folder/"SDL2-api-declarations.stdout",plan["limits"]["api_output_bytes"]).decode()
    require(all(re.search(r"\b"+re.escape(n.lstrip("_"))+r"\s*\(",declarations) for n in plan["required_defined_API_symbols"]), "S1真实预处理缺SDL API声明")
    defined={v.split()[-1] for v in i0.raw_file(folder/"SDL2-defined-API.stdout",plan["limits"]["api_output_bytes"]).decode().splitlines() if v.split()}
    require(set(plan["required_defined_API_symbols"])<=defined, "S1真实nm缺SDL API定义")
    return {"config_before_plus_exact_original_append_equals_installed_bytes":True,"actual_CC_CPPFLAGS_CFLAGS_argv_and_raw_API_stdout_bound":True}


def verify_original_before(table, host_entries, recipe):
    """从原保护快照重算完整H1投影及全部J1原文件身份，不冒称重算清理后的树。"""
    host={}
    for item in host_entries:
        keys={"path","permissions","type"}
        if item["type"]=="file":keys|={"bytes","sha256"}
        elif item["type"]=="symlink":keys|={"target","sha256"}
        else:require(item["type"]=="directory","S1原H1库存特殊成员")
        projected={k:item[k] for k in keys};projected["path"]="tmp/host/"+item["path"]
        require(projected["path"] not in host,"S1原H1库存重复")
        host[projected["path"]]=projected
    require(host and {n:v for n,v in table.items() if n.startswith("tmp/host/") }==host,"S1完整H1与保护前快照不同")
    expected={};directories=set()
    for item in recipe["files"]:
        name=item["path"];directories.update(str(p) for p in Path(name).parents if str(p)!=".")
        observed=table.get(name,{})
        require(observed.get("sha256")==item["sha256"],"S1 J1原source SHA不同")
        if item["mode"]=="120000":
            require(observed.get("type")=="symlink" and observed.get("permissions")=="0777"
                    and identity_bytes(observed["target"].encode())=={"bytes":item["size"],"sha256":item["sha256"]},"S1 J1原链接不同")
        else:
            require(item["mode"] in ("100644","100755") and observed.get("type")=="file"
                    and observed.get("permissions")==("0755" if item["mode"]=="100755" else "0644")
                    and observed.get("bytes")==item["size"],"S1 J1原文件模式/大小不同")
        expected[name]=observed
    require(len(expected)==recipe["file_count"] and all(table.get(n,{}).get("type")=="directory" for n in directories)
            and {n for n in table if n!="tmp" and not n.startswith("tmp/")}==set(expected)|directories,"S1完整J1 source集合不同")


def verify_control(control, old_products, receipt, consumer, plan, runtime, release, arch, i0, inventory, cplan, recipe):
    """核外部handoff/原C与H1小原件、原保护库存和真实claim清理；不假称重算已删旧树。"""
    handoff=i0.decode(i0.raw_file(control/"handoff.json"));contract=plan["handoff_contract"]
    proof=i0.identity(control/"handoff.json")
    require(receipt["handoff"]==proof and handoff["run"]==receipt["run"]
            and set(handoff)==set(contract["handoff_fields"]) and handoff["task"]==contract["task"]
            and handoff["stage"]==contract["stage"] and (handoff["release"],handoff["arch"])==(release,arch)
            and handoff["consumer"]=={"tool":i0.identity(runtime/"run_locked_sdl2_c_tasks.py"),"plan_sha256":consumer.PLAN_SHA256,"bases":plan["bases"]}, "S1外部handoff范围或消费者身份不同")
    require(set(handoff["artifacts"])==set(plan["artifacts"]), "S1外部原件集合不同")
    backups={key:i0.decode(i0.raw_file(control/("input-proof-"+key+".json"))) for key in BACKUP_ARTIFACTS}
    for key in BACKUP_ARTIFACTS:require(i0.identity(control/("input-proof-"+key+".json"))==handoff["artifacts"][key], "S1原C/H1/H0小原件SHA不同")
    for key,name in (("export","export.json"),("prefix_archive","c-prefix.tar.gz"),("prefix_inventory","c-prefix-inventory.json"),("prefix_objects","c-archive-objects.json"),("prefix_headers","c-headers-and-sources.json")):
        require(i0.identity(old_products/name)==handoff["artifacts"][key], "S1原C完整导出和handoff不同")
    require(i0.identity(control/"host-C-verification.stdout")==handoff["artifacts"]["host_verification"], "S1原C host reader身份不同")
    old_host=i0.decode(i0.raw_file(control/"host-C-verification.stdout"))
    require(old_host==i0.decode(i0.raw_file(old_products/"product-verification.stdout"))
            and old_host["all_exported_member_bytes_and_MachO_objects_verified"] is True
            and old_host["returned_binary_executed_on_host"] is False, "S1本轮原C host reader不同")
    for key,name in (("producer_owner","producer-owner.json"),("protected_before","protected-before.json")):
        require(i0.identity(control/name)==handoff["artifacts"][key], "S1原所有权/前快照SHA不同")
    owner=i0.decode(i0.raw_file(control/"producer-owner.json"));before=i0.decode(i0.raw_file(control/"protected-before.json"))
    require(set(owner)==set(contract["owner_fields"]) and set(before)==set(contract["protected_before_fields"])
            and owner["run"]==before["run"]==handoff["run"] and owner["workspace_identity"]==before["workspace_identity"]==handoff["workspace_identity"]
            and owner["stage"]==contract["stage"] and owner["producer"]==plan["producer"], "S1原C保护库存/所有权不同")
    limits={"prefix_members":plan["limits"]["temporary_members"],"prefix_logical_bytes":plan["limits"]["temporary_logical_bytes"]}
    table=i0.inventory_table(before["entries"],limits);old=i0.decode(i0.raw_file(old_products/"c-prefix-inventory.json"))
    prefix="tmp/install.ios-"+arch+"/"
    require(all(table.get(prefix+v["path"])=={**v,"path":prefix+v["path"]} for v in old), "S1完整原C前快照与导出不同")
    h1=cplan["host_producers"][release];host=backups["H1_receipt"];host_entries=backups["H1_inventory"]
    require(handoff["artifacts"]["H1_receipt"]==h1["receipt"] and handoff["artifacts"]["H1_inventory"]==h1["inventory"]
            and host["host_bootstrap_verified"] is True and host["kernel_network_isolation_verified"] is True
            and host["release"]==release and host["prefix"]==h1["original_prefix"]
            and host["plan_sha256"]==h1["execution_plan_sha256"] and host["interpreter_sha256"]==h1["interpreter_sha256"], "S1原完整H1来源不同")
    require(isinstance(host_entries,list) and host_entries, "S1原完整H1库存缺失")
    verify_original_before(table,host_entries,recipe)
    claim=i0.decode(i0.raw_file(control/"sdl2-consumer-claim.json",65536))
    require(claim["run"]==handoff["run"] and claim["workspace_identity"]==handoff["workspace_identity"] and claim["handoff"]==proof
            and claim["tool"]==handoff["consumer"]["tool"] and type(claim["parent_pid"]) is int and type(claim["worker_pid"]) is int
            and re.fullmatch("[0-9a-f]{64}",claim["ticket_sha256"]), "S1实际S0 claim不同")
    workspace=str(Path("/reko/j9-workspaces")/release/arch)
    for name in ("workspace-cleanup.json","parent-workspace-cleanup.json"):
        clean=i0.decode(i0.raw_file(Path(receipt["_folder"])/name))
        require(clean["state"]=="removed" and clean["owned_workspace"]==workspace and clean["claim_retained"] is True, "S1原S0子父finally缺清理证明")
    return handoff,backups,table


def verify_returned(metadata, folder, old_products, control, release, arch, consumer_sha):
    """在独立宿主进程加载实际52文本，只读完整返回包，不执行iOS/Linux返回程序。"""
    runtime=Path(metadata)/"scripts/renpy";source=runtime/"run_locked_sdl2_c_tasks.py";raw=bootstrap_bytes(source)
    require(identity_bytes(raw)["sha256"]==consumer_sha,"S1宿主S0消费者身份不同")
    consumer=types.ModuleType("fixed_S1_host_S0");consumer.__file__=str(source);exec(compile(raw,str(source),"exec"),consumer.__dict__)
    plan,current,i0,ip=consumer.bootstrap(runtime/"sdl2-c-task-plan.json",runtime)
    c,cplan,helpers=i0.load_runtime(runtime,ip)
    return verify_product_documents(runtime,Path(folder),Path(old_products),Path(control),release,arch,consumer,plan,i0,c,cplan,helpers)


def verify_boundaries(receipt, expected):
    """JSON往返的延期字符串按类型和值比较，布尔边界不接受整数冒充。"""
    require(all(type(receipt.get(k)) is type(v) and receipt[k]==v for k,v in expected.items()),"S1原S0边界类型/值不同")


def verify_product_documents(runtime, folder, old_products, control, release, arch, consumer, plan, i0, c, cplan, helpers):
    """完整SDL prefix/对象/77头/配置/真实命令及C/H1输入强身份读验，不以CI状态替代。"""
    inventory,j8,native,validator,common,preflight=helpers
    for path in (folder,old_products,control):i0.guarded(path)
    row=next(v for v in plan["routes"] if v["release"]==release)
    receipt=i0.decode(i0.raw_file(folder/"current-sdl2-c-receipt.json"))
    require(receipt["task"]==consumer.TASK and receipt["scope"]==consumer.SCOPE and (receipt["release"],receipt["arch"])==(release,arch)
            and receipt["plan_sha256"]==consumer.PLAN_SHA256 and receipt["tool"]==i0.identity(runtime/"run_locked_sdl2_c_tasks.py")
            and receipt["sdl2_C_verified"] is True and receipt["temporary_workspace"]=="removed", "S1原S0收据范围/来源/边界不同")
    verify_boundaries(receipt,consumer.FALSE)
    require(all(receipt[k] is True for k in ("current_C_dependency_verified","current_C_fresh_by_controller","all_original_C_workspace_members_unchanged","all_new_archive_objects_verified","actual_configure_and_API_proofs_verified","kernel_network_isolation_verified"))
            and receipt["old_markers_synthesized"] is False and receipt["ran_tasks_seeded"] is False, "S1原C/SDK/H1/source或两Task保护证明不同")
    sidecar_names={"sdl2-prefix-inventory.json","sdl2-archive-objects.json","sdl2-installed-headers.json","sdl2-commands.json","sdl2-configure.json","sdl2-API-proof.json"}
    require(set(receipt["sidecars"])==sidecar_names, "S1固定SDL sidecar集合不同")
    sidecars={}
    for name in sidecar_names:
        require(receipt["sidecars"][name]==i0.identity(folder/name), "S1 SDL sidecar原字节不同")
        sidecars[name]=i0.decode(i0.raw_file(folder/name))
    entries=sidecars["sdl2-prefix-inventory.json"];table=i0.inventory_table(entries,plan["limits"])
    old=i0.decode(i0.raw_file(old_products/"c-prefix-inventory.json"));old_names={v["path"] for v in old}
    require(all(table.get(v["path"])==v for v in old),"S1最终prefix修改原C成员")
    new=[v for v in entries if v["path"] not in old_names]
    require(all(consumer.sdl_prefix_allowed(v["path"],plan) for v in new), "S1 SDL prefix含未知成员")
    headers=[v for v in new if v["type"]=="file" and v["path"].endswith(".h")]
    require(headers==sidecars["sdl2-installed-headers.json"]
            and {v["path"] for v in headers}=={"include/SDL2/"+v for v in plan["installed_headers"]}
            and len(headers)==receipt["complete_SDL2_header_count"]==77
            and all(v["bytes"]>0 for v in headers), "S1完整77安装头不同")
    archive=folder/"sdl2-prefix.tar.gz"
    require(receipt["archive"]["path"]==archive.name and {k:receipt["archive"][k] for k in ("bytes","sha256")}==i0.identity(archive), "S1完整SDL prefix归档身份不同")
    wanted=set(plan["expected_new_archives"])
    require({v["path"] for v in new if v["type"]=="file" and v["path"].endswith(".a")}==wanted,"S1 SDL三静态库集合不同")
    objects,executables=scan_prefix(archive,entries,wanted,old_names,arch,c,i0,inventory,preflight,plan["limits"])
    require(objects==sidecars["sdl2-archive-objects.json"] and len(objects)==receipt["new_archive_count"]==3
            and sum(v["object_count"] for v in objects)==receipt["object_count"] and executables==receipt["target_executables"], "S1三库全部对象/目标程序不同")
    records=[{**{k:s[k] for k in ("index","name","task","kind","function_sha256")},"task_name":s["task"]+"-sdl2.ios-"+arch,
              "operations":len(s["operations"][arch]),"original_Task_run_executed":True} for s in row["tasks"]]
    require(receipt["original_Task_records"]==records and len(records)==2,"S1两原Task身份/完整操作不同")
    verify_commands(sidecars["sdl2-commands.json"],row,arch,plan,c,cplan)
    config=verify_configuration_api(folder,receipt,sidecars,row,arch,consumer,plan,table,i0)
    source=receipt["source"];expected=row["source"]
    require({k:source[k] for k in ("family","version","archive")}=={k:expected[k] for k in ("family","version","archive")}
            and source["full_original_tar_verified"] is True and 0<source["members"]<=32768
            and 0<source["logical_bytes"]<=256*1024**2 and receipt["patches"]==row["patches"], "S1原SDL源码/补丁输入不同")
    binding=i0.decode(i0.raw_file(runtime/"source-task-binding-plan.json"))
    route=next(v for v in binding["routes"] if v["release"]==release);recipe=j8.repository_row(binding,route)
    require(row["recipe"]==route["recipe"],"S1 SDL/J1配方不同")
    receipt_for_control={**receipt,"_folder":str(folder)}
    handoff,backups,before=verify_control(control,old_products,receipt_for_control,consumer,plan,runtime,release,arch,i0,inventory,cplan,recipe)
    C=backups["C_receipt"]
    require(receipt["current_C_receipt"]==handoff["artifacts"]["C_receipt"] and receipt["current_C_export"]==i0.identity(old_products/"export.json")
            and receipt["frontend"]==C["frontend"] and receipt["SDK_install"]==C["SDK_install"], "S1本轮原C/SDK/H0关联不同")
    require(receipt["C_markers_before"] and set(receipt["C_markers_before"])=={v["task_name"] for v in C["tasks"]}, "S1原C marker完整集合不同")
    for name,value in receipt["C_markers_before"].items():
        require({k:before["tmp/complete/"+name][k] for k in ("bytes","sha256")}==value,"S1原C真实marker字节不同")
    driver=i0.decode(i0.raw_file(folder/"driver-result.json"))
    require(receipt["driver"]==driver and driver["candidate"]["passed"] is True,"S1实际SDL C候选driver不同")
    cpu,target=("x86_64" if arch=="sim-x86_64" else "arm64"),(2 if arch=="arm64" else 7)
    for kind,name in (("object","candidate-driver.o"),("executable","candidate-driver")):
        body=i0.raw_file(folder/name);expected_driver=driver["candidate"][kind]
        require({k:expected_driver[k] for k in ("bytes","sha256")}==identity_bytes(body),"S1实际driver原字节不同")
        preflight.check_macho(body,cpu,target,kind=="executable")
    returned=hash_returned(folder,i0);control_files=hash_returned(control,i0)
    for name in ("report.json","worker-report.json"):
        report=i0.decode(i0.raw_file(folder/name))
        require(report["result"]==consumer.RESULT and report["errors"]==[] and report["sdl2_C_verified"] is True
                and report["current_C_dependency_verified"] is True and report["temporary_workspace"]=="removed", "S1原S0父子真实报告不同")
    return {"release":release,"arch":arch,"all_bound_artifacts_verified":True,"all_returned_regular_files_hashed":True,
            "returned_files":returned,"returned_control_files":control_files,"new_archive_count":len(objects),
            "new_object_count":sum(v["object_count"] for v in objects),"complete_SDL2_header_count":len(headers),
            "all_new_archive_objects_verified":True,"complete_configuration_and_API_raw_proofs_verified":True,
            "original_C_H1_source_SDK_marker_protection_bound_to_actual_S0":True,
            "deleted_workspace_raw_rehashed_after_cleanup":False,"returned_binary_executed_on_host":False,**config}

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
    print("[RKLog][RenPySDL2CI] " + message, file=sys.stderr, flush=True)

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
    raw = bootstrap_bytes(args.plan); require(identity_bytes(raw)["sha256"] == PLAN_SHA256, "S1计划SHA不同")
    plan = json.loads(raw); require(plan["task"] == TASK, "S1任务不同")
    basis = plan["I1D_base"]; source = bootstrap_bytes(args.c_controller)
    require(identity_bytes(source) == basis["source"] and identity_bytes(bootstrap_bytes(args.c_controller.parent / "linux-image-c-ci-plan.json")) == basis["plan"], "固定I1D宿主source/plan不同")
    base = types.ModuleType("fixed_sdl2_I1D_basis"); base.__file__ = str(args.c_controller)
    exec(compile(source, str(args.c_controller), "exec"), base.__dict__)
    base_args = argparse.Namespace(**vars(args)); base_args.plan = args.c_controller.parent / "linux-image-c-ci-plan.json"
    bp, current, i0, image_plan, d, dp = base.load_fixed(base_args)
    require(plan["text_runtime_catalog"][:9] == bp["text_runtime_catalog"] and len(plan["text_runtime_catalog"]) == 11
            and plan["D"] == bp["D"] and plan["C_runtime_addon"] == bp["C_runtime_addon"], "S1改变原D/I1D材料")
    for row in plan["text_runtime_catalog"]:
        require(Path(row["path"]).name == row["path"], "文本路径不是固定basename")
        require(i0.identity(args.text_runtime_dir / row["path"], plan["limits"]["text_bytes"]) == {k: row[k] for k in ("bytes", "sha256")}, "固定十一文本不同：" + row["path"])
    source = args.text_runtime_dir / "run_locked_sdl2_c_tasks.py"
    consumer = types.ModuleType("fixed_S1_combined_consumer"); consumer.__file__ = str(source)
    exec(compile(i0.raw_file(source), str(source), "exec"), consumer.__dict__)
    cp, _, ci0, cip = consumer.bootstrap(args.text_runtime_dir / "sdl2-c-task-plan.json", args.text_runtime_dir)
    require(consumer.TASK == "R00-02J11S0" and cip == image_plan and ci0.PLAN_SHA256 == i0.PLAN_SHA256, "SDL2消费者实际基础不同")
    return plan, consumer, cp, current, i0, image_plan, d, dp, base, bp

def consumer_runtime(args, plan, base, bp, h0, h1, i0, metadata, rows, destination):
    """同一个物理50根仅新增S0两件成为真实52；宿主基础不塞入消费闭包。"""
    result = base.consumer_runtime(args, bp, h0, h1, i0, metadata, rows, destination)
    require(len(result) == 50 and plan["contract"]["expected_consumer_members"] == 52, "原消费50/SDL252合同不同")
    for item in plan["text_runtime_catalog"][9:]:
        require(item["path"] in ("run_locked_sdl2_c_tasks.py", "sdl2-c-task-plan.json"), "未知消费新增原件")
        target = i0.guarded(destination / "scripts/renpy" / item["path"])
        raw = i0.raw_file(args.text_runtime_dir / item["path"], plan["limits"]["text_bytes"])
        require(identity_bytes(raw) == {k: item[k] for k in ("bytes", "sha256")}, "S0复制前原件不同")
        with target.open("xb") as stream: stream.write(raw)
        result.append({"path": "scripts/renpy/" + item["path"], **identity_bytes(raw)})
    result.sort(key=lambda v: v["path"])
    require(len(result) == 52 and len({v["path"] for v in result}) == 52, "SDL2实际成员数不同")
    h1.verify_runtime_root(h0, destination, result); h1.verify_runtime_root(h0, metadata, rows)
    return result

def archive_objects(body, name, arch, c, i0, preflight):
    """从原ar所有成员重算CPU/platform/minOS/SDK及原字节身份。"""
    cpu, platform_id = ("x86_64" if arch == "sim-x86_64" else "arm64"), (2 if arch == "arm64" else 7)
    objects = []
    for member, raw in c.ar_members(body):
        info = preflight.check_macho(raw, cpu, platform_id)
        require(info["file_type"] == 1 and info["sdk"] in ([0, 0, 0], [14, 0, 0]), "SDL2对象类型或SDK不同")
        objects.append({"name": member, **identity_bytes(raw), **info})
    require(objects, "SDL2静态archive为空")
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
    require(path.parent == root and path.name.startswith("reko-j11-sdl2-inputs-")
            and owner["parent_pid"] == protocol["parent_pid"] and owner["ticket_sha256"] == base.ticket_hash(protocol)
            and owner["controller"] == i0.identity(Path(__file__).absolute()), "临时输入所有权不属于本轮")
    if path.exists():
        info = path.lstat(); require(stat.S_ISDIR(info.st_mode) and {"device": info.st_dev, "inode": info.st_ino} == owner["identity"], "临时输入根被替换")
        shutil.rmtree(path)
    return {"state": "removed", "removed": True}

def sdl2_handoff(args, plan, consumer, consumer_plan, i0, run, owner, runtime, rows, diagnostics, protocol, base):
    """原C完整reader通过后，在同一live C1一次交接S0并保全全部原件后新进程读验。"""
    remote = "/reko/j11-sdl2-runtime/root"
    system_python = "/usr/bin/python3.10" if args.ubuntu == "22.04" else "/usr/bin/python3.12"
    run.run(["mkdir", "-p", remote, "/reko/j11-sdl2-controller"], "sdl2-directories")
    run.copy(str(runtime) + "/.", remote, "sdl2-copy-consumer52")
    run.checksum("sdl2-consumer52", [(v["sha256"], remote + "/" + v["path"]) for v in rows])
    run.copy(Path(__file__).absolute(), "/reko/j11-sdl2-controller/run_linux_sdl2_c_tasks.py", "sdl2-original-controller")
    paths = consumer.fixed_paths(consumer_plan, args.release, args.arch)
    run.run([system_python, "-B", "-c", base.CREATE_CONTROL_DIRECTORY, str(paths["control"])], "sdl2-exclusive-control")
    original = run.output / "private-products" / args.release / args.arch
    original_reader = original / "product-verification.stdout"
    require(i0.decode(i0.raw_file(original_reader))["all_exported_member_bytes_and_MachO_objects_verified"] is True, "原C完整host reader未通过")
    run.copy(original_reader, str(paths["host_verification"]), "sdl2-original-C-host-reader")
    tool = i0.identity(Path(__file__).absolute()); consumer_sha = next(v["sha256"] for v in plan["text_runtime_catalog"] if v["path"] == "run_locked_sdl2_c_tasks.py")
    raw, _ = run.commands.run([run.docker, "exec", run.name, system_python, "-B", "-c", CREATE_HANDOFF,
                              args.release, args.arch, args.run_id, str(args.attempt), owner["id"], protocol["nonce"], str(tool["bytes"]), tool["sha256"], consumer_sha],
                             "sdl2-create-actual-C-handoff", timeout=300)
    handoff = i0.decode(raw); expected_run = {"github_run_id": args.run_id, "attempt": args.attempt, "container_id": owner["id"], "nonce": protocol["nonce"]}
    require(handoff["run"] == expected_run and handoff["frontend_python"] == base.frontend_python(args, plan, i0), "SDL2外部交接run/前端不符")
    proof = handoff["handoff"]
    require(type(proof["bytes"]) is int and 0 < proof["bytes"] <= consumer_plan["limits"]["handoff_bytes"] and re.fullmatch(r"[0-9a-f]{64}", proof["sha256"]), "SDL2handoff缺外部bytes/SHA")
    argv = [handoff["frontend_python"], "-s", "-B", str(paths["consumer_runtime"] / "run_locked_sdl2_c_tasks.py"), "run",
            "--release", args.release, "--arch", args.arch, "--output", str(paths["output"]), "--handoff-bytes", str(proof["bytes"]), "--handoff-sha256", proof["sha256"],
            "--run-id", args.run_id, "--attempt", str(args.attempt), "--container-id", owner["id"], "--nonce", protocol["nonce"]]
    failure = None
    try:
        remaining = int(protocol["work_deadline_monotonic"] - time.monotonic())
        require(remaining > 0, "统一工作时限已耗尽，不能启动SDL2")
        run.commands.run([run.docker, "exec", run.name, "env", "-i", "PATH=" + str(Path(handoff["frontend_python"]).parent) + ":/usr/bin:/bin",
                          "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC", "PYTHONHASHSEED=0", "PYTHONDONTWRITEBYTECODE=1", *argv],
                         "sdl2-original-S0-consumer", timeout=min(consumer_plan["limits"]["work_seconds"] + 300, remaining))
    except BaseException as error:
        failure = error
    finally:
        for source, destination, label in ((paths["output"], "sdl2-products", "sdl2-return"), (paths["control"], "sdl2-control", "sdl2-control-return")):
            try: base.bounded_copy(run, system_python, str(source), diagnostics / destination, label, plan, i0)
            except Exception as error:
                i0.write_new(diagnostics / (destination + "-preservation-error.json"), {"kind": type(error).__name__, "message": str(error)[:2000]})
                if failure is None: failure = error
    if failure is not None: raise failure
    folder = diagnostics / "sdl2-products"; control = diagnostics / "sdl2-control"
    observed = i0.checked(control / "handoff.json", proof)
    receipt = i0.decode(i0.raw_file(folder / "current-sdl2-c-receipt.json"))
    require(receipt["run"] == observed["run"] == expected_run and receipt["handoff"] == proof
            and observed["consumer"] == {"tool": i0.identity(args.text_runtime_dir / "run_locked_sdl2_c_tasks.py"), "plan_sha256": consumer.PLAN_SHA256, "bases": consumer_plan["bases"]}
            and observed["controller"] == {"path": str(paths["controller"]), **tool}, "回传SDL2收据未绑定真实外部交接")
    remaining = int(protocol["work_deadline_monotonic"] - time.monotonic())
    require(remaining > 0, "统一工作时限不足宿主完整reader")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", HOST_READER, str(Path(__file__).absolute()), tool["sha256"],
                             str(runtime), str(folder), str(original), str(control), args.release, args.arch, consumer_sha], capture_output=True, timeout=min(600, remaining))
    (diagnostics / "sdl2-host-verification.stdout").write_bytes(result.stdout); (diagnostics / "sdl2-host-verification.stderr").write_bytes(result.stderr)
    require(result.returncode == 0 and len(result.stdout) + len(result.stderr) <= plan["limits"]["host_log_bytes"], "SDL2宿主完整reader拒绝/日志超限")
    verification = i0.decode(result.stdout)
    require(all(verification[k] is True for k in ("all_bound_artifacts_verified", "all_returned_regular_files_hashed", "all_new_archive_objects_verified", "complete_configuration_and_API_raw_proofs_verified", "original_C_H1_source_SDK_marker_protection_bound_to_actual_S0"))
            and verification["new_archive_count"] == 3 and verification["complete_SDL2_header_count"] == 77
            and verification["returned_binary_executed_on_host"] is False, "SDL2完整reader范围不同")
    # 完整文件清单只留私有stdout，公开summary仅放计数/证明，不复制正文。
    return {"handoff": proof, "receipt": i0.identity(folder / "current-sdl2-c-receipt.json"),
            "host_verification": {k: v for k, v in verification.items() if k not in ("returned_files", "returned_control_files")}, "host_verification_stdout": i0.identity(diagnostics / "sdl2-host-verification.stdout"),
            "consumer_members": len(rows), "consumer_bytes": sum(v["bytes"] for v in rows)}

def execute(args, plan, consumer, consumer_plan, current, i0, ip, d, dp, base, bp, protocol, report):
    """同open_environment原D只生产真实单C；通过后统一S0，不调用旧image生命周期。"""
    diagnostics = args.output / "private-diagnostics"
    helpers = d.load_helpers(dp); h2, transport, h0, hp, h1, native, inventory = helpers
    require({g["ubuntu"]: g["image_id"] for g in hp["groups"]} == plan["C1_image_ids"], "原H0固定镜像映射不同")
    args.phase = "c-prerequisites"; args.releases = [args.release]; args.arches = [args.arch]; args.h2 = h2
    d.validate_phase_selection(args, dp)
    root = i0.guarded(Path(os.environ["RUNNER_TEMP"]))
    require(root.is_dir() and not root.is_relative_to(args.output), "独立RUNNER_TEMP无效")
    checkout = os.environ.get("GITHUB_WORKSPACE")
    require(not checkout or not root.is_relative_to(i0.guarded(Path(checkout))), "私密输入不能放checkout")
    with tempfile.TemporaryDirectory(prefix="reko-j11-sdl2-inputs-", dir=root) as temporary:
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
                raw, _ = run.host([run.docker, "inspect", run.name], "sdl2-controller-container-identity")
                states = i0.decode(raw); require(len(states) == 1, "实际C1 inspect数量不同")
                image_id = next(v["image_id"] for v in hp["groups"] if v["ubuntu"] == args.ubuntu)
                owner = container_owner(args, protocol, states[0], image_id, i0, base)
                d.execute_cells(run, h2, h0, native, inventory, payload, hp, metadata, rows, workspaces, selected, dp, args, stage)
                cell = stage["cells"][0]
                require(cell["status"] == "C_prerequisites_verified" and cell["product_verification"]["all_exported_member_bytes_and_MachO_objects_verified"] is True, "原C实际cell/host reader未通过，不交接SDL2")
                report["current_C_dependency_verified"] = True
                report["sdl2"] = sdl2_handoff(args, plan, consumer, consumer_plan, i0, run, owner, runtime, combined_rows, diagnostics, protocol, base)
                report["sdl2_C_verified"] = True
        finally:
            report["container_closed"] = stage.get("container_closed") is True; stage.pop("active_stage", None)
            i0.write_new(diagnostics / "original-D-stage-evidence.json", {"original_D_main_executed": False, "original_D_aggregate_success_claimed": False,
                         "actual_stage_fields": stage, "fresh_runtime_contract": proof})
    require(not private.exists() and report["container_closed"], "C1/本轮解密输入未回收")
    report.update(private_inputs_removed=True, same_open_C1_chain_verified=True, result=RESULT)

def parser():
    """只接受固定单tuple/原缓存/实际宿主基础和job截止时间，没有任意hook或下载fallback。"""
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--plan", type=Path, default=HERE / "linux-sdl2-c-ci-plan.json")
    result.add_argument("--ubuntu", choices=("22.04", "24.04"), required=True)
    result.add_argument("--release", choices=("8.5.3", "8.4.1", "8.3.7", "7.8.7"), required=True)
    result.add_argument("--arch", choices=("arm64", "sim-arm64", "sim-x86_64"), required=True)
    for name in ("text-runtime-dir", "c-controller", "d-wrapper", "bundle", "h1-artifact", "runtime-addon", "h0-cipher", "recipe-addon", "device-sdk", "simulator-sdk", "clang-runtime", "output"):
        result.add_argument("--" + name, type=Path, required=True)
    result.add_argument("--run-id", required=True); result.add_argument("--attempt", type=int, required=True)
    result.add_argument("--job-deadline-utc", type=int); result.add_argument("--ccache", action="store_true")
    result.add_argument("--worker-fd", type=int, help=argparse.SUPPRESS)
    return result

def main(argv=None):
    """唯一父监督器控制完整链工作时限/空间/票据与精确清理，成功须父子证据齐全。"""
    args = parser().parse_args(argv); created, trusted, code, i0, protocol, docker, base = False, False, 1, None, None, None, None
    report = {"schema_version": 1, "task": TASK, "scope": "single_tuple_same_C1_actual_C_then_original_two_SDL2_tasks", "ubuntu": args.ubuntu,
              "release": args.release, "arch": args.arch, "result": "failed", "sdl2_C_verified": False, "current_C_dependency_verified": False,
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
            raise NotRun("需要真实Linux amd64及Docker；未执行C/SDL2编译")
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
            require(before >= plan["limits"]["remote_entry_free_bytes"], "远端SDL2入口不足18GiB；估算不是实测峰值")
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
            require(child["result"] == RESULT and all(child[key] is True for key in ("current_C_dependency_verified", "sdl2_C_verified", "same_open_C1_chain_verified", "container_closed", "private_inputs_removed"))
                    and report["container_closed"] and report["private_inputs_removed"], "同C1完整链或父子清理证明不全")
            report.update({key: child[key] for key in ("result", "current_C_dependency_verified", "sdl2_C_verified", "same_open_C1_chain_verified", "producer_runtime_members", "consumer_runtime_members", "sdl2")}); code = 0
    except BaseException as error:
        report["result"] = "not_run" if isinstance(error, NotRun) else "interrupted" if isinstance(error, (Interrupted, KeyboardInterrupt)) else "failed"
        report["errors"].append({"kind": type(error).__name__, "stage": "same_C1_C_sdl2"})
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
        """外部SIGTERM进入本S1统一finally，保留失败并精确清理C1。"""
        raise Interrupted("收到SIGTERM")
    signal.signal(signal.SIGTERM,interrupted)
    raise SystemExit(main())
