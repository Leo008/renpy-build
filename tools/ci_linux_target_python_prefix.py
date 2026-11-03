#!/usr/bin/env python3
"""固定C1同lifetime运行原C；显式B阶段才衔接target安装，pip和iOS运行仍未验收。"""

from __future__ import annotations

import argparse
import ast
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


HERE = Path(__file__).absolute().parent
DEFAULT_PLAN = HERE / "linux-target-python-prefix-ci-plan.json"
PLAN_SHA256 = "d70d6eafcc42eb9460942f140bdc9b89126635a2fea847040c88c139d5263eeb"
C_ELIGIBILITY_SHA256 = "bd7921b80e9d218abc2081d5b6824d100b98ac78c601b1c67b9352968be6d3ea"
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


# B私有前缀/证明包共用窄PAX协议；仅path/linkpath扩展，原C的USTAR协议原样保留。
TARGET_PAX = r'''import hashlib,os,pathlib,re,shutil,stat,tarfile
def pax_identity(path):
 """只流式读取普通原件，不跟随叶链接或特殊文件。"""
 path=pathlib.Path(path);assert not any(p.is_symlink() for p in (path,*path.parents))
 with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
  info=os.fstat(stream.fileno());assert stat.S_ISREG(info.st_mode) and info.st_size<=2*1024**3
  digest=hashlib.sha256();count=0
  while block:=stream.read(262144):digest.update(block);count+=len(block)
  assert count==info.st_size
 return {'bytes':count,'sha256':digest.hexdigest()}
def pax_catalog(entries):
 """完整路径/父目录/链接图先核验；不接受目录别名或任意额外PAX属性。"""
 assert isinstance(entries,list) and entries and len(entries)<=200000
 table={};folded=set()
 for row in entries:
  name=row['path'];assert isinstance(name,str) and len(name.encode())<=4096 and not name.startswith('/') and chr(92) not in name and chr(0) not in name
  assert all(p not in ('','.','..') for p in name.split('/')) and name not in table and name.casefold() not in folded
  assert not any(p.endswith('.sdk') or p in ('SDKSettings.json','locked-sdk-tars') for p in name.split('/'))
  assert re.fullmatch('[0-7]{4}',row['permissions']) and row['type'] in ('directory','file','symlink')
  keys={'path','permissions','type'}|({'bytes','sha256'} if row['type']=='file' else {'target','sha256'} if row['type']=='symlink' else set())
  assert set(row)==keys
  if row['type']=='file':assert type(row['bytes']) is int and 0<=row['bytes']<=2*1024**3
  if row['type']!='directory':assert re.fullmatch('[0-9a-f]{64}',row['sha256'])
  if row['type']=='symlink':assert not pathlib.PurePosixPath(row['target']).is_absolute() and hashlib.sha256(row['target'].encode()).hexdigest()==row['sha256']
  table[name]=row;folded.add(name.casefold())
 for name in table:
  for parent in pathlib.PurePosixPath(name).parents:
   if str(parent)!='.':assert table[str(parent)]['type']=='directory'
 inventory.validate_links({name:row['target'] for name,row in table.items() if row['type']=='symlink'})
 return table
def pax_write(root,entries,archive):
 """仅写完整已核库存，显式PAX支持长stdlib路径，不包含SDK或host整树。"""
 root=pathlib.Path(root);table=pax_catalog(entries);assert not any(p.is_symlink() for p in (root,*root.parents,archive,*archive.parents)) and not archive.exists()
 with tarfile.open(archive,'w:gz',format=tarfile.PAX_FORMAT) as target:
  for row in entries:
   path=root/row['path'];info=tarfile.TarInfo(row['path']);info.mode=int(row['permissions'],8);info.uid=info.gid=info.mtime=0
   if row['type']=='directory':assert path.is_dir() and not path.is_symlink();info.type=tarfile.DIRTYPE;target.addfile(info)
   elif row['type']=='symlink':assert path.is_symlink() and os.readlink(path)==row['target'];info.type=tarfile.SYMTYPE;info.linkname=row['target'];target.addfile(info)
   else:
    assert pax_identity(path)=={k:row[k] for k in ('bytes','sha256')};info.size=row['bytes']
    with path.open('rb') as stream:target.addfile(info,stream)
 return pax_identity(archive)
def pax_extract(archive,entries,destination,identity):
 """先核每个实际成员，再独占展开；失败始终删除本轮临时树并保留原tar。"""
 assert pax_identity(archive)==identity;table=pax_catalog(entries);seen=set()
 with tarfile.open(archive,'r:gz') as source:
  assert not source.pax_headers
  for member in source:
   assert not source.pax_headers
   assert member.name in table and member.name not in seen and not member.sparse;seen.add(member.name);row=table[member.name]
   assert set(member.pax_headers)<={'path','linkpath'} and all(v==({'path':member.name+('/' if member.isdir() else ''),'linkpath':member.linkname}[k]) for k,v in member.pax_headers.items())
   assert member.uid==member.gid==member.mtime==0 and format(member.mode,'04o')==row['permissions']
   if row['type']=='directory':assert member.isdir()
   elif row['type']=='symlink':assert member.issym() and member.linkname==row['target']
   else:
    assert row['type']=='file' and member.isfile() and member.size==row['bytes']
    with source.extractfile(member) as stream:
     digest=hashlib.sha256();count=0
     while block:=stream.read(262144):digest.update(block);count+=len(block)
    assert count==row['bytes'] and digest.hexdigest()==row['sha256']
 assert seen==set(table) and not destination.exists() and not destination.is_symlink();destination.mkdir(mode=0o700)
 try:
  with tarfile.open(archive,'r:gz') as source:
   for member in source:
    row=table[member.name];path=destination/member.name
    if row['type']=='symlink':continue
    path.parent.mkdir(parents=True,exist_ok=True)
    if row['type']=='directory':path.mkdir(exist_ok=True)
    else:
     with source.extractfile(member) as inp,path.open('xb') as out:shutil.copyfileobj(inp,out,262144)
     path.chmod(int(row['permissions'],8))
  mask=os.umask(0)
  try:
   for row in entries:
    if row['type']=='symlink':
     path=destination/row['path'];path.symlink_to(row['target'])
     if stat.S_IMODE(path.lstat().st_mode)!=int(row['permissions'],8):
      assert hasattr(os,'lchmod');os.lchmod(path,int(row['permissions'],8))
     assert stat.S_IMODE(path.lstat().st_mode)==int(row['permissions'],8)
  finally:os.umask(mask)
  for row in sorted(entries,key=lambda r:r['path'].count('/'),reverse=True):
   if row['type']=='directory':(destination/row['path']).chmod(int(row['permissions'],8))
 except BaseException:
  shutil.rmtree(destination);raise
'''

TARGET_SIDECARS = (
    "target-install-receipt.json", "target-prefix-inventory.json", "target-stdlib-sources.json", "target-native-products.json",
    "target-libpython-symbols.json", "target-libpython-nm.stdout", "target-make-projection.json", "target-python-commands.json",
    "target-install-events.jsonl", "target-source-after-patches.json", "target-scproxy-generation.json", "target-implicit-ensurepip.json",
    "target-host-before.json", "target-host-after.json", "target-host-delta.json", "c-prefix-receipt.json", "c-prefix-inventory.json",
    "c-archive-objects.json", "c-headers-and-sources.json", "target-libpython-layout.json", "target-libpython-source-objects.json")

TARGET_BUILD_RECEIPT = r'''import shlex
def verify_cp39_build_context():
 """只静读实际proof/收据，核原configure生成的CP39 wrapper；不在Mac查远程PATH或执行H1。"""
 candidate=spec.get('build_context_candidate');assert receipt['CP39_build_context_candidate_used'] is (candidate is not None)
 if candidate is None:return False
 assert release=='8.3.7' and projection['ENSUREPIP']==m.effective_make_ensurepip(spec)=='no' and spec['expected_make_ensurepip']=='upgrade'
 host=original_prefix.parent/'host';build_python=receipt['build_python'];expected_sha=plan['host_producers'][release]['interpreter_sha256']
 resolved=pathlib.PurePosixPath(build_python['resolved_interpreter']);relative=resolved.relative_to(host).as_posix();assert '..' not in relative.split('/')
 host_record=next(record for record in before if record['path']==relative)
 assert host_record['type']=='file' and host_record['sha256']==build_python['sha256']==expected_sha and int(host_record['permissions'],8)&0o111
 assert build_python['original_requested']==str(host/'bin/python3') and build_python['effective_requested']==projection['PYTHON_FOR_BUILD'] and build_python['CP39_wrapper_added'] is False
 assert build_python['CP39_original_configure_cross_wrapper_enabled'] is True and build_python['implicit_ensurepip_disabled'] is True and build_python['original_install_ensurepip_fragment_verified'] is True
 words=shlex.split(projection['PYTHON_FOR_BUILD']);assert len(words)==5 and words[-1]==candidate['configure_discovery_name']
 assignments=[word.partition('=') for word in words[:-1]];assert all(separator for _,separator,_ in assignments) and len({name for name,_,_ in assignments})==4
 environment={name:value for name,_,value in assignments};platform='darwin-x86_64' if arch=='sim-x86_64' else 'darwin-arm'
 directory=m.raw_file(python_root/'pybuilddir.txt',4096).decode().strip();assert directory=='build/lib.'+platform+'-3.9' and projection['srcdir'] in ('.',str(original_python))
 expected={'_PYTHON_PROJECT_BASE':str(original_python),'_PYTHON_HOST_PLATFORM':platform,
  'PYTHONPATH':str(original_python/directory)+':'+projection['srcdir']+'/Lib',
  '_PYTHON_SYSCONFIGDATA_NAME':'_sysconfigdata_'+projection['ABIFLAGS']+'_'+projection['MACHDEP']+'_'+projection['MULTIARCH']}
 assert environment==expected==build_python['cross_environment'] and projection['MACHDEP']=='darwin'
 flags=[word for word in shlex.split(projection['CONFIG_ARGS']) if word.startswith(('--with-ensurepip','--without-ensurepip'))];assert flags==['--with-ensurepip=no']
 makefile=m.raw_file(python_root/'Makefile');assert m.sha(makefile)==build_python['actual_makefile_sha256'] and makefile.decode().count(candidate['original_install_ensurepip_fragment'])==1
 for key,fragment in [('configure_ac','original_cross_wrapper_fragment'),('makefile_template','original_install_ensurepip_fragment')]:
  descriptor=candidate[key];body=m.raw_file(python_root/descriptor['path']);assert len(body)==descriptor['bytes'] and m.sha(body)==descriptor['sha256'] and body.decode().count(candidate[fragment])==1
 configurations=[event for event in events if event.get('CP39_build_context_candidate') is not None];assert len(configurations)==1
 event=configurations[0];configuration=event['CP39_build_context_candidate'];assert event['returncode']==0 and event['template']==candidate['configure_template']
 assert event['execution_template']==candidate['configure_template']+' '+candidate['candidate_configure_argument'] and event['argv']==configuration['candidate_argv']
 assert configuration['candidate_argv']==configuration['original_argv']+[candidate['candidate_configure_argument']]
 assert not any(word.startswith(('--with-ensurepip','--without-ensurepip')) for word in configuration['original_argv'])
 assert configuration['original_environment']=={'PYTHON_FOR_BUILD':str(host/'bin/python3')} and configuration['candidate_environment']=={'PYTHON_FOR_BUILD':''} and event['environment']['PYTHON_FOR_BUILD']==''
 assert configuration['scope']==candidate['scope'] and configuration['configure_ac']==candidate['configure_ac'] and configuration['reason']==candidate['reason']
 assert configuration['configure_discovery']=={'requested':candidate['configure_discovery_name'],'path':str(host/'bin'/candidate['configure_discovery_name']),'realpath':str(resolved),'sha256':expected_sha}
 assert all(configuration[key] is False for key in ('original_argv_executed','original_task_body_modified','original_cross_wrapper_source_modified'))
 assert before==after and not any(record['path'].startswith('lib/python3.9/site-packages/') and record['path']!='lib/python3.9/site-packages/README.txt' for record in entries)
 return True
'''

TARGET_FRAMEWORK_RECEIPT = r'''def verify_target_framework_receipt():
 """从原make日志重取真实argv并调用固定纯校验器，不把自签receipt当链接证据。"""
 config=plan['target_install']['framework_link_candidate'];expected=release in config['releases']
 filename='target-framework-link-binding.json';record=receipt['B_framework_link_candidate']
 configurations=[event for event in events if event.get('B_framework_link_candidate') is not None]
 if not expected:
  assert release in config['already_complete_releases'] and record is None and receipt['B_framework_link_binding_sha256'] is None
  assert not configurations and filename not in export['files'] and not (folder/filename).exists()
  return False
 assert filename in export['files'] and pax_identity(folder/filename)['sha256']==receipt['B_framework_link_binding_sha256']
 assert m.decode(m.raw_file(folder/filename))==record and len(configurations)==1
 configured=configurations[0];assert configured['returncode']==0 and configured['B_framework_link_candidate']==record['candidate']
 source=config['routes'][release];assert configured['template']==source['configure_template']
 assert {key:configured['environment'][key] for key in m.ENV_KEYS}==record['candidate']['candidate_environment']
 template=source['makefile_template'];body=m.raw_file(python_root/template['path'])
 assert len(body)==template['bytes'] and m.sha(body)==template['sha256'] and body.decode().count(source['link_recipe'])==1
 builds=[event for event in events if event.get('operation')=='run' and event.get('template','').strip()=='{{ make }}']
 assert len(builds)==1 and builds[0]['returncode']==0 and record['actual_make_log']==builds[0]['raw_command_log']
 original=pathlib.Path(record['actual_make_log']['path']);assert original.parent==pathlib.Path('/reko/j9-results')/release/arch and re.fullmatch(r'target-python-command-[0-9]{3}\.log',original.name)
 raw=m.raw_file(folder/original.name,1024**3);assert len(raw)==record['actual_make_log']['bytes'] and m.sha(raw)==record['actual_make_log']['sha256']
 argv=m.extract_target_python_link_argv(raw,projection['BUILDPYTHON'])
 binding=m.check_target_framework_link_binding(record['candidate'],row,spec,arch,original_prefix.parent.parent,plan,
  makefile_raw=m.raw_file(python_root/'Makefile'),projection=projection,actual_argv=argv)
 assert binding==record['binding'] and binding['target_link_argument_binding_verified'] is True
 return True
'''

EXPORT_TARGET_PREFIX = TARGET_PAX + r'''import json,sys,types
metadata,release,arch,worker_sha,sidecars=sys.argv[1:];metadata=pathlib.Path(metadata);sidecars=json.loads(sidecars)
p=metadata/'scripts/renpy/run_locked_target_python_tasks.py';raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()==worker_sha
m=types.ModuleType('reko_j9_B_export');m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__)
plan=m.load_plan();inventory,j8,native,validator,common,preflight=m.helpers(plan)
row=next(r for r in plan['routes'] if r['release']==release);spec=next(r for r in plan['target_install']['routes'] if r['release']==release)
workspace=pathlib.Path('/reko/j9-workspaces')/release/arch;folder=pathlib.Path('/reko/j9-results')/release/arch
receipt=m.decode(m.raw_file(folder/'target-install-receipt.json'));c=m.decode(m.raw_file(folder/'c-prefix-receipt.json'))
assert receipt['task']=='R00-02J9B' and receipt['scope']==m.TARGET_SCOPE and receipt['release']==release and receipt['arch']==arch
assert receipt['execution_source_sha256']==worker_sha and receipt['plan_sha256']==m.PLAN_SHA256 and receipt['target_python_install_verified'] is True
assert all(receipt[k] is False for k in m.FALSE_BOUNDARIES if k!='target_python_install_verified')
assert receipt['C_receipt']['sha256']==pax_identity(folder/'c-prefix-receipt.json')['sha256'] and c['C_prerequisites_verified'] is True
projection=m.decode(m.raw_file(folder/'target-make-projection.json'));assert projection==receipt['make_projection']
build,_=m.expected_paths(workspace,row,arch,spec['tasks'][0]);python_root=build/spec['archive']['root']
args=type('ExportArgs',(),{'workspace':workspace,'arch':arch})()
c_inventory=m.checked_json(folder/'c-prefix-inventory.json',c['inventory_sha256'])
products=m.verify_target_prefix(args,plan,row,spec,python_root,projection,c_inventory,inventory,native)
for filename,key in [('target-prefix-inventory.json','inventory_sha256'),('target-stdlib-sources.json','stdlib_sources_sha256'),('target-native-products.json','native_products_sha256'),('target-libpython-symbols.json','static_module_symbols_sha256'),('target-libpython-layout.json','libpython_layout_sha256'),('target-libpython-source-objects.json','libpython_source_objects_sha256')]:
 assert pax_identity(folder/filename)['sha256']==receipt[key]
assert products['inventory']==m.decode(m.raw_file(folder/'target-prefix-inventory.json')) and products['stdlib']==m.decode(m.raw_file(folder/'target-stdlib-sources.json'))
assert {k:products[k] for k in ('archives','binaries','native_bridge','target_sysconfig')}==m.decode(m.raw_file(folder/'target-native-products.json'))
assert products['libpython_layout']==m.decode(m.raw_file(folder/'target-libpython-layout.json'))
assert products['libpython_layout']['source_objects']==m.decode(m.raw_file(folder/'target-libpython-source-objects.json'))
symbols=m.validate_target_symbols(m.raw_file(folder/'target-libpython-nm.stdout'),row);assert symbols==m.decode(m.raw_file(folder/'target-libpython-symbols.json'))
library=python_root/('libpython'+'.'.join(row['version'].split('.')[:2])+'.a');major='18' if release in ('8.5.3','8.4.1') else '15'
nm_raw=native.command(['/usr/bin/llvm-nm-'+major,'-g','--defined-only',library]);nm=m.validate_target_symbols(nm_raw,row)
assert nm['all_defined_names']==symbols['all_defined_names']
framework=workspace/next(r['path'] for r in row['extra_inputs'] if r['path']==('source/MetalANGLE.framework.ios.zip' if arch=='arm64' else 'source/MetalANGLE.framework.ios.simulator.zip'))
m.verify_framework(framework,workspace/('tmp/install.ios-'+arch),arch,inventory)
target=pathlib.Path('/reko/j9-private-products')/release/arch;target.mkdir(parents=True)
archive=target/'target-prefix.tar.gz';prefix=workspace/('tmp/install.ios-'+arch)
archive_id=pax_write(prefix,products['inventory'],archive)
build_dir=m.raw_file(python_root/'pybuilddir.txt',4096).decode().strip();assert build_dir and not build_dir.startswith('/') and '..' not in build_dir.split('/')
config_name='_sysconfigdata.py' if row['python']=='2' else '_sysconfigdata__'+projection['MACHDEP']+'_'+projection['MULTIARCH']+'.py'
required={'LICENSE','Include/Python.h','Modules/_scproxy.c','pyconfig.h','pybuilddir.txt','Makefile','config.site',build_dir+'/'+config_name,library.name}
# 每个原build对象只运输一次；下面侧文件保留所有重复occurrence/顺序，绝不从归档反推伪造原.o。
layout_source=plan['target_install']['libpython_layout']['routes'][release];template=layout_source['makefile_template']
object_paths=m.parse_libpython_object_paths(m.raw_file(python_root/'Makefile'),m.raw_file(python_root/template['path']),projection,layout_source)
required.add(template['path']);required.update(object_paths)
if spec.get('build_context_candidate'):
 required.update(spec['build_context_candidate'][key]['path'] for key in ('configure_ac','makefile_template'))
directories=projection['LIBSUBDIRS'].split()+(projection['TESTSUBDIRS'].split() if projection['TEST_MODULES']=='yes' else [])
if 'distutils/tests' in directories:required.add('Modules/xxmodule.c')
events=m.decode(m.raw_file(folder/'target-python-commands.json'))
framework_link=m.verify_target_framework_link(events,row,spec,arch,workspace,plan,python_root,projection)
assert framework_link==receipt['B_framework_link_candidate']
sidecars=list(sidecars)
if framework_link is None:
 assert receipt['B_framework_link_binding_sha256'] is None and not (folder/'target-framework-link-binding.json').exists()
else:
 assert m.decode(m.raw_file(folder/'target-framework-link-binding.json'))==framework_link
 assert pax_identity(folder/'target-framework-link-binding.json')['sha256']==receipt['B_framework_link_binding_sha256']
 sidecars.append('target-framework-link-binding.json')
 required.add(plan['target_install']['framework_link_candidate']['routes'][release]['makefile_template']['path'])
for event in events:
 if event['operation']=='generate':required.add(str(pathlib.Path(event['path']).relative_to(python_root)))
proof_stage=target/'proof-staging';proof_stage.mkdir(mode=0o700)
try:
 m.guarded(python_root/'Lib');shutil.copytree(python_root/'Lib',proof_stage/'Lib',symlinks=True)
 for name in sorted(required):
  source=m.guarded(python_root/name);assert source.is_file();destination=proof_stage/name;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,destination)
 proof=m.inventory_tree(proof_stage,inventory);proof_archive=target/'target-build-proof.tar.gz';proof_id=pax_write(proof_stage,proof,proof_archive)
finally:shutil.rmtree(proof_stage)
with (target/'target-export-nm.stdout').open('xb') as stream:stream.write(nm_raw)
files={'target-export-nm.stdout':pax_identity(target/'target-export-nm.stdout')}
for name in sidecars:
 assert '/' not in name;data=m.raw_file(folder/name,512*1024**2)
 with (target/name).open('xb') as stream:stream.write(data)
 files[name]=pax_identity(target/name)
for event in events:
 if event['operation']=='run':
  log=event['raw_command_log'];path=pathlib.Path(log['path']);assert path.parent==folder and re.fullmatch(r'target-python-command-[0-9]{3}\.log',path.name)
  assert pax_identity(path)=={k:log[k] for k in ('bytes','sha256')}
  with path.open('rb') as inp,(target/path.name).open('xb') as out:shutil.copyfileobj(inp,out,262144)
  files[path.name]=pax_identity(target/path.name)
(target/'target-proof-inventory.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n');files['target-proof-inventory.json']=pax_identity(target/'target-proof-inventory.json')
result={'kind':'target-install-success-export','release':release,'arch':arch,'worker_sha256':worker_sha,'plan_sha256':m.PLAN_SHA256,
 'original_prefix':str(prefix),'original_python_root':str(python_root),'files':files,'archive':archive_id,'proof_archive':proof_id,
 'receipt_sha256':files['target-install-receipt.json']['sha256'],'member_count':len(products['inventory']),'proof_member_count':len(proof),
 'target_python_install_verified':True,'target_pip_bound':False,'ios_runtime_verified':False,'container_nm_reexecuted':True}
with (target/'target-export.json').open('x') as stream:json.dump(result,stream,ensure_ascii=False,indent=2);stream.write('\n')
print(json.dumps({'target_python_install_verified':True,'prefix_members':len(products['inventory']),'proof_members':len(proof)}))
'''

VERIFY_TARGET_EXPORT = TARGET_PAX + TARGET_BUILD_RECEIPT + TARGET_FRAMEWORK_RECEIPT + r'''import json,subprocess,sys,types
metadata,folder,workspace,worker_sha=sys.argv[1:];metadata=pathlib.Path(metadata);folder=pathlib.Path(folder);workspace=pathlib.Path(workspace)
p=metadata/'scripts/renpy/run_locked_target_python_tasks.py';raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()==worker_sha
m=types.ModuleType('reko_j9_B_static_reader');m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__)
plan=m.load_plan();inventory,j8,native,validator,common,preflight=m.helpers(plan)
export=m.decode(m.raw_file(folder/'target-export.json'));assert export['kind']=='target-install-success-export' and export['target_python_install_verified'] is True
assert export['worker_sha256']==worker_sha and export['plan_sha256']==m.PLAN_SHA256 and export['container_nm_reexecuted'] is True
assert export['target_pip_bound'] is False and export['ios_runtime_verified'] is False
release,arch=export['release'],export['arch'];row=next(r for r in plan['routes'] if r['release']==release)
spec=next(r for r in plan['target_install']['routes'] if r['release']==release)
required_files={'target-install-receipt.json','target-prefix-inventory.json','target-stdlib-sources.json','target-native-products.json','target-libpython-symbols.json',
 'target-libpython-nm.stdout','target-make-projection.json','target-python-commands.json','target-install-events.jsonl','target-source-after-patches.json',
 'target-scproxy-generation.json','target-implicit-ensurepip.json','target-host-before.json','target-host-after.json','target-host-delta.json',
 'c-prefix-receipt.json','c-prefix-inventory.json','c-archive-objects.json','c-headers-and-sources.json','target-proof-inventory.json','target-export-nm.stdout',
 'target-libpython-layout.json','target-libpython-source-objects.json'}
if release in plan['target_install']['framework_link_candidate']['releases']:required_files.add('target-framework-link-binding.json')
assert required_files<=set(export['files']) and all(name in required_files or re.fullmatch(r'target-python-command-[0-9]{3}\.log',name) for name in export['files'])
for name,identity in export['files'].items():assert '/' not in name and name not in ('.','..') and pax_identity(folder/name)==identity
receipt=m.decode(m.raw_file(folder/'target-install-receipt.json'));c=m.decode(m.raw_file(folder/'c-prefix-receipt.json'))
assert pax_identity(folder/'target-install-receipt.json')['sha256']==export['receipt_sha256']
assert receipt['task']=='R00-02J9B' and receipt['scope']==m.TARGET_SCOPE and receipt['release']==release and receipt['arch']==arch
assert receipt['execution_source_sha256']==worker_sha and receipt['plan_sha256']==m.PLAN_SHA256 and receipt['target_python_install_verified'] is True
assert all(receipt[k] is False for k in m.FALSE_BOUNDARIES if k!='target_python_install_verified')
assert receipt['C_receipt']['sha256']==pax_identity(folder/'c-prefix-receipt.json')['sha256'] and c['C_prerequisites_verified'] is True
assert c['execution_source_sha256']==worker_sha and c['plan_sha256']==m.PLAN_SHA256 and c['release']==release and c['arch']==arch
assert c['task']=='R00-02J9A' and c['scope']==m.SCOPE and c['recipe']==row['recipe'] and c['original_C_tasks_verified'] is True and c['kernel_network_isolation_verified'] is True
for filename,key in [('c-prefix-inventory.json','inventory_sha256'),('c-archive-objects.json','archive_objects_sha256'),('c-headers-and-sources.json','headers_and_sources_sha256')]:assert pax_identity(folder/filename)['sha256']==c[key]
projection=m.decode(m.raw_file(folder/'target-make-projection.json'));assert projection==receipt['make_projection']
original_prefix=pathlib.Path(export['original_prefix']);original_python=pathlib.Path(export['original_python_root'])
assert original_prefix==pathlib.Path('/reko/j9-workspaces')/release/arch/'tmp'/('install.ios-'+arch)
original_build,_=m.expected_paths(original_prefix.parent.parent,row,arch,spec['tasks'][0]);assert original_python==original_build/spec['archive']['root']
assert receipt['C_receipt']['path']==str(pathlib.Path('/reko/j9-results')/release/arch/'c-prefix-receipt.json')
assert projection['prefix']==str(original_prefix) and projection['VERSION']=='.'.join(row['version'].split('.')[:2]) and projection['ABIFLAGS']==''
assert projection['ENSUREPIP']==m.effective_make_ensurepip(spec) and receipt['original_CP39_cross_wrapper_modified'] is False
for filename,key in [('target-prefix-inventory.json','inventory_sha256'),('target-stdlib-sources.json','stdlib_sources_sha256'),('target-native-products.json','native_products_sha256'),('target-libpython-symbols.json','static_module_symbols_sha256'),('target-libpython-layout.json','libpython_layout_sha256'),('target-libpython-source-objects.json','libpython_source_objects_sha256')]:assert pax_identity(folder/filename)['sha256']==receipt[key]
entries=m.decode(m.raw_file(folder/'target-prefix-inventory.json'));proof=m.decode(m.raw_file(folder/'target-proof-inventory.json'))
assert len(entries)==export['member_count'] and len(proof)==export['proof_member_count']
c_inventory=m.checked_json(folder/'c-prefix-inventory.json',c['inventory_sha256'])
prefix=folder/'verified-target-prefix';python_root=folder/'verified-target-build-proof'
try:
 pax_extract(folder/'target-prefix.tar.gz',entries,prefix,export['archive'])
 pax_extract(folder/'target-build-proof.tar.gz',proof,python_root,export['proof_archive'])
 assert m.inventory_tree(prefix,inventory)==entries and m.inventory_tree(python_root,inventory)==proof
 m.assert_existing_members_unchanged(c_inventory,entries);assert receipt['old_C_members_unchanged'] is True
 # 原C子集逐字节未改；用原解析器重算其独立sidecar，不把B新增libpython/ELF混入C库存。
 c_archives=[];c_executables=[];cpu='x86_64' if arch=='sim-x86_64' else 'arm64';platform=2 if arch=='arm64' else 7
 for record in c_inventory:
  if record['type']!='file' or record['path'].startswith('MetalANGLE.framework/'):continue
  path=prefix/record['path']
  if path.suffix=='.a':
   objects=[{'name':name,'bytes':len(body),'sha256':m.sha(body),**preflight.check_macho(body,cpu,platform)} for name,body in m.ar_members(m.raw_file(path,1024**3))]
   assert all(item['file_type']==1 and item['sdk'] in ([0,0,0],[14,0,0]) for item in objects)
   c_archives.append({'path':record['path'],'objects':objects,'object_count':len(objects)})
  else:
   with path.open('rb') as stream:magic=stream.read(4)
   assert magic!=b'\x7fELF'
   if magic==b'\xcf\xfa\xed\xfe':
    identity=preflight.check_macho(m.raw_file(path),cpu,platform,True);assert identity['file_type']==2;c_executables.append({**record,**identity})
 c_objects=m.decode(m.raw_file(folder/'c-archive-objects.json'));assert c_archives==c_objects['archives'] and c_executables==c_objects['executables']
 c_headers=[r for r in c_inventory if r['type']=='file' and r['path'].endswith('.h') and not r['path'].startswith('MetalANGLE.framework/')]
 assert m.decode(m.raw_file(folder/'c-headers-and-sources.json'))=={'headers':c_headers,'sources':row['sources'],'extra_inputs':row['extra_inputs']}
 stdlib=prefix/'lib'/('python'+projection['VERSION']);assert projection['LIBDEST']==str(original_prefix/'lib'/('python'+projection['VERSION']))
 sources=m.stdlib_expected_sources(python_root,projection,row['version']);stdlib_records=[]
 for name,path in sorted(sources.items()):
  actual=stdlib/name;body=m.raw_file(path);assert m.raw_file(actual)==body
  stdlib_records.append({'path':actual.relative_to(prefix).as_posix(),'source':str(original_python/path.relative_to(python_root)),'bytes':len(body),'sha256':m.sha(body)})
 assert stdlib_records==m.decode(m.raw_file(folder/'target-stdlib-sources.json')) and len(stdlib_records)==receipt['target_stdlib_source_count']
 source_snapshot={r['path']:r for r in m.decode(m.raw_file(folder/'target-source-after-patches.json'))}
 stdlib_changes=[]
 for name,path in sources.items():
  relative=path.relative_to(python_root).as_posix();before=source_snapshot.get(relative);actual=pax_identity(path)
  if before is None or before.get('type')!='file' or actual!={k:before[k] for k in ('bytes','sha256')}:
   stdlib_changes.append({'source':relative,'after_make':actual,'post_patch_snapshot':before})
 config_name='_sysconfigdata.py' if row['python']=='2' else '_sysconfigdata__'+projection['MACHDEP']+'_'+projection['MULTIARCH']+'.py'
 build_dir=m.raw_file(python_root/'pybuilddir.txt',4096).decode().strip();assert build_dir and not build_dir.startswith('/') and '..' not in build_dir.split('/')
 config_raw=m.raw_file(python_root/build_dir/config_name);assert config_raw==m.raw_file(stdlib/config_name)
 target_variables=m.verify_sysconfig_data(config_raw,projection)
 minor=projection['VERSION'];headers=prefix/'include'/('python'+minor)
 assert m.raw_file(headers/'Python.h')==m.raw_file(python_root/'Include/Python.h') and m.raw_file(headers/'pyconfig.h')==m.raw_file(python_root/'pyconfig.h')
 config=m.raw_file(python_root/'pyconfig.h').decode();assert re.search(r'^#define SIZEOF_VOID_P 8$',config,re.M) and re.search(r'^#define SIZEOF_LONG 8$',config,re.M) and not re.search(r'^#define WORDS_BIGENDIAN(?:\s+1)?$',config,re.M)
 library_name='libpython'+minor+'.a';library_raw=m.raw_file(prefix/'lib'/library_name,1024**3)
 assert projection['LIBRARY']==library_name and library_raw==m.raw_file(python_root/library_name,1024**3)
 # 只从已回取的原build相对.o读取证明；旧诊断若缺.o即失败，不用archive成员回填source。
 layout_source=plan['target_install']['libpython_layout']['routes'][release];template=layout_source['makefile_template']
 object_paths=m.parse_libpython_object_paths(m.raw_file(python_root/'Makefile'),m.raw_file(python_root/template['path']),projection,layout_source)
 source_objects={name:m.raw_file(python_root/name) for name in set(object_paths)}
 libpython_layout=m.check_libpython_layout(library_raw,m.raw_file(python_root/'Makefile'),m.raw_file(python_root/template['path']),projection,source_objects,row,arch,plan)
 copy_paths=m.libpython_install_paths(original_prefix,row,projection);seen_copies=set()
 assert {**libpython_layout,'installed_copy_paths':copy_paths}==m.decode(m.raw_file(folder/'target-libpython-layout.json'))
 assert libpython_layout['source_objects']==m.decode(m.raw_file(folder/'target-libpython-source-objects.json'))
 archives=[];binaries=[];bridges=[];bridge='bin/hostpython'+row['python'];bridge_sha=plan['host_producers'][release]['interpreter_sha256']
 for record in entries:
  if record['type']!='file' or record['path'].startswith('MetalANGLE.framework/'):continue
  path=prefix/record['path']
  with path.open('rb') as stream:magic=stream.read(8)
  if magic.startswith(b'\x7fELF'):
   assert record['path']==bridge and record['sha256']==bridge_sha and path.stat().st_mode&0o111
   bridges.append({**record,'elf':native.elf_identity(m.raw_file(path))})
  elif magic==b'!<arch>\n':
   if record['path'] in copy_paths:
    assert m.raw_file(path,1024**3)==library_raw;objects=libpython_layout['objects'];seen_copies.add(record['path'])
   else:
    assert record['path'] in {r['path'] for r in c_inventory}
    objects=[{'name':name,'bytes':len(body),'sha256':m.sha(body),**m.target_macho(body,arch)} for name,body in m.ar_members(m.raw_file(path,1024**3))]
   assert all(x['file_type']==1 for x in objects)
   archives.append({'path':record['path'],'bytes':record['bytes'],'sha256':record['sha256'],'objects':objects})
  elif magic[:4]==b'\xcf\xfa\xed\xfe':binaries.append({**record,**m.target_macho(m.raw_file(path),arch)})
  elif path.suffix in ('.so','.dylib','.a','.o'):raise ValueError('unverified target native file')
 assert len(bridges)==1 and seen_copies==set(copy_paths)
 native_products={'archives':archives,'binaries':binaries,'native_bridge':bridges[0],
  'target_sysconfig':{'path':str(original_prefix/'lib'/('python'+minor)/config_name),'sha256':m.sha(config_raw),
  'source':str(original_python/build_dir/config_name),'target_variables':target_variables}}
 assert native_products==m.decode(m.raw_file(folder/'target-native-products.json'))
 if spec['native_sysconfig_copy'] is not None:
  item=spec['native_sysconfig_copy'];assert m.sha(m.raw_file(prefix/item['path']))==item['sha256']
 symbols=m.validate_target_symbols(m.raw_file(folder/'target-libpython-nm.stdout'),row);assert symbols==m.decode(m.raw_file(folder/'target-libpython-symbols.json'))
 nm=m.validate_target_symbols(m.raw_file(folder/'target-export-nm.stdout'),row);assert nm['all_defined_names']==symbols['all_defined_names']
 host_nm=False
 if sys.platform=='darwin':
  result=subprocess.run(['/usr/bin/xcrun','nm','-g','--defined-only',str(prefix/'lib'/library_name)],capture_output=True,timeout=120,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
  assert result.returncode==0;actual_symbols=m.validate_target_symbols(result.stdout,row);assert actual_symbols['all_defined_names']==symbols['all_defined_names'];host_nm=True
 events=m.decode(m.raw_file(folder/'target-python-commands.json'))
 assert len(receipt['tasks'])==len(spec['tasks'])==4
 for actual,expected in zip(receipt['tasks'],spec['tasks']):
  assert all(actual[k]==expected[k] for k in ('index','name','task','kind','function_sha256')) and actual['original_Task_run_executed'] is True and actual['operations']==len(expected['operations'][arch])
 expected_runs=[operation[1] for task in spec['tasks'] for operation in task['operations'][arch] if operation[0]=='run']
 assert [event['template'] for event in events if event['operation']=='run']==expected_runs and all(event['returncode']==0 for event in events if event['operation']=='run')
 for event in events:
  if event['operation']=='generate':
   relative=pathlib.Path(event['path']).relative_to(original_python);assert pax_identity(python_root/relative)=={k:event[k] for k in ('bytes','sha256')}
 generated=m.decode(m.raw_file(folder/'target-scproxy-generation.json'));assert pax_identity(python_root/'Modules/_scproxy.c')=={'bytes':generated['generated_bytes'],'sha256':generated['generated_sha256']}
 assert m.raw_file(python_root/'config.site',4096).decode()==spec['config_site']==receipt['config_site']
 before=m.decode(m.raw_file(folder/'target-host-before.json'));after=m.decode(m.raw_file(folder/'target-host-after.json'));delta=m.decode(m.raw_file(folder/'target-host-delta.json'))
 assert pax_identity(folder/'target-host-before.json')==plan['host_producers'][release]['inventory']
 assert m.inventory_delta(before,after)==delta
 cp39_candidate_verified=verify_cp39_build_context()
 framework_binding_verified=verify_target_framework_receipt()
 ensure=receipt['implicit_install_ensurepip'];assert ensure['explicit_pip_Task_executed'] is False and ensure['target_pip_bound'] is False
 for name,key in [('target-host-before.json','host_before_sha256'),('target-host-after.json','host_after_sha256'),('target-host-delta.json','host_delta_sha256')]:assert pax_identity(folder/name)['sha256']==ensure[key]
 relocated_events=[]
 for event in events:
  copied=dict(event)
  if event['operation']=='run':
   log=event['raw_command_log'];original=pathlib.Path(log['path']);assert original.parent==pathlib.Path(receipt['C_receipt']['path']).parent and re.fullmatch(r'target-python-command-[0-9]{3}\.log',original.name)
   assert pax_identity(folder/original.name)=={k:log[k] for k in ('bytes','sha256')}
   copied['raw_command_log']={**log,'path':str(folder/original.name)}
  relocated_events.append(copied)
 observed_ensure=m.implicit_ensurepip_evidence(relocated_events,spec,original_prefix.parent/'host')
 original_ensure=m.decode(m.raw_file(folder/'target-implicit-ensurepip.json'))
 assert {k:v for k,v in observed_ensure.items() if k!='make_install_log'}=={k:v for k,v in original_ensure.items() if k!='make_install_log'}
 assert {k:observed_ensure['make_install_log'][k] for k in ('bytes','sha256')}=={k:original_ensure['make_install_log'][k] for k in ('bytes','sha256')}
 framework=next(x for x in row['extra_inputs'] if x['path']==('source/MetalANGLE.framework.ios.zip' if arch=='arm64' else 'source/MetalANGLE.framework.ios.simulator.zip'))
 assert pax_identity(workspace/framework['path'])=={'bytes':framework['size'],'sha256':framework['sha256']};m.verify_framework(workspace/framework['path'],prefix,arch,inventory)
 result={'release':release,'arch':arch,'target_python_install_verified':True,'full_inventory_members':len(entries),'stdlib_sources':len(stdlib_records),
  'MachO_archive_objects':sum(len(a['objects']) for a in archives),'hostcopy_verified':True,'original_framework_verified':True,'container_nm_reexecuted':True,
  'libpython_build_object_occurrences':libpython_layout['object_count'],'libpython_unique_member_names':libpython_layout['unique_member_names'],
  'libpython_duplicate_counts':libpython_layout['duplicate_counts'],'libpython_each_original_object_occurrence_verified':True,
  'host_nm_recomputed':host_nm,'CP39_build_context_candidate_verified':cp39_candidate_verified,
  'B_framework_link_argument_binding_verified':framework_binding_verified,
  'stdlib_changed_since_post_patch_snapshot':stdlib_changes,'returned_binary_executed_on_host':False,'target_pip_bound':False,'ios_runtime_verified':False}
finally:
 for temporary in (prefix,python_root):
  if temporary.exists():shutil.rmtree(temporary)
print(json.dumps(result))
'''

SNAPSHOT_FAILED_TARGET = TARGET_PAX + r'''import json,sys,types
metadata,release,arch,worker_sha=sys.argv[1:];metadata=pathlib.Path(metadata)
p=metadata/'scripts/renpy/run_locked_target_python_tasks.py';raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()==worker_sha
m=types.ModuleType('reko_j9_B_failed_snapshot');m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__)
plan=m.load_plan();inventory,*_=m.helpers(plan);row=next(r for r in plan['routes'] if r['release']==release);spec=next(r for r in plan['target_install']['routes'] if r['release']==release)
workspace=pathlib.Path('/reko/j9-workspaces')/release/arch;build,_=m.expected_paths(workspace,row,arch,spec['tasks'][0]);python_root=build/spec['archive']['root']
target=pathlib.Path('/reko/j9-failed-snapshots')/release/arch;target.mkdir(parents=True);stage=target/'staged-regular-diagnostic';stage.mkdir(mode=0o700)
missing=[];links=[];rejected=[];diagnostic_object_paths=None
def capture(source,relative):
 """诊断只复制受控普通原件；链接仅登记原文，绝不跟随或物化到诊断tar。"""
 if relative.startswith('/') or chr(92) in relative or chr(0) in relative or any(p in ('','.','..') for p in relative.split('/')):rejected.append({'path':relative,'reason':'invalid_path'});return
 if any(p.is_symlink() for p in (source,*source.parents)):
  if source.is_symlink():links.append({'path':relative,'target':os.readlink(source)})
  else:rejected.append({'path':relative,'reason':'parent_link'})
  return
 if not source.exists():missing.append(relative);return
 mode=source.lstat().st_mode;destination=stage/relative
 if stat.S_ISDIR(mode):
  destination.mkdir(parents=True,exist_ok=True)
  for child in sorted(source.iterdir()):
   if child.name.endswith('.sdk') or child.name in ('SDKSettings.json','locked-sdk-tars'):rejected.append({'path':relative+'/'+child.name,'reason':'SDK_scope'});continue
   capture(child,relative+'/'+child.name)
 elif stat.S_ISREG(mode):
  try:
   expected=pax_identity(source);destination.parent.mkdir(parents=True,exist_ok=True)
   with source.open('rb') as inp,destination.open('xb') as out:shutil.copyfileobj(inp,out,262144)
   assert pax_identity(destination)==expected;destination.chmod(stat.S_IMODE(mode))
  except Exception:
   if destination.is_file() and not destination.is_symlink():destination.unlink()
   rejected.append({'path':relative,'reason':'unstable_or_unreadable'})
 else:rejected.append({'path':relative,'reason':'special_file'})
def capture_libpython_objects(projection_path):
 """只从已写实际投影和原模板取得明确.o列表；不执行Makefile，不扫描整个build。"""
 global diagnostic_object_paths
 try:
  if projection_path.exists():
   projection=m.decode(m.raw_file(projection_path));source=plan['target_install']['libpython_layout']['routes'][release];template=source['makefile_template']
   diagnostic_object_paths=m.parse_libpython_object_paths(m.raw_file(python_root/'Makefile'),m.raw_file(python_root/template['path']),projection,source)
   capture(python_root/template['path'],'proof/'+template['path'])
   for name in sorted(set(diagnostic_object_paths)):capture(python_root/name,'proof/'+name)
  else:missing.append('proof/libpython-source-object-list')
 except Exception:rejected.append({'path':'proof/libpython-source-object-list','reason':'original_object_list_unavailable'})
try:
 capture(workspace/('tmp/install.ios-'+arch),'prefix')
 for name in ('Lib','Makefile','pyconfig.h','pybuilddir.txt','config.site','LICENSE','Include/Python.h','Modules/_scproxy.c','Modules/Setup.local'):
  capture(python_root/name,'proof/'+name)
 capture_libpython_objects(pathlib.Path('/reko/j9-results')/release/arch/'target-make-projection.json')
 path=python_root/'pybuilddir.txt'
 if path.is_file() and not path.is_symlink():
  directory=m.raw_file(path,4096).decode().strip()
  if directory and not directory.startswith('/') and all(p not in ('','.','..') for p in directory.split('/')):
   parent=python_root/directory
   if parent.is_dir() and not parent.is_symlink():
    for path in sorted(parent.glob('_sysconfigdata*.py')):capture(path,'proof/'+directory+'/'+path.name)
   else:missing.append('proof/'+directory+'/_sysconfigdata*.py')
  else:rejected.append({'path':'proof/pybuilddir.txt','reason':'invalid_build_directory'})
 entries=m.inventory_tree(stage,inventory) if any(stage.iterdir()) else [];archive=target/'target-diagnostic.tar.gz';identity=pax_write(stage,entries,archive) if entries else None
 manifest={'kind':'target-install-diagnostic-only','diagnostic_only':True,'target_success':False,'target_python_install_verified':False,
  'release':release,'arch':arch,'worker_sha256':worker_sha,'plan_sha256':m.PLAN_SHA256,'archive':identity,'members':entries,
  'missing':missing,'links_recorded_not_materialized':links,'rejected_entries':rejected,'SDK_cross_tree_included':False,'host_distribution_tree_included':False}
 manifest['libpython_object_paths_in_original_order']=diagnostic_object_paths
 with (target/'target-diagnostic-identity.json').open('x') as stream:json.dump(manifest,stream,ensure_ascii=False,indent=2);stream.write('\n')
 print(json.dumps({'diagnostic_only':True,'target_success':False,'regular_diagnostic_members':len(entries),'missing_count':len(missing)}))
finally:shutil.rmtree(stage)
'''


class InputUnavailable(ValueError):
    """必要实物或运行条件不存在时记未运行，不伪造本阶段成功。"""


class RunInterrupted(BaseException):
    """CLI取消必须穿过cell的Exception捕获，执行既有日志回收和容器清理。"""


def phase_profile(plan, phase):
    """默认C沿用原七件身份；B仅选择独立已提交profile，不浮动旧C输入。"""
    require(phase in ("c-prerequisites", "target-install"), "未批准phase")
    return plan if phase == "c-prerequisites" else plan["target_install"]


def validate_target_install_eligibility(plan):
    """只绑定原12scope C资格的完整身份/投影；不推断B产品或复用旧C完成状态。"""
    target = plan["target_install"];basis = target["approved_C_basis"]
    canonical = json.dumps(basis, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    require(hashlib.sha256(canonical).hexdigest() == C_ELIGIBILITY_SHA256, "C资格不是完整92bc结果锁的批准投影")
    expected = {(group, release, arch) for group, releases in GROUPS.items() for release in releases for arch in ARCHES}
    require(type(basis["accepted_scope_count"]) is int and basis["accepted_scope_count"] == len(expected) == 12
            and basis["eligibility_only"] is True and basis["B_product_verification_inferred"] is False,
            "历史C资格不能被改标为B验收")
    scopes = basis["scopes"]
    require(len(scopes) == 12 and {(row["ubuntu"], row["release"], row["arch"]) for row in scopes} == expected
            and all(row["C_prerequisites_verified"] is True for row in scopes), "C原资格缺失/重复或未验收")
    cells = target["allowed_cells"]
    require(isinstance(cells, list) and len(cells) == 12
            and all(isinstance(row, dict) and set(row) == {"ubuntu", "release", "arch"} for row in cells)
            and {(row["ubuntu"], row["release"], row["arch"]) for row in cells} == expected,
            "B只允许四版三架构的12个精确C资格选择")


def validate_phase_selection(args, plan):
    """B必须显式选择已有独立C验收的tuple，不能默认扩展到所有route/arch。"""
    if args.phase == "target-install":
        require(bool(args.release) and bool(args.arch), "target-install必须显式release和arch")
        allowed = {(r["ubuntu"], r["release"], r["arch"]) for r in plan["target_install"]["allowed_cells"]}
        require(all((args.ubuntu, r, a) in allowed for r in args.releases for a in args.arches), "target-install选择尚无批准C验收")


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
    allowed = {"inputs", "transport", "environment", "host_frontend", "host_restore", "sdk_toolchain", "c_prerequisites", "target_install", "preserve"}
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


def fresh_runtime_check(destination, output, worker_sha, phase="c-prerequisites"):
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
target=sys.argv[4]=='target-install'
if target:assert plan['target_install']['task']=='R00-02J9B' and len(plan['target_install']['routes'])==4
print(json.dumps({'J9_dependencies_and_locks_verified':True,'H1_old_dependency_contract_verified':True,'source_evidence_count':18,'replay_scope_count':9,'original_CPython_archive_installers_verified':3,'runtime_anchor_sha256':source['runtime_anchor_sha256'],'target_install_contract_verified':target,'C_tasks_executed':False}))
'''
    result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(destination), worker_sha, str(output), phase], capture_output=True, timeout=180)
    (output / "fresh-runtime.stdout").write_bytes(result.stdout);(output / "fresh-runtime.stderr").write_bytes(result.stderr)
    require(result.returncode == 0, "J9派生root独立合同失败")
    value = json.loads(result.stdout)
    require(value["J9_dependencies_and_locks_verified"] is True and value["H1_old_dependency_contract_verified"] is True
            and value["source_evidence_count"] == 18 and value["replay_scope_count"] == 9
            and value["original_CPython_archive_installers_verified"] == 3 and value["C_tasks_executed"] is False, "J9派生root验证范围错误")
    return value


def worker_argv(release, arch, metadata, workspace, output, sdk, clang_runtime, host, frontend_sha, producer, ccache=None, phase="c-prerequisites"):
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
    require(phase in ("c-prerequisites", "target-install"), "worker phase未批准")
    if phase == "target-install":argv += ["--phase", "target-install"]
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


def verify_returned_target(metadata, directory, workspace, worker_sha, output):
    """B只读复核完整PAX/stdlib/config/每native对象和原框架，不执行回传二进制。"""
    result = subprocess.run([sys.executable, "-I", "-B", "-c", VERIFY_TARGET_EXPORT, str(metadata), str(directory), str(workspace), worker_sha],
                            capture_output=True, timeout=600)
    (output / "target-product-verification.stdout").write_bytes(result.stdout)
    (output / "target-product-verification.stderr").write_bytes(result.stderr)
    require(result.returncode == 0, "回传B前缀/源码证明/静态模块/配置未通过")
    value = json.loads(result.stdout)
    require(value["target_python_install_verified"] is True and value["returned_binary_executed_on_host"] is False
            and value["target_pip_bound"] is False, "B读取器验证范围不符")
    return value


def snapshot_target_failure(run, system_python, release, arch, profile):
    """仅诊断回收已存在的B源码/配置/前缀，失败不提升成成功receipt。"""
    run.run([system_python, "-B", "-c", SNAPSHOT_FAILED_TARGET, REMOTE_ROOT, release, arch, profile["worker"]["sha256"]],
            "j9-B-diagnostic-snapshot-" + release + "-" + arch)
    local = run.output / "failed-target-snapshots" / release;local.mkdir(parents=True, exist_ok=True)
    run.host([run.docker, "cp", run.name + ":/reko/j9-failed-snapshots/" + release + "/" + arch, str(local / arch)],
             "j9-copy-B-diagnostic-snapshot-" + release + "-" + arch)


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
    report["active_stage"] = "target_install" if args.phase == "target-install" else "c_prerequisites"
    cells = [(release, arch) for release in args.releases for arch in args.arches]
    profile = phase_profile(plan, args.phase)
    interrupted_cell = None
    try:
        for release, arch in cells:
            row = next(r for r in report["cells"] if r["release"] == release and r["arch"] == arch)
            if release not in restored:
                row.update(status="not_run", reason_code="missing_complete_host_export");continue
            local_workspace = workspaces / release / arch
            remote_workspace = REMOTE_WORKSPACES + "/" + release + "/" + arch
            remote_output = REMOTE_OUTPUT + "/" + release + "/" + arch
            try:
                row["status"] = "running"
                run.run(["mkdir", "-p", remote_workspace], "j9-workspace-directory-" + release + "-" + arch)
                run.copy(str(local_workspace) + "/.", remote_workspace, "j9-copy-full-recipe-" + release + "-" + arch)
                scope = next(s for s in frontend["scopes"] if s["id"] == plan["frontend_scopes"][release])
                require(scope["status"] == "offline_replayed", "当前H0前端未真实通过")
                frontend_python = scope["environment"]["prefix"] + "/bin/python"
                sdk = "/reko/private/" + ("device_sdk" if arch == "arm64" else "simulator_sdk") + ".tar.gz"
                command = [frontend_python, "-s", "-B", *worker_argv(release, arch, REMOTE_ROOT, remote_workspace, remote_output,
                           sdk, "/reko/private/clang_runtime.tar.gz", restored[release]["prefix"], frontend_sha,
                           plan["host_producers"][release], "/reko/j9-ccache" if args.ccache else None, args.phase)]
                run.commands.run([run.docker, "exec", run.name, "env", "-i", "PATH=" + str(Path(frontend_python).parent) + ":/usr/sbin:/usr/bin:/sbin:/bin",
                                  "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC", "DEBIAN_FRONTEND=noninteractive", "PYTHONHASHSEED=0",
                                  "PYTHONDONTWRITEBYTECODE=1", *command], "j9-original-C-tasks-" + release + "-" + arch, timeout=15000)
                if args.phase == "target-install":
                    run.run([system_python, "-B", "-c", EXPORT_TARGET_PREFIX, REMOTE_ROOT, release, arch, profile["worker"]["sha256"], json.dumps(TARGET_SIDECARS)], "j9-export-B-prefix-" + release + "-" + arch)
                else:
                    run.run([system_python, "-B", "-c", EXPORT_C_PREFIX, REMOTE_ROOT, release, arch, profile["worker"]["sha256"]], "j9-export-C-prefix-" + release + "-" + arch)
                local = run.output / "private-products" / release;local.mkdir(parents=True, exist_ok=True)
                run.host([run.docker, "cp", run.name + ":/reko/j9-private-products/" + release + "/" + arch, str(local / arch)], "j9-copy-private-C-products-" + release + "-" + arch)
                if args.phase == "target-install":
                    verification = verify_returned_target(metadata, local / arch, local_workspace, profile["worker"]["sha256"], local / arch)
                    require((verification["release"], verification["arch"]) == (release, arch), "B回传route/arch不对应当前cell")
                    row.update(status="target_python_install_verified", product_verification=verification, export=file_identity(local / arch / "target-export.json"))
                else:
                    verification = verify_returned_products(metadata, local / arch, local_workspace, profile["worker"]["sha256"], local / arch)
                    require((verification["release"], verification["arch"]) == (release, arch), "C回传route/arch不对应当前cell")
                    row.update(status="C_prerequisites_verified", product_verification=verification, export=file_identity(local / arch / "export.json"))
                row["producer_plan_sha256"] = selected[release]["producer"]["execution_plan_sha256"]
            except Exception as error:
                row.update(status="failed", failure=public_failure(error, "target_install" if args.phase == "target-install" else "c_prerequisites"))
                failure = run.output / ("failure-" + release + "-" + arch + ".json")
                write_json(failure, {"type": type(error).__name__, "private_message": str(error)})
                if args.phase == "target-install":
                    try:snapshot_target_failure(run, system_python, release, arch, profile)
                    except Exception as diagnostic_error:write_json(run.output / ("snapshot-failure-" + release + "-" + arch + ".json"), {"kind": type(diagnostic_error).__name__, "private_message": str(diagnostic_error), "target_success": False})
            except RunInterrupted:
                interrupted_cell = release, arch
                row.update(status="interrupted", failure={"stage": report["active_stage"], "kind": "RunInterrupted", "code": "cancelled"})
                raise
    finally:
        try:preserve_private(run, system_python, cells)
        finally:
            if interrupted_cell is not None and args.phase == "target-install":
                release, arch = interrupted_cell
                try:snapshot_target_failure(run, system_python, release, arch, profile)
                except Exception as error:write_json(run.output / ("snapshot-interrupted-" + release + "-" + arch + ".json"), {"kind": type(error).__name__, "target_success": False, "incomplete_cancel_snapshot": True})


def load_plan(path=DEFAULT_PLAN):
    """独立SHA锚定两producer、七增量和21原worker依赖，不接受未知profile或stage。"""
    raw = regular_bytes(path, 1024 * 1024)
    require(hashlib.sha256(raw).hexdigest() == PLAN_SHA256, "J9D固定计划字节改变")
    plan = json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=reject_nonfinite)
    require(set(plan) == {"schema_version", "task", "scope", "groups", "architectures", "helpers", "producer_profiles",
                          "host_producers", "frontend_scopes", "worker", "metadata_addon", "metadata_source_commit", "auditor_functions", "limitations", "target_install"}
            and type(plan["schema_version"]) is int and plan["schema_version"] == 1 and plan["task"] == "R00-02J9D"
            and plan["scope"] == "same_C1_H0_H1_original_iOS_C_prerequisites_only_no_target_python_or_pip"
            and plan["groups"] == GROUPS and plan["architectures"] == list(ARCHES)
            and re.fullmatch("[0-9a-f]{40}", plan["metadata_source_commit"]), "J9D固定阶段/范围错误")
    validate_addon_catalog(plan["metadata_addon"])
    target = plan["target_install"];validate_addon_catalog(target["metadata_addon"])
    require(target["task"] == "R00-02J9B" and target["metadata_source_commit"] == "6d6172ec386bfcd6d97f9a3f08f31220edb2907c", "B原件不是固定提交")
    validate_target_install_eligibility(plan)
    expected = {"run_locked_target_python_tasks.py", "target-python-prefix-plan.json", "validate_lock.py", "build_common.py",
                "materialize_source_inputs.py", "remote-sources.lock.json", "runtime-lock.json"}
    require(len(plan["metadata_addon"]) == 7 and {Path(r["path"]).name for r in plan["metadata_addon"]} == expected
            and len(target["metadata_addon"]) == 7 and {Path(r["path"]).name for r in target["metadata_addon"]} == expected
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
    profile = phase_profile(plan, args.phase)
    runtime_addon = private / "runtime-addon";extract_runtime_addon(args.h2, args.runtime_addon, runtime_addon, profile["metadata_addon"])
    metadata = private / "metadata/root"
    rows = prepare_runtime(h0, h1, payload, recipe_addon, recipe_manifest, h0_plan, runtime_addon, profile["metadata_addon"], metadata)
    worker_plan = read_json(metadata / "scripts/renpy/target-python-prefix-plan.json")
    require(worker_plan["host_producers"] == plan["host_producers"]
            and file_identity(metadata / "scripts/renpy/run_locked_target_python_tasks.py") == {k:profile["worker"][k] for k in ("bytes", "sha256")}, "worker/source producer合同不符")
    fresh = diagnostics / "fresh-runtime";fresh.mkdir()
    proof = fresh_runtime_check(metadata, fresh, profile["worker"]["sha256"], args.phase)
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
    result.add_argument("--phase", choices=("c-prerequisites", "target-install"), default="c-prerequisites")
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
              "phase":args.phase,
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
        validate_phase_selection(args, plan)
        if args.phase == "target-install":report.update(task="R00-02J9D-B", scope=plan["target_install"]["scope"])
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
        expected = "target_python_install_verified" if args.phase == "target-install" else "C_prerequisites_verified"
        if all(row["status"] == expected for row in report["cells"]):
            report.update(result="selected_original_target_python_install_verified" if args.phase == "target-install" else "selected_original_C_prerequisites_verified",C_prerequisites_verified=True)
            if args.phase == "target-install":report["target_python_install_verified"] = True
        else:report["result"] = ("failed_target_python_install" if args.phase == "target-install" else "failed_C_prerequisites") if any(row["status"] == "failed" for row in report["cells"]) else "not_run"
    except RunInterrupted:
        report.update(result="interrupted", C_prerequisites_verified=False, target_python_install_verified=False,
                      interrupted_diagnostics_best_effort=True, cancellation_grace_not_guaranteed=True)
        report["errors"].append({"stage":report.get("active_stage",stage),"kind":"RunInterrupted","code":"cancelled"})
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
    return 0 if report["C_prerequisites_verified"] else 130 if report["result"] == "interrupted" else 3 if report["result"] == "not_run" else 1


def cli_main(argv=None):
    """仅CLI将SIGTERM桥接为不可被cell吞掉的中断，给既有finally保全机会。"""
    previous = signal.getsignal(signal.SIGTERM)
    def terminate(signum, frame):
        """首次取消后禁止重入；GitHub的SIGKILL宽限仍不能保证或伪报完成。"""
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise RunInterrupted()
    signal.signal(signal.SIGTERM, terminate)
    try:
        try:return main(argv)
        except RunInterrupted:log("报告创建前已中断；未声明任何构建通过");return 130
    finally:signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(cli_main())
