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
# 独立SHA绑定真实08运输、原D及已提交pip/导出工具，不接受浮动输入。
PLAN_SHA256 = "a0532f644db62d174b2de9cde7c123dbe264945e71cc49bb20668816cd067480"
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

PRESERVE_PIP_FAILURE = r'''import hashlib,json,pathlib,shutil,stat,sys,types
source,destination,tool,toolsha,planpath=sys.argv[1:];source=pathlib.Path(source);destination=pathlib.Path(destination)
raw=pathlib.Path(tool).read_bytes();assert hashlib.sha256(raw).hexdigest()==toolsha
m=types.ModuleType('j9c_failure_allowlist');m.__file__=tool;exec(compile(raw,tool,'exec'),m.__dict__)
plan=json.loads(pathlib.Path(planpath).read_bytes());destination.mkdir();rows=[];total=0
if source.exists():
 for p in sorted(source.rglob('*')):
  name=p.relative_to(source).as_posix();info=p.lstat()
  if not stat.S_ISREG(info.st_mode) or not m.result_allowed(name,plan):continue
  assert info.st_size<=33554432;total+=info.st_size;assert total<=134217728 and len(rows)<1000
  target=destination/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,target)
  rows.append({'path':name,'bytes':info.st_size,'sha256':hashlib.sha256(target.read_bytes()).hexdigest()})
(destination/'failure-preservation.json').write_text(json.dumps({'diagnostic_only':True,'target_pip_bound':False,'files':rows},indent=2)+'\n')
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
    """08只有四个普通文本成员，逐字节核对且禁止目录、链接或PAX。"""
    expected = {row["path"]: row for row in catalog}; seen = set(); destination.mkdir(mode=0o700)
    with tarfile.open(archive, "r:gz") as source:
        for item in source:
            require(item.name in expected and item.name not in seen and item.isfile() and not item.sparse and not item.pax_headers
                    and item.mode == 0o644 and item.uid == item.gid == item.mtime == 0, "08文本包成员或模式错误")
            row = expected[item.name]; require(item.size == row["bytes"], "08文本成员大小错误"); seen.add(item.name)
            with source.extractfile(item) as stream, (destination / item.name).open("xb") as output:
                body = stream.read(row["bytes"] + 1); require(len(body) == row["bytes"], "08文本成员长度错误"); output.write(body)
            checked(destination / item.name, row)
    require(seen == set(expected), "08文本包缺项")


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


def preserve_failure(run, system_python, plan, diagnostics):
    """失败只回收有限白名单原控制日志，不扫描SDK/工作区或回传完整目标。"""
    worker = next(row for row in plan["text_runtime_catalog"] if row["path"] == "run_target_pip_export.py")
    destination = "/reko/j9c-failure-evidence"
    run.run([system_python, "-B", "-c", PRESERVE_PIP_FAILURE, REMOTE_RESULTS, destination,
             REMOTE_CODE + "/run_target_pip_export.py", worker["sha256"], REMOTE_CODE + "/target-pip-export-plan.json"], "j9c-preserve-failure-controls")
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
        require("pip_runtime_addon" in plan, "计划尚未绑定实际08公开运输身份，禁止执行")
        require(identity(args.pip_addon, plan["limits"]["text_addon_bytes"])["bytes"] > 0, "08文本包为空或超限")
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
