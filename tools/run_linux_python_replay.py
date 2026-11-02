#!/usr/bin/env python3
"""在固定 C1 容器实际重放四个 host 前端 scope；只验 H0，不关闭九 scope 的 J2C。"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys
import types


DEFAULT_PLAN = Path(__file__).with_name("python-linux-host-replay-plan.json")
SCOPES = {"24.04": ["8.5.3-host-ci-success", "8.4.1-host-recipe"],
          "22.04": ["8.3.7-host-recipe", "7.8.7-host-recipe"]}
ALL_SCOPES = {"8.5.3-host-ci-success", "8.5.3-target-ci-success", "8.5.3-target-recipe", "8.4.1-host-recipe",
              "8.4.1-target-recipe", "8.3.7-host-recipe", "8.3.7-target-recipe", "7.8.7-host-recipe", "7.8.7-target-recipe"}
PINS = {
    "root/scripts/renpy/lock_python_inputs.py": "eece439195f241cd7a3533e26404f68e4a294636c3a8366d9dde9bc27403468d",
    "root/scripts/renpy/build_python_wheels.py": "829712b376ce71ccd39f36299ba2f5e09eb92ba7c21a21f9134ec11e2f2391a6",
    "root/scripts/renpy/replay_python_inputs.py": "fb463fc09b482142e4ea2080c554351429a18081468f6ac502fd6f90e788e7f2",
    "root/scripts/renpy/python-inputs.lock.json": "4a9a85b719dd1ef3fb5ded2fcd383f5c9bd8925c0e537bd8f5db0a1132602935",
    "root/scripts/renpy/python-wheel-build-plan.json": "9b231a3a1460180ed1de53474669e0eba786df3a4ff70da981b87eece89cdea4",
    "root/scripts/renpy/python-replay-plan.json": "89763ed8ba512a39dd2c63c4e3d871354de300064638ea3b5272294e6428fef4",
    "root/scripts/renpy/source-inputs.lock.json": "eb8352943bc3e6952f053273e27a3f913dafda9e193de36bcceb083367b81a37",
    "c1-runtime/preflight_environment.py": "c4584adae0e197c3c934bba0e5d00f08307788ef819707e640e3d12513f74839",
    "c1-runtime/materialize_apt_inputs.py": "f0644a862ea95fcafb27e78ab27c8232b5d8c128a1d59cce179f164aa7ddf4ac",
    "c1-runtime/build_linux_python_wheels.py": "0ea0fe3ad88a80e73f7986602b69ab4a79fe290c10bcca13c8bca192fbedd3d8",
    "c1-runtime/apt-inputs.lock.json": "2a69077d989f78713a42ee474574baae741bdc45fd443f314bda7c73124a6685",
    "c1-runtime/environment-preflight.lock.json": "e52c45aebed4359adce14a4f89084dde9cdd3573eeab96717a4fbff23854a56f",
    "receipts/py3/report.json": "1807c50c946a46b17fc0ae83e362caaffdb94191086f8f39a63d64d9f74534cd",
}
IMAGES = {"24.04": ("docker.io/library/ubuntu@sha256:a2d43bffc46670d7108bb3c0468c67c5557c4c92e83e1e34cbff1322ad1b94dc", "5b95f5dbd2490bc262a0d3150211bcc09178b3c452967829590b235314550d6d"),
          "22.04": ("docker.io/library/ubuntu@sha256:98510ac07bb4545e389be502a8918b385c018bfe4ceeb5ac7e0375c782268b04", "d722e3aa9db55925062e70a35486e1e0b1405c064a6dc5a8b7a289900d5c6851")}
IMAGE_IDS = {"24.04": "sha256:6277ab668b2ad3c3ab851d370faa1690d324b30db29d342527f61fed28f20f36",
             "22.04": "sha256:cee13550f97b8a595506e8e4ca74263ba44924248779a4ba4f942e197652acff"}
REMOTE = "/reko/h0-inputs"
REPLAY_OUTPUT = "/reko/h0-replay"
_MODULES = {}
PRESERVE = r'''import pathlib,re,shutil,stat,sys
source=pathlib.Path('/reko/h0-replay');target=pathlib.Path('/reko/h0-results');target.mkdir()
def copy(p):
 """只复制公开报告/命令日志，保留真实失败，不回传环境或未列输入。"""
 if p.is_symlink() or not stat.S_ISREG(p.lstat().st_mode):raise ValueError('unsafe result file')
 q=target/p.relative_to(source);q.parent.mkdir(parents=True,exist_ok=True)
 with q.open('xb') as f:f.write(p.read_bytes())
if (source/'report.json').is_file():copy(source/'report.json')
for name in sys.argv[1:]:
 for folder in [source/name,source/name/'identity-probe']:
  if not folder.is_dir():continue
  if folder.is_symlink():raise ValueError('unsafe result directory')
  for p in folder.iterdir():
   if p.name=='commands.json' or re.fullmatch(r'command-[0-9]+-(stdout|stderr)\.log',p.name):copy(p)
'''


def require(value, message):
    """证据或实际状态不足立即失败，不以默认成功填补。"""
    if not value:
        raise ValueError(message)


def log(message):
    """统一输出实际阶段及拒绝原因。"""
    print("[RenPyLinuxHostReplay] " + message, flush=True)


def regular(path):
    """拒绝任意层链接/点段；只允许受控实际路径。"""
    path = Path(path)
    require(".." not in path.parts, "路径包含父目录点段")
    path = path.absolute()
    require(not any(p.is_symlink() for p in [path, *path.parents]), "路径包含符号链接或链接父目录")
    return path


def read(path, maximum=256 * 1024**2):
    """有界读取普通原字节，不沿叶链接或特殊设备。"""
    path = regular(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, "输入不是有界普通文件")
        data = stream.read(maximum + 1)
        require(len(data) == info.st_size and len(data) <= maximum, "读取期间文件长度改变")
    return data


def digest(data):
    """计算实际完整字节摘要。"""
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    """JSON重复键不可更改最终验收含义。"""
    result = {}
    for key, value in pairs:
        require(key not in result, "JSON键重复")
        result[key] = value
    return result


def decode(data):
    """严格解析UTF8 JSON，拒绝非标准数值。"""
    return json.loads(data, object_pairs_hook=unique, parse_constant=lambda value: (_ for _ in ()).throw(ValueError("非法JSON数值")))


def write(path, value):
    """独占写新报告，不覆盖旧证据。"""
    path = regular(path)
    with path.open("xb") as stream:
        stream.write((json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode())


def safe_name(name):
    """只接纳规范相对文件路径，拒绝别名、控制字符与目录跳转。"""
    require(isinstance(name, str) and name and not name.startswith("/") and "\\" not in name
            and not any(ord(c) < 32 for c in name) and all(p not in ("", ".", "..", ".git") for p in name.split("/")), "输入相对路径越界")
    return name


def load_plan(path, expected):
    """独立SHA和编译锚点共同绑定103原件与两组host职责；不接纳任意任务。"""
    raw = read(path, 256 * 1024)
    require(re.fullmatch(r"[a-f0-9]{64}", expected or "") and digest(raw) == expected, "H0计划独立SHA不符")
    plan = decode(raw)
    require(set(plan) == {"schema_version", "task", "scope", "files", "groups", "limitations"}
            and type(plan["schema_version"]) is int and plan["schema_version"] == 1
            and plan["task"] == "R00-02J2C-H0" and plan["scope"] == "four_linux_host_frontend_scopes_only", "H0 schema/scope错误")
    require(isinstance(plan["files"], list) and len(plan["files"]) == 103, "H0原件集合不是固定103项")
    seen = {}
    for row in plan["files"]:
        require(set(row) == {"path", "bytes", "sha256"} and type(row["bytes"]) is int and 0 < row["bytes"] <= 128 * 1024**2
                and re.fullmatch(r"[a-f0-9]{64}", row["sha256"]), "H0逐文件身份错误")
        name = safe_name(row["path"])
        require(name.casefold() not in seen, "H0文件重复/大小写别名")
        seen[name.casefold()] = row
    require(all(name.casefold() in seen and seen[name.casefold()]["path"] == name and seen[name.casefold()]["sha256"] == sha
                for name, sha in PINS.items()), "原工具/JSON/Darwin收据未获独立批准")
    require(isinstance(plan["groups"], list) and len(plan["groups"]) == 2 and {g["ubuntu"] for g in plan["groups"]} == set(SCOPES), "H0两环境缺失/重复")
    for group in plan["groups"]:
        require(set(group) == {"ubuntu", "image", "image_id", "manifest_sha256", "scopes"}
                and group["scopes"] == SCOPES[group["ubuntu"]]
                and (group["image"], group["manifest_sha256"]) == IMAGES[group["ubuntu"]]
                and group["image_id"] == IMAGE_IDS[group["ubuntu"]], "H0环境/范围未批准")
    require(isinstance(plan["limitations"], list) and plan["limitations"] and all(isinstance(v, str) and v for v in plan["limitations"]), "H0缺职责边界")
    return plan


def verify_files(payload, rows):
    """完整逐文件重算，拒绝缺件、多项、链接、忽略文件和假stat命中。"""
    payload = regular(payload);require(payload.is_dir(), "缺少实际H0输入目录")
    expected = {row["path"]: row for row in rows};actual = set()
    for parent, directories, files in os.walk(payload, followlinks=False):
        require(not any((Path(parent) / name).is_symlink() for name in directories), "输入目录含链接")
        for name in files:
            path = Path(parent) / name;relative = safe_name(path.relative_to(payload).as_posix())
            require(relative in expected, "H0输入多出未登记文件：" + relative)
            row = expected[relative];raw = read(path, row["bytes"])
            require(len(raw) == row["bytes"] and digest(raw) == row["sha256"], "H0原件实际身份不符：" + relative)
            actual.add(relative)
    require(actual == set(expected), "H0输入缺少必要原文件")


def load_module(path, sha, name):
    """直接编译已验原源字节，拒绝环境同名模块或旧pyc改变实际执行代码。"""
    path = regular(path);raw = read(path, 256 * 1024)
    require(digest(raw) == sha, "加载工具SHA改变")
    previous = sys.modules.get(name)
    if previous is not None:
        require(previous is _MODULES.get(name) and Path(previous.__file__) == path, "环境已有非本入口加载的同名工具")
        return previous
    module = types.ModuleType(name);module.__file__ = str(path);module.__package__ = "";sys.modules[name] = module
    try:
        exec(compile(raw, str(path), "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    _MODULES[name] = module
    return module


def verify_original_contracts(payload, catalog):
    """实际复用原校验器核完整九scope来源、旧Darwin收据及四host依赖；不运行安装。"""
    modules = {}
    for name in ("lock_python_inputs", "build_python_wheels", "replay_python_inputs"):
        relative = "root/scripts/renpy/" + name + ".py"
        modules[name] = load_module(payload / relative, PINS[relative], name)
    inputs, builder, replay = [modules[name] for name in ("lock_python_inputs", "build_python_wheels", "replay_python_inputs")]
    plan, build_plan, manifest, sha = replay.load_plan(payload / "root/scripts/renpy/python-replay-plan.json")
    evidence = inputs.verify_evidence(manifest["scopes"])
    require(len(evidence) == 18, "原九scope证据集合改变")
    parser = inputs.load_parser(payload / "cache", manifest)
    products, receipts = replay.read_build_receipts([payload / "receipts/py3/report.json"], [PINS["receipts/py3/report.json"]],
        build_plan, manifest, payload / "cache", payload / "cache", parser)
    require(len(products) == 4, "旧Mac四个py3产物不完整")
    expected = dict(PINS)
    expected.update({"root/" + name: sha for name, sha in evidence.items()})
    for item in plan["installers"].values():
        name = "root/" + item["source_archive"]
        require(digest(read(payload / name)) == item["source_archive_sha256"], "必需原CPython tar身份错误")
        expected[name] = item["source_archive_sha256"]
    required = {manifest["tool_dependency"]["artifact"]}
    for scope in manifest["scopes"]:
        if scope["kind"] == "host":
            wheels, missing, proof = replay.resolve_scope(scope, manifest, payload / "cache", products, parser)
            require(not missing and len(wheels) == len(scope["packages"]), "所选host分发缺件")
            required.update(p["artifact"] for p in scope["packages"])
    required.update(key[0] for key in products)
    for sha in required:
        expected["cache/" + sha + "/" + manifest["artifacts"][sha]["filename"]] = sha
    for sha in build_plan["families"]["py3"]["tools"]:
        expected["cache/" + sha + "/" + build_plan["tools"][sha]["filename"]] = sha
    for product in products.values():
        expected[product["path"].relative_to(payload).as_posix()] = product["artifact"]["sha256"]
    require(len(expected) == 103 and {r["path"]: r["sha256"] for r in catalog} == expected, "H0清单不等于原证据/选中分发/收据完整派生闭包")
    return manifest, plan


@contextmanager
def open_environment(args, plan, report):
    """创建/安装一个固定受控lifetime，调用者可在其中复用固定H0步骤，退出必关容器。"""
    require(sys.platform == "linux" and platform.machine() in ("x86_64", "amd64"), "H0实际运行需要Linux amd64及Docker")
    docker = shutil.which("docker");require(docker is not None, "缺少实际Docker运行时")
    payload = regular(args.payload)
    c0 = load_module(payload / "c1-runtime/preflight_environment.py", PINS["c1-runtime/preflight_environment.py"], "reko_h0_c0")
    l0 = load_module(payload / "c1-runtime/build_linux_python_wheels.py", PINS["c1-runtime/build_linux_python_wheels.py"], "reko_h0_l0")
    apt = c0.load_collector(payload / "c1-runtime/materialize_apt_inputs.py", PINS["c1-runtime/materialize_apt_inputs.py"])
    group = next(g for g in plan["groups"] if g["ubuntu"] == args.ubuntu)
    bundle = regular(args.bundle)
    verification = apt.verify_bundle(bundle, group["manifest_sha256"])
    require(verification["result"] == "passed", "原APT分发复核未通过")
    write(args.output / "apt-byte-verification.json", verification)
    manifest = apt.read_json(bundle / "manifest.json")
    require(manifest["image"] == group["image"] and manifest["image_id"] == group["image_id"] and manifest["ubuntu"] == args.ubuntu, "实际APT分发身份不同")
    report["apt_bundle_verified"] = True
    run = c0.EnvironmentRun(apt, args.output, docker)
    try:
        before = l0.prepare_container(run, bundle, manifest, report)
        c0.install_packages(run, bundle, manifest, before, report)
        yield run
    finally:
        run.close()
        report["container_closed"] = True


def verify_result(result, group, manifest, identity, exit_code):
    """只接纳2项真重放+7项未选和原exit2；不把H0提升为完整J2C或接受伪成功。"""
    runtime = identity["runtime"]
    require(re.fullmatch(r"[a-f0-9]{64}", identity["sha256"]) and runtime["platform"] == "linux"
            and runtime["implementation"] == "CPython" and runtime["machine"] == "x86_64"
            and runtime["version"].startswith("3.12." if group["ubuntu"] == "24.04" else "3.10."), "H0缺实际Linux前端解释器")
    require(exit_code == 2 and result.get("task") == "R00-02J2C1" and result.get("command") == "replay"
            and result.get("status") == "incomplete_scopes_not_run" and result.get("J2C_complete") is False
            and result.get("ios_runtime_verified") is False and result.get("plan_sha256") == PINS["root/scripts/renpy/python-replay-plan.json"]
            and result.get("j2a_manifest_sha256") == PINS["root/scripts/renpy/python-inputs.lock.json"], "H0原退出/完整状态/计划身份异常")
    scopes = result["scopes"];require(len(scopes) == 9 and {s["id"] for s in scopes} == ALL_SCOPES, "原九scope行被删减/重复")
    receipts = result["build_receipts"]
    require(len(receipts) == 1 and receipts[0]["sha256"] == PINS["receipts/py3/report.json"], "原Darwin收据身份变化")
    for row in scopes:
        if row["id"] not in group["scopes"]:
            require(row["status"] == "not_run" and row.get("reason") == "本次未选择", "未选scope被计为执行/失败")
            continue
        require(row["status"] == "offline_replayed" and row.get("missing_built_wheels", []) == []
                and row["ios_runtime_verified"] is False and row["full_engine_session_verified"] is False, "所选host未真实重放")
        require(row["interpreter"]["sha256"] == identity["sha256"] and row["interpreter"]["runtime"] == identity["runtime"], "实际重放解释器身份不同")
        proof = row["network_isolation"]
        require(proof["backend"] == "unshare" and proof["kernel_network_isolation_verified"] is True
                and proof["control"]["connected"] is True and proof["isolated"]["connected"] is False
                and proof["control"]["network_namespace"] != proof["isolated"]["network_namespace"]
                and proof["prefix"] == [proof["program"]["realpath"], "--net", "--"], "缺实际内核断网对照")
        expected = next(s for s in manifest["scopes"] if s["id"] == row["id"])
        require({s["name"]: s["version"] for s in row["installed"]} == expected["expected_versions"]
                and len(row["installed"]) == len(expected["packages"]), "实际安装集合缺项/错版")
        probe = row["probe"]
        prefix = REPLAY_OUTPUT + "/" + row["id"] + "/environment"
        require(row["environment"]["prefix"] == prefix and row["source_evidence"]["dependency_metadata_verified"] is True
                and row["source_evidence"]["id"] == row["id"], "实际环境/来源证据不符")
        require(not probe["errors"] and len(probe["modules"]) == len(expected["packages"])
                and {m["distribution"] for m in probe["modules"]} == set(expected["expected_versions"])
                and all(m["file"] and (m["origin"] == "stdlib" if m["distribution"] == "typing" else m["origin"] == "site" and m["file"].startswith(prefix + "/")) for m in probe["modules"])
                and len(probe["resources"]) == 1 and probe["resources"][0]["kind"] == "certifi_ca_bundle"
                and type(probe["resources"][0]["ca_count"]) is int and probe["resources"][0]["ca_count"] > 0
                and probe["resources"][0]["file"].startswith(prefix + "/") and re.fullmatch(r"[a-f0-9]{64}", probe["resources"][0]["sha256"])
                and len(probe["smoke"]) == 2
                and {s["kind"] for s in probe["smoke"]} == {"requests_prepare", "rsa_ecdsa_sign_verify"}
                and all(s["passed"] is True for s in probe["smoke"]), "导入/CA/签名smoke覆盖不足")
        require(row["commands"] and all(type(c["returncode"]) is int and c["returncode"] == 0
                and c["argv"][:len(proof["prefix"])] == proof["prefix"] for c in row["commands"]), "实际隔离子进程未全部成功")


def verify_saved_logs(directory, result, group):
    """回传原命令总表与每个真实通道必须完整，identity原stdout与解释器记录逐项相等。"""
    for row in result["scopes"]:
        if row["id"] not in group["scopes"]:
            continue
        folder = directory / row["id"]
        require(decode(read(folder / "commands.json")) == row["commands"], "回传命令表与原report不同")
        identity_commands = decode(read(folder / "identity-probe/commands.json"))
        require(len(identity_commands) == 1 and identity_commands[0]["returncode"] == 0, "identity原命令未成功")
        for base, commands in [(folder, row["commands"]), (folder / "identity-probe", identity_commands)]:
            for command in commands:
                for channel in ("stdout", "stderr"):
                    name = command[channel]
                    require(re.fullmatch(r"command-[0-9]+-" + channel + r"\.log", name), "原命令通道路径异常")
                    read(base / name, 32 * 1024**2)
        require(decode(read(folder / "identity-probe" / identity_commands[0]["stdout"])) == row["interpreter"]["runtime"], "identity原stdout与report不符")


def replay_host_group(run, payload, group, plan, manifest, report):
    """在已受控且APT安装完成的同一容器内执行固定两host重放；无任意后置命令入口。"""
    run.run(["mkdir", "-p", REMOTE], "h0-input-directory")
    run.copy(str(payload) + "/.", REMOTE, "h0-copy-fixed-inputs")
    run.checksum("h0-inputs", [(row["sha256"], REMOTE + "/" + row["path"]) for row in plan["files"]])
    path, _ = run.run(["readlink", "-f", "/usr/bin/python3"], "h0-system-python-path")
    python = path.decode().strip();require(re.fullmatch(r"/usr/bin/python3\.(10|12)", python), "系统Python路径未批准")
    code = "import json,sys,platform;print(json.dumps({'version':platform.python_version(),'implementation':platform.python_implementation(),'executable':sys.executable,'prefix':sys.prefix,'base_prefix':getattr(sys,'base_prefix',sys.prefix),'platform':sys.platform,'machine':platform.machine()}))"
    runtime, _ = run.run([python, "-E", "-s", "-c", code], "h0-system-python-runtime")
    runtime = decode(runtime);family = "3.12." if group["ubuntu"] == "24.04" else "3.10."
    require(runtime["version"].startswith(family) and runtime["implementation"] == "CPython" and runtime["platform"] == "linux"
            and runtime["machine"] == "x86_64" and runtime["executable"] == python, "系统解释器实际版本/架构不符")
    raw, _ = run.run(["sha256sum", python], "h0-system-python-hash")
    parts = raw.decode().split();require(len(parts) == 2 and re.fullmatch(r"[0-9a-f]{64}", parts[0]) and parts[1] == python, "解释器SHA输出错误")
    identity = {"sha256": parts[0], "runtime": runtime};report["consumer_interpreter"] = identity
    script = REMOTE + "/root/scripts/renpy/replay_python_inputs.py"
    argv = [python, "-B", script, "replay", "--source-cache", REMOTE + "/cache", "--tool-cache", REMOTE + "/cache",
            "--installer-cache", "/reko/h0-installers", "--report", REPLAY_OUTPUT, "--build-report", REMOTE + "/receipts/py3/report.json",
            "--build-report-sha256", PINS["receipts/py3/report.json"], "--isolation", "unshare"]
    for scope in group["scopes"]:
        argv += ["--scope", scope, "--interpreter", scope + "=" + python, "--interpreter-sha256", scope + "=" + parts[0]]
    exit_code = None
    try:
        try:
            run.run(argv, "h0-original-replay")
            exit_code = 0
        except run.apt.AptInputError:
            row = run.commands.records[-1]
            require(row["label"] == "h0-original-replay", "非重放命令错误不能作预期exit2")
            exit_code = row["returncode"]
            if exit_code == 2:
                row["expected_partial_result"] = True
    finally:
        path = run.output / "generated/h0-preserve-results.py"
        path.parent.mkdir(exist_ok=True)
        with path.open("x") as stream:
            stream.write(PRESERVE)
        run.copy(path, "/reko/h0-preserve-results.py", "h0-copy-result-preserver")
        run.run([python, "-B", "/reko/h0-preserve-results.py", *group["scopes"]], "h0-preserve-selected-results")
        run.host([run.docker, "cp", run.name + ":/reko/h0-results", str(run.output / "python-replay")], "h0-copy-public-results")
    result = decode(read(run.output / "python-replay/report.json", 8 * 1024**2))
    verify_result(result, group, manifest, identity, exit_code)
    verify_saved_logs(run.output / "python-replay", result, group)
    report.update(H0_group_complete=True, original_replay_exit_code=exit_code, selected_scopes=group["scopes"],
                  original_replay_report_sha256=digest(read(run.output / "python-replay/report.json")))
    return result


def main(argv=None):
    """verify只核原件，run实际Linux执行；两模式均不报告九scope或运行时通过。"""
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument("command", choices=("verify", "run"))
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN);parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--payload", type=Path, required=True);parser.add_argument("--bundle", type=Path)
    parser.add_argument("--ubuntu", choices=sorted(SCOPES), required=True);parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = {"scope": "four_linux_host_frontend_scopes_only", "result": "failed", "ubuntu": args.ubuntu, "command": args.command,
              "errors": [], "input_bytes_verified": False, "original_contracts_verified": False, "apt_bundle_verified": False,
              "H0_group_complete": False, "container_closed": False, "J2C_complete": False, "ios_runtime_verified": False,
              "exact_target_interpreters_verified": False, "full_source_build_executed": False}
    created = False
    try:
        args.output, args.payload = regular(args.output), regular(args.payload)
        if args.bundle is not None:
            args.bundle = regular(args.bundle)
            require(not args.output.is_relative_to(args.bundle) and not args.bundle.is_relative_to(args.output), "报告与APT原件目录不能重合/嵌套")
        require(not args.output.exists() and args.output.parent.is_dir() and not args.output.is_relative_to(args.payload)
                and not args.payload.is_relative_to(args.output), "输出必须全新且与输入分离")
        args.output.mkdir();created = True
        plan = load_plan(args.plan, args.plan_sha256)
        report.update(plan_sha256=args.plan_sha256, payload_file_count=len(plan["files"]),
                      runtime_pins=PINS, producer_receipt_sha256=PINS["receipts/py3/report.json"],
                      group=next(g for g in plan["groups"] if g["ubuntu"] == args.ubuntu))
        if args.command == "run":
            require(sys.platform == "linux" and platform.machine() in ("x86_64", "amd64"), "H0实际运行需要Linux amd64及Docker")
            require(args.bundle is not None, "run缺少固定完整APT bundle")
        verify_files(args.payload, plan["files"]);report["input_bytes_verified"] = True
        manifest, replay_plan = verify_original_contracts(args.payload, plan["files"]);report["original_contracts_verified"] = True
        if args.command == "run":
            group = next(g for g in plan["groups"] if g["ubuntu"] == args.ubuntu)
            with open_environment(args, plan, report) as run:
                replay_host_group(run, args.payload, group, plan, manifest, report)
            require(report["H0_group_complete"] and report["container_closed"], "H0未完成或容器未关闭")
            report["result"] = "selected_host_group_offline_replayed"
        else:
            report["result"] = "original_input_bytes_and_contracts_verified_no_replay"
    except Exception as error:
        report["H0_group_complete"] = False
        report["errors"].append(type(error).__name__ + ": " + str(error))
    if created:
        report["files"] = [{"path": str(path.relative_to(args.output)), "sha256": digest(read(path)), "bytes": path.stat().st_size}
                           for path in sorted(args.output.rglob("*")) if path.is_file()]
        write(args.output / "report.json", report)
    log("结果=" + report["result"] + "；" + "; ".join(report["errors"]))
    return 0 if report["result"] != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
