#!/usr/bin/env python3
"""复用完整固定APT输入在断网jammy容器生成两个py2纯wheel；不计目标ABI或SDK验收。"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys
import tarfile
import types
import zipfile


ROOT = Path(__file__).resolve().parents[2]
RUNTIME_PINS = {
    "lock_python_inputs.py": "eece439195f241cd7a3533e26404f68e4a294636c3a8366d9dde9bc27403468d",
    "build_python_wheels.py": "829712b376ce71ccd39f36299ba2f5e09eb92ba7c21a21f9134ec11e2f2391a6",
    "python-inputs.lock.json": "4a9a85b719dd1ef3fb5ded2fcd383f5c9bd8925c0e537bd8f5db0a1132602935",
    "python-wheel-build-plan.json": "9b231a3a1460180ed1de53474669e0eba786df3a4ff70da981b87eece89cdea4",
}
JOBS = ("future-0.18.3-py2", "pefile-2019.4.18-py2")
_RUNTIME_MODULES = {}
PHASES = ("input_bytes_verified", "apt_bundle_verified", "container_identity_verified", "container_capabilities_verified",
          "signature_reexecuted", "apt_install_verified", "interpreter_verified", "producer_report_verified")
COPY_RESULTS = """import pathlib,shutil,re,stat,sys
source=pathlib.Path(sys.argv[1]);target=pathlib.Path(sys.argv[2])
target.mkdir()
def copy(path):
 if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):raise ValueError('unsafe producer output')
 destination=target/path.relative_to(source);destination.parent.mkdir(parents=True,exist_ok=True)
 with destination.open('xb') as out:out.write(path.read_bytes())
if (source/'report.json').is_file():copy(source/'report.json')
for name in ('future-0.18.3-py2','pefile-2019.4.18-py2'):
 folder=source/name
 if not folder.exists():continue
 if folder.is_symlink():raise ValueError('unsafe producer directory')
 for path in folder.iterdir():
  if path.name=='commands.json' or re.fullmatch(r'command-[0-9]+-(stdout|stderr)\\.log',path.name):copy(path)
 output=folder/'output'
 if output.exists():
  if output.is_symlink():raise ValueError('unsafe output directory')
  for path in output.iterdir():
   if path.suffix=='.whl':copy(path)
"""


def log(message):
    """输出独立生成端中文日志，保留真实失败边界。"""
    print("[RenPyLinuxPythonWheels] " + message, flush=True)


def require(condition, message):
    """前置缺失或身份错误立即失败，不用默认成功代替执行。"""
    if not condition:
        raise ValueError(message)


def regular(path):
    """所有输入与输出拒绝任意层链接，避免校验与实际使用分离。"""
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), "拒绝链接路径：" + str(path))
    return path


def digest(path):
    """流式核对真实普通文件SHA256。"""
    path = regular(path)
    require(stat.S_ISREG(path.stat().st_mode), "输入不是普通文件：" + str(path))
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_json(path, value):
    """独占写入证据，不覆盖旧结果或失败残留。"""
    path = regular(path)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def load_runtime(directory):
    """执行前核验四个既有原文件，明确B1默认ROOT布局，不读取九scope的外部证据树。"""
    directory = regular(directory)
    require(directory.parts[-2:] == ("scripts", "renpy"), "原工具必须保留scripts/renpy布局")
    records, sources = {}, {}
    for name, expected in RUNTIME_PINS.items():
        path = directory / name
        require(digest(path) == expected, "既有工具/锁原字节改变：" + name)
        records[name] = {"sha256": expected, "bytes": path.stat().st_size}
        if name.endswith(".py"):
            sources[name] = path.read_bytes()
            require(hashlib.sha256(sources[name]).hexdigest() == expected, "读取执行原字节时身份改变：" + name)
    for name in ("lock_python_inputs", "build_python_wheels"):
        previous = sys.modules.get(name)
        require(previous is None or (previous is _RUNTIME_MODULES.get(name)
                and Path(previous.__file__).absolute() == directory / (name + ".py")), "环境已有未由本入口核验执行的原工具")
    for name in ("lock_python_inputs", "build_python_wheels"):
        if name in sys.modules:
            continue
        path = directory / (name + ".py")
        module = types.ModuleType(name)
        module.__file__, module.__package__ = str(path), ""
        module.__spec__ = importlib.util.spec_from_loader(name, loader=None, origin=str(path))
        sys.modules[name] = module
        try:
            # 直接编译已验原字节，完全绕过可能可读的旧pyc；同名模块使build的既有import依赖保持不变。
            exec(compile(sources[name + ".py"], str(path), "exec"), module.__dict__)
            _RUNTIME_MODULES[name] = module
        except BaseException:
            sys.modules.pop(name, None)
            raise
    inputs, builder = sys.modules["lock_python_inputs"], sys.modules["build_python_wheels"]
    require(Path(inputs.__file__).absolute() == directory / "lock_python_inputs.py"
            and Path(builder.__file__).absolute() == directory / "build_python_wheels.py", "实际原工具来源不符")
    plan, manifest, fingerprint = builder.load_plan(directory / "python-wheel-build-plan.json")
    return inputs, builder, plan, manifest, fingerprint, records


def load_preflight(path, expected):
    """只加载显式SHA校验后的C0原件，复用其命令记录与APT安装，不调用SDK入口。"""
    require(re.fullmatch(r"[0-9a-f]{64}", expected or "") and digest(path) == expected, "C0原件SHA不符")
    spec = importlib.util.spec_from_file_location("reko_py2_preflight", path)
    require(spec is not None, "C0模块无法加载")
    module = importlib.util.module_from_spec(spec)
    exec(compile(regular(path).read_bytes(), str(path), "exec"), module.__dict__)
    require(all(callable(getattr(module, name, None)) for name in ("load_collector", "EnvironmentRun", "install_packages")), "C0安装阶段接口缺失")
    return module


def verify_inputs(inputs, builder, plan, manifest, cache, download=False):
    """只物化两sdist和六工具wheel，共八原件；prepare可显式联网，run没有下载回退。"""
    selected = [j for j in plan["jobs"] if j["id"] in JOBS]
    require({j["id"] for j in selected} == set(JOBS) and all(j["family"] == "py2" for j in selected), "py2任务集合错误")
    artifacts = {j["source"]: manifest["artifacts"][j["source"]] for j in selected}
    artifacts.update(plan["tools"])
    require(len(artifacts) == 8, "生成端输入必须为八个唯一分发")
    records = {}
    for sha, artifact in artifacts.items():
        path = inputs.artifact_path(cache, artifact)
        if not path.exists():
            require(download, "缺少已物化输入：" + artifact["filename"])
            inputs.fetch_artifact(cache, artifact)
        inspection = builder.verify_tool(path, artifact) if sha in plan["tools"] else builder.inspect_source(path, artifact, plan["sources"][sha])
        records[sha] = {"filename": artifact["filename"], "sha256": sha, "bytes": artifact["size"],
                        "source_url": artifact["url"], "inspection": inspection}
    return artifacts, records


def container_argv(docker, name, image):
    """只授予本轮unshare必需能力，保持禁网、无挂载、无宿主凭据。"""
    return [docker, "run", "--detach", "--user", "0:0", "--platform", "linux/amd64", "--network", "none",
            "--cap-add", "SYS_ADMIN", "--security-opt", "seccomp=unconfined", "--name", name, image, "/bin/sleep", "infinity"]


def check_container(state, image):
    """核验实际内核隔离、显式能力、非privileged及无额外环境/挂载。"""
    host = state["HostConfig"]
    capabilities = host.get("CapAdd") or []
    require(host["NetworkMode"] == "none" and not state.get("Mounts") and host.get("Privileged") is False
            and len(capabilities) == 1 and capabilities[0] in ("SYS_ADMIN", "CAP_SYS_ADMIN")
            and host.get("SecurityOpt") == ["seccomp=unconfined"], "实际生成容器能力/网络/挂载边界不符")
    require(state["Image"] == image["Id"] and state["Config"].get("Env") == image["Config"].get("Env")
            and state["Config"].get("User") == "0:0", "容器image/用户或环境发生变化")


def prepare_container(run, bundle, manifest, report):
    """使用C0相同base/传输门禁，独立创建带明确unshare能力的生成容器。"""
    run.host([run.docker, "pull", "--platform", "linux/amd64", manifest["image"]], "pull-fixed-image")
    raw, _ = run.host([run.docker, "image", "inspect", manifest["image"]], "image-inspect")
    images = json.loads(raw)
    require(len(images) == 1 and images[0]["Id"] == manifest["image_id"] and images[0]["Architecture"] == "amd64"
            and images[0]["Os"] == "linux", "实际固定jammy镜像身份不符")
    run.host(container_argv(run.docker, run.name, manifest["image"]), "producer-container-start")
    run.active = True
    raw, _ = run.host([run.docker, "inspect", run.name], "producer-container-inspect")
    states = json.loads(raw)
    require(len(states) == 1, "生成容器inspect数量错误")
    check_container(states[0], images[0])
    report["container_capabilities_verified"] = True
    run.run(["uname", "-a"], "shared-host-kernel")
    run.host([run.docker, "version"], "docker-version")
    before, _ = run.run(["dpkg-query", "--show", "--showformat=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n"], "base-packages")
    status, _ = run.run(["cat", "/var/lib/dpkg/status"], "base-status")
    release, _ = run.run(["cat", "/etc/os-release"], "base-os")
    for actual, key in ((before, "base_package_label"), (status, "base_status_label"), (release, "os_release_label")):
        require(actual == run.apt.command_by_label(bundle, manifest, manifest[key])[1], "生成端base状态不同于固定B1输入")
    report["container_identity_verified"] = True
    run.run(["mkdir", "-p", "/reko/repo", "/reko/apt/lists/partial", "/reko/apt/archives/partial", "/reko/project/scripts/renpy", "/reko/python-cache"], "producer-directories")
    run.copy(str(bundle / "repository") + "/.", "/reko/repo", "copy-repository")
    checks = [(r["sha256"], "/reko/repo/" + r["path"].removeprefix("repository/")) for r in manifest["files"] if r["path"].startswith("repository/")]
    for name in ("sources.list", "apt.conf", "preferences"):
        run.copy(bundle / name, "/reko/" + name, "copy-" + name)
        checks.append((digest(bundle / name), "/reko/" + name))
    run.checksum("apt-inputs", checks)
    return run.apt.base_packages(before)


def transfer_inputs(run, runtime, artifacts, cache):
    """仅向容器传入四原文件/八原件，传输后再次核验，不复制任何SDK或来源证据占位。"""
    checks = []
    for name, expected in RUNTIME_PINS.items():
        target = "/reko/project/scripts/renpy/" + name
        run.copy(runtime / name, target, "copy-runtime-" + name)
        checks.append((expected, target))
    for sha, artifact in artifacts.items():
        folder = "/reko/python-cache/" + sha
        run.run(["mkdir", "-p", folder], "prepare-input-" + sha[:12])
        target = folder + "/" + artifact["filename"]
        run.copy(cache / sha / artifact["filename"], target, "copy-input-" + sha[:12])
        checks.append((sha, target))
    run.checksum("python-inputs", checks)


def interpreter_identity(run, executable, version, label):
    """读取真实系统解释器/标准模块与二进制身份；APT名义版本不能代替实际执行。"""
    expected_platform = {"2.7.18": "linux2", "3.10.12": "linux"}.get(version)
    require(expected_platform is not None, "未批准的系统解释器版本契约")
    path, _ = run.run(["readlink", "-f", executable], label + "-path")
    path = path.decode().strip()
    require(path.startswith("/usr/") and "\n" not in path, "系统解释器路径不受控")
    code = "import json,platform,sys,site,sysconfig,socket,zlib,ssl,distutils;print(json.dumps({'version':platform.python_version(),'implementation':platform.python_implementation(),'platform':sys.platform,'machine':platform.machine(),'executable':sys.executable}))"
    raw, _ = run.run([path, "-E", "-s", "-c", code], label + "-runtime")
    identity = json.loads(raw)
    require(identity["version"] == version and identity["implementation"] == "CPython" and identity["platform"] == expected_platform
            and identity["machine"] == "x86_64", "实际系统解释器版本/平台不符合生成端要求")
    sha, _ = run.run(["sha256sum", path], label + "-hash")
    checksum = sha.decode().split()
    require(len(checksum) == 2 and re.fullmatch(r"[0-9a-f]{64}", checksum[0]) and checksum[1] == path, "解释器SHA输出错误")
    return {"realpath": path, "sha256": checksum[0], "runtime": identity}


def preserve_results(run):
    """只拷回报告、命令日志和wheel，不带独立环境、bootstrap或原源码树。"""
    script = run.output / "generated/preserve-python-results.py"
    script.parent.mkdir(parents=True, exist_ok=True)
    with script.open("x") as stream:
        stream.write(COPY_RESULTS)
    run.copy(script, "/reko/preserve-python-results.py", "copy-result-preserver")
    run.run(["/usr/bin/python3.10", "-I", "/reko/preserve-python-results.py", "/reko/py2-wheel-report", "/reko/py2-wheel-public"], "stage-producer-evidence")
    run.host([run.docker, "cp", run.name + ":/reko/py2-wheel-public/.", str(run.output / "producer-report")], "preserve-producer-evidence")


def source_payload(source, output, name):
    """将实际生成代码/资源直接与原sdist逐字节绑定，不循环相信收据。"""
    with tarfile.open(source, "r:*") as archive:
        members = archive.getmembers()
        root = members[0].name.split("/")[0] + "/"
        files = {m.name[len(root):]: archive.extractfile(m).read() for m in members if m.isfile()}
    with zipfile.ZipFile(output) as archive:
        entries = [n for n in archive.namelist() if n.endswith(".dist-info/entry_points.txt")]
        if name == "future":
            require(len(entries) == 1, "future入口元数据缺失")
            config = configparser.ConfigParser(interpolation=None)
            config.read_string(archive.read(entries[0]).decode())
            require(config.sections() == ["console_scripts"] and dict(config["console_scripts"]) == {
                "futurize": "libfuturize.main:main", "pasteurize": "libpasteurize.main:main"}, "future入口元数据不是原配方")
        else:
            require(not entries, "pefile出现未声明入口")
        for member in archive.infolist():
            if member.is_dir() or member.filename.split("/")[0].endswith(".dist-info"):
                continue
            relative = ("src/" if name == "future" else "") + member.filename
            require(relative in files and files[relative] == archive.read(member), "产物payload不属于原sdist：" + member.filename)


def verify_results(inputs, builder, plan, manifest, cache, output, interpreter):
    """完整核验原B1收据、真实unshare证明与两个新产物，未运行的四任务保持未运行。"""
    receipt_path = regular(output / "producer-report/report.json")
    receipt = json.loads(receipt_path.read_bytes(), object_pairs_hook=inputs.unique_object)
    require(receipt["task"] == "R00-02J2B1" and receipt["status"] == "selected_builder_content_verified"
            and receipt["plan_sha256"] == RUNTIME_PINS["python-wheel-build-plan.json"]
            and receipt["j2a_manifest_sha256"] == RUNTIME_PINS["python-inputs.lock.json"], "实际B1生成收据身份/状态不符")
    proof = receipt["network_isolation"]
    require(proof["backend"] == "unshare" and proof["kernel_network_isolation_verified"] is True
            and proof["control"]["connected"] is True and proof["isolated"]["connected"] is False
            and proof["control"]["network_namespace"] and proof["control"]["network_namespace"] != proof["isolated"]["network_namespace"], "实际B1没有内核网络命名空间隔离证明")
    require(receipt["interpreter"]["realpath"] == interpreter["realpath"] and receipt["interpreter"]["sha256"] == interpreter["sha256"], "B1实际解释器与生成容器探针不一致")
    control_command = proof["control_command"]
    require(control_command[:5] == [interpreter["realpath"], "-E", "-s", "-c", builder.PROBE]
            and len(control_command) == 6 and control_command[-1].isdigit()
            and proof["isolated_command"] == proof["prefix"] + control_command
            and proof["prefix"] == [proof["program"]["realpath"], "--net", "--"], "实际隔离子命令不是固定root unshare配方")
    require(receipt["tools"] == {sha: builder.verify_tool(inputs.artifact_path(cache, artifact), artifact)
                                  for sha, artifact in plan["tools"].items()}, "完整工具检查收据不符")
    require(len(receipt["jobs"]) == 6 and {r["id"] for r in receipt["jobs"]} == builder.JOB_IDS, "B1任务集合不完整")
    parser = inputs.load_parser(cache, manifest)
    products = []
    for row in receipt["jobs"]:
        if row["id"] not in JOBS:
            require(row["status"] == "not_run", "禁止额外运行或伪填py3任务")
            continue
        job = next(j for j in plan["jobs"] if j["id"] == row["id"])
        original, profile = manifest["artifacts"][job["source"]], plan["sources"][job["source"]]
        family = plan["families"]["py2"]
        ids = family["tools"] + [family["bootstrap"]]
        require(row["status"] == "builder_content_verified" and row["source_artifact"] == original and row["source_recipe"] == profile
                and row["tool_inputs"] == {sha: plan["tools"][sha] for sha in ids}, "实际py2源/构建工具收据不符")
        require(row["interpreter"]["sha256"] == interpreter["sha256"] and row["interpreter"]["runtime"]["version"] == "2.7.18"
                and all(row[key] is False for key in ("actual_target_interpreter_verified", "target_import_verified", "offline_consumer_verified", "ios_runtime_verified")), "生成端不得提前声明目标验收")
        filename = row["output"]["filename"]
        require(inputs.safe_name(filename, "产物") == filename and "/" not in filename, "产物路径越界")
        path = regular(output / "producer-report" / row["id"] / "output" / filename)
        product = builder.verify_output(path, job, profile, parser)
        require(product == row["output"], "实际wheel与B1收据字节/RECORD不一致")
        builder.inspect_source(inputs.artifact_path(cache, original), original, profile)
        source_payload(inputs.artifact_path(cache, original), path, profile["name"])
        products.append({"job": row["id"], "source_sha256": job["source"], "path": str(path), **product})
    require(len(products) == 2, "缺少两个实际py2产物")
    return {"receipt_sha256": digest(receipt_path), "network_isolation": proof, "products": products}


def execute(args, report, inputs, builder, plan, manifest, artifacts):
    """只在真实Linux固定jammy执行APT安装和两个py2任务，异常也收集失败证据并清理。"""
    docker = shutil.which("docker")
    report["host_observations"] = {"system": platform.system(), "machine": platform.machine(), "python": platform.python_version(), "docker_cli": docker}
    require(platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64"), "真实Linux amd64生成环境缺失；当前平台不计通过")
    require(sys.version_info[:2] == (3, 10), "宿主生成编排必须显式使用Python3.10")
    require(docker is not None, "Docker运行时缺失；不计实际生成通过")
    preflight = load_preflight(args.preflight, args.preflight_sha256)
    collector = preflight.load_collector(args.collector, args.collector_sha256)
    verification = collector.verify_bundle(args.bundle, args.manifest_sha256)
    write_json(args.output / "apt-byte-verification.json", verification)
    bundle_manifest = collector.read_json(args.bundle / "manifest.json")
    require(bundle_manifest["ubuntu"] == "22.04", "py2生成端仅接受已批准固定jammy路线")
    report.update(apt_bundle_verified=True, apt_manifest_sha256=args.manifest_sha256, image=bundle_manifest["image"], image_id=bundle_manifest["image_id"],
                  preflight_sha256=args.preflight_sha256, collector_sha256=args.collector_sha256)
    run = preflight.EnvironmentRun(collector, args.output, docker)
    run.name = "reko-python-wheels-" + run.name.removeprefix("reko-preflight-")
    try:
        before = prepare_container(run, args.bundle, bundle_manifest, report)
        preflight.install_packages(run, args.bundle, bundle_manifest, before, report)
        report["producer_interpreter"] = interpreter_identity(run, "/usr/bin/python2.7", "2.7.18", "python27")
        report["frontend_interpreter"] = interpreter_identity(run, "/usr/bin/python3.10", "3.10.12", "python310")
        report["interpreter_verified"] = True
        transfer_inputs(run, args.runtime_dir, artifacts, args.cache)
        command = ["/usr/bin/python3.10", "/reko/project/scripts/renpy/build_python_wheels.py", "build", "--source-cache", "/reko/python-cache",
                   "--tool-cache", "/reko/python-cache", "--python", report["producer_interpreter"]["realpath"], "--python-sha256",
                   report["producer_interpreter"]["sha256"], "--isolation", "unshare", "--report", "/reko/py2-wheel-report"]
        for job in JOBS:
            command += ["--job", job]
        try:
            run.run(command, "build-two-py2-wheels")
        finally:
            try:
                preserve_results(run)
            except Exception as error:
                report["errors"].append("保存生成端证据失败：" + str(error))
        report["producer"] = verify_results(inputs, builder, plan, manifest, args.cache, args.output, report["producer_interpreter"])
        require(not report["errors"], "生成端证据保存存在失败")
        report["producer_report_verified"] = True
    finally:
        run.close()
    require(all(report[key] is True for key in PHASES), "生成阶段存在未执行项")
    report["result"] = "passed"


def main(argv=None):
    """prepare仅校验八原件，run才执行Linux；所有失败保持真实状态和全新报告。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "run"))
    parser.add_argument("--runtime-dir", type=Path, default=ROOT / "scripts/renpy")
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--collector", type=Path)
    parser.add_argument("--collector-sha256")
    parser.add_argument("--preflight", type=Path)
    parser.add_argument("--preflight-sha256")
    args = parser.parse_args(argv)
    report = {"task": "R00-02J2B2-linux-py2-producer", "mode": args.mode, "result": "failed", "errors": [],
              **{key: False for key in PHASES}, "SDK_executed": False, "target_runtime_verified": False,
              "original_target_CPython_source_verified": False, "J2B_complete": False, "J2C_complete": False}
    output = None
    try:
        args.output, args.cache, args.runtime_dir = regular(args.output), regular(args.cache), regular(args.runtime_dir)
        require(not args.output.exists() and not args.output.is_relative_to(args.cache)
                and not args.output.is_relative_to(args.runtime_dir), "输出必须全新且位于输入缓存/原工具外")
        args.output.mkdir(parents=True)
        output = args.output / "linux-python-wheels-report.json"
        inputs, builder, plan, manifest, fingerprint, files = load_runtime(args.runtime_dir)
        require(not args.download or args.mode == "prepare", "run禁止联网物化Python输入，请先显式prepare")
        artifacts, verification = verify_inputs(inputs, builder, plan, manifest, args.cache, args.download)
        report.update(input_bytes_verified=True, runtime_files=files, build_plan_sha256=fingerprint, input_artifacts=verification,
                      source_scope_evidence_reread=False, source_provenance="原完整J2A/B1字节保留；本生成端仅重验所需八原件，不宣称九scope重放")
        if args.mode == "prepare":
            report["result"] = "inputs_verified_no_build"
        else:
            require(all(getattr(args, key) is not None for key in ("bundle", "manifest_sha256", "collector", "collector_sha256", "preflight", "preflight_sha256")), "run需要完整APT与C0原件的显式路径/SHA")
            args.bundle, args.collector, args.preflight = regular(args.bundle), regular(args.collector), regular(args.preflight)
            require(not args.output.is_relative_to(args.bundle), "输出不能修改原APT bundle")
            execute(args, report, inputs, builder, plan, manifest, artifacts)
    except KeyboardInterrupt:
        report["result"] = "failed"
        report["errors"].append("本轮生成被取消；未完成不计通过")
        log(report["errors"][-1])
    except Exception as error:
        report["result"] = "failed"
        report["errors"].append(type(error).__name__ + ": " + str(error))
        log("失败：" + report["errors"][-1])
    finally:
        if output is not None:
            try:
                report["files"] = [{"path": str(p.relative_to(args.output)), "bytes": p.stat().st_size, "sha256": digest(p)}
                                   for p in sorted(args.output.rglob("*")) if p.is_file()]
            except Exception as error:
                report["result"] = "failed"
                report["errors"].append("证据文件身份登记失败：" + str(error))
            try:
                write_json(output, report)
            except Exception as error:
                log("无法保存本轮失败报告：" + str(error))
                return 1
    log(report["result"] + "；仅生成端范围，目标验收未完成")
    return 1 if report["result"] == "failed" else 0


if __name__ == "__main__":
    sys.exit(main())
