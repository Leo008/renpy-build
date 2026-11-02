#!/usr/bin/env python3
"""由已锁源码和工具在断网独立环境生成纯 wheel；不修改 J2A 身份或声称目标运行通过。"""

from __future__ import annotations

import argparse
import ast
import configparser
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tarfile
import zipfile

import lock_python_inputs as inputs


ROOT = inputs.ROOT
DEFAULT_PLAN = ROOT / "scripts/renpy/python-wheel-build-plan.json"
DEFAULT_WORK = ROOT / "ThirdParty/build/renpy-tests/goal-input-audit-20261102/versions/python-inputs/wheel-build"
JOB_IDS = {"typing-3.7.4.3-py3", "future-0.18.3-py3", "future-0.18.3-py2",
           "pefile-2022.5.30-py3", "pefile-2021.9.3-py3", "pefile-2019.4.18-py2"}
PROBE = """import json,os,socket,sys
s=socket.socket();s.settimeout(3)
try:
 s.connect(('127.0.0.1',int(sys.argv[1])));s.sendall(b'reko');r={'connected':True}
except socket.error as e:r={'connected':False,'errno':e.errno,'error':str(e)}
r['network_namespace']=os.readlink('/proc/self/ns/net') if os.path.exists('/proc/self/ns/net') else None
print(json.dumps(r));s.close()
"""
IDENTITY = """import json,sys,platform
print(json.dumps({'version':platform.python_version(),'implementation':platform.python_implementation(),
 'executable':sys.executable,'prefix':sys.prefix,'base_prefix':getattr(sys,'base_prefix',getattr(sys,'real_prefix',sys.prefix)),
 'platform':sys.platform,'machine':platform.machine()}))
"""


def log(message):
    """输出可归属本任务的中文日志。"""
    print("[RenPyWheelBuild] " + message, flush=True)


def require(condition, message):
    """契约缺失即失败，禁止用默认成功补齐证据。"""
    inputs.require(condition, message)


def file_identity(path):
    """锁定实际解释器或隔离程序字节，显式记录请求路径与解析后路径。"""
    requested = Path(path).absolute()
    actual = inputs.regular_path(requested.resolve(strict=True))
    require(actual.is_file() and os.access(actual, os.X_OK), "程序不存在或不可执行：" + str(actual))
    content = actual.read_bytes()
    return {"requested_path": str(requested), "realpath": str(actual), "sha256": inputs.digest(content), "size": len(content)}


def load_plan(path, manifest_path=inputs.DEFAULT_LOCK):
    """把五个源码输入绑定到完整 J2A 字节，强校验工具、主版本及六个显式 job。"""
    raw = inputs.regular_path(path).read_bytes()
    value = json.loads(raw, object_pairs_hook=inputs.unique_object)
    inputs.keys(value, ("schema_version", "task", "j2a_manifest_sha256", "sources", "tools", "families", "jobs", "limitations"), "构建计划")
    require(value["schema_version"] == 1 and value["task"] == "R00-02J2B1", "构建计划版本错误")
    manifest, fingerprint = inputs.load_manifest(manifest_path)
    require(value["j2a_manifest_sha256"] == fingerprint, "J2A 原字节身份改变")
    require(set(value["sources"]) == {k for k, a in manifest["artifacts"].items() if a["type"] == "sdist"}, "源码集合不等于 J2A 五个 sdist")
    for sha, source in value["sources"].items():
        inputs.keys(source, ("name", "version", "filename", "build_files", "frontend", "pyproject", "setup_requires", "build_requires", "runtime_requires", "runtime_requires_python", "review"), "源码配方")
        original = manifest["artifacts"][sha]
        require(all(source[k] == original[k] for k in ("name", "version", "filename")), "源码身份与 J2A 不同")
        require(source["runtime_requires_python"] == original["metadata"]["requires_python"], "源码 Python 限制与原字节不符")
        require(source["frontend"] == "setup.py_bdist_wheel" and source["pyproject"] is False
                and source["setup_requires"] is False and source["build_requires"] == ["setuptools", "wheel"], "未知源码构建配方")
        require("setup.py" in source["build_files"] and set(source["build_files"]) <= {"setup.py", "setup.cfg"}
                and all(inputs.SHA.fullmatch(h) for h in source["build_files"].values()), "构建文件身份缺失")
    require(type(value["tools"]) is dict and value["tools"], "构建工具为空")
    for sha, tool in value["tools"].items():
        inputs.keys(tool, ("name", "version", "filename", "type", "url", "sha256", "size", "metadata", "metadata_sha256", "inspection", "metadata_source", "origin", "usage"), "工具")
        require(inputs.SHA.fullmatch(sha) and sha == tool["sha256"] and tool["type"] == "wheel"
                and tool["usage"] == "isolated_builder_only", "工具身份/职责错误")
        require(tool["url"].startswith("https://files.pythonhosted.org/packages/")
                and tool["url"].endswith("/" + tool["filename"]) and "/" not in tool["filename"], "工具必须来自锁定官方 URL")
        require(tool["metadata_source"]["url"] == "https://pypi.org/pypi/" + tool["name"] + "/" + tool["version"] + "/json"
                and inputs.SHA.fullmatch(tool["metadata_source"]["sha256"]), "工具元数据来源错误")
        if tool["origin"] == "J2A_locked_distribution_bytes":
            require(sha in manifest["artifacts"] and all(tool[k] == manifest["artifacts"][sha][k] for k in
                    ("name", "version", "filename", "size", "inspection", "url")), "复用工具不等于 J2A 字节")
        else:
            require(tool["origin"] == "official_pypi_exact_version", "未知工具来源")
    require(set(value["families"]) == {"py2", "py3"}, "缺少 Python 主版本族")
    referenced = set()
    for family, config in value["families"].items():
        inputs.keys(config, ("python_major", "python_specifier", "tools", "environment", "bootstrap"), "构建族")
        major = int(family[-1])
        require(config["python_major"] == major and config["python_specifier"] == (">=3.8,<4" if major == 3 else ">=2.7,<2.8")
                and config["environment"] == ("stdlib_venv_without_pip" if major == 3 else "virtualenv_without_seed"), "构建族解释器要求错误")
        require(len(config["tools"]) == len(set(config["tools"])), "重复构建工具")
        require(all(k in value["tools"] for k in config["tools"]), "未锁构建工具")
        names = {value["tools"][k]["name"] for k in config["tools"]}
        require(names == ({"setuptools", "wheel", "packaging"} if major == 3 else {"setuptools", "wheel"}), "构建工具集合不完整")
        require((major == 3 and config["bootstrap"] is None) or (major == 2 and config["bootstrap"] in value["tools"]
                and value["tools"][config["bootstrap"]]["name"] == "virtualenv"), "独立环境 bootstrap 错误")
        referenced.update(config["tools"])
        if config["bootstrap"]:
            referenced.add(config["bootstrap"])
    require(referenced == set(value["tools"]), "构建计划存在未使用工具")
    require(type(value["jobs"]) is list and {j["id"] for j in value["jobs"]} == JOB_IDS and len(value["jobs"]) == 6, "构建 job 集合错误")
    for job in value["jobs"]:
        inputs.keys(job, ("id", "source", "family", "expected_tags", "consumer_scopes", "content_variant", "validation_boundary"), "job")
        require(job["source"] in value["sources"] and job["family"] in value["families"], "job 依赖未锁")
        source = value["sources"][job["source"]]
        require(job["id"] == source["name"] + "-" + source["version"] + "-" + job["family"]
                and job["expected_tags"] == [job["family"] + "-none-any"], "job 身份或标签错误")
        scopes = [s["id"] for s in manifest["scopes"] if any(p["artifact"] == job["source"] for p in s["packages"])
                  and (s["python_version"].startswith("2.") == (job["family"] == "py2"))]
        require(job["consumer_scopes"] == scopes, "job 消费范围与 J2A 不同")
    return value, manifest, inputs.digest(raw)


def prepare_tools(plan, cache, original_cache, download):
    """仅物化显式锁定工具，不安装，不自动选版，不给 build 阶段联网回退。"""
    result = {}
    for sha, tool in plan["tools"].items():
        path = inputs.artifact_path(cache, tool)
        if not path.exists():
            original = inputs.artifact_path(original_cache, tool)
            if original.exists():
                inputs.inspect_artifact(original, tool)
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("xb") as output:
                    output.write(original.read_bytes())
            else:
                require(download, "工具未物化（请先显式 prepare）：" + tool["filename"])
                inputs.fetch_artifact(cache, tool)
        result[sha] = verify_tool(path, tool)
    return result


def verify_tool(path, tool):
    """核验工具完整字节及 RECORD，PE 仅允许锁定 setuptools launcher 构建数据。"""
    info = inputs.inspect_artifact(path, tool)
    require(info["root_is_purelib"] and all(t.endswith("-none-any") for t in info["tags"]), "构建工具必须是纯 wheel")
    native = info["native_members"]
    if native:
        suffixes = ("", "-32", "-64", "-arm64") if tool["version"] == "74.1.2" else ("", "-32", "-64")
        allowed = {"setuptools/" + kind + suffix + ".exe" for kind in ("cli", "gui") for suffix in suffixes}
        require(tool["name"] == "setuptools" and tool["version"] in ("74.1.2", "41.2.0")
                and {n["path"] for n in native} == allowed and all(n["kind"] == "PE" for n in native)
                and native == tool["inspection"]["native_members"], "未锁定的构建工具原生成员")
    return info


def clean_environment(work, python):
    """切断用户 Python/配置继承；无索引变量是额外约束，网络证明由内核隔离提供。"""
    home, temporary = work / "home", work / "tmp"
    home.mkdir(exist_ok=True)
    temporary.mkdir(exist_ok=True)
    return {"PATH": str(Path(python).parent) + ":/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(temporary),
            "LANG": "en_US.UTF-8" if sys.platform == "darwin" else "C.UTF-8", "LC_ALL": "C",
            "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0",
            "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_CONFIG_FILE": os.devnull,
            "SETUPTOOLS_USE_DISTUTILS": "local", "SOURCE_DATE_EPOCH": "1704067200"}


class Isolation:
    """包装真实操作系统断网机制，使用同一子进程连接对照保存隔离证据。"""

    def __init__(self, backend):
        """只接纳明确选择的 sandbox-exec 或独立 Linux 网络命名空间。"""
        require(backend in ("sandbox-exec", "unshare"), "必须显式选择真实断网机制")
        self.backend = backend
        binary = "/usr/bin/sandbox-exec" if backend == "sandbox-exec" else shutil.which("unshare")
        require(binary, "隔离程序不存在")
        self.identity = file_identity(binary)
        if backend == "sandbox-exec":
            require(sys.platform == "darwin", "sandbox-exec 只适用于 macOS")
            self.prefix = [self.identity["realpath"], "-p", "(version 1) (allow default) (deny network*)"]
        else:
            require(sys.platform == "linux", "unshare 只适用于 Linux")
            self.prefix = [self.identity["realpath"], *( [] if os.geteuid() == 0 else ["--user", "--map-root-user"] ), "--net", "--"]

    def command(self, argv):
        """把每个实际执行构建输入的进程放进同一种内核断网机制。"""
        require(file_identity(self.identity["realpath"]) == self.identity, "隔离程序字节发生变化")
        return self.prefix + list(argv)

    def prove(self, python, work):
        """先证明回环端点可连，再证明相同 Python 子进程受隔离，不能把环境变量当证据。"""
        env = clean_environment(work, python)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(2)
            listener.settimeout(5)
            argv = [python, "-E", "-s", "-c", PROBE, str(listener.getsockname()[1])]
            control = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=15)
            require(control.returncode == 0, "网络成功对照未运行：" + control.stderr)
            normal = json.loads(control.stdout)
            require(normal["connected"], "网络成功对照无法连接，不能证明新增隔离")
            connection, _ = listener.accept()
            with connection:
                require(connection.recv(4) == b"reko", "对照连接未到达监听端")
            denied = subprocess.run(self.command(argv), capture_output=True, text=True, env=env, timeout=15)
            require(denied.returncode == 0, "隔离机制不可用：" + denied.stderr)
            isolated = json.loads(denied.stdout)
            require(not isolated["connected"], "隔离子进程仍可联网")
            if self.backend == "sandbox-exec":
                require(isolated.get("errno") in (1, 13), "没有内核 EPERM/EACCES 断网证据")
            else:
                require(normal["network_namespace"] and normal["network_namespace"] != isolated["network_namespace"], "网络命名空间未改变")
            return {"backend": self.backend, "program": self.identity, "prefix": self.prefix,
                    "control_command": argv, "isolated_command": self.command(argv), "control": normal,
                    "isolated": isolated, "kernel_network_isolation_verified": True}


class Runner:
    """串行执行构建命令，逐条保存 argv、退出码及完整日志。"""

    def __init__(self, isolation, work, python):
        """固定隔离器和独立环境变量，不使用 shell 或 RTK。"""
        self.isolation = isolation
        self.work = work
        self.env = clean_environment(work, python)
        self.commands = []

    def run(self, argv, cwd=None):
        """实际执行隔离命令；失败日志先落盘，再向上返回真实失败。"""
        command = self.isolation.command([str(a) for a in argv])
        record = {"argv": command, "cwd": str(cwd or self.work)}
        self.commands.append(record)
        index = len(self.commands)
        try:
            process = subprocess.run(command, cwd=cwd or self.work, env=self.env, capture_output=True, timeout=300)
            record["returncode"] = process.returncode
            stdout, stderr = process.stdout, process.stderr
        except subprocess.TimeoutExpired as exc:
            record["returncode"] = "timeout"
            stdout, stderr = exc.stdout or b"", exc.stderr or b""
        for label, content in (("stdout", stdout), ("stderr", stderr)):
            name = "command-%02d-%s.log" % (index, label)
            (self.work / name).write_bytes(content)
            record[label] = name
        (self.work / "commands.json").write_text(json.dumps(self.commands, ensure_ascii=False, indent=2) + "\n")
        require(record["returncode"] == 0, "隔离命令失败（见完整日志）：" + str(record["returncode"]))
        return stdout.decode("utf-8")


def extract_wheel(path, destination):
    """仅解包已经完整核验的 wheel；拒绝工具文件覆盖和 wheel 安装方案脚本。"""
    with zipfile.ZipFile(path) as archive:
        require(not any(n.split("/")[0].endswith(".data") for n in archive.namelist()), "构建工具不支持 .data 安装方案")
        for entry in archive.infolist():
            target = destination / inputs.safe_name(entry.filename, "工具")
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as output:
                    output.write(archive.read(entry))


def inspect_source(path, artifact, profile):
    """在执行前复核整个 sdist、已审 setup 字节和无隐式构建依赖的边界。"""
    info = inputs.inspect_artifact(path, artifact)
    prefix = info["archive_root"] + "/"
    build_files = {}
    with tarfile.open(path, "r:*") as archive:
        for member in archive.getmembers():
            relative = member.name[len(prefix):]
            require(not relative.endswith("pyproject.toml"), "拒绝未经审核的 PEP517 构建入口")
            if relative in ("setup.py", "setup.cfg") and member.isfile():
                build_files[relative] = archive.extractfile(member).read()
    require({k: inputs.digest(v) for k, v in build_files.items()} == profile["build_files"], "构建入口字节与审核配方不同")
    text = build_files["setup.py"].decode("utf-8")
    tree = ast.parse(text)
    require(not any(isinstance(n, ast.keyword) and n.arg == "setup_requires" for n in ast.walk(tree))
            and "setup_requires" not in text, "禁止 setup_requires 隐式下载")
    if "setup.cfg" in build_files:
        config = configparser.ConfigParser(interpolation=None)
        config.read_string(build_files["setup.cfg"].decode("utf-8"))
        require(not any(config.has_option(section, "setup_requires") for section in config.sections()), "配置含 setup_requires")
    return info


def extract_source(path, destination, root):
    """逐个复制已核验普通文件，不调用 tar.extractall，也不接受源链接。"""
    with tarfile.open(path, "r:*") as archive:
        for member in archive.getmembers():
            target = destination / inputs.safe_name(member.name, "源码")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                require(member.isfile(), "源码类型变化")
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as output:
                    output.write(archive.extractfile(member).read())
    return destination / root


def check_tool_dependencies(tool_infos, version, parser):
    """用锁定官方 PEP508 解析器核对构建依赖闭包，测试/docs extra 不作为构建依赖。"""
    env = parser["markers"].default_environment()
    env.update(python_version=".".join(version.split(".")[:2]), python_full_version=version, extra="")
    versions = {x["metadata"]["name"]: x["metadata"]["version"] for x in tool_infos}
    for info in tool_infos:
        require(parser["specifiers"].SpecifierSet(info["metadata"]["requires_python"]).contains(version), "构建工具不支持解释器版本")
        for text in info["metadata"]["requires_dist"]:
            req = parser["requirements"].Requirement(text)
            if req.marker and not req.marker.evaluate(env):
                continue
            require(not req.url and not req.extras and inputs.canonical(req.name) in versions
                    and parser["version"].Version(versions[inputs.canonical(req.name)]) in req.specifier, "未锁构建工具依赖：" + text)


def verify_output(path, job, source, parser):
    """核对新 wheel 身份、完整 RECORD、真实纯度和 Python 主版本内容，绝不重标标签。"""
    info = inputs.read_wheel(inputs.regular_path(path))
    name, version, _, tags = parser["utils"].parse_wheel_filename(path.name)
    require(name == source["name"] and str(version) == source["version"]
            and info["metadata"]["name"] == name and info["metadata"]["version"] == source["version"], "生成 wheel 名称/版本错误")
    require(info["root_is_purelib"] and not info["native_members"] and info["tags"] == job["expected_tags"]
            and all(t.abi == "none" and t.platform == "any" for t in tags), "生成 wheel 原生成员/平台 ABI/标签不合格")
    require(sorted(info["metadata"]["requires_dist"]) == sorted(source["runtime_requires"]), "生成 wheel 运行依赖偏离已锁源码")
    require(info["metadata"]["requires_python"] == source["runtime_requires_python"], "生成 wheel Python 版本限制改变")
    if source["name"] == "future":
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
        py2_content = {"builtins/__init__.py", "copyreg/__init__.py", "queue/__init__.py", "http/__init__.py"}
        require((py2_content <= names) if job["family"] == "py2" else not (py2_content & names), "future Python 主版本内容不符")
    content = path.read_bytes()
    return {"filename": path.name, "sha256": inputs.digest(content), "size": len(content), "inspection": info}


def build_job(job, plan, manifest, source_cache, tool_cache, parser, python_identity, isolation, work):
    """用明确解释器建立无 pip 独立环境并执行一个已锁源码，返回实际产物而非预填成功。"""
    family = plan["families"][job["family"]]
    source = plan["sources"][job["source"]]
    artifact = manifest["artifacts"][job["source"]]
    original = inputs.artifact_path(source_cache, artifact)
    source_info = inspect_source(original, artifact, source)
    runner = Runner(isolation, work, python_identity["realpath"])
    python = python_identity["realpath"]
    identity = json.loads(runner.run([python, "-E", "-s", "-c", IDENTITY]))
    require(identity["implementation"] == "CPython" and int(identity["version"].split(".")[0]) == family["python_major"]
            and parser["specifiers"].SpecifierSet(family["python_specifier"]).contains(identity["version"]), "解释器不满足 job 主版本/工具要求")
    tool_ids = family["tools"] + ([family["bootstrap"]] if family["bootstrap"] else [])
    tool_infos = [verify_tool(inputs.artifact_path(tool_cache, plan["tools"][sha]), plan["tools"][sha]) for sha in tool_ids]
    check_tool_dependencies(tool_infos, identity["version"], parser)
    require(parser["specifiers"].SpecifierSet(source_info["metadata"]["requires_python"]).contains(identity["version"]), "源码不支持构建解释器")
    environment = work / "environment"
    if family["python_major"] == 3:
        runner.run([python, "-I", "-m", "venv", "--without-pip", "--copies", str(environment)])
    else:
        bootstrap = work / "bootstrap"
        bootstrap.mkdir()
        extract_wheel(inputs.artifact_path(tool_cache, plan["tools"][family["bootstrap"]]), bootstrap)
        runner.run([python, "-E", "-s", str(bootstrap / "virtualenv.py"), "--no-pip", "--no-setuptools", "--no-wheel", str(environment)])
    env_python = environment / "bin/python"
    site_code = "import json,sys,site;print(json.dumps({'prefix':sys.prefix,'sites':site.getsitepackages(),'user':site.ENABLE_USER_SITE,'pip':__import__('pkgutil').find_loader('pip') is not None}))"
    details = json.loads(runner.run([str(env_python), "-E", "-s", "-c", site_code]))
    require(Path(details["prefix"]).resolve() == environment.resolve() and not details["user"] and not details["pip"], "独立环境继承外部 site 或 pip")
    sites = [Path(p) for p in details["sites"] if Path(p).is_relative_to(environment)]
    require(sites and all(Path(p).is_relative_to(environment) for p in details["sites"]), "环境 site-packages 越界")
    site = sites[0]
    site.mkdir(parents=True, exist_ok=True)
    for sha in family["tools"]:
        extract_wheel(inputs.artifact_path(tool_cache, plan["tools"][sha]), site)
    check_code = "import json,os,setuptools,wheel;print(json.dumps({x.__name__:{'file':x.__file__,'version':x.__version__} for x in (setuptools,wheel)}))"
    installed = json.loads(runner.run([str(env_python), "-E", "-s", "-c", check_code]))
    for module, actual in installed.items():
        expected = next(plan["tools"][sha] for sha in family["tools"] if plan["tools"][sha]["name"] == module)
        require(Path(actual["file"]).is_relative_to(site) and actual["version"] == expected["version"], "实际构建模块被环境版本替换")
    staging = work / "source"
    staging.mkdir()
    source_root = extract_source(original, staging, source_info["archive_root"])
    output = work / "output"
    output.mkdir()
    script = "import sys,runpy;sys.path.insert(0,sys.argv[1]);root=sys.argv.pop(1);sys.argv=['setup.py','bdist_wheel','--dist-dir',sys.argv[1]];runpy.run_path(root+'/setup.py',run_name='__main__')"
    runner.run([str(env_python), "-E", "-s", "-c", script, str(source_root), str(output)], cwd=source_root)
    files = list(output.iterdir())
    require(len(files) == 1 and files[0].suffix == ".whl", "构建输出不是唯一 wheel")
    product = verify_output(files[0], job, source, parser)
    require(file_identity(python) == {**python_identity, "requested_path": python}, "构建期间解释器字节变化")
    inputs.inspect_artifact(original, artifact)
    for sha in tool_ids:
        verify_tool(inputs.artifact_path(tool_cache, plan["tools"][sha]), plan["tools"][sha])
    return {"status": "builder_content_verified", "source_artifact": artifact, "source_recipe": source,
            "interpreter": {**python_identity, "runtime": identity}, "environment": details, "loaded_tools": installed,
            "tool_inputs": {sha: plan["tools"][sha] for sha in tool_ids}, "commands": runner.commands,
            "output": product, "output_path": str(files[0]), "actual_target_interpreter_verified": False,
            "target_import_verified": False, "offline_consumer_verified": False, "ios_runtime_verified": False}


def main(argv=None):
    """显式 prepare/build，所有构建结果写全新目录；失败保留具体证据和非零退出。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "build"))
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--source-cache", type=Path, default=inputs.DEFAULT_CACHE)
    parser.add_argument("--tool-cache", type=Path, default=DEFAULT_WORK / "tools")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--python", type=Path)
    parser.add_argument("--python-sha256")
    parser.add_argument("--isolation", choices=("sandbox-exec", "unshare"))
    parser.add_argument("--job", action="append", default=[])
    args = parser.parse_args(argv)
    report_dir = inputs.regular_path(args.report)
    report_dir.mkdir(parents=True, exist_ok=False)
    report = {"task": "R00-02J2B1", "command": args.command, "status": "failed", "jobs": [],
              "target_runtime_acceptance": False, "parent_J2B_complete": False}
    try:
        plan, manifest, plan_hash = load_plan(args.plan)
        report.update(plan_sha256=plan_hash, j2a_manifest_sha256=plan["j2a_manifest_sha256"], limitations=plan["limitations"])
        report["tools"] = prepare_tools(plan, inputs.regular_path(args.tool_cache), inputs.regular_path(args.source_cache), args.command == "prepare")
        if args.command == "prepare":
            report["status"] = "tool_bytes_verified_no_install"
        else:
            require(args.python and args.python_sha256 and inputs.SHA.fullmatch(args.python_sha256), "必须显式提供解释器和实际 SHA256")
            require(args.job and len(set(args.job)) == len(args.job) and set(args.job) <= JOB_IDS, "必须明确选择唯一有效 job")
            identity = file_identity(args.python)
            require(identity["sha256"] == args.python_sha256, "解释器字节 hash 不符")
            report["interpreter"] = identity
            isolation = Isolation(args.isolation)
            report["network_isolation"] = isolation.prove(identity["realpath"], report_dir)
            actual_parser = inputs.load_parser(args.source_cache, manifest)
            for job in plan["jobs"]:
                if job["id"] not in args.job:
                    report["jobs"].append({"id": job["id"], "status": "not_run", "reason": "本次未选择；缺失实际解释器/目标环境时不计通过"})
                    continue
                work = report_dir / job["id"]
                work.mkdir()
                try:
                    log("开始隔离构建：" + job["id"])
                    result = build_job(job, plan, manifest, args.source_cache, args.tool_cache, actual_parser, identity, isolation, work)
                    report["jobs"].append({"id": job["id"], **result})
                    log("纯内容候选通过：" + job["id"])
                except Exception as exc:
                    report["jobs"].append({"id": job["id"], "status": "failed", "error": type(exc).__name__ + ": " + str(exc), "work": str(work)})
                    log("构建失败：" + job["id"] + "；" + str(exc))
            require(all(j["status"] != "failed" for j in report["jobs"]), "部分实际 job 失败，详见结果与命令日志")
            report["status"] = "selected_builder_content_verified"
    except Exception as exc:
        report["error"] = type(exc).__name__ + ": " + str(exc)
        log("失败：" + report["error"])
    finally:
        (report_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return 1 if report["status"] == "failed" else 0


if __name__ == "__main__":
    sys.exit(main())
