#!/usr/bin/env python3
"""锁定并复核受 Git 跟踪的源码输入；不执行上游配方，不代表完整构建闭包。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import unicodedata


ROOT = Path(__file__).resolve().parents[2]
SCOPE = "versioned_inputs_only"
NOT_COVERED = ["pip_distributions", "remote_source_checkouts", "host_packages_and_runner",
               "untracked_files", "ignored_files", "symlink_target_materialization"]
MODES = {"100644", "100755", "120000"}
REPOSITORY_KEYS = {"role", "release", "abi", "python", "path", "commit", "tree",
                   "object_format", "file_count", "files"}
CI_KEYS = {"verified_ci_commit", "verified_ci_tree", "upstream_commit", "upstream_tree",
           "diff_from_upstream", "diff_from_verified_ci", "execution_code_matches_verified_ci"}
RUNTIME_ANCHOR_FIELDS = ["schema_version", "releases[].release", "releases[].abi",
                         "releases[].source_recipe.python", "releases[].build_repository.path",
                         "releases[].build_repository.commit"]


class InputError(ValueError):
    """表示输入身份或证据契约不满足，调用方必须明确失败。"""


def require(condition: bool, message: str) -> None:
    """缺失或不一致立即失败，不把未知值转换成成功。"""
    if not condition:
        raise InputError(message)


def relative_path(value: str) -> str:
    """接纳唯一 UTF-8 POSIX 相对路径，拒绝越界和可混淆写法。"""
    require(type(value) is str and bool(value) and "\\" not in value
            and not any(ord(c) < 32 or ord(c) == 127 for c in value), "相对路径格式错误")
    require(not PurePosixPath(value).is_absolute()
            and all(part not in ("", ".", "..") for part in value.split("/")), "相对路径越界或未规范化：" + value)
    return value


def guard_parents(path: Path) -> None:
    """所有父目录都必须是实际目录，叶子链接由文件类型检查单独处理。"""
    require(path.is_absolute(), "路径必须是绝对路径")
    for parent in path.parents:
        require(not parent.is_symlink(), "父目录拒绝符号链接：" + str(parent))


def absolute_path(path: Path, root: Path) -> Path:
    """展开调用路径但不跟随符号链接，保留后续类型校验的边界。"""
    result = Path(os.path.abspath(root / path))
    guard_parents(result)
    return result


def pairs_without_duplicates(pairs: list) -> dict:
    """JSON 重复键不得覆盖原值后伪装成完整证据。"""
    result = {}
    for key, value in pairs:
        require(key not in result, "JSON 存在重复键：" + key)
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    """拒绝 JSON 非有限数值，不让非标准常量进入输入身份。"""
    raise InputError("JSON 非有限常量：" + value)


def read_json(path: Path) -> tuple[dict, str]:
    """读取实际普通 JSON 文件，同时保存原字节身份。"""
    guard_parents(path)
    require(not path.is_symlink() and path.is_file(), "缺少普通 JSON 文件：" + str(path))
    content = path.read_bytes()
    value = json.loads(content, object_pairs_hook=pairs_without_duplicates, parse_constant=reject_nonfinite)
    require(type(value) is dict, "JSON 根节点必须为对象")
    return value, hashlib.sha256(content).hexdigest()


def git(repository: Path, *args: str) -> bytes:
    """直接只读调用 Git，禁用 fsmonitor；开发交互代理不作为构建依赖。"""
    command = ["git", "-c", "core.fsmonitor=false", "-C", str(repository), *args]
    result = subprocess.run(command, capture_output=True)
    require(result.returncode == 0, "Git 查询失败：" + args[0])
    return result.stdout


def oid(value: str, object_format: str) -> str:
    """只接受对应对象格式的完整小写 OID，不允许分支或缩写代替。"""
    length = {"sha1": 40, "sha256": 64}[object_format]
    require(type(value) is str and re.fullmatch("[0-9a-f]{%d}" % length, value) is not None, "Git OID 格式错误")
    return value


def tracked_tree(repository: Path, commit: str, object_format: str) -> tuple[str, dict]:
    """读取锁定提交的完整树，拒绝子模块和同一路径的别名。"""
    oid(commit, object_format)
    actual = git(repository, "rev-parse", "--verify", commit + "^{commit}").decode().strip()
    require(actual == commit, "Git 提交身份错误")
    tree = git(repository, "rev-parse", commit + "^{tree}").decode().strip()
    records = {}
    aliases = set()
    for record in git(repository, "ls-tree", "-r", "-z", commit).split(b"\0"):
        if not record:
            continue
        header, raw_path = record.split(b"\t", 1)
        mode, kind, blob = header.decode("ascii").split()
        path = relative_path(raw_path.decode("utf-8"))
        alias = unicodedata.normalize("NFC", path).casefold()
        require(path not in records and alias not in aliases, "Git 树存在重复或大小写/Unicode路径别名：" + path)
        require(mode in MODES and kind == "blob", "拒绝子模块或未知 Git 类型：" + path)
        records[path] = {"mode": mode, "blob_oid": oid(blob, object_format)}
        aliases.add(alias)
    require(bool(records), "Git 树不能为空")
    return oid(tree, object_format), records


def validate_index(repository: Path, expected: dict) -> None:
    """索引必须逐项等于锁定树；暂存、冲突、增加和删除都不能放行。"""
    actual = {}
    for record in git(repository, "ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        header, raw_path = record.split(b"\t", 1)
        mode, blob, stage = header.decode("ascii").split()
        path = relative_path(raw_path.decode("utf-8"))
        require(stage == "0" and path not in actual, "Git 索引包含冲突或重复路径")
        actual[path] = {"mode": mode, "blob_oid": blob}
    require(actual == expected, "Git 索引与锁定 tree 不一致")


def file_identity(path: Path, mode: str, object_format: str) -> tuple[int, str, str, str | None]:
    """直接读取工作区原字节计算 Git blob 和 SHA256，绕过 Git stat 缓存。"""
    guard_parents(path)
    info = path.lstat()
    target = None
    if mode == "120000":
        require(stat.S_ISLNK(info.st_mode), "实际文件应为符号链接：" + str(path))
        target = os.readlink(path)
        content = os.fsencode(target)
        size = len(content)
        sha = hashlib.sha256(content)
        blob = hashlib.new(object_format, b"blob " + str(size).encode() + b"\0" + content)
    else:
        require(stat.S_ISREG(info.st_mode), "实际文件不是普通文件：" + str(path))
        executable = bool(info.st_mode & stat.S_IXUSR)
        require(executable == (mode == "100755"), "工作区可执行位与 Git mode 不符：" + str(path))
        size = info.st_size
        sha = hashlib.sha256()
        blob = hashlib.new(object_format, b"blob " + str(size).encode() + b"\0")
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
            opened = os.fstat(stream.fileno())
            require((opened.st_dev, opened.st_ino, opened.st_size) == (info.st_dev, info.st_ino, size), "读取期间文件身份改变")
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                sha.update(block)
                blob.update(block)
            after = os.fstat(stream.fileno())
            require((after.st_size, after.st_mtime_ns) == (size, opened.st_mtime_ns), "读取期间文件内容改变")
    return size, sha.hexdigest(), blob.hexdigest(), target


def validate_links(links: dict) -> None:
    """只解析受跟踪链接文字的树内关系，拒绝逃逸和循环，不要求目标已物化。"""
    for path, target in links.items():
        require(type(target) is str and bool(target) and not target.startswith("/")
                and "\\" not in target and not any(ord(c) < 32 for c in target), "链接目标必须为相对路径：" + path)
        pending = list(PurePosixPath(path).parent.parts) + target.split("/")
        resolved, seen = [], set()
        while pending:
            part = pending.pop(0)
            if part in ("", "."):
                continue
            if part == "..":
                require(bool(resolved), "链接目标逃逸源码树：" + path)
                resolved.pop()
                continue
            resolved.append(part)
            prefix = "/".join(resolved)
            if prefix in links:
                require(prefix not in seen, "受跟踪链接存在循环：" + path)
                seen.add(prefix)
                replacement = links[prefix]
                require(not replacement.startswith("/") and "\\" not in replacement, "链接链存在绝对目标")
                resolved.pop()
                pending = replacement.split("/") + pending


def snapshot(repository: Path, expected_commit: str) -> dict:
    """核对提交、索引与每个工作区文件，生成受跟踪输入的精确快照。"""
    guard_parents(repository)
    require(not repository.is_symlink() and repository.is_dir(), "缺少实际源码目录：" + str(repository))
    require(Path(git(repository, "rev-parse", "--show-toplevel").decode().strip()) == repository, "源码路径不是 Git 工作树根")
    object_format = git(repository, "rev-parse", "--show-object-format").decode().strip()
    require(object_format in ("sha1", "sha256"), "不支持的 Git 对象格式")
    oid(expected_commit, object_format)
    require(git(repository, "rev-parse", "HEAD").decode().strip() == expected_commit, "Git HEAD 与明确锁定 commit 不符")
    tree, expected = tracked_tree(repository, expected_commit, object_format)
    validate_index(repository, expected)
    files, links = [], {}
    for path, item in sorted(expected.items()):
        size, sha, actual_blob, target = file_identity(repository / path, item["mode"], object_format)
        require(actual_blob == item["blob_oid"], "工作区原字节与 Git blob 不符：" + path)
        row = {"path": path, **item, "sha256": sha, "size": size}
        if target is not None:
            row["link_target"] = target
            links[path] = target
        files.append(row)
    validate_links(links)
    return {"commit": expected_commit, "tree": tree, "object_format": object_format,
            "file_count": len(files), "files": files}


def tree_difference(before: dict, after: dict) -> list:
    """保存两个精确树的每条路径差异，不把当前检出冒充历史 CI。"""
    return [{"path": path, "before": before.get(path), "after": after.get(path)}
            for path in sorted(before.keys() | after.keys()) if before.get(path) != after.get(path)]


def collect(root: Path, runtime_path: Path, execution_repository: str, execution_release: str,
            execution_commit: str, verified_ci_commit: str) -> dict:
    """以主锁和调用者明确提交为独立锚点捕获全部官方树及 CI 执行树。"""
    lock, _ = read_json(runtime_path)
    require(type(lock.get("schema_version")) is int and lock["schema_version"] == 1, "runtime-lock schema错误")
    releases = lock.get("releases")
    require(type(releases) is list and bool(releases), "runtime-lock 缺少版本列表")
    repositories, identities, paths, anchors = [], set(), set(), []
    for release in releases:
        name, abi = release["release"], release["abi"]
        python = release["source_recipe"]["python"]
        require(type(name) is str and name not in identities, "runtime-lock 版本缺失或重复")
        require(abi in {"cp27", "cp39", "cp312"} and type(python) is str
                and python.startswith({"cp27": "2.7.", "cp39": "3.9.", "cp312": "3.12."}[abi]), "ABI/Python配对错误")
        path = relative_path(release["build_repository"]["path"])
        require(path not in paths, "官方源码路径重复")
        identities.add(name)
        paths.add(path)
        anchors.append({"release": name, "abi": abi, "source_recipe": {"python": python},
                        "build_repository": {"path": path, "commit": release["build_repository"]["commit"]}})
        repositories.append({"role": "official", "release": name, "abi": abi, "python": python,
                             "path": path, **snapshot(root / path, release["build_repository"]["commit"])})
    require(execution_release in identities, "执行配方版本不在主锁中")
    path = relative_path(execution_repository)
    require(path not in paths, "执行配方必须与官方基线分开检出")
    base = next(row for row in repositories if row["release"] == execution_release)
    repository = root / path
    current = snapshot(repository, execution_commit)
    ci_tree, ci_entries = tracked_tree(repository, verified_ci_commit, current["object_format"])
    upstream_tree, upstream_entries = tracked_tree(repository, base["commit"], current["object_format"])
    require(upstream_tree == base["tree"], "执行配方的上游树身份不符")
    require(subprocess.run(["git", "-C", str(repository), "merge-base", "--is-ancestor",
                            base["commit"], verified_ci_commit], capture_output=True).returncode == 0, "成功CI不是锁定上游的后代")
    require(subprocess.run(["git", "-C", str(repository), "merge-base", "--is-ancestor",
                            verified_ci_commit, execution_commit], capture_output=True).returncode == 0, "当前执行树不是成功CI的后代")
    _, current_entries = tracked_tree(repository, execution_commit, current["object_format"])
    ci_diff = tree_difference(ci_entries, current_entries)
    require(all(row["path"] == "CI_IOS.md" and row["before"] is not None and row["after"] is not None
                and row["before"]["mode"] == row["after"]["mode"] == "100644" for row in ci_diff), "当前执行代码与锁定成功CI不一致")
    repositories.append({"role": "ci_execution", "release": execution_release, "abi": base["abi"],
                         "python": base["python"], "path": path, **current,
                         "verified_ci_commit": verified_ci_commit, "verified_ci_tree": ci_tree,
                         "upstream_commit": base["commit"], "upstream_tree": upstream_tree,
                         "diff_from_upstream": tree_difference(upstream_entries, current_entries),
                         "diff_from_verified_ci": ci_diff, "execution_code_matches_verified_ci": True})
    # 只锁实际消费的字段投影；后续主锁引用本清单时不会形成相互依赖的文件hash。
    anchor = {"schema_version": lock["schema_version"], "releases": anchors}
    anchor_sha = hashlib.sha256(json.dumps(anchor, ensure_ascii=False, sort_keys=True,
                                          separators=(",", ":")).encode("utf-8")).hexdigest()
    return {"schema_version": 1, "scope": SCOPE, "complete_closure": False,
            "not_covered": NOT_COVERED, "runtime_anchor_sha256": anchor_sha, "repositories": repositories}


def validate_manifest(manifest: dict) -> None:
    """验证固定清单模式，拒绝缺项、多项、重复路径和弱类型成功值。"""
    require(set(manifest) == {"schema_version", "scope", "complete_closure", "not_covered",
                             "runtime_anchor_sha256", "repositories"}, "清单顶层字段不符")
    require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1
            and manifest["scope"] == SCOPE and manifest["complete_closure"] is False
            and manifest["not_covered"] == NOT_COVERED, "清单范围/schema错误")
    require(type(manifest["runtime_anchor_sha256"]) is str
            and re.fullmatch("[0-9a-f]{64}", manifest["runtime_anchor_sha256"]), "主锁字段投影SHA256格式错误")
    require(type(manifest["repositories"]) is list and bool(manifest["repositories"]), "清单源码列表缺失")
    for repository in manifest["repositories"]:
        role = repository.get("role")
        require(role in ("official", "ci_execution") and set(repository) == REPOSITORY_KEYS | (CI_KEYS if role == "ci_execution" else set()), "源码清单字段不符")
        require(repository["object_format"] in ("sha1", "sha256"), "清单对象格式错误")
        for key in ("commit", "tree"):
            oid(repository[key], repository["object_format"])
        require(type(repository["file_count"]) is int and type(repository["files"]) is list
                and repository["file_count"] == len(repository["files"]) > 0, "清单文件数量不符")
        previous, aliases = None, set()
        for row in repository["files"]:
            require(type(row) is dict and row.get("mode") in MODES, "清单文件类型错误")
            require(set(row) == {"path", "mode", "blob_oid", "sha256", "size"} | ({"link_target"} if row["mode"] == "120000" else set()), "清单文件字段不符")
            path = relative_path(row["path"])
            alias = unicodedata.normalize("NFC", path).casefold()
            require((previous is None or path > previous) and alias not in aliases, "清单路径重复/错序/别名")
            previous = path
            aliases.add(alias)
            oid(row["blob_oid"], repository["object_format"])
            require(type(row["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", row["sha256"])
                    and type(row["size"]) is int and row["size"] >= 0, "清单SHA256/字节数错误")
            if row["mode"] == "120000":
                require(type(row["link_target"]) is str, "清单链接文字错误")
        if role == "ci_execution":
            require(repository["execution_code_matches_verified_ci"] is True
                    and type(repository["diff_from_upstream"]) is list
                    and type(repository["diff_from_verified_ci"]) is list, "CI关系字段错误")


def write_new(path: Path, value: dict) -> None:
    """只创建全新普通输出，不覆盖既有报告、清单或链接。"""
    guard_parents(path)
    require(not path.exists() and not path.is_symlink(), "输出已存在，拒绝覆盖：" + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    """执行捕获或复核，始终明确记录有限范围与真实失败。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("capture", "verify"))
    parser.add_argument("--runtime-lock", type=Path, required=True)
    parser.add_argument("--execution-repository", required=True)
    parser.add_argument("--execution-release", required=True)
    parser.add_argument("--execution-commit", required=True)
    parser.add_argument("--verified-ci-commit", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    report = {"schema_version": 1, "mode": args.mode, "scope": SCOPE,
              "complete_closure": False, "not_covered": NOT_COVERED, "result": "failed", "errors": []}
    output = None
    try:
        root = absolute_path(root, Path.cwd())
        output = absolute_path(args.report, root)
        require(not output.exists() and not output.is_symlink(), "报告已存在，拒绝覆盖")
        manifest_path = absolute_path(args.manifest, root)
        runtime_path = absolute_path(args.runtime_lock, root)
        require(output not in (manifest_path, runtime_path) and manifest_path != runtime_path, "输入输出路径不能重合")
        if args.mode == "capture":
            require(not manifest_path.exists() and not manifest_path.is_symlink(), "清单已存在，拒绝覆盖")
        else:
            manifest, manifest_sha = read_json(manifest_path)
            validate_manifest(manifest)
        actual = collect(root, runtime_path, args.execution_repository, args.execution_release,
                         args.execution_commit, args.verified_ci_commit)
        validate_manifest(actual)
        if args.mode == "capture":
            write_new(manifest_path, actual)
            _, manifest_sha = read_json(manifest_path)
        else:
            require(manifest == actual, "清单与主锁/明确提交/实际源码输入不一致")
        report.update(result="passed", manifest=str(manifest_path), manifest_sha256=manifest_sha,
                      runtime_lock_sha256=read_json(runtime_path)[1],
                      runtime_anchor_sha256=actual["runtime_anchor_sha256"],
                      runtime_anchor_fields=RUNTIME_ANCHOR_FIELDS,
                      repositories=[{k: row[k] for k in ("role", "release", "commit", "tree", "file_count")}
                                    for row in actual["repositories"]])
    except (InputError, OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError) as error:
        report["errors"].append(str(error))
    if output is not None:
        try:
            write_new(output, report)
        except (InputError, OSError) as error:
            report["result"] = "failed"
            report["errors"].append(str(error))
    print("[RenPySourceInputs] " + ("通过；仅覆盖受跟踪输入，完整闭包仍未完成" if report["result"] == "passed"
                                     else "失败：" + "; ".join(report["errors"])), flush=True)
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
