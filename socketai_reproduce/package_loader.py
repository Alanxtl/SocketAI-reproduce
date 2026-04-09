from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from socketai_reproduce.config import compact_path_label
from utils.find_archives import ARCHIVE_EXTS, extract_archive, iter_dangerous_files

LIFECYCLE_SCRIPT_NAMES = ("preinstall", "install", "postinstall")
KNOWN_COMMANDS = {
    "bash",
    "bun",
    "cmd",
    "cross-env",
    "node",
    "nodejs",
    "npm",
    "npx",
    "pnpm",
    "powershell",
    "pwsh",
    "sh",
    "tsx",
    "yarn",
}

PATH_TOKEN_RE = re.compile(r"(?P<token>(?:\.{0,2}[\\/])?[\w./\\-]+(?:\.[A-Za-z0-9]+)?)")


@dataclass(slots=True)
class LoadedPackage:
    source_input: Path
    package_root: Path
    workspace_root: Path
    is_archive: bool
    package_json_path: Path | None
    package_json: dict[str, Any]
    lifecycle_scripts: dict[str, str]
    install_script_files: list[Path] = field(default_factory=list)
    base_candidate_files: list[Path] = field(default_factory=list)

    @property
    def package_name(self) -> str:
        return str(self.package_json.get("name") or self.package_root.name)

    @property
    def package_version(self) -> str | None:
        value = self.package_json.get("version")
        return str(value) if value is not None else None

    def relative_path(self, path: Path) -> str:
        return path.resolve().relative_to(self.package_root.resolve()).as_posix()

    def build_file_id(self, path: Path) -> str:
        digest = hashlib.sha1(self.relative_path(path).encode("utf-8")).hexdigest()[:12]
        stem = compact_path_label(path.stem or "file", max_length=20, default="file")
        return f"{stem}-{digest}"


def is_archive_path(path: Path) -> bool:
    lower = path.name.lower()
    return any(lower.endswith(ext) for ext in ARCHIVE_EXTS)


def load_package(input_path: Path, scratch_root: Path) -> LoadedPackage:
    source_input = input_path.resolve()
    scratch_root.mkdir(parents=True, exist_ok=True)

    if source_input.is_dir():
        package_root = source_input
        workspace_root = source_input
        is_archive = False
    elif source_input.is_file() and is_archive_path(source_input):
        package_root = extract_archive(source_input, scratch_root)
        workspace_root = package_root
        is_archive = True
    else:
        raise ValueError(
            f"Unsupported input path: {source_input}. Expected a directory or npm archive."
        )

    package_json_path = package_root / "package.json"
    package_json = {}
    if package_json_path.exists():
        package_json = json.loads(package_json_path.read_text(encoding="utf-8", errors="ignore"))
    else:
        package_json_path = None

    lifecycle_scripts = extract_lifecycle_scripts(package_json)
    install_script_files = resolve_install_script_files(package_root, lifecycle_scripts)
    base_candidate_files = select_candidate_files(package_root, package_json_path, install_script_files)

    return LoadedPackage(
        source_input=source_input,
        package_root=package_root,
        workspace_root=workspace_root,
        is_archive=is_archive,
        package_json_path=package_json_path,
        package_json=package_json,
        lifecycle_scripts=lifecycle_scripts,
        install_script_files=install_script_files,
        base_candidate_files=base_candidate_files,
    )


def extract_lifecycle_scripts(package_json: dict[str, Any]) -> dict[str, str]:
    scripts = package_json.get("scripts")
    if not isinstance(scripts, dict):
        return {}
    return {
        name: str(command)
        for name, command in scripts.items()
        if name in LIFECYCLE_SCRIPT_NAMES and isinstance(command, str)
    }


def resolve_install_script_files(package_root: Path, lifecycle_scripts: dict[str, str]) -> list[Path]:
    resolved: dict[Path, None] = {}
    for command in lifecycle_scripts.values():
        for token in _extract_candidate_path_tokens(command):
            candidate = _resolve_script_token(package_root, token)
            if candidate is not None:
                resolved[candidate] = None
    return sorted(resolved, key=lambda path: path.as_posix())


def select_candidate_files(
    package_root: Path, package_json_path: Path | None, install_script_files: list[Path]
) -> list[Path]:
    candidates: dict[Path, None] = {}
    for path in iter_dangerous_files(package_root):
        candidates[path.resolve()] = None
    if package_json_path is not None and package_json_path.exists():
        candidates[package_json_path.resolve()] = None
    for path in install_script_files:
        candidates[path.resolve()] = None
    return sorted(candidates, key=lambda path: path.as_posix())


def _extract_candidate_path_tokens(command: str) -> list[str]:
    tokens: list[str] = []
    for match in PATH_TOKEN_RE.finditer(command):
        token = match.group("token").strip().strip("'\"")
        if not token or token in KNOWN_COMMANDS:
            continue
        if token.startswith("-") or "=" in token or "://" in token:
            continue
        if token.startswith("$") or token.startswith("%"):
            continue
        tokens.append(token)
    return tokens


def _resolve_script_token(package_root: Path, token: str) -> Path | None:
    path = Path(token)
    if path.is_absolute():
        return None
    candidate = (package_root / path).resolve()
    try:
        candidate.relative_to(package_root.resolve())
    except ValueError:
        return None
    if candidate.is_file():
        return candidate
    return None
