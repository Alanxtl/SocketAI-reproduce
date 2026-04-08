from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlparse

from socketai_reproduce.analysis.models import CodeQLFinding, CodeQLResult

CODEQL_PACK_LOCK = "codeql-pack.lock.yml"
SMART_QUOTE_CHARS = "\"'`\u201c\u201d\u2018\u2019"
MISSING_PACK_HINTS = (
    "pack 'codeql/javascript-all' was not found",
    "no valid pack solution found",
    "run 'codeql pack install'",
    "referenced pack",
)


class CodeQLSetupError(RuntimeError):
    """Raised when the CodeQL environment is unavailable or misconfigured."""


class CodeQLExecutionError(RuntimeError):
    """Raised when CodeQL executes but fails to build the database or analyze it."""


class CodeQLPrescreener:
    def __init__(
        self,
        *,
        codeql_bin: str | None = None,
        query_suite: Path | None = None,
    ) -> None:
        self.codeql_bin = codeql_bin
        self.query_suite = query_suite or (
            Path(__file__).resolve().parent.parent / "codeql_queries" / "socketai-javascript.qls"
        )

    def screen(self, package_root: Path, output_dir: Path) -> CodeQLResult:
        codeql_bin = resolve_codeql_bin(self.codeql_bin)
        if codeql_bin is None:
            raise CodeQLSetupError(
                "CodeQL was requested but no executable was found. "
                "Install CodeQL and expose it on PATH or set CODEQL_BIN."
            )

        package_root = package_root.resolve()
        output_dir = output_dir.resolve()
        query_suite = self.query_suite.resolve()
        query_pack_root = resolve_query_pack_root(query_suite)
        output_dir.mkdir(parents=True, exist_ok=True)
        database_dir = (output_dir / "database").resolve()
        sarif_path = (output_dir / "results.sarif").resolve()

        pack_install_cmd = [
            codeql_bin,
            "pack",
            "install",
            "--",
            str(query_pack_root),
        ]
        create_cmd = [
            codeql_bin,
            "database",
            "create",
            str(database_dir),
            "--overwrite",
            "--language=javascript",
            f"--source-root={package_root}",
        ]
        analyze_cmd = [
            codeql_bin,
            "database",
            "analyze",
            str(database_dir),
            str(query_suite),
            "--format=sarifv2.1.0",
            f"--output={sarif_path}",
            "--rerun",
            "--threads=0",
        ]

        command_lines: list[list[str]] = []
        if should_run_pack_install(query_pack_root):
            self._run_command(pack_install_cmd, query_pack_root)
            command_lines.append(pack_install_cmd)
        self._run_command(create_cmd, package_root)
        command_lines.append(create_cmd)
        try:
            self._run_command(analyze_cmd, package_root)
        except CodeQLExecutionError as exc:
            if not should_retry_pack_install(exc):
                raise
            self._run_command(pack_install_cmd, query_pack_root)
            command_lines.append(pack_install_cmd)
            self._run_command(analyze_cmd, package_root)
        command_lines.append(analyze_cmd)

        findings = parse_sarif_findings(sarif_path, package_root)
        candidate_files = sorted({finding.file_path for finding in findings})
        return CodeQLResult(
            enabled=True,
            status="success",
            query_suite=str(query_suite),
            database_path=str(database_dir),
            results_path=str(sarif_path),
            codeql_bin=codeql_bin,
            candidate_files=candidate_files,
            findings=findings,
            command_lines=command_lines,
        )

    def _run_command(self, command: list[str], cwd: Path) -> None:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            env=build_sanitized_codeql_env(),
        )
        if completed.returncode != 0:
            stderr = completed.stderr.strip()
            stdout = completed.stdout.strip()
            detail = stderr or stdout or "Unknown CodeQL failure."
            raise CodeQLExecutionError(detail)


def resolve_codeql_bin(explicit_path: str | None = None) -> str | None:
    if explicit_path:
        return explicit_path
    return os.getenv("CODEQL_BIN") or shutil.which("codeql")


def resolve_query_pack_root(query_suite: Path) -> Path:
    query_suite = query_suite.resolve()
    for candidate in (query_suite.parent, *query_suite.parents):
        if (candidate / "qlpack.yml").exists():
            return candidate
    raise CodeQLSetupError(
        f"Unable to locate qlpack.yml for query suite: {query_suite}"
    )


def build_sanitized_codeql_env(base_env: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(base_env or os.environ)
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        raw_value = env.get(name)
        if raw_value is None:
            continue
        sanitized = sanitize_proxy_value(raw_value)
        if sanitized is None:
            env.pop(name, None)
        else:
            env[name] = sanitized
    return env


def sanitize_proxy_value(value: str) -> str | None:
    cleaned = value.strip().strip(SMART_QUOTE_CHARS)
    if not cleaned:
        return None

    parsed = urlparse(cleaned)
    if parsed.scheme and parsed.hostname:
        return cleaned
    return None


def should_run_pack_install(query_pack_root: Path) -> bool:
    return not (query_pack_root / CODEQL_PACK_LOCK).exists()


def should_retry_pack_install(exc: CodeQLExecutionError) -> bool:
    message = str(exc).lower()
    return any(hint in message for hint in MISSING_PACK_HINTS)


def parse_sarif_findings(sarif_path: Path, package_root: Path) -> list[CodeQLFinding]:
    if not sarif_path.exists():
        return []

    payload = json.loads(sarif_path.read_text(encoding="utf-8", errors="ignore"))
    findings: list[CodeQLFinding] = []
    for run in payload.get("runs", []):
        for result in run.get("results", []):
            locations = result.get("locations") or []
            if not locations:
                continue
            first_location = locations[0]
            physical = first_location.get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            uri = unquote(str(artifact.get("uri", "")))
            file_path = _normalize_sarif_path(uri, package_root)
            if file_path is None:
                continue
            region = physical.get("region", {})
            findings.append(
                CodeQLFinding(
                    rule_id=str(result.get("ruleId", "unknown-rule")),
                    message=str(result.get("message", {}).get("text", "")),
                    severity=_extract_severity(result),
                    file_path=file_path,
                    start_line=region.get("startLine"),
                    start_column=region.get("startColumn"),
                    end_line=region.get("endLine"),
                    end_column=region.get("endColumn"),
                )
            )
    return findings


def _normalize_sarif_path(uri: str, package_root: Path) -> str | None:
    if uri.startswith("file:///"):
        candidate = Path(uri.replace("file:///", "", 1))
    else:
        candidate = Path(uri)
    if not candidate.is_absolute():
        candidate = (package_root / candidate).resolve()
    try:
        return candidate.resolve().relative_to(package_root.resolve()).as_posix()
    except ValueError:
        return None


def _extract_severity(result: dict[str, object]) -> str | None:
    properties = result.get("properties")
    if isinstance(properties, dict):
        precision = properties.get("precision")
        if precision is not None:
            return str(precision)
        severity = properties.get("security-severity")
        if severity is not None:
            return str(severity)
    level = result.get("level")
    return str(level) if level is not None else None
