from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from urllib.parse import unquote

from socketai_reproduce.analysis.models import CodeQLFinding, CodeQLResult


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

        output_dir.mkdir(parents=True, exist_ok=True)
        database_dir = output_dir / "database"
        sarif_path = output_dir / "results.sarif"

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
            str(self.query_suite),
            "--format=sarifv2.1.0",
            f"--output={sarif_path}",
            "--rerun",
            "--threads=0",
        ]

        self._run_command(create_cmd, package_root)
        self._run_command(analyze_cmd, package_root)

        findings = parse_sarif_findings(sarif_path, package_root)
        candidate_files = sorted({finding.file_path for finding in findings})
        return CodeQLResult(
            enabled=True,
            status="success",
            query_suite=str(self.query_suite),
            database_path=str(database_dir),
            results_path=str(sarif_path),
            codeql_bin=codeql_bin,
            candidate_files=candidate_files,
            findings=findings,
            command_lines=[create_cmd, analyze_cmd],
        )

    def _run_command(self, command: list[str], cwd: Path) -> None:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
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
