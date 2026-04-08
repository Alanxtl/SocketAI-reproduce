from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from socketai_reproduce.analysis.models import CodeQLFinding
from socketai_reproduce.package_loader import LoadedPackage


@dataclass(slots=True)
class PromptBundle:
    stage_name: str
    messages: list[dict[str, str]]
    prompt_text: str
    prompt_context: dict[str, Any]


def build_stage1_prompt(
    *,
    loaded_package: LoadedPackage,
    file_path: Path,
    file_text: str,
    truncated: bool,
    codeql_findings: list[CodeQLFinding],
) -> PromptBundle:
    package_context = build_package_context(loaded_package)
    file_context = build_file_context(
        loaded_package=loaded_package,
        file_path=file_path,
        truncated=truncated,
        codeql_findings=codeql_findings,
    )

    system_prompt = (
        "You are a security reviewer for npm packages. "
        "Assess whether this single file contains malicious package behavior. "
        "Return JSON only."
    )
    user_prompt = (
        "Review the file and produce an initial maliciousness assessment.\n"
        "Use score in [0,1]. A score >= 0.5 indicates malicious suspicion.\n"
        "Be evidence-driven and avoid speculation.\n"
        'Return a JSON object with exactly these keys: "label", "score", '
        '"confidence", "suspicious_behaviors", "reasoning_summary".\n\n'
        f"Package context:\n{json.dumps(package_context, indent=2, ensure_ascii=True)}\n\n"
        f"File context:\n{json.dumps(file_context, indent=2, ensure_ascii=True)}\n\n"
        f"File content:\n```text\n{file_text}\n```"
    )
    return _bundle("stage1", system_prompt, user_prompt, package_context, file_context)


def build_stage2_prompt(
    *,
    loaded_package: LoadedPackage,
    file_path: Path,
    file_text: str,
    truncated: bool,
    stage1_output: dict[str, Any] | None,
    codeql_findings: list[CodeQLFinding],
) -> PromptBundle:
    package_context = build_package_context(loaded_package)
    file_context = build_file_context(
        loaded_package=loaded_package,
        file_path=file_path,
        truncated=truncated,
        codeql_findings=codeql_findings,
    )
    system_prompt = (
        "You are critically reviewing a prior npm malware assessment. "
        "Correct false positives and false negatives. Return JSON only."
    )
    user_prompt = (
        "Review the prior analysis, challenge unsupported claims, and update the assessment.\n"
        'Return a JSON object with exactly these keys: "label", "score", '
        '"confidence", "suspicious_behaviors", "reasoning_summary", "changes_made".\n\n'
        f"Prior stage output:\n{json.dumps(stage1_output or {}, indent=2, ensure_ascii=True)}\n\n"
        f"Package context:\n{json.dumps(package_context, indent=2, ensure_ascii=True)}\n\n"
        f"File context:\n{json.dumps(file_context, indent=2, ensure_ascii=True)}\n\n"
        f"File content:\n```text\n{file_text}\n```"
    )
    return _bundle("stage2", system_prompt, user_prompt, package_context, file_context)


def build_stage3_prompt(
    *,
    loaded_package: LoadedPackage,
    file_path: Path,
    stage1_output: dict[str, Any] | None,
    stage2_output: dict[str, Any] | None,
    codeql_findings: list[CodeQLFinding],
) -> PromptBundle:
    package_context = build_package_context(loaded_package)
    file_context = build_file_context(
        loaded_package=loaded_package,
        file_path=file_path,
        truncated=False,
        codeql_findings=codeql_findings,
    )
    system_prompt = (
        "You are producing the final file-level verdict for npm malware review. "
        "Return JSON only."
    )
    user_prompt = (
        "Synthesize the two previous analyses into a final evidence-based verdict.\n"
        'Return a JSON object with exactly these keys: "final_label", "final_score", '
        '"confidence", "evidence", "benign_explanations", "malicious_explanations".\n\n'
        f"Stage 1 output:\n{json.dumps(stage1_output or {}, indent=2, ensure_ascii=True)}\n\n"
        f"Stage 2 output:\n{json.dumps(stage2_output or {}, indent=2, ensure_ascii=True)}\n\n"
        f"Package context:\n{json.dumps(package_context, indent=2, ensure_ascii=True)}\n\n"
        f"File context:\n{json.dumps(file_context, indent=2, ensure_ascii=True)}"
    )
    return _bundle("stage3", system_prompt, user_prompt, package_context, file_context)


def build_package_context(loaded_package: LoadedPackage) -> dict[str, Any]:
    package_json = loaded_package.package_json
    deps = package_json.get("dependencies") if isinstance(package_json.get("dependencies"), dict) else {}
    dev_deps = (
        package_json.get("devDependencies")
        if isinstance(package_json.get("devDependencies"), dict)
        else {}
    )
    scripts = package_json.get("scripts") if isinstance(package_json.get("scripts"), dict) else {}
    return {
        "name": loaded_package.package_name,
        "version": loaded_package.package_version,
        "description": package_json.get("description"),
        "main": package_json.get("main"),
        "bin": package_json.get("bin"),
        "scripts": scripts,
        "dependencies": dict(list(deps.items())[:20]),
        "dev_dependencies": dict(list(dev_deps.items())[:10]),
        "archive_input": loaded_package.is_archive,
    }


def build_file_context(
    *,
    loaded_package: LoadedPackage,
    file_path: Path,
    truncated: bool,
    codeql_findings: list[CodeQLFinding],
) -> dict[str, Any]:
    return {
        "relative_path": loaded_package.relative_path(file_path),
        "is_package_json": loaded_package.package_json_path == file_path,
        "is_lifecycle_script": file_path in loaded_package.install_script_files,
        "truncated": truncated,
        "codeql_findings": [
            {
                "rule_id": finding.rule_id,
                "message": finding.message,
                "severity": finding.severity,
                "line": finding.start_line,
                "column": finding.start_column,
            }
            for finding in codeql_findings
        ],
    }


def _bundle(
    stage_name: str,
    system_prompt: str,
    user_prompt: str,
    package_context: dict[str, Any],
    file_context: dict[str, Any],
) -> PromptBundle:
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    prompt_text = f"[system]\n{system_prompt}\n\n[user]\n{user_prompt}"
    return PromptBundle(
        stage_name=stage_name,
        messages=messages,
        prompt_text=prompt_text,
        prompt_context={
            "package_context": package_context,
            "file_context": file_context,
        },
    )
