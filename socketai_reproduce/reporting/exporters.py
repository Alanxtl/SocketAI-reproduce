from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from socketai_reproduce.analysis.models import FileAnalysisResult, RunResult

PACKAGE_LEVEL_FIELDNAMES = [
    "run_id",
    "input_path",
    "package_name",
    "package_version",
    "label",
    "status",
    "error_type",
    "threshold",
    "max_file_score",
    "flagged_file_count",
    "top_k_suspicious_files",
    "decision_reason",
    "total_files",
    "analyzed_files",
    "model",
    "provider",
    "use_codeql",
]

FILE_LEVEL_FIELDNAMES = [
    "run_id",
    "package_name",
    "relative_path",
    "from_codeql",
    "codeql_rules",
    "final_label",
    "final_score",
    "confidence",
    "status",
    "error_message",
    "stage1_status",
    "stage2_status",
    "stage3_status",
]


def export_run_result(run_result: RunResult, run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    write_json(run_dir / "run_meta.json", run_result.run_meta.model_dump(mode="json"))
    write_json(
        run_dir / "package_summary.json",
        run_result.package_summary.model_dump(mode="json"),
    )
    write_json(run_dir / "metrics.json", run_result.metrics.model_dump(mode="json"))
    write_json(run_dir / "codeql" / "results.json", run_result.codeql.model_dump(mode="json"))

    rows = []
    for file_result in run_result.files:
        rows.append(_file_level_row(run_result, file_result))
        write_stage_traces(run_dir, file_result)

    write_jsonl(run_dir / "files.jsonl", rows)
    write_csv(run_dir / "exports" / "file_level.csv", rows)
    write_csv(
        run_dir / "exports" / "package_level.csv",
        [_package_level_row(run_result)],
    )


def export_batch_results(
    batch_dir: Path,
    *,
    batch_id: str,
    manifest_path: Path,
    run_results: list[RunResult],
    total_packages: int | None = None,
) -> None:
    batch_dir.mkdir(parents=True, exist_ok=True)
    package_rows = [_package_level_row(result) for result in run_results]
    file_rows = [
        _file_level_row(result, file_result)
        for result in run_results
        for file_result in result.files
    ]
    write_json(
        batch_dir / "batch_meta.json",
        {
            "batch_id": batch_id,
            "manifest_path": str(manifest_path),
            "status": "completed",
            "packages_total": total_packages if total_packages is not None else len(package_rows),
            "packages_completed": len(package_rows),
            "files_exported": len(file_rows),
        },
    )
    write_csv(batch_dir / "exports" / "package_level.csv", package_rows)
    write_csv(batch_dir / "exports" / "file_level.csv", file_rows)


def initialize_batch_results(
    batch_dir: Path,
    *,
    batch_id: str,
    manifest_path: Path,
    total_packages: int,
) -> None:
    batch_dir.mkdir(parents=True, exist_ok=True)
    ensure_csv_header(batch_dir / "exports" / "package_level.csv", PACKAGE_LEVEL_FIELDNAMES)
    ensure_csv_header(batch_dir / "exports" / "file_level.csv", FILE_LEVEL_FIELDNAMES)
    write_json(
        batch_dir / "batch_meta.json",
        {
            "batch_id": batch_id,
            "manifest_path": str(manifest_path),
            "status": "running",
            "packages_total": total_packages,
            "packages_completed": 0,
            "files_exported": 0,
        },
    )


def checkpoint_batch_result(
    batch_dir: Path,
    *,
    batch_id: str,
    manifest_path: Path,
    run_result: RunResult,
    total_packages: int,
    completed_packages: int,
    exported_files: int,
) -> None:
    package_row = _package_level_row(run_result)
    file_rows = [_file_level_row(run_result, file_result) for file_result in run_result.files]
    append_csv_rows(
        batch_dir / "exports" / "package_level.csv",
        [package_row],
        PACKAGE_LEVEL_FIELDNAMES,
    )
    append_csv_rows(
        batch_dir / "exports" / "file_level.csv",
        file_rows,
        FILE_LEVEL_FIELDNAMES,
    )
    write_json(
        batch_dir / "batch_meta.json",
        {
            "batch_id": batch_id,
            "manifest_path": str(manifest_path),
            "status": "running",
            "packages_total": total_packages,
            "packages_completed": completed_packages,
            "files_exported": exported_files,
            "last_completed_run_id": run_result.run_meta.run_id,
        },
    )


def write_stage_traces(run_dir: Path, file_result: FileAnalysisResult) -> None:
    stage_dir = run_dir / "stages" / file_result.file_id
    write_json(stage_dir / "stage1.json", file_result.stage1.model_dump(mode="json"))
    write_json(stage_dir / "stage2.json", file_result.stage2.model_dump(mode="json"))
    write_json(stage_dir / "stage3.json", file_result.stage3.model_dump(mode="json"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def ensure_csv_header(path: Path, fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > 0:
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()


def append_csv_rows(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    if not rows:
        ensure_csv_header(path, fieldnames)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    needs_header = not path.exists() or path.stat().st_size == 0
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if needs_header:
            writer.writeheader()
        writer.writerows(rows)


def _package_level_row(run_result: RunResult) -> dict[str, Any]:
    summary = run_result.package_summary
    return {
        "run_id": run_result.run_meta.run_id,
        "input_path": summary.input_path,
        "package_name": summary.package_name,
        "package_version": summary.package_version,
        "label": summary.label,
        "status": summary.status,
        "error_type": summary.error_type,
        "threshold": summary.threshold,
        "max_file_score": summary.max_file_score,
        "flagged_file_count": summary.flagged_file_count,
        "top_k_suspicious_files": json.dumps(summary.top_k_suspicious_files, ensure_ascii=False),
        "decision_reason": summary.decision_reason,
        "total_files": summary.total_files,
        "analyzed_files": summary.analyzed_files,
        "model": run_result.run_meta.model,
        "provider": run_result.run_meta.provider,
        "use_codeql": run_result.run_meta.use_codeql,
    }


def _file_level_row(run_result: RunResult, file_result: FileAnalysisResult) -> dict[str, Any]:
    return {
        "run_id": run_result.run_meta.run_id,
        "package_name": run_result.package_summary.package_name,
        "relative_path": file_result.relative_path,
        "from_codeql": file_result.from_codeql,
        "codeql_rules": ";".join(file_result.codeql_rules),
        "final_label": file_result.final_label,
        "final_score": file_result.final_score,
        "confidence": file_result.confidence,
        "status": file_result.status,
        "error_message": file_result.error_message,
        "stage1_status": file_result.stage1.status,
        "stage2_status": file_result.stage2.status,
        "stage3_status": file_result.stage3.status,
    }
