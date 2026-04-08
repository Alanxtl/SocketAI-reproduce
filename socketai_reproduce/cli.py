from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import typer

from socketai_reproduce.config import (
    DEFAULT_BATCHES_DIR,
    DEFAULT_PROVIDER,
    DEFAULT_RUNS_DIR,
    DEFAULT_TEMPERATURE,
    DEFAULT_THRESHOLD,
    WorkflowConfig,
    build_run_id,
)
from socketai_reproduce.env import load_project_dotenv
from socketai_reproduce.llm.client import LiteLLMClient
from socketai_reproduce.prescreener import (
    CodeQLExecutionError,
    CodeQLPrescreener,
    CodeQLSetupError,
)
from socketai_reproduce.reporting.exporters import export_batch_results, export_run_result
from socketai_reproduce.workflow import SocketAIWorkflow, build_error_run_result

app = typer.Typer(add_completion=False, no_args_is_help=True)


@app.command()
def detect(
    input_path: Path = typer.Option(..., "--input", exists=True, readable=True, resolve_path=True),
    model: str = typer.Option(..., "--model"),
    output_dir: Path = typer.Option(DEFAULT_RUNS_DIR, "--output-dir"),
    provider: str = typer.Option(DEFAULT_PROVIDER, "--provider"),
    temperature: float = typer.Option(DEFAULT_TEMPERATURE, "--temperature"),
    threshold: float = typer.Option(DEFAULT_THRESHOLD, "--threshold"),
    use_codeql: bool = typer.Option(True, "--use-codeql/--no-codeql"),
    codeql_bin: str | None = typer.Option(None, "--codeql-bin"),
) -> None:
    workflow = build_workflow(
        model=model,
        provider=provider,
        temperature=temperature,
        threshold=threshold,
        use_codeql=use_codeql,
        codeql_bin=codeql_bin,
    )
    try:
        result = workflow.detect(input_path, output_dir)
    except (CodeQLExecutionError, CodeQLSetupError, RuntimeError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc

    typer.echo(
        json.dumps(
            {
                "run_id": result.run_meta.run_id,
                "output_dir": result.run_meta.output_dir,
                "package_label": result.package_summary.label,
                "max_file_score": result.package_summary.max_file_score,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


@app.command()
def batch(
    manifest: Path = typer.Option(..., "--manifest", exists=True, readable=True, resolve_path=True),
    model: str = typer.Option(..., "--model"),
    output_dir: Path = typer.Option(DEFAULT_BATCHES_DIR, "--output-dir"),
    provider: str = typer.Option(DEFAULT_PROVIDER, "--provider"),
    temperature: float = typer.Option(DEFAULT_TEMPERATURE, "--temperature"),
    threshold: float = typer.Option(DEFAULT_THRESHOLD, "--threshold"),
    use_codeql: bool = typer.Option(True, "--use-codeql/--no-codeql"),
    codeql_bin: str | None = typer.Option(None, "--codeql-bin"),
) -> None:
    workflow = build_workflow(
        model=model,
        provider=provider,
        temperature=temperature,
        threshold=threshold,
        use_codeql=use_codeql,
        codeql_bin=codeql_bin,
    )
    entries = load_manifest_entries(manifest)
    batch_id = f"batch-{build_run_id(manifest)}"
    batch_dir = output_dir / batch_id
    run_results = []

    for entry in entries:
        sample_input = Path(entry["input"]).resolve()
        run_id = build_run_id(sample_input)
        run_dir = batch_dir / "runs" / run_id
        try:
            result = workflow.detect(sample_input, batch_dir / "runs")
        except CodeQLSetupError as exc:
            result = build_error_run_result(
                run_id=run_id,
                input_path=sample_input,
                run_dir=run_dir,
                model=model,
                provider=provider,
                threshold=threshold,
                use_codeql=use_codeql,
                status="setup_error",
                error_type="codeql_setup_error",
                error_message=str(exc),
            )
            export_run_result(result, run_dir)
        except (CodeQLExecutionError, RuntimeError, ValueError) as exc:
            result = build_error_run_result(
                run_id=run_id,
                input_path=sample_input,
                run_dir=run_dir,
                model=model,
                provider=provider,
                threshold=threshold,
                use_codeql=use_codeql,
                status="error",
                error_type="workflow_error",
                error_message=str(exc),
            )
            export_run_result(result, run_dir)
        run_results.append(result)

    export_batch_results(
        batch_dir,
        batch_id=batch_id,
        manifest_path=manifest,
        run_results=run_results,
    )
    typer.echo(
        json.dumps(
            {
                "batch_id": batch_id,
                "packages": len(run_results),
                "output_dir": str(batch_dir),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


def build_workflow(
    *,
    model: str,
    provider: str,
    temperature: float,
    threshold: float,
    use_codeql: bool,
    codeql_bin: str | None,
) -> SocketAIWorkflow:
    load_project_dotenv()
    config = WorkflowConfig(
        model=model,
        provider=provider,
        temperature=temperature,
        threshold=threshold,
        use_codeql=use_codeql,
        codeql_bin=codeql_bin,
    )
    llm_client = LiteLLMClient(
        model_name=model,
        provider_name=provider,
        temperature=temperature,
    )
    prescreener = (
        CodeQLPrescreener(codeql_bin=codeql_bin, query_suite=config.codeql_query_suite)
        if use_codeql
        else None
    )
    return SocketAIWorkflow(
        config=config,
        llm_client=llm_client,
        codeql_prescreener=prescreener,
    )


def load_manifest_entries(manifest_path: Path) -> list[dict[str, Any]]:
    if manifest_path.suffix.lower() == ".jsonl":
        rows = []
        for line in manifest_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
        return _validate_manifest_rows(rows)
    if manifest_path.suffix.lower() == ".csv":
        with manifest_path.open("r", encoding="utf-8", newline="") as handle:
            return _validate_manifest_rows(list(csv.DictReader(handle)))
    raise ValueError("Manifest must be JSONL or CSV and include an 'input' column.")


def run() -> None:
    app()


def _validate_manifest_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for index, row in enumerate(rows, start=1):
        if "input" not in row or not str(row["input"]).strip():
            raise ValueError(f"Manifest row {index} is missing a non-empty 'input' field.")
    return rows
