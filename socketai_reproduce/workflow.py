from __future__ import annotations

import re
import time
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

from socketai_reproduce.analysis.models import (
    CodeQLFinding,
    CodeQLResult,
    CriticalFileAssessment,
    FileAnalysisResult,
    FinalFileAssessment,
    InitialFileAssessment,
    PackageSummary,
    RunMetadata,
    RunMetrics,
    RunResult,
    StageTrace,
    UsageStats,
)
from socketai_reproduce.config import WorkflowConfig, build_run_id, utc_now_iso
from socketai_reproduce.llm.client import LLMClient
from socketai_reproduce.llm.prompts import (
    PromptBundle,
    build_stage1_prompt,
    build_stage2_prompt,
    build_stage3_prompt,
)
from socketai_reproduce.package_loader import LoadedPackage, load_package
from socketai_reproduce.prescreener import CodeQLPrescreener
from socketai_reproduce.reporting.exporters import export_run_result

ModelT = TypeVar("ModelT", bound=BaseModel)


class SocketAIWorkflow:
    def __init__(
        self,
        *,
        config: WorkflowConfig,
        llm_client: LLMClient,
        codeql_prescreener: CodeQLPrescreener | None = None,
    ) -> None:
        self.config = config
        self.llm_client = llm_client
        self.codeql_prescreener = codeql_prescreener

    def detect(self, input_path: Path, output_root: Path) -> RunResult:
        run_id = build_run_id(input_path)
        run_dir = output_root / run_id
        scratch_dir = run_dir / "_tmp"

        started_at = time.perf_counter()
        loaded_package = load_package(input_path, scratch_dir)
        codeql_result = self._run_codeql(loaded_package, run_dir)
        selected_files, codeql_map = self._select_files(loaded_package, codeql_result)
        findings_by_file = group_findings_by_file(codeql_result)

        file_results: list[FileAnalysisResult] = []
        metrics = RunMetrics(
            input_files=len(loaded_package.base_candidate_files),
            codeql_candidate_files=len(codeql_result.candidate_files),
        )

        for file_path in selected_files:
            file_result, file_metrics = self._analyze_file(
                loaded_package=loaded_package,
                file_path=file_path,
                codeql_findings=findings_by_file.get(loaded_package.relative_path(file_path), []),
                from_codeql=codeql_map.get(file_path.resolve(), False),
            )
            file_results.append(file_result)
            metrics.llm_calls += file_metrics["llm_calls"]
            metrics.prompt_tokens += file_metrics["prompt_tokens"]
            metrics.completion_tokens += file_metrics["completion_tokens"]
            metrics.total_tokens += file_metrics["total_tokens"]
            metrics.errors += file_metrics["errors"]

        metrics.analyzed_files = len(file_results)
        metrics.latency_ms = int((time.perf_counter() - started_at) * 1000)

        package_summary = self._summarize_package(
            loaded_package=loaded_package,
            input_path=input_path,
            run_id=run_id,
            file_results=file_results,
        )
        run_result = RunResult(
            run_meta=RunMetadata(
                run_id=run_id,
                timestamp_utc=utc_now_iso(),
                input_path=str(input_path.resolve()),
                output_dir=str(run_dir),
                model=self.llm_client.model_name,
                provider=self.llm_client.provider_name,
                temperature=self.config.temperature,
                threshold=self.config.threshold,
                use_codeql=self.config.use_codeql,
                codeql_bin=codeql_result.codeql_bin,
                package_name=loaded_package.package_name,
                package_version=loaded_package.package_version,
                package_root=str(loaded_package.package_root),
            ),
            package_summary=package_summary,
            files=file_results,
            codeql=codeql_result,
            metrics=metrics,
        )
        export_run_result(run_result, run_dir)
        return run_result

    def _run_codeql(self, loaded_package: LoadedPackage, run_dir: Path) -> CodeQLResult:
        if not self.config.use_codeql:
            return CodeQLResult(enabled=False, status="disabled")
        if self.codeql_prescreener is None:
            raise RuntimeError("CodeQL was enabled, but no CodeQL prescreener was configured.")
        return self.codeql_prescreener.screen(loaded_package.package_root, run_dir / "codeql")

    def _select_files(
        self,
        loaded_package: LoadedPackage,
        codeql_result: CodeQLResult,
    ) -> tuple[list[Path], dict[Path, bool]]:
        if not self.config.use_codeql:
            return loaded_package.base_candidate_files, {
                path.resolve(): False for path in loaded_package.base_candidate_files
            }

        selected: dict[Path, bool] = {}
        for relative_path in codeql_result.candidate_files:
            candidate = (loaded_package.package_root / relative_path).resolve()
            if candidate.exists():
                selected[candidate] = True
        if loaded_package.package_json_path is not None:
            package_json_path = loaded_package.package_json_path.resolve()
            selected[package_json_path] = selected.get(package_json_path, False)
        for install_file in loaded_package.install_script_files:
            resolved = install_file.resolve()
            selected[resolved] = selected.get(resolved, False)

        ordered_paths = sorted(selected, key=lambda path: loaded_package.relative_path(path))
        return ordered_paths, selected

    def _analyze_file(
        self,
        *,
        loaded_package: LoadedPackage,
        file_path: Path,
        codeql_findings: list[CodeQLFinding],
        from_codeql: bool,
    ) -> tuple[FileAnalysisResult, dict[str, int]]:
        raw_text = file_path.read_text(encoding="utf-8", errors="ignore")
        prompt_text, truncated = truncate_for_prompt(raw_text, self.config.max_prompt_chars)

        stage1_bundle = build_stage1_prompt(
            loaded_package=loaded_package,
            file_path=file_path,
            file_text=prompt_text,
            truncated=truncated,
            codeql_findings=codeql_findings,
        )
        stage1_trace, stage1_output, stage1_calls = self._run_stage(
            bundle=stage1_bundle,
            response_model=InitialFileAssessment,
        )

        stage2_bundle = build_stage2_prompt(
            loaded_package=loaded_package,
            file_path=file_path,
            file_text=prompt_text,
            truncated=truncated,
            stage1_output=stage1_output.model_dump(mode="json") if stage1_output else None,
            codeql_findings=codeql_findings,
        )
        stage2_trace, stage2_output, stage2_calls = self._run_stage(
            bundle=stage2_bundle,
            response_model=CriticalFileAssessment,
        )

        stage3_bundle = build_stage3_prompt(
            loaded_package=loaded_package,
            file_path=file_path,
            stage1_output=stage1_output.model_dump(mode="json") if stage1_output else None,
            stage2_output=stage2_output.model_dump(mode="json") if stage2_output else None,
            codeql_findings=codeql_findings,
        )
        stage3_trace, stage3_output, stage3_calls = self._run_stage(
            bundle=stage3_bundle,
            response_model=FinalFileAssessment,
        )

        final_output = stage3_output or fallback_final_output(stage1_output, stage2_output)
        status = "success" if stage3_output is not None else "degraded"
        error_message = stage3_trace.error_message if stage3_output is None else None
        result = FileAnalysisResult(
            file_id=loaded_package.build_file_id(file_path),
            relative_path=loaded_package.relative_path(file_path),
            from_codeql=from_codeql,
            codeql_rules=sorted({finding.rule_id for finding in codeql_findings}),
            stage1=stage1_trace,
            stage2=stage2_trace,
            stage3=stage3_trace,
            final_label=final_output.final_label,
            final_score=final_output.final_score,
            confidence=final_output.confidence,
            evidence=final_output.evidence,
            benign_explanations=final_output.benign_explanations,
            malicious_explanations=final_output.malicious_explanations,
            status=status,
            error_message=error_message,
        )
        file_metrics = {
            "llm_calls": stage1_calls + stage2_calls + stage3_calls,
            "prompt_tokens": result.stage1.usage.prompt_tokens
            + result.stage2.usage.prompt_tokens
            + result.stage3.usage.prompt_tokens,
            "completion_tokens": result.stage1.usage.completion_tokens
            + result.stage2.usage.completion_tokens
            + result.stage3.usage.completion_tokens,
            "total_tokens": result.stage1.usage.total_tokens
            + result.stage2.usage.total_tokens
            + result.stage3.usage.total_tokens,
            "errors": 0 if result.status == "success" else 1,
        }
        return result, file_metrics

    def _run_stage(
        self,
        *,
        bundle: PromptBundle,
        response_model: type[ModelT],
    ) -> tuple[StageTrace, ModelT | None, int]:
        raw_responses: list[str] = []
        total_latency_ms = 0
        usage = UsageStats()
        last_error: str | None = None
        attempts = self.config.llm_retry_limit + 1

        for attempt_index in range(attempts):
            try:
                response = self.llm_client.generate(
                    bundle.messages,
                    temperature=self.config.temperature,
                    n=1,
                )
                raw_responses.extend(response["texts"])
                usage = usage.merge(response["usage"])
                total_latency_ms += response["latency_ms"]
                if not response["texts"]:
                    raise ValueError("Model returned no text.")
                parsed = parse_json_model(response["texts"][0], response_model)
                return (
                    StageTrace(
                        stage_name=bundle.stage_name,
                        prompt_text=bundle.prompt_text,
                        prompt_context=bundle.prompt_context,
                        raw_response_text=raw_responses,
                        parsed_response=parsed.model_dump(mode="json"),
                        usage=usage,
                        latency_ms=total_latency_ms,
                        retry_count=attempt_index,
                        status="success",
                    ),
                    parsed,
                    attempt_index + 1,
                )
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)

        status = "parse_error" if raw_responses else "error"
        return (
            StageTrace(
                stage_name=bundle.stage_name,
                prompt_text=bundle.prompt_text,
                prompt_context=bundle.prompt_context,
                raw_response_text=raw_responses,
                parsed_response=None,
                usage=usage,
                latency_ms=total_latency_ms,
                retry_count=attempts - 1,
                status=status,
                error_message=last_error,
            ),
            None,
            attempts,
        )

    def _summarize_package(
        self,
        *,
        loaded_package: LoadedPackage,
        input_path: Path,
        run_id: str,
        file_results: list[FileAnalysisResult],
    ) -> PackageSummary:
        if not file_results:
            return PackageSummary(
                package_name=loaded_package.package_name,
                package_version=loaded_package.package_version,
                input_path=str(input_path.resolve()),
                package_root=str(loaded_package.package_root),
                run_id=run_id,
                label="benign",
                threshold=self.config.threshold,
                max_file_score=0.0,
                flagged_file_count=0,
                top_k_suspicious_files=[],
                decision_reason="No candidate files were selected for LLM analysis.",
                total_files=len(loaded_package.base_candidate_files),
                analyzed_files=0,
            )

        sorted_files = sorted(file_results, key=lambda item: item.final_score, reverse=True)
        flagged = [result for result in file_results if result.final_score >= self.config.threshold]
        package_label = "malicious" if flagged else "benign"
        top_k = [
            {
                "relative_path": result.relative_path,
                "score": result.final_score,
                "label": result.final_label,
            }
            for result in sorted_files[: self.config.top_k_suspicious_files]
        ]
        status = (
            "partial_success"
            if any(item.status != "success" for item in file_results)
            else "success"
        )
        if flagged:
            decision_reason = (
                f"{len(flagged)} file(s) reached or exceeded the malicious threshold "
                f"of {self.config.threshold:.2f}."
            )
        else:
            decision_reason = (
                f"No analyzed file reached the malicious threshold of {self.config.threshold:.2f}."
            )

        return PackageSummary(
            package_name=loaded_package.package_name,
            package_version=loaded_package.package_version,
            input_path=str(input_path.resolve()),
            package_root=str(loaded_package.package_root),
            run_id=run_id,
            label=package_label,
            threshold=self.config.threshold,
            max_file_score=sorted_files[0].final_score,
            flagged_file_count=len(flagged),
            top_k_suspicious_files=top_k,
            decision_reason=decision_reason,
            total_files=len(loaded_package.base_candidate_files),
            analyzed_files=len(file_results),
            status=status,
        )


def build_error_run_result(
    *,
    run_id: str,
    input_path: Path,
    run_dir: Path,
    model: str,
    provider: str,
    threshold: float,
    use_codeql: bool,
    status: str,
    error_type: str,
    error_message: str,
) -> RunResult:
    return RunResult(
        run_meta=RunMetadata(
            run_id=run_id,
            timestamp_utc=utc_now_iso(),
            input_path=str(input_path.resolve()),
            output_dir=str(run_dir),
            model=model,
            provider=provider,
            temperature=0.0,
            threshold=threshold,
            use_codeql=use_codeql,
        ),
        package_summary=PackageSummary(
            package_name=input_path.stem,
            package_version=None,
            input_path=str(input_path.resolve()),
            package_root=str(input_path.resolve()),
            run_id=run_id,
            label="unknown",
            threshold=threshold,
            max_file_score=0.0,
            flagged_file_count=0,
            top_k_suspicious_files=[],
            decision_reason=error_message,
            total_files=0,
            analyzed_files=0,
            status=status,
            error_type=error_type,
        ),
        files=[],
        codeql=CodeQLResult(
            enabled=use_codeql,
            status=status,
            error_message=error_message,
        ),
        metrics=RunMetrics(errors=1),
    )


def group_findings_by_file(codeql_result: CodeQLResult) -> dict[str, list[CodeQLFinding]]:
    grouped: dict[str, list[CodeQLFinding]] = {}
    for finding in codeql_result.findings:
        grouped.setdefault(finding.file_path, []).append(finding)
    return grouped


def truncate_for_prompt(text: str, max_chars: int) -> tuple[str, bool]:
    if len(text) <= max_chars:
        return text, False
    half = max_chars // 2
    truncated = text[:half] + "\n\n...[TRUNCATED FOR PROMPT BUDGET]...\n\n" + text[-half:]
    return truncated, True


def parse_json_model(text: str, response_model: type[ModelT]) -> ModelT:
    normalized = text.strip()
    for candidate in iter_json_candidates(normalized):
        try:
            return response_model.model_validate_json(candidate)
        except Exception:  # noqa: BLE001
            continue
    raise ValueError("Unable to parse model response as JSON.")


def iter_json_candidates(text: str) -> list[str]:
    candidates = [text]
    candidates.extend(
        match.group(1).strip()
        for match in re.finditer(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    )
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        candidates.append(text[first_brace : last_brace + 1])
    deduped: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in deduped:
            deduped.append(candidate)
    return deduped


def fallback_final_output(
    stage1_output: InitialFileAssessment | None,
    stage2_output: CriticalFileAssessment | None,
) -> FinalFileAssessment:
    if stage2_output is not None:
        return FinalFileAssessment(
            final_label=stage2_output.label,
            final_score=stage2_output.score,
            confidence=stage2_output.confidence,
            evidence=stage2_output.suspicious_behaviors,
            benign_explanations=[],
            malicious_explanations=[stage2_output.reasoning_summary],
        )
    if stage1_output is not None:
        return FinalFileAssessment(
            final_label=stage1_output.label,
            final_score=stage1_output.score,
            confidence=stage1_output.confidence,
            evidence=stage1_output.suspicious_behaviors,
            benign_explanations=[],
            malicious_explanations=[stage1_output.reasoning_summary],
        )
    return FinalFileAssessment(
        final_label="unknown",
        final_score=0.0,
        confidence=0.0,
        evidence=[],
        benign_explanations=[],
        malicious_explanations=[],
    )
