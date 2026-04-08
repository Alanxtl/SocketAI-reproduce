from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


def _clamp_score(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _normalize_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        cleaned = value.strip()
        return [cleaned] if cleaned else []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()] if str(value).strip() else []


class UsageStats(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def merge(self, other: "UsageStats") -> "UsageStats":
        return UsageStats(
            prompt_tokens=self.prompt_tokens + other.prompt_tokens,
            completion_tokens=self.completion_tokens + other.completion_tokens,
            total_tokens=self.total_tokens + other.total_tokens,
        )


class InitialFileAssessment(BaseModel):
    label: str
    score: float
    confidence: float
    suspicious_behaviors: list[str] = Field(default_factory=list)
    reasoning_summary: str

    @field_validator("score", "confidence", mode="before")
    @classmethod
    def _normalize_scores(cls, value: float) -> float:
        return _clamp_score(value)

    @field_validator("suspicious_behaviors", mode="before")
    @classmethod
    def _normalize_suspicious_behaviors(cls, value: Any) -> list[str]:
        return _normalize_string_list(value)


class CriticalFileAssessment(BaseModel):
    label: str
    score: float
    confidence: float
    suspicious_behaviors: list[str] = Field(default_factory=list)
    reasoning_summary: str
    changes_made: list[str] = Field(default_factory=list)

    @field_validator("score", "confidence", mode="before")
    @classmethod
    def _normalize_scores(cls, value: float) -> float:
        return _clamp_score(value)

    @field_validator("suspicious_behaviors", "changes_made", mode="before")
    @classmethod
    def _normalize_list_fields(cls, value: Any) -> list[str]:
        return _normalize_string_list(value)


class FinalFileAssessment(BaseModel):
    final_label: str
    final_score: float
    confidence: float
    evidence: list[str] = Field(default_factory=list)
    benign_explanations: list[str] = Field(default_factory=list)
    malicious_explanations: list[str] = Field(default_factory=list)

    @field_validator("final_score", "confidence", mode="before")
    @classmethod
    def _normalize_scores(cls, value: float) -> float:
        return _clamp_score(value)

    @field_validator(
        "evidence",
        "benign_explanations",
        "malicious_explanations",
        mode="before",
    )
    @classmethod
    def _normalize_reason_lists(cls, value: Any) -> list[str]:
        return _normalize_string_list(value)


class StageTrace(BaseModel):
    stage_name: str
    prompt_text: str
    prompt_context: dict[str, Any] = Field(default_factory=dict)
    raw_response_text: list[str] = Field(default_factory=list)
    parsed_response: dict[str, Any] | None = None
    usage: UsageStats = Field(default_factory=UsageStats)
    latency_ms: int = 0
    retry_count: int = 0
    status: str = "success"
    error_message: str | None = None


class CodeQLFinding(BaseModel):
    rule_id: str
    message: str
    severity: str | None = None
    file_path: str
    start_line: int | None = None
    start_column: int | None = None
    end_line: int | None = None
    end_column: int | None = None


class CodeQLResult(BaseModel):
    enabled: bool = False
    status: str = "disabled"
    query_suite: str | None = None
    database_path: str | None = None
    results_path: str | None = None
    codeql_bin: str | None = None
    candidate_files: list[str] = Field(default_factory=list)
    findings: list[CodeQLFinding] = Field(default_factory=list)
    command_lines: list[list[str]] = Field(default_factory=list)
    error_message: str | None = None


class FileAnalysisResult(BaseModel):
    file_id: str
    relative_path: str
    from_codeql: bool = False
    codeql_rules: list[str] = Field(default_factory=list)
    stage1: StageTrace
    stage2: StageTrace
    stage3: StageTrace
    final_label: str
    final_score: float
    confidence: float
    evidence: list[str] = Field(default_factory=list)
    benign_explanations: list[str] = Field(default_factory=list)
    malicious_explanations: list[str] = Field(default_factory=list)
    status: str = "success"
    error_message: str | None = None

    @field_validator("final_score", "confidence", mode="before")
    @classmethod
    def _normalize_scores(cls, value: float) -> float:
        return _clamp_score(value)


class PackageSummary(BaseModel):
    package_name: str
    package_version: str | None = None
    input_path: str
    package_root: str
    run_id: str
    label: str
    threshold: float
    max_file_score: float
    flagged_file_count: int
    top_k_suspicious_files: list[dict[str, Any]] = Field(default_factory=list)
    decision_reason: str
    total_files: int
    analyzed_files: int
    status: str = "success"
    error_type: str | None = None

    @field_validator("threshold", "max_file_score", mode="before")
    @classmethod
    def _normalize_scores(cls, value: float) -> float:
        return _clamp_score(value)


class RunMetadata(BaseModel):
    run_id: str
    timestamp_utc: str
    input_path: str
    output_dir: str
    model: str
    provider: str
    temperature: float
    threshold: float
    use_codeql: bool
    codeql_bin: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    package_root: str | None = None


class RunMetrics(BaseModel):
    input_files: int = 0
    analyzed_files: int = 0
    llm_calls: int = 0
    codeql_candidate_files: int = 0
    errors: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: int = 0


class RunResult(BaseModel):
    run_meta: RunMetadata
    package_summary: PackageSummary
    files: list[FileAnalysisResult] = Field(default_factory=list)
    codeql: CodeQLResult = Field(default_factory=CodeQLResult)
    metrics: RunMetrics = Field(default_factory=RunMetrics)
