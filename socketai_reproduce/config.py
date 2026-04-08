from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_RUNS_DIR = Path("result") / "runs"
DEFAULT_BATCHES_DIR = Path("result") / "batches"
DEFAULT_THRESHOLD = 0.5
DEFAULT_TEMPERATURE = 0.0
DEFAULT_LLM_RETRY_LIMIT = 2
DEFAULT_MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024
DEFAULT_MAX_PROMPT_CHARS = 20_000
DEFAULT_TOP_K_SUSPICIOUS_FILES = 5
DEFAULT_PROVIDER = "openai-compatible"


@dataclass(slots=True)
class WorkflowConfig:
    model: str
    provider: str = DEFAULT_PROVIDER
    temperature: float = DEFAULT_TEMPERATURE
    threshold: float = DEFAULT_THRESHOLD
    use_codeql: bool = True
    llm_retry_limit: int = DEFAULT_LLM_RETRY_LIMIT
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES
    max_prompt_chars: int = DEFAULT_MAX_PROMPT_CHARS
    keep_raw_responses: bool = True
    codeql_bin: str | None = None
    codeql_query_suite: Path | None = None
    top_k_suspicious_files: int = DEFAULT_TOP_K_SUSPICIOUS_FILES
    runs_output_dir: Path = field(default_factory=lambda: DEFAULT_RUNS_DIR)
    batches_output_dir: Path = field(default_factory=lambda: DEFAULT_BATCHES_DIR)


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_run_id(source: Path) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    digest = hashlib.sha1(str(source.resolve()).encode("utf-8")).hexdigest()[:10]
    return f"{stamp}-{source.stem}-{digest}"
