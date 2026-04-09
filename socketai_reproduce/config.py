from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_RUNS_DIR = Path("result") / "runs"
DEFAULT_BATCHES_DIR = Path("result") / "batches"
DEFAULT_SCRATCH_DIR = Path("result") / "_scratch"
DEFAULT_THRESHOLD = 0.5
DEFAULT_TEMPERATURE = 0.0
DEFAULT_LLM_RETRY_LIMIT = 2
DEFAULT_MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024
DEFAULT_MAX_PROMPT_CHARS = 20_000
DEFAULT_TOP_K_SUSPICIOUS_FILES = 5
DEFAULT_PROVIDER = "openai-compatible"
DEFAULT_PATH_LABEL_LENGTH = 24


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
    scratch_output_dir: Path = field(default_factory=lambda: DEFAULT_SCRATCH_DIR)


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def compact_path_label(
    value: str,
    *,
    max_length: int = DEFAULT_PATH_LABEL_LENGTH,
    default: str = "item",
) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]+", "-", value).strip("-").lower()
    if not normalized:
        normalized = default
    compact = normalized[:max_length].strip("-")
    return compact or default


def build_run_id(source: Path) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    digest = hashlib.sha1(str(source.resolve()).encode("utf-8")).hexdigest()[:10]
    label = compact_path_label(source.stem, max_length=24, default="run")
    return f"{stamp}-{label}-{digest}"


def build_batch_id(source: Path) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    digest = hashlib.sha1(str(source.resolve()).encode("utf-8")).hexdigest()[:10]
    label = compact_path_label(source.stem, max_length=8, default="batch")
    return f"batch-{stamp}-{label}-{digest}"


def build_scratch_dir_name(run_id: str) -> str:
    digest = hashlib.sha1(run_id.encode("utf-8")).hexdigest()[:12]
    return f"s-{digest}"
