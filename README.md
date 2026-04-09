# SocketAI-reproduce

`socketai-reproduce` is an engineering-oriented reproduction of the ICSE 2025 paper *Leveraging Large Language Models to Detect NPM Malicious Packages*. The current version implements a runnable npm package detection workflow:

- Accept a local npm package directory or a `.tgz/.tar/.zip` archive as input
- Optionally use real `CodeQL` for static prescreening
- Run three-stage LLM analysis on candidate files
- Output a package-level maliciousness verdict
- Preserve the prompt, raw response, parsed result, token usage, and latency for every step to support debugging and research statistics

## Project Structure

```text
socketai_reproduce/
  cli.py                  # detect / batch CLI
  workflow.py             # End-to-end orchestration
  package_loader.py       # Directory/archive input handling
  analysis/models.py      # Structured data models
  llm/
    client.py             # LiteLLM adapter
    prompts.py            # Three-stage prompts
  prescreener/
    codeql.py             # CodeQL prescreening and SARIF parsing
  reporting/exporters.py  # JSON/JSONL/CSV exports
  codeql_queries/         # Built-in CodeQL query pack
utils/
  find_archives.py        # Archive extraction and risky file enumeration helpers
tests/
  ...                     # Minimal unit tests and smoke tests
```

## Environment Setup

The repository uses the local `.venv` by default.

```powershell
uv sync
```

If you want to use real CodeQL prescreening, install the CodeQL CLI and satisfy either of the following:

- `codeql` is available in the system `PATH`
- Set the `CODEQL_BIN` environment variable

When you run detection with `--use-codeql` for the first time, the program will automatically install the query pack dependencies if `codeql-pack.lock.yml` is missing. Once the lock file has been generated, later runs will skip that step.

LLM configuration is read from the repository root `.env` by default, and then falls back to the current process environment variables. It is recommended to create a `.env` file in the repository root:

```powershell
OPENAI_API_KEY=your-key
OPENAI_BASE_URL=https://your-compatible-endpoint/v1
```

If you prefer setting environment variables temporarily, that still works. The `.env` file will not override existing system environment variables.

## CLI Usage

After installing dependencies, you can use:

```powershell
uv run .\main.py --help
```

### 1. Single-Package Detection

Without CodeQL:

```powershell
uv run .\main.py detect `
  --input .\samples\some-package `
  --model gpt-4o-mini `
  --no-codeql
```

With CodeQL:

```powershell
uv run .\main.py detect `
  --input .\samples\some-package.tgz `
  --model gpt-4o-mini `
  --use-codeql
```

Common arguments:

- `--input`: Local directory or npm archive
- `--model`: Model name used by LiteLLM
- `--output-dir`: Root directory for detection results, default `result/runs`
- `--threshold`: Package-level aggregation threshold, default `0.5`
- `--temperature`: LLM temperature, default `0`
- `--use-codeql / --no-codeql`: Whether to enable CodeQL prescreening
- `--codeql-bin`: Explicitly specify the CodeQL executable

### 2. Batch Detection

Supports a `jsonl` or `csv` manifest with at least an `input` field.

Example `manifest.jsonl`:

```json
{"input": "D:/datasets/pkg_a"}
{"input": "D:/datasets/pkg_b.tgz"}
```

Run:

```powershell
uv run .\main.py batch `
  --manifest .\manifest.jsonl `
  --model gpt-4o-mini `
  --output-dir .\result\batches `
  --no-codeql
```

If `batch` encounters a CodeQL environment error for a single sample, it does not stop the whole batch. Instead, that sample is marked as `setup_error` and execution continues.

Batch-level checkpoint files are updated after each completed sample. If the process is interrupted midway, the already-finished per-run outputs remain available under `runs/`, and the batch-level `batch_meta.json`, `exports/package_level.csv`, and `exports/file_level.csv` preserve progress up to the last completed sample.

## Output Directory

A single `detect` run outputs to `result/runs/<run_id>/` by default:

```text
run_meta.json
package_summary.json
files.jsonl
metrics.json
codeql/results.json
exports/file_level.csv
exports/package_level.csv
stages/<file_id>/stage1.json
stages/<file_id>/stage2.json
stages/<file_id>/stage3.json
```

Each stage JSON preserves:

- `prompt_text`
- `prompt_context`
- `raw_response_text`
- `parsed_response`
- `usage`
- `latency_ms`
- `retry_count`
- `status`

`batch` additionally exports aggregated `exports/package_level.csv` and `exports/file_level.csv` under the batch directory for downstream plotting.

To reduce Windows path-length failures, archive extraction workspaces and temporary CodeQL databases are created under `result/_scratch/<short_id>/` instead of nested under each batch run directory. The exported debug artifacts remain under the corresponding `result/runs/<run_id>/` or batch output directory.

## Workflow Overview

1. Input preparation: parse the package root, read `package.json`, and identify risky script files and install lifecycle scripts.
2. CodeQL prescreening: if enabled, run the built-in query suite to obtain candidate files and matched rules.
3. Three-stage LLM analysis:
   - Stage 1: Initial maliciousness assessment
   - Stage 2: Self-review and correction
   - Stage 3: Final file-level verdict
4. Package-level aggregation: if any file has `final_score >= threshold`, the package is classified as `malicious`.

## Validation

A minimal test suite is provided:

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Coverage includes:

- Directory and archive input parsing
- Install lifecycle script extraction
- Setup errors when CodeQL is missing
- Mapping SARIF results to file paths
- Retry logic for invalid LLM JSON
- Package-level threshold aggregation
- Batch mode continuing when a single sample fails

## Current Reproduction Scope

- The LLM backend uses a LiteLLM-wrapped OpenAI-compatible API
- Packages are not automatically downloaded from the npm registry by default; only local directories or archives are accepted
- The CodeQL query set is a lightweight, extensible built-in version that supports iterative refinement toward the paper's experimental setup
