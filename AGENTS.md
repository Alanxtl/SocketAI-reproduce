# AGENTS.md

This file provides constraints and context for coding agents working in this repository. Unless the user explicitly requests otherwise, follow these project-level rules first.

## Project Overview

- Repository name: `socketai-reproduce`
- Goal: reproduce the npm malicious package detection workflow from the SocketAI paper
- Current mainline: accept a local npm package directory or archive as input, run optional CodeQL prescreening and three-stage LLM analysis, and export experiment artifacts that support debugging and statistics

## Key Directories

- `socketai_reproduce/cli.py`: CLI entry point providing `detect` and `batch`
- `socketai_reproduce/workflow.py`: main workflow orchestration
- `socketai_reproduce/package_loader.py`: directory/archive input handling, `package.json` parsing, and candidate file selection
- `socketai_reproduce/llm/`: LiteLLM client and prompt templates
- `socketai_reproduce/prescreener/codeql.py`: CodeQL prescreening and SARIF parsing
- `socketai_reproduce/reporting/exporters.py`: JSON/JSONL/CSV export logic
- `socketai_reproduce/codeql_queries/`: built-in CodeQL query pack
- `scripts/plot_batch_results.py`: publication-style visualization for batch checkpoints
- `utils/find_archives.py`: existing helpers for archive extraction and risky file traversal
- `tests/`: minimal unit tests and smoke tests
- `result/`: runtime artifact output directory, not tracked by version control by default

## Working Principles

- This is a research reproduction repository. Prioritize workflow transparency, traceable data, and reusable experiments.
- Every LLM input and output should be saved, replayable, and comparable whenever possible.
- If external behavior changes, `README.md` must be updated at the same time.
- If you add workflow stages, exported files, configuration items, or experiment entry points, also update `README.md`.
- Prefer keeping intermediate results. Do not delete debug data that helps reproduction just for cleanliness.
- Batch exports are checkpointed incrementally. Preserve that behavior unless there is a strong reason to change it.

## Code Navigation Suggestions

- Start with `socketai_reproduce/workflow.py` to understand the main flow.
- Then read `socketai_reproduce/package_loader.py` and `socketai_reproduce/prescreener/codeql.py` to understand input preparation and prescreening.
- If you need to adjust prompts or LLM output structure, look at `socketai_reproduce/llm/prompts.py` and `socketai_reproduce/analysis/models.py` first.
- If you need to change result formats or statistical tables, look at `socketai_reproduce/reporting/exporters.py` first.

## Common Commands

Python environment conventions:

- Prefer using the interpreter and dependencies in the repository-local `.venv` directly. Do not switch to system Python or another virtual environment.
- On Windows, usually use `.venv\Scripts\python.exe`.
- Prefer `uv sync` to install or synchronize dependencies.
- By default, LLM and CodeQL configuration should be read from the repository root `.env`; only use system environment variables for temporary overrides when needed.

Common commands:

```powershell
uv sync
uv run .\main.py --help
uv run .\main.py detect --input <path> --model <model> --no-codeql
uv run .\main.py batch --manifest <manifest.jsonl> --model <model> --no-codeql
uv run .\scripts\plot_batch_results.py --batch-dir <result/batches/batch_id>
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

If you need to call the interpreter explicitly, prefer:

```powershell
.venv\Scripts\python.exe -m unittest
```

## Modification Constraints

- Prefer reusing the existing archive and candidate file utilities in `utils/find_archives.py`.
- When adding new result exports, keep field names stable and avoid breaking downstream plotting scripts without a clear reason.
- Workflow output should go under `result/` by default. Do not commit one-off experiment outputs into the repository.
- If you change thresholds, stage names, or exported fields related to the paper workflow, clearly explain why.
- CodeQL-related implementations must preserve diagnosable error messages when the environment is missing. Do not silently swallow setup errors.

## Validation Standards

- Run at least the tests directly related to your changes whenever possible.
- If your changes affect the CLI, export format, classification labels, or tool return values, explain how you validated them.
- If validation cannot be completed, explicitly state what was not validated and why.
- For workflow, export, or result aggregation changes, prefer running:

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Documentation Requirements

- If external behavior changes, update `README.md` at the same time.
- If you add agent tools, prompt stages, exported files, or batch experiment entry points, document them in the relevant README section.
- If you change the output directory structure, make sure the README directory description is updated accordingly.

## CodeQL Notes

- Real CodeQL prescreening depends on the external `codeql` CLI.
- The executable can be specified through the system `PATH` or the `CODEQL_BIN` environment variable.
- If CodeQL is not installed, `detect --use-codeql` should report a clear error; `batch --use-codeql` should mark the single sample as `setup_error` and continue.

## Debug Data Requirements

- `result/runs/<run_id>/stages/<file_id>/stage{1,2,3}.json` are critical debug artifacts. Do not delete them unless the user explicitly requests it.
- Each stage should retain at least:
  - `prompt_text`
  - `prompt_context`
  - `raw_response_text`
  - `parsed_response`
  - `usage`
  - `latency_ms`
  - `retry_count`
  - `status`
- File-level and package-level CSV outputs are foundational for downstream research plots. Confirm the impact before changing fields.

## Prohibited Actions

- Do not modify existing analysis artifacts under `result/` without a clear reason as a "fix".
- Do not write one-off sample paths, absolute paths, or local secrets into the repository.
- Do not delete regression tests or weaken assertions just to make tests pass, unless the user explicitly requests a baseline adjustment.
