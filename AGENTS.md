# AGENTS.md

本文件为在本仓库内工作的代码代理提供约束和上下文。除非用户明确要求，否则优先遵循这里的项目级规则。

## 项目概览

- 仓库名：`socketai-reproduce`
- 目标：复现 SocketAI 论文中的 npm 恶意包检测工作流
- 当前主线：输入本地 npm 包目录或归档，执行可选 CodeQL 预筛和三阶段 LLM 分析，并导出可调试、可统计的实验产物

## 关键目录

- `socketai_reproduce/cli.py`：CLI 入口，提供 `detect` 和 `batch`
- `socketai_reproduce/workflow.py`：主工作流编排
- `socketai_reproduce/package_loader.py`：目录/归档输入、`package.json` 解析、候选文件选择
- `socketai_reproduce/llm/`：LiteLLM 客户端与 prompt 模板
- `socketai_reproduce/prescreener/codeql.py`：CodeQL 预筛与 SARIF 解析
- `socketai_reproduce/reporting/exporters.py`：JSON/JSONL/CSV 导出
- `socketai_reproduce/codeql_queries/`：仓库内置 CodeQL query pack
- `utils/find_archives.py`：已有的归档提取与危险文件遍历辅助
- `tests/`：最小单元测试与 smoke test
- `result/`：运行产物输出目录，默认不纳入版本控制

## 工作原则

- 这是科研复现仓库，优先保证流程透明、数据可追踪、实验可复用。
- 每一步 LLM 输入输出都应尽量可落盘、可回放、可比对。
- 对外行为变化时，必须同步更新 `README.md`。
- 若新增工作流阶段、导出文件、配置项或实验入口，也要同步更新 `README.md`。
- 优先保留中间结果，不要为了“整洁”而删除对复现有帮助的 debug 数据。

## 代码导航建议

- 先看 `socketai_reproduce/workflow.py`，理解主流程。
- 再看 `socketai_reproduce/package_loader.py` 和 `socketai_reproduce/prescreener/codeql.py`，理解输入准备与预筛。
- 如果要调 prompt 或 LLM 输出结构，优先看 `socketai_reproduce/llm/prompts.py` 与 `socketai_reproduce/analysis/models.py`。
- 如果要改结果格式或统计表，优先看 `socketai_reproduce/reporting/exporters.py`。

## 常用命令

Python 环境约定：

- 优先直接使用仓库内 `.venv` 的解释器与依赖，不要切换到系统 Python 或其他虚拟环境。
- 在 Windows 路径下通常使用 `.venv\Scripts\python.exe`。
- 安装或同步依赖优先使用 `uv sync`。
- LLM 和 CodeQL 的默认配置优先从仓库根目录 `.env` 读取；仅在需要临时覆盖时再使用系统环境变量。

常用命令：

```powershell
uv sync
uv run .\main.py --help
uv run .\main.py detect --input <path> --model <model> --no-codeql
uv run .\main.py batch --manifest <manifest.jsonl> --model <model> --no-codeql
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

如果需要显式调用解释器，可优先使用：

```powershell
.venv\Scripts\python.exe -m unittest
```

## 修改约束

- 优先复用 `utils/find_archives.py` 中已有的归档与候选文件工具。
- 新增结果导出时，保持字段名稳定，避免无故破坏下游画图脚本。
- 工作流默认输出到 `result/` 下；不要把一次性实验输出提交进仓库。
- 与论文流程相关的阈值、阶段命名、导出字段，修改时要明确说明原因。
- CodeQL 相关实现要保留“环境缺失时可诊断”的错误信息，不要静默吞掉 setup error。

## 验证标准

- 能跑的测试至少跑与改动直接相关的那部分。
- 如果改动影响 CLI、导出格式、判定标签或工具返回值，说明验证方式。
- 如果无法完成验证，要明确写出未验证项和原因。
- 涉及工作流、导出或结果聚合时，优先跑：

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## 文档要求

- 对外行为发生变化时，同时更新 `README.md`。
- 新增代理工具、提示阶段、导出文件或批量实验入口时，补充到 README 对应章节。
- 如果修改输出目录结构，务必同步更新 README 中的目录说明。

## CodeQL 说明

- 真实 CodeQL 预筛依赖外部 `codeql` CLI。
- 可通过系统 `PATH` 或环境变量 `CODEQL_BIN` 指定可执行文件。
- 若本机未安装 CodeQL，`detect --use-codeql` 应报清晰错误；`batch --use-codeql` 应把单样本标记为 `setup_error` 后继续。

## Debug 数据要求

- `result/runs/<run_id>/stages/<file_id>/stage{1,2,3}.json` 是关键调试产物，除非用户明确要求，否则不要删除。
- 每个阶段至少要保留：
  - `prompt_text`
  - `prompt_context`
  - `raw_response_text`
  - `parsed_response`
  - `usage`
  - `latency_ms`
  - `retry_count`
  - `status`
- 文件级和包级 CSV 是后续科研画图的基础数据，改字段前先确认影响。

## 禁止事项

- 不要无故改动 `result/` 下已有分析产物作为“修复”。
- 不要把一次性的样本路径、绝对路径或本地密钥写入仓库。
- 不要为了通过测试而删除回归用例或弱化断言，除非用户明确要求调整基线。
