# SocketAI-reproduce

`socketai-reproduce` 是对 ICSE 2025 论文 *Leveraging Large Language Models to Detect NPM Malicious Packages* 的工程化复现。当前版本实现了一条可运行的 npm 包检测 workflow：

- 输入本地 npm 包目录或 `.tgz/.tar/.zip` 归档
- 可选使用真实 `CodeQL` 做静态预筛
- 对候选文件运行三阶段 LLM 分析
- 输出包级恶意判定
- 保留每一步 prompt、raw response、解析结果、token 与耗时，便于 debug 和科研统计

## 项目结构

```text
socketai_reproduce/
  cli.py                  # detect / batch CLI
  workflow.py             # 端到端编排
  package_loader.py       # 目录/归档输入处理
  analysis/models.py      # 结构化数据模型
  llm/
    client.py             # LiteLLM 适配
    prompts.py            # 三阶段 prompt
  prescreener/
    codeql.py             # CodeQL 预筛与 SARIF 解析
  reporting/exporters.py  # JSON/JSONL/CSV 导出
  codeql_queries/         # 仓库内置 CodeQL query pack
utils/
  find_archives.py        # 归档解压与危险文件枚举辅助
tests/
  ...                     # 最小单元测试与 smoke test
```

## 环境准备

仓库默认使用本地 `.venv`。

```powershell
uv sync
```

如果需要真实 CodeQL 预筛，请额外安装 CodeQL CLI，并满足以下任一条件：

- `codeql` 已加入系统 `PATH`
- 设置环境变量 `CODEQL_BIN`

LLM 配置默认从仓库根目录 `.env` 读取，再回退到当前进程环境变量。推荐在仓库根目录创建 `.env`：

```powershell
OPENAI_API_KEY=your-key
OPENAI_BASE_URL=https://your-compatible-endpoint/v1
```

如果你更习惯临时设置环境变量，现有方式仍然可用；`.env` 不会覆盖已经存在的系统环境变量。

## CLI 用法

安装依赖后可直接使用：

```powershell
uv run .\main.py --help
```

### 1. 单包检测

不开启 CodeQL：

```powershell
uv run .\main.py detect `
  --input .\samples\some-package `
  --model gpt-4o-mini `
  --no-codeql
```

启用 CodeQL：

```powershell
uv run .\main.py detect `
  --input .\samples\some-package.tgz `
  --model gpt-4o-mini `
  --use-codeql
```

常用参数：

- `--input`: 本地目录或 npm 归档
- `--model`: LiteLLM 使用的模型名
- `--output-dir`: 检测结果根目录，默认 `result/runs`
- `--threshold`: 包级聚合阈值，默认 `0.5`
- `--temperature`: LLM 温度，默认 `0`
- `--use-codeql / --no-codeql`: 是否启用 CodeQL 预筛
- `--codeql-bin`: 显式指定 CodeQL 可执行文件

### 2. 批量检测

支持 `jsonl` 或 `csv` manifest，至少包含 `input` 字段。

`manifest.jsonl` 示例：

```json
{"input": "D:/datasets/pkg_a"}
{"input": "D:/datasets/pkg_b.tgz"}
```

运行方式：

```powershell
uv run .\main.py batch `
  --manifest .\manifest.jsonl `
  --model gpt-4o-mini `
  --output-dir .\result\batches `
  --no-codeql
```

`batch` 遇到单样本 `CodeQL` 环境错误时不会整体中止，而是把该样本标记为 `setup_error` 后继续。

## 输出目录

单次 `detect` 默认输出到 `result/runs/<run_id>/`：

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

各阶段 JSON 都会保留：

- `prompt_text`
- `prompt_context`
- `raw_response_text`
- `parsed_response`
- `usage`
- `latency_ms`
- `retry_count`
- `status`

`batch` 额外在批次目录下导出聚合版 `exports/package_level.csv` 与 `exports/file_level.csv`，便于后续画图。

## 工作流说明

当前实现采用“论文风格、工程上可调试”的固定流程：

1. 输入准备：解析包根目录、读取 `package.json`、识别危险脚本文件与 install 生命周期脚本。
2. CodeQL 预筛：若启用，则运行仓库内置 query suite，得到候选文件集合与规则命中。
3. 三阶段 LLM 分析：
   - Stage 1：初始恶意评估
   - Stage 2：自我复核与修正
   - Stage 3：最终文件级判定
4. 包级聚合：若任一文件 `final_score >= threshold`，则该包判为 `malicious`。

## 验证

已提供最小测试集：

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

覆盖内容包括：

- 目录输入与归档输入解析
- install 生命周期脚本提取
- CodeQL 缺失时的 setup error
- SARIF 结果到文件路径的映射
- LLM 非法 JSON 重试
- 包级阈值聚合
- batch 模式下单样本失败不整体中止

## 当前复现边界

- 当前版本优先复现“流程结构、调试产物和实验数据导出”，不是论文全部 benchmark 的逐项复刻
- LLM 后端使用 LiteLLM 封装的 OpenAI 兼容接口
- 默认不从 npm registry 自动下载包，只接受本地目录或归档
- CodeQL 查询集是仓库内置的轻量可扩展版本，便于后续迭代逼近论文实验设置
