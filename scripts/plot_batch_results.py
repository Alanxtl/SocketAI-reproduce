from __future__ import annotations

import argparse
import io
import json
import sys
from collections import Counter
from contextlib import redirect_stdout
from pathlib import Path
from textwrap import shorten

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = REPO_ROOT / ".agents" / "skills" / "scientific-visualization"
sys.path.insert(0, str(SKILL_ROOT / "scripts"))
sys.path.insert(0, str(SKILL_ROOT / "assets"))

from color_palettes import OKABE_ITO_LIST  # type: ignore  # noqa: E402
from figure_export import save_publication_figure  # type: ignore  # noqa: E402
from style_presets import apply_publication_style  # type: ignore  # noqa: E402


STATUS_COLORS = {
    "success": "#0072B2",
    "error": "#D55E00",
    "remaining": "#B3B3B3",
}

VERDICT_COLORS = {
    "malicious": "#D55E00",
    "suspicious": "#E69F00",
    "benign": "#009E73",
    "unknown": "#7F7F7F",
}

COHORT_COLORS = {
    "p0-33": "#0072B2",
    "p0-66": "#E69F00",
    "p0-100": "#009E73",
    "unknown": "#7F7F7F",
}

PANEL_LABELS = ("A", "B", "C", "D", "E", "F")
PACKAGE_LABEL_ORDER = ["malicious", "benign", "unknown"]
FILE_LABEL_ORDER = ["malicious", "suspicious", "benign"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create publication-ready summary figures from SocketAI batch results."
    )
    parser.add_argument(
        "--batch-dir",
        type=Path,
        default=None,
        help="Path to a batch result directory. Defaults to the latest batch with batch_meta.json.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("result") / "figures",
        help="Root directory for generated figures.",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=10,
        help="Number of top suspicious packages to show in the highlights panel.",
    )
    parser.add_argument(
        "--labels",
        type=Path,
        default=None,
        help="Optional CSV or JSONL file with ground truth labels. Expected fields: input + label/ground_truth.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    batch_dir = args.batch_dir.resolve() if args.batch_dir else discover_latest_batch_dir()
    batch_meta = json.loads((batch_dir / "batch_meta.json").read_text(encoding="utf-8"))
    package_df = pd.read_csv(batch_dir / "exports" / "package_level.csv")
    file_df = pd.read_csv(batch_dir / "exports" / "file_level.csv")
    manifest_path = Path(batch_meta["manifest_path"])

    cohort_totals = load_manifest_cohort_totals(manifest_path)
    package_df = prepare_package_df(package_df)
    file_df = prepare_file_df(file_df)
    file_df = file_df.loc[file_df["run_id"].isin(package_df["run_id"])].copy()
    run_metrics_df = load_run_metrics_df(batch_dir, package_df["run_id"].tolist())
    ground_truth_df = load_ground_truth(args.labels, manifest_path)
    accuracy_summary = compute_accuracy_summary(package_df, ground_truth_df)
    focus_summary = build_focus_summary(package_df, file_df, run_metrics_df, accuracy_summary)

    figure_output_dir = args.output_dir.resolve() / batch_meta["batch_id"]
    figure_output_dir.mkdir(parents=True, exist_ok=True)

    summary = build_summary(batch_meta, package_df, file_df, cohort_totals, args.top_n)
    summary["accuracy"] = accuracy_summary
    summary["focus_metrics"] = focus_summary
    summary_path = figure_output_dir / "batch_overview_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    highlights_path = figure_output_dir / "top_suspicious_packages.csv"
    top_df = pd.DataFrame(summary["top_suspicious_packages"])
    if not top_df.empty:
        top_df.to_csv(highlights_path, index=False, encoding="utf-8")

    figure_path = figure_output_dir / "batch_overview"
    fig = render_overview_figure(
        batch_meta=batch_meta,
        package_df=package_df,
        file_df=file_df,
        cohort_totals=cohort_totals,
        summary=summary,
        top_n=args.top_n,
    )
    save_figure_quietly(fig, figure_path)
    plt.close(fig)

    focus_figure_path = figure_output_dir / "batch_focus_metrics"
    focus_fig = render_focus_figure(
        batch_meta=batch_meta,
        package_df=package_df,
        file_df=file_df,
        run_metrics_df=run_metrics_df,
        accuracy_summary=accuracy_summary,
        focus_summary=focus_summary,
    )
    save_figure_quietly(focus_fig, focus_figure_path)
    plt.close(focus_fig)

    print(json.dumps({"batch_dir": str(batch_dir), "output_dir": str(figure_output_dir)}, indent=2))


def discover_latest_batch_dir(root: Path | None = None) -> Path:
    search_root = (root or (REPO_ROOT / "result" / "batches")).resolve()
    batch_meta_files = list(search_root.rglob("batch_meta.json"))
    if not batch_meta_files:
        raise FileNotFoundError(f"No batch_meta.json found under {search_root}")
    latest_meta = max(batch_meta_files, key=lambda path: path.stat().st_mtime)
    return latest_meta.parent


def extract_cohort(path_value: str) -> str:
    for part in Path(str(path_value)).parts:
        if str(part).startswith("p0-"):
            return str(part)
    return "unknown"


def normalize_package_label(value: object) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"malicious", "benign", "unknown"}:
        return normalized
    if normalized == "suspicious":
        return "malicious"
    return "unknown"


def normalize_file_label(value: object) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"malicious", "benign", "suspicious"}:
        return normalized
    return "unknown"


def load_manifest_cohort_totals(manifest_path: Path) -> dict[str, int]:
    counts: Counter[str] = Counter()
    if not manifest_path.exists():
        return {}
    for line in manifest_path.read_text(encoding="utf-8-sig").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        counts[extract_cohort(row["input"])] += 1
    ordered = ["p0-33", "p0-66", "p0-100"]
    result = {cohort: counts.get(cohort, 0) for cohort in ordered}
    for cohort, count in counts.items():
        if cohort not in result:
            result[cohort] = count
    return result


def prepare_package_df(package_df: pd.DataFrame) -> pd.DataFrame:
    if package_df.empty:
        package_df = pd.DataFrame(
            columns=[
                "run_id",
                "input_path",
                "package_name",
                "label",
                "status",
                "max_file_score",
                "flagged_file_count",
                "analyzed_files",
            ]
        )
    prepared = package_df.copy()
    prepared["cohort"] = prepared["input_path"].map(extract_cohort)
    prepared["archive_name"] = prepared["input_path"].map(lambda value: Path(str(value)).name)
    prepared["status_norm"] = prepared["status"].astype(str).str.strip().str.lower()
    prepared["label_norm"] = prepared["label"].map(normalize_package_label)
    prepared["max_file_score"] = pd.to_numeric(prepared["max_file_score"], errors="coerce").fillna(0.0)
    prepared["flagged_file_count"] = (
        pd.to_numeric(prepared["flagged_file_count"], errors="coerce").fillna(0).astype(int)
    )
    prepared["analyzed_files"] = (
        pd.to_numeric(prepared["analyzed_files"], errors="coerce").fillna(0).astype(int)
    )
    return prepared


def prepare_file_df(file_df: pd.DataFrame) -> pd.DataFrame:
    if file_df.empty:
        file_df = pd.DataFrame(
            columns=["run_id", "from_codeql", "final_label", "final_score", "confidence", "codeql_rules"]
        )
    prepared = file_df.copy()
    prepared["from_codeql"] = prepared["from_codeql"].astype(str).str.lower().eq("true")
    prepared["final_label_norm"] = prepared["final_label"].map(normalize_file_label)
    prepared["final_score"] = pd.to_numeric(prepared["final_score"], errors="coerce").fillna(0.0)
    prepared["confidence"] = pd.to_numeric(prepared["confidence"], errors="coerce").fillna(0.0)
    prepared["source"] = prepared["from_codeql"].map(
        {True: "CodeQL-hit", False: "Context-added"}
    )
    return prepared


def build_summary(
    batch_meta: dict[str, object],
    package_df: pd.DataFrame,
    file_df: pd.DataFrame,
    cohort_totals: dict[str, int],
    top_n: int,
) -> dict[str, object]:
    success_df = package_df.loc[package_df["status_norm"] == "success"].copy()
    error_df = package_df.loc[package_df["status_norm"] != "success"].copy()

    rule_counts = (
        file_df["codeql_rules"]
        .fillna("")
        .astype(str)
        .str.split(";")
        .explode()
        .loc[lambda series: series != ""]
        .value_counts()
    )

    top_packages_df = (
        success_df.sort_values(
            by=["max_file_score", "flagged_file_count", "analyzed_files", "package_name"],
            ascending=[False, False, False, True],
        )
        .head(top_n)
        .copy()
    )

    return {
        "batch_id": batch_meta["batch_id"],
        "status": batch_meta["status"],
        "manifest_path": batch_meta["manifest_path"],
        "packages_total": int(batch_meta["packages_total"]),
        "packages_completed": int(batch_meta["packages_completed"]),
        "packages_remaining": int(batch_meta["packages_total"]) - int(batch_meta["packages_completed"]),
        "packages_success": int(len(success_df)),
        "packages_error": int(len(error_df)),
        "files_exported": int(batch_meta["files_exported"]),
        "cohort_totals": cohort_totals,
        "package_label_counts": success_df["label_norm"].value_counts().to_dict(),
        "file_label_counts": file_df["final_label_norm"].value_counts().to_dict(),
        "selection_source_counts": file_df["source"].value_counts().to_dict(),
        "top_codeql_rules": [
            {"rule_id": rule_id, "count": int(count)}
            for rule_id, count in rule_counts.head(8).items()
        ],
        "top_suspicious_packages": [
            {
                "package_name": row["package_name"],
                "cohort": row["cohort"],
                "max_file_score": float(row["max_file_score"]),
                "flagged_file_count": int(row["flagged_file_count"]),
                "analyzed_files": int(row["analyzed_files"]),
            }
            for _, row in top_packages_df.iterrows()
        ],
        "last_completed_run_id": batch_meta.get("last_completed_run_id"),
    }


def load_run_metrics_df(batch_dir: Path, run_ids: list[str]) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    run_id_set = set(run_ids)
    for run_dir in sorted((batch_dir / "runs").glob("*")):
        if run_dir.name not in run_id_set:
            continue
        metrics_path = run_dir / "metrics.json"
        if not metrics_path.exists():
            continue
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        rows.append(
            {
                "run_id": run_dir.name,
                "input_files": int(metrics.get("input_files", 0)),
                "analyzed_files_metric": int(metrics.get("analyzed_files", 0)),
                "llm_calls": int(metrics.get("llm_calls", 0)),
                "codeql_candidate_files": int(metrics.get("codeql_candidate_files", 0)),
                "errors": int(metrics.get("errors", 0)),
                "prompt_tokens": int(metrics.get("prompt_tokens", 0)),
                "completion_tokens": int(metrics.get("completion_tokens", 0)),
                "total_tokens": int(metrics.get("total_tokens", 0)),
                "latency_ms": int(metrics.get("latency_ms", 0)),
            }
        )
    if not rows:
        return pd.DataFrame(
            columns=[
                "run_id",
                "prompt_tokens",
                "completion_tokens",
                "total_tokens",
                "latency_ms",
                "llm_calls",
            ]
        )
    return pd.DataFrame(rows)


def load_ground_truth(labels_path: Path | None, manifest_path: Path) -> pd.DataFrame:
    candidate_paths = [labels_path.resolve()] if labels_path else [manifest_path.resolve()]
    for path in candidate_paths:
        if not path.exists():
            continue
        rows = load_rows(path)
        if not rows:
            continue
        normalized_rows = []
        for row in rows:
            normalized = normalize_ground_truth_row(row)
            if normalized is not None:
                normalized_rows.append(normalized)
        if normalized_rows:
            df = pd.DataFrame(normalized_rows)
            dedupe_keys = [key for key in ("input_path", "archive_name", "cohort") if key in df.columns]
            return df.drop_duplicates(subset=dedupe_keys)
    return pd.DataFrame(columns=["input_path", "archive_name", "cohort", "ground_truth"])


def load_rows(path: Path) -> list[dict[str, object]]:
    if path.suffix.lower() == ".jsonl":
        return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    if path.suffix.lower() == ".csv":
        return pd.read_csv(path).to_dict(orient="records")
    raise ValueError(f"Unsupported label file format: {path}")


def normalize_ground_truth_label(value: object) -> str | None:
    normalized = str(value).strip().lower()
    if normalized in {"malicious", "1", "true", "positive", "pos"}:
        return "malicious"
    if normalized in {"benign", "0", "false", "negative", "neg"}:
        return "benign"
    return None


def normalize_ground_truth_row(row: dict[str, object]) -> dict[str, object] | None:
    input_value = row.get("input")
    direct_label = row.get("label", row.get("ground_truth", row.get("gt")))
    if input_value and direct_label is not None:
        normalized_label = normalize_ground_truth_label(direct_label)
        if normalized_label is None:
            return None
        return {
            "input_path": str(Path(str(input_value)).resolve()),
            "ground_truth": normalized_label,
        }

    archive_name = row.get("archive_name")
    cohort = row.get("bin_label")
    annotation = row.get("annotation")
    verdict = annotation.get("verdict") if isinstance(annotation, dict) else None
    normalized_label = normalize_ground_truth_label(verdict)
    if archive_name and cohort and normalized_label is not None:
        return {
            "archive_name": str(archive_name),
            "cohort": str(cohort),
            "ground_truth": normalized_label,
        }
    return None


def compute_accuracy_summary(
    package_df: pd.DataFrame,
    ground_truth_df: pd.DataFrame,
) -> dict[str, object]:
    if ground_truth_df.empty:
        predicted_counts = package_df["label_norm"].value_counts().to_dict()
        return {
            "available": False,
            "message": "Ground truth labels were not provided. Pass --labels with input + label columns.",
            "predicted_counts": predicted_counts,
        }

    if "input_path" in ground_truth_df.columns and ground_truth_df["input_path"].notna().any():
        merged = package_df.merge(ground_truth_df, on="input_path", how="left")
    elif {"archive_name", "cohort"}.issubset(ground_truth_df.columns):
        merged = package_df.merge(ground_truth_df, on=["archive_name", "cohort"], how="left")
    else:
        return {
            "available": False,
            "message": "Ground truth file format is unsupported for evaluation.",
        }
    eval_df = merged.loc[merged["ground_truth"].isin(["malicious", "benign"])].copy()
    if eval_df.empty:
        return {
            "available": False,
            "message": "Ground truth file was loaded, but no rows matched the current batch inputs.",
        }

    label_set = set(eval_df["ground_truth"].unique())
    if label_set == {"malicious"}:
        detected_positive = int((eval_df["label_norm"] == "malicious").sum())
        missed_positive = int(len(eval_df) - detected_positive)
        return {
            "available": True,
            "mode": "positive_only",
            "message": "Only malicious ground truth labels are available, so recall-style metrics are reported.",
            "evaluated_packages": int(len(eval_df)),
            "positive_recall": detected_positive / len(eval_df) if len(eval_df) else 0.0,
            "detected_positive": detected_positive,
            "missed_positive": missed_positive,
            "unknown_predictions": int((eval_df["label_norm"] == "unknown").sum()),
            "benign_predictions": int((eval_df["label_norm"] == "benign").sum()),
        }
    if label_set == {"benign"}:
        detected_benign = int((eval_df["label_norm"] == "benign").sum())
        missed_benign = int(len(eval_df) - detected_benign)
        return {
            "available": True,
            "mode": "negative_only",
            "message": "Only benign ground truth labels are available, so specificity-style metrics are reported.",
            "evaluated_packages": int(len(eval_df)),
            "negative_recall": detected_benign / len(eval_df) if len(eval_df) else 0.0,
            "detected_benign": detected_benign,
            "missed_benign": missed_benign,
            "unknown_predictions": int((eval_df["label_norm"] == "unknown").sum()),
            "malicious_predictions": int((eval_df["label_norm"] == "malicious").sum()),
        }

    predicted_positive = eval_df["label_norm"].eq("malicious")
    actual_positive = eval_df["ground_truth"].eq("malicious")
    tp = int((predicted_positive & actual_positive).sum())
    tn = int((~predicted_positive & ~actual_positive).sum())
    fp = int((predicted_positive & ~actual_positive).sum())
    fn = int((~predicted_positive & actual_positive).sum())
    total = len(eval_df)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / total if total else 0.0

    return {
        "available": True,
        "mode": "binary",
        "evaluated_packages": int(total),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "unknown_predictions": int((eval_df["label_norm"] == "unknown").sum()),
    }


def build_focus_summary(
    package_df: pd.DataFrame,
    file_df: pd.DataFrame,
    run_metrics_df: pd.DataFrame,
    accuracy_summary: dict[str, object],
) -> dict[str, object]:
    metrics_df = package_df.merge(run_metrics_df, on="run_id", how="left")
    metrics_df["prompt_tokens"] = pd.to_numeric(metrics_df["prompt_tokens"], errors="coerce").fillna(0).astype(int)
    metrics_df["completion_tokens"] = (
        pd.to_numeric(metrics_df["completion_tokens"], errors="coerce").fillna(0).astype(int)
    )
    metrics_df["total_tokens"] = pd.to_numeric(metrics_df["total_tokens"], errors="coerce").fillna(0).astype(int)
    metrics_df["latency_ms"] = pd.to_numeric(metrics_df["latency_ms"], errors="coerce").fillna(0).astype(int)

    file_work = file_df.copy()
    file_work["risk"] = file_work["final_label_norm"].isin({"malicious", "suspicious"})
    source_yield_df = (
        file_work.groupby("source")
        .agg(total_files=("run_id", "size"), risky_files=("risk", "sum"))
        .reset_index()
    )
    source_yield_df["yield_rate"] = (
        source_yield_df["risky_files"] / source_yield_df["total_files"].replace(0, 1)
    )

    package_contribution = file_work.groupby("run_id").apply(
        lambda group: pd.Series(
            {
                "any_risky": bool(group["risk"].any()),
                "any_codeql_risky": bool(((group["from_codeql"]) & (group["risk"])).any()),
            }
        )
    )
    contribution_counts = {
        "codeql_contributed_risky_packages": int(
            ((package_contribution["any_risky"]) & (package_contribution["any_codeql_risky"])).sum()
        ),
        "context_only_risky_packages": int(
            ((package_contribution["any_risky"]) & (~package_contribution["any_codeql_risky"])).sum()
        ),
        "clean_packages": int((~package_contribution["any_risky"]).sum()),
    }

    top_token_df = (
        metrics_df.sort_values(by=["total_tokens", "latency_ms"], ascending=[False, False])
        .head(10)
        .loc[:, ["package_name", "cohort", "total_tokens", "latency_ms", "label_norm"]]
    )

    return {
        "accuracy": accuracy_summary,
        "token_totals": {
            "prompt_tokens": int(metrics_df["prompt_tokens"].sum()),
            "completion_tokens": int(metrics_df["completion_tokens"].sum()),
            "total_tokens": int(metrics_df["total_tokens"].sum()),
        },
        "token_quantiles": metrics_df["total_tokens"].quantile([0.25, 0.5, 0.75, 0.9, 0.95]).to_dict(),
        "source_yield": source_yield_df.to_dict(orient="records"),
        "package_contribution": contribution_counts,
        "top_token_packages": [
            {
                "package_name": row["package_name"],
                "cohort": row["cohort"],
                "label": row["label_norm"],
                "total_tokens": int(row["total_tokens"]),
                "latency_ms": int(row["latency_ms"]),
            }
            for _, row in top_token_df.iterrows()
        ],
    }


def render_overview_figure(
    *,
    batch_meta: dict[str, object],
    package_df: pd.DataFrame,
    file_df: pd.DataFrame,
    cohort_totals: dict[str, int],
    summary: dict[str, object],
    top_n: int,
) -> plt.Figure:
    with redirect_stdout(io.StringIO()):
        apply_publication_style("default")
    plt.rcParams["pdf.fonttype"] = 42
    plt.rcParams["ps.fonttype"] = 42
    plt.rcParams["svg.fonttype"] = "none"
    plt.rcParams["axes.prop_cycle"] = plt.cycler(color=OKABE_ITO_LIST)

    fig, axes = plt.subplot_mosaic(
        [["A", "B", "C"], ["D", "E", "F"]],
        figsize=(11.2, 7.2),
        constrained_layout=True,
    )

    annotate_panels(axes)

    render_overall_progress(axes["A"], batch_meta, summary)
    render_cohort_progress(axes["B"], batch_meta, package_df, cohort_totals)
    render_package_verdicts(axes["C"], package_df, cohort_totals)
    render_file_source_panel(axes["D"], file_df)
    render_rule_hits(axes["E"], file_df)
    render_top_packages(axes["F"], package_df, top_n)

    checkpoint_label = "Partial checkpoint" if batch_meta.get("status") != "completed" else "Completed batch"
    fig.suptitle(
        f"SocketAI Batch Result Overview | {batch_meta['batch_id']} | {checkpoint_label}",
        fontsize=11,
        fontweight="bold",
        y=1.01,
    )
    return fig


def save_figure_quietly(fig: plt.Figure, filename: Path) -> None:
    with redirect_stdout(io.StringIO()):
        save_publication_figure(fig, filename, formats=["pdf", "png"], dpi=300)


def annotate_panels(axes: dict[str, plt.Axes]) -> None:
    for label, axis_key in zip(PANEL_LABELS, axes):
        axes[axis_key].text(
            -0.14,
            1.03,
            label,
            transform=axes[axis_key].transAxes,
            fontsize=11,
            fontweight="bold",
            va="top",
        )


def render_overall_progress(
    ax: plt.Axes,
    batch_meta: dict[str, object],
    summary: dict[str, object],
) -> None:
    total = int(batch_meta["packages_total"])
    packages_completed = int(batch_meta["packages_completed"])
    success_rows = int(summary["packages_success"])
    error_rows = int(summary["packages_error"])
    remaining = int(summary["packages_remaining"])

    ax.set_title("Batch progress", loc="left", fontsize=10, fontweight="bold")

    status_text = str(batch_meta.get("status", "running")).lower()
    source_counts = summary["selection_source_counts"]
    source_text = (
        f"Selection sources: {source_counts.get('Context-added', 0)} context-added, "
        f"{source_counts.get('CodeQL-hit', 0)} CodeQL-hit"
    )
    description_lines = [
        f"Packages completed: {packages_completed}/{total} ({packages_completed / total:.1%})",
        f"Files exported: {int(batch_meta['files_exported'])}",
        f"Batch status: {status_text}",
        source_text,
    ]
    if batch_meta.get("last_completed_run_id"):
        description_lines.append(
            f"Last completed run: {shorten(str(batch_meta['last_completed_run_id']), width=30, placeholder='...')}"
        )

    ax.barh([0], [success_rows], color=STATUS_COLORS["success"], label="Success", height=0.35)
    ax.barh(
        [0],
        [error_rows],
        left=[success_rows],
        color=STATUS_COLORS["error"],
        label="Error",
        height=0.35,
    )
    ax.barh(
        [0],
        [remaining],
        left=[success_rows + error_rows],
        color=STATUS_COLORS["remaining"],
        label="Remaining",
        height=0.35,
    )
    ax.set_xlim(0, total)
    ax.set_yticks([])
    ax.set_xlabel("Packages")
    ax.legend(ncol=3, frameon=False, loc="upper center", bbox_to_anchor=(0.5, 1.18))
    ax.text(
        0.02,
        0.08,
        "\n".join(description_lines),
        transform=ax.transAxes,
        ha="left",
        va="bottom",
        fontsize=8,
        bbox={"facecolor": "#F6F6F6", "edgecolor": "#D0D0D0", "boxstyle": "round,pad=0.3"},
    )


def render_cohort_progress(
    ax: plt.Axes,
    batch_meta: dict[str, object],
    package_df: pd.DataFrame,
    cohort_totals: dict[str, int],
) -> None:
    ax.set_title("Cohort completion", loc="left", fontsize=10, fontweight="bold")
    rows = []
    for cohort, total in cohort_totals.items():
        cohort_df = package_df.loc[package_df["cohort"] == cohort]
        success_count = int((cohort_df["status_norm"] == "success").sum())
        error_count = int((cohort_df["status_norm"] != "success").sum())
        remaining_count = int(total) - success_count - error_count
        rows.append(
            {
                "cohort": cohort,
                "success": success_count,
                "error": error_count,
                "remaining": max(remaining_count, 0),
                "total": total,
            }
        )
    progress_df = pd.DataFrame(rows)
    y_positions = list(range(len(progress_df)))
    left = [0] * len(progress_df)
    for key, label in [("success", "Success"), ("error", "Error"), ("remaining", "Remaining")]:
        values = progress_df[key].tolist()
        ax.barh(
            y_positions,
            values,
            left=left,
            color=STATUS_COLORS[key],
            label=label,
            height=0.55,
        )
        left = [current + value for current, value in zip(left, values)]
    ax.set_yticks(y_positions, progress_df["cohort"].tolist())
    ax.set_xlabel("Packages")
    ax.invert_yaxis()
    ax.legend(frameon=False, fontsize=7, loc="lower right")
    for idx, row in progress_df.iterrows():
        ax.text(row["total"] + 8, idx, f"n={row['total']}", va="center", fontsize=7)


def render_package_verdicts(ax: plt.Axes, package_df: pd.DataFrame, cohort_totals: dict[str, int]) -> None:
    ax.set_title("Successful package verdicts", loc="left", fontsize=10, fontweight="bold")
    success_df = package_df.loc[package_df["status_norm"] == "success"].copy()
    if success_df.empty:
        ax.text(0.5, 0.5, "No successful package results yet", ha="center", va="center")
        ax.set_axis_off()
        return

    rows = []
    for cohort in cohort_totals:
        cohort_success = success_df.loc[success_df["cohort"] == cohort]
        total_success = len(cohort_success)
        row = {"cohort": cohort, "total_success": total_success}
        for verdict in PACKAGE_LABEL_ORDER:
            row[verdict] = int((cohort_success["label_norm"] == verdict).sum())
        rows.append(row)

    verdict_df = pd.DataFrame(rows)
    y_positions = list(range(len(verdict_df)))
    left = [0.0] * len(verdict_df)
    for verdict in ["malicious", "benign"]:
        totals = verdict_df["total_success"].replace(0, 1)
        fractions = (verdict_df[verdict] / totals).tolist()
        ax.barh(
            y_positions,
            fractions,
            left=left,
            color=VERDICT_COLORS[verdict],
            label=verdict.capitalize(),
            height=0.55,
        )
        left = [current + value for current, value in zip(left, fractions)]

    ax.set_xlim(0, 1.0)
    ax.xaxis.set_major_formatter(PercentFormatter(xmax=1.0))
    ax.set_yticks(y_positions, verdict_df["cohort"].tolist())
    ax.invert_yaxis()
    ax.set_xlabel("Fraction of successful packages")
    ax.legend(frameon=False, fontsize=7, loc="lower right")
    for idx, row in verdict_df.iterrows():
        if row["total_success"] == 0:
            ax.text(0.01, idx, "No completed successes", va="center", fontsize=7)
        else:
            ax.text(1.02, idx, f"n={row['total_success']}", va="center", fontsize=7)


def render_file_source_panel(ax: plt.Axes, file_df: pd.DataFrame) -> None:
    ax.set_title("File verdicts by selection source", loc="left", fontsize=10, fontweight="bold")
    if file_df.empty:
        ax.text(0.5, 0.5, "No file-level results yet", ha="center", va="center")
        ax.set_axis_off()
        return

    source_table = (
        pd.crosstab(file_df["source"], file_df["final_label_norm"])
        .reindex(index=["Context-added", "CodeQL-hit"], fill_value=0)
        .reindex(columns=FILE_LABEL_ORDER, fill_value=0)
    )
    x_positions = list(range(len(source_table.index)))
    bottoms = [0] * len(x_positions)
    for verdict in FILE_LABEL_ORDER:
        values = source_table[verdict].tolist()
        ax.bar(
            x_positions,
            values,
            bottom=bottoms,
            color=VERDICT_COLORS[verdict],
            label=verdict.capitalize(),
            width=0.55,
        )
        bottoms = [current + value for current, value in zip(bottoms, values)]

    ax.set_xticks(x_positions, source_table.index.tolist())
    ax.set_ylabel("Analyzed files")
    ax.legend(frameon=False, fontsize=7, loc="upper right")
    for idx, total in enumerate(source_table.sum(axis=1).tolist()):
        ax.text(idx, total + 10, f"n={total}", ha="center", fontsize=7)


def render_rule_hits(ax: plt.Axes, file_df: pd.DataFrame) -> None:
    ax.set_title("Top CodeQL rule hits", loc="left", fontsize=10, fontweight="bold")
    if file_df.empty:
        ax.text(0.5, 0.5, "No CodeQL findings yet", ha="center", va="center")
        ax.set_axis_off()
        return

    rule_counts = (
        file_df["codeql_rules"]
        .fillna("")
        .astype(str)
        .str.split(";")
        .explode()
        .loc[lambda series: series != ""]
        .value_counts()
        .head(6)
        .sort_values(ascending=True)
    )
    if rule_counts.empty:
        ax.text(0.5, 0.5, "No CodeQL rules were exported", ha="center", va="center")
        ax.set_axis_off()
        return

    labels = [shorten(label, width=28, placeholder="...") for label in rule_counts.index]
    ax.barh(labels, rule_counts.values, color=OKABE_ITO_LIST[: len(rule_counts)])
    ax.set_xlabel("Matched files")
    for idx, value in enumerate(rule_counts.values):
        ax.text(value + 3, idx, str(int(value)), va="center", fontsize=7)


def render_top_packages(ax: plt.Axes, package_df: pd.DataFrame, top_n: int) -> None:
    ax.set_title("Top suspicious packages", loc="left", fontsize=10, fontweight="bold")
    success_df = package_df.loc[package_df["status_norm"] == "success"].copy()
    if success_df.empty:
        ax.text(0.5, 0.5, "No successful package results yet", ha="center", va="center")
        ax.set_axis_off()
        return

    top_df = (
        success_df.sort_values(
            by=["max_file_score", "flagged_file_count", "analyzed_files", "package_name"],
            ascending=[False, False, False, True],
        )
        .head(top_n)
        .sort_values(by=["max_file_score", "flagged_file_count"], ascending=[True, True])
    )
    labels = [shorten(name, width=24, placeholder="...") for name in top_df["package_name"]]
    colors = [COHORT_COLORS.get(cohort, COHORT_COLORS["unknown"]) for cohort in top_df["cohort"]]
    ax.barh(labels, top_df["max_file_score"], color=colors)
    ax.axvline(0.5, color="#404040", linestyle="--", linewidth=1, label="Threshold = 0.5")
    ax.set_xlim(0, 1.05)
    ax.set_xlabel("Maximum file score")
    for idx, (_, row) in enumerate(top_df.iterrows()):
        ax.text(
            min(row["max_file_score"] + 0.02, 1.02),
            idx,
            f"{row['cohort']} | flagged={row['flagged_file_count']}",
            va="center",
            fontsize=7,
        )
    cohort_handles = [
        plt.Line2D([0], [0], color=color, lw=4, label=cohort)
        for cohort, color in COHORT_COLORS.items()
        if cohort in set(top_df["cohort"])
    ]
    threshold_handle = plt.Line2D([0], [0], color="#404040", linestyle="--", lw=1, label="Threshold = 0.5")
    ax.legend(handles=cohort_handles + [threshold_handle], frameon=False, fontsize=7, loc="lower right")


def render_focus_figure(
    *,
    batch_meta: dict[str, object],
    package_df: pd.DataFrame,
    file_df: pd.DataFrame,
    run_metrics_df: pd.DataFrame,
    accuracy_summary: dict[str, object],
    focus_summary: dict[str, object],
) -> plt.Figure:
    with redirect_stdout(io.StringIO()):
        apply_publication_style("default")
    plt.rcParams["pdf.fonttype"] = 42
    plt.rcParams["ps.fonttype"] = 42
    plt.rcParams["svg.fonttype"] = "none"
    plt.rcParams["axes.prop_cycle"] = plt.cycler(color=OKABE_ITO_LIST)

    fig, axes = plt.subplot_mosaic(
        [["A", "B", "C"], ["D", "E", "F"]],
        figsize=(11.2, 7.2),
        constrained_layout=True,
    )
    annotate_panels(axes)

    metrics_df = package_df.merge(run_metrics_df, on="run_id", how="left")
    metrics_df["prompt_tokens"] = pd.to_numeric(metrics_df["prompt_tokens"], errors="coerce").fillna(0)
    metrics_df["completion_tokens"] = pd.to_numeric(
        metrics_df["completion_tokens"], errors="coerce"
    ).fillna(0)
    metrics_df["total_tokens"] = pd.to_numeric(metrics_df["total_tokens"], errors="coerce").fillna(0)
    metrics_df["latency_ms"] = pd.to_numeric(metrics_df["latency_ms"], errors="coerce").fillna(0)

    render_accuracy_panel(axes["A"], accuracy_summary, package_df)
    render_token_allocation_panel(axes["B"], metrics_df)
    render_token_distribution_panel(axes["C"], metrics_df)
    render_codeql_yield_panel(axes["D"], file_df)
    render_codeql_contribution_panel(axes["E"], file_df)
    render_top_token_panel(axes["F"], metrics_df)

    checkpoint_label = "Partial checkpoint" if batch_meta.get("status") != "completed" else "Completed batch"
    fig.suptitle(
        f"SocketAI Accuracy / Token / CodeQL Focus | {batch_meta['batch_id']} | {checkpoint_label}",
        fontsize=11,
        fontweight="bold",
        y=1.01,
    )
    return fig


def render_accuracy_panel(
    ax: plt.Axes,
    accuracy_summary: dict[str, object],
    package_df: pd.DataFrame,
) -> None:
    ax.set_title("Accuracy view", loc="left", fontsize=10, fontweight="bold")
    if not accuracy_summary.get("available"):
        predicted_counts = accuracy_summary.get("predicted_counts", {})
        malicious_count = int(predicted_counts.get("malicious", 0))
        benign_count = int(predicted_counts.get("benign", 0))
        unknown_count = int(predicted_counts.get("unknown", 0))
        ax.bar(
            ["Malicious", "Benign", "Unknown"],
            [malicious_count, benign_count, unknown_count],
            color=[
                VERDICT_COLORS["malicious"],
                VERDICT_COLORS["benign"],
                VERDICT_COLORS["unknown"],
            ],
            width=0.6,
        )
        ax.set_ylabel("Completed packages")
        ax.text(
            0.02,
            0.96,
            str(accuracy_summary["message"]),
            transform=ax.transAxes,
            ha="left",
            va="top",
            fontsize=8,
            bbox={"facecolor": "#F6F6F6", "edgecolor": "#D0D0D0", "boxstyle": "round,pad=0.3"},
        )
        return

    mode = str(accuracy_summary.get("mode", "binary"))
    if mode == "positive_only":
        recall_value = float(accuracy_summary["positive_recall"])
        bars = {
            "Detected malicious": int(accuracy_summary["detected_positive"]),
            "Missed malicious": int(accuracy_summary["missed_positive"]),
        }
        ax.bar(
            list(bars.keys()),
            list(bars.values()),
            color=[VERDICT_COLORS["malicious"], VERDICT_COLORS["unknown"]],
            width=0.6,
        )
        ax.set_ylabel("Labeled malicious packages")
        ax.text(
            0.02,
            0.96,
            (
                f"{accuracy_summary['message']}\n"
                f"Evaluated positives={accuracy_summary['evaluated_packages']} | "
                f"Malicious recall={recall_value:.1%}\n"
                f"Unknown={accuracy_summary['unknown_predictions']} "
                f"Benign={accuracy_summary['benign_predictions']}"
            ),
            transform=ax.transAxes,
            ha="left",
            va="top",
            fontsize=8,
            bbox={"facecolor": "#F6F6F6", "edgecolor": "#D0D0D0", "boxstyle": "round,pad=0.3"},
        )
        return
    if mode == "negative_only":
        specificity_value = float(accuracy_summary["negative_recall"])
        bars = {
            "Detected benign": int(accuracy_summary["detected_benign"]),
            "Missed benign": int(accuracy_summary["missed_benign"]),
        }
        ax.bar(
            list(bars.keys()),
            list(bars.values()),
            color=[VERDICT_COLORS["benign"], VERDICT_COLORS["unknown"]],
            width=0.6,
        )
        ax.set_ylabel("Labeled benign packages")
        ax.text(
            0.02,
            0.96,
            (
                f"{accuracy_summary['message']}\n"
                f"Evaluated negatives={accuracy_summary['evaluated_packages']} | "
                f"Benign recall={specificity_value:.1%}\n"
                f"Unknown={accuracy_summary['unknown_predictions']} "
                f"Malicious={accuracy_summary['malicious_predictions']}"
            ),
            transform=ax.transAxes,
            ha="left",
            va="top",
            fontsize=8,
            bbox={"facecolor": "#F6F6F6", "edgecolor": "#D0D0D0", "boxstyle": "round,pad=0.3"},
        )
        return

    metrics = {
        "Accuracy": float(accuracy_summary["accuracy"]),
        "Precision": float(accuracy_summary["precision"]),
        "Recall": float(accuracy_summary["recall"]),
        "F1": float(accuracy_summary["f1"]),
    }
    ax.bar(
        list(metrics.keys()),
        list(metrics.values()),
        color=[OKABE_ITO_LIST[0], OKABE_ITO_LIST[1], OKABE_ITO_LIST[2], OKABE_ITO_LIST[3]],
        width=0.6,
    )
    ax.set_ylim(0, 1.0)
    ax.yaxis.set_major_formatter(PercentFormatter(xmax=1.0))
    ax.set_ylabel("Score")
    ax.text(
        0.02,
        0.96,
        (
            f"n={accuracy_summary['evaluated_packages']} | "
            f"TP={accuracy_summary['tp']} TN={accuracy_summary['tn']} "
            f"FP={accuracy_summary['fp']} FN={accuracy_summary['fn']}\n"
            f"Unknown predictions={accuracy_summary['unknown_predictions']}"
        ),
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=8,
        bbox={"facecolor": "#F6F6F6", "edgecolor": "#D0D0D0", "boxstyle": "round,pad=0.3"},
    )


def render_token_allocation_panel(ax: plt.Axes, metrics_df: pd.DataFrame) -> None:
    ax.set_title("Token allocation by cohort", loc="left", fontsize=10, fontweight="bold")
    if metrics_df.empty:
        ax.text(0.5, 0.5, "No token metrics available", ha="center", va="center")
        ax.set_axis_off()
        return

    cohort_df = (
        metrics_df.groupby("cohort")[["prompt_tokens", "completion_tokens"]]
        .sum()
        .reindex(["p0-33", "p0-66", "p0-100"], fill_value=0)
    )
    x_positions = list(range(len(cohort_df.index)))
    ax.bar(
        x_positions,
        cohort_df["prompt_tokens"].tolist(),
        color=OKABE_ITO_LIST[0],
        label="Prompt tokens",
        width=0.55,
    )
    ax.bar(
        x_positions,
        cohort_df["completion_tokens"].tolist(),
        bottom=cohort_df["prompt_tokens"].tolist(),
        color=OKABE_ITO_LIST[4],
        label="Completion tokens",
        width=0.55,
    )
    ax.set_xticks(x_positions, cohort_df.index.tolist())
    ax.set_ylabel("Tokens")
    ax.legend(frameon=False, fontsize=7, loc="upper right")
    for idx, total in enumerate((cohort_df["prompt_tokens"] + cohort_df["completion_tokens"]).tolist()):
        ax.text(idx, total + max(total * 0.01, 1000), f"{int(total):,}", ha="center", fontsize=7)


def render_token_distribution_panel(ax: plt.Axes, metrics_df: pd.DataFrame) -> None:
    ax.set_title("Token distribution per package", loc="left", fontsize=10, fontweight="bold")
    if metrics_df.empty:
        ax.text(0.5, 0.5, "No token metrics available", ha="center", va="center")
        ax.set_axis_off()
        return

    cohorts = [cohort for cohort in ["p0-33", "p0-66", "p0-100"] if cohort in set(metrics_df["cohort"])]
    data = [metrics_df.loc[metrics_df["cohort"] == cohort, "total_tokens"].tolist() for cohort in cohorts]
    if not any(data):
        ax.text(0.5, 0.5, "No completed packages with token data", ha="center", va="center")
        ax.set_axis_off()
        return
    box = ax.boxplot(data, patch_artist=True, tick_labels=cohorts, showfliers=False)
    for patch, cohort in zip(box["boxes"], cohorts):
        patch.set_facecolor(COHORT_COLORS.get(cohort, COHORT_COLORS["unknown"]))
        patch.set_alpha(0.75)
    ax.set_ylabel("Total tokens per package")
    for idx, cohort in enumerate(cohorts, start=1):
        median_value = metrics_df.loc[metrics_df["cohort"] == cohort, "total_tokens"].median()
        ax.text(idx, median_value, f"{int(median_value):,}", ha="center", va="bottom", fontsize=7)


def render_codeql_yield_panel(ax: plt.Axes, file_df: pd.DataFrame) -> None:
    ax.set_title("CodeQL effective hit rate", loc="left", fontsize=10, fontweight="bold")
    if file_df.empty:
        ax.text(0.5, 0.5, "No file-level results available", ha="center", va="center")
        ax.set_axis_off()
        return

    work_df = file_df.copy()
    work_df["risk"] = work_df["final_label_norm"].isin({"malicious", "suspicious"})
    yield_df = (
        work_df.groupby("source")
        .agg(total_files=("run_id", "size"), risky_files=("risk", "sum"))
        .reindex(["Context-added", "CodeQL-hit"], fill_value=0)
    )
    yield_df["yield_rate"] = yield_df["risky_files"] / yield_df["total_files"].replace(0, 1)
    ax.bar(
        yield_df.index.tolist(),
        yield_df["yield_rate"].tolist(),
        color=[OKABE_ITO_LIST[1], OKABE_ITO_LIST[0]],
        width=0.55,
    )
    ax.set_ylim(0, 1.0)
    ax.yaxis.set_major_formatter(PercentFormatter(xmax=1.0))
    ax.set_ylabel("High-risk yield")
    for idx, (_, row) in enumerate(yield_df.iterrows()):
        ax.text(
            idx,
            min(row["yield_rate"] + 0.03, 0.98),
            f"{int(row['risky_files'])}/{int(row['total_files'])}",
            ha="center",
            fontsize=7,
        )


def render_codeql_contribution_panel(ax: plt.Axes, file_df: pd.DataFrame) -> None:
    ax.set_title("CodeQL contribution to risky packages", loc="left", fontsize=10, fontweight="bold")
    if file_df.empty:
        ax.text(0.5, 0.5, "No file-level results available", ha="center", va="center")
        ax.set_axis_off()
        return

    work_df = file_df.copy()
    work_df["risk"] = work_df["final_label_norm"].isin({"malicious", "suspicious"})
    contribution_df = work_df.groupby("run_id").apply(
        lambda group: pd.Series(
            {
                "any_risky": bool(group["risk"].any()),
                "any_codeql_risky": bool(((group["from_codeql"]) & (group["risk"])).any()),
            }
        )
    )
    counts = {
        "CodeQL contributed": int(
            ((contribution_df["any_risky"]) & (contribution_df["any_codeql_risky"])).sum()
        ),
        "Context only": int(
            ((contribution_df["any_risky"]) & (~contribution_df["any_codeql_risky"])).sum()
        ),
        "No risky files": int((~contribution_df["any_risky"]).sum()),
    }
    ax.bar(
        list(counts.keys()),
        list(counts.values()),
        color=[OKABE_ITO_LIST[0], OKABE_ITO_LIST[1], "#B3B3B3"],
        width=0.55,
    )
    ax.set_ylabel("Packages")
    for idx, value in enumerate(counts.values()):
        ax.text(idx, value + max(value * 0.02, 2), str(value), ha="center", fontsize=7)


def render_top_token_panel(ax: plt.Axes, metrics_df: pd.DataFrame) -> None:
    ax.set_title("Top token-consuming packages", loc="left", fontsize=10, fontweight="bold")
    if metrics_df.empty:
        ax.text(0.5, 0.5, "No token metrics available", ha="center", va="center")
        ax.set_axis_off()
        return

    top_df = (
        metrics_df.sort_values(by=["total_tokens", "latency_ms"], ascending=[False, False])
        .head(8)
        .sort_values(by=["total_tokens", "latency_ms"], ascending=[True, True])
    )
    labels = [shorten(str(name), width=22, placeholder="...") for name in top_df["package_name"]]
    colors = [COHORT_COLORS.get(cohort, COHORT_COLORS["unknown"]) for cohort in top_df["cohort"]]
    ax.barh(labels, top_df["total_tokens"], color=colors)
    ax.set_xlabel("Total tokens")
    for idx, (_, row) in enumerate(top_df.iterrows()):
        ax.text(
            row["total_tokens"] + max(row["total_tokens"] * 0.01, 500),
            idx,
            f"{int(row['latency_ms'] / 1000)}s",
            va="center",
            fontsize=7,
        )
    cohort_handles = [
        plt.Line2D([0], [0], color=color, lw=4, label=cohort)
        for cohort, color in COHORT_COLORS.items()
        if cohort in set(top_df["cohort"])
    ]
    ax.legend(handles=cohort_handles, frameon=False, fontsize=7, loc="lower right")


if __name__ == "__main__":
    main()
