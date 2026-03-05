"""Shared helpers for project notebooks."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence


def find_project_root(start: Path | None = None) -> Path:
    """Find repository root by locating the pmmap package directory."""
    base = start or Path().resolve()
    for path in [base, *base.parents]:
        if (path / "pmmap").is_dir():
            return path
    raise RuntimeError("Could not find project root (pmmap directory).")


def init_notebook_paths(start: Path | None = None) -> tuple[Path, Path, Path]:
    """Prepare sys.path and return (ROOT, DATA_DIR, RUN_DIR)."""
    root = find_project_root(start=start)
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    data_dir = root / "data"
    run_dir = data_dir / "run" / "notebook"
    run_dir.mkdir(parents=True, exist_ok=True)

    print("Project root:", root)
    print("Run dir:", run_dir)
    return root, data_dir, run_dir


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    """Read JSON Lines file into a list of dictionaries."""
    records: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                records.append(rec)
    return records


def display_table(
    rows: Sequence[dict[str, Any]],
    columns: Sequence[tuple[str, str]],
    title: str,
    limit: int = 10,
) -> None:
    """Render a markdown table in Jupyter output."""
    from IPython.display import Markdown, display

    display(Markdown(f"### {title}"))
    if not rows:
        display(Markdown("_No data._"))
        return

    lines = ["| " + " | ".join(col[0] for col in columns) + " |"]
    lines.append("| " + " | ".join(["---"] * len(columns)) + " |")
    for row in list(rows)[:limit]:
        values = [str(row.get(col[1], "")) for col in columns]
        lines.append("| " + " | ".join(values) + " |")
    display(Markdown("\n".join(lines)))


def top_items(counter: dict[str, int], k: int = 10) -> list[dict[str, Any]]:
    """Convert a counter-like dict into sorted top-k rows."""
    items = sorted(counter.items(), key=lambda item: item[1], reverse=True)[:k]
    return [{"value": key, "count": value} for key, value in items]


def ensure_exists(path: str | Path, label: str) -> None:
    """Raise a clear file-not-found error for notebook users."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{label} not found: {p}")
