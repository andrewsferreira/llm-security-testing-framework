"""JSON serialization helpers and a path-traversal-safe output resolver.

Reporters must only ever write inside the configured output directory. `resolve_output_path`
is the single choke point that enforces that, so a malformed campaign id or filename can never
escape it (e.g. via "../../etc/passwd").
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel


def to_jsonable(value: Any) -> Any:
    """Convert pydantic models (and nested containers of them) into plain JSON-safe data."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {k: to_jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [to_jsonable(v) for v in value]
    return value


def resolve_output_path(output_dir: Path, filename: str) -> Path:
    """Resolve `filename` under `output_dir`, refusing to write outside of it."""
    base = output_dir.resolve()
    candidate = (base / filename).resolve()
    if candidate != base and base not in candidate.parents:
        raise ValueError(f"Refusing to write outside output directory: {filename!r}")
    return candidate


def write_json(path: Path, data: Any, *, indent: int = 2) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_jsonable(data), indent=indent, ensure_ascii=False) + "\n")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())
