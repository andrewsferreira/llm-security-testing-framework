from pathlib import Path

import pytest
from pydantic import BaseModel

from llmsec.utils.serialization import read_json, resolve_output_path, to_jsonable, write_json


class _Sample(BaseModel):
    name: str
    value: int


def test_to_jsonable_converts_pydantic_model() -> None:
    assert to_jsonable(_Sample(name="a", value=1)) == {"name": "a", "value": 1}


def test_to_jsonable_recurses_into_containers() -> None:
    data = {"items": [_Sample(name="a", value=1), _Sample(name="b", value=2)]}
    assert to_jsonable(data) == {
        "items": [{"name": "a", "value": 1}, {"name": "b", "value": 2}]
    }


def test_resolve_output_path_allows_nested_files(tmp_path: Path) -> None:
    resolved = resolve_output_path(tmp_path, "run-001/results.json")
    assert resolved == (tmp_path / "run-001/results.json").resolve()


def test_resolve_output_path_rejects_traversal(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="outside output directory"):
        resolve_output_path(tmp_path, "../../etc/passwd")


def test_write_and_read_json_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "out" / "data.json"
    write_json(path, {"a": 1, "nested": _Sample(name="x", value=2)})
    assert read_json(path) == {"a": 1, "nested": {"name": "x", "value": 2}}
