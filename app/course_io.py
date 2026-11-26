"""Local course dataset handling and post-run evaluation; never passed to model."""
from __future__ import annotations
import json
from pathlib import Path
from pydantic import ValidationError
from app.models import DetectionInput
from app.rag import load_jsonl
from app.service_types import MAX_BATCH

MAX_KNOWLEDGE_BYTES = 60 * 1024 * 1024
MAX_TEST_BYTES = 48 * 1024 * 1024


def read_local_file(directory: Path, name: str, limit: int) -> bytes:
    """Read exactly the known filename inside the configured dataset directory."""
    if name not in ("knowledge.jsonl", "test.jsonl"):
        raise ValueError("本地数据仅允许读取 knowledge.jsonl / test.jsonl")
    path = directory / name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"未找到常规文件 {path}；请先放入 dataset/ 目录")
    if path.stat().st_size > limit:
        raise ValueError(f"{name} 文件超过大小限制")
    with path.open('rb') as handle:
        content = handle.read(limit+1)
    if len(content) > limit:
        raise ValueError(f"{name} 文件超过大小限制")
    return content


def parse_test_rows(raw: bytes) -> list[DetectionInput]:
    if len(raw) > MAX_TEST_BYTES:
        raise ValueError("test.jsonl 超过 48MB")
    rows = load_jsonl(raw)
    if not rows or len(rows) > MAX_BATCH:
        raise ValueError(f"测试样本数必须为 1～{MAX_BATCH}")
    items = []
    for index, row in enumerate(rows, 1):
        try:
            items.append(DetectionInput.model_validate(row))
        except ValidationError as exc:
            raise ValueError(f"第 {index} 行输入无效：{exc.errors()[0]['msg']}") from exc
    return items


def output_rows(rows: list[dict]) -> list[dict]:
    result = []
    for row in rows:
        if row['status'] != 'completed' or not row.get('report'):
            continue
        report = row['report']
        idx = report['idx']
        # Course evaluator requires integer idx; preserve the original type in JSON.
        result.append({'idx':idx, 'prediction':report['prediction']})
    return result


def grade_result(truth: list[dict], predictions: list[dict]) -> dict:
    from app.scoring import evaluate
    data = evaluate(truth, predictions)
    data['complete'] = data['predictions'] == len(truth) and data['evaluated_pairs'] == data['pairs']
    data['grade_is_provisional'] = not data['complete']
    return data


def atomic_json(path: Path, payload) -> None:
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    temp.replace(path)


def atomic_jsonl(path: Path, rows: list[dict]) -> None:
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(''.join(json.dumps(x, ensure_ascii=False) + '\n' for x in rows), encoding='utf-8')
    temp.replace(path)
