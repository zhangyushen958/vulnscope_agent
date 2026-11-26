#!/usr/bin/env python3
"""Evaluate using the supplied course evaluation.py's authoritative pairing rules.

Usage: python scripts/evaluate_pairs.py --truth dataset/test.jsonl --pred result.jsonl
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path


def evaluate(truth_rows: list[dict], pred_rows: list[dict], pair_key: str | None = None) -> dict:
    """Match the bundled course evaluator: adjacency, optionally incomplete predictions."""
    from collections import Counter
    seen = {}
    for row in truth_rows:
        idx, label = row.get("idx"), row.get("target")
        if type(idx) is not int or type(label) is not int or label not in (0, 1):
            raise ValueError("测试集 idx 和 target 必须是严格整数，target 只能为 0/1")
        if idx in seen and seen[idx] != row:
            raise ValueError(f"测试集 idx={idx} 对应不同记录")
        seen[idx] = row
    if not truth_rows or len(truth_rows) % 2:
        raise ValueError("测试集必须是非空、条目数为偶数的 JSONL")
    pred = {}
    for row in pred_rows:
        idx, label = row.get("idx"), row.get("prediction")
        if type(idx) is not int or type(label) is not int or label not in (0, 1):
            raise ValueError("预测 idx 和 prediction 必须是严格整数，prediction 只能为 0/1")
        if idx in pred and pred[idx] != label:
            raise ValueError(f"idx={idx} 的预测冲突")
        pred[idx] = label
    unknown = pred.keys() - seen.keys()
    if unknown:
        raise ValueError(f"包含未知 idx: {sorted(unknown)[:10]}")
    counts = Counter({"P-C": 0, "P-V": 0, "P-B": 0, "P-R": 0})
    for i in range(0, len(truth_rows), 2):
        one, two = truth_rows[i:i+2]
        if {one["target"], two["target"]} != {0, 1}:
            raise ValueError(f"第 {i//2+1} 对标签必须各包含一个 0 和 1")
        if one["idx"] not in pred or two["idx"] not in pred:
            continue
        v, f = (one, two) if one["target"] == 1 else (two, one)
        counts[{(1,0): "P-C", (1,1): "P-V", (0,0): "P-B", (0,1): "P-R"}[(pred[v["idx"]], pred[f["idx"]])]] += 1
    pc = counts["P-C"]
    grade = "A" if pc >= 30 else "B" if pc >= 25 else "C" if pc >= 20 else "D"
    penalty = counts["P-R"] > pc / 2
    if penalty:
        grade = {"A": "B", "B": "C", "C": "D", "D": "D"}[grade]
    return {"pairs": len(truth_rows)//2, "evaluated_pairs": sum(counts.values()),
            "predictions": len(pred), **counts, "penalty": penalty, "grade": grade,
            "pair_accuracy": round(pc / (len(truth_rows)//2), 4)}


def main():
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--truth", required=True, type=Path)
    parser.add_argument("--pred", required=True, type=Path)
    parser.add_argument("--pair-key", default=None, help="兼容旧调用；官方评测始终按相邻记录配对")
    args = parser.parse_args()
    def read(p):
        with p.open(encoding="utf-8-sig") as f:
            return [json.loads(t) for t in f if t.strip()]
    print(json.dumps(evaluate(read(args.truth), read(args.pred), args.pair_key), ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
