#!/usr/bin/env python3
"""OFFLINE evaluator. Truth labels are used ONLY here, never in agent inference.

Input test file: idx, commit_url, target(0/1), func and optional pair_id.
Predictions: idx, prediction. Pair by explicit --pair-key or uniquely shared
commit_url. Refuses ambiguous groups instead of inventing matching logic.
"""
from __future__ import annotations
import argparse
import json
from collections import defaultdict
from pathlib import Path
from app.rag import load_jsonl


def evaluate(truth_rows: list[dict], pred_rows: list[dict], pair_key: str | None = None) -> dict:
    truth = {}
    for x in truth_rows:
        idx = str(x["idx"])
        if idx in truth:
            raise ValueError(f"测试集含重复 idx: {idx}")
        target = x.get("target")
        if type(target) is bool or str(target) not in ("0", "1"):
            raise ValueError(f"测试样本 {idx} target 必须为 0 或 1")
        truth[idx] = x
    pred = {}
    for x in pred_rows:
        idx = str(x["idx"])
        if idx in pred:
            raise ValueError(f"预测包含重复 idx: {idx}")
        p = x.get("prediction")
        if type(p) is bool or str(p) not in ("0", "1"):
            raise ValueError(f"预测 {idx} 不是 0 或 1")
        pred[idx] = int(p)
    missing = set(truth) - set(pred)
    extra = set(pred) - set(truth)
    if missing or extra:
        raise ValueError(f"索引不完全匹配: 缺少 {sorted(missing)[:6]}, 多余 {sorted(extra)[:6]}")
    groups = defaultdict(dict)
    for idx, x in truth.items():
        if pair_key:
            key = x.get(pair_key)
        else:
            key = x.get("pair_id") or x.get("commit_url")
        if not key:
            raise ValueError(f"无法确定 idx={idx} 的配对键；请提供 --pair-key")
        label = int(x["target"])
        if label in groups[str(key)]:
            raise ValueError(f"配对键 {key!r} 下出现重复标签，可能同一提交修复多个函数；请提供唯一 pair_id")
        groups[str(key)][label] = pred[idx]
    tally = {"P-C": 0, "P-V": 0, "P-B": 0, "P-R": 0}
    for key, group in groups.items():
        if set(group) != {0, 1}:
            raise ValueError(f"配对 {key!r} 不完整（需要 target=1 和 target=0）")
        v, f = group[1], group[0]
        category = "P-C" if (v, f) == (1, 0) else "P-V" if (v, f) == (1, 1) else "P-B" if (v, f) == (0, 0) else "P-R"
        tally[category] += 1
    pc = tally["P-C"]
    grade = "A" if pc >= 30 else "B" if pc >= 25 else "C" if pc >= 20 else "D"
    penalty = tally["P-R"] > pc / 2
    if penalty:
        grade = {"A": "B", "B": "C", "C": "D", "D": "D"}[grade]
    return {"pairs": len(groups), "predictions": len(pred), **tally, "penalty": penalty, "grade": grade,
            "pair_accuracy": round(pc / len(groups), 4) if groups else 0}


def main():
    ap = argparse.ArgumentParser(description="Score P-C / P-V / P-B / P-R and letter grade")
    ap.add_argument("--truth", type=Path, required=True)
    ap.add_argument("--pred", type=Path, required=True)
    ap.add_argument("--pair-key", type=str, default=None)
    args = ap.parse_args()
    results = evaluate(load_jsonl(args.truth.read_bytes()), load_jsonl(args.pred.read_bytes()), args.pair_key)
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
