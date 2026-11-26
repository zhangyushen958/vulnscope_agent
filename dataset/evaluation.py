#!/usr/bin/env python3
"""按原始测试集的相邻记录配对，通过 idx 匹配预测并统计 P-C/P-V/P-B/P-R。

用法（仅依赖 Python 3 标准库）：
    python dataset/evaluation.py
    python dataset/evaluation.py --result student_result.jsonl
    python dataset/evaluation.py --dataset test.jsonl --result result.jsonl

测试集记录至少包含整数 idx 和整数 target（0/1），结果记录至少包含
整数 idx 和整数 prediction（0/1）。额外字段不参与评分，空行忽略。
每个相邻记录对必须包含一个 target=1 的漏洞版和一个 target=0 的修复版。
结果顺序任意，可只包含部分测试集 idx，但不能包含未知 idx。
仅统计两个样本都有预测的原始配对；缺少任意一方预测的组跳过。
结果为空或没有完整配对时，四类组数均为 0。
测试集中完全相同的重复记录保留其配对位置，并复用对应 idx 的预测。
结果中重复 idx 的 prediction 必须一致，否则报错，避免覆盖冲突结果。
"""

import argparse
import json
from pathlib import Path


def read_jsonl(path):
    """逐条读取 JSON 对象，保留行号以便定位格式错误。"""
    with path.open("r", encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            location = f"{path}:{line_number}"
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{location}: JSON 格式错误：{exc.msg}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"{location}: 每条记录必须是 JSON 对象")
            yield location, record


def validate_record(record, label_field, location):
    """严格校验整数类型，避免把布尔值、浮点数或字符串当作标签。"""
    for field in ("idx", label_field):
        if field not in record:
            raise ValueError(f"{location}: 缺少字段 {field}")
        if type(record[field]) is not int:
            raise ValueError(f"{location}: {field} 必须是整数")
    if record[label_field] not in (0, 1):
        raise ValueError(f"{location}: {label_field} 必须为 0 或 1")


def load_dataset(path):
    """保留测试集顺序；重复 idx 仅允许对应完全相同的样本。"""
    samples = []
    seen = {}
    for location, record in read_jsonl(path):
        validate_record(record, "target", location)
        idx = record["idx"]
        if idx in seen and seen[idx] != record:
            raise ValueError(f"{location}: 测试集 idx={idx} 对应不同样本，无法唯一匹配")
        seen[idx] = record
        samples.append(record)

    if not samples:
        raise ValueError(f"{path}: 测试集为空")
    if len(samples) % 2:
        raise ValueError(f"{path}: 测试集有 {len(samples)} 条记录，必须为偶数才能配对")
    for offset in range(0, len(samples), 2):
        first, second = samples[offset:offset + 2]
        if {first["target"], second["target"]} != {0, 1}:
            raise ValueError(
                f"{path}: 第 {offset // 2 + 1} 对（idx={first['idx']}, "
                f"{second['idx']}）必须包含一个 target=1 和一个 target=0"
            )
    return samples


def load_predictions(path):
    """按 idx 索引预测；相同预测可重复，冲突预测不能覆盖。"""
    predictions = {}
    for location, record in read_jsonl(path):
        validate_record(record, "prediction", location)
        idx, prediction = record["idx"], record["prediction"]
        if idx in predictions and predictions[idx] != prediction:
            raise ValueError(f"{location}: idx={idx} 的重复 prediction 相互冲突")
        predictions[idx] = prediction
    return predictions


def preview_ids(indices):
    ordered = sorted(indices)
    return ", ".join(map(str, ordered[:10])) + (", ..." if len(ordered) > 10 else "")


def evaluate(dataset_path, result_path):
    """返回样本数、唯一 idx 数及四类组数；仅统计预测齐全的原始配对。"""
    samples = load_dataset(Path(dataset_path))
    predictions = load_predictions(Path(result_path))
    expected_ids = {sample["idx"] for sample in samples}
    unknown = predictions.keys() - expected_ids
    if unknown:
        raise ValueError(f"包含 {len(unknown)} 个未知 idx：{preview_ids(unknown)}")

    categories = {(1, 0): "P-C", (1, 1): "P-V", (0, 0): "P-B", (0, 1): "P-R"}
    counts = {name: 0 for name in categories.values()}
    for offset in range(0, len(samples), 2):
        first, second = samples[offset:offset + 2]
        if first["idx"] not in predictions or second["idx"] not in predictions:
            continue
        # 相邻关系由测试集决定，漏洞版/修复版身份由 target 决定。
        vulnerable, fixed = (first, second) if first["target"] == 1 else (second, first)
        predicted_pair = (predictions[vulnerable["idx"]], predictions[fixed["idx"]])
        counts[categories[predicted_pair]] += 1
    return len(samples), len(expected_ids), counts


def main():
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--dataset", type=Path, default=script_dir / "test.jsonl",
        help="测试集 JSONL 路径（默认：脚本目录下的 test.jsonl）",
    )
    parser.add_argument(
        "--result", type=Path, default=script_dir.parent / "result.jsonl",
        help="检测结果 JSONL 路径（默认：脚本目录上一级的 result.jsonl）",
    )
    args = parser.parse_args()
    try:
        sample_count, unique_count, counts = evaluate(args.dataset, args.result)
    except (OSError, UnicodeError, ValueError) as exc:
        parser.exit(2, f"评估失败：{exc}\n")

    print(f"测试集样本数：{sample_count}")
    print(f"配对组数：{sample_count // 2}")
    evaluated_pairs = sum(counts.values())
    print(f"实际评估组数：{evaluated_pairs}")
    print(f"跳过组数（预测不完整）：{sample_count // 2 - evaluated_pairs}")
    if unique_count != sample_count:
        print(f"唯一 idx 数：{unique_count}（重复样本在各自配对中复用预测）")
    for name, description in (
        ("P-C", "成对正确"), ("P-V", "成对漏洞"),
        ("P-B", "成对良性"), ("P-R", "成对错误"),
    ):
        print(f"{name}（{description}组数）：{counts[name]}")


if __name__ == "__main__":
    main()
