#!/usr/bin/env python3
"""Import the supplied course dataset.zip (historical cases only; never test labels)."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.dataset_adapter import read_dataset_archive
from app.rag import HistoricalKB, load_jsonl
from app.models import DetectionInput


def main() -> None:
    parser = argparse.ArgumentParser(description='Validate class dataset and import its historical CVE cases')
    parser.add_argument('archive', type=Path)
    parser.add_argument('--out', type=Path, default=Path('runtime/historical_cases.json'))
    parser.add_argument('--validate-only', action='store_true')
    args = parser.parse_args()
    data = args.archive.read_bytes()
    history = read_dataset_archive(data, 'knowledge.jsonl')
    test = load_jsonl(read_dataset_archive(data, 'test.jsonl'))
    if len(test) != 300:
        print(f'警告：实际测试样本为 {len(test)} 条，非预期 300 条')
    if len(test) % 2:
        parser.error('测试集记录数必须为偶数')
    for i, record in enumerate(test, 1):
        DetectionInput.model_validate(record)
    for i in range(0,len(test),2):
        if {test[i]['target'],test[i+1]['target']} != {0,1}:
            parser.error(f'第 {i//2+1} 个测试配对标签无效')
    if args.validate_only:
        from app.dataset_adapter import build_course_cases
        rows = load_jsonl(history)
        _, audit = build_course_cases(rows)
        print(json.dumps({'test_samples':len(test),'test_pairs':len(test)//2,
            'knowledge_rows':len(rows),'valid_history_pairs':audit.accepted_pairs,
            'rejected_history_pairs':audit.rejected_pairs,'bad_pair_lines':audit.rejected_offsets},ensure_ascii=False,indent=2))
    else:
        kb = HistoricalKB(args.out)
        count = kb.import_jsonl(history)
        print(json.dumps({'test_samples_validated':len(test),'knowledge_indexed_pairs':count,
                          **kb.stats()['import_audit']},ensure_ascii=False,indent=2))
        print('提示：test.jsonl 未被导入知识库，未向模型提供任何 target。')

if __name__=='__main__':
    main()
