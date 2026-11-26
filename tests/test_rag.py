import json
import pytest
from app.rag import HistoricalKB, normalize_cases, load_jsonl


def test_paired_import_persist_and_search(tmp_path, paired_rows):
    path=tmp_path/'kb.json'
    kb=HistoricalKB(path)
    assert kb.stats()['case_count']==0
    assert kb.import_jsonl(('\n'.join(json.dumps(r) for r in paired_rows)).encode())==2
    assert path.exists()
    assert kb.stats()['cwe_types']==2
    result=kb.search('int hist(char *p, int n) { for (int i=0;i<n;i++) p[i]=0; }')
    assert result and result[0]['case_id'].startswith('H-')
    assert result[0]['score']>=0
    assert len(HistoricalKB(path).search('hist copy length'))>0


def test_exact_overlap_exclusion(kb, paired_rows):
    assert kb.search(paired_rows[0]['vulnerable_func'], top_k=5)
    assert all(x['file_name']!='example.c' for x in kb.search(paired_rows[0]['vulnerable_func'], top_k=5))


def test_exclude_same_commit(tmp_path):
    row={'vulnerable_func':'int a(int x) { return x / x; }', 'fixed_func':'int a(int x) { return x != 0 ? x / x : 0; }', 'commit_url':'https://example.invalid/fix'}
    kb=HistoricalKB(tmp_path/'x.json')
    kb.import_jsonl(json.dumps(row).encode())
    assert kb.search('int a(int n) { return n/n; }',exclude_commit_url=row['commit_url'])==[]


def test_two_row_grouping():
    rows=[{'pair_id':'CASE-X','target':1,'func':'int a(int x) { return x*2; }','cwe':'CWE-1'},
          {'pair_id':'CASE-X','target':0,'func':'int a(int x) { return x>0?x*2:0; }'}]
    assert len(normalize_cases(rows))==1
    assert 'target' not in normalize_cases(rows)[0]


def test_reject_unpaired():
    with pytest.raises(ValueError,match='缺少配对'):
        normalize_cases([{'pair_id':'X','target':1,'func':'int test(int x) { return x; }'}])


def test_reject_ambiguous():
    rows=[{'pair_id':'X','target':1,'func':'int test(int x) { return x; }'}]*2
    with pytest.raises(ValueError,match='重复'):
        normalize_cases(rows)


def test_reject_missing_pair_id():
    with pytest.raises(ValueError,match='pair_id'):
        normalize_cases([{'target':0,'func':'int z(int x) { return x; }'}])


def test_reject_truncated_file():
    with pytest.raises(ValueError,match='JSON'):
        load_jsonl(b'{wrong json}')


def test_reject_duplicates(tmp_path):
    row={'vulnerable_func':'int a(int x) { return x + 1; }','fixed_func':'int a(int x) { return x + 2; }'}
    kb=HistoricalKB(tmp_path/'k.json')
    with pytest.raises(ValueError,match='重复'):
        kb.import_jsonl((json.dumps(row)+'\n'+json.dumps(row)).encode())
    assert not (tmp_path/'k.json').exists()


def test_import_failure_preserves_kb(kb, paired_rows):
    old=kb.stats()['case_count']
    with pytest.raises(ValueError):
        kb.import_jsonl(b'not json')
    assert kb.stats()['case_count']==old
