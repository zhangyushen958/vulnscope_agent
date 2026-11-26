"""Historical-case-only hybrid sparse-vector RAG: zero external knowledge sources.

The fitted vectorizers are derived strictly from the user-supplied CVE records.
No pretraining corpus, internet retrieval, or external security examples are used.
"""
from __future__ import annotations
import hashlib
import json
import re
import threading
from pathlib import Path
from typing import Any
from sklearn.feature_extraction.text import TfidfVectorizer
from app.dataset_adapter import build_course_cases, is_course_knowledge, normalize_missing
from sklearn.metrics.pairwise import cosine_similarity

MAX_CASES = 30000
MAX_CODE_CHARS = 20000
META = ("cve_desc", "commit_message", "cwe", "project", "file_name", "commit_url")


def _get(data: dict, *keys: str) -> Any:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _target(value: Any) -> int | None:
    if type(value) is bool:
        return None
    if value in (1, "1"):
        return 1
    if value in (0, "0"):
        return 0
    return None


def _text_code(obj: Any) -> str:
    if isinstance(obj, str):
        return obj[:MAX_CODE_CHARS]
    if isinstance(obj, dict):
        return _get(obj, "func", "code", "function", "content")[:MAX_CODE_CHARS]
    return ""


def normalize_cases(rows: list[dict]) -> list[dict]:
    """Accept pre-paired records or two-row historical (target 1/0) records.

    No inferred pairs based on adjacency. Ambiguous/incomplete pairs are rejected.
    """
    cases: list[dict] = []
    groups: dict[str, dict[int, dict]] = {}
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"第 {i+1} 行不是 JSON 对象")
        vulnerable = _text_code(_get(row, "vulnerable_func", "vul_func", "before_func", "func_before") or row.get("vulnerable") or row.get("before"))
        fixed = _text_code(_get(row, "fixed_func", "fix_func", "patched_func", "after_func", "func_after") or row.get("fixed") or row.get("after"))
        # Additional common prepaired keys in private class datasets.
        if not (vulnerable and fixed) and isinstance(row.get("functions"), dict):
            fs = row["functions"]
            vulnerable = _text_code(fs.get("vulnerable") or fs.get("1"))
            fixed = _text_code(fs.get("fixed") or fs.get("0"))
        if vulnerable and fixed:
            case = {k: normalize_missing(row.get(k))[:5000] for k in META}
            case.update(vulnerable_func=vulnerable, fixed_func=fixed)
            cases.append(case)
            continue
        label = _target(row.get("target", row.get("label")))
        if label is None or not _get(row, "func", "code"):
            raise ValueError(f"第 {i+1} 行不是可识别的成对历史案例：缺少漏洞/修复函数或 target 和 func")
        group_id = _get(row, "pair_id", "case_id", "cve_id")
        if not group_id:
            # A commit may fix many functions; the function/file identity is mandatory.
            commit = _get(row, "commit_url")
            identity = _get(row, "function_name", "func_name") or _get(row, "file_name")
            if not (commit and identity):
                raise ValueError(f"第 {i+1} 行缺少 pair_id（或 commit_url + function_name/file_name），不能安全配对")
            group_id = commit + "::" + identity
        grouped = groups.setdefault(group_id, {})
        if label in grouped:
            raise ValueError(f"同一历史案例 {group_id!r} 存在重复的 target={label}，拒绝模糊配对")
        grouped[label] = row
    for key, pair in groups.items():
        if set(pair) != {0, 1}:
            raise ValueError(f"历史案例 {key!r} 缺少配对函数")
        v, f = pair[1], pair[0]
        case = {k: normalize_missing(v.get(k) or f.get(k))[:5000] for k in META}
        case.update(vulnerable_func=_get(v, "func", "code")[:MAX_CODE_CHARS], fixed_func=_get(f, "func", "code")[:MAX_CODE_CHARS])
        cases.append(case)
    if not cases:
        raise ValueError("未发现有效案例")
    if len(cases) > MAX_CASES:
        raise ValueError(f"案例数超出限制（{MAX_CASES}）")
    for case in cases:
        if len(case["vulnerable_func"]) < 10 or len(case["fixed_func"]) < 10:
            raise ValueError("案例函数过短或缺失")
        # Do not persist input-provided labels, alternative versions or arbitrary fields.
        case["case_id"] = "H-" + hashlib.sha256((case["vulnerable_func"] + "\x00" + case["fixed_func"]).encode()).hexdigest()[:12]
    ids = [x["case_id"] for x in cases]
    if len(set(ids)) != len(ids):
        raise ValueError("包含重复的历史案例")
    return cases


def load_jsonl(data: bytes) -> list[dict]:
    if len(data) > 60 * 1024 * 1024:
        raise ValueError("JSONL 不得大于 60MB")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("文件必须是 UTF-8 编码") from exc
    rows: list[dict] = []
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"第 {i} 行 JSON 格式错误：{exc.msg}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"第 {i} 行必须是 JSON 对象")
        rows.append(value)
        if len(rows) > 2 * MAX_CASES:
            raise ValueError("数据量超过限制")
    return rows


class HistoricalKB:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self.cases: list[dict] = []
        self.audit_path = path.with_suffix(".audit.json")
        self.import_audit: dict = json.loads(self.audit_path.read_text(encoding="utf-8")) if self.audit_path.exists() else {}
        self.vectorizers = None
        self.matrices = None
        if path.exists():
            self._set_cases(json.loads(path.read_text(encoding="utf-8")))

    @staticmethod
    def _docs(cases: list[dict]) -> tuple[list[str], list[str]]:
        codes = [x["vulnerable_func"][:4000] + "\n" + x["fixed_func"][:4000] for x in cases]
        descriptions = [" ".join(x[k] for k in ("cve_desc", "commit_message", "cwe", "project", "file_name")) + "\n" + codes[i][:1500] for i, x in enumerate(cases)]
        return codes, descriptions

    def _set_cases(self, cases: list[dict]) -> None:
        with self._lock:
            self.cases = cases
            if not cases:
                self.vectorizers = self.matrices = None
                return
            codes, descriptions = self._docs(cases)
            code_vec = TfidfVectorizer(analyzer="word", token_pattern=r"(?u)\b[A-Za-z_][A-Za-z_0-9]*\b", ngram_range=(1, 2), min_df=1, sublinear_tf=True, max_features=30000)
            text_vec = TfidfVectorizer(analyzer="word", token_pattern=r"(?u)\b\w+\b", ngram_range=(1, 2), min_df=1, max_features=12000)
            self.matrices = (code_vec.fit_transform(codes), text_vec.fit_transform(descriptions))
            self.vectorizers = (code_vec, text_vec)

    def import_jsonl(self, data: bytes) -> int:
        rows = load_jsonl(data)
        if is_course_knowledge(rows):
            prepaired, audit = build_course_cases(rows)
            # Course export contains repeat function pairs; dedupe by identical
            # code pair (not by commit URL or ambiguous position).
            unique = {}
            for pair in prepaired:
                key = hashlib.sha256((pair["vulnerable_func"] + "\x00" + pair["fixed_func"]).encode()).hexdigest()
                unique.setdefault(key, pair)
            cases = normalize_cases(list(unique.values()))
            audit_summary = {"source_rows": audit.source_rows, "accepted_pairs": audit.accepted_pairs,
                             "indexed_pairs": len(cases), "duplicate_pairs": len(prepaired)-len(cases),
                             "rejected_pairs": audit.rejected_pairs, "rejected_offsets": list(audit.rejected_offsets)}
        else:
            cases = normalize_cases(rows)
            audit_summary = {"source_rows": len(rows), "accepted_pairs": len(cases), "rejected_pairs": 0, "rejected_offsets": []}
        # Construct new vectors in memory before publishing; avoid ever reading a
        # previously existing temporary/placeholder knowledge file as a source.
        new_code = TfidfVectorizer(analyzer="word", token_pattern=r"(?u)\b[A-Za-z_][A-Za-z_0-9]*\b", ngram_range=(1, 2), min_df=1, sublinear_tf=True, max_features=30000)
        new_meta = TfidfVectorizer(analyzer="word", token_pattern=r"(?u)\b\w+\b", ngram_range=(1, 2),
                                   min_df=1, max_features=12000)
        codes, descriptions = self._docs(cases)
        new_matrices = (new_code.fit_transform(codes), new_meta.fit_transform(descriptions))
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temp = self.path.with_suffix(".tmp")
            temp.write_text(json.dumps(cases, ensure_ascii=False), encoding="utf-8")
            temp.replace(self.path)
            audit_temp = self.audit_path.with_suffix(".audit.tmp")
            audit_temp.write_text(json.dumps(audit_summary, ensure_ascii=False), encoding="utf-8")
            audit_temp.replace(self.audit_path)
            self.cases = cases
            self.import_audit = audit_summary
            self.vectorizers = (new_code, new_meta)
            self.matrices = new_matrices
        return len(cases)

    def clear(self) -> int:
        """Remove indexed cases only, preserving course input data and settings."""
        with self._lock:
            previous = len(self.cases)
            for file in (self.path, self.audit_path):
                if file.exists():
                    file.unlink()
            self.cases = []
            self.import_audit = {}
            self.vectorizers = None
            self.matrices = None
            return previous

    def stats(self) -> dict:
        with self._lock:
            return {"case_count": len(self.cases), "source": "user_uploaded_history_only", "indexed": bool(self.vectorizers),
                    "cwe_types": len({c["cwe"] for c in self.cases if c["cwe"]}),
                    "import_audit": self.import_audit}

    def search(self, query: str, top_k: int = 4, exclude_commit_url: str = "") -> list[dict]:
        with self._lock:
            if not self.vectorizers or not query.strip():
                return []
            code, text = self.vectorizers
            score_code = cosine_similarity(code.transform([query[:20000]]), self.matrices[0]).ravel()
            score_text = cosine_similarity(text.transform([query[:20000]]), self.matrices[1]).ravel()
            combined = .72 * score_code + .28 * score_text
            ranked = sorted(range(len(self.cases)), key=lambda i: float(combined[i]), reverse=True)
            output: list[dict] = []
            for i in ranked:
                item = self.cases[i]
                if exclude_commit_url and item.get("commit_url", "").rstrip("/") == exclude_commit_url.rstrip("/"):
                    continue
                if query.strip() in (item["vulnerable_func"].strip(), item["fixed_func"].strip()):
                    continue  # exact train-test overlap guard
                output.append({"case_id": item["case_id"], "score": round(float(combined[i]), 4),
                               "cwe": item["cwe"], "project": item["project"], "file_name": item["file_name"],
                               "cve_desc": item["cve_desc"][:1400], "commit_message": item["commit_message"][:700],
                               "vulnerable_func": item["vulnerable_func"][:2200], "fixed_func": item["fixed_func"][:2200]})
                if len(output) >= min(8, max(1, top_k)):
                    break
            return output
