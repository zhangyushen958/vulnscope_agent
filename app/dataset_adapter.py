"""Course dataset adapter. No labels from evaluation data enter model prompts.

Knowledge has *positional* proposed pairs, with some demonstrably inconsistent
adjacent records. We never pair records with different commits/CVEs.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ImportAudit:
    source_rows: int
    accepted_pairs: int
    rejected_pairs: int
    rejected_offsets: tuple[int, ...]


def normalize_missing(value: Any) -> str:
    if value is None or isinstance(value, str) and value.strip().lower() in {"none", "null", "nan", ""}:
        return ""
    if isinstance(value, list):
        return ", ".join(str(part) for part in value if part is not None)
    return str(value)


def is_course_knowledge(rows: list[dict]) -> bool:
    return bool(rows and isinstance(rows[0], dict) and
                {"func_hash", "commit_id", "cve", "target", "func"}.issubset(rows[0]))


def build_course_cases(rows: list[dict]) -> tuple[list[dict], ImportAudit]:
    if len(rows) % 2:
        raise ValueError("课程知识库记录必须是偶数；不能假定不完整记录的配对身份")
    cases = []
    rejected = []
    for i in range(0, len(rows), 2):
        v, f = rows[i:i + 2]
        if not (isinstance(v, dict) and isinstance(f, dict)):
            raise ValueError(f"第 {i + 1} 至 {i + 2} 行不是 JSON 对象")
        if type(v.get("target")) is not int or type(f.get("target")) is not int or (v["target"], f["target"]) != (1, 0):
            rejected.append(i + 1)
            continue
        # Reject mismatches rather than invent a pairing through adjacency.
        if not all(v.get(k) and v.get(k) == f.get(k) for k in ("commit_id", "commit_url", "cve")):
            rejected.append(i + 1)
            continue
        code_v, code_f = v.get("func"), f.get("func")
        if not isinstance(code_v, str) or not isinstance(code_f, str) or len(code_v.strip()) < 10 or len(code_f.strip()) < 10:
            rejected.append(i + 1)
            continue
        case = {key: normalize_missing(v.get(key) or f.get(key))[:5000]
                for key in ("cve_desc", "commit_message", "cwe", "project", "file_name", "commit_url")}
        case.update(vulnerable_func=code_v[:20000], fixed_func=code_f[:20000])
        cases.append(case)
    if not cases:
        raise ValueError("课程历史案例中没有通过配对校验的记录")
    return cases, ImportAudit(len(rows), len(cases), len(rejected), tuple(rejected))


def read_dataset_archive(archive: bytes, entry: str) -> bytes:
    """Read only the named course dataset entry from an untrusted zip (no extraction)."""
    import io
    import zipfile
    if entry not in {"knowledge.jsonl", "test.jsonl"}:
        raise ValueError("不允许读取其他归档条目")
    if len(archive) > 80 * 1024 * 1024:
        raise ValueError("ZIP 文件体积超过 80 MB")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            candidates = [x for x in z.infolist() if x.filename in (entry, "dataset/" + entry)]
            if len(candidates) != 1:
                raise ValueError(f"归档缺少唯一的 {entry} 条目")
            info = candidates[0]
            limit = 60 * 1024 * 1024 if entry == "knowledge.jsonl" else 48 * 1024 * 1024
            if info.is_dir() or info.file_size > limit:
                raise ValueError(f"{entry} 大小非法或超限")
            with z.open(info) as reader:
                raw = reader.read(limit + 1)
            if len(raw) > limit:
                raise ValueError(f"{entry} 实际解压体积超限")
            return raw
    except zipfile.BadZipFile as exc:
        raise ValueError("ZIP 文件损坏或格式不正确") from exc
