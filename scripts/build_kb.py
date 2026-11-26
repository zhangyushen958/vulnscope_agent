#!/usr/bin/env python3
"""Import only the course-provided historical vulnerability-case JSONL."""
from __future__ import annotations
import argparse
from pathlib import Path
from app.rag import HistoricalKB


def main() -> None:
    parser = argparse.ArgumentParser(description="Build local historical-case RAG (course dataset only)")
    parser.add_argument("history", type=Path, help="Course-provided historical CVE paired .jsonl")
    parser.add_argument("--out", type=Path, default=Path("runtime/historical_cases.json"))
    args = parser.parse_args()
    if args.history.suffix.lower() != ".jsonl":
        parser.error("history must have .jsonl extension")
    kb = HistoricalKB(args.out)
    count = kb.import_jsonl(args.history.read_bytes())
    print(f"Built RAG with {count} historical paired cases -> {args.out}")


if __name__ == "__main__":
    main()
