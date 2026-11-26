import io
import json
import zipfile
from pathlib import Path
import pytest
from app.rag import HistoricalKB


@pytest.fixture
def paired_rows():
    return [
        {"cve_desc":"Historical case about input length handling", "commit_message":"Improve input limits", "cwe":"CWE-TEST-1", "project":"training-example",
         "file_name":"example.c", "vulnerable_func":"int hist(char *p, int n) { char tmp[3]; for (int i=0;i<n;i++) tmp[i]=p[i]; return 0; }",
         "fixed_func":"int hist(char *p, int n) { char tmp[3]; for (int i=0;i<n && i<3;i++) tmp[i]=p[i]; return 0; }"},
        {"cve_desc":"Historical case about checking pointer arguments", "commit_message":"Validate arguments", "cwe":"CWE-TEST-2", "project":"training-example",
         "file_name":"other.c", "vulnerable_func":"int other(char *p) { return p[0]; }",
         "fixed_func":"int other(char *p) { if (!p) return -1; return p[0]; }"},
    ]


@pytest.fixture
def kb(tmp_path, paired_rows):
    base = HistoricalKB(tmp_path / "kb.json")
    base.import_jsonl(("\n".join(json.dumps(r) for r in paired_rows)).encode())
    return base


@pytest.fixture
def repository(tmp_path):
    src = tmp_path / "snapshot"
    src.mkdir()
    (src / "module.c").write_text("int helper(int n) { return n + 1; }\nint process(int n) { return helper(n); }\n", encoding="utf-8")
    (src / "globals.h").write_text("#define LENGTH 24\nextern int shared_count;\n", encoding="utf-8")
    (src / "readme.txt").write_text("secret non-code", encoding="utf-8")
    return src


def make_zip(files):
    buff = io.BytesIO()
    with zipfile.ZipFile(buff,'w') as z:
        for name,content in files.items():
            z.writestr(name,content)
    return buff.getvalue()
