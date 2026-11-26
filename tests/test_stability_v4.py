import io
import json
import threading
import time
import zipfile
from pathlib import Path

import httpx
from app.agent import VulnerabilityAgent
from app.config import Settings
from app.llm import ModelTurn, OpenAICompatibleClient
from app.models import DetectionInput
from app.repository import extract_safe_source_zip
from app.service import DetectionService
from app.store import RunStore
from tests.test_agent import SAMPLE, VERDICT


def test_deepseek_explicitly_disables_thinking(tmp_path):
    seen = []
    def handle(req):
        seen.append(json.loads(req.content))
        return httpx.Response(200, json={"choices":[{"message":{"role":"assistant", "content": "{}"}}]})
    s = Settings(data_dir=tmp_path, llm_api_key="secret", llm_base_url="https://api.deepseek.com")
    OpenAICompatibleClient(s, httpx.MockTransport(handle), thinking="disabled").complete([], [])
    OpenAICompatibleClient(s, httpx.MockTransport(handle), thinking="enabled").complete([], [])
    assert [x["thinking"]["type"] for x in seen] == ["disabled", "enabled"]
    assert all(x["tool_choice"] == "auto" for x in seen)


def test_model_non_tool_response_clean_payload_and_error_code(tmp_path):
    seen = []
    def handler(req):
        seen.append(json.loads(req.content))
        if len(seen) == 1:
            return httpx.Response(200, json={"choices":[{"message":{"role":"assistant", "content":"Only prose"}}]})
        return httpx.Response(400, json={"error":{"type":"invalid_request_error", "message":"never include secret"}})
    c = OpenAICompatibleClient(Settings(data_dir=tmp_path,llm_api_key="token"), httpx.MockTransport(handler))
    first = c.complete([{"role":"user","content":"hi"}], [])
    assert "tool_calls" not in first.message
    assert first.message["content"] == "Only prose"
    try:
        c.complete([first.message], [])
    except RuntimeError as exc:
        assert "HTTP 400" in str(exc)
        assert "invalid_request_error" in str(exc)
        assert "secret" not in str(exc)
    else:
        raise AssertionError("expected error")


def test_large_archive_with_many_non_code_entries_is_allowed(tmp_path):
    b=io.BytesIO()
    with zipfile.ZipFile(b,"w",compression=zipfile.ZIP_STORED) as z:
        z.writestr("repo-sha/main.c", "int main(){return 0;}")
        for i in range(25100):
            z.writestr(f"repo-sha/docs/{i}.txt", "")
    assert extract_safe_source_zip(b.getvalue(), tmp_path) == 1
    assert (tmp_path/"main.c").exists()


def test_valid_non_tool_json_verdict(kb):
    class PlainJson:
        def complete(self, messages, tools):
            return ModelTurn({"role":"assistant", "content":json.dumps(VERDICT, ensure_ascii=False)}, [])
    result=VulnerabilityAgent(kb,PlainJson(),max_steps=2).detect(DetectionInput(idx=1,func=SAMPLE))
    assert result.prediction==0
    assert any("结构化判定" in e.title for e in result.trace)


def test_unstructured_prose_does_not_make_up_prediction(kb):
    class PlainText:
        def complete(self, messages, tools):
            return ModelTurn({"role":"assistant", "content":"I cannot judge"}, [])
    import pytest
    with pytest.raises(RuntimeError, match="最大推理轮次"):
        VulnerabilityAgent(kb, PlainText(), max_steps=2).detect(DetectionInput(idx=1,func=SAMPLE))


def test_events_are_written_during_job(tmp_path):
    store=RunStore(tmp_path/"runtime"/"jobs.sqlite3", tmp_path/"result")
    job=store.new_job("batch", 2)
    store.add_event(job,"trace",{"idx":"42", "kind":"knowledge", "detail":{"sample":"hello"}})
    f=tmp_path/"result"/job/"events.jsonl"
    assert f.is_file()
    event=json.loads(f.read_text().splitlines()[0])
    assert event["data"]["idx"]=="42"
    assert event["kind"]=="trace"
    assert store.events_since(job)


def test_sample_level_concurrency_and_ordered_results(tmp_path):
    running=0
    peak=0
    lock=threading.Lock()
    class SlowModel:
        def complete(self,messages,tools):
            nonlocal running,peak
            with lock:
                running+=1
                peak=max(peak,running)
            time.sleep(.045)
            with lock:
                running-=1
            return ModelTurn({"role":"assistant", "content":json.dumps(VERDICT,ensure_ascii=False)}, [])
    settings=Settings(data_dir=tmp_path/"runtime", result_dir=tmp_path/"result", batch_concurrency=3)
    service=DetectionService(settings,model=SlowModel())
    items=[DetectionInput(idx=i,func=SAMPLE) for i in range(7)]
    job=service.store.new_job("batch",len(items))
    service._run(job,items,service.model,service.profile)
    assert peak==3
    assert service.store.job(job)["status"]=="completed"
    assert [r["idx"] for r in service.store.rows(job)]==list(map(str,range(7)))
    assert (settings.result_dir/job/"result.jsonl").exists()
    assert (settings.result_dir/job/"events.jsonl").exists()


def test_repository_limits_are_separately_configurable(monkeypatch, tmp_path):
    from app.config import Settings
    monkeypatch.setenv("VULNSCOPE_MAX_REPO_MB", "700")
    monkeypatch.setenv("VULNSCOPE_MAX_REPO_ARCHIVE_MB", "300")
    monkeypatch.setenv("VULNSCOPE_DATA_DIR", str(tmp_path / "runtime"))
    settings = Settings.from_env()
    assert settings.max_repo_mb == 700
    assert settings.max_repo_archive_mb == 300


def test_repository_limits_are_clamped(monkeypatch, tmp_path):
    from app.config import Settings
    monkeypatch.setenv("VULNSCOPE_MAX_REPO_MB", "5000")
    monkeypatch.setenv("VULNSCOPE_MAX_REPO_ARCHIVE_MB", "5000")
    monkeypatch.setenv("VULNSCOPE_DATA_DIR", str(tmp_path / "runtime"))
    settings = Settings.from_env()
    assert settings.max_repo_mb == 1024
    assert settings.max_repo_archive_mb == 512


def test_stability_defaults_for_batch_and_agent(monkeypatch, tmp_path):
    for key in (
        "VULNSCOPE_MAX_AGENT_STEPS", "VULNSCOPE_MAX_TOOL_CALLS",
        "VULNSCOPE_BATCH_CONCURRENCY", "VULNSCOPE_MAX_REPO_MB",
        "VULNSCOPE_MAX_REPO_ARCHIVE_MB",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("VULNSCOPE_DATA_DIR", str(tmp_path / "runtime"))
    settings = Settings.from_env()
    assert settings.max_agent_steps == 16
    assert settings.max_tool_calls == 32
    assert settings.batch_concurrency == 1
    assert settings.max_repo_mb == 1024
    assert settings.max_repo_archive_mb == 250


def test_batch_warns_when_github_token_missing_and_repo_links_present(tmp_path):
    class JsonModel:
        def complete(self, messages, tools):
            return ModelTurn(
                {"role": "assistant", "content": json.dumps(VERDICT, ensure_ascii=False)},
                [],
            )

    settings = Settings(
        data_dir=tmp_path / "runtime",
        result_dir=tmp_path / "result",
        github_token="",
        batch_concurrency=1,
    )
    service = DetectionService(settings, model=JsonModel())
    item = DetectionInput(
        idx="github-no-token",
        func=SAMPLE,
        commit_url="https://github.com/org/project/commit/" + "a" * 40,
        target=0,
    )
    job_id = service.store.new_job("batch", 1)
    service._run(job_id, [item], service.model, service.profile)
    events = service.store.events_since(job_id)
    assert any(
        e["kind"] == "trace"
        and e["data"].get("title") == "GitHub 访问令牌未配置"
        for e in events
    )
