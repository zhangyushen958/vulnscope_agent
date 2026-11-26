"""FastAPI GUI/JSON API and server-sent event trace updates."""
from __future__ import annotations
import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from app.agent import LANGGRAPH_AVAILABLE
from app.dataset_adapter import read_dataset_archive
from app.config import Settings
from app.models import DetectionInput
from app.rag import load_jsonl
from app.service import DetectionService, MAX_BATCH
from app.course_io import parse_test_rows, read_local_file, MAX_KNOWLEDGE_BYTES, MAX_TEST_BYTES

STATIC = Path(__file__).parent / "static"


def create_app(service: DetectionService | None = None) -> FastAPI:
    service = service or DetectionService(Settings.from_env())
    api = FastAPI(title="VulnScope Agent", description="C/C++ function vulnerability analysis with case-only RAG and isolated repository context", version="3.4.0")
    api.state.service = service
    api.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

    @api.middleware("http")
    async def prevent_stale_frontend(request: Request, call_next):
        response = await call_next(request)
        if request.url.path == "/" or request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
        return response


    @api.get("/", include_in_schema=False)
    def home():
        return FileResponse(STATIC / "index.html")

    @api.get("/api/health")
    def health():
        settings = service.settings
        return {"ok": True, "model_configured": bool(settings.llm_api_key) or settings.llm_base_url.startswith("http://localhost")
                or settings.llm_base_url.startswith("http://127.0.0.1"),
                "model_name": service.get_profile()["model"], "langgraph_installed": LANGGRAPH_AVAILABLE,
                "knowledge": service.kb.stats(), "version": "3.4.0", "dataset_files": {name: (service.settings.dataset_dir / name).is_file() for name in ("knowledge.jsonl", "test.jsonl")}}

    @api.get("/api/models")
    def models():
        return {"provider": "aliyun-bailian", "base_url": service.settings.llm_base_url,
                "models": ["deepseek-v4.1-flash-1017", "deepseek-v4-pro"],
                "active": service.get_profile(), "configured": bool(service.settings.llm_api_key)}

    @api.post("/api/models/select")
    async def select_model(request: Request):
        try:
            data = await request.json()
            profile = service.set_profile(data)
            return {"active": profile, "message": "配置已保存，仅作用于新提交的检测任务"}
        except (ValueError, TypeError) as exc:
            raise HTTPException(422, str(exc)) from exc

    @api.post("/api/models/test")
    def probe_model():
        # Minimal real network probe, only if a user explicitly presses test.
        from dataclasses import replace
        from app.llm import OpenAICompatibleClient
        from app.agent import TOOLS_FINISH
        if not service.settings.llm_api_key:
            raise HTTPException(422, "尚未配置阿里云百炼 API Key")
        try:
            profile = service.get_profile()
            # This endpoint verifies Function Calling itself, not the user's
            # optional reasoning preference. Bailian does not allow
            # tool_choice=required while thinking is enabled, so the probe
            # deliberately uses non-thinking mode and forces one tool call.
            client = OpenAICompatibleClient(
                replace(service.settings, llm_model=profile["model"]),
                thinking="disabled",
            )
            response = client.complete(
                [
                    {"role": "system", "content": (
                        "这是 Function Calling 连通性测试。你必须调用 submit_verdict 工具，"
                        "不要用自然语言回答。prediction 填 0，reason 说明这是接口测试，"
                        "confidence 填 1，evidence 填 [\"connectivity probe\"]。"
                    )},
                    {"role": "user", "content": "请立即调用 submit_verdict 完成工具调用测试。"},
                ],
                [TOOLS_FINISH],
                tool_choice="required",
            )
            return {
                "connected": True,
                "tool_call_supported": bool(response.calls),
                "tool_names": [call.name for call in response.calls],
                "finish_reason": response.finish_reason,
                "model": profile["model"],
                "probe_mode": "non-thinking + tool_choice=required",
                "message": ("Function Calling 可用" if response.calls else
                            "HTTP 请求成功，但响应没有 tool_calls；请检查模型服务端工具调用能力"),
            }
        except Exception as exc:
            # OpenAICompatibleClient errors are sanitized before reaching here.
            detail = str(exc)[:300]
            raise HTTPException(502, f"模型工具调用测试失败：{detail or type(exc).__name__}") from exc

    @api.post("/api/knowledge/import")
    async def import_knowledge(file: UploadFile = File(...)):
        name = (file.filename or "").lower()
        if not name.endswith((".jsonl", ".zip")):
            raise HTTPException(422, "只支持历史案例 .jsonl 或课程 dataset.zip")
        data = await file.read(80 * 1024 * 1024 + 1)
        try:
            if name.endswith(".zip"):
                data = read_dataset_archive(data, "knowledge.jsonl")
            count = await asyncio.to_thread(service.kb.import_jsonl, data)
        except (ValueError, UnicodeError) as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"imported_pairs": count, "knowledge": service.kb.stats(),
                "message": "仅从本次上传的历史漏洞/修复配对数据重新构建 RAG"}

    @api.post("/api/knowledge/import-local")
    async def import_local_knowledge():
        try:
            raw = await asyncio.to_thread(read_local_file, service.settings.dataset_dir, "knowledge.jsonl", MAX_KNOWLEDGE_BYTES)
            count = await asyncio.to_thread(service.kb.import_jsonl, raw)
            return {"imported_pairs": count, "knowledge": service.kb.stats(), "source": "dataset/knowledge.jsonl"}
        except (ValueError, UnicodeError, OSError) as exc:
            raise HTTPException(422, str(exc)) from exc

    @api.post("/api/jobs/batch-local", status_code=202)
    async def submit_local_batch():
        try:
            raw = await asyncio.to_thread(read_local_file, service.settings.dataset_dir, "test.jsonl", MAX_TEST_BYTES)
            inputs = parse_test_rows(raw)
            job_id = service.submit(inputs, "batch")
            return {"job_id": job_id, "status": "queued", "total": len(inputs), "source": "dataset/test.jsonl"}
        except (ValueError, UnicodeError, OSError) as exc:
            raise HTTPException(422, str(exc)) from exc

    @api.get("/api/results")
    def list_results():
        return {"jobs": service.store.recent_jobs()}

    @api.post("/api/results/clear")
    def clear_results(request_body: dict):
        if request_body.get("confirm") != "CLEAR_RESULTS":
            raise HTTPException(422, "请确认清空结果")
        job_id = request_body.get("job_id")
        if job_id is not None and not isinstance(job_id, str):
            raise HTTPException(422, "任务 ID 必须是字符串")
        try:
            return service.clear_results(job_id)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        except (ValueError, OSError) as exc:
            raise HTTPException(422, str(exc)) from exc

    @api.post("/api/knowledge/clear")
    def clear_knowledge(request_body: dict):
        if request_body.get("confirm") != "CLEAR_KNOWLEDGE":
            raise HTTPException(422, "请确认清空知识库")
        try:
            return service.clear_knowledge()
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        except OSError as exc:
            raise HTTPException(500, "知识库删除失败，请检查文件权限") from exc

    @api.get("/api/jobs/{job_id}/score")
    def score_job(job_id: str):
        try:
            return service.score(job_id)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        except (ValueError, OSError) as exc:
            raise HTTPException(422, str(exc)) from exc

    @api.post("/api/jobs/single", status_code=202)
    def submit_single(item: DetectionInput):
        try:
            job_id = service.submit([item], "single")
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"job_id": job_id, "status": "queued"}

    @api.post("/api/jobs/batch", status_code=202)
    async def submit_batch(file: UploadFile = File(...)):
        name = (file.filename or "").lower()
        if not name.endswith((".jsonl", ".zip")):
            raise HTTPException(422, "只支持 .jsonl 或课程 dataset.zip")
        raw = await file.read(80 * 1024 * 1024 + 1)
        try:
            if name.endswith(".zip"):
                raw = read_dataset_archive(raw, "test.jsonl")
            inputs = parse_test_rows(raw)
            job_id = service.submit(inputs, "batch")
        except (ValueError, UnicodeError) as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"job_id": job_id, "status": "queued", "total": len(inputs)}

    @api.get("/api/jobs/{job_id}")
    def get_job(job_id: str):
        job = service.store.job(job_id)
        if not job:
            raise HTTPException(404, "不存在的任务")
        return {**job, "rows": service.store.rows(job_id)}

    @api.get("/api/jobs/{job_id}/events")
    async def stream_events(job_id: str, request: Request, after: int = 0):
        if not service.store.job(job_id):
            raise HTTPException(404, "不存在的任务")
        cursor = max(0, after)
        header_last = request.headers.get("last-event-id")
        if header_last and header_last.isdigit():
            cursor = max(cursor, int(header_last))

        async def generate():
            nonlocal cursor
            idle = 0
            while not await request.is_disconnected():
                events = service.store.events_since(job_id, cursor)
                if events:
                    for event in events:
                        cursor = event["id"]
                        yield f"id: {cursor}\nevent: trace\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"
                    idle = 0
                else:
                    idle += 1
                    if idle % 15 == 0:
                        yield ": keepalive\n\n"
                job = service.store.job(job_id)
                if job and job["status"] in {"completed", "partial", "failed"} and not service.store.events_since(job_id, cursor, 1):
                    yield "event: finished\ndata: {}\n\n"
                    return
                await asyncio.sleep(.5)
        return StreamingResponse(generate(), media_type="text/event-stream", headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"})

    @api.get("/api/jobs/{job_id}/download")
    def download(job_id: str, format: str = "result"):
        job = service.store.job(job_id)
        if not job:
            raise HTTPException(404, "不存在的任务")
        if job["status"] not in {"completed", "partial", "failed"}:
            raise HTTPException(409, "任务尚未完成")
        rows = service.store.rows(job_id)
        if format == "result":
            if job["status"] != "completed" or len(rows) != job["total"]:
                raise HTTPException(409, "存在检测失败或条目缺失；禁止将不完整结果伪装为 result.jsonl，请下载 reports 排查")
            body = "".join(json.dumps({"idx": row["report"]["idx"], "prediction": row["report"]["prediction"]},
                                      ensure_ascii=False) + "\n" for row in rows)
            return Response(body, media_type="application/x-ndjson", headers={"Content-Disposition": "attachment; filename=result.jsonl"})
        if format == "reports":
            return Response(json.dumps({"job": job, "rows": rows}, ensure_ascii=False, indent=2),
                            media_type="application/json", headers={"Content-Disposition": "attachment; filename=reports.json"})
        raise HTTPException(422, "format 必须是 result 或 reports")

    return api


app = create_app()
