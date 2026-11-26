"""Asynchronous in-server job executor, per-sample isolation and durable outputs."""
from __future__ import annotations
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import shutil
import re
from dataclasses import replace
from app.model_profile import ModelProfile, MODEL_FLASH, ALLOWED_MODELS, normalize_model_name
from typing import Callable
from app.agent import VulnerabilityAgent
from app.config import Settings
from app.llm import ModelClient, OpenAICompatibleClient
from app.models import DetectionInput
from app.rag import HistoricalKB
from app.repository import RepositoryTools, SnapshotProvider
from app.store import RunStore
from app.course_io import atomic_json, atomic_jsonl, output_rows, grade_result, read_local_file, MAX_TEST_BYTES
from app.rag import load_jsonl

from app.service_types import MAX_BATCH


class DetectionService:
    def __init__(self, settings: Settings, model: ModelClient | None = None,
                 provider: SnapshotProvider | None = None):
        self.settings = settings
        settings.ensure_dirs()
        self.kb = HistoricalKB(settings.data_dir / "historical_cases.json")
        self.store = RunStore(settings.data_dir / "jobs.sqlite3", result_dir=settings.result_dir)
        self._injected_model = model
        self.model = model or OpenAICompatibleClient(settings)
        saved = self.store.get_setting("model_profile")
        self.profile = ModelProfile.validate(saved) if saved else ModelProfile(
            model=normalize_model_name(settings.llm_model) if normalize_model_name(settings.llm_model) in ALLOWED_MODELS else MODEL_FLASH,
            max_agent_steps=settings.max_agent_steps)
        self._profile_lock = threading.RLock()
        self._maintenance_lock = threading.RLock()
        self.provider = provider or SnapshotProvider(
            settings.data_dir / "snapshots", settings.github_token,
            max_bytes=settings.max_repo_archive_mb * 1024 * 1024,
            max_uncompressed=settings.max_repo_mb * 1024 * 1024,
        )

    def set_profile(self, raw: dict) -> dict:
        profile = ModelProfile.validate(raw)
        with self._profile_lock:
            self.store.set_setting("model_profile", profile.public())
            self.profile = profile
        return profile.public()

    def get_profile(self) -> dict:
        with self._profile_lock:
            return self.profile.public()

    def submit(self, inputs: list[DetectionInput], mode: str = "single") -> str:
        if not inputs or len(inputs) > MAX_BATCH:
            raise ValueError(f"输入条数必须为 1～{MAX_BATCH}")
        ids = [str(x.idx) for x in inputs]
        if len(set(ids)) != len(ids):
            raise ValueError("idx 必须唯一，不能在同一批次出现重复索引")
        with self._profile_lock:
            profile = self.profile
        model = self._injected_model or OpenAICompatibleClient(
            replace(self.settings, llm_model=profile.model), thinking=profile.thinking)
        with self._maintenance_lock:
            job_id = self.store.new_job(mode, len(inputs))
        if mode == "batch":
            # Persist the exact normalized sample payload at submission time.
            # Scoring must use this immutable snapshot, not whichever test.jsonl
            # happens to be present later (e.g. full test set vs uploaded demo subset).
            snapshot_rows = [item.model_dump(mode="json") for item in inputs]
            snapshot_digest = self._input_digest(inputs)
            snapshot_dir = self.settings.result_dir / job_id
            try:
                snapshot_dir.mkdir(parents=True, exist_ok=True)
                atomic_jsonl(snapshot_dir / "submitted_dataset.jsonl", snapshot_rows)
                self.store.set_setting(f"batch_digest:{job_id}", {"sha256": snapshot_digest})
            except OSError as exc:
                self.store.set_status(job_id, "failed")
                raise ValueError(f"无法保存任务提交时的数据集快照，任务未启动：{exc}") from exc
        self.store.add_event(job_id, "model", {"profile": profile.public(), "message": "任务级模型配置已固定"})
        # Each sample is run in a fresh agent invocation and one allowed snapshot.
        worker = threading.Thread(target=self._run, args=(job_id, inputs, model, profile), daemon=True, name=f"vulnscope-{job_id[:6]}")
        worker.start()
        return job_id

    def clear_results(self, job_id: str | None = None) -> dict:
        """Remove completed runs without touching user dataset, RAG, keys or snapshot cache."""
        with self._maintenance_lock:
            if job_id is not None and not re.fullmatch(r"[0-9a-f]{32}", job_id):
                raise ValueError("无效任务 ID")
            if self.store.active_jobs():
                raise RuntimeError("后台任务仍在运行或排队，不能清空结果")
            ids = self.store.delete_finished(job_id)
            # Folder names originate from UUID-generated IDs in our own jobs table.
            for id_ in ids:
                output = self.settings.result_dir / id_
                if output.is_symlink():
                    output.unlink()
                elif output.is_dir():
                    shutil.rmtree(output)
            return {"deleted_jobs": len(ids), "message": "历史结果与日志已清空；知识库和模型配置已保留"}

    def clear_knowledge(self) -> dict:
        with self._maintenance_lock:
            if self.store.active_jobs():
                raise RuntimeError("检测任务运行中，禁止清空领域知识库")
            count = self.kb.clear()
            return {"deleted_cases": count, "knowledge": self.kb.stats(),
                    "message": "知识库索引已清空；dataset/knowledge.jsonl 原始文件保留"}

    @staticmethod
    def _input_digest(inputs: list[DetectionInput]) -> str:
        # Ensures evaluation compares exactly the test functions used for this job.
        payload = [x.model_dump(mode='json') for x in inputs]
        return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode('utf-8')).hexdigest()

    def _run(self, job_id: str, items: list[DetectionInput], model: ModelClient, profile: ModelProfile) -> None:
        self.store.set_status(job_id, "running")
        self.store.add_event(job_id, "job", {"message": "任务启动", "total": len(items)})
        if any(item.commit_url for item in items) and not self.settings.github_token:
            self.store.add_event(job_id, "trace", {
                "kind": "warning",
                "title": "GitHub 访问令牌未配置",
                "detail": {
                    "message": "本批次包含 GitHub 提交链接，但未配置 VULNSCOPE_GITHUB_TOKEN。"
                               "匿名 GitHub REST API 配额通常为每小时 60 次；300 条批量检测强烈建议先配置令牌。",
                    "action": "在项目根目录 .env 配置 VULNSCOPE_GITHUB_TOKEN 后重启服务，再提交批量任务。",
                },
            })
        def process_sample(order: int, item: DetectionInput) -> None:
            row_label = str(item.idx)
            self.store.add_event(job_id, "sample_start", {"idx": row_label, "current": order + 1, "total": len(items)})
            try:
                repository = None
                if item.commit_url:
                    # Fetch only on model-initiated repo tool access (not before RAG).
                    # The target label is confined to SnapshotProvider and never
                    # appears in model/tool messages.
                    repository = LazyRepository(self.provider, item.commit_url, item.target,
                        lambda sha, count: self.store.add_event(job_id, "snapshot", {
                            "idx": row_label, "message": "Agent 触发了单版本仓库快照读取",
                            "file_count": count, "sha_prefix": sha[:10]}))
                else:
                    self.store.add_event(job_id, "snapshot", {"idx": row_label,
                        "message": "未提供仓库链接：仅使用待测函数及领域历史案例"})

                def on_trace(event: dict) -> None:
                    self.store.add_event(job_id, "trace", {"idx": row_label, **event})

                result = VulnerabilityAgent(
                    self.kb, model, profile.max_agent_steps,
                    max_tool_calls=self.settings.max_tool_calls,
                ).detect(item, repo=repository, on_event=on_trace)
                self.store.add_row(job_id, order, row_label, result.model_dump(), None)
                self.store.add_event(job_id, "sample_done", {"idx": row_label,
                    "prediction": result.prediction, "confidence": result.confidence, "reason": result.reason[:600]})
            except Exception as exc:
                # No guessing when the repository or LLM fails.
                error = str(exc)[:900]
                self.store.add_row(job_id, order, row_label, None, error)
                self.store.add_event(job_id, "sample_error", {"idx": row_label, "message": error})
        # Each sample is isolated; only a bounded number of remote LLM calls
        # and repository downloads can be in flight at the same time.
        workers = min(len(items), max(1, self.settings.batch_concurrency))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="vulnscope-sample") as pool:
            futures = [pool.submit(process_sample, order, item) for order, item in enumerate(items)]
            for future in as_completed(futures):
                future.result()  # surface unexpected programming errors
        job = self.store.job(job_id)
        status = "completed" if job["failures"] == 0 else ("partial" if job["success"] else "failed")
        saved = self._save_artifacts(job_id, status)
        if not saved:
            status = "partial" if job["success"] else "failed"
        self.store.set_status(job_id, status)
        self.store.add_event(job_id, "job_done", {"status": status, "total": job["total"], "success": job["success"],
                                                   "failures": job["failures"]})


    def _save_artifacts(self, job_id: str, status: str) -> bool:
        """Save job-specific outputs atomically, including partial run diagnostics."""
        folder = self.settings.result_dir / job_id
        try:
            folder.mkdir(parents=True, exist_ok=True)
            rows = self.store.rows(job_id)
            result = output_rows(rows)
            atomic_json(folder / 'reports.json', {'job': self.store.job(job_id), 'rows': rows})
            # Do not represent a partial result as a complete course submission.
            if status == 'completed' and len(result) == self.store.job(job_id)['total']:
                atomic_jsonl(folder / 'result.jsonl', result)
            else:
                atomic_jsonl(folder / 'partial_predictions.jsonl', result)
            self.store.add_event(job_id, 'artifact', {'message': '检测输出已保存', 'directory': f'result/{job_id}/'})
            return True
        except OSError as exc:
            self.store.add_event(job_id, 'artifact_error', {'message': f'结果写入失败：{exc}'})
            return False

    def score(self, job_id: str) -> dict:
        job = self.store.job(job_id)
        if not job:
            raise LookupError('任务不存在')
        if job['status'] not in {'completed', 'partial', 'failed'}:
            raise RuntimeError('任务未结束，禁止提前评分')
        if job['mode'] != 'batch':
            raise ValueError('仅批量检测任务支持课程成对评分')
        # Ground truth is accessed only after inference. Always score against the
        # exact dataset snapshot captured when this batch job was submitted. This
        # supports uploaded subsets such as demo.jsonl without accidentally
        # comparing them with a different local dataset/test.jsonl.
        snapshot_path = self.settings.result_dir / job_id / "submitted_dataset.jsonl"
        if snapshot_path.is_symlink() or not snapshot_path.is_file():
            # Backward compatibility for batch jobs created before immutable
            # snapshots were introduced: retain the old strict local-dataset guard.
            truth = load_jsonl(read_local_file(self.settings.dataset_dir, 'test.jsonl', MAX_TEST_BYTES))
            original = [DetectionInput.model_validate(row) for row in truth]
            recorded = self.store.get_setting(f'batch_digest:{job_id}')
            if not recorded or recorded.get('sha256') != self._input_digest(original):
                raise ValueError('任务缺少有效的提交数据集快照，且当前 dataset/test.jsonl 与任务提交内容不一致，拒绝错误配对评分；请重新提交该 JSONL 任务')
        else:
            try:
                raw_snapshot = snapshot_path.read_bytes()
            except OSError as exc:
                raise ValueError(f'无法读取任务提交数据集快照：{exc}') from exc
            if len(raw_snapshot) > MAX_TEST_BYTES:
                raise ValueError('任务提交数据集快照超过大小限制，拒绝评分')
            truth = load_jsonl(raw_snapshot)
            original = [DetectionInput.model_validate(row) for row in truth]
            recorded = self.store.get_setting(f'batch_digest:{job_id}')
            if not recorded or recorded.get('sha256') != self._input_digest(original):
                raise ValueError('任务提交数据集快照与提交时摘要不一致，拒绝错误配对评分')
        # The course pair scorer requires explicit binary labels. Manual/unlabelled
        # batch uploads may run inference, but are not eligible for pair scoring.
        if any(type(row.get('target')) is not int or row.get('target') not in (0, 1) for row in truth):
            raise ValueError('任务提交的数据集缺少有效 target=0/1 标签，无法进行成对评分')
        predictions = output_rows(self.store.rows(job_id))
        # Scoring requires exact test IDs; batch uploads may be unrelated to the local test set.
        score = grade_result(truth, predictions)
        score['job_id'] = job_id
        score['output_directory'] = f'result/{job_id}/'
        folder = self.settings.result_dir / job_id
        folder.mkdir(parents=True, exist_ok=True)
        atomic_json(folder / 'score.json', score)
        return score


class LazyRepository:
    """Per-sample read-only on-demand snapshot. Never compares two versions."""
    def __init__(self, provider: SnapshotProvider, url: str, target: int, on_load):
        self.provider, self.url, self.target = provider, url, target
        self.on_load = on_load
        self._tools = None
        self._failure: Exception | None = None
        self._lock = threading.RLock()

    @property
    def failed(self) -> bool:
        return self._failure is not None

    def _get(self) -> RepositoryTools:
        with self._lock:
            if self._failure is not None:
                raise RuntimeError(f"仓库快照不可用：{self._failure}") from self._failure
            if self._tools is None:
                try:
                    root, sha = self.provider.fetch(self.url, self.target)
                    tools = RepositoryTools(root)
                    self._tools = tools
                    self.on_load(sha, len(tools.files))
                except Exception as exc:
                    # Cache the failure for this sample. A rate-limited or
                    # oversized snapshot must not trigger repeated downloads
                    # for every subsequent repository tool call.
                    self._failure = exc
                    raise
            return self._tools

    def search_code(self, symbol):
        return self._get().search_code(symbol)

    def find_callers(self, symbol):
        return self._get().find_callers(symbol)

    def find_definitions(self, symbol):
        return self._get().find_definitions(symbol)

    def read_file(self, path, start_line=1, end_line=90):
        return self._get().read_file(path, start_line, end_line)
