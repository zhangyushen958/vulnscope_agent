"""Runtime configuration: secrets never enter tool output or LLM prompts."""
from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    data_dir: Path = Path("runtime")
    llm_api_key: str = ""
    llm_base_url: str = "https://workspace-id.cn-beijing.maas.aliyuncs.com/compatible-mode/v1"
    llm_model: str = "deepseek-v4.1-flash-1017"
    github_token: str = ""
    max_agent_steps: int = 16
    max_tool_calls: int = 32
    max_repo_mb: int = 1024
    max_repo_archive_mb: int = 250
    batch_concurrency: int = 1
    dataset_dir: Path = Path("dataset")
    result_dir: Path = Path("result")

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            data_dir=Path(os.getenv("VULNSCOPE_DATA_DIR", "runtime")).expanduser().resolve(),
            dataset_dir=Path(os.getenv("VULNSCOPE_DATASET_DIR", "dataset")).expanduser().resolve(),
            result_dir=Path(os.getenv("VULNSCOPE_RESULT_DIR", "result")).expanduser().resolve(),
            llm_api_key=os.getenv("VULNSCOPE_LLM_API_KEY", ""),
            llm_base_url=os.getenv("VULNSCOPE_LLM_BASE_URL", "https://workspace-id.cn-beijing.maas.aliyuncs.com/compatible-mode/v1").rstrip("/"),
            llm_model=os.getenv("VULNSCOPE_LLM_MODEL", "deepseek-v4.1-flash-1017"),
            github_token=os.getenv("VULNSCOPE_GITHUB_TOKEN", ""),
            max_agent_steps=max(2, min(20, int(os.getenv("VULNSCOPE_MAX_AGENT_STEPS", "16")))),
            max_tool_calls=max(8, min(64, int(os.getenv("VULNSCOPE_MAX_TOOL_CALLS", "32")))),
            # Uncompressed allowlisted C/C++ source budget. Bounded to 1 GiB.
            max_repo_mb=max(10, min(1024, int(os.getenv("VULNSCOPE_MAX_REPO_MB", "1024")))),
            # Downloaded GitHub ZIP budget is separate from extracted source budget.
            max_repo_archive_mb=max(10, min(512, int(os.getenv("VULNSCOPE_MAX_REPO_ARCHIVE_MB", "250")))),
            batch_concurrency=max(1, min(6, int(os.getenv("VULNSCOPE_BATCH_CONCURRENCY", "1")))),
        )

    def validate_llm_url(self) -> None:
        u = urlsplit(self.llm_base_url)
        if u.scheme != "https" and not (u.scheme == "http" and u.hostname in {"127.0.0.1", "localhost", "::1"}):
            raise ValueError("模型接口必须使用 HTTPS，或指向 localhost 本地推理服务")
        if u.username or u.password or u.fragment or not u.hostname:
            raise ValueError("模型接口地址不合法")

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.result_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "snapshots").mkdir(exist_ok=True)
