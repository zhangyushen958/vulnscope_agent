"""API and report contracts. Test labels are routing metadata, NOT LLM input."""
from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator, model_validator


class DetectionInput(BaseModel):
    idx: str | int = Field(default="manual")
    func: str = Field(min_length=10, max_length=140000)
    commit_url: str | None = None
    target: Literal[0, 1] | None = None

    @field_validator("func")
    @classmethod
    def function_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("函数代码不可为空")
        return v

    @field_validator("target", mode="before")
    @classmethod
    def parse_label(cls, v: Any) -> Any:
        if v in (None, "", "unknown"):
            return None
        if type(v) is bool:
            raise ValueError("target 必须是整数 0 或 1")
        if v in ("0", "1"):
            return int(v)
        return v

    @model_validator(mode="after")
    def valid_snapshot_spec(self) -> "DetectionInput":
        if self.commit_url is not None and not self.commit_url.strip():
            self.commit_url = None
        if self.commit_url and self.target is None:
            raise ValueError("提供 commit_url 时，必须提供 target=1（父提交）或 0（修复提交）以准确隔离仓库版本")
        return self


class TraceEvent(BaseModel):
    kind: str
    title: str
    detail: dict[str, Any] = Field(default_factory=dict)


class DetectionReport(BaseModel):
    idx: str | int
    prediction: Literal[0, 1]
    reason: str = Field(min_length=12)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    trace: list[TraceEvent] = Field(default_factory=list)
    repository_status: str = "not_requested"


class JobRow(BaseModel):
    idx: str | int
    status: Literal["completed", "failed"]
    report: DetectionReport | None = None
    error: str | None = None
