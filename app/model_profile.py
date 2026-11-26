"""Validated server-side DeepSeek model selection; never persists or returns API keys."""
from __future__ import annotations
from dataclasses import dataclass, asdict

MODEL_FLASH = 'deepseek-v4.1-flash-1017'
MODEL_PRO = 'deepseek-v4-pro'
ALLOWED_MODELS = (MODEL_FLASH, MODEL_PRO)
LEGACY_MODEL_ALIASES = {'deepseek-flash': MODEL_FLASH}


def normalize_model_name(model: str) -> str:
    return LEGACY_MODEL_ALIASES.get(model, model)


@dataclass(frozen=True)
class ModelProfile:
    model: str = MODEL_FLASH
    thinking: str = 'disabled'
    max_agent_steps: int = 16

    @classmethod
    def validate(cls, value: dict) -> 'ModelProfile':
        if not isinstance(value, dict):
            raise ValueError('模型配置必须是 JSON 对象')
        model = normalize_model_name(value.get('model', MODEL_FLASH))
        thinking = value.get('thinking', 'disabled')
        steps = value.get('max_agent_steps', 16)
        if model not in ALLOWED_MODELS:
            raise ValueError('不支持的模型名称')
        if thinking not in ('enabled', 'disabled'):
            raise ValueError('thinking 必须为 enabled 或 disabled')
        if type(steps) is not int or steps < 2 or steps > 20:
            raise ValueError('max_agent_steps 必须为 2 至 20 之间的整数')
        return cls(model, thinking, steps)

    def public(self) -> dict:
        return asdict(self)
