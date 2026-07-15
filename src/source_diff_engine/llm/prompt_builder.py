from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class PromptBuilder:
    def __init__(self, prompts_file: str):
        path = Path(prompts_file)
        if not path.exists() and path.name == "prompts.yaml":
            path = Path(__file__).resolve().with_name("prompts.yaml")
        with path.open("r", encoding="utf-8") as f:
            self.prompts = yaml.safe_load(f) or {}

    def build(self, prompt_name: str, **kwargs: Any) -> str:
        if prompt_name not in self.prompts:
            raise ValueError(f"Prompt '{prompt_name}' is not defined")
        prompt_info = self.prompts[prompt_name]
        template = prompt_info.get("template", "")
        required = prompt_info.get("fields", [])
        for field in required:
            if field not in kwargs:
                raise ValueError(f"Missing field '{field}' for prompt '{prompt_name}'")
        return template.format(**kwargs)
