from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from source_diff_engine.config_loader import load_config
from source_diff_engine.llm.client import OpenCodeLLM


def main() -> int:
    parser = argparse.ArgumentParser(description="Diagnose LLM connectivity and provider compatibility")
    parser.add_argument("--config", default="configs/config.example.json", type=str, help="Config file path")
    parser.add_argument("--skip-models-check", action="store_true", help="Skip models.list during preflight")
    args = parser.parse_args()

    cfg = load_config(args.config)
    llm_cfg = cfg["llm"]
    llm = OpenCodeLLM(
        model=llm_cfg["model"],
        base_url=llm_cfg["base_url"],
        api_key=llm_cfg["api_key"],
        temperature=float(llm_cfg["temperature"]),
        timeout=int(llm_cfg["timeout"]),
        request_retries=int(llm_cfg["max_retries"]),
        max_tokens=int(llm_cfg["max_tokens"]),
        api_style=str(llm_cfg.get("api_style", "auto")),
    )

    status = "ok"
    try:
        llm.preflight(skip_models_check=bool(args.skip_models_check))
    except Exception as exc:
        status = "failed"
        result = llm.diagnose_connectivity()
        result["status"] = status
        result["error"] = str(exc)
        result["api_key_env"] = str(llm_cfg.get("api_key_env", ""))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1

    result = llm.diagnose_connectivity()
    result["status"] = status
    result["api_key_env"] = str(llm_cfg.get("api_key_env", ""))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
