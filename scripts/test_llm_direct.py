from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

from openai import OpenAI

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config_loader import load_config


def _messages_to_responses_input(messages: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for msg in messages:
        out.append(
            {
                "role": str(msg.get("role", "user") or "user"),
                "content": [
                    {
                        "type": "input_text",
                        "text": str(msg.get("content", "") or ""),
                    }
                ],
            }
        )
    return out


def _extract_responses_text(resp: Any) -> str:
    text = getattr(resp, "output_text", None)
    if isinstance(text, str) and text.strip():
        return text.strip()

    output = getattr(resp, "output", None)
    if isinstance(output, list):
        chunks: List[str] = []
        for item in output:
            content = getattr(item, "content", None)
            if not isinstance(content, list):
                continue
            for part in content:
                part_text = getattr(part, "text", None)
                if isinstance(part_text, str) and part_text.strip():
                    chunks.append(part_text.strip())
        if chunks:
            return "\n".join(chunks).strip()

    if hasattr(resp, "model_dump"):
        try:
            dump = resp.model_dump()
        except Exception:
            dump = None
        if isinstance(dump, dict):
            dump_text = dump.get("output_text")
            if isinstance(dump_text, str) and dump_text.strip():
                return dump_text.strip()
            output_dump = dump.get("output")
            if isinstance(output_dump, list):
                chunks = []
                for item in output_dump:
                    if not isinstance(item, dict):
                        continue
                    content = item.get("content")
                    if not isinstance(content, list):
                        continue
                    for part in content:
                        if not isinstance(part, dict):
                            continue
                        for key in ("text", "output_text"):
                            value = part.get(key)
                            if isinstance(value, str) and value.strip():
                                chunks.append(value.strip())
                if chunks:
                    return "\n".join(chunks).strip()
    return ""


def _collect_streamed_responses_text(stream: Any) -> str:
    done_chunks: List[str] = []
    delta_chunks: List[str] = []
    for event in stream:
        event_type = str(getattr(event, "type", "") or "")
        if event_type == "response.output_text.done":
            text = getattr(event, "text", None)
            if isinstance(text, str) and text.strip():
                done_chunks.append(text.strip())
        elif event_type == "response.output_text.delta":
            delta = getattr(event, "delta", None)
            if isinstance(delta, str) and delta:
                delta_chunks.append(delta)
    if done_chunks:
        return "\n".join(done_chunks).strip()
    return "".join(delta_chunks).strip()


def _invoke_chat(client: OpenAI, model: str, messages: List[Dict[str, str]], temperature: float, max_tokens: int) -> str:
    payload: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }
    if max_tokens > 0:
        payload["max_tokens"] = max_tokens
    resp = client.chat.completions.create(**payload)
    return str(resp.choices[0].message.content or "")


def _invoke_responses(client: OpenAI, model: str, messages: List[Dict[str, str]], max_tokens: int) -> str:
    payload: Dict[str, Any] = {
        "model": model,
        "input": _messages_to_responses_input(messages),
        "store": False,
    }
    if max_tokens > 0:
        payload["max_output_tokens"] = max_tokens
    with client.responses.stream(**payload) as stream:
        streamed_text = _collect_streamed_responses_text(stream)
        resp = stream.get_final_response()
    if streamed_text:
        return streamed_text
    return _extract_responses_text(resp)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Direct LLM probe using the same config/env as the project, without going through main.py"
    )
    parser.add_argument("--config", default="config.json", type=str, help="Config file path")
    parser.add_argument("--prompt", default="Reply with exactly: pong", type=str, help="Prompt for the live request")
    parser.add_argument(
        "--api-style",
        choices=["auto", "chat", "responses"],
        default="auto",
        help="Force a specific API style, or auto to use config value",
    )
    parser.add_argument("--skip-models-check", action="store_true", help="Skip models.list probe")
    args = parser.parse_args()

    cfg = load_config(args.config)
    llm_cfg = cfg["llm"]
    api_style = str(args.api_style if args.api_style != "auto" else llm_cfg.get("api_style", "auto")).strip().lower()
    if api_style not in {"chat", "responses"}:
        api_style = "responses"

    result: Dict[str, Any] = {
        "config_path": str(Path(args.config).resolve()),
        "base_url": str(llm_cfg.get("base_url", "")),
        "model": str(llm_cfg.get("model", "")),
        "api_style": api_style,
        "api_key_env": str(llm_cfg.get("api_key_env", "")),
        "api_key_present": bool(llm_cfg.get("api_key", "")),
        "models_check": {"skipped": bool(args.skip_models_check)},
        "request": {},
    }

    if not bool(llm_cfg.get("api_key", "")):
        result["status"] = "failed"
        result["error"] = "missing API key"
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1

    client = OpenAI(
        api_key=str(llm_cfg.get("api_key", "")),
        base_url=str(llm_cfg.get("base_url", "")),
        timeout=int(llm_cfg.get("timeout", 90)),
        max_retries=0,
    )

    if not bool(args.skip_models_check):
        started = time.time()
        try:
            models = client.models.list()
            model_ids = [str(getattr(item, "id", "") or "") for item in getattr(models, "data", [])]
            result["models_check"] = {
                "skipped": False,
                "ok": True,
                "elapsed_seconds": round(time.time() - started, 3),
                "count": len(model_ids),
                "contains_configured_model": str(llm_cfg.get("model", "")) in model_ids,
                "preview": model_ids[:20],
            }
        except Exception as exc:
            result["models_check"] = {
                "skipped": False,
                "ok": False,
                "elapsed_seconds": round(time.time() - started, 3),
                "error": str(exc),
            }

    messages = [{"role": "user", "content": str(args.prompt)}]
    started = time.time()
    try:
        if api_style == "chat":
            text = _invoke_chat(
                client=client,
                model=str(llm_cfg.get("model", "")),
                messages=messages,
                temperature=float(llm_cfg.get("temperature", 0.1)),
                max_tokens=int(llm_cfg.get("max_tokens", 4096)),
            )
        else:
            text = _invoke_responses(
                client=client,
                model=str(llm_cfg.get("model", "")),
                messages=messages,
                max_tokens=int(llm_cfg.get("max_tokens", 4096)),
            )
        result["request"] = {
            "ok": True,
            "elapsed_seconds": round(time.time() - started, 3),
            "response_text": text,
        }
        result["status"] = "ok"
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        result["request"] = {
            "ok": False,
            "elapsed_seconds": round(time.time() - started, 3),
            "error": str(exc),
        }
        result["status"] = "failed"
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
