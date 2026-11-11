"""Redacting mitmproxy addon for Antigravity Desktop traffic auditing.

Captures only structural metadata, JSON key trees, numeric policy values, and
token usage across both channels:
  - Google OAuth native channel (`v1internal:streamGenerateContent`,
    `v1internal:fetchAvailableModels`, `v1internal:recordTrajectoryAnalytics`)
  - Enterprise Gateway channel (`/v1/chat/completions`, `/chat/completions`,
    `/v1/models`, `:streamGenerateContent`)

Never writes message text, prompts, tool outputs, file contents, or auth headers.
Output files are created with mode `0600`.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Set

from mitmproxy import http

OUT = os.environ.get("CAPTURE_OUT", "/tmp/antigravity-desktop-capture.jsonl")
ALLOW = (
    "streamGenerateContent",
    "generateContent",
    "fetchAvailableModels",
    "recordTrajectoryAnalytics",
    "/chat/completions",
    "/v1/models",
)
MAX_NODES = 500_000

CONFIG_TARGET_NORM = {
    "checkpointconfig",
    "cascadeconfig",
    "maxtokenlimit",
    "tokenlimit",
    "tokenthreshold",
    "contextwindow",
    "maxcontexttokens",
    "autocompact",
    "contextwindowcompression",
    "contextwindowcompressionconfig",
    "checkpointindex",
    "errorontruncationwithoutcheckpoint",
}


def _norm_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _coerce_scalar(val: Any) -> Any:
    if isinstance(val, (int, float, bool)):
        return val
    if isinstance(val, str):
        s = val.strip()
        if re.fullmatch(r"-?\d+", s):
            return int(s)
        if re.fullmatch(r"-?\d+\.\d+", s):
            return float(s)
    return None


def _sanitize_checkpoint_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only numeric/boolean/enum diagnostics; redact prompt strings."""
    safe: Dict[str, Any] = {}
    for k, v in cfg.items():
        scalar = _coerce_scalar(v)
        if scalar is not None:
            safe[k] = scalar
        elif k in ("strategy", "checkpointModel") and isinstance(v, str) and len(v) < 80:
            safe[k] = v
        elif isinstance(v, dict):
            safe[k] = {
                sk: _coerce_scalar(sv)
                for sk, sv in v.items()
                if _coerce_scalar(sv) is not None
            }
        elif isinstance(v, str):
            safe[k] = f"<redacted:{len(v)}B>"
    return safe


def _write(record: Dict[str, Any]) -> None:
    parent = os.path.dirname(os.path.abspath(OUT))
    if parent:
        os.makedirs(parent, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False, sort_keys=True)
    with open(OUT, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    os.chmod(OUT, 0o600)


def _find_config_keys(
    obj: Any, path: str = "", out: Optional[List[Dict[str, Any]]] = None,
    budget: Optional[List[int]] = None,
) -> List[Dict[str, Any]]:
    if out is None:
        out = []
    if budget is None:
        budget = [MAX_NODES]
    budget[0] -= 1
    if budget[0] <= 0:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else k
            if _norm_key(k) in CONFIG_TARGET_NORM:
                scalar = _coerce_scalar(v)
                if scalar is not None:
                    val: Any = scalar
                elif _norm_key(k) == "checkpointconfig" and isinstance(v, dict):
                    val = _sanitize_checkpoint_config(v)
                else:
                    val = f"<{type(v).__name__}>"
                out.append({"path": p, "key": k, "value": val})
            if isinstance(v, (dict, list)):
                _find_config_keys(v, p, out, budget)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, (dict, list)):
                _find_config_keys(v, f"{path}[{i}]", out, budget)
    return out


def _key_tree_full(
    obj: Any, out: Optional[Set[str]] = None, budget: Optional[List[int]] = None,
) -> Set[str]:
    if out is None:
        out = set()
    if budget is None:
        budget = [MAX_NODES]
    budget[0] -= 1
    if budget[0] <= 0:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(k)
            if isinstance(v, (dict, list)):
                _key_tree_full(v, out, budget)
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, (dict, list)):
                _key_tree_full(v, out, budget)
    return out


def _extract_sse_usage(text: str) -> Dict[str, Any]:
    resp_keys: Set[str] = set()
    last_usage: Optional[Dict[str, Any]] = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("data:"):
            line = line[5:].strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if not isinstance(ev, dict):
            continue
        _key_tree_full(ev, resp_keys)
        um = (
            ev.get("usageMetadata")
            or (ev.get("response") or {}).get("usageMetadata")
            or ev.get("usage")
        )
        if isinstance(um, dict):
            numeric_um = {
                uk: _coerce_scalar(uv)
                for uk, uv in um.items()
                if _coerce_scalar(uv) is not None
            }
            if numeric_um:
                last_usage = numeric_um
    return {
        "response_keys": sorted(resp_keys),
        "usage": last_usage,
    }


def response(flow: http.HTTPFlow) -> None:
    if not any(a in flow.request.path for a in ALLOW):
        return
    req_bytes = flow.request.raw_content or b""
    rec: Dict[str, Any] = {
        "ts": time.time(),
        "method": flow.request.method,
        "path": flow.request.path,
        "request_bytes": len(req_bytes),
        "status": flow.response.status_code if flow.response else None,
        "response_bytes": len(flow.response.raw_content or b"") if flow.response else None,
    }
    if req_bytes:
        try:
            req_obj = json.loads(req_bytes)
            if isinstance(req_obj, dict):
                rec["top_keys"] = list(req_obj.keys())
                rec["key_tree"] = sorted(_key_tree_full(req_obj))
                rec["config_matches"] = _find_config_keys(req_obj)
                if isinstance(req_obj.get("requestType"), str):
                    rec["requestType"] = req_obj["requestType"]
                if isinstance(req_obj.get("requestId"), str):
                    rec["requestId"] = req_obj["requestId"]
                if isinstance(req_obj.get("model"), str):
                    rec["model"] = req_obj["model"]
                if "max_completion_tokens" in req_obj:
                    rec["max_completion_tokens"] = _coerce_scalar(
                        req_obj.get("max_completion_tokens")
                    )
                inner = req_obj.get("request", req_obj)
                if isinstance(inner, dict) and isinstance(inner.get("contents"), list):
                    rec["contents_count"] = len(inner["contents"])
                if isinstance(req_obj.get("messages"), list):
                    rec["messages_count"] = len(req_obj["messages"])
        except Exception:
            rec["request_json_parsed"] = False

    if flow.response and flow.response.raw_content:
        txt = flow.response.get_text(strict=False) or ""
        sse = _extract_sse_usage(txt)
        if sse["response_keys"]:
            rec["response_keys"] = sse["response_keys"]
        if sse["usage"] is not None:
            rec["usage"] = sse["usage"]

    _write(rec)
