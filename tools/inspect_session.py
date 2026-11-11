#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Read-only SQLite session inspector for Antigravity Desktop conversations.

Decodes numeric diagnostics from `~/.gemini/antigravity/conversations/<uuid>.db`:
  - `gen_metadata` protobuf blobs (`ChatStartMetadata.ContextWindowMetadata`):
    `estimated_tokens_used` (`est`), `truncation_reason` (`reason`),
    `max_context_tokens` (`maxctx`), model identifier, `model_enum`,
    `request_id`, and `last_step_index`.
  - `steps` table: indices and payload byte lengths of `step_type = 23`
    local Checkpoint steps.

Strictly read-only: opens SQLite via a `mode=ro` URI with `PRAGMA query_only=ON`.
Message text and conversation contents are never read or printed.

Usage:
    python3 tools/inspect_session.py <cascadeId|path-to-db> [--rows] [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

CONV_DIR = os.path.expanduser("~/.gemini/antigravity/conversations")


# ---------------------------------------------------------------------------
# Minimal protobuf wire-format reader (standard library only)
# ---------------------------------------------------------------------------

def _varint(buf: bytes, pos: int) -> Tuple[int, int]:
    val = 0
    shift = 0
    for _ in range(10):
        if pos >= len(buf):
            raise ValueError("truncated varint")
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, pos
        shift += 7
    raise ValueError("varint overflow")


def parse_wire(buf: bytes) -> List[Tuple[int, str, Any]]:
    pos = 0
    out: List[Tuple[int, str, Any]] = []
    while pos < len(buf):
        try:
            key, pos = _varint(buf, pos)
        except ValueError:
            return out
        field_no = key >> 3
        wire_type = key & 0x7
        if field_no == 0:
            return out
        if wire_type == 0:
            try:
                v, pos = _varint(buf, pos)
            except ValueError:
                return out
            out.append((field_no, "v", v))
        elif wire_type == 1:
            if pos + 8 > len(buf):
                return out
            out.append((field_no, "d", buf[pos:pos + 8]))
            pos += 8
        elif wire_type == 2:
            try:
                length, pos = _varint(buf, pos)
            except ValueError:
                return out
            if pos + length > len(buf):
                return out
            out.append((field_no, "b", buf[pos:pos + length]))
            pos += length
        elif wire_type == 5:
            if pos + 4 > len(buf):
                return out
            out.append((field_no, "f", buf[pos:pos + 4]))
            pos += 4
        else:
            return out
    return out


def _get_one(buf: bytes, field_no: int) -> Optional[Tuple[str, Any]]:
    for f, w, v in parse_wire(buf):
        if f == field_no:
            return w, v
    return None


def _get_all(buf: bytes, field_no: int) -> List[Tuple[str, Any]]:
    return [(w, v) for f, w, v in parse_wire(buf) if f == field_no]


def _decode_str(val: Any) -> Any:
    return val.decode("utf-8", "replace") if isinstance(val, bytes) else val


def decode_gen_metadata_row(blob: bytes) -> Optional[Dict[str, Any]]:
    """Decode numeric ContextWindowMetadata and non-sensitive step labels."""
    chat = _get_one(blob, 1)
    if not chat or chat[0] != "b":
        return None
    c = chat[1]
    out: Dict[str, Any] = {}

    step_idx = _get_one(c, 3)
    out["step_index"] = step_idx[1] if step_idx else None

    g9 = _get_one(c, 9)
    if g9 and g9[0] == "b":
        for f, w, v in parse_wire(g9[1]):
            if f == 10 and w == "b":
                for ff, _ww, vv in parse_wire(v):
                    if ff == 1:
                        out["est"] = vv
                    elif ff == 2:
                        out["trunc"] = vv
                    elif ff == 4:
                        out["maxctx"] = vv

    model_entry = _get_one(c, 19)
    if model_entry:
        out["model"] = _decode_str(model_entry[1])

    labels: Dict[str, Any] = {}
    for w, v in _get_all(c, 20):
        if w != "b":
            continue
        kv: Dict[str, Any] = {}
        for ff, _ww, vv in parse_wire(v):
            if ff == 1:
                kv["k"] = _decode_str(vv)
            elif ff == 2:
                kv["v"] = _decode_str(vv)
        if "k" in kv:
            labels[kv["k"]] = kv.get("v")
    out["labels"] = labels
    return out


# ---------------------------------------------------------------------------
# Read-only SQLite inspection
# ---------------------------------------------------------------------------

def resolve(arg: str) -> str:
    if arg.endswith(".db") or os.path.sep in arg:
        return os.path.abspath(os.path.expanduser(arg))
    return os.path.join(CONV_DIR, arg + ".db")


def open_ro(path: str) -> sqlite3.Connection:
    if not os.path.exists(path):
        raise FileNotFoundError(f"no such DB: {path}")
    con = sqlite3.connect("file:" + path + "?mode=ro", uri=True, timeout=10)
    con.execute("PRAGMA query_only=ON")
    return con


def export(path: str) -> Dict[str, Any]:
    con = open_ro(path)
    try:
        rows: List[Dict[str, Any]] = []
        for idx, data in con.execute(
            "SELECT idx, data FROM gen_metadata ORDER BY idx"
        ):
            info = decode_gen_metadata_row(data) if data is not None else None
            if info is None:
                rows.append({
                    "idx": idx,
                    "est": None,
                    "reason": None,
                    "maxctx": None,
                    "last_step": None,
                    "model": None,
                    "model_enum": None,
                    "request_id": None,
                })
                continue
            labels = info.get("labels") or {}
            # In proto3, absent field 2 (`truncation_reason`) defaults to 0.
            rows.append({
                "idx": idx,
                "est": info.get("est"),
                "reason": info.get("trunc", 0) or 0,
                "maxctx": info.get("maxctx"),
                "last_step": labels.get("last_step_index", info.get("step_index")),
                "model": info.get("model"),
                "model_enum": labels.get("model_enum"),
                "request_id": labels.get("request_id"),
            })

        # `step_type == 23` marks local Checkpoint summary steps. A missing
        # `steps` table is an error rather than silent "zero checkpoints".
        try:
            cps = [
                {"idx": r[0], "payload_bytes": r[1]}
                for r in con.execute(
                    "SELECT idx, length(step_payload) FROM steps "
                    "WHERE step_type=23 ORDER BY idx"
                )
            ]
        except sqlite3.Error as exc:
            raise RuntimeError(f"cannot read checkpoint steps from {path}: {exc}") from exc

        return {
            "path": path,
            "rows": rows,
            "checkpoint_step_idx": [c["idx"] for c in cps],
            "checkpoint_steps": cps,
        }
    finally:
        con.close()


def summarise(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    ests = [r["est"] for r in rows if r.get("est") is not None]
    comp = [
        (i, rows[i - 1]["est"] if i else None, r["est"])
        for i, r in enumerate(rows)
        if r.get("reason") == 2
    ]
    return {
        "rows": len(rows),
        "maxctx_set": sorted({r["maxctx"] for r in rows if r.get("maxctx") is not None}),
        "compactions": len(comp),
        "first_compaction_row": comp[0][0] if comp else None,
        "pre_compaction_est": [c[1] for c in comp],
        "post_compaction_est": [c[2] for c in comp],
        "est_min": min(ests) if ests else None,
        "est_max": max(ests) if ests else None,
        "est_last": ests[-1] if ests else None,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="inspect_session.py",
        description="Read-only SQLite session inspector for Antigravity Desktop.",
    )
    ap.add_argument("session", help="conversation UUID or path to <uuid>.db")
    ap.add_argument("--rows", action="store_true", help="print per-row token diagnostics")
    ap.add_argument("--json", action="store_true", help="emit JSON output")
    args = ap.parse_args(argv)

    try:
        path = resolve(args.session)
        data = export(path)
    except (FileNotFoundError, RuntimeError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    data["summary"] = summarise(data["rows"])
    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0

    s = data["summary"]
    print(f"DB        : {path}")
    print(f"rows      : {s['rows']}")
    print(f"maxctx set: {s['maxctx_set']}")
    print(
        f"compactions (reason=2): {s['compactions']}"
        + (f"  first at row {s['first_compaction_row']}" if s["compactions"] else "")
    )
    print(f"checkpoint steps (type=23): {data['checkpoint_step_idx']}")
    print(f"est range : {s['est_min']} .. {s['est_max']}  (last={s['est_last']})")
    for i, pre, post in zip(
        range(s["compactions"]), s["pre_compaction_est"], s["post_compaction_est"]
    ):
        print(f"  compaction #{i}: pre_est={pre}  post_est={post}")
    if args.rows:
        for r in data["rows"]:
            print(
                f"  idx={r['idx']:>4} est={str(r['est']):>8} reason={r['reason']}"
                f" maxctx={r['maxctx']} last_step={r['last_step']}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
