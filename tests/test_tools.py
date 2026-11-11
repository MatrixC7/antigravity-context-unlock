#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline tests for `tools/inspect_session.py` and `verify_live.py`."""
from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import inspect_session  # noqa: E402
import verify_live  # noqa: E402


def _enc_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _enc_field_varint(field_no: int, val: int) -> bytes:
    return _enc_varint((field_no << 3) | 0) + _enc_varint(val)


def _enc_field_bytes(field_no: int, payload: bytes) -> bytes:
    return _enc_varint((field_no << 3) | 2) + _enc_varint(len(payload)) + payload


def _make_gen_metadata_blob(
    est: int,
    maxctx: int,
    reason: int = 0,
    model: str = "gemini-3.8-flash",
    model_enum: str = "MODEL_PLACEHOLDER_M318",
    last_step: str = "5",
) -> bytes:
    cwm = _enc_field_varint(1, est) + _enc_field_varint(4, maxctx)
    if reason != 0:
        cwm += _enc_field_varint(2, reason)
    chat_start = _enc_field_bytes(10, cwm)

    kv_enum = _enc_field_bytes(1, b"model_enum") + _enc_field_bytes(2, model_enum.encode())
    kv_step = _enc_field_bytes(1, b"last_step_index") + _enc_field_bytes(2, last_step.encode())

    chat = (
        _enc_field_varint(3, int(last_step))
        + _enc_field_bytes(9, chat_start)
        + _enc_field_bytes(19, model.encode())
        + _enc_field_bytes(20, kv_enum)
        + _enc_field_bytes(20, kv_step)
    )
    return _enc_field_bytes(1, chat)


class TestInspectSession(unittest.TestCase):
    def test_decode_proto3_default_reason_and_compaction_summary(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "session.db"
            con = sqlite3.connect(str(db_path))
            con.execute("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB, size INTEGER)")
            con.execute("CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, step_payload BLOB)")
            b0 = _make_gen_metadata_blob(est=426910, maxctx=256000, reason=0, last_step="28")
            b1 = _make_gen_metadata_blob(est=19162, maxctx=256000, reason=2, last_step="30")
            b2 = _make_gen_metadata_blob(est=51140, maxctx=256000, reason=0, last_step="32")
            con.executemany(
                "INSERT INTO gen_metadata (idx, data, size) VALUES (?, ?, ?)",
                [(0, b0, len(b0)), (1, b1, len(b1)), (2, b2, len(b2))],
            )
            con.execute(
                "INSERT INTO steps (idx, step_type, step_payload) VALUES (29, 23, ?)",
                (b"x" * 1024,),
            )
            con.commit()
            con.close()

            info = inspect_session.export(str(db_path))
            self.assertEqual(len(info["rows"]), 3)
            self.assertEqual(info["rows"][0]["reason"], 0)
            self.assertEqual(info["rows"][1]["reason"], 2)
            self.assertEqual(info["checkpoint_step_idx"], [29])
            self.assertEqual(info["checkpoint_steps"], [{"idx": 29, "payload_bytes": 1024}])

            s = inspect_session.summarise(info["rows"])
            self.assertEqual(s["maxctx_set"], [256000])
            self.assertEqual(s["compactions"], 1)
            self.assertEqual(s["first_compaction_row"], 1)
            self.assertEqual(s["pre_compaction_est"], [426910])
            self.assertEqual(s["post_compaction_est"], [19162])

    def test_missing_steps_table_raises_instead_of_fabricating_zero(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "incomplete.db"
            con = sqlite3.connect(str(db_path))
            con.execute("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB)")
            con.commit()
            con.close()

            self.assertEqual(inspect_session.main([str(db_path)]), 1)


class TestVerifyLiveValidation(unittest.TestCase):
    def test_invalid_turns_rejected(self):
        self.assertEqual(verify_live.main(["--turns", "0"]), 2)

    def test_invalid_kb_rejected(self):
        self.assertEqual(verify_live.main(["--kb", "0"]), 2)

    def test_invalid_port_rejected(self):
        self.assertEqual(verify_live.main(["--port", "70000"]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
