#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Live standalone engine check: verify `max_context_tokens` on Google OAuth.

Starts `language_server` in `--standalone` mode on a local loopback port (does
not launch or modify the Electron GUI), sends a short multi-turn conversation
through the engine's local Connect/HTTPS API on the Google OAuth native channel,
cleanly stops the engine with SIGTERM, and inspects the resulting SQLite session
database strictly read-only (`mode=ro` + `PRAGMA query_only=ON`).

What it does NOT do
-------------------
* Never patches or restores the binary (run `antigravity_context_unlock.py` first).
* Never launches `/opt/Antigravity/antigravity` (the Electron GUI).
* Never writes to `~/.gemini/antigravity/conversations/**` except via the engine's
  own normal session creation, and reads the resulting DB in `query_only` mode.

Examples
--------
    # Verify patched binary resolves max_context_tokens == 983040:
    python3 verify_live.py --expect 983040

    # Specify an outbound HTTP/HTTPS proxy explicitly:
    python3 verify_live.py --proxy http://127.0.0.1:2080 --expect 983040

    # Negative control (unpatched binary; expected max_context_tokens == 256000):
    python3 verify_live.py --expect 256000

Exit codes:
  0 = observed max_context_tokens matches expectation (or run succeeded without --expect)
  1 = mismatch, empty metadata, or RPC failure
  2 = invalid arguments or engine failed to start (e.g. port already in use)
"""
from __future__ import annotations

import argparse
import json
import os
import random
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from typing import Optional, Sequence, Tuple

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import antigravity_context_unlock as tool  # noqa: E402
import inspect_session  # noqa: E402

DEFAULT_MODEL = "MODEL_PLACEHOLDER_M318"  # Gemini 3.8 Flash (High)
WORDS = (
    "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo "
    "lima mike november oscar papa quebec romeo sierra tango uniform victor "
    "whiskey xray yankee zulu system kernel buffer packet stream socket "
    "thread mutex vector matrix tensor scalar harbor canyon meadow glacier"
).split()


def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def rpc(method: str, payload: dict, port: int, csrf: str, timeout: int) -> Tuple[int, str]:
    """Minimal Connect/JSON client for the engine's local loopback HTTPS API."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    url = f"https://127.0.0.1:{port}/exa.language_server_pb.LanguageServerService/{method}"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Connect-Protocol-Version": "1",
            "x-codeium-csrf-token": csrf,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        return 0, str(exc)


def filler(nbytes: int, seed: int) -> str:
    rnd = random.Random(seed)
    out, total = [], 0
    while total < nbytes:
        w = rnd.choice(WORDS)
        out.append(w)
        total += len(w) + 1
    return " ".join(out)


def build_parser() -> argparse.ArgumentParser:
    default_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or ""
    ap = argparse.ArgumentParser(
        prog="verify_live.py",
        description="Live standalone engine verification for Antigravity Desktop context budget.",
    )
    ap.add_argument(
        "--binary",
        default=tool.DEFAULT_BINARY,
        help=f"path to language_server binary (default: {tool.DEFAULT_BINARY})",
    )
    ap.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"model enum to test (default: {DEFAULT_MODEL} / Gemini 3.8 Flash High)",
    )
    ap.add_argument("--turns", type=int, default=2, help="number of turns to send (default: 2)")
    ap.add_argument("--kb", type=int, default=80, help="filler payload KiB per turn (default: 80)")
    ap.add_argument("--port", type=int, default=24560, help="local loopback HTTPS port (default: 24560)")
    ap.add_argument("--csrf", default="ctxunlock-verify-csrf", help="local loopback CSRF token")
    ap.add_argument(
        "--proxy",
        default=default_proxy,
        help="outbound HTTP/HTTPS proxy URL (default: inherit HTTPS_PROXY/HTTP_PROXY if set)",
    )
    ap.add_argument(
        "--expect",
        type=int,
        default=None,
        help="expected max_context_tokens (e.g. 983040 when patched, 256000 when pristine)",
    )
    ap.add_argument("--keep-engine", action="store_true", help="leave standalone engine running on exit")
    ap.add_argument("--timeout", type=int, default=600, help="per-turn RPC timeout in seconds")
    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.turns < 1:
        print("error: --turns must be >= 1", file=sys.stderr)
        return 2
    if args.kb < 1:
        print("error: --kb must be >= 1", file=sys.stderr)
        return 2
    if not (1 <= args.port <= 65535):
        print("error: --port must be in 1..65535", file=sys.stderr)
        return 2

    engine = os.path.abspath(os.path.expanduser(args.binary))
    print(f"engine : {engine}")
    print("state  : ", end="", flush=True)
    try:
        data, elf, syms = tool.load_binary(engine)
        site = tool.locate_site(data, elf, syms)
        print(site.state.upper())
    except Exception as exc:  # noqa: BLE001
        print(f"UNKNOWN ({exc})")
        return 1

    if port_open(args.port):
        print(
            f"error: port {args.port} already in use - stop the running engine or pass --port",
            file=sys.stderr,
        )
        return 2

    env = dict(os.environ)
    if args.proxy:
        env["HTTPS_PROXY"] = args.proxy
        env["HTTP_PROXY"] = args.proxy
    env["NO_PROXY"] = "127.0.0.1,localhost,::1"

    fd, log_path = tempfile.mkstemp(prefix="antigravity_verify_live_", suffix=".log")
    logfh = os.fdopen(fd, "wb")
    proc = subprocess.Popen(
        [
            engine,
            "--standalone",
            "--override_ide_name", "antigravity",
            "--subclient_type", "hub",
            "--override_ide_version", "2.31.0",
            "--override_user_agent_name", "antigravity",
            "--https_server_port", str(args.port),
            "--csrf_token", args.csrf,
            "--app_data_dir", "antigravity",
            "--api_server_url", "https://generativelanguage.googleapis.com",
            "--cloud_code_endpoint", "https://daily-cloudcode-pa.googleapis.com",
        ],
        env=env,
        stdout=logfh,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    print(f"engine : pid {proc.pid}, log {log_path}")

    cid: Optional[str] = None
    try:
        for _ in range(60):
            if port_open(args.port):
                break
            if proc.poll() is not None:
                print(f"error: engine exited early; see {log_path}", file=sys.stderr)
                return 2
            time.sleep(0.5)
        else:
            print("error: engine did not open its HTTPS port within 30s", file=sys.stderr)
            return 2
        print(f"port   : {args.port} ready")

        st, body = rpc(
            "StartCascade",
            {
                "source": "CORTEX_TRAJECTORY_SOURCE_CLI",
                "trajectoryType": "CASCADE_TRAJECTORY_TYPE_CASCADE",
                "requestedModel": args.model,
                "workspaceUris": ["file:///tmp"],
            },
            args.port,
            args.csrf,
            180,
        )
        if st != 200:
            print(f"error: StartCascade HTTP {st}: {body[:300]}", file=sys.stderr)
            return 1
        cid = json.loads(body)["cascadeId"]
        print(f"cascade: {cid}")

        for i in range(args.turns):
            text = (
                f"[LIVE CHECK TURN {i}] Acknowledge in one short sentence.\n"
                + filler(args.kb * 1024, i * 7919 + 13)
            )
            st, _ = rpc(
                "SendUserCascadeMessage",
                {
                    "cascadeId": cid,
                    "items": [{"text": text}],
                    "blocking": True,
                    "cascadeConfig": {"plannerConfig": {"planModel": args.model}},
                },
                args.port,
                args.csrf,
                args.timeout,
            )
            print(f"  turn {i}: http={st}")
            if st != 200:
                print("error: turn failed", file=sys.stderr)
                return 1
    finally:
        if not args.keep_engine:
            try:
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=15)
            except Exception:  # noqa: BLE001
                proc.kill()
            logfh.close()
            print("engine : stopped")

    assert cid is not None
    db_path = inspect_session.resolve(cid)
    info = None
    for _ in range(20):
        if os.path.exists(db_path):
            info = inspect_session.export(db_path)
            if info["rows"]:
                break
        time.sleep(0.5)
    if info is None:
        print(f"NO DATA : session DB never appeared ({db_path})", file=sys.stderr)
        return 1

    summary = inspect_session.summarise(info["rows"])
    maxctx = summary["maxctx_set"]
    print()
    print(f"rows     : {summary['rows']}")
    print(f"maxctx   : {maxctx}")
    print(f"checkpoint steps (type=23): {info['checkpoint_step_idx']}")
    print(f"est      : {summary['est_min']} .. {summary['est_max']}")

    if not info["rows"]:
        print(
            "NO DATA : session produced no gen_metadata rows; no budget observed.",
            file=sys.stderr,
        )
        return 1

    models = {(r.get("model"), r.get("model_enum")) for r in info["rows"]}
    print(f"models   : {models}")
    if not any(m == args.model or e == args.model for m, e in models):
        print(
            f"NO DATA : none of the rows belongs to {args.model} ({models})",
            file=sys.stderr,
        )
        return 1

    if args.expect is not None:
        ok = maxctx == [args.expect]
        print(f"expect   : {args.expect} -> {'MATCH' if ok else 'MISMATCH'}")
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
