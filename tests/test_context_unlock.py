#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline unit tests for antigravity_context_unlock.

These tests never modify the installed engine binary. They construct a synthetic
Go 1.18+ ELF64 fixture (valid pclntab + a byte-for-byte copy of the real
`utils.ClampCheckpointConfigForModelInfo` body) in a temporary directory and
exercise locate/patch/verify/restore and fail-closed safety invariants.

Run:
    python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import antigravity_context_unlock as tool  # noqa: E402

REAL_BINARY = tool.DEFAULT_BINARY

# Exact 128-byte body of `utils.ClampCheckpointConfigForModelInfo` from the
# verified build (`CL 1017595969` / `antigravity 2.31.0-1`).
CLAMP_BODY = bytes.fromhex(
    "4885c074644885db745f83780c00751c486353144881fa409c00007f0531d290"
    "eb074881c2c063ffff89500c8b531485d27e1589d629ca39f10f42f20f1f4000"
    "39700c760389700c488b48504885c9741780390074128b4b7085c97e0b8b5010"
    "39ca0f47d1895010c3c3cccccccccccccccccccccccccccccccccccccccccccc"
)


class SyntheticELF:
    """Minimal valid Go 1.18+ ELF64 image containing one patchable function."""

    TEXT_VA = 0x1000
    NFUNC = 1200

    def __init__(self, body: bytes, func_name: str):
        self.body = body
        self.func_name = func_name

    def build(self) -> bytes:
        body = self.body
        text_off = self.TEXT_VA
        target_entryoff = 0
        nfunc = self.NFUNC

        filler_base = len(body)
        filler_stride = 16
        filler_region_end = filler_base + (nfunc - 1) * filler_stride + filler_stride
        pcln_off = text_off + filler_region_end + 0x40

        funcname_off = 72
        names = bytearray()
        name_offsets = []
        for i in range(nfunc):
            name_offsets.append(len(names))
            names += (self.func_name if i == 0 else f"pkg.filler{i}").encode() + b"\0"
        pcln_table_off = funcname_off + len(names)

        functab_size = (nfunc + 1) * 8
        recs = bytearray()
        pairs = []
        filler_region = filler_base + (nfunc - 1) * filler_stride
        for i in range(nfunc):
            eo = target_entryoff if i == 0 else filler_base + (i - 1) * filler_stride
            funcoff = functab_size + len(recs)
            pairs.append(struct.pack("<II", eo, funcoff))
            recs += struct.pack("<Ii", eo, name_offsets[i]) + b"\0" * 16
        pairs.append(struct.pack("<II", filler_region, functab_size + len(recs) - 24))

        pcln = bytearray()
        pcln += struct.pack("<I", 0xFFFFFFF1)
        pcln += b"\x00\x00"
        pcln += bytes([1, 8])
        pcln += struct.pack("<Q", nfunc)
        pcln += struct.pack("<Q", 1)
        pcln += struct.pack("<Q", self.TEXT_VA)
        pcln += struct.pack("<Q", funcname_off)
        pcln += struct.pack("<Q", 0)
        pcln += struct.pack("<Q", 0)
        pcln += struct.pack("<Q", 0)
        pcln += struct.pack("<Q", pcln_table_off)
        assert len(pcln) == funcname_off, len(pcln)
        pcln += names
        for pair in pairs:
            pcln += pair
        pcln += recs

        size = pcln_off + len(pcln) + 0x100
        buf = bytearray(size)

        buf[0:4] = b"\x7fELF"
        buf[4] = 2
        buf[5] = 1
        buf[6] = 1
        struct.pack_into("<H", buf, 16, 2)
        struct.pack_into("<H", buf, 18, 0x3E)
        struct.pack_into("<Q", buf, 24, self.TEXT_VA)
        phoff = 64
        struct.pack_into("<Q", buf, 32, phoff)
        struct.pack_into("<Q", buf, 40, 0)
        struct.pack_into("<H", buf, 52, 64)
        struct.pack_into("<H", buf, 54, 56)
        struct.pack_into("<H", buf, 56, 1)

        struct.pack_into("<IIQQQQQQ", buf, phoff, 1, 7, 0, 0, 0, size, size, 0x1000)

        buf[text_off:text_off + len(body)] = body
        for i in range(1, nfunc):
            off = text_off + filler_base + (i - 1) * filler_stride
            if off + 1 <= len(buf):
                buf[off:off + 1] = b"\xc3"
        buf[pcln_off:pcln_off + len(pcln)] = pcln
        return bytes(buf)


class TestLocateAndPatch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ctxunlock-test-")
        self.path = os.path.join(self.tmp, "language_server")
        image = SyntheticELF(CLAMP_BODY, "utils.ClampCheckpointConfigForModelInfo").build()
        with open(self.path, "wb") as fh:
            fh.write(image)

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.unlink(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def test_self_test_runs(self):
        rc = tool.main(["self-test", "--binary", self.path])
        self.assertEqual(rc, 0)

    def test_locate_finds_pristine_site(self):
        data, elf, syms = tool.load_binary(self.path)
        site = tool.locate_site(data, elf, syms)
        self.assertEqual(site.state, "pristine")
        self.assertEqual(bytes(data[site.offset:site.offset + 8]), tool.ORIGINAL_SITE)

    def test_patch_then_verify_then_restore(self):
        with open(self.path, "rb") as fh:
            original = fh.read()

        rc = tool.main(["patch", "--binary", self.path, "--yes"])
        self.assertEqual(rc, 0)

        data, elf, syms = tool.load_binary(self.path)
        site = tool.locate_site(data, elf, syms)
        self.assertEqual(site.state, "patched")
        self.assertEqual(bytes(data[site.offset:site.offset + 8]), tool.PATCH_PHYSICAL_MAX)

        self.assertEqual(tool.main(["verify", "--binary", self.path]), 0)

        with open(self.path, "rb") as fh:
            once = fh.read()
        self.assertEqual(tool.main(["patch", "--binary", self.path, "--yes"]), 0)
        with open(self.path, "rb") as fh:
            self.assertEqual(fh.read(), once)

        self.assertEqual(tool.main(["restore", "--binary", self.path, "--yes"]), 0)
        with open(self.path, "rb") as fh:
            self.assertEqual(fh.read(), original)

    def test_dry_run_does_not_write(self):
        with open(self.path, "rb") as fh:
            before = fh.read()
        rc = tool.main(["patch", "--binary", self.path])
        self.assertEqual(rc, 2)
        with open(self.path, "rb") as fh:
            self.assertEqual(fh.read(), before)

    def test_rejects_unknown_build(self):
        with open(self.path, "rb") as fh:
            img = bytearray(fh.read())
        i = img.find(tool.ORIGINAL_SITE)
        self.assertGreater(i, 0)
        img[i:i + 8] = b"\x0f\x0b" * 4
        with open(self.path, "wb") as fh:
            fh.write(bytes(img))
        rc = tool.main(["self-test", "--binary", self.path])
        self.assertEqual(rc, 3)

    def test_restore_refuses_patched_backup(self):
        tool.main(["patch", "--binary", self.path, "--yes"])
        backup = self.path + tool.BACKUP_SUFFIX
        with open(self.path, "rb") as fh:
            patched = fh.read()
        with open(backup, "wb") as fh:
            fh.write(patched)
        self.assertEqual(tool.main(["restore", "--binary", self.path, "--yes"]), 1)


class TestPatchBytes(unittest.TestCase):
    def test_replacement_lengths_match(self):
        self.assertEqual(len(tool.ORIGINAL_SITE), 8)
        self.assertEqual(len(tool.PATCH_PHYSICAL_MAX), 8)
        self.assertEqual(len(tool.SITE_PREFIX), 30)
        self.assertEqual(len(tool.SITE_SUFFIX), 21)
        self.assertEqual(
            len(tool.CONTEXT_PRISTINE),
            len(tool.SITE_PREFIX) + 8 + len(tool.SITE_SUFFIX),
        )
        self.assertEqual(len(tool.CONTEXT_PATCHED), len(tool.CONTEXT_PRISTINE))
        self.assertEqual(tool.SITE_IN_CONTEXT, len(tool.SITE_PREFIX))

    def test_physical_max_semantics(self):
        self.assertEqual(tool.PATCH_PHYSICAL_MAX[:3], b"\x89\x70\x0c")
        self.assertEqual(tool.PATCH_PHYSICAL_MAX[3:5], b"\xeb\x03")

    def test_context_is_prefix_plus_site_plus_suffix(self):
        self.assertEqual(
            tool.CONTEXT_PRISTINE,
            tool.SITE_PREFIX + tool.ORIGINAL_SITE + tool.SITE_SUFFIX,
        )
        self.assertEqual(
            tool.CONTEXT_PATCHED,
            tool.SITE_PREFIX + tool.PATCH_PHYSICAL_MAX + tool.SITE_SUFFIX,
        )

    def test_context_is_unique_in_both_states(self):
        backup = tool.DEFAULT_BINARY + tool.BACKUP_SUFFIX
        if not os.path.exists(backup):
            self.skipTest("no pristine backup to check against")
        with open(backup, "rb") as fh:
            pristine = fh.read()
        with open(tool.DEFAULT_BINARY, "rb") as fh:
            current = fh.read()
        self.assertEqual(pristine.count(tool.CONTEXT_PRISTINE), 1)
        self.assertEqual(pristine.count(tool.CONTEXT_PATCHED), 0)
        self.assertLessEqual(
            current.count(tool.CONTEXT_PRISTINE) + current.count(tool.CONTEXT_PATCHED),
            1,
        )


class TestFailClosed(unittest.TestCase):
    """Negative tests ensuring invalid or ambiguous inputs fail closed."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ctxunlock-neg-")
        self.path = os.path.join(self.tmp, "language_server")
        self.backup = self.path + tool.BACKUP_SUFFIX

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.unlink(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def _image(self, body: bytes) -> bytes:
        return SyntheticELF(body, tool.CLAMP_FUNC).build()

    def _write(self, data: bytes) -> bytes:
        with open(self.path, "wb") as fh:
            fh.write(data)
        return data

    def _read(self) -> bytes:
        with open(self.path, "rb") as fh:
            return fh.read()

    def test_signature_inside_immediate_is_rejected(self):
        data = self._write(self._image(b"\x48\xb8" + tool.ORIGINAL_SITE + b"\xc3\x90"))
        self.assertEqual(tool.main(["patch", "--binary", self.path, "--yes"]), 3)
        self.assertEqual(self._read(), data)
        self.assertFalse(os.path.exists(self.backup))

    def test_duplicate_original_signature_rejected(self):
        body = (
            CLAMP_BODY[:8] + tool.CONTEXT_PRISTINE
            + CLAMP_BODY[8:16] + tool.CONTEXT_PRISTINE
            + CLAMP_BODY[16:]
        )
        data = self._write(self._image(body))
        self.assertEqual(tool.main(["patch", "--binary", self.path, "--yes"]), 3)
        self.assertEqual(self._read(), data)

    def test_mixed_state_rejected(self):
        body = (
            CLAMP_BODY[:8] + tool.CONTEXT_PATCHED
            + CLAMP_BODY[8:16] + tool.CONTEXT_PRISTINE
            + CLAMP_BODY[16:]
        )
        data = self._write(self._image(body))
        self.assertNotEqual(tool.main(["verify", "--binary", self.path]), 0)
        self.assertEqual(tool.main(["patch", "--binary", self.path, "--yes"]), 3)
        self.assertEqual(self._read(), data)

    def test_truncated_elf_fails_closed(self):
        data = self._write(b"\x7fELF")
        self.assertEqual(tool.main(["patch", "--binary", self.path, "--yes"]), 3)
        self.assertEqual(self._read(), data)
        self.assertFalse(os.path.exists(self.backup))

    def test_missing_symbol_rejected(self):
        data = self._write(
            self._image(CLAMP_BODY).replace(
                tool.CLAMP_FUNC.encode(), b"pkg.UnrelatedFunction" + b"\0" * 4, 1
            )
        )
        self.assertEqual(tool.main(["patch", "--binary", self.path, "--yes"]), 3)
        self.assertEqual(self._read(), data)

    def test_stale_backup_from_other_build_not_reused(self):
        good = self._image(CLAMP_BODY)
        other = good + b"new-build"
        self._write(other)
        with open(self.backup, "wb") as fh:
            fh.write(good)
        self.assertEqual(tool.main(["patch", "--binary", self.path, "--yes"]), 3)
        self.assertEqual(self._read(), other)

    def test_restore_refuses_unpaired_backup(self):
        good = self._image(CLAMP_BODY)
        other = good + b"new-build"
        self._write(other)
        with open(self.backup, "wb") as fh:
            fh.write(good)
        self.assertEqual(tool.main(["restore", "--binary", self.path, "--yes"]), 3)
        self.assertEqual(self._read(), other)

    def test_restore_rejects_corrupt_backup(self):
        self._write(self._image(CLAMP_BODY))
        with open(self.backup, "wb") as fh:
            fh.write(b"not an elf at all")
        self.assertEqual(tool.main(["restore", "--binary", self.path, "--yes"]), 3)

    def test_cap_option_removed(self):
        self._write(self._image(CLAMP_BODY))
        with self.assertRaises(SystemExit) as ctx:
            tool.main(["patch", "--binary", self.path, "--yes", "--cap", "900000"])
        self.assertEqual(ctx.exception.code, 2)

    def test_strict_build_rejects_unlisted(self):
        self._write(self._image(CLAMP_BODY))
        self.assertEqual(
            tool.main(["patch", "--binary", self.path, "--yes", "--strict-build"]),
            3,
        )


class TestBackupGuarantees(unittest.TestCase):
    """Backup existence, sidecar integrity, and single-snapshot restore guarantees."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ctxunlock-bk-")
        self.path = os.path.join(self.tmp, "engine")
        self.backup = self.path + tool.BACKUP_SUFFIX
        self.meta = self.path + tool.BACKUP_SUFFIX + ".json"
        self.pristine = SyntheticELF(CLAMP_BODY, tool.CLAMP_FUNC).build()
        self.patched = self.pristine.replace(tool.CONTEXT_PRISTINE, tool.CONTEXT_PATCHED)

    def tearDown(self):
        for name in os.listdir(self.tmp):
            p = os.path.join(self.tmp, name)
            if os.path.islink(p) or os.path.isfile(p):
                os.unlink(p)
        os.rmdir(self.tmp)

    def _write(self, path: str, data):
        if isinstance(data, str):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(data)
            return
        with open(path, "wb") as fh:
            fh.write(data)

    def _read(self, path: str) -> bytes:
        with open(path, "rb") as fh:
            return fh.read()

    def test_dangling_backup_blocks_patch(self):
        self._write(self.path, self.pristine)
        os.symlink(os.path.join(self.tmp, "absent"), self.backup)
        self.assertEqual(tool.main(["patch", "--binary", self.path, "--yes"]), 3)
        self.assertEqual(self._read(self.path), self.pristine)

    def test_wrong_build_backup_blocks_patch(self):
        self._write(self.path, self.pristine)
        self._write(self.backup, self.pristine + b"other-build")
        self.assertEqual(tool.main(["patch", "--binary", self.path, "--yes"]), 3)
        self.assertEqual(self._read(self.path), self.pristine)

    def test_bad_sidecar_blocks_patch(self):
        self._write(self.path, self.pristine)
        self._write(self.backup, self.pristine)
        self._write(self.meta, '{"original_sha256": "deadbeef"}')
        self.assertEqual(tool.main(["patch", "--binary", self.path, "--yes"]), 3)
        self.assertEqual(self._read(self.path), self.pristine)

    def test_patch_creates_usable_backup(self):
        self._write(self.path, self.pristine)
        self.assertEqual(tool.main(["patch", "--binary", self.path, "--yes"]), 0)
        self.assertEqual(self._read(self.backup), self.pristine)
        self.assertTrue(os.path.exists(self.meta))

    def test_restore_uses_single_snapshot(self):
        other = self.pristine + b"other-build"
        self._write(self.path, other.replace(tool.CONTEXT_PRISTINE, tool.CONTEXT_PATCHED))
        self.assertNotEqual(self._read(self.path), self.patched)
        self._write(self.backup, self.pristine)
        self._write(self.meta, json.dumps({"original_sha256": tool._sha256(self.pristine)}))

        real_read = tool.read_file
        calls = {"n": 0}

        def swap_before_second_read(path):
            if os.path.abspath(path) == os.path.abspath(self.backup):
                calls["n"] += 1
                if calls["n"] == 2:
                    self._write(self.backup, other)
            return real_read(path)

        with mock.patch.object(tool, "read_file", side_effect=swap_before_second_read):
            rc = tool.main(["restore", "--binary", self.path, "--yes"])
        self.assertEqual(rc, 3)
        self.assertNotEqual(self._read(self.path), self.pristine)

    def test_restore_refuses_when_target_changes_after_pairing(self):
        self._write(self.path, self.patched)
        self._write(self.backup, self.pristine)
        real_pair = tool._pairs_with

        def pair_then_upgrade(*a, **kw):
            result = real_pair(*a, **kw)
            upgraded = os.path.join(self.tmp, "upgraded")
            self._write(upgraded, self.pristine + b"other-build")
            os.replace(upgraded, self.path)
            return result

        with mock.patch.object(tool, "_pairs_with", side_effect=pair_then_upgrade):
            rc = tool.main(["restore", "--binary", self.path, "--yes"])
        self.assertEqual(rc, 3)

    def test_repeated_restore_is_idempotent(self):
        self._write(self.path, self.pristine)
        self.assertEqual(tool.main(["patch", "--binary", self.path, "--yes"]), 0)
        self.assertEqual(tool.main(["restore", "--binary", self.path, "--yes"]), 0)
        self.assertEqual(tool.main(["restore", "--binary", self.path, "--yes"]), 0)
        self.assertEqual(self._read(self.path), self.pristine)

    def test_malformed_sidecar_does_not_crash(self):
        self._write(self.path, self.pristine)
        self.assertEqual(tool.main(["patch", "--binary", self.path, "--yes"]), 0)
        self._write(self.meta, "[1]")
        self.assertEqual(tool.main(["restore", "--binary", self.path, "--yes"]), 0)
        self.assertEqual(self._read(self.path), self.pristine)

    def test_full_window_must_be_inside_function(self):
        data = bytearray(
            SyntheticELF(tool.CONTEXT_PRISTINE + b"\xc3", tool.CLAMP_FUNC).build()
        )
        sy = tool.GoSymbols(tool.ELFFile(bytes(data)))
        struct.pack_into("<I", data, sy.pcln_off, 1)
        struct.pack_into("<I", data, sy.pcln_off + sy.find(tool.CLAMP_FUNC).funcoff, 1)
        self._write(self.path, bytes(data))
        self.assertEqual(tool.main(["patch", "--binary", self.path, "--yes"]), 3)
        self.assertEqual(self._read(self.path), bytes(data))

    def test_self_test_honours_strict_build(self):
        self._write(self.path, self.pristine)
        self.assertEqual(
            tool.main(["self-test", "--binary", self.path, "--strict-build"]),
            3,
        )


@unittest.skipUnless(os.path.exists(REAL_BINARY), "real engine binary not present")
class TestRealBinaryRoundTrip(unittest.TestCase):
    """Whole-file hash round trip on an isolated temporary copy."""

    def test_round_trip(self):
        def sha(p: str) -> str:
            with open(p, "rb") as fh:
                return hashlib.sha256(fh.read()).hexdigest()

        with tempfile.TemporaryDirectory(prefix="ctxunlock-real-") as d:
            p = os.path.join(d, "language_server")
            backup = p + tool.BACKUP_SUFFIX
            src = REAL_BINARY + tool.BACKUP_SUFFIX
            if not os.path.exists(src):
                src = REAL_BINARY
                with open(src, "rb") as fh:
                    raw = fh.read()
                _, elf, syms = tool.load_binary(src)
                if tool.locate_site(raw, elf, syms).state != "pristine":
                    self.skipTest("no pristine binary or backup available to seed copy")
            shutil.copy2(src, p)
            before = sha(p)
            self.assertEqual(tool.main(["patch", "--binary", p, "--yes"]), 0)
            patched = sha(p)
            self.assertNotEqual(patched, before)
            self.assertEqual(sha(backup), before)
            self.assertEqual(tool.main(["restore", "--binary", p, "--yes"]), 0)
            self.assertEqual(sha(p), before)


@unittest.skipUnless(os.path.exists(REAL_BINARY), "real engine binary not present")
class TestRealBinaryReadOnly(unittest.TestCase):
    """Read-only checks against the installed binary."""

    def test_real_binary_self_test(self):
        data, elf, syms = tool.load_binary(REAL_BINARY)
        fn = syms.find(tool.CLAMP_FUNC)
        self.assertGreater(fn.end, fn.va)

        n_orig = data.count(tool.ORIGINAL_SITE)
        n_patch = data.count(tool.PATCH_PHYSICAL_MAX)
        self.assertIn(
            (n_orig, n_patch),
            {(1, 0), (0, 1)},
            f"ambiguous patch state: pristine={n_orig} patched={n_patch}",
        )

        site = tool.locate_site(data, elf, syms)
        self.assertEqual(site.state, "pristine" if n_orig else "patched")
        self.assertEqual(
            bytes(data[site.offset:site.offset + 8]),
            tool.ORIGINAL_SITE if n_orig else tool.PATCH_PHYSICAL_MAX,
        )

    def test_embedded_profiles_parse(self):
        data, _, _ = tool.load_binary(REAL_BINARY)
        prof = tool.embedded_profiles(data)
        self.assertIsNotNone(prof)
        mp = prof["model_profiles"]
        self.assertIn("MODEL_PLACEHOLDER_M124", mp)
        self.assertIn("MODEL_PLACEHOLDER_M408", mp)


if __name__ == "__main__":
    unittest.main(verbosity=2)
