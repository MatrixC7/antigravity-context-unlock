#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""antigravity-context-unlock: unlock >256K context budget in Antigravity Desktop.

Target
------
`/opt/Antigravity/resources/bin/language_server` - the Go ELF64 PIE inference
and orchestration engine shipped with the Antigravity desktop application.
This is **not** the standalone CLI (`antigravity-cli` / `/usr/bin/agy`); the two
binaries have distinct configuration paths and share no patch sites.

Verified mechanism (see docs/ for the full evidence chain)
----------------------------------------------------------
1. Context auto-compaction in Antigravity Desktop is initiated **locally by the
   `language_server` engine** (`checkpoint.shouldCheckpoint` /
   `checkpoint.MaybeCreateCheckpoint`), not enforced as a 256K cap on main
   generation requests by the upstream API. When the hybrid token count exceeds
   `CheckpointConfig.MaxTokenLimit`, the engine issues a separate
   `requestType: "checkpoint"` continuation-summary request, records a
   `step_type = 23` step in SQLite, and replaces older conversation history.
2. On the **Google OAuth native channel**, the engine assembles
   `CheckpointConfig` along this call chain:

       cortex.(*CascadeManager).getCascadeConfig
         -> config.GetCascadeConversationalConfigWithExperiment
              -> config.augmentConversationalConfigWithExperiment
                   -> config.applyFeatureProviderCheckpointOverrideConfig
                        -> config.resolveDefaultCheckpointConfig
                             -> utils.GetCheckpointConfigForModelInfo
                                  -> utils.GetCheckpointConfig          (ceiling 1)
                                       -> utils.GetDefaultCheckpointConfigForModel
                        -> config.selectCheckpointExperimentKey
                        -> config.MergeConfigsDedup                     (policy merge)
              -> config.clampAndValidateConfig
                   -> utils.ClampCheckpointConfigForModelInfo           (patched here)

   Two mechanisms pin Google-native models at 256,000 tokens:
   - `utils.GetCheckpointConfig` applies `min(x, 256000)` for `apiProvider`
     3 / 24 / 26 (Vertex, Google Gemini, Anthropic Vertex).
   - `config.MergeConfigsDedup` merges the per-model
     `CASCADE_USE_EXPERIMENT_CHECKPOINTER` policy (`"max_token_limit": "256000"`),
     after which `config.clampAndValidateConfig` calls
     `utils.ClampCheckpointConfigForModelInfo`.

   Note: Enterprise Gateway models (`apiProvider = 31`) already bypass the 256K
   clamp natively (computing `MaxTokens - max(40000, MaxOutputTokens)`, e.g.
   872,000) and do not require binary patching.

What the 8-byte binary patch does
---------------------------------
`utils.ClampCheckpointConfigForModelInfo` computes the model's physical upper
bound `esi = ctx - maxOutputTokens` (when `0 < maxOutputTokens < ctx`) and
normally writes `[rax+0xc]` (`CheckpointConfig.MaxTokenLimit`) only when the
existing limit exceeds `esi`. Rewriting **8 bytes** (5 changed byte values) at
that conditional store turns it into an **unconditional store** of `esi`:

    39 70 0c 76 03 89 70 0c   cmp [rax+0xc], esi ; jbe .done ; mov [rax+0xc], esi
 -> 89 70 0c eb 03 90 90 90   mov [rax+0xc], esi ; jmp .done ; nop ; nop ; nop

Because the patch modifies the function body, both calls to
`ClampCheckpointConfigForModelInfo` (pre-merge and post-merge) execute it; the
post-merge call inside `clampAndValidateConfig` overrides the 256,000 policy
limit with `MaxTokens - MaxOutputTokens` (e.g. `1,048,576 - 65,536 = 983,040`
for Gemini 3.8 Flash). No immediate constant is hardcoded, all other
`CheckpointConfig` fields (`use_model_reported_token_count`, `token_threshold`,
`strategy`, `is_sync`) remain untouched, and `ValidateCheckpointConfigForModelInfo`
passes cleanly for standard models (`maxOutputTokens < maxTokens`).

Safety guarantees
-----------------
* Symbols are resolved dynamically from the Go 1.18+ `pclntab` (`0xFFFFFFF1`).
* The 8-byte patch site is anchored by a **59-byte instruction context window**
  (30-byte prefix + 8-byte site + 21-byte suffix) that must appear **exactly
  once** across the entire file and lie **completely** inside the target
  function's `[va, end)` range, rejecting lookalike bytes in immediates.
* `--strict-build` optionally pins the whole-file SHA256 to `KNOWN_BUILDS`.
* Every command operates on a single in-memory snapshot and re-verifies on-disk
  file identity (`ino`, `dev`, `size`, `mtime_ns`) right before replacement.
* Patching never commits without a verified pristine backup, created via
  `os.link` or refreshed via `os.replace`; no historical backups are retained.
  A `.ctxunlock-backup.json` SHA256 sidecar records the original digest.
* Writes are atomic (same-directory temp file + `fsync` + `os.replace` +
  directory `fsync`), and `restore` validates content-level pairing from a
  single backup read before restoring.

Commands
--------
    self-test   recognise the build and validate every signature (read-only)
    patch       apply the patch (verifies/creates backup first)
    verify      report the current patch state and backup pairing
    restore     restore the pristine binary from its paired backup
    info        print the embedded per-model Checkpoint budget table
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

VERSION = "1.2.3"
BACKUP_SUFFIX = ".ctxunlock-backup"
DEFAULT_BINARY = "/opt/Antigravity/resources/bin/language_server"

SHF_EXECINSTR = 0x4
PF_X = 0x1
SHT_NOBITS = 8


class BinaryError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Minimal ELF64 + Go pclntab reader (standard library only)
# ---------------------------------------------------------------------------

@dataclass
class Section:
    name: str
    sh_type: int
    flags: int
    addr: int
    offset: int
    size: int


@dataclass
class Segment:
    p_type: int
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int


class ELFFile:
    """Minimal little-endian ELF64/x86-64 reader for Go PIE binaries."""

    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF":
            raise BinaryError("not an ELF file")
        self.data = data
        if data[4] != 2 or data[5] != 1:
            raise BinaryError("only ELF64 little-endian is supported")
        if struct.unpack_from("<H", data, 18)[0] != 0x3E:
            raise BinaryError("unsupported ELF machine (want x86-64)")
        self.phoff = struct.unpack_from("<Q", data, 32)[0]
        self.shoff = struct.unpack_from("<Q", data, 40)[0]
        self.phentsize, self.phnum = struct.unpack_from("<HH", data, 54)
        self.shentsize, self.shnum, self.shstrndx = struct.unpack_from("<HHH", data, 58)
        self.sections: List[Section] = []
        self.segments: List[Segment] = []
        self._read_sections()
        self._read_segments()

    def _read_sections(self) -> None:
        if not self.shoff:
            return
        raw = []
        for i in range(self.shnum):
            base = self.shoff + i * self.shentsize
            nameoff, sh_type = struct.unpack_from("<II", self.data, base)
            flags, addr, offset, size = struct.unpack_from("<QQQQ", self.data, base + 8)
            raw.append((nameoff, sh_type, flags, addr, offset, size))
        strtab_off = raw[self.shstrndx][4] if self.shstrndx < len(raw) else 0
        for nameoff, sh_type, flags, addr, offset, size in raw:
            end = self.data.find(b"\0", strtab_off + nameoff) if strtab_off else -1
            name = (self.data[strtab_off + nameoff:end].decode("utf-8", "replace")
                    if end > 0 else "")
            self.sections.append(Section(name, sh_type, flags, addr, offset, size))

    def _read_segments(self) -> None:
        for i in range(self.phnum):
            base = self.phoff + i * self.phentsize
            (p_type, p_flags, p_offset, p_vaddr, _paddr,
             p_filesz, p_memsz, _align) = struct.unpack_from("<IIQQQQQQ", self.data, base)
            self.segments.append(Segment(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))

    def va_to_off_exec(self, va: int) -> Optional[int]:
        for s in self.sections:
            if (s.sh_type != SHT_NOBITS and (s.flags & SHF_EXECINSTR)
                    and s.addr and s.addr <= va < s.addr + s.size):
                return s.offset + (va - s.addr)
        for seg in self.segments:
            if seg.p_type == 1 and (seg.flags & PF_X) and seg.vaddr <= va < seg.vaddr + seg.filesz:
                return seg.offset + (va - seg.vaddr)
        return None

    def off_to_va(self, off: int) -> Optional[int]:
        for s in self.sections:
            if s.sh_type != SHT_NOBITS and s.offset <= off < s.offset + s.size:
                return s.addr + (off - s.offset)
        for seg in self.segments:
            if seg.p_type == 1 and seg.offset <= off < seg.offset + seg.filesz:
                return seg.vaddr + (off - seg.offset)
        return None

    def section(self, name: str) -> Optional[Section]:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def relocations(self) -> Dict[int, int]:
        """r_offset -> addend for R_X86_64_RELATIVE entries."""
        out: Dict[int, int] = {}
        for s in self.sections:
            if s.sh_type != 4 or s.size < 24:  # SHT_RELA
                continue
            for i in range(0, s.size - 23, 24):
                r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.data, s.offset + i)
                if (r_info & 0xFFFFFFFF) == 8:
                    out[r_offset] = r_addend
        return out


@dataclass
class GoFunc:
    name: str
    entryoff: int
    funcoff: int
    va: int
    end: int


class GoSymbols:
    """Go 1.18+ pclntab (magic 0xFFFFFFF1) function-table reader."""

    def __init__(self, elf: ELFFile):
        self.elf = elf
        self.data = elf.data
        self.relocs = elf.relocations()
        self.pclntab_off, self.min_lc, self.nfunc = self._find_pclntab()
        base = self.pclntab_off
        self.funcname_off = base + struct.unpack_from("<Q", self.data, base + 32)[0]
        self.pcln_off = base + struct.unpack_from("<Q", self.data, base + 64)[0]
        self.pclntab_va = elf.off_to_va(self.pclntab_off)
        if self.pclntab_va is None:
            raise BinaryError("cannot map pclntab offset to a VA")
        self.text_base = self._find_text_base()
        self.funcs = self._build()

    def _find_pclntab(self) -> Tuple[int, int, int]:
        data = self.data
        candidates = []
        needle = struct.pack("<I", 0xFFFFFFF1) + b"\x00\x00"
        pos = 0
        while True:
            i = data.find(needle, pos)
            if i < 0:
                break
            pos = i + 1
            if i + 72 > len(data):
                continue
            min_lc, ptr_size = data[i + 6], data[i + 7]
            if min_lc not in (1, 2, 4) or ptr_size != 8:
                continue
            nfunc = struct.unpack_from("<Q", data, i + 8)[0]
            if not (1000 < nfunc < 5_000_000):
                continue
            fn_off = struct.unpack_from("<Q", data, i + 32)[0]
            pcln_off = struct.unpack_from("<Q", data, i + 64)[0]
            if not (72 <= fn_off < 1 << 40 and 72 <= pcln_off < 1 << 40):
                continue
            fn = i + fn_off
            head = data[fn:fn + 128].split(b"\0", 1)[0]
            if len(head) < 4 or not all(0x20 <= c < 0x7F for c in head):
                continue
            if i + pcln_off + (nfunc + 1) * 8 > len(data):
                continue
            va = self.elf.off_to_va(i)
            has_moduledata = False
            if va is not None:
                for slot, addend in self.relocs.items():
                    if addend == va:
                        minpc = self.relocs.get(slot + 0xA0)
                        text = self.relocs.get(slot + 0xB0)
                        if minpc and text and minpc == text:
                            has_moduledata = True
                            break
            candidates.append((has_moduledata, nfunc, i, min_lc))
        if not candidates:
            raise BinaryError("Go pclntab not found (unsupported build?)")
        candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
        _, nfunc, off, min_lc = candidates[0]
        return off, min_lc, nfunc

    def _find_text_base(self) -> int:
        for slot, addend in self.relocs.items():
            if addend != self.pclntab_va:
                continue
            minpc = self.relocs.get(slot + 0xA0)
            text = self.relocs.get(slot + 0xB0)
            if minpc and text and minpc == text and self._plausible_base(text):
                return text
        header_text = struct.unpack_from("<Q", self.data, self.pclntab_off + 24)[0]
        if header_text and self._plausible_base(header_text):
            return header_text
        text_sec = self.elf.section(".text")
        if text_sec:
            for delta in (0x80, 0x0):
                cand = text_sec.addr + delta
                if self._plausible_base(cand):
                    return cand
        # 4) last resort: executable segment start (synthetic/minimal images)
        for seg in self.elf.segments:
            if seg.p_type == 1 and (seg.flags & PF_X) and seg.vaddr:
                if self._plausible_base(seg.vaddr):
                    return seg.vaddr
        raise BinaryError("cannot determine Go text base")

    def _plausible_base(self, base: int) -> bool:
        if self.elf.va_to_off_exec(base) is None:
            return False
        ok = total = 0
        for i in (1, 2, 10, 100, 1000):
            if i + 1 > self.nfunc:
                continue
            eo, _ = struct.unpack_from("<II", self.data, self.pcln_off + i * 8)
            off = self.elf.va_to_off_exec(base + eo)
            if off is None or off >= len(self.data):
                continue
            total += 1
            if self.data[off] not in (0x00, 0xCC):
                ok += 1
        return total > 0 and ok >= max(1, total - 1)

    def _funcname(self, nameoff: int) -> str:
        start = self.funcname_off + nameoff
        end = self.data.find(b"\0", start, start + 512)
        return "" if end < 0 else self.data[start:end].decode("utf-8", "replace")

    def _build(self) -> Dict[str, GoFunc]:
        funcs: Dict[str, GoFunc] = {}
        entries: List[Tuple[int, int, str]] = []
        for i in range(self.nfunc):
            eo, fo = struct.unpack_from("<II", self.data, self.pcln_off + i * 8)
            rec = self.pcln_off + fo
            if rec + 8 > len(self.data):
                continue
            name = self._funcname(struct.unpack_from("<i", self.data, rec + 4)[0])
            if name:
                entries.append((eo, fo, name))
        entries.sort()
        for idx, (eo, fo, name) in enumerate(entries):
            end = entries[idx + 1][0] if idx + 1 < len(entries) else eo + 0x1000
            va = self.text_base + eo
            prev = funcs.get(name)
            if prev is None or va < prev.va:
                funcs[name] = GoFunc(name, eo, fo, va, self.text_base + end)
        return funcs

    def find(self, suffix: str) -> GoFunc:
        exact = self.funcs.get(suffix)
        if exact is not None:
            return exact
        matches = [f for n, f in self.funcs.items()
                   if n.endswith("." + suffix) or n.endswith("/" + suffix)]
        if not matches:
            raise BinaryError(f"symbol not found: {suffix}")
        if len({(f.entryoff, f.va) for f in matches}) > 1:
            names = sorted({f.name for f in matches})[:5]
            raise BinaryError(f"ambiguous symbol {suffix}: {names}")
        return matches[0]


# ---------------------------------------------------------------------------
# Patch definition
# ---------------------------------------------------------------------------
#
# Target function: utils.ClampCheckpointConfigForModelInfo
#
# Original code around the site (Intel syntax, Go compiler output):
#
#   .upper:
#     mov   edx, [rbx+0x14]      ; edx = ModelInfo.MaxTokens          (ctx)
#     test  edx, edx
#     jle   .done                ; ctx <= 0 -> leave config alone
#     mov   esi, edx             ; esi = ctx
#     sub   edx, ecx             ; edx = ctx - MaxOutputTokens
#     cmp   ecx, esi
#     cmovb esi, edx             ; esi = (out < ctx) ? (ctx - out) : ctx
#     nop   dword ptr [rax+0x0]
#     cmp   [rax+0xc], esi       ; MaxTokenLimit vs bound      <-- site start
#     jbe   .done
#     mov   [rax+0xc], esi       ; MaxTokenLimit = bound
#   .done:
#
# The 8-byte site is replaced by an *unconditional* store of `esi` followed by
# an unconditional jump past the remaining 3 bytes:
#
#     mov   [rax+0xc], esi
#     jmp   .done
#     nop ; nop ; nop
#
# Net effect: MaxTokenLimit = ModelInfo.MaxTokens - MaxOutputTokens (983,040 for
# a 1,048,576 / 65,536 model), overriding both the 256,000 provider default
# clamp and the 256,000 experiment-policy value merged earlier.

CLAMP_FUNC = "utils.ClampCheckpointConfigForModelInfo"

# The 8-byte site itself.
ORIGINAL_SITE = bytes.fromhex("39700c760389700c")       # cmp/jbe/mov
PATCH_PHYSICAL_MAX = bytes.fromhex("89700ceb03909090")  # mov/jmp/nop*3

# Surrounding context window required to match:
#   prefix (30 bytes): tail of zero-fallback + upper-bound computation (`cmovb`)
#   site   ( 8 bytes): conditional vs unconditional store of `[rax+0xc]`
#   suffix (21 bytes): start of `.done` block (`MaxOutputTokens` check)
#
# Requiring the full 59-byte window to be unique across the whole file and fully
# contained inside `[fn.va, fn.end)` prevents an identical 8-byte sequence
# inside an instruction immediate or data table from being mistaken for code.
SITE_PREFIX = bytes.fromhex(
    "4881c2c063ffff"      # add  rdx, -0x9c40      (zero-fallback tail)
    "89500c"              # mov  [rax+0xc], edx
    "8b5314"              # mov  edx, [rbx+0x14]
    "85d2"                # test edx, edx
    "7e15"                # jle  .done
    "89d6"                # mov  esi, edx
    "29ca"                # sub  edx, ecx
    "39f1"                # cmp  ecx, esi
    "0f42f2"              # cmovb esi, edx
    "0f1f4000"            # nop  DWORD PTR [rax+0x0]
)
SITE_SUFFIX = bytes.fromhex(
    "488b4850"            # mov  rcx, [rax+0x50]   (.done)
    "4885c9"              # test rcx, rcx
    "7417"                # je   .ret
    "803900"              # cmp  byte [rcx], 0
    "7412"                # je   .ret
    "8b4b70"              # mov  ecx, [rbx+0x70]
    "85c9"                # test ecx, ecx
    "7e0b"                # jle  .ret
)
CONTEXT_PRISTINE = SITE_PREFIX + ORIGINAL_SITE + SITE_SUFFIX
CONTEXT_PATCHED = SITE_PREFIX + PATCH_PHYSICAL_MAX + SITE_SUFFIX

# Byte offset of the 8-byte site within the 59-byte context window.
SITE_IN_CONTEXT = len(SITE_PREFIX)

# Whole-file SHA256 digests of builds verified end-to-end.
KNOWN_BUILDS = {
    # CL 1017595969, Antigravity desktop 2.31.0-1 (Linux x86-64)
    "e49711c4f7b2fa0e62c0e130c9566579423094b63647bdce82f4ddd81eeb983f":
        "pristine: CL 1017595969 / antigravity 2.31.0-1",
    "a1ceb2f2064835273524310592dc35998767f6bec81d05882117b9d1b85c7e6e":
        "patched : CL 1017595969 / antigravity 2.31.0-1",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_binary(path: str) -> Tuple[bytes, ELFFile, GoSymbols]:
    with open(path, "rb") as fh:
        data = fh.read()
    elf = ELFFile(data)
    return data, elf, GoSymbols(elf)


@dataclass
class Site:
    func_va: int
    func_end: int
    offset: int
    va: Optional[int]
    state: str          # "pristine" | "patched"
    patched_bytes: Optional[bytes] = None
    known_build: Optional[str] = None


def _occurrences(haystack: bytes, needle: bytes) -> List[int]:
    out, pos = [], 0
    while True:
        i = haystack.find(needle, pos)
        if i < 0:
            return out
        out.append(i)
        pos = i + 1


def locate_site(data: bytes, elf: ELFFile, syms: GoSymbols,
                strict_build: bool = False) -> Site:
    """Resolve the patch site, or raise BinaryError before anything is written.

    Acceptance requires all of the following, in order:

      1. the owning function resolves from pclntab and maps into an executable
         segment;
      2. the 59-byte context signature occurs *exactly once* in the whole file;
      3. the entire 59-byte context window lies inside the owning function's
         `[va, end)` range;
      4. the file is in *exactly one* of the two known states (pristine or
         patched). A file carrying both forms, or neither, is refused.

    `strict_build` additionally requires the whole-file SHA256 to match one of
    `KNOWN_BUILDS`.
    """
    fn = syms.find(CLAMP_FUNC)
    start = elf.va_to_off_exec(fn.va)
    last = elf.va_to_off_exec(fn.end - 1)
    if start is None or last is None:
        raise BinaryError(f"cannot map {CLAMP_FUNC} into file offsets")
    end = last + 1

    digest = _sha256(data)
    known = KNOWN_BUILDS.get(digest)
    if strict_build and known is None:
        raise BinaryError(
            f"build not in KNOWN_BUILDS (sha256={digest}); refusing under "
            f"--strict-build"
        )

    # (2) context uniqueness across the whole file
    n_ctx_p = _occurrences(data, CONTEXT_PRISTINE)
    n_ctx_x = _occurrences(data, CONTEXT_PATCHED)
    if len(n_ctx_p) + len(n_ctx_x) != 1:
        raise BinaryError(
            f"{CLAMP_FUNC}: expected exactly one recognisable site in the file, "
            f"found {len(n_ctx_p)} pristine + {len(n_ctx_x)} patched "
            f"(sha256={digest}) - unsupported or already-modified build"
        )

    ctx_off = (n_ctx_p or n_ctx_x)[0]
    patched = bool(n_ctx_x)
    off = ctx_off + SITE_IN_CONTEXT

    # (3) the WHOLE context window must lie inside the owning function
    ctx_end = ctx_off + len(CONTEXT_PRISTINE)
    if not (start <= ctx_off and ctx_end <= end):
        raise BinaryError(
            f"{CLAMP_FUNC}: the matching {len(CONTEXT_PRISTINE)}-byte context at "
            f"[{ctx_off:#x},{ctx_end:#x}) is not fully inside the owning function "
            f"[{start:#x},{end:#x}) - refusing"
        )

    if not patched:
        if bytes(data[off:off + 8]) != ORIGINAL_SITE:
            raise BinaryError("internal: pristine context but site bytes differ")

    return Site(
        func_va=fn.va, func_end=fn.end, offset=off, va=elf.off_to_va(off),
        state="patched" if patched else "pristine",
        patched_bytes=PATCH_PHYSICAL_MAX if patched else None,
        known_build=known,
    )


def atomic_write(path: str, data: bytes) -> None:
    """Replace `path` with `data` atomically (same dir, fsync, os.replace).

    Note: this guarantees that readers see either the whole old file or the
    whole new one. It does not make the replacement transactional with respect
    to a concurrent writer (e.g. a package upgrade); callers re-check on-disk
    identity immediately before invoking this function.
    """
    directory = os.path.dirname(os.path.abspath(path))
    st = os.stat(path)
    fd, tmp = tempfile.mkstemp(prefix=".ctxunlock-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, st.st_mode & 0o7777)
        os.replace(tmp, path)
        dfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def backup_path(binary: str) -> str:
    return binary + BACKUP_SUFFIX


def backup_meta_path(binary: str) -> str:
    return binary + BACKUP_SUFFIX + ".json"


def read_file(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def write_backup(binary: str, pristine: bytes, *, replace_existing: bool = False) -> None:
    """Publish a complete pristine snapshot and sidecar, without retaining history.

    New backups use `os.link` to avoid silently overwriting an existing file.
    Explicit refresh stages and fsyncs both files before atomically replacing
    the backup. The old sidecar is removed first so an interrupted refresh cannot
    leave a new backup paired with stale metadata. The two files are not a
    transaction; a missing sidecar is safe because restore checks content pairing.
    """
    bp = os.path.abspath(backup_path(binary))
    mp = os.path.abspath(backup_meta_path(binary))
    if replace_existing:
        for target in (bp, mp):
            if os.path.lexists(target) and (
                    os.path.islink(target) or not os.path.isfile(target)):
                raise BinaryError(f"refusing to replace non-regular backup file: {target}")
    directory = os.path.dirname(bp)
    tmp = mtmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix=".ctxunlock-bk-", dir=directory)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pristine)
            fh.flush()
            os.fsync(fh.fileno())

        meta = {
            "original_sha256": _sha256(pristine),
            "original_size": len(pristine),
            "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "tool_version": VERSION,
        }
        mfd, mtmp = tempfile.mkstemp(prefix=".ctxunlock-md-", dir=directory)
        with os.fdopen(mfd, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        if replace_existing:
            if os.path.lexists(mp):
                os.unlink(mp)
            os.replace(tmp, bp)
            os.replace(mtmp, mp)
        else:
            os.link(tmp, bp)
            try:
                os.link(mtmp, mp)
            except FileExistsError:
                pass      # an older sidecar is fine; it is validated separately
        dfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except FileExistsError as exc:
        raise BinaryError(
            f"backup path {bp} is already occupied but is not a usable backup; "
            f"inspect or remove it first ({exc})"
        ) from exc
    finally:
        for leftover in (tmp, mtmp):
            if leftover and os.path.exists(leftover):
                try:
                    os.unlink(leftover)
                except OSError:
                    pass


def read_backup_meta(binary: str) -> Optional[dict]:
    """Return the sidecar metadata dict, or None when absent/unusable."""
    mpath = backup_meta_path(binary)
    try:
        with open(mpath, encoding="utf-8") as fh:
            obj = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    digest = obj.get("original_sha256")
    if not isinstance(digest, str) or not digest:
        return None
    return obj


def check_backup(binary: str, expected_digest: str) -> Tuple[str, str]:
    """Inspect the canonical backup path and report whether it is usable.

    Returns `(status, detail)` where `status` is one of:
      `usable`, `missing`, `dangling`, `unreadable`, `wrong-build`, `bad-meta`.
    """
    bp = backup_path(binary)
    if os.path.islink(bp) and not os.path.exists(bp):
        return "dangling", f"{bp} is a symlink to a missing target"
    if not os.path.lexists(bp):
        return "missing", f"no backup at {bp}"
    try:
        if not os.path.isfile(bp):
            return "unreadable", f"{bp} is not a regular file"
        with open(bp, "rb") as fh:
            content = fh.read()
    except OSError as exc:
        return "unreadable", f"cannot read {bp}: {exc}"

    actual = _sha256(content)
    if actual != expected_digest:
        return "wrong-build", (
            f"{bp} holds {actual}, but this binary is {expected_digest}")

    meta = read_backup_meta(binary)
    if meta and meta["original_sha256"] != actual:
        return "bad-meta", (
            f"{bp} sidecar records {meta['original_sha256']}, file is {actual}")
    return "usable", f"{bp} matches this build"


# ---------------------------------------------------------------------------
# Embedded profile table
# ---------------------------------------------------------------------------

PROFILE_ANCHOR = b'{\n  "base"'


def embedded_profiles(data: bytes) -> Optional[dict]:
    pos = 0
    while True:
        idx = data.find(PROFILE_ANCHOR, pos)
        if idx < 0:
            return None
        pos = idx + 1
        chunk = data[idx:idx + 400_000].decode("utf-8", "replace")
        try:
            obj, end = json.JSONDecoder().raw_decode(chunk)
        except ValueError:
            continue
        if isinstance(obj, dict) and "model_profiles" in obj:
            obj["_offset"] = idx
            obj["_length"] = end
            return obj


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_self_test(args) -> int:
    path = args.binary
    print(f"binary : {path}")
    if not os.path.exists(path):
        print("  FAIL: file not found")
        return 1
    data, elf, syms = load_binary(path)
    print(f"  size   : {len(data):,} bytes")
    print(f"  sha256 : {_sha256(data)}")
    print(f"  go funcs: {len(syms.funcs):,}   text base: {syms.text_base:#x}")

    fn = syms.find(CLAMP_FUNC)
    print(f"\ntarget function: {CLAMP_FUNC}")
    print(f"  va    : {fn.va:#x} .. {fn.end:#x}  ({fn.end - fn.va} bytes)")

    site = locate_site(data, elf, syms, strict_build=args.strict_build)
    print(f"  state : {site.state.upper()}")
    print(f"  site  : va={site.va:#x} off={site.offset:#x}")
    print(f"  before: {ORIGINAL_SITE.hex(' ')}")
    print(f"  after : {PATCH_PHYSICAL_MAX.hex(' ')}")
    print(f"  build : {site.known_build or 'unlisted (passed structural checks)'}")

    prof = embedded_profiles(data)
    if prof:
        mp = prof.get("model_profiles") or {}
        print(f"\nembedded profiles @ {prof['_offset']:#x} ({prof['_length']:,} bytes), "
              f"{len(mp)} entries")
        for name in ("MODEL_PLACEHOLDER_M124", "MODEL_PLACEHOLDER_M318",
                     "MODEL_PLACEHOLDER_M408", "MODEL_PLACEHOLDER_M400"):
            entry = mp.get(name)
            if not isinstance(entry, dict):
                continue
            for k, v in entry.items():
                if "CHECKPOINTER" not in k:
                    continue
                try:
                    pol = json.loads(v) if isinstance(v, str) else v
                except ValueError:
                    continue
                variant = k.split("/", 1)[1] if "/" in k else "(bare)"
                print(f"  {name:24} {variant:16} max_token_limit="
                      f"{str(pol.get('max_token_limit')):>8}  {pol.get('strategy')}")
    return 0


def _pairs_with(pristine: bytes, bsite: Site, current_digest: str,
                cur_site: Site) -> bool:
    """True when `pristine` is the pre-patch image of the installed binary."""
    if cur_site.state == "pristine":
        return _sha256(pristine) == current_digest
    expect = bytearray(pristine)
    expect[bsite.offset:bsite.offset + 8] = PATCH_PHYSICAL_MAX
    return _sha256(bytes(expect)) == current_digest


def _describe_pairing(binary: str, current_digest: str,
                      cur_site: Site) -> str:
    """Human-readable pairing status for `verify` (read-only)."""
    bp = backup_path(binary)
    if os.path.islink(bp) and not os.path.exists(bp):
        return "no (backup path is a dangling symlink)"
    if not os.path.lexists(bp):
        return "no backup"
    try:
        pristine = read_file(bp)
        elf = ELFFile(pristine)
        bsite = locate_site(pristine, elf, GoSymbols(elf))
    except (OSError, BinaryError) as exc:
        return f"no (backup unusable: {exc})"
    if bsite.state != "pristine":
        return "no (backup is itself patched)"
    return "yes" if _pairs_with(pristine, bsite, current_digest, cur_site) else "no (different build)"


def _snapshot(path: str) -> Tuple[bytes, str, os.stat_result]:
    """Read the binary once and return (bytes, sha256, stat)."""
    st = os.stat(path)
    data = read_file(path)
    return data, _sha256(data), st


def _identity_changed(path: str, st: os.stat_result) -> bool:
    try:
        now = os.stat(path)
    except OSError:
        return True
    return (now.st_ino, now.st_dev, now.st_size, now.st_mtime_ns) != (
        st.st_ino, st.st_dev, st.st_size, st.st_mtime_ns)


def cmd_patch(args) -> int:
    path = args.binary
    print(f"binary : {path}")
    try:
        data, digest, st = _snapshot(path)
    except OSError as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        return 3
    print(f"before : {digest}")

    elf = ELFFile(data)
    syms = GoSymbols(elf)
    site = locate_site(data, elf, syms, strict_build=args.strict_build)
    print(f"build  : {site.known_build or 'unlisted (passed structural checks)'}")

    if site.state == "patched":
        print("already patched - nothing to do")
        return 0

    print(f"site   : va={site.va:#x} off={site.offset:#x}")
    print(f"  before: {ORIGINAL_SITE.hex(' ')}")
    print(f"  after : {PATCH_PHYSICAL_MAX.hex(' ')}")

    bp = backup_path(path)
    status, detail = check_backup(path, digest)
    if status == "wrong-build" and args.refresh_backup:
        if not args.yes:
            print(f"\nwould replace {bp} and its sidecar with this build's backup "
                  "and patch (no archive). Pass --yes to write.")
            return 2
        if _identity_changed(path, st):
            raise BinaryError("the binary changed before backup refresh; aborted")
        write_backup(path, data, replace_existing=True)
        print("backup : refreshed for this build (previous backup replaced)")
        status, detail = check_backup(path, digest)
    if status == "usable":
        print(f"backup : {detail}")
    elif status == "missing":
        if not args.yes:
            print(f"\nwould back up to {bp} and patch. Pass --yes to write.")
            return 2
        try:
            write_backup(path, data)
        except BinaryError as exc:
            print(f"error: could not create a backup: {exc}", file=sys.stderr)
            print("       The target binary is unchanged.",
                  file=sys.stderr)
            return 3
        status, detail = check_backup(path, digest)
        if status != "usable":
            print(f"error: backup is not usable after creation ({status}): {detail}",
                  file=sys.stderr)
            print("       The target binary is unchanged.",
                  file=sys.stderr)
            return 3
        print(f"backup : {detail}")
    else:
        print(f"error: existing backup is not usable ({status}): {detail}",
              file=sys.stderr)
        if status == "wrong-build":
            print("       It belongs to a different build. Use --refresh-backup "
                  "to replace it with this build's backup first.", file=sys.stderr)
        elif status == "dangling":
            print("       Remove that symlink and re-run to create a real backup.",
                  file=sys.stderr)
        print("       The target binary is unchanged.", file=sys.stderr)
        return 3

    if read_backup_meta(path) is None:
        print("note   : backup has no metadata file (created by an older tool "
              "version); restore falls back to content pairing")

    if not args.yes:
        print("\ndry run - pass --yes to write")
        return 2

    # Re-check identity right before the write to catch a concurrent upgrade.
    if _identity_changed(path, st):
        print("error: the binary changed while we were working (concurrent "
              "upgrade?). Nothing was written.", file=sys.stderr)
        return 3

    buf = bytearray(data)
    off = site.offset
    if bytes(buf[off:off + 8]) != ORIGINAL_SITE:
        raise BinaryError("byte mismatch immediately before write; aborted")
    buf[off:off + 8] = PATCH_PHYSICAL_MAX
    atomic_write(path, bytes(buf))

    after = read_file(path)
    after_digest = _sha256(after)
    print(f"after  : {after_digest}")
    ok = after[off:off + 8] == PATCH_PHYSICAL_MAX
    if ok:
        elf2 = ELFFile(after)
        site2 = locate_site(after, elf2, GoSymbols(elf2), strict_build=False)
        ok = site2.state == "patched" and site2.offset == off
    if ok and site.known_build and site.known_build.startswith("pristine"):
        expected = [h for h, label in KNOWN_BUILDS.items()
                    if label.startswith("patched")]
        if expected and after_digest not in expected:
            print(f"error: patched image {after_digest} is not a known patched "
                  f"artifact for this build (expected one of {expected})",
                  file=sys.stderr)
            ok = False
    print(f"verify : {'OK - patched' if ok else 'FAILED - on-disk bytes do not match'}")
    return 0 if ok else 1


def cmd_verify(args) -> int:
    path = args.binary
    try:
        data, digest, _ = _snapshot(path)
        elf = ELFFile(data)
        site = locate_site(data, elf, GoSymbols(elf), strict_build=args.strict_build)
    except (OSError, BinaryError) as exc:
        print(f"binary : {path}")
        print(f"state  : UNKNOWN - {exc}")
        return 1
    print(f"binary : {path}")
    print(f"sha256 : {digest}")
    print(f"build  : {site.known_build or 'unlisted (passed structural checks)'}")
    print(f"state  : {site.state.upper()}")
    print(f"site   : va={site.va:#x} off={site.offset:#x}")
    bp = backup_path(path)
    if os.path.exists(bp):
        bdigest = _sha256(read_file(bp))
        print(f"backup : {bp}")
        print(f"         sha256={bdigest}")
        print(f"         pairs : {_describe_pairing(path, digest, site)}")
    else:
        print(f"backup : {bp}  (MISSING)")
    return 0 if site.state == "patched" else 1


def cmd_restore(args) -> int:
    path = args.binary
    bp = backup_path(path)
    if os.path.islink(bp) and not os.path.exists(bp):
        print(f"error: backup path {bp} is a dangling symlink", file=sys.stderr)
        return 1
    if not os.path.lexists(bp):
        print(f"no backup at {bp} - cannot restore", file=sys.stderr)
        return 1

    # ONE snapshot of the backup decides everything below.
    try:
        pristine = read_file(bp)
    except OSError as exc:
        print(f"error: cannot read backup: {exc}", file=sys.stderr)
        return 3
    pristine_digest = _sha256(pristine)

    try:
        elf = ELFFile(pristine)
        bsite = locate_site(pristine, elf, GoSymbols(elf))
    except BinaryError as exc:
        print(f"error: backup is not a usable pristine image: {exc}", file=sys.stderr)
        return 3
    if bsite.state != "pristine":
        print("error: backup itself is patched - refusing to restore", file=sys.stderr)
        return 1

    meta = read_backup_meta(path)
    if meta and meta["original_sha256"] != pristine_digest:
        print("error: backup content does not match its recorded metadata "
              f"(recorded {meta['original_sha256']}, actual {pristine_digest})",
              file=sys.stderr)
        return 3

    current = None
    current_digest = None
    cur_site = None
    cur_stat = None
    if os.path.exists(path):
        try:
            cur_stat = os.stat(path)
            current = read_file(path)
            current_digest = _sha256(current)
            elf_c = ELFFile(current)
            cur_site = locate_site(current, elf_c, GoSymbols(elf_c))
        except (OSError, BinaryError):
            cur_site = None

    print(f"backup : {bp} ({pristine_digest})")

    if cur_site is not None and cur_site.state == "pristine" \
            and current_digest == pristine_digest:
        print("already pristine - nothing to do")
        return 0

    paired = cur_site is not None and _pairs_with(
        pristine, bsite, current_digest, cur_site)

    if not paired:
        print("error: this backup does not pair with the installed binary.",
              file=sys.stderr)
        print("       Restoring it would install a different build than the one "
              "currently present.", file=sys.stderr)
        if not args.force:
            print("       Refusing. Re-run with --force only if you are certain.",
                  file=sys.stderr)
            return 3

    if not args.yes:
        print("dry run - pass --yes to restore")
        return 2

    if cur_stat is not None and _identity_changed(path, cur_stat):
        print("error: the binary changed while we were working (concurrent "
              "upgrade?). Nothing was written.", file=sys.stderr)
        return 3

    atomic_write(path, pristine)
    after = read_file(path)
    ok = _sha256(after) == pristine_digest
    print(f"restored: {path}")
    print(f"sha256  : {_sha256(after)}")
    print(f"verify  : {'OK - pristine' if ok else 'FAILED'}")
    return 0 if ok else 1


def cmd_info(args) -> int:
    with open(args.binary, "rb") as fh:
        data = fh.read()
    prof = embedded_profiles(data)
    if not prof:
        print("no embedded profile table found", file=sys.stderr)
        return 1
    mp = prof.get("model_profiles") or {}
    print(f"{'profile':26} {'variant':18} {'max_token_limit':>16}  strategy")
    print("-" * 84)
    for name, entry in mp.items():
        if not isinstance(entry, dict):
            continue
        if args.model and args.model.lower() not in name.lower():
            continue
        for k, v in entry.items():
            if "CHECKPOINTER" not in k:
                continue
            try:
                pol = json.loads(v) if isinstance(v, str) else v
            except ValueError:
                continue
            variant = k.split("/", 1)[1] if "/" in k else "(bare)"
            print(f"{name:26} {variant:18} {str(pol.get('max_token_limit')):>16}  "
                  f"{pol.get('strategy')}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="antigravity-context-unlock",
        description="Unlock the 256K local context compaction ceiling in Antigravity Desktop (language_server).",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_text):
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument("--binary", default=DEFAULT_BINARY,
                        help=f"desktop engine binary (default: {DEFAULT_BINARY})")
        sp.add_argument("--yes", action="store_true", help="confirm and write changes")
        sp.set_defaults(func=fn)
        return sp

    def add_strict(sp):
        sp.add_argument("--strict-build", action="store_true",
                        help="require the whole-file SHA256 to match KNOWN_BUILDS")
        return sp

    add_strict(add("self-test", cmd_self_test,
                   "recognise the build and validate the patch signature (read-only)"))
    sp = add_strict(add("patch", cmd_patch, "apply the patch (creates/verifies backup first)"))
    sp.add_argument("--refresh-backup", action="store_true",
                    help="replace a different build's backup and sidecar with "
                         "this pristine build; keep no archive (requires --yes to write)")
    add_strict(add("verify", cmd_verify, "report the current patch state and backup pairing"))
    sp = add("restore", cmd_restore, "restore the pristine binary from its paired backup")
    sp.add_argument("--force", action="store_true",
                    help="restore even when the backup does not pair with the "
                         "installed build (dangerous)")
    sp = add("info", cmd_info, "print the embedded per-model Checkpoint budget table")
    sp.add_argument("--model", default="", help="filter by profile-name substring")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BinaryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except (IndexError, struct.error, ValueError, MemoryError) as exc:
        print(f"error: malformed binary ({type(exc).__name__}: {exc})", file=sys.stderr)
        return 3
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("note: this failure happened while writing. The file may already "
              "have been replaced. Re-run `verify` to see the actual state.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
