"""
Windows update packages: cabinet extraction (stored and MSZIP), PSF express packages, and MSDELTA patches.

Microsoft's own ``msdelta.dll`` is never shipped here. :func:`apply_delta` runs it under Wine from a path the user
gives, taken from a Windows installation they own.
"""

from __future__ import annotations

import re
import struct
import subprocess  # nosec B404
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path


def cabinet_files(data: bytes) -> dict[str, bytes]:
    """
    Extract every file of a cabinet that uses no compression or MSZIP.

    :param data: The cabinet bytes
    :returns: File contents by name
    :raises ValueError: When the data is not a cabinet or uses LZX or Quantum
    """
    if data[:4] != b"MSCF":
        raise ValueError("not a cabinet file")
    files_offset = struct.unpack_from("<I", data, 16)[0]
    folder_count, file_count, flags = struct.unpack_from("<HHH", data, 26)
    offset = 36
    folder_reserve = data_reserve = 0
    if flags & 4:
        header_reserve, folder_reserve, data_reserve = struct.unpack_from("<HBB", data, offset)
        offset += 4 + header_reserve
    folders: list[bytes] = []
    for _ in range(folder_count):
        first, blocks, compression = struct.unpack_from("<IHH", data, offset)
        offset += 8 + folder_reserve
        if compression & 0xF not in (0, 1):
            raise ValueError("cabinet uses LZX or Quantum; extract it with cabextract")
        cursor, out, window = first, bytearray(), b""
        for _ in range(blocks):
            _checksum, packed, _unpacked = struct.unpack_from("<IHH", data, cursor)
            cursor += 8 + data_reserve
            block = data[cursor : cursor + packed]
            cursor += packed
            if compression & 0xF == 0:
                out += block
                continue
            if block[:2] != b"CK":
                raise ValueError("bad MSZIP block")
            decoder = zlib.decompressobj(-15, zdict=window) if window else zlib.decompressobj(-15)
            window = decoder.decompress(block[2:])
            out += window
        folders.append(bytes(out))
    result: dict[str, bytes] = {}
    offset = files_offset
    for _ in range(file_count):
        size, start, folder = struct.unpack_from("<IIH", data, offset)
        offset += 16
        end = data.index(b"\0", offset)
        name = data[offset:end].decode("utf-8", "replace").replace("\\", "/")
        offset = end + 1
        result[name] = folders[folder][start : start + size]
    return result


@dataclass(frozen=True)
class PsfEntry:
    """One file described by an express package's index."""

    name: str
    offset: int
    length: int


def psf_entries(index_xml: str, pattern: str = r"dbx") -> list[PsfEntry]:
    """
    List files in ``express.psf.cix.xml`` whose name matches ``pattern``.

    :param index_xml: The index's text
    :param pattern: A regular expression applied to each file name, case insensitive
    :returns: The matching files with their location in the ``.psf``
    """
    entries: list[PsfEntry] = []
    for match in re.finditer(
        r'<File [^>]*name="([^"]+)"[^>]*>.*?<Source [^>]*offset="(\d+)" length="(\d+)"', index_xml, re.S
    ):
        if re.search(pattern, match.group(1), re.I):
            entries.append(PsfEntry(match.group(1).replace("\\", "/"), int(match.group(2)), int(match.group(3))))
    return entries


_APPLY_SCRIPT = r"""
import ctypes, sys
from ctypes import wintypes
class DI(ctypes.Structure):
    _fields_ = [("lpStart", ctypes.c_void_p), ("uSize", ctypes.c_size_t), ("Editable", wintypes.BOOL)]
class DO(ctypes.Structure):
    _fields_ = [("lpStart", ctypes.c_void_p), ("uSize", ctypes.c_size_t)]
md = ctypes.WinDLL(sys.argv[1])
src = open(sys.argv[2], "rb").read() if sys.argv[2] != "-" else b""
delta = open(sys.argv[3], "rb").read()[4:]
sb = ctypes.create_string_buffer(src, len(src)) if src else None
db = ctypes.create_string_buffer(delta, len(delta))
out = DO()
ok = md.ApplyDeltaB(ctypes.c_int64(0), DI(ctypes.cast(sb, ctypes.c_void_p) if sb else None, len(src), False),
                    DI(ctypes.cast(db, ctypes.c_void_p), len(delta), False), ctypes.byref(out))
if not ok:
    raise SystemExit("ApplyDeltaB failed")
open(sys.argv[4], "wb").write(ctypes.string_at(out.lpStart, out.uSize))
md.DeltaFree(ctypes.c_void_p(out.lpStart))
"""


def apply_delta(msdelta_dll: Path, windows_python: Path, base: Path | None, delta: Path, output: Path) -> None:
    """
    Apply a PA30 patch (4 byte CRC prefix included) with Microsoft's msdelta.dll under Wine.

    :param msdelta_dll: ``msdelta.dll`` copied from a Windows installation you own
    :param windows_python: ``python.exe`` from Python's Windows embeddable package
    :param base: The file the patch applies to, or ``None`` for a patch against an empty file
    :param delta: The patch
    :param output: Where to write the result
    :raises RuntimeError: When Wine or the patch fails
    """
    with tempfile.TemporaryDirectory() as work:
        script = Path(work) / "apply.py"
        script.write_text(_APPLY_SCRIPT, encoding="utf-8")
        command = ["wine", str(windows_python), str(script), str(msdelta_dll.resolve()), str(base) if base else "-"]
        command += [str(delta), str(output)]
        env = {"WINEDEBUG": "-all", "WINEDLLOVERRIDES": "msdelta=n", "WINEPREFIX": str(Path(work) / "prefix")}
        result = subprocess.run(  # nosec B603
            command, capture_output=True, text=True, env={**_base_env(), **env}, check=False
        )
        if result.returncode != 0 or not output.is_file():
            raise RuntimeError(f"wine failed: {result.stderr.strip() or result.stdout.strip()}")


def _base_env() -> dict[str, str]:
    import os

    return {key: value for key, value in os.environ.items() if key in ("PATH", "HOME", "DISPLAY", "XDG_RUNTIME_DIR")}
