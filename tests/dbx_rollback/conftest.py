"""Synthetic fixtures: no Microsoft files and no real machine data are used anywhere in the tests."""

from __future__ import annotations

import hashlib
import struct
import uuid

from dbx_rollback.efi import EFI_CERT_SHA256, SignatureList

OWNER = uuid.UUID("77fa9abd-0359-4d32-bd60-28f4e78f784b").bytes_le


def entry(seed: int) -> bytes:
    """
    Make a fake SHA256 dbx entry.

    :param seed: Any integer
    :returns: The entry
    """
    return OWNER + hashlib.sha256(seed.to_bytes(4, "little")).digest()


def sha_list(seeds: list[int]) -> bytes:
    """
    Make a SHA256 signature list of fake entries.

    :param seeds: One integer per entry
    :returns: The list bytes
    """
    return SignatureList(EFI_CERT_SHA256, b"", 48, tuple(entry(s) for s in seeds)).to_bytes()


def signed(payload: bytes) -> bytes:
    """
    Wrap a payload in a fake EFI_VARIABLE_AUTHENTICATION_2 header.

    :param payload: Signature lists
    :returns: A signed looking update
    """
    certificate = b"\x00" * 40
    return b"\x00" * 16 + struct.pack("<I", 8 + len(certificate)) + b"\x00" * 4 + certificate + payload
