"""
UEFI signature databases: parse and build EFI_SIGNATURE_LISTs and simulate authenticated appends.

The append model follows EDK2's AuthVariableLib: entries already present anywhere in the variable are dropped,
and each payload list that keeps at least one entry is appended as a new list. That is why a dbx updated over the
years holds one list per applied update, and why replaying the same signed updates in the same order rebuilds it
byte for byte.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass
from pathlib import Path

EFI_GLOBAL_VARIABLE = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
EFI_IMAGE_SECURITY_DATABASE = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
EFI_CERT_SHA256 = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")
EFI_CERT_X509 = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
EFIVARS = Path("/sys/firmware/efi/efivars")
VARIABLE_GUIDS = {
    "SecureBoot": EFI_GLOBAL_VARIABLE,
    "SetupMode": EFI_GLOBAL_VARIABLE,
    "PK": EFI_GLOBAL_VARIABLE,
    "KEK": EFI_GLOBAL_VARIABLE,
    "db": EFI_IMAGE_SECURITY_DATABASE,
    "dbx": EFI_IMAGE_SECURITY_DATABASE,
    "PKDefault": EFI_GLOBAL_VARIABLE,
    "KEKDefault": EFI_GLOBAL_VARIABLE,
    "dbDefault": EFI_GLOBAL_VARIABLE,
    "dbxDefault": EFI_GLOBAL_VARIABLE,
}


@dataclass(frozen=True)
class SignatureList:
    """One EFI_SIGNATURE_LIST."""

    signature_type: uuid.UUID
    header: bytes
    signature_size: int
    entries: tuple[bytes, ...]

    def to_bytes(self) -> bytes:
        """
        Serialise the list exactly as firmware stores it.

        :returns: The EFI_SIGNATURE_LIST bytes
        """
        size = 28 + len(self.header) + self.signature_size * len(self.entries)
        return (
            self.signature_type.bytes_le
            + struct.pack("<III", size, len(self.header), self.signature_size)
            + self.header
            + b"".join(self.entries)
        )


def parse_lists(data: bytes) -> list[SignatureList]:
    """
    Split a signature database into its lists.

    :param data: The variable's data, without the 4 byte attribute prefix efivarfs adds
    :returns: The lists in stored order
    :raises ValueError: When the data is not a well formed signature database
    """
    lists: list[SignatureList] = []
    offset = 0
    while offset < len(data):
        if offset + 28 > len(data):
            raise ValueError(f"truncated signature list header at offset {offset}")
        list_size, header_size, signature_size = struct.unpack_from("<III", data, offset + 16)
        if list_size < 28 + header_size or signature_size == 0 or offset + list_size > len(data):
            raise ValueError(f"bad signature list at offset {offset}")
        body = data[offset + 28 + header_size : offset + list_size]
        if len(body) % signature_size:
            raise ValueError(f"signature list at offset {offset} is not a whole number of entries")
        lists.append(
            SignatureList(
                uuid.UUID(bytes_le=data[offset : offset + 16]),
                data[offset + 28 : offset + 28 + header_size],
                signature_size,
                tuple(body[i : i + signature_size] for i in range(0, len(body), signature_size)),
            )
        )
        offset += list_size
    return lists


def list_boundaries(data: bytes) -> list[int]:
    """
    Give the byte offset where each list ends.

    :param data: A signature database
    :returns: The end offset of every list, in order
    """
    ends: list[int] = []
    offset = 0
    for item in parse_lists(data):
        offset += len(item.to_bytes())
        ends.append(offset)
    return ends


def auth2_payload(blob: bytes) -> bytes:
    """
    Strip the EFI_VARIABLE_AUTHENTICATION_2 header from a signed update.

    :param blob: A signed update file, such as a DBXUpdate.bin
    :returns: The signature lists the update carries
    :raises ValueError: When the blob is too short to hold the header
    """
    if len(blob) < 24:
        raise ValueError("file too short to be an authenticated variable")
    certificate_length = struct.unpack_from("<I", blob, 16)[0]
    return blob[16 + certificate_length :]


def simulate_append(current: bytes, payload: bytes) -> bytes:
    """
    Predict a variable after an authenticated append of ``payload``.

    :param current: The variable's data now
    :param payload: The signature lists of the update (see :func:`auth2_payload`)
    :returns: The variable's data after the append
    """
    present = {(item.signature_type, entry) for item in parse_lists(current) for entry in item.entries}
    added = b""
    for item in parse_lists(payload):
        keep = tuple(entry for entry in item.entries if (item.signature_type, entry) not in present)
        if keep:
            added += SignatureList(item.signature_type, item.header, item.signature_size, keep).to_bytes()
            present.update((item.signature_type, entry) for entry in keep)
    return current + added


def read_variable(name: str, directory: Path = EFIVARS) -> bytes | None:
    """
    Read a UEFI variable's data from efivarfs or a copy of it.

    :param name: The variable name, such as ``dbx``
    :param directory: The efivarfs mount or a directory holding copied efivarfs files
    :returns: The data without the attribute prefix, or ``None`` when absent
    """
    matches = sorted(directory.glob(f"{name}-*"))
    exact = [path for path in matches if path.name.split("-", 1)[0] == name]
    if not exact:
        return None
    return exact[0].read_bytes()[4:]
