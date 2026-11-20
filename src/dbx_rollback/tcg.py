"""TCG event logs and PCR 7: parse the crypto agile log, replay PCR 7, and build the Secure Boot events."""

from __future__ import annotations

import hashlib
import struct
import uuid
from dataclasses import dataclass

from dbx_rollback.efi import EFI_GLOBAL_VARIABLE, EFI_IMAGE_SECURITY_DATABASE

SHA256 = 0x000B
EV_SEPARATOR = 0x00000004
EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001
EV_EFI_VARIABLE_AUTHORITY = 0x800000E0
ZERO = b"\x00" * 32


@dataclass(frozen=True)
class Event:
    """One event of a TCG2 log."""

    pcr: int
    event_type: int
    sha256: bytes | None
    data: bytes


def parse_log(blob: bytes) -> list[Event]:
    """
    Parse a crypto agile TCG2 event log such as ``/sys/kernel/security/tpm0/binary_bios_measurements``.

    :param blob: The raw log
    :returns: Every event after the Spec ID header
    """
    header_size = struct.unpack_from("<I", blob, 28)[0]
    spec = blob[32 : 32 + header_size]
    count = struct.unpack_from("<I", spec, 24)[0]
    sizes = {}
    for index in range(count):
        algorithm, size = struct.unpack_from("<HH", spec, 28 + 4 * index)
        sizes[algorithm] = size
    events: list[Event] = []
    offset = 32 + header_size
    while offset + 12 <= len(blob):
        pcr, event_type, digest_count = struct.unpack_from("<III", blob, offset)
        cursor = offset + 12
        digests: dict[int, bytes] = {}
        for _ in range(digest_count):
            algorithm = struct.unpack_from("<H", blob, cursor)[0]
            digests[algorithm] = blob[cursor + 2 : cursor + 2 + sizes[algorithm]]
            cursor += 2 + sizes[algorithm]
        event_size = struct.unpack_from("<I", blob, cursor)[0]
        events.append(Event(pcr, event_type, digests.get(SHA256), blob[cursor + 4 : cursor + 4 + event_size]))
        offset = cursor + 4 + event_size
    return events


def variable_event(guid: str, name: str, data: bytes) -> bytes:
    """
    Build a UEFI_VARIABLE_DATA structure, the event data firmware measures for Secure Boot variables.

    :param guid: The variable's vendor GUID
    :param name: The variable's name
    :param data: The variable's data
    :returns: The structure's bytes
    """
    return uuid.UUID(guid).bytes_le + struct.pack("<QQ", len(name), len(data)) + name.encode("utf-16-le") + data


def extend(pcr: bytes, digest: bytes) -> bytes:
    """
    Extend a SHA256 PCR.

    :param pcr: The PCR value now
    :param digest: The measurement
    :returns: The new PCR value
    """
    return hashlib.sha256(pcr + digest).digest()


def replay(digests: list[bytes]) -> bytes:
    """
    Replay measurements into a PCR that starts at zero.

    :param digests: The measurements in order
    :returns: The final PCR value
    """
    value = ZERO
    for digest in digests:
        value = extend(value, digest)
    return value


def pcr7_for(secure_boot: bytes, pk: bytes, kek: bytes, db: bytes, dbx: bytes, authorities: list[bytes]) -> bytes:
    """
    Compute PCR 7 for a boot, from variable contents and the db entries that verified each loaded image.

    :param secure_boot: The SecureBoot variable's data, usually the single byte 1
    :param pk: The PK variable's data
    :param kek: The KEK variable's data
    :param db: The db variable's data
    :param dbx: The dbx variable's data
    :param authorities: The EFI_SIGNATURE_DATA entries of db that verified each image, in load order
    :returns: The PCR 7 value
    """
    digests = [
        hashlib.sha256(variable_event(EFI_GLOBAL_VARIABLE, "SecureBoot", secure_boot)).digest(),
        hashlib.sha256(variable_event(EFI_GLOBAL_VARIABLE, "PK", pk)).digest(),
        hashlib.sha256(variable_event(EFI_GLOBAL_VARIABLE, "KEK", kek)).digest(),
        hashlib.sha256(variable_event(EFI_IMAGE_SECURITY_DATABASE, "db", db)).digest(),
        hashlib.sha256(variable_event(EFI_IMAGE_SECURITY_DATABASE, "dbx", dbx)).digest(),
        hashlib.sha256(b"\x00\x00\x00\x00").digest(),
    ]
    for entry in authorities:
        digests.append(hashlib.sha256(variable_event(EFI_IMAGE_SECURITY_DATABASE, "db", entry)).digest())
    return replay(digests)


def check_log_model(events: list[Event]) -> list[str]:
    """
    Confirm the log's PCR 7 events use the layout :func:`pcr7_for` assumes.

    :param events: A parsed log
    :returns: Problems found, empty when the model holds
    """
    problems: list[str] = []
    for event in events:
        if event.pcr != 7 or event.sha256 is None:
            continue
        if hashlib.sha256(event.data).digest() != event.sha256:
            problems.append(f"PCR 7 event type {event.event_type:#x} is not measured as SHA256 of its data")
    return problems
