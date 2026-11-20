"""Find the dbx a TPM protector was sealed against, and the signed updates that rebuild it."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from dbx_rollback.bitlocker import SealedPolicy
from dbx_rollback.efi import list_boundaries, parse_lists, simulate_append
from dbx_rollback.tcg import ZERO, pcr7_for


@dataclass(frozen=True)
class SealedState:
    """A dbx and boot authority that reproduce the sealed PCR 7."""

    dbx_length: int
    authority_index: int


def find_sealed_dbx(
    policy: SealedPolicy, secure_boot: bytes, pk: bytes, kek: bytes, db: bytes, dbx: bytes
) -> list[SealedState]:
    """
    Try every list boundary of dbx with every db entry as the boot authority.

    Firmware only appends to dbx, so the dbx a protector was sealed against is normally a prefix of today's, cut at
    a list boundary.

    :param policy: The protector's sealed policy (PCRs 7 and 11)
    :param secure_boot: The SecureBoot variable data
    :param pk: PK data
    :param kek: KEK data
    :param db: db data
    :param dbx: Today's dbx data
    :returns: Every combination that matches, usually exactly one
    """
    entries = [entry for item in parse_lists(db) for entry in item.entries]
    found: list[SealedState] = []
    for end in [0, *list_boundaries(dbx)]:
        for index, entry in enumerate(entries):
            value = pcr7_for(secure_boot, pk, kek, db, dbx[:end], [entry])
            if policy.matches([value, ZERO]):
                found.append(SealedState(end, index))
    return found


def find_sequence(start: bytes, target: bytes, payloads: Mapping[str, bytes], max_steps: int = 12) -> list[str] | None:
    """
    Search for an order of signed updates that turns ``start`` into ``target``.

    Every step must keep the result a prefix of the target, which keeps the search small.

    :param start: The dbx after a factory key load
    :param target: The dbx to rebuild
    :param payloads: Signature lists of each candidate update, by name (see :func:`efi.auth2_payload`)
    :param max_steps: The longest sequence to try
    :returns: The update names in order, or ``None`` when no sequence rebuilds the target
    """
    if not target.startswith(start):
        return None

    def walk(current: bytes, path: list[str]) -> list[str] | None:
        if current == target:
            return path
        if len(path) >= max_steps:
            return None
        for name, payload in payloads.items():
            after = simulate_append(current, payload)
            if len(after) > len(current) and target.startswith(after):
                result = walk(after, [*path, name])
                if result is not None:
                    return result
        return None

    return walk(start, [])


def missing_step(start: bytes, target: bytes, payloads: Mapping[str, bytes]) -> tuple[int, int] | None:
    """
    Report the first target list no candidate update produces.

    :param start: The dbx after a factory key load
    :param target: The dbx to rebuild
    :param payloads: Candidate updates by name
    :returns: (list index, entry count) of the first list that cannot be reached, or ``None``
    """
    current = start
    while current != target:
        for payload in payloads.values():
            after = simulate_append(current, payload)
            if len(after) > len(current) and target.startswith(after):
                current = after
                break
        else:
            index = len(parse_lists(current))
            return index, len(parse_lists(target)[index].entries)
    return None
