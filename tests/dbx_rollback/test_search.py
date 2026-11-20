import hashlib
import struct

from dbx_rollback.bitlocker import SealedPolicy, parse_tpm_encoded
from dbx_rollback.search import find_sealed_dbx, find_sequence, missing_step
from dbx_rollback.tcg import ZERO, pcr7_for
from tests.dbx_rollback.conftest import sha_list


def _policy_for(pcr7: bytes) -> SealedPolicy:
    digest = hashlib.sha256(pcr7 + ZERO).digest()
    bitmap = bytes([0x80, 0x08, 0x00])
    unsealed = SealedPolicy(b"", digest, bitmap)
    return SealedPolicy(unsealed.expected_policy(), digest, bitmap)


def test_policy_model_and_pcrs() -> None:
    policy = _policy_for(ZERO)
    assert policy.consistent()
    assert policy.pcrs == [7, 11]


def test_parse_tpm_encoded_layout() -> None:
    policy = _policy_for(b"\x01" * 32)
    public = struct.pack(">HHI", 8, 11, 0x412) + struct.pack(">H", 32) + policy.auth_policy + b"\x00\x10"
    public += struct.pack(">H", 32) + b"\x02" * 32
    blob = struct.pack(">H", 4) + b"priv" + struct.pack(">H", len(public)) + public
    blob += struct.pack(">H", 32) + policy.pcr_digest + bytes([3]) + policy.pcr_bitmap
    parsed = parse_tpm_encoded(blob)
    assert parsed == policy and parsed.consistent()


def test_find_sealed_dbx_finds_the_prefix_before_an_append() -> None:
    pk, kek = sha_list([100]), sha_list([101])
    db = sha_list([102, 103])
    sealed_dbx = sha_list([1, 2]) + sha_list([3])
    authority = db[28 + 48 : 28 + 96]
    policy = _policy_for(pcr7_for(b"\x01", pk, kek, db, sealed_dbx, [authority]))
    today = sealed_dbx + sha_list([4, 5, 6])
    found = find_sealed_dbx(policy, b"\x01", pk, kek, db, today)
    assert [(state.dbx_length, state.authority_index) for state in found] == [(len(sealed_dbx), 1)]


def test_find_sequence_and_gap() -> None:
    factory = sha_list([1, 2])
    target = factory + sha_list([3]) + sha_list([4, 5])
    payloads = {"big": sha_list([1, 2, 3, 4, 5]), "small": sha_list([1, 2, 3]), "noise": sha_list([9])}
    assert find_sequence(factory, target, payloads) == ["small", "big"]
    assert missing_step(factory, target, {"big": payloads["big"]}) == (1, 1)
