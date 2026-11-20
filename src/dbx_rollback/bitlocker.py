"""
BitLocker TPM protectors: read the sealed PCR policy from a TPM_ENCODED key protector.

A TPM-only protector seals the VMK to PolicyAuthValue followed by PolicyPCR over the SHA256 bank. The protector
stores the TPM2B_PRIVATE and TPM2B_PUBLIC of the sealed object, then the PolicyPCR digest and the PCR bitmap. This
module pulls those out and checks they reproduce the object's authPolicy, so a candidate PCR 7 can be tested offline.
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass

TPM_CC_POLICY_AUTH_VALUE = 0x0000016B
TPM_CC_POLICY_PCR = 0x0000017F


@dataclass(frozen=True)
class SealedPolicy:
    """The PCR policy a TPM protector is sealed to."""

    auth_policy: bytes
    pcr_digest: bytes
    pcr_bitmap: bytes

    @property
    def pcrs(self) -> list[int]:
        """
        Give the PCR numbers the policy covers.

        :returns: The selected PCRs
        """
        return [8 * index + bit for index, byte in enumerate(self.pcr_bitmap) for bit in range(8) if byte >> bit & 1]

    def expected_policy(self) -> bytes:
        """
        Recompute authPolicy as PolicyAuthValue then PolicyPCR.

        :returns: The policy digest the stored values imply
        """
        selection = struct.pack(">IHB", 1, 0x000B, len(self.pcr_bitmap)) + self.pcr_bitmap
        after_auth = hashlib.sha256(b"\x00" * 32 + struct.pack(">I", TPM_CC_POLICY_AUTH_VALUE)).digest()
        return hashlib.sha256(after_auth + struct.pack(">I", TPM_CC_POLICY_PCR) + selection + self.pcr_digest).digest()

    def consistent(self) -> bool:
        """
        Check the stored PCR digest really is what authPolicy commits to.

        :returns: Whether the policy model holds for this protector
        """
        return self.expected_policy() == self.auth_policy

    def matches(self, pcr_values: list[bytes]) -> bool:
        """
        Test whether the TPM would unseal with these PCR values.

        :param pcr_values: One value per selected PCR, in ascending PCR order
        :returns: Whether SHA256 of the concatenated values equals the sealed digest
        """
        return hashlib.sha256(b"".join(pcr_values)).digest() == self.pcr_digest


def parse_tpm_encoded(payload: bytes) -> SealedPolicy:
    """
    Read a TPM_ENCODED key protector payload.

    :param payload: The payload bytes of the TPM_ENCODED datum
    :returns: The sealed policy
    :raises ValueError: When the layout is not the expected private, public, digest, bitmap sequence
    """
    offset = 0
    private_size = struct.unpack_from(">H", payload, offset)[0]
    offset += 2 + private_size
    public_size = struct.unpack_from(">H", payload, offset)[0]
    public = payload[offset + 2 : offset + 2 + public_size]
    offset += 2 + public_size
    policy_size = struct.unpack_from(">H", public, 8)[0]
    auth_policy = public[10 : 10 + policy_size]
    digest_size = struct.unpack_from(">H", payload, offset)[0]
    pcr_digest = payload[offset + 2 : offset + 2 + digest_size]
    offset += 2 + digest_size
    bitmap_size = payload[offset]
    pcr_bitmap = payload[offset + 1 : offset + 1 + bitmap_size]
    if len(auth_policy) != 32 or len(pcr_digest) != 32 or not pcr_bitmap:
        raise ValueError("payload is not a TPM_ENCODED protector with a SHA256 PCR policy")
    return SealedPolicy(auth_policy, pcr_digest, pcr_bitmap)


def payloads_from_dislocker(text: str) -> list[bytes]:
    """
    Pull every TPM_ENCODED payload out of ``dislocker-metadata -V`` output.

    :param text: The tool's printed output
    :returns: One payload per TPM protector found
    """
    payloads: list[bytes] = []
    for block in re.split(r"TPM_ENCODED", text)[1:]:
        chunk = block.split("Payload:", 1)
        if len(chunk) < 2:
            continue
        data = bytearray()
        for line in chunk[1].splitlines():
            match = re.search(r"0x[0-9a-f]{8} ((?:[0-9a-f]{2}[ -]?)+)", line)
            if match:
                data += bytes.fromhex(match.group(1).replace("-", " "))
            elif data and ("~~~" in line or "---" in line or "====" in line):
                break
        if data:
            payloads.append(bytes(data))
    return payloads
