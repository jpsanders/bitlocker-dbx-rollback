"""
Build a rebuild kit: the target dbx, the expected PK, KEK and db, the signed updates in order, and a guarded script.

The script runs on the locked machine from a Linux USB stick, after the firmware's factory Secure Boot keys were
loaded. It writes only dbx, checks every step against the simulation, stops at the first difference, can be rerun,
and has a read only ``verify`` mode for after a reboot. Every run appends to ``rebuild.log`` beside it.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from dbx_rollback.efi import auth2_payload, simulate_append

SCRIPT = r"""#!/usr/bin/env bash
# Rebuild dbx to the state a BitLocker TPM protector was sealed against, with signed append updates.
# Usage:  sudo bash rebuild.sh          (rebuild; safe to rerun)
#         sudo bash rebuild.sh verify   (read only check, for example after a reboot)
# Writes ONLY the dbx variable. Never touches the TPM or any disk. Log: rebuild.log next to this script.
set -u
K="$(cd "$(dirname "$0")" && pwd)"
EV=/sys/firmware/efi/efivars
V=$EV/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f
MODE="${1:-rebuild}"
TARGET_SIZE=__TARGET_SIZE__
STEPS=(__STEPS__)
exec > >(tee -a "$K/rebuild.log") 2>&1
echo; echo "=== $(date -u +%FT%TZ) mode=$MODE host=$(cat /sys/class/dmi/id/product_name 2>/dev/null) ==="
fail() { echo "STOP: $*"; echo "Do NOT boot Windows."; exit 1; }
[ "$(id -u)" = 0 ] || fail "run with sudo"
if systemctl list-unit-files secureboot-db.service >/dev/null 2>&1 && \
    ! systemctl is-enabled secureboot-db.service 2>/dev/null | grep -q -E 'masked|not-found'; then
    fail "secureboot-db.service would write dbx at every boot; run: sudo systemctl mask --now secureboot-db.service"
fi
cur() { tail -c +5 "$V"; }
size() { cur | wc -c; }
sb=$(od -An -tx1 -j4 -N1 $EV/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | tr -d ' ')
sm=$(od -An -tx1 -j4 -N1 $EV/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | tr -d ' ')
echo "SecureBoot=$sb SetupMode=$sm dbx=$(size) bytes sha256=$(cur | sha256sum | cut -c1-16)"
for n in PK KEK db; do
    f=$(ls $EV/$n-* 2>/dev/null | head -1); [ -n "$f" ] || fail "$n variable missing (load the factory keys first)"
    if cmp -s <(tail -c +5 "$f") "$K/expect-$n.bin"; then
        echo "$n: identical to the sealed state"
    else
        fail "$n differs from the sealed state"
    fi
done
[ "$sm" = 01 ] && fail "firmware is in Setup Mode; load the factory keys first"
isprefix() { cmp -s <(cur) <(head -c "$(size)" "$K/target-dbx.bin"); }
n=$(size)
{ [ "$n" -le "$TARGET_SIZE" ] && isprefix; } || fail "dbx ($n bytes) is not the factory list or a step of the rebuild"
if [ "$MODE" = verify ]; then
    cmp -s <(cur) "$K/target-dbx.bin" || fail "dbx is $n of $TARGET_SIZE bytes; run the rebuild"
    [ "$sb" = 01 ] || fail "dbx is right but Secure Boot is off; enable it in the firmware first"
    echo "VERIFIED: dbx equals the sealed state and Secure Boot is on. Unplug the USB and boot Windows."
    exit 0
fi
chattr -i "$V" 2>/dev/null
for s in "${STEPS[@]}"; do
    f=${s% *}; want=${s#* }
    [ "$(size)" -ge "$want" ] && { echo "$f: already applied ($(size) bytes)"; continue; }
    [ -f "$K/$f" ] || fail "missing $f"
    tmp=$(mktemp); printf '\x67\x00\x00\x00' > "$tmp"; cat "$K/$f" >> "$tmp"
    if cat "$tmp" > "$V" 2>"$tmp.err"; then
        echo "$f: write accepted"
    else
        echo "$f: write error: $(cat "$tmp.err")"
    fi
    rm -f "$tmp" "$tmp.err"
    got=$(size); echo "$f: dbx now $got bytes (expected $want)"
    [ "$got" = "$want" ] || fail "$f gave $got bytes, expected $want"
    isprefix || fail "dbx no longer matches the target after $f"
done
cmp -s <(cur) "$K/target-dbx.bin" || fail "final dbx differs from the target"
echo "SUCCESS: dbx is byte for byte the pre-lockout list (sha256 $(cur | sha256sum | cut -c1-16))."
echo "Next: reboot into the USB once more and run: sudo bash $0 verify"
"""


def build_kit(
    out: Path, factory_dbx: bytes, target: bytes, pk: bytes, kek: bytes, db: bytes, sequence: list[Path]
) -> list[tuple[str, int]]:
    """
    Write a rebuild kit after proving, by simulation, that the sequence rebuilds the target.

    :param out: The kit directory to create
    :param factory_dbx: dbx right after the firmware's factory key load
    :param target: The dbx to rebuild
    :param pk: PK data the sealed state used
    :param kek: KEK data the sealed state used
    :param db: db data the sealed state used
    :param sequence: The signed update files, in order
    :returns: Each step's file name and the dbx size it must produce
    :raises ValueError: When the sequence does not rebuild the target exactly
    """
    current = factory_dbx
    steps: list[tuple[str, int]] = []
    out.mkdir(parents=True, exist_ok=True)
    for number, path in enumerate(sequence, start=1):
        current = simulate_append(current, auth2_payload(path.read_bytes()))
        name = f"{number}-{path.name}"
        shutil.copyfile(path, out / name)
        steps.append((name, len(current)))
    if current != target:
        raise ValueError("the sequence does not rebuild the target dbx; no kit written")
    (out / "target-dbx.bin").write_bytes(target)
    (out / "factory-dbx.bin").write_bytes(factory_dbx)
    for label, data in (("PK", pk), ("KEK", kek), ("db", db)):
        (out / f"expect-{label}.bin").write_bytes(data)
    script = SCRIPT.replace("__TARGET_SIZE__", str(len(target))).replace(
        "__STEPS__", " ".join(f'"{name} {size}"' for name, size in steps)
    )
    (out / "rebuild.sh").write_text(script, encoding="utf-8")
    (out / "rebuild.sh").chmod(0o755)
    return steps
