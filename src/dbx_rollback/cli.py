"""
Command line for bitlocker-dbx-rollback.

    dbx-rollback analyze --efivars DIR --dislocker-log FILE --out target-dbx.bin
    dbx-rollback fetch --out payloads/ [--lvfs] [--secureboot-objects] [--windows /mnt/win]
    dbx-rollback plan --factory-dbx FILE --target FILE --payloads payloads/
    dbx-rollback psf --cab Windows10.0-KBxxxx-x64.cab --psf Windows10.0-KBxxxx-x64.psf --out patches/
    dbx-rollback apply-delta --msdelta DLL --python python.exe [--base FILE] --delta FILE --out FILE
    dbx-rollback kit --efivars DIR --factory-dbx FILE --target FILE --sequence A B C --out kit/
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess  # nosec B404
import sys
from importlib import metadata, resources
from pathlib import Path

from dbx_rollback import bitlocker, efi, search, sources, windows
from dbx_rollback.kit import build_kit


def _build_parser() -> argparse.ArgumentParser:
    """
    Build the argument parser.

    :returns: The parser
    """
    parser = argparse.ArgumentParser(
        prog="dbx-rollback",
        description="Recover a BitLocker drive whose TPM unlock broke because the Secure Boot dbx changed.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_version()}")
    sub = parser.add_subparsers(dest="command")

    analyze = sub.add_parser("analyze", help="find the dbx the TPM protector was sealed against")
    analyze.add_argument("--efivars", type=Path, default=efi.EFIVARS, help="efivarfs or a copy of it")
    analyze.add_argument("--dislocker-log", type=Path, required=True, help="output of dislocker-metadata -V")
    analyze.add_argument("--out", type=Path, help="write the sealed dbx here")

    fetch = sub.add_parser("fetch", help="download Microsoft signed dbx updates from their public sources")
    fetch.add_argument("--out", type=Path, required=True)
    fetch.add_argument("--lvfs", action="store_true", help="every uefi.org release from LVFS")
    fetch.add_argument("--secureboot-objects", action="store_true", help="microsoft/secureboot_objects history")
    fetch.add_argument("--checkout", type=Path, default=Path("secureboot_objects"))
    fetch.add_argument("--windows", type=Path, help="a mounted Windows volume you own")
    fetch.add_argument("--catalog", metavar="KB", help="print Update Catalog links for a KB, such as KB5036894")

    plan = sub.add_parser("plan", help="find the order of signed updates that rebuilds the sealed dbx")
    plan.add_argument("--factory-dbx", type=Path, required=True, help="dbx after a factory key load (dbxDefault)")
    plan.add_argument("--target", type=Path, required=True)
    plan.add_argument("--payloads", type=Path, required=True, help="directory of signed update files")

    psf = sub.add_parser("psf", help="pull dbx patches out of a Windows update's express package")
    psf.add_argument("--cab", type=Path, required=True, help="the inner Windows10.0-KB...-x64.cab")
    psf.add_argument("--psf", type=Path, required=True, help="the matching .psf file")
    psf.add_argument("--out", type=Path, required=True)

    delta = sub.add_parser("apply-delta", help="apply a PA30 patch with msdelta.dll under Wine")
    delta.add_argument("--msdelta", type=Path, required=True, help="msdelta.dll from a Windows install you own")
    delta.add_argument("--python", type=Path, required=True, help="python.exe of the Windows embeddable package")
    delta.add_argument("--base", type=Path, help="file the patch applies to; omit for a patch against nothing")
    delta.add_argument("--delta", type=Path, required=True)
    delta.add_argument("--out", type=Path, required=True)

    kit = sub.add_parser("kit", help="write a verified rebuild kit and its guarded script")
    kit.add_argument("--efivars", type=Path, default=efi.EFIVARS)
    kit.add_argument("--factory-dbx", type=Path, required=True)
    kit.add_argument("--target", type=Path, required=True)
    kit.add_argument("--sequence", type=Path, nargs="+", required=True)
    kit.add_argument("--out", type=Path, required=True)

    sub.add_parser("guide", help="print the full manual, for people and agents")
    man = sub.add_parser("man", help="show the man page")
    man.add_argument("--install", action="store_true", help="install it so `man dbx-rollback` works")
    man.add_argument("--raw", action="store_true", help="print the roff source")
    return parser


def _version() -> str:
    """
    Read the installed version, which setuptools_scm takes from the git tag.

    :returns: The version, or ``unknown`` in a source tree that was never installed
    """
    try:
        return metadata.version("bitlocker-dbx-rollback")
    except metadata.PackageNotFoundError:
        return "unknown"


def _data(name: str) -> str:
    """
    Read a file shipped in the package's data folder.

    :param name: File name inside ``data``
    :returns: Its text
    """
    return (resources.files("dbx_rollback") / "data" / name).read_text(encoding="utf-8")


def _man(install: bool, raw: bool) -> None:
    """
    Show the man page, print its roff source, or install it for ``man dbx-rollback``.

    :param install: Write it to the per user man folder
    :param raw: Print the roff source
    """
    page = _data("dbx-rollback.1")
    if install:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        target = Path(base) / "man" / "man1" / "dbx-rollback.1"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(page, encoding="utf-8")
        print(f"installed {target}; open it with: man dbx-rollback")
        return
    man = shutil.which("man")
    if man and sys.stdout.isatty() and not raw:
        with resources.as_file(resources.files("dbx_rollback") / "data" / "dbx-rollback.1") as path:
            subprocess.call([man, "-l", str(path)])  # nosec B603: man, fixed arguments
        return
    print(page, end="")


def _require(data: bytes | None, name: str) -> bytes:
    """
    Fail clearly when a variable is missing.

    :param data: The variable's data or ``None``
    :param name: Its name, for the message
    :returns: The data
    :raises SystemExit: When the variable is missing
    """
    if data is None:
        raise SystemExit(f"{name} not found in the efivars directory")
    return data


def _analyze(args: argparse.Namespace) -> None:
    """
    Report which dbx the protector was sealed against.

    :param args: Parsed arguments
    :raises SystemExit: When no TPM protector or no match is found
    """
    payloads = bitlocker.payloads_from_dislocker(args.dislocker_log.read_text(encoding="utf-8", errors="replace"))
    if not payloads:
        raise SystemExit("no TPM_ENCODED protector in that dislocker-metadata output")
    policy = bitlocker.parse_tpm_encoded(payloads[0])
    print(f"TPM protector: PCRs {policy.pcrs}, policy model {'holds' if policy.consistent() else 'DOES NOT hold'}")
    if policy.pcrs != [7, 11]:
        raise SystemExit("this tool handles protectors sealed to PCRs 7 and 11 only")
    v = {name: _require(efi.read_variable(name, args.efivars), name) for name in ("SecureBoot", "PK", "KEK", "db")}
    dbx = _require(efi.read_variable("dbx", args.efivars), "dbx")
    found = search.find_sealed_dbx(policy, v["SecureBoot"], v["PK"], v["KEK"], v["db"], dbx)
    if not found:
        raise SystemExit("no prefix of today's dbx matches; PK, KEK, db or the boot path changed too")
    for state in found:
        print(f"MATCH: the protector was sealed with dbx = first {state.dbx_length} of {len(dbx)} bytes")
    if args.out:
        args.out.write_bytes(dbx[: found[0].dbx_length])
        print(f"wrote {args.out}")


def _fetch(args: argparse.Namespace) -> None:
    """
    Download signed updates, or list catalog links.

    :param args: Parsed arguments
    """
    if args.catalog:
        for link in sources.catalog_links(args.catalog):
            print(link)
        return
    written: list[Path] = []
    if args.lvfs:
        written += sources.lvfs(args.out)
    if args.secureboot_objects:
        written += sources.secureboot_objects(args.out, args.checkout)
    if args.windows:
        written += sources.from_windows(args.windows, args.out)
    print(f"{len(written)} files in {args.out}")


def _payloads(directory: Path) -> dict[str, bytes]:
    """
    Load every parseable signed update in a directory.

    :param directory: Where the update files are
    :returns: Signature lists by file name
    """
    loaded: dict[str, bytes] = {}
    for path in sorted(directory.iterdir()):
        try:
            payload = efi.auth2_payload(path.read_bytes())
            efi.parse_lists(payload)
        except ValueError, OSError:
            continue
        if payload and payload not in loaded.values():
            loaded[path.name] = payload
    return loaded


def _plan(args: argparse.Namespace) -> None:
    """
    Print the update order that rebuilds the target, or the first gap.

    :param args: Parsed arguments
    :raises SystemExit: When no complete sequence exists
    """
    start, target = args.factory_dbx.read_bytes(), args.target.read_bytes()
    payloads = _payloads(args.payloads)
    print(f"{len(payloads)} distinct signed updates loaded")
    sequence = search.find_sequence(start, target, payloads)
    if sequence:
        print("REBUILDS EXACTLY, in this order:")
        for step in sequence:
            print(f"  {step}")
        return
    gap = search.missing_step(start, target, payloads)
    if gap:
        raise SystemExit(f"no update produces list {gap[0]} ({gap[1]} entries); find the update Windows applied then")
    raise SystemExit("the factory dbx is not a prefix of the target")


def _psf(args: argparse.Namespace) -> None:
    """
    Extract dbx patches from an express package.

    :param args: Parsed arguments
    :raises SystemExit: When the index is missing
    """
    files = windows.cabinet_files(args.cab.read_bytes())
    index = next((data for name, data in files.items() if name.endswith("express.psf.cix.xml")), None)
    if index is None:
        raise SystemExit("no express.psf.cix.xml in that cabinet")
    args.out.mkdir(parents=True, exist_ok=True)
    with args.psf.open("rb") as handle:
        for entry in windows.psf_entries(index.decode("utf-8", "replace")):
            handle.seek(entry.offset)
            name = entry.name.replace("/", "_")
            (args.out / name).write_bytes(handle.read(entry.length))
            print(f"{name} ({entry.length} bytes, a PA30 patch)")


def main(argv: list[str] | None = None) -> None:
    """
    Run the command line.

    :param argv: Arguments, defaulting to ``sys.argv``
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return
    if args.command == "guide":
        print(_data("MANUAL.md"), end="")
    elif args.command == "man":
        _man(args.install, args.raw)
    elif args.command == "analyze":
        _analyze(args)
    elif args.command == "fetch":
        _fetch(args)
    elif args.command == "plan":
        _plan(args)
    elif args.command == "psf":
        _psf(args)
    elif args.command == "apply-delta":
        windows.apply_delta(args.msdelta, args.python, args.base, args.delta, args.out)
        print(f"wrote {args.out}")
    elif args.command == "kit":
        variables = {name: _require(efi.read_variable(name, args.efivars), name) for name in ("PK", "KEK", "db")}
        steps = build_kit(
            args.out,
            args.factory_dbx.read_bytes(),
            args.target.read_bytes(),
            variables["PK"],
            variables["KEK"],
            variables["db"],
            list(args.sequence),
        )
        for name, size in steps:
            print(f"{name}: dbx must reach {size} bytes")
        print(f"kit written to {args.out}; run it with: sudo bash {args.out}/rebuild.sh")
