"""
Fetch Microsoft signed dbx updates from their public homes. Nothing is redistributed by this project.

*   LVFS publishes every uefi.org dbx release as a cabinet.
*   ``microsoft/secureboot_objects`` keeps the current files and their git history.
*   Windows keeps the updates it applied in ``System32/SecureBootUpdates`` and ``WinSxS``; :func:`from_windows`
    collects those from a mounted Windows volume you own.
"""

from __future__ import annotations

import json
import re
import subprocess  # nosec B404
import urllib.parse
import urllib.request
from pathlib import Path

from dbx_rollback.windows import cabinet_files

LVFS_INDEX = "https://cdn.fwupd.org/downloads/firmware.xml.zst"
LVFS_DOWNLOAD = "https://cdn.fwupd.org/downloads/"
SECUREBOOT_OBJECTS = "https://github.com/microsoft/secureboot_objects"
USER_AGENT = "bitlocker-dbx-rollback"


def _get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    with urllib.request.urlopen(request, timeout=120) as response:  # nosec B310
        return bytes(response.read())


def lvfs(destination: Path, architecture: str = "x64") -> list[Path]:
    """
    Download every dbx cabinet for an architecture from LVFS and unpack its payload.

    :param destination: Directory for the payloads
    :param architecture: ``x64``, ``ia32`` or ``aa64``
    :returns: The payload files written
    :raises RuntimeError: When zstd is missing
    """
    destination.mkdir(parents=True, exist_ok=True)
    compressed = _get(LVFS_INDEX)
    try:
        xml = subprocess.run(  # nosec B603 B607
            ["zstd", "-dc"], input=compressed, capture_output=True, check=True
        ).stdout.decode("utf-8", "replace")
    except FileNotFoundError as error:
        raise RuntimeError("install zstd to read the LVFS index") from error
    names = sorted(set(re.findall(rf"[0-9a-f]{{64}}-DBXUpdate-[0-9]+(?:-legacy)?-{architecture}\.cab", xml)))
    written: list[Path] = []
    for name in names:
        for inner, data in cabinet_files(_get(LVFS_DOWNLOAD + name)).items():
            if inner.lower().endswith(".bin"):
                path = destination / f"lvfs-{Path(inner).name}"
                path.write_bytes(data)
                written.append(path)
    return written


def secureboot_objects(destination: Path, checkout: Path) -> list[Path]:
    """
    Collect every historical x64 dbx file from Microsoft's secureboot_objects repository.

    :param destination: Directory for the payloads
    :param checkout: Where to clone the repository (blobs are fetched on demand)
    :returns: The payload files written
    """
    destination.mkdir(parents=True, exist_ok=True)
    if not (checkout / ".git").is_dir():
        subprocess.run(  # nosec B603 B607
            ["git", "clone", "-q", "--filter=blob:none", SECUREBOOT_OBJECTS, str(checkout)], check=True
        )
    git = ["git", "-C", str(checkout)]
    commits = subprocess.run(  # nosec B603 B607
        [*git, "log", "--all", "--format=%H", "--", "*.bin", "*.efiauth2"], capture_output=True, text=True, check=True
    ).stdout.split()
    written: dict[bytes, Path] = {}
    for commit in commits:
        files = subprocess.run(  # nosec B603 B607
            [*git, "ls-tree", "-r", "--name-only", commit], capture_output=True, text=True, check=True
        ).stdout.splitlines()
        for name in files:
            if not re.search(r"dbx", name, re.I) or re.search(r"arm|aa64|aarch64|ia32|x86", name, re.I):
                continue
            if not name.endswith((".bin", ".efiauth2")):
                continue
            data = subprocess.run(  # nosec B603 B607
                [*git, "show", f"{commit}:{name}"], capture_output=True, check=True
            ).stdout
            if len(data) > 100 and data not in written:
                path = destination / f"sbo-{commit[:8]}-{name.replace('/', '_')}"
                path.write_bytes(data)
                written[data] = path
    return list(written.values())


def from_windows(windows_root: Path, destination: Path) -> list[Path]:
    """
    Copy the dbx updates a Windows installation applied, from a read only mount of it.

    :param windows_root: The mounted volume's root (the folder holding ``Windows``)
    :param destination: Directory for the payloads
    :returns: The files copied; ``f``, ``r`` and ``n`` folder entries are MSDELTA patches, not payloads
    """
    destination.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    patterns = ["Windows/System32/SecureBootUpdates/*dbx*", "Windows/WinSxS/*boot-firmwareupdate*/**/*dbx*"]
    for pattern in patterns:
        for path in windows_root.glob(pattern):
            if path.is_file():
                label = path.relative_to(windows_root).as_posix().replace("/", "_")
                target = destination / f"win-{label}"
                target.write_bytes(path.read_bytes())
                written.append(target)
    return written


def catalog_links(kb: str) -> list[str]:
    """
    Find the download links of a Windows update in the Microsoft Update Catalog.

    :param kb: The update's KB number, such as ``KB5036894``
    :returns: Direct ``.msu`` and ``.cab`` links
    """
    page = _get(f"https://www.catalog.update.microsoft.com/Search.aspx?q={kb}").decode("utf-8", "replace")
    links: list[str] = []
    for update_id in sorted(set(re.findall(r'goToDetails\("([0-9a-f-]{36})"\)', page))):
        body = json.dumps([{"size": 0, "languages": "", "uidInfo": update_id, "updateID": update_id}])
        request = urllib.request.Request(  # noqa: S310
            "https://www.catalog.update.microsoft.com/DownloadDialog.aspx",
            data=("updateIDs=" + urllib.parse.quote(body)).encode(),
            headers={"User-Agent": USER_AGENT, "Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(request, timeout=60) as response:  # nosec B310
            links += re.findall(r"https?://[^'\"]+\.(?:msu|cab)", response.read().decode("utf-8", "replace"))
    return sorted(set(links))
