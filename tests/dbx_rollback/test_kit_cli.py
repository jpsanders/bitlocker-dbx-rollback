from pathlib import Path

import pytest

from dbx_rollback.cli import _build_parser
from dbx_rollback.kit import build_kit
from tests.dbx_rollback.conftest import sha_list, signed


def test_kit_proves_the_sequence(tmp_path: Path) -> None:
    factory = sha_list([1])
    first, second = tmp_path / "a.bin", tmp_path / "b.bin"
    first.write_bytes(signed(sha_list([1, 2])))
    second.write_bytes(signed(sha_list([1, 2, 3])))
    target = factory + sha_list([2]) + sha_list([3])
    steps = build_kit(tmp_path / "kit", factory, target, b"pk", b"kek", b"db", [first, second])
    assert steps == [("1-a.bin", 152), ("2-b.bin", 228)]
    script = (tmp_path / "kit" / "rebuild.sh").read_text()
    assert '"1-a.bin 152"' in script and "TARGET_SIZE=228" in script
    with pytest.raises(ValueError):
        build_kit(tmp_path / "bad", factory, target, b"pk", b"kek", b"db", [second])


def test_parser_commands() -> None:
    parser = _build_parser()
    args = parser.parse_args(["plan", "--factory-dbx", "f", "--target", "t", "--payloads", "p"])
    assert args.command == "plan"
    assert parser.parse_args([]).command is None
