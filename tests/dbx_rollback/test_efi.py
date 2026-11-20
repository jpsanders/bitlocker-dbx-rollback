import pytest

from dbx_rollback.efi import auth2_payload, list_boundaries, parse_lists, simulate_append
from tests.dbx_rollback.conftest import sha_list, signed


def test_round_trip() -> None:
    data = sha_list([1, 2, 3]) + sha_list([4])
    lists = parse_lists(data)
    assert [len(item.entries) for item in lists] == [3, 1]
    assert b"".join(item.to_bytes() for item in lists) == data
    assert list_boundaries(data) == [28 + 3 * 48, 28 + 3 * 48 + 28 + 48]


def test_append_filters_existing_and_adds_one_list_per_update() -> None:
    factory = sha_list([1, 2])
    after_first = simulate_append(factory, sha_list([1, 2, 3, 4]))
    assert [len(item.entries) for item in parse_lists(after_first)] == [2, 2]
    after_second = simulate_append(after_first, sha_list([1, 2, 3, 4, 5]))
    assert [len(item.entries) for item in parse_lists(after_second)] == [2, 2, 1]
    assert simulate_append(after_second, sha_list([5])) == after_second


def test_auth2_payload_strips_header() -> None:
    payload = sha_list([9])
    assert auth2_payload(signed(payload)) == payload


def test_bad_data_raises() -> None:
    with pytest.raises(ValueError):
        parse_lists(b"\x00" * 30)
