"""The lock that keeps two processes from writing the same files, on any OS."""
import pytest

from shikari import filelock


def test_a_held_lock_refuses_a_second_holder(tmp_path):
    path = tmp_path / "x.lock"
    with open(path, "a") as first, open(path, "a") as second:
        filelock.lock(first)
        with pytest.raises(BlockingIOError):
            filelock.lock(second, block=False)
        filelock.unlock(first)
        filelock.lock(second, block=False)
        filelock.unlock(second)
