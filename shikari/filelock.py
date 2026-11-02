"""Locks between processes on a lock file, on Windows as well as macOS and Linux.

Open the lock file in append mode: on Windows a lock is mandatory, and opening with "w" truncates a
file another process may hold.
"""
import os
import time

if os.name == "nt":
    import msvcrt

    def lock(fh, block=True):
        """Take the lock; without block, raise BlockingIOError if another process has it."""
        while True:
            try:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                if not block:
                    raise BlockingIOError("locked by another process") from None
                time.sleep(0.05)

    def unlock(fh):
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def lock(fh, block=True):
        """Take the lock; without block, raise BlockingIOError if another process has it."""
        fcntl.flock(fh, fcntl.LOCK_EX | (0 if block else fcntl.LOCK_NB))

    def unlock(fh):
        fcntl.flock(fh, fcntl.LOCK_UN)
