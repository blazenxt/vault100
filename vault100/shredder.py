"""Secure file shredding.

Overwrites file contents with random data before deletion.

Honest caveat: overwriting is effective on classic magnetic HDDs and most
filesystems, but flash storage (SSDs, USB sticks) with wear-levelling and
copy-on-write or journaling filesystems may silently retain old blocks.
Where encryption is already used (as with Vault100), shredding is a second
layer of defence — the plaintext was never at rest unencrypted unless it
existed before you encrypted it.
"""

from __future__ import annotations

import os

_BLOCK = 4 * 1024 * 1024  # 4 MiB overwrite blocks


class ShredError(Exception):
    """Raised when a file cannot be shredded."""


def shred_file(path: str, *, passes: int = 3, progress=None) -> None:
    """Overwrite *path* with random data *passes* times, sync, then delete.

    *progress* is an optional ``progress(done_bytes, total_bytes)`` callback
    covering all passes combined.
    """
    if not os.path.isfile(path) or os.path.islink(path):
        raise ShredError(f"refusing to shred: {path!r} is not a regular file")

    size = os.path.getsize(path)
    total = max(size, 1) * passes
    done = 0

    with open(path, "r+b", buffering=0) as f:
        for _ in range(passes):
            f.seek(0)
            remaining = size
            while remaining > 0:
                block = os.urandom(min(_BLOCK, remaining))
                f.write(block)
                remaining -= len(block)
                done += len(block)
                if progress is not None:
                    progress(done, total)
            f.flush()
            os.fsync(f.fileno())
        f.truncate(0)
        f.flush()
        os.fsync(f.fileno())

    os.remove(path)
    if progress is not None and size == 0:
        progress(1, 1)
