#!/usr/bin/env python3
"""Generate repeated ENOENT activity followed by sustained CPU work."""

import errno
import os
import shutil
import time
from pathlib import Path

TEST_DIR = Path("/tmp/ebpf-agent-monitor-resource")
TARGET = TEST_DIR / "missing.txt"
ATTEMPTS = 5
BUSY_SECONDS = 1.0


def main() -> None:
    # Refuse to touch a pre-existing directory so cleanup stays test-local.
    TEST_DIR.mkdir()
    try:
        print(
            f"WORKLOAD pid={os.getpid()} target={TARGET} "
            f"attempts={ATTEMPTS} busy_seconds={BUSY_SECONDS}",
            flush=True,
        )
        for attempt in range(1, ATTEMPTS + 1):
            try:
                TARGET.open("rb")
            except OSError as error:
                if error.errno != errno.ENOENT:
                    raise
                print(
                    f"WORKLOAD pid={os.getpid()} attempt={attempt} "
                    f"errno={error.errno}",
                    flush=True,
                )
            else:
                raise RuntimeError("missing test file unexpectedly exists")

        # A wall-clock deadline makes the cgroup sampler observe several intervals.
        deadline = time.monotonic() + BUSY_SECONDS
        value = 1
        while time.monotonic() < deadline:
            value = (value * 1664525 + 1013904223) & 0xFFFFFFFF

        print(f"WORKLOAD pid={os.getpid()} cpu_busy_done=1 checksum={value}", flush=True)
    finally:
        shutil.rmtree(TEST_DIR)
    print(f"WORKLOAD pid={os.getpid()} done=1", flush=True)


if __name__ == "__main__":
    main()
