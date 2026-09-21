#!/usr/bin/env python3
"""Reach the failed-open threshold, then remain CPU-idle."""

import errno
import os
import shutil
import time
from pathlib import Path

TEST_DIR = Path("/tmp/ebpf-agent-monitor-repeat-only")
TARGET = TEST_DIR / "missing.txt"


def main() -> None:
    TEST_DIR.mkdir()
    try:
        # Let interpreter startup CPU fall into an earlier sampling interval.
        time.sleep(0.5)
        print(
            f"WORKLOAD role=repeat_only pid={os.getpid()} target={TARGET}",
            flush=True,
        )
        for attempt in range(1, 6):
            try:
                TARGET.open("rb")
            except OSError as error:
                if error.errno != errno.ENOENT:
                    raise
                print(
                    f"WORKLOAD role=repeat_only pid={os.getpid()} "
                    f"attempt={attempt} errno={error.errno}",
                    flush=True,
                )
            else:
                raise RuntimeError("missing test file unexpectedly exists")

        # Stay alive for several CPU samples without doing CPU-intensive work.
        time.sleep(0.8)
    finally:
        shutil.rmtree(TEST_DIR)
    print(f"WORKLOAD role=repeat_only pid={os.getpid()} done=1", flush=True)


if __name__ == "__main__":
    main()
