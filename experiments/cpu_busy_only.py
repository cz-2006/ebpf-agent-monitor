#!/usr/bin/env python3
"""Consume one CPU without generating the target repeated-open activity."""

import os
import time

BUSY_SECONDS = 0.8


def main() -> None:
    # Align the busy phase with the repeat-only Agent's activity phase.
    time.sleep(0.5)
    print(
        f"WORKLOAD role=cpu_only pid={os.getpid()} "
        f"busy_seconds={BUSY_SECONDS}",
        flush=True,
    )
    deadline = time.monotonic() + BUSY_SECONDS
    value = 1
    while time.monotonic() < deadline:
        value = (value * 1103515245 + 12345) & 0xFFFFFFFF
    print(
        f"WORKLOAD role=cpu_only pid={os.getpid()} "
        f"done=1 checksum={value}",
        flush=True,
    )


if __name__ == "__main__":
    main()
