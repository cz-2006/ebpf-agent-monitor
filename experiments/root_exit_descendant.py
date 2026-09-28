#!/usr/bin/env python3
"""Exit the root first while a descendant remains alive briefly."""

import os
import time


def main() -> None:
    child = os.fork()
    if child == 0:
        print(
            f"WORKLOAD role=descendant pid={os.getpid()} "
            f"parent_pid={os.getppid()} state=running",
            flush=True,
        )
        time.sleep(0.8)
        print(
            f"WORKLOAD role=descendant pid={os.getpid()} state=done",
            flush=True,
        )
        os._exit(0)

    print(
        f"WORKLOAD role=root pid={os.getpid()} child_pid={child} "
        "state=exiting_first",
        flush=True,
    )
    os._exit(0)


if __name__ == "__main__":
    main()
