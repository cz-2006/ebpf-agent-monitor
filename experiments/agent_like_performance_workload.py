#!/usr/bin/env python3
"""Deterministic low-density workload resembling an interactive tool-using Agent."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

CYCLES = 4
CPU_ITERATIONS_PER_CYCLE = 300_000
FILE_READS_PER_CYCLE = 25
CONNECTS_PER_CYCLE = 2
CHILDREN_PER_CYCLE = 2
WAIT_SECONDS_PER_CYCLE = 0.5


def timed(function):
    start = time.perf_counter_ns()
    result = function()
    return time.perf_counter_ns() - start, result


def cpu_action(seed: int) -> int:
    value = seed
    for _ in range(CPU_ITERATIONS_PER_CYCLE):
        value = (value * 1664525 + 1013904223) & 0xFFFFFFFF
    return value


def file_action(path: Path) -> int:
    byte_count = 0
    for _ in range(FILE_READS_PER_CYCLE):
        fd = os.open(path, os.O_RDONLY)
        try:
            byte_count += len(os.read(fd, 4096))
        finally:
            os.close(fd)
    return byte_count


def network_action(listener: socket.socket) -> int:
    accepted = 0
    address = listener.getsockname()
    for _ in range(CONNECTS_PER_CYCLE):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect(address)
            connection, _ = listener.accept()
            connection.close()
            accepted += 1
    return accepted


def process_action() -> int:
    completed = 0
    for _ in range(CHILDREN_PER_CYCLE):
        subprocess.run(
            ["/usr/bin/true"],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        completed += 1
    return completed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", type=Path)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="ebpf-agent-like-") as directory:
        fixture = Path(directory) / "context.txt"
        fixture.write_text("agent context\n" * 32, encoding="utf-8")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)

            cpu_ns = file_ns = network_ns = process_ns = wait_ns = 0
            checksum = bytes_read = accepted = children = 0
            total_start = time.perf_counter_ns()
            for cycle in range(CYCLES):
                elapsed, checksum = timed(lambda: cpu_action(checksum + cycle + 1))
                cpu_ns += elapsed
                elapsed, count = timed(lambda: file_action(fixture))
                file_ns += elapsed
                bytes_read += count
                elapsed, count = timed(lambda: network_action(listener))
                network_ns += elapsed
                accepted += count
                elapsed, count = timed(process_action)
                process_ns += elapsed
                children += count
                wait_start = time.perf_counter_ns()
                time.sleep(WAIT_SECONDS_PER_CYCLE)
                wait_ns += time.perf_counter_ns() - wait_start
            total_ns = time.perf_counter_ns() - total_start

    active_ns = cpu_ns + file_ns + network_ns + process_ns
    line = (
        f"total_ns={total_ns} active_ns={active_ns} wait_ns={wait_ns} "
        f"cpu_ns={cpu_ns} file_ns={file_ns} network_ns={network_ns} "
        f"process_ns={process_ns} checksum={checksum} bytes_read={bytes_read} "
        f"accepted={accepted} children={children} cycles={CYCLES}"
    )
    if args.result:
        with args.result.open("a", encoding="utf-8") as result_file:
            result_file.write(line + "\n")
    print("AGENT_LIKE_BENCHMARK " + line, flush=True)


if __name__ == "__main__":
    main()
