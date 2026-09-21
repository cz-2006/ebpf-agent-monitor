#!/usr/bin/env python3
"""Fixed mixed workload used for monitored/unmonitored timing comparisons."""

import argparse
import os
import socket
import subprocess
import time
from pathlib import Path

CPU_ITERATIONS = 2_000_000
FILE_OPENS = 10_000
TCP_CONNECTS = 500
CHILD_PROCESSES = 100


def timed(function):
    start = time.perf_counter_ns()
    result = function()
    return time.perf_counter_ns() - start, result


def cpu_phase() -> int:
    value = 1
    for _ in range(CPU_ITERATIONS):
        value = (value * 1664525 + 1013904223) & 0xFFFFFFFF
    return value


def file_phase() -> int:
    total = 0
    for _ in range(FILE_OPENS):
        fd = os.open("/dev/null", os.O_RDONLY)
        total += fd
        os.close(fd)
    return total


def network_phase() -> int:
    accepted = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        address = listener.getsockname()
        for _ in range(TCP_CONNECTS):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.connect(address)
                connection, _ = listener.accept()
                connection.close()
                accepted += 1
    return accepted


def process_phase() -> int:
    completed = 0
    for _ in range(CHILD_PROCESSES):
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

    total_start = time.perf_counter_ns()
    cpu_ns, checksum = timed(cpu_phase)
    file_ns, fd_sum = timed(file_phase)
    network_ns, accepted = timed(network_phase)
    process_ns, completed = timed(process_phase)
    total_ns = time.perf_counter_ns() - total_start

    line = (
        f"total_ns={total_ns} cpu_ns={cpu_ns} file_ns={file_ns} "
        f"network_ns={network_ns} process_ns={process_ns} "
        f"checksum={checksum} fd_sum={fd_sum} "
        f"accepted={accepted} children={completed}"
    )
    if args.result:
        with args.result.open("a", encoding="utf-8") as result_file:
            result_file.write(line + "\n")
    print("BENCHMARK " + line, flush=True)


if __name__ == "__main__":
    main()
