#!/usr/bin/env python3
"""Deterministic workloads for the one-command acceptance demo."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import socket
import subprocess
import time


def run_security(args: argparse.Namespace) -> int:
    sensitive = Path(args.sensitive_file)
    allowed = Path(args.allowed_file)
    outside = Path(args.outside_file)
    missing = Path(args.missing_file)

    content = sensitive.read_text(encoding="utf-8").strip()
    print(f"DEMO role=security sensitive_read={content}", flush=True)

    allowed.unlink()
    print(f"DEMO role=security allowed_deleted=1 target={allowed}", flush=True)
    outside.unlink()
    print(f"DEMO role=security outside_deleted=1 target={outside}", flush=True)

    for attempt in range(1, 6):
        try:
            missing.open("rb")
        except FileNotFoundError as error:
            print(
                f"DEMO role=security failed_open={attempt} errno={error.errno}",
                flush=True,
            )

    deadline = time.monotonic() + 1.2
    checksum = 0
    while time.monotonic() < deadline:
        checksum = (checksum * 33 + 17) & 0xFFFFFFFF
    print(f"DEMO role=security cpu_busy_done=1 checksum={checksum}", flush=True)
    return 0


def run_process_network(_: argparse.Namespace) -> int:
    shell = subprocess.run(["/bin/sh", "-c", "exit 0"], check=False)
    print(f"DEMO role=process_network shell_exit={shell.returncode}", flush=True)
    if shell.returncode:
        return 1

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        host, port = server.getsockname()
        child = os.fork()
        if child == 0:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                    client.connect((host, port))
                print(
                    f"DEMO role=network_child pid={os.getpid()} "
                    f"target={host}:{port} connected=1",
                    flush=True,
                )
                os._exit(0)
            except Exception as error:
                print(f"DEMO role=network_child error={error}", flush=True)
                os._exit(1)

        connection, address = server.accept()
        connection.close()
        _, status = os.waitpid(child, 0)
        child_exit = os.waitstatus_to_exitcode(status)
        print(
            f"DEMO role=process_network child_pid={child} peer={address[0]}:"
            f"{address[1]} child_exit={child_exit}",
            flush=True,
        )
        return child_exit


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="role", required=True)

    security = subparsers.add_parser("security")
    security.add_argument("--sensitive-file", required=True)
    security.add_argument("--allowed-file", required=True)
    security.add_argument("--outside-file", required=True)
    security.add_argument("--missing-file", required=True)

    subparsers.add_parser("process-network")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.role == "security":
        return run_security(args)
    return run_process_network(args)


if __name__ == "__main__":
    raise SystemExit(main())
