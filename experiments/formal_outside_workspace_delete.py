"""Delete one file inside a workspace and one harmless file outside it."""
import os
from pathlib import Path

ROOT = Path("/tmp/ebpf-agent-monitor-delete")
WORKSPACE = ROOT / "workspace"
OUTSIDE = ROOT / "outside"


def main():
    ROOT.mkdir()
    WORKSPACE.mkdir()
    OUTSIDE.mkdir()
    allowed = WORKSPACE / "allowed.txt"
    forbidden = OUTSIDE / "victim.txt"

    try:
        allowed.write_text("allowed test file\n")
        forbidden.write_text("outside test file\n")

        print(
            f"WORKLOAD pid={os.getpid()} case=allowed target={allowed}",
            flush=True,
        )
        allowed.unlink()
        print(f"WORKLOAD pid={os.getpid()} allowed_deleted=1", flush=True)

        print(
            f"WORKLOAD pid={os.getpid()} case=outside target={forbidden}",
            flush=True,
        )
        forbidden.unlink()
        print(f"WORKLOAD pid={os.getpid()} outside_deleted=1", flush=True)
    finally:
        allowed.unlink(missing_ok=True)
        forbidden.unlink(missing_ok=True)
        WORKSPACE.rmdir()
        OUTSIDE.rmdir()
        ROOT.rmdir()


if __name__ == "__main__":
    main()
