"""Create and read a harmless file under a fixed sensitive test directory."""
import os
from pathlib import Path

SENSITIVE_DIR = Path("/tmp/ebpf-agent-monitor-sensitive")
TARGET = SENSITIVE_DIR / "secret.txt"


def main():
    SENSITIVE_DIR.mkdir(mode=0o700, exist_ok=False)
    try:
        # 写入夹具使用只写方式，不应触发 sensitive_read_denied。
        TARGET.write_text("harmless test secret\n")
        print(
            f"WORKLOAD pid={os.getpid()} action=open_sensitive target={TARGET}",
            flush=True,
        )

        fd = os.open(TARGET, os.O_RDONLY)
        try:
            data = os.read(fd, 64)
        finally:
            os.close(fd)
        if data != b"harmless test secret\n":
            raise RuntimeError("unexpected fixture content")
        print(
            f"WORKLOAD pid={os.getpid()} read_sensitive=1 bytes={len(data)}",
            flush=True,
        )
    finally:
        TARGET.unlink(missing_ok=True)
        SENSITIVE_DIR.rmdir()


if __name__ == "__main__":
    main()
