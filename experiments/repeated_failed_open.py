"""Open the same missing file five times for repeated-activity detection."""
import errno
import os
from pathlib import Path


ROOT = Path("/tmp/ebpf-exp6-repeat")
TARGET = ROOT / "missing.txt"
ATTEMPTS = 5


def main():
    # 专用目录若已存在就停止，避免清理未知内容。
    ROOT.mkdir()
    print(
        f"WORKLOAD pid={os.getpid()} target={TARGET} "
        f"attempts={ATTEMPTS} expected_errno={errno.ENOENT}",
        flush=True,
    )
    try:
        for attempt in range(1, ATTEMPTS + 1):
            try:
                fd = os.open(str(TARGET), os.O_RDONLY)
            except OSError as error:
                print(
                    f"WORKLOAD pid={os.getpid()} attempt={attempt} "
                    f"errno={error.errno}",
                    flush=True,
                )
                if error.errno != errno.ENOENT:
                    raise
            else:
                os.close(fd)
                raise RuntimeError("Missing file unexpectedly opened")
        print(f"WORKLOAD pid={os.getpid()} done=1", flush=True)
        return 0
    finally:
        ROOT.rmdir()


if __name__ == "__main__":
    raise SystemExit(main())
