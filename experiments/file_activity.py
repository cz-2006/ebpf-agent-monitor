"""Open and unlink a private file, then verify both missing-path failures."""
import errno
import os
from pathlib import Path
import tempfile


def main():
    with tempfile.TemporaryDirectory(prefix="ebpf-exp3-", dir="/tmp") as directory:
        target = Path(directory) / "sample.txt"
        print(f"WORKLOAD pid={os.getpid()} test_dir={directory}", flush=True)
        target.write_text("experiment 3c\n")
        fd = os.open(str(target), os.O_RDONLY)
        print(f"WORKLOAD pid={os.getpid()} case=open_existing filename={target} fd={fd}", flush=True)
        os.close(fd)
        os.unlink(str(target))
        print(f"WORKLOAD pid={os.getpid()} case=unlink_existing filename={target} deleted=1", flush=True)
        try:
            fd = os.open(str(target), os.O_RDONLY)
        except OSError as error:
            print(f"WORKLOAD pid={os.getpid()} case=open_missing filename={target} errno={error.errno}", flush=True)
            if error.errno != errno.ENOENT:
                raise
        else:
            os.close(fd)
            raise RuntimeError("Deleted file unexpectedly opened")
        try:
            os.unlink(str(target))
        except OSError as error:
            print(f"WORKLOAD pid={os.getpid()} case=unlink_missing filename={target} errno={error.errno}", flush=True)
            if error.errno != errno.ENOENT:
                raise
        else:
            raise RuntimeError("Missing file unexpectedly deleted")
    print(f"WORKLOAD pid={os.getpid()} done=1", flush=True)


if __name__ == "__main__":
    main()
