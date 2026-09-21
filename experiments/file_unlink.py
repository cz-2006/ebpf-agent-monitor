"""Delete only a private test file, then retry its now-missing path."""
import errno
import os
from pathlib import Path
import tempfile


def main():
    with tempfile.TemporaryDirectory(prefix="ebpf-exp3-", dir="/tmp") as directory:
        target = Path(directory) / "sample.txt"
        target.write_text("experiment 3b\n")
        print(f"WORKLOAD pid={os.getpid()} test_dir={directory}", flush=True)
        os.unlink(str(target))
        print(f"WORKLOAD case=existing filename={target} deleted=1", flush=True)
        if target.exists():
            raise RuntimeError("Deleted path still exists")
        try:
            os.unlink(str(target))
        except OSError as error:
            print(f"WORKLOAD case=missing filename={target} errno={error.errno}", flush=True)
            if error.errno != errno.ENOENT:
                raise
        else:
            raise RuntimeError("Missing file unexpectedly deleted")
    print("WORKLOAD done=1", flush=True)


if __name__ == "__main__":
    main()
