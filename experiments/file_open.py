"""Open a private test file and a missing path; clean up only our temp directory."""
import errno
import os
from pathlib import Path
import tempfile


def main():
    with tempfile.TemporaryDirectory(prefix="ebpf-exp3-", dir="/tmp") as directory:
        target = Path(directory) / "sample.txt"
        target.write_text("experiment 3\n")
        print(f"WORKLOAD pid={os.getpid()} test_dir={directory}", flush=True)
        fd = os.open(str(target), os.O_RDONLY)
        print(f"WORKLOAD case=existing filename={target} fd={fd}", flush=True)
        os.close(fd)
        missing = Path(directory) / "missing.txt"
        try:
            fd = os.open(str(missing), os.O_RDONLY)
        except OSError as error:
            print(f"WORKLOAD case=missing filename={missing} errno={error.errno}", flush=True)
            if error.errno != errno.ENOENT:
                raise
        else:
            os.close(fd)
            raise RuntimeError("Missing file unexpectedly opened")
    print("WORKLOAD done=1", flush=True)


if __name__ == "__main__":
    main()
