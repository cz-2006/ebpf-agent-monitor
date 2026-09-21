"""Launch two local-network workloads behind one shared start gate."""
import os
from pathlib import Path


def main():
    workload = str(Path(__file__).with_name("network_connect.py").resolve())
    read_fd, write_fd = os.pipe()
    children = []
    print(f"LAUNCHER pid={os.getpid()}", flush=True)
    try:
        # 先创建两组根进程，再一起放行。
        for agent in (1, 2):
            child = os.fork()
            if child == 0:
                os.close(write_fd)
                try:
                    token = os.read(read_fd, 1)
                    os.close(read_fd)
                    if token != b"x":
                        os._exit(125)
                    os.execv("/usr/bin/python3", ["/usr/bin/python3", workload])
                except OSError as error:
                    print(f"LAUNCHER child_error={error}", flush=True)
                    os._exit(127)
            children.append((agent, child))
            print(f"LAUNCHER agent_id={agent} root_pid={child}", flush=True)
        os.write(write_fd, b"xx")
    finally:
        os.close(read_fd)
        os.close(write_fd)
        failed = False
        for agent, child in children:
            _, status = os.waitpid(child, 0)
            code = os.waitstatus_to_exitcode(status)
            print(
                f"LAUNCHER agent_id={agent} root_pid={child} exit_code={code}",
                flush=True,
            )
            failed = failed or code != 0
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
