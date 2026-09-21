"""Single-threaded workload: fork one child, exec true, and wait for it."""
import os


def main():
    print(f"WORKLOAD root_pid={os.getpid()}", flush=True)
    child = os.fork()
    if child == 0:
        print(f"WORKLOAD child_pid={os.getpid()} parent_pid={os.getppid()}", flush=True)
        try:
            os.execv("/usr/bin/true", ["/usr/bin/true"])
        except OSError as error:
            print(f"WORKLOAD exec_failed={error}", flush=True)
            os._exit(127)

    _, status = os.waitpid(child, 0)
    code = os.waitstatus_to_exitcode(status)
    print(f"WORKLOAD waited_child={child} child_exit_code={code}", flush=True)
    return 0 if code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
