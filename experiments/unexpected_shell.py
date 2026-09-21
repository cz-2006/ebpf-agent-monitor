"""Fork one child that executes a harmless shell command for rule testing."""
import os


def main():
    # 根进程代表被监控的 Agent，策略禁止它启动 Shell。
    print(f"WORKLOAD root_pid={os.getpid()} policy=shell_denied", flush=True)
    # 创建一个孩子，验证 Agent 标签能否沿进程树继承。
    child = os.fork()
    if child == 0:
        print(
            f"WORKLOAD child_pid={os.getpid()} parent_pid={os.getppid()} "
            "action=exec_shell target=/bin/sh",
            flush=True,
        )
        try:
            # 命令只正常退出，不读取、修改文件或访问网络。
            os.execv("/bin/sh", ["/bin/sh", "-c", "exit 0"])
        except OSError as error:
            # execv 失败时使用非零退出码，让父进程能识别失败。
            print(f"WORKLOAD exec_failed={error}", flush=True)
            os._exit(127)

    # 父进程等待孩子，并核对 Shell 命令是否正常结束。
    _, status = os.waitpid(child, 0)
    code = os.waitstatus_to_exitcode(status)
    print(f"WORKLOAD waited_child={child} child_exit_code={code}", flush=True)
    return 0 if code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
