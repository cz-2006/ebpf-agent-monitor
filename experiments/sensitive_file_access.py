"""Create a harmless sensitive-file fixture, then let one Agent read it."""
import os
from pathlib import Path
import tempfile


def main():
    # 启动器先创建无害的模拟敏感文件。
    directory = Path(tempfile.mkdtemp(prefix="ebpf-exp5-sensitive-", dir="/tmp"))
    target = directory / "secret.txt"
    target.write_text("harmless test secret\n")
    print(
        f"LAUNCHER pid={os.getpid()} fixture={target} policy=sensitive_read_denied",
        flush=True,
    )

    # 孩子代表 Agent 1；启动器本身不作为 Agent 监控。
    child = os.fork()
    if child == 0:
        print(
            f"WORKLOAD pid={os.getpid()} parent_pid={os.getppid()} "
            f"action=open_sensitive target={target}",
            flush=True,
        )
        try:
            # Agent 以只读方式打开文件，并读取内容进行自检。
            fd = os.open(str(target), os.O_RDONLY)
            try:
                data = os.read(fd, 64)
            finally:
                os.close(fd)
            if data != b"harmless test secret\n":
                raise RuntimeError("Unexpected fixture content")
            print(
                f"WORKLOAD pid={os.getpid()} read_sensitive=1 bytes={len(data)}",
                flush=True,
            )
            os._exit(0)
        except Exception as error:
            print(f"WORKLOAD pid={os.getpid()} error={error}", flush=True)
            os._exit(1)

    # 启动器等待 Agent 结束，并把孩子状态转换为脚本退出状态。
    try:
        _, status = os.waitpid(child, 0)
        code = os.waitstatus_to_exitcode(status)
        print(f"LAUNCHER agent_id=1 root_pid={child} exit_code={code}", flush=True)
        return 0 if code == 0 else 1
    finally:
        # 清理只由未登记为 Agent 的启动器执行。
        target.unlink(missing_ok=True)
        directory.rmdir()


if __name__ == "__main__":
    raise SystemExit(main())
