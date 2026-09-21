"""Delete one allowed file and one outside-workspace test file."""
import os
from pathlib import Path


ROOT = Path("/tmp/ebpf-exp5-delete")
WORKSPACE = ROOT / "workspace"
OUTSIDE = ROOT / "outside"


def main():
    # 使用固定专用目录；若已存在则停止，避免覆盖未知内容。
    ROOT.mkdir()
    WORKSPACE.mkdir()
    OUTSIDE.mkdir()
    allowed = WORKSPACE / "allowed.txt"
    forbidden = OUTSIDE / "victim.txt"
    allowed.write_text("allowed test file\n")
    forbidden.write_text("outside test file\n")
    print(
        f"LAUNCHER pid={os.getpid()} workspace={WORKSPACE} "
        f"outside={OUTSIDE} policy=workspace_delete_only",
        flush=True,
    )

    child = os.fork()
    if child == 0:
        print(
            f"WORKLOAD pid={os.getpid()} parent_pid={os.getppid()} "
            f"case=allowed target={allowed}",
            flush=True,
        )
        try:
            os.unlink(allowed)
            print(f"WORKLOAD pid={os.getpid()} allowed_deleted=1", flush=True)

            print(
                f"WORKLOAD pid={os.getpid()} case=outside target={forbidden}",
                flush=True,
            )
            os.unlink(forbidden)
            print(f"WORKLOAD pid={os.getpid()} outside_deleted=1", flush=True)
            os._exit(0)
        except Exception as error:
            print(f"WORKLOAD pid={os.getpid()} error={error}", flush=True)
            os._exit(1)

    try:
        _, status = os.waitpid(child, 0)
        code = os.waitstatus_to_exitcode(status)
        print(f"LAUNCHER agent_id=1 root_pid={child} exit_code={code}", flush=True)
        return 0 if code == 0 else 1
    finally:
        # 清理由未登记为 Agent 的启动器执行。
        allowed.unlink(missing_ok=True)
        forbidden.unlink(missing_ok=True)
        WORKSPACE.rmdir()
        OUTSIDE.rmdir()
        ROOT.rmdir()


if __name__ == "__main__":
    raise SystemExit(main())
