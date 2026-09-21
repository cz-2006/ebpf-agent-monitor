"""Attempt one blocking IPv4 TCP connection to a just-released local port."""
import errno
import os
import signal
import socket


def main():
    # 最多运行 10 秒，防止连接过程意外卡住。
    signal.alarm(10)
    try:
        # 先让系统选择端口，关闭监听 socket 后，该端口通常无人监听。
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserver:
            reserver.bind(("127.0.0.1", 0))
            target = reserver.getsockname()
        print(
            f"WORKLOAD pid={os.getpid()} dst_ip={target[0]} "
            f"dst_port={target[1]} listener_closed=1",
            flush=True,
        )

        # 使用阻塞式 IPv4 TCP 客户端连接刚释放的端口。
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.setblocking(True)
            print(
                f"WORKLOAD pid={os.getpid()} case=connect_missing "
                f"fd={client.fileno()} dst_ip={target[0]} dst_port={target[1]}",
                flush=True,
            )
            try:
                client.connect(target)
            except OSError as error:
                # 没有服务监听时，预期错误为 ECONNREFUSED（Linux errno 111）。
                print(
                    f"WORKLOAD pid={os.getpid()} connect_failed=1 "
                    f"errno={error.errno}",
                    flush=True,
                )
                if error.errno != errno.ECONNREFUSED:
                    raise
            else:
                # 若端口恰好被其他进程占用，则本次实验不符合预期。
                raise RuntimeError("Connection unexpectedly succeeded")
        print(f"WORKLOAD pid={os.getpid()} done=1", flush=True)
    finally:
        # 无论成功还是异常，都取消定时信号。
        signal.alarm(0)


if __name__ == "__main__":
    main()
