"""One blocking IPv4 TCP connection to our own loopback listener."""
import os
import signal
import socket


def main():
    # 最多运行 10 秒，避免卡住；连接仍使用阻塞模式。
    signal.alarm(10)
    try:
        # 创建 IPv4 TCP 服务端；with 结束时自动关闭 socket。
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))  # 仅监听本机，端口 0 表示由系统分配。
            server.listen(1)
            target = server.getsockname()  # 取得实际监听的 IP 和端口。
            print(f"WORKLOAD pid={os.getpid()} dst_ip={target[0]} dst_port={target[1]} listening=1", flush=True)
            # 在同一进程中创建客户端，连接上面的监听端口。
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.setblocking(True)
                print(f"WORKLOAD pid={os.getpid()} case=connect fd={client.fileno()} dst_ip={target[0]} dst_port={target[1]}", flush=True)
                client.connect(target)
                if client.getpeername() != target:
                    raise RuntimeError("Unexpected connected peer")
                print(f"WORKLOAD pid={os.getpid()} connected=1", flush=True)
                # 内核完成握手后，服务端取出连接；peer 是客户端地址。
                connection, peer = server.accept()
                with connection:
                    # 核对接收到的连接确实来自这个客户端。
                    if peer != client.getsockname():
                        raise RuntimeError("Accepted peer does not match client")
                    print(f"WORKLOAD pid={os.getpid()} accepted=1 peer_ip={peer[0]} peer_port={peer[1]}", flush=True)
        print(f"WORKLOAD pid={os.getpid()} done=1", flush=True)
    finally:
        signal.alarm(0)  # 结束时取消定时信号。


if __name__ == "__main__":
    main()
