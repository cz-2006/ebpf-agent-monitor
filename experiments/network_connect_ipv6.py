"""One blocking IPv6 TCP connection to our own loopback listener."""
import os
import signal
import socket


def main():
    signal.alarm(10)
    try:
        # 使用 IPv6 回环地址和动态端口，不访问虚拟机外部网络。
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as server:
            server.bind(("::1", 0))
            server.listen(1)
            target = server.getsockname()
            print(
                f"WORKLOAD pid={os.getpid()} dst_ip={target[0]} "
                f"dst_port={target[1]} listening=1 family=ipv6",
                flush=True,
            )

            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as client:
                print(
                    f"WORKLOAD pid={os.getpid()} case=connect fd={client.fileno()} "
                    f"dst_ip={target[0]} dst_port={target[1]}",
                    flush=True,
                )
                client.connect(target)
                peer_target = client.getpeername()
                if peer_target[:2] != target[:2]:
                    raise RuntimeError("Unexpected connected peer")
                print(f"WORKLOAD pid={os.getpid()} connected=1", flush=True)

                connection, peer = server.accept()
                with connection:
                    if peer[:2] != client.getsockname()[:2]:
                        raise RuntimeError("Accepted peer does not match client")
                    print(
                        f"WORKLOAD pid={os.getpid()} accepted=1 "
                        f"peer_ip={peer[0]} peer_port={peer[1]}",
                        flush=True,
                    )
        print(f"WORKLOAD pid={os.getpid()} done=1", flush=True)
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    main()
