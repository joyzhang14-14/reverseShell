#!/usr/bin/env python3
"""
Mac 端监听脚本，替代 nc。
持续监听，客户端断开后等待下一次连接。
"""
import socket
import sys
import threading

HOST = "0.0.0.0"
PORT = 4444


def bridge(conn: socket.socket) -> None:
    stop = threading.Event()

    def recv_loop():
        try:
            while not stop.is_set():
                data = conn.recv(4096)
                if not data:
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
        except OSError:
            pass
        finally:
            stop.set()

    t = threading.Thread(target=recv_loop, daemon=True)
    t.start()

    try:
        while not stop.is_set():
            line = sys.stdin.buffer.readline()
            if not line:
                break
            conn.sendall(line)
    except (OSError, KeyboardInterrupt):
        pass
    finally:
        stop.set()
        conn.close()


def main() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(1)
    print(f"[监听] 等待连接 {HOST}:{PORT} ... (Ctrl+C 退出)")

    try:
        while True:
            conn, addr = srv.accept()
            print(f"\n[连接] 来自 {addr}")
            bridge(conn)
            print(f"\n[断开] {addr}，等待下一次连接...")
    except KeyboardInterrupt:
        print("\n[退出]")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
