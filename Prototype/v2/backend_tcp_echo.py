"""
Simple TCP echo backend for proxy demos.

Unlike backend_http_demo.py (HTTP), this accepts ANY raw bytes,
prints them, and echoes them back. Use this when testing with the
interactive PQ client typing plain text like "Hi".

Run:
    python backend_tcp_echo.py

Proxy:
    python -m middleware.main --mode proxy --backend-host 127.0.0.1 --backend-port 8080

Client:
    python -m middleware.main --mode client --host 127.0.0.1 --port 5000
    then type: Hi
"""

import socket


HOST = "0.0.0.0"
PORT = 8080


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    print(f"TCP echo backend listening on {HOST}:{PORT}")
    print("Will print and echo ANY bytes received from the proxy.")

    try:
        while True:
            conn, addr = server.accept()
            print(f"\n[BACKEND] connection from {addr}")
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        print("[BACKEND] client closed")
                        break

                    print(f"[BACKEND] received ({len(data)} bytes): {data!r}")
                    reply = b"ACK: " + data
                    conn.sendall(reply)
                    print(f"[BACKEND] sent: {reply!r}")
            except Exception as exc:
                print(f"[BACKEND] error: {exc}")
            finally:
                conn.close()
                print("[BACKEND] connection closed")
    except KeyboardInterrupt:
        print("\nBackend stopped")
    finally:
        server.close()


if __name__ == "__main__":
    main()
