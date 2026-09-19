"""
Minimal plaintext TCP echo backend for demoing the proxy.

Run this as the "ordinary backend" the proxy forwards to:

    python3 demo_backend_echo.py --port 8080

It has no PQC/TLS awareness at all -- deliberately, to demonstrate that
the proxy terminates the quantum-safe handshake and forwards plain
bytes to a completely unmodified service.
"""

import argparse
import socket
import threading


def handle_client(conn, addr):
    print(f"[BACKEND] Client connected: {addr}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            print(f"[BACKEND] Received: {data!r}")
            conn.sendall(b"BACKEND-ECHO: " + data)
    except ConnectionError:
        pass
    finally:
        conn.close()
        print(f"[BACKEND] Client disconnected: {addr}")


def main():
    parser = argparse.ArgumentParser(description="Demo plaintext echo backend")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(5)

    print(f"[BACKEND] Plaintext echo backend listening on {args.host}:{args.port}")
    print("[BACKEND] Waiting for the proxy to forward a connection...\n")

    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(
                target=handle_client, args=(conn, addr), daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\n[BACKEND] Shutdown requested")
    finally:
        server.close()


if __name__ == "__main__":
    main()
