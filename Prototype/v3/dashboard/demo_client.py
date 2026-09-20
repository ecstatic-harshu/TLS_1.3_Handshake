"""
Non-interactive secure client used by the dashboard to demonstrate
one full round trip through the PQ-TLS proxy.

Runs inside the pqtls-middleware Docker image (the only place
liboqs/`oqs` is installed), invoked as:

    python -m dashboard.demo_client --host <proxy> --port <port> --message "..."

It prints plain, greppable lines that dashboard/server.py tails and
turns into pipeline-stage events for the browser UI.
"""

import argparse
import os
import sys
import time

from common.middleware import secure_connect

# Pause between visible demo steps so the dashboard UI can keep up.
# Override with DEMO_STEP_DELAY=0 for full speed.
STEP_DELAY = float(os.environ.get("DEMO_STEP_DELAY", "1.5"))


def _pause():
    if STEP_DELAY > 0:
        time.sleep(STEP_DELAY)


def send_message(host, port, message, timeout=10.0):

    print(f"[DEMO_CLIENT] Connecting to {host}:{port} ...", flush=True)
    _pause()

    session = secure_connect(
        host=host,
        port=port,
        timeout=timeout
    )

    print("[DEMO_CLIENT] Secure session established", flush=True)
    print("[DEMO_CLIENT] PQ channel ready (ML-KEM-768 + ML-DSA-65 + AES-256-GCM)", flush=True)
    _pause()

    session.send_secure(message.encode("utf-8"))

    print("[SESSION] Secure message sent (seq=0)", flush=True)
    print(f"[DEMO_CLIENT] Sent message: {message}", flush=True)
    _pause()

    reply = session.receive_secure()

    try:
        reply_text = reply.decode("utf-8")
    except UnicodeDecodeError:
        reply_text = repr(reply)

    print(f"[SESSION] Secure message received (reply)", flush=True)
    print(f"[DEMO_CLIENT] Received reply: {reply_text}", flush=True)
    _pause()

    try:
        session.socket.close()
    except Exception:
        pass

    print("[DEMO_CLIENT] Connection closed", flush=True)

    return reply_text


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--message", default="Hello from dashboard")
    parser.add_argument("--timeout", type=float, default=30.0)

    args = parser.parse_args()

    try:
        send_message(args.host, args.port, args.message, args.timeout)
    except Exception as exc:
        print(f"[DEMO_CLIENT] ERROR: {exc}", flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
