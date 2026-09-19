"""
Live demo dashboard for the Quantum-Safe Proxy prototype.

Responsibilities:
  - Start the demo HTTP backend (backend_http_demo.py) on the host.
  - Start the proxy in a Docker container (the only place `oqs` /
    liboqs is installed).
  - Tail both processes' stdout, classify lines into pipeline
    "stages", and stream them to the browser over Server-Sent Events.
  - Accept "send a message" requests from the browser, run one
    non-interactive secure client (dashboard/demo_client.py) inside
    a throwaway Docker container, and stream its output the same way.
  - Serve the static UI (dashboard/static/*).

Deliberately stdlib-only so nothing besides Docker + Python 3 is
required on the host.
"""

import atexit
import json
import os
import queue
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


# =====================================
# CONFIGURATION
# =====================================

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"

DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", "8090"))

BACKEND_PORT = int(os.environ.get("BACKEND_PORT", "8080"))
PROXY_PORT = int(os.environ.get("PROXY_PORT", "5000"))

IMAGE_TAG = os.environ.get("PQTLS_IMAGE", "pqtls-middleware:1.0.0")
PROXY_CONTAINER = os.environ.get("PROXY_CONTAINER", "pqtls-proxy-demo")


def _env_flag(name, default=True):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() not in ("0", "false", "no", "off")


# When false, the dashboard assumes the backend / proxy are already
# running elsewhere (another terminal) and only serves the UI +
# tails/log-classifies whatever it finds, instead of spawning and
# later tearing them down itself.
MANAGE_BACKEND = _env_flag("MANAGE_BACKEND", True)
MANAGE_PROXY = _env_flag("MANAGE_PROXY", True)


# =====================================
# EVENT BUS (SSE fan-out)
# =====================================

class EventBus:

    def __init__(self):
        self._subscribers = []
        self._lock = threading.Lock()
        self._seq = 0

    def subscribe(self):
        q = queue.Queue()
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q):
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def publish(self, event):
        with self._lock:
            self._seq += 1
            payload = dict(event)
            payload["id"] = self._seq
            payload.setdefault("ts", time.time())
            subs = list(self._subscribers)

        data = json.dumps(payload)

        for q in subs:
            q.put(data)


bus = EventBus()
send_lock = threading.Lock()

state = {
    "backend": "starting",
    "proxy": "starting"
}

procs = {}


# =====================================
# LOG LINE -> PIPELINE STAGE
# =====================================

def classify_line(source, line):

    if (
        "TCP_CONNECT" in line
        or "TCP connection established" in line
        or "TCP client connected" in line
    ):
        return "tcp"

    if (
        "TLS_HANDSHAKE" in line
        or "TLS connection established" in line
        or "TLS established for" in line
        or "TLS Cipher:" in line
    ):
        return "tls"

    if (
        "AUTHENTICATED_PQ_HANDSHAKE" in line
        or "PQ KEM:" in line
        or "PQ Signature:" in line
    ):
        return "pq"

    if (
        "HYBRID_KEY_DERIVATION" in line
        or "HYBRID_KEY_DERIVED" in line
    ):
        return "hybrid"

    if (
        "SECURE_CHANNEL_CREATION" in line
        or "SECURE_CHANNEL_CREATED" in line
        or "Secure session established" in line
    ):
        return "channel"

    if "Secure message sent" in line:
        return "send" if source == "client" else "response"

    if "Secure message received" in line:
        return "proxy_relay" if source == "proxy" else "receive"

    if (
        "HTTP backend mode" in line
        or "Dialing backend" in line
        or "Backend connected" in line
    ):
        return "proxy_relay"

    if source == "backend" and (" POST " in line or " GET " in line or '"POST' in line or '"GET' in line):
        return "backend"

    if "HTTP relay round-trip" in line:
        return "response"

    return None


def log_event(source, line):
    stage = classify_line(source, line)
    bus.publish({
        "type": "log",
        "source": source,
        "line": line,
        "stage": stage
    })


def tail_stream(stream, source):
    try:
        for raw in iter(stream.readline, ""):
            line = raw.rstrip("\n")
            if line:
                log_event(source, line)
    except Exception:
        pass


# =====================================
# PROCESS / CONTAINER MANAGEMENT
# =====================================

def start_backend():
    proc = subprocess.Popen(
        [sys.executable, "-u", "backend_http_demo.py"],
        cwd=str(BASE_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    procs["backend"] = proc
    threading.Thread(
        target=tail_stream,
        args=(proc.stdout, "backend"),
        daemon=True
    ).start()
    return proc


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], cwd=str(BASE_DIR), **kwargs)


def ensure_image_exists():
    result = docker(
        "image", "inspect", IMAGE_TAG,
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(
            f"[DASHBOARD] Docker image '{IMAGE_TAG}' not found.\n"
            f"            Run ./setup.sh first (it builds the image)."
        )
        sys.exit(1)


def proxy_container_exists():
    result = docker(
        "inspect", PROXY_CONTAINER,
        capture_output=True, text=True
    )
    return result.returncode == 0


def attach_proxy_logs():
    """Tail an already-running proxy container's logs (does not start it)."""
    proc = subprocess.Popen(
        ["docker", "logs", "-f", PROXY_CONTAINER],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    procs["proxy_logs"] = proc
    threading.Thread(
        target=tail_stream,
        args=(proc.stdout, "proxy"),
        daemon=True
    ).start()


def start_proxy_container():
    docker("rm", "-f", PROXY_CONTAINER, capture_output=True, text=True)

    result = docker(
        "run", "-d",
        "--name", PROXY_CONTAINER,
        "-p", f"{PROXY_PORT}:5000",
        "--add-host=host.docker.internal:host-gateway",
        IMAGE_TAG,
        "--mode", "proxy",
        "--host", "0.0.0.0",
        "--port", "5000",
        "--backend-host", "host.docker.internal",
        "--backend-port", str(BACKEND_PORT),
        capture_output=True, text=True
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to start proxy container: {result.stderr.strip()}"
        )

    attach_proxy_logs()


def wait_for_port(host, port, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.4)
    return False


def run_send(message):

    if not send_lock.acquire(blocking=False):
        return

    try:
        bus.publish({"type": "run_start", "message": message})

        proc = subprocess.Popen(
            [
                "docker", "run", "--rm",
                "--add-host=host.docker.internal:host-gateway",
                "-v", f"{BASE_DIR / 'dashboard'}:/app/dashboard:ro",
                "--entrypoint", "python",
                IMAGE_TAG,
                "-m", "dashboard.demo_client",
                "--host", "host.docker.internal",
                "--port", str(PROXY_PORT),
                "--message", message
            ],
            cwd=str(BASE_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        reply = None
        error_line = None

        for raw in iter(proc.stdout.readline, ""):
            line = raw.rstrip("\n")
            if not line:
                continue

            log_event("client", line)

            match = re.search(r"Received reply: (.*)", line)
            if match:
                reply = match.group(1)

            if line.startswith("[DEMO_CLIENT] ERROR:"):
                error_line = line

        proc.wait(timeout=30)

        ok = proc.returncode == 0 and reply is not None

        bus.publish({
            "type": "run_complete",
            "success": ok,
            "reply": reply,
            "message": message,
            "error": error_line
        })

    except Exception as exc:
        bus.publish({
            "type": "run_complete",
            "success": False,
            "reply": None,
            "message": message,
            "error": str(exc)
        })

    finally:
        send_lock.release()


def cleanup():
    print("\n[DASHBOARD] Shutting down demo services...")

    backend_proc = procs.get("backend")
    if backend_proc and backend_proc.poll() is None:
        try:
            backend_proc.terminate()
        except Exception:
            pass

    proxy_logs_proc = procs.get("proxy_logs")
    if proxy_logs_proc and proxy_logs_proc.poll() is None:
        try:
            proxy_logs_proc.terminate()
        except Exception:
            pass

    if MANAGE_PROXY:
        docker("rm", "-f", PROXY_CONTAINER, capture_output=True, text=True)

    print("[DASHBOARD] Stopped")


# =====================================
# HTTP / SSE HANDLER
# =====================================

STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}


class Handler(BaseHTTPRequestHandler):

    server_version = "PQTLSDashboard/1.0"

    def log_message(self, fmt, *args):
        pass

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in STATIC_FILES:
            filename, content_type = STATIC_FILES[self.path]
            file_path = STATIC_DIR / filename
            try:
                body = file_path.read_bytes()
            except OSError:
                self.send_error(404, "Not found")
                return

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/status":
            self._send_json(200, {
                "backend": state["backend"],
                "proxy": state["proxy"],
                "busy": send_lock.locked()
            })
            return

        if self.path == "/events":
            self._handle_sse()
            return

        self.send_error(404, "Not found")

    def do_POST(self):
        if self.path != "/send":
            self.send_error(404, "Not found")
            return

        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"

        try:
            data = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            data = {}

        message = str(data.get("message", "")).strip()

        if not message:
            self._send_json(400, {"error": "message is required"})
            return

        message = message[:300]

        if send_lock.locked():
            self._send_json(409, {"error": "A demo run is already in progress"})
            return

        threading.Thread(target=run_send, args=(message,), daemon=True).start()
        self._send_json(202, {"status": "started"})

    def _handle_sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        q = bus.subscribe()

        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()

            while True:
                try:
                    data = q.get(timeout=15)
                    self.wfile.write(f"data: {data}\n\n".encode("utf-8"))
                except queue.Empty:
                    self.wfile.write(b": heartbeat\n\n")
                self.wfile.flush()

        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            bus.unsubscribe(q)


# =====================================
# MAIN
# =====================================

def _port_open(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def health_watch():
    """Keep /status accurate regardless of who started backend/proxy,
    including services that come up after the dashboard does."""
    while True:
        state["backend"] = "online" if _port_open("127.0.0.1", BACKEND_PORT) else "offline"
        state["proxy"] = "online" if _port_open("127.0.0.1", PROXY_PORT) else "offline"
        time.sleep(3)


def main():

    atexit.register(cleanup)

    def _handle_sigterm(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _handle_sigterm)

    # Always required: "Send Secure Message" spawns a throwaway client
    # container from this image regardless of who manages backend/proxy.
    ensure_image_exists()

    if MANAGE_BACKEND:
        print("[DASHBOARD] Starting demo HTTP backend...")
        start_backend()

        if not wait_for_port("127.0.0.1", BACKEND_PORT, timeout=15):
            print(f"[DASHBOARD] ERROR: backend did not come up on port {BACKEND_PORT}")
            sys.exit(1)

        print(f"[DASHBOARD] Backend online on port {BACKEND_PORT}")
    else:
        print(
            f"[DASHBOARD] MANAGE_BACKEND=0 — expecting backend already "
            f"running on port {BACKEND_PORT} (won't start or stop it)"
        )

    if MANAGE_PROXY:
        print("[DASHBOARD] Starting proxy container...")
        start_proxy_container()

        if not wait_for_port("127.0.0.1", PROXY_PORT, timeout=30):
            print(f"[DASHBOARD] ERROR: proxy did not come up on port {PROXY_PORT}")
            sys.exit(1)

        print(f"[DASHBOARD] Proxy online on port {PROXY_PORT}")
    else:
        print(
            f"[DASHBOARD] MANAGE_PROXY=0 — expecting proxy already "
            f"running on port {PROXY_PORT} (won't start or stop it)"
        )

        if proxy_container_exists():
            print(f"[DASHBOARD] Found container '{PROXY_CONTAINER}', attaching to its logs")
            attach_proxy_logs()
        else:
            print(
                f"[DASHBOARD] No container named '{PROXY_CONTAINER}' found — "
                f"live proxy/backend log stages won't show up, but sending "
                f"messages still works as long as the proxy is reachable.\n"
                f"            Set PROXY_CONTAINER to match your container's "
                f"name to enable log tailing."
            )

    threading.Thread(target=health_watch, daemon=True).start()

    url = f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}"

    httpd = ThreadingHTTPServer((DASHBOARD_HOST, DASHBOARD_PORT), Handler)
    httpd.daemon_threads = True

    print(f"[DASHBOARD] Dashboard ready: {url}")
    print("[DASHBOARD] Press Ctrl+C to stop everything\n")

    try:
        webbrowser.open(url)
    except Exception:
        pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
