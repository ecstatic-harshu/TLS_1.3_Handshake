"""
Live demo dashboard for the Quantum-Safe Proxy prototype.

Responsibilities:
  - Start a PQ secure server container (--mode server).
  - Start the proxy in a Docker container with --backend-pq
    (Client --PQ--> Proxy --PQ--> Server).
  - Tail both containers' stdout, classify lines into pipeline
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

BACKEND_PORT = int(os.environ.get("BACKEND_PORT", "6000"))
PROXY_PORT = int(os.environ.get("PROXY_PORT", "5000"))

IMAGE_TAG = os.environ.get("PQTLS_IMAGE", "pqtls-middleware:1.0.0")
PROXY_CONTAINER = os.environ.get("PROXY_CONTAINER", "pqtls-proxy-demo")
SERVER_CONTAINER = os.environ.get("SERVER_CONTAINER", "pqtls-server-demo")
DEMO_NETWORK = os.environ.get("PQTLS_NETWORK", "pqtls-demo")


def _env_flag(name, default=True):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() not in ("0", "false", "no", "off")


# When false, the dashboard assumes the PQ server / proxy are already
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
        q = queue.Queue(maxsize=500)
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
            try:
                q.put_nowait(data)
            except queue.Full:
                # Drop oldest-style: skip if a slow browser fell behind.
                try:
                    q.get_nowait()
                    q.put_nowait(data)
                except Exception:
                    pass


bus = EventBus()
send_lock = threading.Lock()
demo_active = threading.Event()

state = {
    "backend": "starting",
    "proxy": "starting"
}

procs = {}


# =====================================
# LOG LINE -> PIPELINE STAGE
# =====================================

def classify_line(source, line):
    # Demo client prints (authoritative for client-side stages).
    if source == "client":
        if "Connecting to" in line:
            return "tcp"
        if "Secure session established" in line or "PQ channel ready" in line:
            return "channel"
        if "Sent message:" in line or "Secure message sent" in line:
            return "send"
        if "Received reply:" in line or "Secure message received" in line:
            return "response"
        if "Connection closed" in line:
            return "response"
        if "ERROR:" in line:
            return None

    if (
        "TCP_CONNECT" in line
        or "TCP connection established" in line
        or "TCP client connected" in line
        or "TCP_CONNECTED" in line
    ):
        return "tcp"

    if (
        "TLS_HANDSHAKE" in line
        or "TLS connection established" in line
        or "TLS established for" in line
        or "TLS Cipher:" in line
        or "TLS_CONNECTED" in line
        or "TLS_METADATA" in line
    ):
        return "tls"

    if (
        "AUTHENTICATED_PQ_HANDSHAKE" in line
        or "PQ KEM:" in line
        or "PQ Signature:" in line
        or "PQ_CLIENT_HANDSHAKE" in line
        or "PQ_SERVER_HANDSHAKE" in line
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
        or "Secure Channel:" in line
    ):
        return "channel"

    if "Secure message sent" in line:
        # Proxy sending the wrapped backend reply back to the client.
        return "send" if source == "client" else "response"

    if "Secure message received" in line:
        return "proxy_relay" if source == "proxy" else "receive"

    if (
        "PQ backend mode" in line
        or "PQ backend session" in line
        or "PQ↔PQ relay" in line
        or "PQ↔PQ" in line
        or "Dialing backend" in line
        or "Backend connected" in line
        or "HTTP backend mode" in line
        or "HTTP relay round-trip" in line
        or "Starting HTTP" in line
    ):
        if "HTTP relay round-trip" in line or "PQ↔PQ relay" in line:
            return "proxy_relay"
        if "PQ backend session established" in line:
            return "backend"
        return "proxy_relay"

    if source == "backend" and (
        "ACK:" in line
        or "Waiting for secure" in line
        or "Secure message received" in line
        or "Secure message sent" in line
        or " POST " in line
        or " GET " in line
        or '"POST' in line
        or '"GET' in line
        or "[BACKEND]" in line
    ):
        return "backend"

    return None


# Benign noise from Docker HEALTHCHECK / bare TCP probes against TLS.
_SUPPRESSED_LOG_MARKERS = (
    "UNEXPECTED_EOF_WHILE_READING",
    "Connection reset by peer",
    "HEALTHCHECK",
)


def log_event(source, line):
    if any(marker in line for marker in _SUPPRESSED_LOG_MARKERS):
        return

    stage = classify_line(source, line)
    bus.publish({
        "type": "log",
        "source": source,
        "line": line,
        "stage": stage,
        "demo": demo_active.is_set(),
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
            f"            Build it first:\n"
            f"            docker build -t {IMAGE_TAG} ."
        )
        sys.exit(1)


def ensure_demo_network():
    result = docker(
        "network", "inspect", DEMO_NETWORK,
        capture_output=True, text=True
    )
    if result.returncode != 0:
        created = docker(
            "network", "create", DEMO_NETWORK,
            capture_output=True, text=True
        )
        if created.returncode != 0:
            raise RuntimeError(
                f"Failed to create Docker network "
                f"'{DEMO_NETWORK}': {created.stderr.strip()}"
            )


def _attach_container_logs(container_name, source, proc_key):
    """Follow container logs from now on (no history dump)."""
    proc = subprocess.Popen(
        ["docker", "logs", "-f", "--tail", "0", container_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    procs[proc_key] = proc
    threading.Thread(
        target=tail_stream,
        args=(proc.stdout, source),
        daemon=True
    ).start()


def attach_proxy_logs():
    _attach_container_logs(PROXY_CONTAINER, "proxy", "proxy_logs")


def attach_server_logs():
    _attach_container_logs(SERVER_CONTAINER, "backend", "server_logs")


def container_running(name):
    try:
        result = docker(
            "inspect", "--format", "{{.State.Running}}", name,
            capture_output=True, text=True
        )
    except Exception:
        return False

    if result.returncode != 0:
        return False

    return result.stdout.strip() == "true"


def start_backend():
    """Start a PQ-speaking server (--mode server) as the backend hop."""
    ensure_demo_network()
    docker("rm", "-f", SERVER_CONTAINER, capture_output=True, text=True)

    result = docker(
        "run", "-d",
        "--name", SERVER_CONTAINER,
        "--network", DEMO_NETWORK,
        "-p", f"{BACKEND_PORT}:6000",
        IMAGE_TAG,
        "--mode", "server",
        "--host", "0.0.0.0",
        "--port", "6000",
        capture_output=True, text=True
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to start PQ server container: {result.stderr.strip()}"
        )

    attach_server_logs()


def start_proxy_container():
    ensure_demo_network()
    docker("rm", "-f", PROXY_CONTAINER, capture_output=True, text=True)

    # PQ↔PQ hop: proxy dials the PQ server by Docker DNS name.
    result = docker(
        "run", "-d",
        "--name", PROXY_CONTAINER,
        "--network", DEMO_NETWORK,
        "-p", f"{PROXY_PORT}:5000",
        "--add-host=host.docker.internal:host-gateway",
        IMAGE_TAG,
        "--mode", "proxy",
        "--host", "0.0.0.0",
        "--port", "5000",
        "--backend-host", SERVER_CONTAINER,
        "--backend-port", "6000",
        "--backend-pq",
        "--no-backend-http",
        capture_output=True, text=True
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to start proxy container: {result.stderr.strip()}"
        )

    attach_proxy_logs()


def wait_for_container(name, label, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if container_running(name):
            return True
        time.sleep(0.4)
    print(f"[DASHBOARD] ERROR: {label} container '{name}' did not come up")
    return False


def proxy_container_running():
    return container_running(PROXY_CONTAINER)


def wait_for_proxy(timeout=30):
    return wait_for_container(PROXY_CONTAINER, "proxy", timeout=timeout)


def _docker_volume_path(path: Path) -> str:
    """Normalize a host path for `docker -v` (esp. Windows + spaces)."""
    return str(path.resolve()).replace("\\", "/")


def run_send(message):

    if not send_lock.acquire(blocking=False):
        return

    proc = None
    try:
        demo_active.set()
        bus.publish({"type": "run_start", "message": message})

        dashboard_mount = _docker_volume_path(BASE_DIR / "dashboard")

        proc = subprocess.Popen(
            [
                "docker", "run", "--rm",
                "--add-host=host.docker.internal:host-gateway",
                "-e", "DEMO_STEP_DELAY=1.5",
                "-v", f"{dashboard_mount}:/app/dashboard:ro",
                "--entrypoint", "python",
                IMAGE_TAG,
                "-m", "dashboard.demo_client",
                "--host", "host.docker.internal",
                "--port", str(PROXY_PORT),
                "--message", message,
                "--timeout", "45"
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

        try:
            proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
            error_line = error_line or "[DEMO_CLIENT] ERROR: client timed out"

        ok = proc.returncode == 0 and reply is not None

        bus.publish({
            "type": "run_complete",
            "success": ok,
            "reply": reply,
            "message": message,
            "error": error_line if not ok else None
        })

    except Exception as exc:
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass
        bus.publish({
            "type": "run_complete",
            "success": False,
            "reply": None,
            "message": message,
            "error": str(exc)
        })

    finally:
        demo_active.clear()
        send_lock.release()


def cleanup():
    print("\n[DASHBOARD] Shutting down demo services...")

    for key in ("proxy_logs", "server_logs"):
        log_proc = procs.get(key)
        if log_proc and log_proc.poll() is None:
            try:
                log_proc.terminate()
            except Exception:
                pass

    if MANAGE_PROXY:
        docker("rm", "-f", PROXY_CONTAINER, capture_output=True, text=True)

    if MANAGE_BACKEND:
        docker("rm", "-f", SERVER_CONTAINER, capture_output=True, text=True)

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
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path in STATIC_FILES:
            filename, content_type = STATIC_FILES[path]
            file_path = STATIC_DIR / filename
            try:
                body = file_path.read_bytes()
            except OSError:
                self.send_error(404, "Not found")
                return

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            # Always revalidate so paced UI / explain text updates show up.
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/status":
            proxy = state["proxy"]
            backend = state["backend"]
            if proxy == "online" and backend == "online":
                gateway = "online"
            elif proxy == "offline" and backend == "offline":
                gateway = "offline"
            else:
                gateway = "starting"
            self._send_json(200, {
                "backend": backend,
                "proxy": proxy,
                "busy": send_lock.locked() or demo_active.is_set(),
                "proxy_port": PROXY_PORT,
                "backend_port": BACKEND_PORT,
                "gateway": gateway
            })
            return

        if path == "/events":
            self._handle_sse()
            return

        self.send_error(404, "Not found")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != "/send":
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

        message = message[:500]

        if send_lock.locked() or demo_active.is_set():
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

def health_watch():
    while True:
        state["backend"] = (
            "online" if container_running(SERVER_CONTAINER) else "offline"
        )
        state["proxy"] = (
            "online" if container_running(PROXY_CONTAINER) else "offline"
        )
        time.sleep(3)


def main():

    atexit.register(cleanup)

    def _handle_sigterm(signum, frame):
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGTERM, _handle_sigterm)
    except Exception:
        pass

    ensure_image_exists()

    if MANAGE_BACKEND:
        print("[DASHBOARD] Starting PQ secure server (--mode server)...")
        try:
            start_backend()
        except RuntimeError as exc:
            print(f"[DASHBOARD] ERROR: {exc}")
            sys.exit(1)

        if not wait_for_container(SERVER_CONTAINER, "PQ server", timeout=30):
            sys.exit(1)

        print(
            f"[DASHBOARD] PQ server online "
            f"({SERVER_CONTAINER} → host :{BACKEND_PORT})"
        )
    else:
        print(
            f"[DASHBOARD] MANAGE_BACKEND=0 — expecting PQ server already "
            f"running as '{SERVER_CONTAINER}'"
        )
        if container_running(SERVER_CONTAINER):
            attach_server_logs()

    if MANAGE_PROXY:
        print("[DASHBOARD] Starting proxy container (PQ↔PQ backend hop)...")
        try:
            start_proxy_container()
        except RuntimeError as exc:
            print(f"[DASHBOARD] ERROR: {exc}")
            sys.exit(1)

        if not wait_for_proxy(timeout=30):
            print(
                f"[DASHBOARD] ERROR: proxy did not come up "
                f"on port {PROXY_PORT}"
            )
            sys.exit(1)

        print(f"[DASHBOARD] Proxy online on port {PROXY_PORT}")
    else:
        print(
            f"[DASHBOARD] MANAGE_PROXY=0 — expecting proxy already "
            f"running on port {PROXY_PORT}"
        )

        if proxy_container_running():
            print(
                f"[DASHBOARD] Found container '{PROXY_CONTAINER}', "
                f"attaching to its logs"
            )
            attach_proxy_logs()
        else:
            print(
                f"[DASHBOARD] No running container named "
                f"'{PROXY_CONTAINER}' — set PROXY_CONTAINER if needed."
            )

    threading.Thread(target=health_watch, daemon=True).start()

    url = f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}"

    try:
        httpd = ThreadingHTTPServer((DASHBOARD_HOST, DASHBOARD_PORT), Handler)
    except OSError as exc:
        print(f"[DASHBOARD] ERROR: cannot bind {url} — {exc}")
        sys.exit(1)

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
    finally:
        try:
            httpd.server_close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
