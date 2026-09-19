"""
Demo-only, process-local observability hub for the proxy.

Purely additive: it never touches crypto/session internals. The
gateway path (common/middleware.py, common/relay.py) reports stage
transitions and byte counts into DashboardHub as they already happen;
this module just remembers the last N events per connection and
serves them as JSON over a small local HTTP server for
dashboard.html to poll.

Not started at all unless a caller explicitly calls
start_dashboard_server() (see middleware/proxy.py).
"""

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MAX_LOG_EVENTS = 300
MAX_CLOSED_CONNECTIONS = 50


class DashboardHub:

    def __init__(self):
        self._lock = threading.Lock()
        self._connections = {}
        self._closed_ids = []
        self._log = []
        self.started_at = time.time()

    # =====================================
    # EVENT LOG
    # =====================================

    def log(self, message, level="info"):
        with self._lock:
            self._log.append({
                "ts": time.time(),
                "level": level,
                "message": message,
            })
            if len(self._log) > MAX_LOG_EVENTS:
                del self._log[0: len(self._log) - MAX_LOG_EVENTS]

    # =====================================
    # CONNECTION LIFECYCLE
    # =====================================

    def register_connection(
        self, conn_id, addr, backend_host=None, backend_port=None
    ):
        client = f"{addr[0]}:{addr[1]}"
        now = time.time()

        with self._lock:
            self._connections[conn_id] = {
                "conn_id": conn_id,
                "client": client,
                "backend": (
                    f"{backend_host}:{backend_port}"
                    if backend_host else None
                ),
                "stage": "tcp_connected",
                "status": "active",
                "started_at": now,
                "updated_at": now,
                "closed_at": None,
                "bytes_client_to_backend": 0,
                "bytes_backend_to_client": 0,
                "history": [
                    {"stage": "tcp_connected", "ts": now, "detail": {}}
                ],
                "error": None,
            }

        self.log(f"{client} connected")

    def update_stage(self, conn_id, stage, detail=None):
        with self._lock:
            conn = self._connections.get(conn_id)
            if conn is None:
                return
            conn["stage"] = stage
            conn["updated_at"] = time.time()
            conn["history"].append({
                "stage": stage,
                "ts": time.time(),
                "detail": detail or {},
            })
            if detail and detail.get("backend"):
                conn["backend"] = detail["backend"]
            client = conn["client"]

        self.log(f"{client} -> {stage}")

    def add_bytes(self, conn_id, direction, n):
        key = (
            "bytes_client_to_backend"
            if direction == "client_to_backend"
            else "bytes_backend_to_client"
        )
        with self._lock:
            conn = self._connections.get(conn_id)
            if conn is None:
                return
            conn[key] += n
            conn["updated_at"] = time.time()

    def close_connection(self, conn_id, status="closed", error=None):
        with self._lock:
            conn = self._connections.get(conn_id)
            if conn is None:
                return

            conn["status"] = status
            conn["error"] = error
            conn["closed_at"] = time.time()
            conn["updated_at"] = time.time()

            self._closed_ids.append(conn_id)
            if len(self._closed_ids) > MAX_CLOSED_CONNECTIONS:
                stale_id = self._closed_ids.pop(0)
                self._connections.pop(stale_id, None)

            client = conn["client"]

        suffix = f" ({error})" if error else ""
        self.log(f"{client} {status}{suffix}")

    # =====================================
    # SNAPSHOT FOR THE DASHBOARD PAGE
    # =====================================

    def snapshot(self):
        with self._lock:
            connections = sorted(
                self._connections.values(),
                key=lambda c: c["started_at"],
                reverse=True,
            )
            log_copy = list(self._log[-100:])

            return {
                "server_time": time.time(),
                "started_at": self.started_at,
                "connections": connections,
                "log": log_copy,
            }


_dashboard_hub = DashboardHub()


def get_dashboard():
    return _dashboard_hub


# =====================================
# LOCAL HTTP SERVER
# =====================================

def _default_html_path():
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "dashboard.html",
    )


def _make_handler(hub, html_path):

    class DashboardHandler(BaseHTTPRequestHandler):

        def log_message(self, fmt, *args):
            # Keep the proxy's own terminal output clean during a demo.
            pass

        def _send_json(self, payload):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                try:
                    with open(html_path, "rb") as f:
                        body = f.read()
                except OSError:
                    self.send_response(404)
                    self.end_headers()
                    return

                self.send_response(200)
                self.send_header(
                    "Content-Type", "text/html; charset=utf-8"
                )
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            elif self.path == "/status.json":
                self._send_json(hub.snapshot())

            else:
                self.send_response(404)
                self.end_headers()

    return DashboardHandler


def start_dashboard_server(
    hub=None, host="127.0.0.1", port=8090, html_path=None
):
    """
    Start the dashboard's local HTTP server in a background thread.

    Serves:
        GET /            -> dashboard.html
        GET /status.json -> hub.snapshot() as JSON

    Bound to localhost by default -- this is demo instrumentation,
    not meant to be reachable off the host.
    """

    if hub is None:
        hub = get_dashboard()

    if html_path is None:
        html_path = _default_html_path()

    handler_cls = _make_handler(hub, html_path)
    server = ThreadingHTTPServer((host, port), handler_cls)

    thread = threading.Thread(
        target=server.serve_forever,
        name="DashboardHTTP",
        daemon=True,
    )
    thread.start()

    return server
