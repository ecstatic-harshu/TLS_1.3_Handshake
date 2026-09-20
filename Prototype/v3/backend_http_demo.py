"""
Simple demo HTTP API for the PQ middleware proxy backend.

Run:
    python backend_http_demo.py

Then point the proxy at it:
    python -m middleware.main --mode proxy --backend-host 127.0.0.1 --backend-port 8080

Test the API directly (without proxy):
    curl http://127.0.0.1:8080/
    curl http://127.0.0.1:8080/health
    curl -X POST http://127.0.0.1:8080/echo -d "hello"
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import os


HOST = "0.0.0.0"
PORT = int(os.environ.get("BACKEND_PORT") or os.environ.get("PORT") or "8080")


class DemoAPIHandler(BaseHTTPRequestHandler):

    def _send(self, status: int, body: bytes, content_type: str = "text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/health"):
            self._send(200, b"OK - demo HTTP API on 8080\n")
            return

        if self.path == "/info":
            body = (
                b'{"service":"demo-backend","port":8080,"status":"up"}\n'
            )
            self._send(200, body, "application/json")
            return

        self._send(404, b"Not found\n")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length) if length > 0 else b""

        if self.path == "/echo":
            reply = b"echo: " + data + b"\n"
            self._send(200, reply)
            return

        self._send(404, b"Not found\n")

    def log_message(self, format, *args):
        print(f"[BACKEND] {self.address_string()} - {format % args}")


def main():
    server = HTTPServer((HOST, PORT), DemoAPIHandler)
    print(f"Demo HTTP API listening on http://{HOST}:{PORT}")
    print("Endpoints: GET /, GET /health, GET /info, POST /echo")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nBackend stopped")
        server.server_close()


if __name__ == "__main__":
    main()
