import socket
import threading
import time
import unittest

from common.relay import relay_secure_to_backend


class FakeSession:
    """Minimal stand-in for SecureSession."""

    def __init__(self, messages, client_sock):
        self._messages = list(messages)
        self._index = 0
        self.socket = client_sock
        self.sent = []
        self._lock = threading.Lock()

    def receive_secure(self):
        with self._lock:
            if self._index < len(self._messages):
                message = self._messages[self._index]
                self._index += 1
                return message

        # Block like a real socket until relay closes.
        try:
            self.socket.recv(1)
        except Exception:
            pass

        raise ConnectionError("client closed")

    def send_secure(self, data):
        self.sent.append(data)


class RelayTests(unittest.TestCase):

    def test_client_to_backend_and_response(self):
        backend_server = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )
        backend_server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )
        backend_server.bind(("127.0.0.1", 0))
        backend_server.listen(1)
        backend_port = backend_server.getsockname()[1]

        received = {}
        responded = threading.Event()

        def backend_handler():
            conn, _ = backend_server.accept()
            try:
                data = conn.recv(4096)
                received["data"] = data
                conn.sendall(b"ACK:" + data)
                responded.set()
            finally:
                conn.close()
                backend_server.close()

        threading.Thread(
            target=backend_handler,
            daemon=True
        ).start()

        backend_sock = socket.create_connection(
            ("127.0.0.1", backend_port),
            timeout=2.0
        )

        client_sock, _peer = socket.socketpair()

        session = FakeSession(
            [b"hello-proxy"],
            client_sock
        )

        relay_thread = threading.Thread(
            target=relay_secure_to_backend,
            kwargs={
                "session": session,
                "backend_sock": backend_sock,
                "idle_timeout": 2.0
            },
            daemon=True
        )
        relay_thread.start()

        self.assertTrue(
            responded.wait(2.0),
            "backend did not receive/respond"
        )

        # Allow backend→client pump to deliver.
        # (responded is already set here, so waiting on it again would
        # return immediately -- use a real sleep to poll for delivery.)
        for _ in range(50):
            if session.sent:
                break
            time.sleep(0.05)

        # Close client leg to stop the relay.
        try:
            _peer.close()
        except Exception:
            pass

        relay_thread.join(timeout=2.0)

        self.assertEqual(
            received.get("data"),
            b"hello-proxy"
        )
        self.assertEqual(
            session.sent,
            [b"ACK:hello-proxy"]
        )


if __name__ == "__main__":
    unittest.main()
