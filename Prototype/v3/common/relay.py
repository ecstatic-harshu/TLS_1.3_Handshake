import socket
import threading

from common.backend import connect_backend


DEFAULT_BACKEND_RECV_SIZE = 4096


def relay_secure_to_backend(
    session,
    backend_sock,
    logger=None,
    metrics=None,
    idle_timeout=None,
    recv_size=DEFAULT_BACKEND_RECV_SIZE
):
    """
    Bidirectional raw-byte relay (TCP backends).

    client → backend:
        session.receive_secure() → backend sendall

    backend → client:
        backend recv() → session.send_secure()
    """

    if session is None:
        raise ValueError("session is required")

    if backend_sock is None:
        raise ValueError(
            "backend_sock is required"
        )

    stop_event = threading.Event()
    close_lock = threading.Lock()

    def _log(level, message):
        if logger is None:
            return

        log_fn = getattr(logger, level, None)
        if callable(log_fn):
            log_fn(message)

    def _record(label, metadata=None):
        if metrics is None:
            return

        metrics.record(label, metadata or {})

    def _shutdown():
        if stop_event.is_set():
            return

        stop_event.set()

        with close_lock:
            try:
                backend_sock.shutdown(
                    socket.SHUT_RDWR
                )
            except Exception:
                pass

            try:
                backend_sock.close()
            except Exception:
                pass

            client_sock = getattr(
                session,
                "socket",
                None
            )

            if client_sock is not None:
                try:
                    client_sock.shutdown(
                        socket.SHUT_RDWR
                    )
                except Exception:
                    pass

                try:
                    client_sock.close()
                except Exception:
                    pass

    if idle_timeout is not None:
        timeout_value = float(idle_timeout)

        if timeout_value <= 0:
            raise ValueError(
                "idle_timeout must be positive"
            )

        try:
            backend_sock.settimeout(timeout_value)
        except Exception:
            pass

        client_sock = getattr(
            session,
            "socket",
            None
        )

        if client_sock is not None:
            try:
                client_sock.settimeout(
                    timeout_value
                )
            except Exception:
                pass

    def client_to_backend():
        try:
            while not stop_event.is_set():
                try:
                    chunk = session.receive_secure()
                except Exception as exc:
                    _log(
                        "info",
                        "Client→backend stopped: "
                        f"{exc}"
                    )
                    _record(
                        "RELAY_CLIENT_TO_BACKEND_STOP",
                        {"error": str(exc)}
                    )
                    break

                if not chunk:
                    _log(
                        "info",
                        "Client→backend empty "
                        "message; closing relay"
                    )
                    break

                try:
                    backend_sock.sendall(chunk)
                except Exception as exc:
                    _log(
                        "info",
                        "Backend send failed: "
                        f"{exc}"
                    )
                    _record(
                        "RELAY_BACKEND_SEND_FAILED",
                        {"error": str(exc)}
                    )
                    break

                _record(
                    "RELAY_CLIENT_TO_BACKEND",
                    {"bytes": len(chunk)}
                )

        finally:
            _shutdown()

    def backend_to_client():
        try:
            while not stop_event.is_set():
                try:
                    chunk = backend_sock.recv(
                        recv_size
                    )
                except socket.timeout:
                    _log(
                        "info",
                        "Backend idle timeout; "
                        "closing relay"
                    )
                    _record(
                        "RELAY_BACKEND_IDLE_TIMEOUT"
                    )
                    break
                except Exception as exc:
                    _log(
                        "info",
                        "Backend→client stopped: "
                        f"{exc}"
                    )
                    _record(
                        "RELAY_BACKEND_TO_CLIENT_STOP",
                        {"error": str(exc)}
                    )
                    break

                if not chunk:
                    _log(
                        "info",
                        "Backend EOF; closing relay"
                    )
                    _record("RELAY_BACKEND_EOF")
                    break

                try:
                    session.send_secure(chunk)
                except Exception as exc:
                    _log(
                        "info",
                        "Client send failed: "
                        f"{exc}"
                    )
                    _record(
                        "RELAY_CLIENT_SEND_FAILED",
                        {"error": str(exc)}
                    )
                    break

                _record(
                    "RELAY_BACKEND_TO_CLIENT",
                    {"bytes": len(chunk)}
                )

        finally:
            _shutdown()

    _log(
        "info",
        "Starting bidirectional backend relay"
    )
    _record("RELAY_STARTED")

    client_thread = threading.Thread(
        target=client_to_backend,
        name="RelayClientToBackend",
        daemon=True
    )

    backend_thread = threading.Thread(
        target=backend_to_client,
        name="RelayBackendToClient",
        daemon=True
    )

    client_thread.start()
    backend_thread.start()

    client_thread.join()
    backend_thread.join()

    _shutdown()
    _record("RELAY_STOPPED")
    _log("info", "Backend relay stopped")


def _build_http_post(path, host, body):
    if not isinstance(body, bytes):
        raise TypeError("body must be bytes")

    if not path.startswith("/"):
        path = "/" + path

    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii")

    return headers + body


def _recv_http_response(sock, timeout=None):
    if timeout is not None:
        sock.settimeout(float(timeout))

    chunks = []
    while True:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            break

        if not data:
            break

        chunks.append(data)

    return b"".join(chunks)


def _extract_http_body(response):
    """
    Return response body if headers are
    present; otherwise return the raw bytes.
    """

    separator = b"\r\n\r\n"
    index = response.find(separator)

    if index < 0:
        return response

    return response[index + len(separator):]


def relay_secure_to_http_backend(
    session,
    backend_host,
    backend_port,
    backend_use_tls=False,
    backend_connect_timeout=10.0,
    http_path="/echo",
    logger=None,
    metrics=None,
    idle_timeout=None
):
    """
    Request/response HTTP relay.

    Each secure client message becomes one
    POST {http_path} with Connection: close,
    using a fresh backend TCP connection.

    The HTTP response body is returned to
    the client as one secure message.
    """

    if session is None:
        raise ValueError("session is required")

    def _log(level, message):
        if logger is None:
            return

        log_fn = getattr(logger, level, None)
        if callable(log_fn):
            log_fn(message)

    def _record(label, metadata=None):
        if metrics is None:
            return

        metrics.record(label, metadata or {})

    client_sock = getattr(session, "socket", None)

    if idle_timeout is not None and client_sock is not None:
        try:
            client_sock.settimeout(float(idle_timeout))
        except Exception:
            pass

    _log(
        "info",
        "Starting HTTP request/response relay "
        f"(POST {http_path})"
    )
    _record(
        "RELAY_HTTP_STARTED",
        {"path": http_path}
    )

    try:
        while True:
            try:
                payload = session.receive_secure()
            except Exception as exc:
                _log(
                    "info",
                    f"HTTP relay client stopped: {exc}"
                )
                _record(
                    "RELAY_HTTP_CLIENT_STOP",
                    {"error": str(exc)}
                )
                break

            if not payload:
                _log(
                    "info",
                    "HTTP relay empty payload; stopping"
                )
                break

            backend_sock = None

            try:
                backend_sock = connect_backend(
                    host=backend_host,
                    port=backend_port,
                    use_tls=backend_use_tls,
                    timeout=backend_connect_timeout,
                    metrics=metrics
                )

                request = _build_http_post(
                    path=http_path,
                    host=backend_host,
                    body=payload
                )

                backend_sock.sendall(request)

                _record(
                    "RELAY_HTTP_REQUEST_SENT",
                    {
                        "request_bytes": len(request),
                        "body_bytes": len(payload)
                    }
                )

                response = _recv_http_response(
                    backend_sock,
                    timeout=idle_timeout
                )

                body = _extract_http_body(response)

                if not body:
                    body = response or b""

                session.send_secure(body)

                _log(
                    "info",
                    "HTTP relay round-trip "
                    f"({len(payload)} B → "
                    f"{len(body)} B)"
                )

                _record(
                    "RELAY_HTTP_RESPONSE_SENT",
                    {
                        "response_bytes": len(response),
                        "body_bytes": len(body)
                    }
                )

            except Exception as exc:
                _log(
                    "error",
                    f"HTTP relay request failed: {exc}"
                )
                _record(
                    "RELAY_HTTP_REQUEST_FAILED",
                    {"error": str(exc)}
                )

                try:
                    session.send_secure(
                        f"BACKEND_ERROR: {exc}".encode(
                            "utf-8"
                        )
                    )
                except Exception:
                    break

            finally:
                if backend_sock is not None:
                    try:
                        backend_sock.close()
                    except Exception:
                        pass

    finally:
        _record("RELAY_HTTP_STOPPED")
        _log("info", "HTTP backend relay stopped")

        if client_sock is not None:
            try:
                client_sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass

            try:
                client_sock.close()
            except Exception:
                pass


def relay_secure_to_secure(
    client_session,
    backend_session,
    logger=None,
    metrics=None,
    idle_timeout=None
):
    """
    Bidirectional relay between two PQ
    SecureSession objects.

    Used when the proxy↔backend hop is also
    quantum-safe (backend_pq mode).
    """

    if client_session is None:
        raise ValueError(
            "client_session is required"
        )

    if backend_session is None:
        raise ValueError(
            "backend_session is required"
        )

    stop_event = threading.Event()
    close_lock = threading.Lock()

    def _log(level, message):
        if logger is None:
            return

        log_fn = getattr(logger, level, None)
        if callable(log_fn):
            log_fn(message)

    def _record(label, metadata=None):
        if metrics is None:
            return

        metrics.record(label, metadata or {})

    def _close_session(session):
        sock = getattr(session, "socket", None)
        if sock is None:
            return

        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass

        try:
            sock.close()
        except Exception:
            pass

    def _shutdown():
        if stop_event.is_set():
            return

        stop_event.set()

        with close_lock:
            _close_session(client_session)
            _close_session(backend_session)

    def _apply_timeout(session):
        if idle_timeout is None:
            return

        sock = getattr(session, "socket", None)
        if sock is None:
            return

        try:
            sock.settimeout(float(idle_timeout))
        except Exception:
            pass

    _apply_timeout(client_session)
    _apply_timeout(backend_session)

    def client_to_backend():
        try:
            while not stop_event.is_set():
                try:
                    chunk = client_session.receive_secure()
                except Exception as exc:
                    _log(
                        "info",
                        "PQ client→backend stopped: "
                        f"{exc}"
                    )
                    _record(
                        "RELAY_PQ_CLIENT_TO_BACKEND_STOP",
                        {"error": str(exc)}
                    )
                    break

                if not chunk:
                    break

                try:
                    backend_session.send_secure(chunk)
                except Exception as exc:
                    _log(
                        "info",
                        "PQ backend send failed: "
                        f"{exc}"
                    )
                    _record(
                        "RELAY_PQ_BACKEND_SEND_FAILED",
                        {"error": str(exc)}
                    )
                    break

                _record(
                    "RELAY_PQ_CLIENT_TO_BACKEND",
                    {"bytes": len(chunk)}
                )
        finally:
            _shutdown()

    def backend_to_client():
        try:
            while not stop_event.is_set():
                try:
                    chunk = backend_session.receive_secure()
                except Exception as exc:
                    _log(
                        "info",
                        "PQ backend→client stopped: "
                        f"{exc}"
                    )
                    _record(
                        "RELAY_PQ_BACKEND_TO_CLIENT_STOP",
                        {"error": str(exc)}
                    )
                    break

                if not chunk:
                    break

                try:
                    client_session.send_secure(chunk)
                except Exception as exc:
                    _log(
                        "info",
                        "PQ client send failed: "
                        f"{exc}"
                    )
                    _record(
                        "RELAY_PQ_CLIENT_SEND_FAILED",
                        {"error": str(exc)}
                    )
                    break

                _record(
                    "RELAY_PQ_BACKEND_TO_CLIENT",
                    {"bytes": len(chunk)}
                )
        finally:
            _shutdown()

    _log(
        "info",
        "Starting PQ↔PQ secure backend relay"
    )
    _record("RELAY_PQ_STARTED")

    t1 = threading.Thread(
        target=client_to_backend,
        name="RelayPqClientToBackend",
        daemon=True
    )
    t2 = threading.Thread(
        target=backend_to_client,
        name="RelayPqBackendToClient",
        daemon=True
    )

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    _shutdown()
    _record("RELAY_PQ_STOPPED")
    _log("info", "PQ↔PQ backend relay stopped")
