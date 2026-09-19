import socket
import threading


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
    Bidirectional terminate-and-reissue relay.

    client → backend:
        session.receive_secure() → backend sendall

    backend → client:
        backend recv() → session.send_secure()

    Each backend recv() chunk becomes one
    secure message (message-framed client leg).

    Either leg closing (EOF, error, or idle
    timeout) stops both directions and closes
    both sockets.
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
