import socket
import ssl
import time


DEFAULT_CONNECT_TIMEOUT = 10.0


def connect_backend(
    host,
    port,
    use_tls=False,
    timeout=DEFAULT_CONNECT_TIMEOUT,
    server_hostname=None,
    metrics=None
):
    """
    Dial an ordinary backend over plain TCP
    or standard TLS.

    The backend does not speak the PQ
    protocol — this is a normal outbound
    connection for terminate-and-reissue
    proxying.
    """

    if not isinstance(host, str) or not host:
        raise ValueError(
            "backend host must be a non-empty string"
        )

    if not isinstance(port, int):
        raise TypeError("backend port must be int")

    if not (1 <= port <= 65535):
        raise ValueError(
            "backend port must be between 1 and 65535"
        )

    if (
        not isinstance(timeout, (int, float))
        or timeout <= 0
    ):
        raise ValueError(
            "backend timeout must be positive"
        )

    raw_socket = None
    connected = None
    start = time.perf_counter()

    try:
        raw_socket = socket.create_connection(
            (host, port),
            timeout=float(timeout)
        )

        if use_tls:
            context = ssl.create_default_context()

            hostname = (
                server_hostname
                if server_hostname is not None
                else host
            )

            connected = context.wrap_socket(
                raw_socket,
                server_hostname=hostname
            )
            raw_socket = None
        else:
            connected = raw_socket
            raw_socket = None

        duration_ms = (
            time.perf_counter() - start
        ) * 1000

        if metrics is not None:
            metrics.record(
                "BACKEND_CONNECTED",
                {
                    "host": host,
                    "port": port,
                    "use_tls": bool(use_tls),
                    "duration_ms": round(
                        duration_ms,
                        4
                    )
                }
            )

        return connected

    except Exception as exc:
        if metrics is not None:
            metrics.record(
                "BACKEND_CONNECT_FAILED",
                {
                    "host": host,
                    "port": port,
                    "use_tls": bool(use_tls),
                    "error": str(exc)
                }
            )

        if connected is not None:
            try:
                connected.close()
            except Exception:
                pass

        if raw_socket is not None:
            try:
                raw_socket.close()
            except Exception:
                pass

        raise ConnectionError(
            f"Failed to connect to backend "
            f"{host}:{port}: {exc}"
        ) from exc
