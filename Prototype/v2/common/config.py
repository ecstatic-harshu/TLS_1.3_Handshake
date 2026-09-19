import os

HOST = os.getenv("HOST", "0.0.0.0")

PORT = int(os.getenv("PORT", "5000"))

CERT_FILE = os.getenv(
    "CERT_FILE",
    "certs/server.crt"
)

KEY_FILE = os.getenv(
    "KEY_FILE",
    "certs/server.key"
)

LOG_LEVEL = os.getenv(
    "LOG_LEVEL",
    "INFO"
)

# =====================================
# PROXY / BACKEND TARGET (v1: single)
# =====================================

BACKEND_HOST = os.getenv(
    "BACKEND_HOST",
    "127.0.0.1"
)

BACKEND_PORT = int(
    os.getenv(
        "BACKEND_PORT",
        "8080"
    )
)

BACKEND_USE_TLS = (
    os.getenv(
        "BACKEND_USE_TLS",
        "false"
    ).strip().lower()
    in (
        "1",
        "true",
        "yes",
        "on"
    )
)

BACKEND_CONNECT_TIMEOUT = float(
    os.getenv(
        "BACKEND_CONNECT_TIMEOUT",
        "10.0"
    )
)

# Idle read timeout on both proxy legs.
# A timeout closes the relay (v1 policy).
PROXY_IDLE_TIMEOUT = float(
    os.getenv(
        "PROXY_IDLE_TIMEOUT",
        "60.0"
    )
)

# When true, each client message becomes one
# HTTP POST to BACKEND_HTTP_PATH (new TCP
# connection per message). Fixes plain-text
# interactive clients talking to HTTP APIs.
BACKEND_HTTP = (
    os.getenv(
        "BACKEND_HTTP",
        "true"
    ).strip().lower()
    in (
        "1",
        "true",
        "yes",
        "on"
    )
)

BACKEND_HTTP_PATH = os.getenv(
    "BACKEND_HTTP_PATH",
    "/echo"
)