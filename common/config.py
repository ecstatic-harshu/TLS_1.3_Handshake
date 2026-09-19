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