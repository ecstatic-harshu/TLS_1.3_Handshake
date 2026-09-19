import ssl

from pathlib import Path
from common.config import CERT_FILE, KEY_FILE



# =====================================
# PROJECT PATHS
# =====================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)

DEFAULT_CERT_DIR = (
    PROJECT_ROOT
    /
    "certs"
)

DEFAULT_SERVER_CERT = (
    DEFAULT_CERT_DIR
    /
    "server.crt"
)

DEFAULT_SERVER_KEY = (
    DEFAULT_CERT_DIR
    /
    "server.key"
)


# =====================================
# INTERNAL HELPERS
# =====================================

def _require_file(
    path,
    label: str
) -> str:

    resolved = Path(
        path
    ).expanduser().resolve()

    if not resolved.is_file():

        raise FileNotFoundError(
            f"{label} not found: "
            f"{resolved}"
        )

    return str(
        resolved
    )


# =====================================
# CREATE SERVER TLS CONTEXT
# =====================================

def create_server_context(
    certfile=None,
    keyfile=None
):
    """
    Create TLS 1.3-only server context.
    """

    if certfile is None:

        certfile = (
            DEFAULT_SERVER_CERT
        )

    if keyfile is None:

        keyfile = (
            DEFAULT_SERVER_KEY
        )

    certfile = _require_file(
        certfile,
        "Server certificate"
    )

    keyfile = _require_file(
        keyfile,
        "Server private key"
    )

    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_SERVER
    )

    # =====================================
    # REQUIRE TLS 1.3 EXACTLY
    # =====================================

    context.minimum_version = (
        ssl.TLSVersion.TLSv1_3
    )

    context.maximum_version = (
        ssl.TLSVersion.TLSv1_3
    )

    # =====================================
    # LOAD SERVER IDENTITY
    # =====================================

    context.load_cert_chain(
        CERT_FILE,
        KEY_FILE
    )

    return context


# =====================================
# CREATE CLIENT TLS CONTEXT
# =====================================

def create_client_context(
    cafile=None,
    verify_server=True
):
    """
    Create TLS 1.3-only client context.

    Production/research-secure mode:

        create_client_context(
            cafile="certs/server.crt",
            verify_server=True
        )

    Local prototype mode:

        create_client_context(
            verify_server=False
        )
    """

    # =====================================
    # VERIFIED MODE
    # =====================================

    if verify_server:

        context = (
            ssl.create_default_context(
                purpose=
                    ssl.Purpose.SERVER_AUTH
            )
        )

        if cafile is not None:

            cafile = _require_file(
                cafile,
                "CA certificate"
            )

            context.load_verify_locations(
                cafile=cafile
            )

        context.check_hostname = True

        context.verify_mode = (
            ssl.CERT_REQUIRED
        )

    # =====================================
    # LOCAL PROTOTYPE MODE
    # =====================================

    else:

        context = ssl.SSLContext(
            ssl.PROTOCOL_TLS_CLIENT
        )

        context.check_hostname = False

        context.verify_mode = (
            ssl.CERT_NONE
        )

    # =====================================
    # REQUIRE TLS 1.3 EXACTLY
    # =====================================

    context.minimum_version = (
        ssl.TLSVersion.TLSv1_3
    )

    context.maximum_version = (
        ssl.TLSVersion.TLSv1_3
    )

    return context