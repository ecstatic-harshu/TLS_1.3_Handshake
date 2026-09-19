import socket
import threading
import time

from common.logger import (
    setup_logger
)

from common.handshake import (
    perform_client_handshake,
    perform_server_handshake
)

from common.pq_dsa import (
    generate_keypair as dsa_keypair
)

from common.tls import (
    create_client_context,
    create_server_context
)

from common.tls_session import (
    TLSSession
)

from common.hybrid import (
    HybridKeyDerivation
)

from common.middleware_logger import (
    MiddlewareLogger
)

from common.secure_channel import (
    SecureChannel
)

from common.metrics import (
    Metrics
)

from common.session import (
    SecureSession
)

from common.backend import (
    connect_backend
)

from common.relay import (
    relay_secure_to_backend
)

from common.dashboard import (
    get_dashboard
)

from common.config import (
    BACKEND_HOST,
    BACKEND_PORT,
    BACKEND_USE_TLS,
    BACKEND_CONNECT_TIMEOUT,
    PROXY_IDLE_TIMEOUT
)


# =====================================
# OPTIONAL TRANSPORT LOCK CLEANUP
# =====================================

try:
    from common.transport import (
        release_socket_lock
    )

except ImportError:

    def release_socket_lock(sock):
        pass


# =====================================
# CONFIGURATION
# =====================================

DEFAULT_HOST = "127.0.0.1"

DEFAULT_PORT = 5000

DEFAULT_CONNECT_TIMEOUT = 10.0

DEFAULT_LISTEN_BACKLOG = 10

DEFAULT_PROXY_IDLE_TIMEOUT = PROXY_IDLE_TIMEOUT


# =====================================
# INTERNAL HELPERS
# =====================================

def _safe_close(
    sock
):
    """
    Best-effort socket shutdown and close.
    """

    if sock is None:
        return

    try:
        release_socket_lock(
            sock
        )
    except Exception:
        pass

    try:
        sock.shutdown(
            socket.SHUT_RDWR
        )
    except Exception:
        pass

    try:
        sock.close()
    except Exception:
        pass


def _display_digest(
    digest
):
    """
    Convert transcript digest into
    human-readable form.
    """

    if isinstance(
        digest,
        bytes
    ):
        return digest.hex()

    return str(
        digest
    )


def _require_handshake_result(
    handshake_result
):
    """
    Validate required HandshakeResult fields.
    """

    if handshake_result is None:

        raise ValueError(
            "Handshake returned no result"
        )

    required_fields = (
        "authenticated",
        "pq_shared_secret",
        "final_transcript_digest",
        "client_nonce",
        "server_nonce"
    )

    for field_name in required_fields:

        if not hasattr(
            handshake_result,
            field_name
        ):

            raise ValueError(
                "Handshake result missing "
                f"field: {field_name}"
            )

    if not handshake_result.authenticated:

        raise ValueError(
            "Handshake authentication failed"
        )

    byte_fields = (
        "pq_shared_secret",
        "final_transcript_digest",
        "client_nonce",
        "server_nonce"
    )

    for field_name in byte_fields:

        value = getattr(
            handshake_result,
            field_name
        )

        if not isinstance(
            value,
            bytes
        ):

            raise TypeError(
                f"Handshake result "
                f"{field_name} must be bytes"
            )

        if len(value) == 0:

            raise ValueError(
                f"Handshake result "
                f"{field_name} cannot be empty"
            )


def _record_duration(
    metrics,
    label,
    start_time,
    metadata=None
):
    """
    Record duration.

    Supports upgraded Metrics.record_duration()
    when available.

    Falls back to Metrics.record().
    """

    if hasattr(
        metrics,
        "record_duration"
    ):

        metrics.record_duration(
            label,
            start_time,
            metadata or {}
        )

        return

    duration_ms = (
        time.perf_counter()
        -
        start_time
    ) * 1000

    event_metadata = dict(
        metadata or {}
    )

    event_metadata[
        "duration_ms"
    ] = round(
        duration_ms,
        4
    )

    metrics.record(
        label,
        event_metadata
    )


def _export_tls_contribution(
    tls_session,
    logger,
    metrics
):
    """
    Export deterministic TLS contribution.

    Compatibility behavior:

    1. Prefer export_tls_binding()
       when available.

    2. Fall back to export_tls_secret()
       for older TLSSession versions.

    IMPORTANT:
    This helper does not claim that a
    metadata-derived value is a genuine
    TLS exporter secret.
    """

    contribution = None

    contribution_type = None

    # =====================================
    # PREFERRED:
    # TLS CONTEXT BINDING
    # =====================================

    if hasattr(
        tls_session,
        "export_tls_binding"
    ):

        contribution = (
            tls_session.export_tls_binding()
        )

        contribution_type = (
            "context_binding"
        )

    # =====================================
    # FALLBACK:
    # LEGACY TLS CONTRIBUTION API
    # =====================================

    elif hasattr(
        tls_session,
        "export_tls_secret"
    ):

        contribution = (
            tls_session.export_tls_secret()
        )

        contribution_type = (
            "legacy_tls_contribution"
        )

    else:

        raise AttributeError(
            "TLSSession must implement "
            "export_tls_binding() or "
            "export_tls_secret()"
        )

    # =====================================
    # VALIDATION
    # =====================================

    if not isinstance(
        contribution,
        bytes
    ):

        raise TypeError(
            "TLS contribution must be bytes"
        )

    if len(contribution) == 0:

        raise ValueError(
            "TLS contribution is empty"
        )

    # =====================================
    # METRICS
    # =====================================

    metrics.record(
        "TLS_CONTRIBUTION_EXPORTED",
        {
            "size":
                len(contribution),

            "type":
                contribution_type
        }
    )

    logger.info(
        f"TLS contribution exported: "
        f"{len(contribution)} bytes "
        f"({contribution_type})"
    )

    return (
        contribution,
        contribution_type
    )


def _create_secure_channel(
    hybrid_key,
    role
):
    """
    Create directional SecureChannel.

    Preferred integrated API:

        SecureChannel(
            master_key=hybrid_key,
            role="client"
        )

    Compatibility fallback:

        SecureChannel(hybrid_key)
    """

    try:

        return SecureChannel(
            master_key=hybrid_key,
            role=role
        )

    except TypeError:

        return SecureChannel(
            hybrid_key
        )


def _create_secure_session(
    pq_secret,
    tls_contribution,
    hybrid_key,
    transcript_hash,
    secure_channel,
    metrics,
    role
):
    """
    Create SecureSession with compatibility
    for upgraded and legacy constructors.
    """

    try:

        return SecureSession(
            pq_secret=
                pq_secret,

            tls_secret=
                tls_contribution,

            hybrid_key=
                hybrid_key,

            transcript_hash=
                transcript_hash,

            secure_channel=
                secure_channel,

            metrics=
                metrics,

            role=
                role
        )

    except TypeError:

        return SecureSession(
            pq_secret=
                pq_secret,

            tls_secret=
                tls_contribution,

            hybrid_key=
                hybrid_key,

            transcript_hash=
                transcript_hash,

            secure_channel=
                secure_channel,

            metrics=
                metrics
        )


# =====================================
# CLIENT API
# =====================================

def secure_connect(
    host=DEFAULT_HOST,
    port=DEFAULT_PORT,
    cafile=None,
    verify_server=False,
    server_hostname=None,
    timeout=DEFAULT_CONNECT_TIMEOUT
):
    """
    Establish complete secure client session.

    Pipeline:

        TCP
          ↓
        TLS 1.3
          ↓
        Authenticated PQ Handshake
          ├── ML-KEM-768
          └── ML-DSA-65
          ↓
        TLS Contribution
          ↓
        Transcript-Bound Hybrid HKDF
          ↓
        Directional AES-256-GCM
          ↓
        SecureSession
    """

    logger = setup_logger(
        "SECURE_CLIENT"
    )

    metrics = Metrics()

    raw_socket = None

    client_socket = None

    full_start = (
        time.perf_counter()
    )

    try:

        # =====================================
        # VALIDATE PARAMETERS
        # =====================================

        if not isinstance(
            host,
            str
        ) or not host:

            raise ValueError(
                "host must be a non-empty string"
            )

        if not isinstance(
            port,
            int
        ):

            raise TypeError(
                "port must be int"
            )

        if not (
            1 <= port <= 65535
        ):

            raise ValueError(
                "port must be between "
                "1 and 65535"
            )

        if (
            not isinstance(
                timeout,
                (int, float)
            )
            or
            timeout <= 0
        ):

            raise ValueError(
                "timeout must be positive"
            )

        # =====================================
        # STAGE 1
        # CREATE TCP SOCKET
        # =====================================

        MiddlewareLogger.log_stage(
            logger,
            "TCP_CONNECT"
        )

        raw_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        raw_socket.settimeout(
            float(timeout)
        )

        # =====================================
        # STAGE 2
        # CREATE TLS CONTEXT
        # =====================================

        try:

            context = create_client_context(
                cafile=cafile,
                verify_server=verify_server
            )

        except TypeError:

            # Compatibility with older tls.py
            context = create_client_context()

        # =====================================
        # SERVER HOSTNAME
        # =====================================

        if server_hostname is None:

            server_hostname = host

        # =====================================
        # STAGE 3
        # WRAP TLS SOCKET
        # =====================================

        client_socket = (
            context.wrap_socket(
                raw_socket,
                server_hostname=
                    server_hostname,
                do_handshake_on_connect=
                    False
            )
        )

        # SSLSocket now owns raw socket.
        raw_socket = None

        # =====================================
        # STAGE 4
        # TCP CONNECTION
        # =====================================

        tcp_start = (
            time.perf_counter()
        )

        client_socket.connect(
            (host, port)
        )

        _record_duration(
            metrics,
            "TCP_CONNECTED",
            tcp_start,
            {
                "host":
                    host,

                "port":
                    port
            }
        )

        logger.info(
            "TCP connection established"
        )

        # =====================================
        # STAGE 5
        # TLS HANDSHAKE
        # =====================================

        MiddlewareLogger.log_stage(
            logger,
            "TLS_HANDSHAKE"
        )

        tls_start = (
            time.perf_counter()
        )

        client_socket.do_handshake()

        _record_duration(
            metrics,
            "TLS_CONNECTED",
            tls_start,
            {
                "host":
                    host,

                "port":
                    port
            }
        )

        logger.info(
            "TLS connection established"
        )

        # =====================================
        # STAGE 6
        # TLS SESSION INFORMATION
        # =====================================

        tls_session = TLSSession(
            client_socket
        )

        tls_metadata = (
            tls_session.get_tls_metadata()
        )

        metrics.record(
            "TLS_METADATA",
            tls_metadata
        )

        logger.info(
            f"TLS Version: "
            f"{tls_metadata.get('version')}"
        )

        logger.info(
            f"TLS Cipher: "
            f"{tls_metadata.get('cipher')}"
        )

        # =====================================
        # STAGE 7
        # TLS CONTRIBUTION
        # =====================================

        (
            tls_contribution,
            tls_contribution_type
        ) = _export_tls_contribution(
            tls_session=
                tls_session,

            logger=
                logger,

            metrics=
                metrics
        )

        # =====================================
        # STAGE 8
        # AUTHENTICATED PQ HANDSHAKE
        # =====================================

        MiddlewareLogger.log_stage(
            logger,
            "AUTHENTICATED_PQ_HANDSHAKE"
        )

        pq_start = (
            time.perf_counter()
        )

        handshake_result = (
            perform_client_handshake(
                conn=client_socket,
                logger=logger,
                metrics=metrics
            )
        )

        _record_duration(
            metrics,
            "PQ_HANDSHAKE_COMPLETE",
            pq_start
        )

        _require_handshake_result(
            handshake_result
        )

        # =====================================
        # STAGE 9
        # HYBRID KEY DERIVATION
        # =====================================

        MiddlewareLogger.log_stage(
            logger,
            "HYBRID_KEY_DERIVATION"
        )

        hybrid_start = (
            time.perf_counter()
        )

        hybrid = (
            HybridKeyDerivation()
        )

        hybrid_key = hybrid.derive(
            pq_secret=(
                handshake_result
                .pq_shared_secret
            ),

            tls_secret=
                tls_contribution,

            transcript_digest=(
                handshake_result
                .final_transcript_digest
            ),

            client_nonce=(
                handshake_result
                .client_nonce
            ),

            server_nonce=(
                handshake_result
                .server_nonce
            )
        )

        if not isinstance(
            hybrid_key,
            bytes
        ):

            raise TypeError(
                "Hybrid key must be bytes"
            )

        if len(hybrid_key) != 32:

            raise ValueError(
                "Hybrid key must be "
                "32 bytes for AES-256-GCM"
            )

        _record_duration(
            metrics,
            "HYBRID_KEY_DERIVED",
            hybrid_start,
            {
                "key_size":
                    len(hybrid_key),

                "tls_input_type":
                    tls_contribution_type
            }
        )

        # =====================================
        # STAGE 10
        # CREATE DIRECTIONAL AES-GCM CHANNEL
        # =====================================

        MiddlewareLogger.log_stage(
            logger,
            "SECURE_CHANNEL_CREATION"
        )

        secure_channel = (
            _create_secure_channel(
                hybrid_key=
                    hybrid_key,

                role=
                    "client"
            )
        )

        metrics.record(
            "SECURE_CHANNEL_CREATED",
            {
                "algorithm":
                    "AES-256-GCM",

                "role":
                    "client",

                "key_size":
                    len(hybrid_key)
            }
        )

        # =====================================
        # STAGE 11
        # CREATE SECURE SESSION
        # =====================================

        session = (
            _create_secure_session(
                pq_secret=(
                    handshake_result
                    .pq_shared_secret
                ),

                tls_contribution=
                    tls_contribution,

                hybrid_key=
                    hybrid_key,

                transcript_hash=(
                    handshake_result
                    .final_transcript_digest
                ),

                secure_channel=
                    secure_channel,

                metrics=
                    metrics,

                role=
                    "client"
            )
        )

        session.socket = (
            client_socket
        )

        session.mark_authenticated()

        session.mark_established()

        metrics.record(
            "SESSION_ESTABLISHED",
            {
                "authenticated":
                    True,

                "role":
                    "client",

                "tls_contribution_type":
                    tls_contribution_type,

                "transcript_digest":
                    (
                        handshake_result
                        .final_transcript_digest
                        .hex()
                    )
            }
        )

        # =====================================
        # COMPLETE
        # =====================================

        _record_duration(
            metrics,
            "FULL_HANDSHAKE",
            full_start
        )

        logger.info(
            "Secure session established"
        )

        logger.info(
            "Authentication: SUCCESS"
        )

        logger.info(
            "PQ KEM: ML-KEM-768"
        )

        logger.info(
            "PQ Signature: ML-DSA-65"
        )

        logger.info(
            "Secure Channel: "
            "Directional AES-256-GCM"
        )

        logger.info(
            f"Transcript: "
            f"{_display_digest(
                handshake_result
                .final_transcript_digest
            )}"
        )

        logger.info(
            f"Metrics Summary: "
            f"{metrics.summary()}"
        )

        # Session owns socket now.
        client_socket = None

        return session

    except Exception as exc:

        metrics.record(
            "CONNECTION_FAILED",
            {
                "error":
                    str(exc)
            }
        )

        logger.error(
            f"Secure connection failed: "
            f"{exc}"
        )

        _safe_close(
            client_socket
        )

        _safe_close(
            raw_socket
        )

        raise


# =====================================
# SINGLE CONNECTION SERVER API
# =====================================

def secure_accept(
    host=DEFAULT_HOST,
    port=DEFAULT_PORT
):
    """
    Accept exactly one secure client.
    """

    logger = setup_logger(
        "SECURE_SERVER"
    )

    server_socket = None

    raw_client_socket = None

    conn = None

    try:

        # =====================================
        # SERVER ML-DSA IDENTITY
        # =====================================

        logger.info(
            "Generating server "
            "ML-DSA-65 keypair"
        )

        server_dsa_keypair = (
            dsa_keypair()
        )

        # =====================================
        # CREATE SERVER SOCKET
        # =====================================

        server_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        server_socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        server_socket.bind(
            (host, port)
        )

        server_socket.listen(
            1
        )

        logger.info(
            f"Secure server listening "
            f"on {host}:{port}"
        )

        # =====================================
        # TLS CONTEXT
        # =====================================

        context = (
            create_server_context()
        )

        # =====================================
        # ACCEPT TCP CLIENT
        # =====================================

        (
            raw_client_socket,
            addr
        ) = server_socket.accept()

        logger.info(
            f"TCP client connected: "
            f"{addr}"
        )

        # =====================================
        # TLS WRAP
        # =====================================

        conn = context.wrap_socket(
            raw_client_socket,
            server_side=True,
            do_handshake_on_connect=False
        )

        # SSLSocket owns raw socket.
        raw_client_socket = None

        # =====================================
        # TLS HANDSHAKE
        # =====================================

        tls_start = (
            time.perf_counter()
        )

        conn.do_handshake()

        logger.info(
            f"TLS client connected: "
            f"{addr}"
        )

        # =====================================
        # CREATE SESSION
        # =====================================

        session = _create_server_session(
            conn=conn,
            addr=addr,
            server_dsa_keypair=
                server_dsa_keypair,
            tls_handshake_start=
                tls_start
        )

        # Session owns conn.
        conn = None

        return session

    except Exception:

        _safe_close(
            conn
        )

        _safe_close(
            raw_client_socket
        )

        raise

    finally:

        _safe_close(
            server_socket
        )


# =====================================
# CREATE SERVER SESSION
# =====================================

def _create_server_session(
    conn,
    addr,
    server_dsa_keypair,
    tls_handshake_start=None
):
    """
    Convert established TLS connection
    into authenticated PQ-hybrid session.
    """

    logger = setup_logger(
        f"CLIENT_{addr[0]}_{addr[1]}"
    )

    metrics = Metrics()

    full_start = (
        time.perf_counter()
    )

    # =====================================
    # TLS CONNECTED
    # =====================================

    if tls_handshake_start is not None:

        _record_duration(
            metrics,
            "TLS_CONNECTED",
            tls_handshake_start,
            {
                "peer":
                    str(addr)
            }
        )

    else:

        metrics.record(
            "TLS_CONNECTED",
            {
                "peer":
                    str(addr)
            }
        )

    MiddlewareLogger.log_stage(
        logger,
        "TLS_HANDSHAKE_COMPLETE"
    )

    # =====================================
    # TLS SESSION INFORMATION
    # =====================================

    tls_session = TLSSession(
        conn
    )

    tls_metadata = (
        tls_session.get_tls_metadata()
    )

    metrics.record(
        "TLS_METADATA",
        tls_metadata
    )

    logger.info(
        f"TLS Version: "
        f"{tls_metadata.get('version')}"
    )

    logger.info(
        f"TLS Cipher: "
        f"{tls_metadata.get('cipher')}"
    )

    # =====================================
    # TLS CONTRIBUTION
    # =====================================

    (
        tls_contribution,
        tls_contribution_type
    ) = _export_tls_contribution(
        tls_session=
            tls_session,

        logger=
            logger,

        metrics=
            metrics
    )

    # =====================================
    # AUTHENTICATED PQ HANDSHAKE
    # =====================================

    MiddlewareLogger.log_stage(
        logger,
        "AUTHENTICATED_PQ_HANDSHAKE"
    )

    pq_start = (
        time.perf_counter()
    )

    handshake_result = (
        perform_server_handshake(
            conn=conn,
            logger=logger,
            metrics=metrics,
            server_dsa_keypair=
                server_dsa_keypair
        )
    )

    _record_duration(
        metrics,
        "PQ_HANDSHAKE_COMPLETE",
        pq_start
    )

    _require_handshake_result(
        handshake_result
    )

    # =====================================
    # HYBRID KEY DERIVATION
    # =====================================

    MiddlewareLogger.log_stage(
        logger,
        "HYBRID_KEY_DERIVATION"
    )

    hybrid_start = (
        time.perf_counter()
    )

    hybrid = (
        HybridKeyDerivation()
    )

    hybrid_key = hybrid.derive(
        pq_secret=(
            handshake_result
            .pq_shared_secret
        ),

        tls_secret=
            tls_contribution,

        transcript_digest=(
            handshake_result
            .final_transcript_digest
        ),

        client_nonce=(
            handshake_result
            .client_nonce
        ),

        server_nonce=(
            handshake_result
            .server_nonce
        )
    )

    if not isinstance(
        hybrid_key,
        bytes
    ):

        raise TypeError(
            "Hybrid key must be bytes"
        )

    if len(hybrid_key) != 32:

        raise ValueError(
            "Hybrid key must be "
            "32 bytes for AES-256-GCM"
        )

    _record_duration(
        metrics,
        "HYBRID_KEY_DERIVED",
        hybrid_start,
        {
            "key_size":
                len(hybrid_key),

            "tls_input_type":
                tls_contribution_type
        }
    )

    # =====================================
    # DIRECTIONAL AES-GCM CHANNEL
    # =====================================

    secure_channel = (
        _create_secure_channel(
            hybrid_key=
                hybrid_key,

            role=
                "server"
        )
    )

    metrics.record(
        "SECURE_CHANNEL_CREATED",
        {
            "algorithm":
                "AES-256-GCM",

            "role":
                "server",

            "key_size":
                len(hybrid_key)
        }
    )

    # =====================================
    # SECURE SESSION
    # =====================================

    session = (
        _create_secure_session(
            pq_secret=(
                handshake_result
                .pq_shared_secret
            ),

            tls_contribution=
                tls_contribution,

            hybrid_key=
                hybrid_key,

            transcript_hash=(
                handshake_result
                .final_transcript_digest
            ),

            secure_channel=
                secure_channel,

            metrics=
                metrics,

            role=
                "server"
        )
    )

    session.socket = (
        conn
    )

    session.mark_authenticated()

    session.mark_established()

    metrics.record(
        "SESSION_ESTABLISHED",
        {
            "authenticated":
                True,

            "role":
                "server",

            "peer":
                str(addr),

            "tls_contribution_type":
                tls_contribution_type,

            "transcript_digest":
                (
                    handshake_result
                    .final_transcript_digest
                    .hex()
                )
        }
    )

    # =====================================
    # COMPLETE
    # =====================================

    _record_duration(
        metrics,
        "FULL_HANDSHAKE",
        full_start
    )

    logger.info(
        f"Secure session established "
        f"for {addr}"
    )

    logger.info(
        "Authentication: SUCCESS"
    )

    logger.info(
        "PQ KEM: ML-KEM-768"
    )

    logger.info(
        "PQ Signature: ML-DSA-65"
    )

    logger.info(
        "Secure Channel: "
        "Directional AES-256-GCM"
    )

    logger.info(
        f"Transcript: "
        f"{_display_digest(
            handshake_result
            .final_transcript_digest
        )}"
    )

    return session


# =====================================
# MULTI-CLIENT HANDLER
# =====================================
def server_receive_loop(session, logger):

    logger.info("Waiting for secure client messages...")

    while True:

        try:

            data = session.receive_secure()

            message = data.decode("utf-8")

            logger.info(
                f"Received secure message: {message}"
            )

            # Optional response
            response = f"ACK: {message}"

            session.send_secure(
                response.encode("utf-8")
            )

        except Exception as e:

            logger.info(
                f"Receive loop stopped: {e}"
            )

            break


def handle_secure_client(
    conn,
    addr,
    server_dsa_keypair
):
    """
    Handle one secure client.

    TLS handshake runs in this worker
    thread so a stalled client cannot
    block the accept loop.
    """

    logger = setup_logger(
        f"CLIENT_{addr[0]}_{addr[1]}"
    )

    session = None

    try:

        logger.info(
            f"Handling secure client: "
            f"{addr}"
        )

        # =====================================
        # TLS HANDSHAKE (worker thread)
        # =====================================

        tls_start = (
            time.perf_counter()
        )

        conn.do_handshake()

        tls_duration_ms = (
            time.perf_counter()
            -
            tls_start
        ) * 1000

        logger.info(
            f"TLS established for "
            f"{addr} in "
            f"{tls_duration_ms:.4f} ms"
        )

        # =====================================
        # CREATE AUTHENTICATED SESSION
        # =====================================

        session = _create_server_session(
            conn=conn,
            addr=addr,
            server_dsa_keypair=
                server_dsa_keypair,
            tls_handshake_start=
                tls_start
        )

        # =====================================
        # RECEIVE SECURE MESSAGES
        # =====================================

        # while True:

            # plaintext = (
            #     session.receive_secure()
            # )

            # try:

            #     display_message = (
            #         plaintext.decode(
            #             "utf-8"
            #         )
            #     )

            # except UnicodeDecodeError:

            #     display_message = (
            #         repr(plaintext)
            #     )

            # logger.info(
            #     f"Received secure message: "
            #     f"{display_message}"
            # )
            
        server_receive_loop(
            session,
            logger
        )    

    except ConnectionError as exc:

        logger.info(
            f"Client disconnected: "
            f"{addr} - {exc}"
        )

    except Exception as exc:

        logger.error(
            f"Secure client error "
            f"{addr}: {exc}"
        )

        if (
            session is not None
            and
            session.metrics is not None
        ):

            session.metrics.record(
                "SESSION_ERROR",
                {
                    "error":
                        str(exc)
                }
            )

    finally:

        # =====================================
        # LOG METRICS
        # =====================================

        if (
            session is not None
            and
            session.metrics is not None
        ):

            logger.info(
                f"Metrics Summary: "
                f"{session.metrics.summary()}"
            )

            logger.info(
                f"Metrics Events: "
                f"{session.metrics.dump()}"
            )

        # =====================================
        # CLOSE CONNECTION
        # =====================================

        _safe_close(
            conn
        )

        logger.info(
            f"Connection closed: "
            f"{addr}"
        )


# =====================================
# MULTI-SESSION SERVER
# =====================================

def run_secure_server(
    host=DEFAULT_HOST,
    port=DEFAULT_PORT,
    backlog=DEFAULT_LISTEN_BACKLOG
):
    """
    Run multi-client TLS/PQ secure server.

    Server identity:
        one ML-DSA-65 keypair per process.

    Per client:
        independent TLS session
        independent ML-KEM shared secret
        independent transcript
        independent hybrid key
        independent SecureChannel
        independent replay state
    """

    logger = setup_logger(
        "MULTI_SERVER"
    )

    server_socket = None

    # =====================================
    # VALIDATE PARAMETERS
    # =====================================

    if not isinstance(
        host,
        str
    ) or not host:

        raise ValueError(
            "host must be a non-empty string"
        )

    if not isinstance(
        port,
        int
    ):

        raise TypeError(
            "port must be int"
        )

    if not (
        1 <= port <= 65535
    ):

        raise ValueError(
            "port must be between "
            "1 and 65535"
        )

    if not isinstance(
        backlog,
        int
    ) or backlog <= 0:

        raise ValueError(
            "backlog must be positive int"
        )

    # =====================================
    # GENERATE SERVER ML-DSA IDENTITY ONCE
    # =====================================

    logger.info(
        "Generating server "
        "ML-DSA-65 identity keypair"
    )

    server_dsa_keypair = (
        dsa_keypair()
    )

    logger.info(
        "Server ML-DSA-65 "
        "identity keypair ready"
    )

    try:

        # =====================================
        # CREATE TCP SERVER
        # =====================================

        server_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        server_socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        server_socket.bind(
            (host, port)
        )

        server_socket.listen(
            backlog
        )

        logger.info(
            f"Multi-session secure server "
            f"listening on {host}:{port}"
        )

        # =====================================
        # CREATE TLS CONTEXT ONCE
        # =====================================

        context = (
            create_server_context()
        )

        # =====================================
        # ACCEPT LOOP
        # =====================================

        while True:

            raw_client_socket = None

            conn = None

            try:

                # =====================================
                # ACCEPT TCP CLIENT
                # =====================================

                (
                    raw_client_socket,
                    addr
                ) = server_socket.accept()

                logger.info(
                    f"TCP client connected: "
                    f"{addr}"
                )

                # =====================================
                # TLS WRAP
                # =====================================

                conn = context.wrap_socket(
                    raw_client_socket,
                    server_side=True,
                    do_handshake_on_connect=False
                )

                # SSLSocket owns raw socket.
                raw_client_socket = None

                # =====================================
                # START CLIENT THREAD
                # TLS handshake runs inside
                # the worker thread.
                # =====================================

                thread = threading.Thread(
                    target=
                        handle_secure_client,

                    args=(
                        conn,
                        addr,
                        server_dsa_keypair
                    ),

                    daemon=True,

                    name=(
                        f"SecureClient-"
                        f"{addr[0]}-"
                        f"{addr[1]}"
                    )
                )

                thread.start()

                # Thread owns conn now.
                conn = None

                logger.info(
                    f"Started secure thread "
                    f"for {addr}"
                )

            except Exception as exc:

                logger.error(
                    f"Failed to establish "
                    f"client connection: {exc}"
                )

                _safe_close(
                    conn
                )

                _safe_close(
                    raw_client_socket
                )

    except KeyboardInterrupt:

        logger.info(
            "Server shutdown requested"
        )

    finally:

        _safe_close(
            server_socket
        )

        logger.info(
            "Secure server stopped"
        )


# =====================================
# GATEWAY / PROXY HANDLER
# =====================================

def handle_gateway_client(
    conn,
    addr,
    server_dsa_keypair,
    backend_host,
    backend_port,
    backend_use_tls=False,
    backend_connect_timeout=
        BACKEND_CONNECT_TIMEOUT,
    idle_timeout=DEFAULT_PROXY_IDLE_TIMEOUT,
    conn_id=None
):
    """
    PQ-terminate one client, dial backend,
    then bidirectionally relay traffic.
    """

    logger = setup_logger(
        f"GATEWAY_{addr[0]}_{addr[1]}"
    )

    dashboard = get_dashboard()

    session = None
    backend_sock = None
    close_status = "closed"
    close_error = None

    try:

        logger.info(
            f"Handling gateway client: "
            f"{addr}"
        )

        # =====================================
        # TLS HANDSHAKE (worker thread)
        # =====================================

        tls_start = (
            time.perf_counter()
        )

        conn.do_handshake()

        tls_duration_ms = (
            time.perf_counter()
            -
            tls_start
        ) * 1000

        logger.info(
            f"TLS established for "
            f"{addr} in "
            f"{tls_duration_ms:.4f} ms"
        )

        if conn_id:
            dashboard.update_stage(
                conn_id,
                "tls_established",
                {"duration_ms": round(tls_duration_ms, 2)}
            )

        # =====================================
        # PQ SESSION WITH CLIENT
        # =====================================

        session = _create_server_session(
            conn=conn,
            addr=addr,
            server_dsa_keypair=
                server_dsa_keypair,
            tls_handshake_start=
                tls_start
        )

        if conn_id:
            dashboard.update_stage(
                conn_id,
                "pq_handshake_complete",
                {"kem": "ML-KEM-768", "sig": "ML-DSA-65"}
            )

        # =====================================
        # DIAL BACKEND
        # =====================================

        logger.info(
            "Dialing backend "
            f"{backend_host}:{backend_port} "
            f"(tls={backend_use_tls})"
        )

        backend_sock = connect_backend(
            host=backend_host,
            port=backend_port,
            use_tls=backend_use_tls,
            timeout=backend_connect_timeout,
            metrics=session.metrics
        )

        logger.info(
            "Backend connected; "
            "starting relay"
        )

        if conn_id:
            dashboard.update_stage(
                conn_id,
                "backend_connected",
                {"backend": f"{backend_host}:{backend_port}"}
            )
            dashboard.update_stage(
                conn_id,
                "relaying"
            )

        # =====================================
        # BIDIRECTIONAL RELAY
        # =====================================

        relay_secure_to_backend(
            session=session,
            backend_sock=backend_sock,
            logger=logger,
            metrics=session.metrics,
            idle_timeout=idle_timeout,
            conn_id=conn_id,
            dashboard=dashboard
        )

    except ConnectionError as exc:

        logger.info(
            f"Gateway client disconnected: "
            f"{addr} - {exc}"
        )

        close_status = "disconnected"
        close_error = str(exc)

    except Exception as exc:

        logger.error(
            f"Gateway client error "
            f"{addr}: {exc}"
        )

        close_status = "error"
        close_error = str(exc)

        if (
            session is not None
            and
            session.metrics is not None
        ):

            session.metrics.record(
                "GATEWAY_SESSION_ERROR",
                {
                    "error":
                        str(exc)
                }
            )

    finally:

        if (
            session is not None
            and
            session.metrics is not None
        ):

            logger.info(
                f"Metrics Summary: "
                f"{session.metrics.summary()}"
            )

        if conn_id:
            dashboard.close_connection(
                conn_id,
                status=close_status,
                error=close_error
            )

        _safe_close(
            backend_sock
        )

        _safe_close(
            conn
        )

        logger.info(
            f"Gateway connection closed: "
            f"{addr}"
        )


# =====================================
# MULTI-SESSION GATEWAY / PROXY
# =====================================

def run_secure_gateway(
    host=DEFAULT_HOST,
    port=DEFAULT_PORT,
    backend_host=BACKEND_HOST,
    backend_port=BACKEND_PORT,
    backend_use_tls=BACKEND_USE_TLS,
    backend_connect_timeout=
        BACKEND_CONNECT_TIMEOUT,
    idle_timeout=DEFAULT_PROXY_IDLE_TIMEOUT,
    backlog=DEFAULT_LISTEN_BACKLOG
):
    """
    Run PQ-terminating gateway proxy.

    Client-facing leg:
        TLS 1.3 + ML-KEM/ML-DSA session

    Backend-facing leg:
        plain TCP or standard TLS

    Application bytes are relayed after
    PQ terminate-and-reissue.
    """

    logger = setup_logger(
        "SECURE_GATEWAY"
    )

    server_socket = None

    if not isinstance(
        host,
        str
    ) or not host:

        raise ValueError(
            "host must be a non-empty string"
        )

    if not isinstance(
        port,
        int
    ):

        raise TypeError(
            "port must be int"
        )

    if not (
        1 <= port <= 65535
    ):

        raise ValueError(
            "port must be between "
            "1 and 65535"
        )

    if not isinstance(
        backend_host,
        str
    ) or not backend_host:

        raise ValueError(
            "backend_host must be a "
            "non-empty string"
        )

    if not isinstance(
        backend_port,
        int
    ):

        raise TypeError(
            "backend_port must be int"
        )

    if not (
        1 <= backend_port <= 65535
    ):

        raise ValueError(
            "backend_port must be between "
            "1 and 65535"
        )

    if not isinstance(
        backlog,
        int
    ) or backlog <= 0:

        raise ValueError(
            "backlog must be positive int"
        )

    logger.info(
        "Generating server "
        "ML-DSA-65 identity keypair"
    )

    server_dsa_keypair = (
        dsa_keypair()
    )

    logger.info(
        "Server ML-DSA-65 "
        "identity keypair ready"
    )

    try:

        server_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        server_socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        server_socket.bind(
            (host, port)
        )

        server_socket.listen(
            backlog
        )

        logger.info(
            f"Secure gateway listening "
            f"on {host}:{port}"
        )

        logger.info(
            f"Backend target "
            f"{backend_host}:{backend_port} "
            f"(tls={backend_use_tls})"
        )

        context = (
            create_server_context()
        )

        while True:

            raw_client_socket = None

            conn = None

            try:

                (
                    raw_client_socket,
                    addr
                ) = server_socket.accept()

                logger.info(
                    f"TCP client connected: "
                    f"{addr}"
                )

                conn = context.wrap_socket(
                    raw_client_socket,
                    server_side=True,
                    do_handshake_on_connect=
                        False
                )

                raw_client_socket = None

                conn_id = (
                    f"{addr[0]}:{addr[1]}:"
                    f"{time.time_ns()}"
                )

                get_dashboard().register_connection(
                    conn_id,
                    addr,
                    backend_host=backend_host,
                    backend_port=backend_port
                )

                thread = threading.Thread(
                    target=
                        handle_gateway_client,

                    args=(
                        conn,
                        addr,
                        server_dsa_keypair,
                        backend_host,
                        backend_port,
                        backend_use_tls,
                        backend_connect_timeout,
                        idle_timeout,
                        conn_id
                    ),

                    daemon=True,

                    name=(
                        f"GatewayClient-"
                        f"{addr[0]}-"
                        f"{addr[1]}"
                    )
                )

                thread.start()

                conn = None

                logger.info(
                    f"Started gateway thread "
                    f"for {addr}"
                )

            except Exception as exc:

                logger.error(
                    f"Failed to accept "
                    f"gateway client: {exc}"
                )

                _safe_close(
                    conn
                )

                _safe_close(
                    raw_client_socket
                )

    except KeyboardInterrupt:

        logger.info(
            "Gateway shutdown requested"
        )

    finally:

        _safe_close(
            server_socket
        )

        logger.info(
            "Secure gateway stopped"
        )