import hashlib
import hmac
import time

from dataclasses import dataclass

from common.transport import (
    send_packet,
    recv_packet
)

from common.protocol import (
    build_hello,
    build_ciphertext,
    build_dsa_pubkey,
    build_signature,
    build_done,
    build_error,
    parse_packet
)

from common.pq_kem import (
    generate_keypair as kem_keypair,
    encapsulate,
    decapsulate
)

from common.pq_dsa import (
    generate_keypair as dsa_keypair,
    sign_data,
    verify_signature
)

from common.transcript import (
    Transcript,
    generate_nonce
)

from common.serializer import (
    MSG_HELLO,
    MSG_CIPHERTEXT,
    MSG_DSA_PUBKEY,
    MSG_SIGNATURE,
    MSG_DONE,
    MSG_ERROR
)

from common.middleware_logger import (
    MiddlewareLogger
)


# =====================================
# PROTOCOL CONFIGURATION
# =====================================

TRANSCRIPT_LABEL = (
    "QSCP-HYBRID-HANDSHAKE-v1"
)

KEM_ALGORITHM = (
    "ML-KEM-768"
)

DSA_ALGORITHM = (
    "ML-DSA-65"
)

NONCE_SIZE = 32

MIN_SHARED_SECRET_SIZE = 16


# =====================================
# HANDSHAKE RESULT
# =====================================

@dataclass(frozen=True)
class HandshakeResult:

    pq_shared_secret: bytes

    auth_transcript_digest: bytes

    final_transcript_digest: bytes

    client_nonce: bytes

    server_nonce: bytes

    local_dsa_public_key: bytes

    peer_dsa_public_key: bytes

    authenticated: bool

    handshake_time_ms: float


# =====================================
# INTERNAL HELPERS
# =====================================

def _record_metric(
    metrics,
    label,
    metadata=None
):
    """
    Record a metric when a Metrics
    instance is available.
    """

    if metrics is None:
        return

    metrics.record(
        label,
        metadata or {}
    )


def _elapsed_ms(
    start_time
):
    """
    Return elapsed milliseconds using
    monotonic high-resolution timing.
    """

    return (
        time.perf_counter()
        -
        start_time
    ) * 1000


def _send_error(
    conn,
    message
):
    """
    Best-effort protocol error delivery.

    Failure to send the error must not
    hide the original handshake failure.
    """

    try:

        error_packet = build_error(
            str(message)
        )

        send_packet(
            conn,
            error_packet
        )

    except Exception:

        pass


def _expect_message(
    conn,
    expected_type
):
    """
    Receive exactly one framed protocol
    message and validate its type.
    """

    raw_packet = recv_packet(
        conn
    )

    msg_type, fields = parse_packet(
        raw_packet
    )

    # =====================================
    # PEER REPORTED ERROR
    # =====================================

    if msg_type == MSG_ERROR:

        error_message = fields.get(
            "error",
            "Peer reported handshake error"
        )

        raise ValueError(
            f"Peer handshake error: "
            f"{error_message}"
        )

    # =====================================
    # UNEXPECTED MESSAGE TYPE
    # =====================================

    if msg_type != expected_type:

        raise ValueError(
            "Unexpected message type. "
            f"Expected {expected_type:#04x}, "
            f"received {msg_type:#04x}"
        )

    return (
        raw_packet,
        fields
    )


def _require_bytes(
    value,
    field_name,
    minimum_size=1
):
    """
    Validate required byte fields received
    from protocol parsing.
    """

    if not isinstance(
        value,
        bytes
    ):

        raise TypeError(
            f"{field_name} must be bytes"
        )

    if len(value) < minimum_size:

        raise ValueError(
            f"{field_name} is too short"
        )

    return value


def _require_nonce(
    nonce,
    field_name
):
    """
    Require the protocol nonce size.
    """

    _require_bytes(
        nonce,
        field_name,
        NONCE_SIZE
    )

    if len(nonce) != NONCE_SIZE:

        raise ValueError(
            f"{field_name} must be "
            f"{NONCE_SIZE} bytes"
        )

    return nonce


def _require_shared_secret(
    shared_secret
):
    """
    Validate KEM output before returning
    it to hybrid derivation.
    """

    return _require_bytes(
        shared_secret,
        "pq_shared_secret",
        MIN_SHARED_SECRET_SIZE
    )


def _derive_confirmation_tag(
    pq_shared_secret,
    auth_digest,
    client_nonce,
    server_nonce,
    role
):
    """
    Derive role-separated key-confirmation
    tag from the ML-KEM shared secret.

    This proves both peers possess the
    same PQ shared secret.

    IMPORTANT:
    This is confirmation, not the final
    application traffic key.
    """

    if role not in (
        "client",
        "server"
    ):

        raise ValueError(
            "role must be client or server"
        )

    confirmation_input = (
        b"QSCP-PQ-CONFIRM-v1"
        +
        role.encode(
            "ascii"
        )
        +
        auth_digest
        +
        client_nonce
        +
        server_nonce
    )

    return hmac.new(
        pq_shared_secret,
        confirmation_input,
        hashlib.sha256
    ).digest()


def _build_done_confirmation(
    confirmation_tag
):
    """
    Build DONE payload.

    This requires build_done(payload)
    support in common.protocol.
    """

    return build_done(
        confirmation_tag
    )


def _extract_done_confirmation(
    fields
):
    """
    Extract confirmation bytes from a
    parsed DONE message.

    Supports either:
        fields["confirmation"]
    or:
        fields["payload"]
    """

    confirmation = fields.get(
        "confirmation"
    )

    if confirmation is None:

        confirmation = fields.get(
            "payload"
        )

    return _require_bytes(
        confirmation,
        "DONE confirmation",
        32
    )


# =====================================
# CLIENT HANDSHAKE
# =====================================

def perform_client_handshake(
    conn,
    logger,
    metrics=None
):

    handshake_start = (
        time.perf_counter()
    )

    MiddlewareLogger.log_stage(
        logger,
        "PQ_CLIENT_HANDSHAKE_START"
    )

    transcript = Transcript(
        label=TRANSCRIPT_LABEL
    )

    try:

        # =====================================
        # STEP 1
        # GENERATE CLIENT ML-KEM KEYPAIR
        # =====================================

        kem_start = (
            time.perf_counter()
        )

        (
            kem_public_key,
            kem_secret_key
        ) = kem_keypair()

        kem_public_key = _require_bytes(
            kem_public_key,
            "Client KEM public key"
        )

        kem_secret_key = _require_bytes(
            kem_secret_key,
            "Client KEM secret key"
        )

        _record_metric(
            metrics,
            "CLIENT_KEM_KEYPAIR_GENERATED",
            {
                "algorithm":
                    KEM_ALGORITHM,

                "public_key_size":
                    len(kem_public_key),

                "secret_key_size":
                    len(kem_secret_key),

                "time_ms":
                    round(
                        _elapsed_ms(
                            kem_start
                        ),
                        4
                    )
            }
        )

        logger.info(
            "[HANDSHAKE] Client "
            "ML-KEM-768 keypair generated"
        )

        # =====================================
        # STEP 2
        # GENERATE CLIENT ML-DSA KEYPAIR
        # =====================================

        dsa_start = (
            time.perf_counter()
        )

        (
            dsa_public_client,
            dsa_secret_client
        ) = dsa_keypair()

        dsa_public_client = _require_bytes(
            dsa_public_client,
            "Client DSA public key"
        )

        dsa_secret_client = _require_bytes(
            dsa_secret_client,
            "Client DSA secret key"
        )

        _record_metric(
            metrics,
            "CLIENT_DSA_KEYPAIR_GENERATED",
            {
                "algorithm":
                    DSA_ALGORITHM,

                "public_key_size":
                    len(dsa_public_client),

                "secret_key_size":
                    len(dsa_secret_client),

                "time_ms":
                    round(
                        _elapsed_ms(
                            dsa_start
                        ),
                        4
                    )
            }
        )

        logger.info(
            "[HANDSHAKE] Client "
            "ML-DSA-65 keypair generated"
        )

        # =====================================
        # STEP 3
        # GENERATE CLIENT NONCE
        # =====================================

        client_nonce = generate_nonce(
            NONCE_SIZE
        )

        _require_nonce(
            client_nonce,
            "client_nonce"
        )

        # =====================================
        # STEP 4
        # SEND CLIENT HELLO
        # =====================================

        hello_packet = build_hello(
            client_nonce,
            kem_public_key
        )

        send_packet(
            conn,
            hello_packet
        )

        transcript.add(
            "client",
            MSG_HELLO,
            client_nonce
            +
            kem_public_key
        )

        _record_metric(
            metrics,
            "CLIENT_HELLO_SENT",
            {
                "packet_size":
                    len(hello_packet),

                "nonce_size":
                    len(client_nonce),

                "kem_public_key_size":
                    len(kem_public_key)
            }
        )

        logger.info(
            "[HANDSHAKE] CLIENT_HELLO sent"
        )

        # =====================================
        # STEP 5
        # RECEIVE SERVER CIPHERTEXT
        # =====================================

        (
            ciphertext_packet,
            fields
        ) = _expect_message(
            conn,
            MSG_CIPHERTEXT
        )

        server_nonce = _require_nonce(
            fields["nonce"],
            "server_nonce"
        )

        ciphertext = _require_bytes(
            fields["ciphertext"],
            "ML-KEM ciphertext"
        )

        transcript.add(
            "server",
            MSG_CIPHERTEXT,
            server_nonce
            +
            ciphertext
        )

        _record_metric(
            metrics,
            "SERVER_CIPHERTEXT_RECEIVED",
            {
                "packet_size":
                    len(ciphertext_packet),

                "ciphertext_size":
                    len(ciphertext),

                "nonce_size":
                    len(server_nonce)
            }
        )

        logger.info(
            "[HANDSHAKE] Server KEM "
            "ciphertext received"
        )

        # =====================================
        # STEP 6
        # ML-KEM DECAPSULATION
        # =====================================

        decap_start = (
            time.perf_counter()
        )

        pq_shared_secret = decapsulate(
            ciphertext,
            kem_secret_key
        )

        pq_shared_secret = (
            _require_shared_secret(
                pq_shared_secret
            )
        )

        _record_metric(
            metrics,
            "ML_KEM_DECAPSULATION_COMPLETE",
            {
                "algorithm":
                    KEM_ALGORITHM,

                "shared_secret_size":
                    len(pq_shared_secret),

                "time_ms":
                    round(
                        _elapsed_ms(
                            decap_start
                        ),
                        4
                    )
            }
        )

        logger.info(
            "[HANDSHAKE] ML-KEM-768 "
            "decapsulation complete"
        )

        # =====================================
        # STEP 7
        # RECEIVE SERVER DSA PUBLIC KEY
        # =====================================

        (
            server_dsa_packet,
            fields
        ) = _expect_message(
            conn,
            MSG_DSA_PUBKEY
        )

        dsa_public_server = _require_bytes(
            fields["dsa_public_key"],
            "Server DSA public key"
        )

        transcript.add(
            "server",
            MSG_DSA_PUBKEY,
            dsa_public_server
        )

        _record_metric(
            metrics,
            "SERVER_DSA_PUBLIC_KEY_RECEIVED",
            {
                "packet_size":
                    len(server_dsa_packet),

                "public_key_size":
                    len(dsa_public_server)
            }
        )

        logger.info(
            "[HANDSHAKE] Server "
            "ML-DSA-65 public key received"
        )

        # =====================================
        # STEP 8
        # SEND CLIENT DSA PUBLIC KEY
        # =====================================

        client_dsa_packet = (
            build_dsa_pubkey(
                dsa_public_client
            )
        )

        send_packet(
            conn,
            client_dsa_packet
        )

        transcript.add(
            "client",
            MSG_DSA_PUBKEY,
            dsa_public_client
        )

        _record_metric(
            metrics,
            "CLIENT_DSA_PUBLIC_KEY_SENT",
            {
                "packet_size":
                    len(client_dsa_packet),

                "public_key_size":
                    len(dsa_public_client)
            }
        )

        logger.info(
            "[HANDSHAKE] Client "
            "ML-DSA-65 public key sent"
        )

        # =====================================
        # STEP 9
        # AUTHENTICATION TRANSCRIPT
        # =====================================

        auth_digest = (
            transcript.digest()
        )

        _record_metric(
            metrics,
            "AUTH_TRANSCRIPT_CREATED",
            {
                "digest_size":
                    len(auth_digest)
            }
        )

        # =====================================
        # STEP 10
        # RECEIVE SERVER SIGNATURE
        # =====================================

        (
            server_sig_packet,
            fields
        ) = _expect_message(
            conn,
            MSG_SIGNATURE
        )

        server_signature = _require_bytes(
            fields["signature"],
            "Server signature"
        )

        # =====================================
        # STEP 11
        # VERIFY SERVER SIGNATURE
        # =====================================

        verify_start = (
            time.perf_counter()
        )

        server_valid = verify_signature(
            auth_digest,
            server_signature,
            dsa_public_server
        )

        _record_metric(
            metrics,
            "SERVER_SIGNATURE_VERIFIED",
            {
                "valid":
                    bool(server_valid),

                "signature_size":
                    len(server_signature),

                "packet_size":
                    len(server_sig_packet),

                "time_ms":
                    round(
                        _elapsed_ms(
                            verify_start
                        ),
                        4
                    )
            }
        )

        if not server_valid:

            raise ValueError(
                "Server ML-DSA-65 "
                "signature verification failed"
            )

        logger.info(
            "[HANDSHAKE] Server "
            "ML-DSA-65 signature verified"
        )

        # =====================================
        # STEP 12
        # ADD SERVER SIGNATURE
        # =====================================

        transcript.add(
            "server",
            MSG_SIGNATURE,
            server_signature
        )

        # =====================================
        # STEP 13
        # CLIENT SIGNS AUTH DIGEST
        # =====================================

        sign_start = (
            time.perf_counter()
        )

        client_signature = sign_data(
            auth_digest,
            dsa_secret_client
        )

        client_signature = _require_bytes(
            client_signature,
            "Client signature"
        )

        client_sig_packet = (
            build_signature(
                client_signature
            )
        )

        send_packet(
            conn,
            client_sig_packet
        )

        transcript.add(
            "client",
            MSG_SIGNATURE,
            client_signature
        )

        _record_metric(
            metrics,
            "CLIENT_SIGNATURE_SENT",
            {
                "signature_size":
                    len(client_signature),

                "packet_size":
                    len(client_sig_packet),

                "time_ms":
                    round(
                        _elapsed_ms(
                            sign_start
                        ),
                        4
                    )
            }
        )

        logger.info(
            "[HANDSHAKE] Client "
            "ML-DSA-65 signature sent"
        )

        # =====================================
        # STEP 14
        # FINAL TRANSCRIPT DIGEST
        # =====================================

        final_digest = (
            transcript.digest()
        )

        _record_metric(
            metrics,
            "FINAL_TRANSCRIPT_CREATED",
            {
                "digest_size":
                    len(final_digest)
            }
        )

        # =====================================
        # STEP 15
        # CLIENT KEY CONFIRMATION
        # =====================================

        client_confirmation = (
            _derive_confirmation_tag(
                pq_shared_secret=
                    pq_shared_secret,

                auth_digest=
                    auth_digest,

                client_nonce=
                    client_nonce,

                server_nonce=
                    server_nonce,

                role=
                    "client"
            )
        )

        client_done_packet = (
            _build_done_confirmation(
                client_confirmation
            )
        )

        send_packet(
            conn,
            client_done_packet
        )

        _record_metric(
            metrics,
            "CLIENT_DONE_SENT",
            {
                "key_confirmation":
                    True,

                "confirmation_size":
                    len(client_confirmation)
            }
        )

        # =====================================
        # STEP 16
        # RECEIVE SERVER CONFIRMATION
        # =====================================

        (
            _,
            fields
        ) = _expect_message(
            conn,
            MSG_DONE
        )

        received_server_confirmation = (
            _extract_done_confirmation(
                fields
            )
        )

        expected_server_confirmation = (
            _derive_confirmation_tag(
                pq_shared_secret=
                    pq_shared_secret,

                auth_digest=
                    auth_digest,

                client_nonce=
                    client_nonce,

                server_nonce=
                    server_nonce,

                role=
                    "server"
            )
        )

        if not hmac.compare_digest(
            received_server_confirmation,
            expected_server_confirmation
        ):

            raise ValueError(
                "Server PQ key confirmation failed"
            )

        _record_metric(
            metrics,
            "SERVER_DONE_RECEIVED",
            {
                "key_confirmation":
                    True
            }
        )

        logger.info(
            "[HANDSHAKE] Server DONE "
            "and PQ key confirmation verified"
        )

        # =====================================
        # COMPLETE
        # =====================================

        handshake_time_ms = (
            _elapsed_ms(
                handshake_start
            )
        )

        _record_metric(
            metrics,
            "PQ_HANDSHAKE_COMPLETE",
            {
                "authenticated":
                    True,

                "time_ms":
                    round(
                        handshake_time_ms,
                        4
                    )
            }
        )

        MiddlewareLogger.log_stage(
            logger,
            "PQ_CLIENT_HANDSHAKE_COMPLETE"
        )

        return HandshakeResult(
            pq_shared_secret=
                pq_shared_secret,

            auth_transcript_digest=
                auth_digest,

            final_transcript_digest=
                final_digest,

            client_nonce=
                client_nonce,

            server_nonce=
                server_nonce,

            local_dsa_public_key=
                dsa_public_client,

            peer_dsa_public_key=
                dsa_public_server,

            authenticated=
                True,

            handshake_time_ms=
                handshake_time_ms
        )

    except Exception as exc:

        _record_metric(
            metrics,
            "PQ_CLIENT_HANDSHAKE_FAILED",
            {
                "error":
                    str(exc)
            }
        )

        _send_error(
            conn,
            str(exc)
        )

        logger.error(
            "[HANDSHAKE] Client handshake "
            f"failed: {exc}"
        )

        raise


# =====================================
# SERVER HANDSHAKE
# =====================================

def perform_server_handshake(
    conn,
    logger,
    metrics=None,
    server_dsa_keypair=None
):

    handshake_start = (
        time.perf_counter()
    )

    MiddlewareLogger.log_stage(
        logger,
        "PQ_SERVER_HANDSHAKE_START"
    )

    transcript = Transcript(
        label=TRANSCRIPT_LABEL
    )

    try:

        # =====================================
        # STEP 1
        # SERVER DSA KEYPAIR
        # =====================================

        if server_dsa_keypair is None:

            dsa_start = (
                time.perf_counter()
            )

            (
                dsa_public_server,
                dsa_secret_server
            ) = dsa_keypair()

            dsa_public_server = _require_bytes(
                dsa_public_server,
                "Server DSA public key"
            )

            dsa_secret_server = _require_bytes(
                dsa_secret_server,
                "Server DSA secret key"
            )

            _record_metric(
                metrics,
                "SERVER_DSA_KEYPAIR_GENERATED",
                {
                    "algorithm":
                        DSA_ALGORITHM,

                    "public_key_size":
                        len(
                            dsa_public_server
                        ),

                    "secret_key_size":
                        len(
                            dsa_secret_server
                        ),

                    "time_ms":
                        round(
                            _elapsed_ms(
                                dsa_start
                            ),
                            4
                        )
                }
            )

        else:

            if (
                not isinstance(
                    server_dsa_keypair,
                    tuple
                )
                or
                len(server_dsa_keypair) != 2
            ):

                raise ValueError(
                    "server_dsa_keypair must "
                    "be (public_key, secret_key)"
                )

            (
                dsa_public_server,
                dsa_secret_server
            ) = server_dsa_keypair

            dsa_public_server = _require_bytes(
                dsa_public_server,
                "Server DSA public key"
            )

            dsa_secret_server = _require_bytes(
                dsa_secret_server,
                "Server DSA secret key"
            )

            _record_metric(
                metrics,
                "SERVER_DSA_KEYPAIR_REUSED",
                {
                    "algorithm":
                        DSA_ALGORITHM,

                    "public_key_size":
                        len(
                            dsa_public_server
                        )
                }
            )

        logger.info(
            "[HANDSHAKE] Server "
            "ML-DSA-65 keypair ready"
        )

        # =====================================
        # STEP 2
        # RECEIVE CLIENT HELLO
        # =====================================

        (
            hello_packet,
            fields
        ) = _expect_message(
            conn,
            MSG_HELLO
        )

        client_nonce = _require_nonce(
            fields["nonce"],
            "client_nonce"
        )

        kem_public_client = _require_bytes(
            fields["kem_public_key"],
            "Client KEM public key"
        )

        transcript.add(
            "client",
            MSG_HELLO,
            client_nonce
            +
            kem_public_client
        )

        _record_metric(
            metrics,
            "CLIENT_HELLO_RECEIVED",
            {
                "packet_size":
                    len(hello_packet),

                "nonce_size":
                    len(client_nonce),

                "kem_public_key_size":
                    len(kem_public_client)
            }
        )

        logger.info(
            "[HANDSHAKE] CLIENT_HELLO received"
        )

        # =====================================
        # STEP 3
        # GENERATE SERVER NONCE
        # =====================================

        server_nonce = generate_nonce(
            NONCE_SIZE
        )

        _require_nonce(
            server_nonce,
            "server_nonce"
        )

        # =====================================
        # STEP 4
        # ML-KEM ENCAPSULATION
        # =====================================

        encaps_start = (
            time.perf_counter()
        )

        (
            ciphertext,
            pq_shared_secret
        ) = encapsulate(
            kem_public_client
        )

        ciphertext = _require_bytes(
            ciphertext,
            "ML-KEM ciphertext"
        )

        pq_shared_secret = (
            _require_shared_secret(
                pq_shared_secret
            )
        )

        _record_metric(
            metrics,
            "ML_KEM_ENCAPSULATION_COMPLETE",
            {
                "algorithm":
                    KEM_ALGORITHM,

                "ciphertext_size":
                    len(ciphertext),

                "shared_secret_size":
                    len(pq_shared_secret),

                "time_ms":
                    round(
                        _elapsed_ms(
                            encaps_start
                        ),
                        4
                    )
            }
        )

        logger.info(
            "[HANDSHAKE] ML-KEM-768 "
            "encapsulation complete"
        )

        # =====================================
        # STEP 5
        # SEND KEM CIPHERTEXT
        # =====================================

        ciphertext_packet = (
            build_ciphertext(
                server_nonce,
                ciphertext
            )
        )

        send_packet(
            conn,
            ciphertext_packet
        )

        transcript.add(
            "server",
            MSG_CIPHERTEXT,
            server_nonce
            +
            ciphertext
        )

        _record_metric(
            metrics,
            "SERVER_CIPHERTEXT_SENT",
            {
                "packet_size":
                    len(ciphertext_packet),

                "ciphertext_size":
                    len(ciphertext),

                "nonce_size":
                    len(server_nonce)
            }
        )

        logger.info(
            "[HANDSHAKE] Server KEM "
            "ciphertext sent"
        )

        # =====================================
        # STEP 6
        # SEND SERVER DSA PUBLIC KEY
        # =====================================

        server_dsa_packet = (
            build_dsa_pubkey(
                dsa_public_server
            )
        )

        send_packet(
            conn,
            server_dsa_packet
        )

        transcript.add(
            "server",
            MSG_DSA_PUBKEY,
            dsa_public_server
        )

        _record_metric(
            metrics,
            "SERVER_DSA_PUBLIC_KEY_SENT",
            {
                "packet_size":
                    len(server_dsa_packet),

                "public_key_size":
                    len(dsa_public_server)
            }
        )

        logger.info(
            "[HANDSHAKE] Server "
            "ML-DSA-65 public key sent"
        )

        # =====================================
        # STEP 7
        # RECEIVE CLIENT DSA PUBLIC KEY
        # =====================================

        (
            client_dsa_packet,
            fields
        ) = _expect_message(
            conn,
            MSG_DSA_PUBKEY
        )

        dsa_public_client = _require_bytes(
            fields["dsa_public_key"],
            "Client DSA public key"
        )

        transcript.add(
            "client",
            MSG_DSA_PUBKEY,
            dsa_public_client
        )

        _record_metric(
            metrics,
            "CLIENT_DSA_PUBLIC_KEY_RECEIVED",
            {
                "packet_size":
                    len(client_dsa_packet),

                "public_key_size":
                    len(dsa_public_client)
            }
        )

        logger.info(
            "[HANDSHAKE] Client "
            "ML-DSA-65 public key received"
        )

        # =====================================
        # STEP 8
        # AUTH TRANSCRIPT SNAPSHOT
        # =====================================

        auth_digest = (
            transcript.digest()
        )

        _record_metric(
            metrics,
            "AUTH_TRANSCRIPT_CREATED",
            {
                "digest_size":
                    len(auth_digest)
            }
        )

        # =====================================
        # STEP 9
        # SERVER SIGNS AUTH DIGEST
        # =====================================

        sign_start = (
            time.perf_counter()
        )

        server_signature = sign_data(
            auth_digest,
            dsa_secret_server
        )

        server_signature = _require_bytes(
            server_signature,
            "Server signature"
        )

        server_sig_packet = (
            build_signature(
                server_signature
            )
        )

        send_packet(
            conn,
            server_sig_packet
        )

        transcript.add(
            "server",
            MSG_SIGNATURE,
            server_signature
        )

        _record_metric(
            metrics,
            "SERVER_SIGNATURE_SENT",
            {
                "signature_size":
                    len(server_signature),

                "packet_size":
                    len(server_sig_packet),

                "time_ms":
                    round(
                        _elapsed_ms(
                            sign_start
                        ),
                        4
                    )
            }
        )

        logger.info(
            "[HANDSHAKE] Server "
            "ML-DSA-65 signature sent"
        )

        # =====================================
        # STEP 10
        # RECEIVE CLIENT SIGNATURE
        # =====================================

        (
            client_sig_packet,
            fields
        ) = _expect_message(
            conn,
            MSG_SIGNATURE
        )

        client_signature = _require_bytes(
            fields["signature"],
            "Client signature"
        )

        # =====================================
        # STEP 11
        # VERIFY CLIENT SIGNATURE
        # =====================================

        verify_start = (
            time.perf_counter()
        )

        client_valid = verify_signature(
            auth_digest,
            client_signature,
            dsa_public_client
        )

        _record_metric(
            metrics,
            "CLIENT_SIGNATURE_VERIFIED",
            {
                "valid":
                    bool(client_valid),

                "signature_size":
                    len(client_signature),

                "packet_size":
                    len(client_sig_packet),

                "time_ms":
                    round(
                        _elapsed_ms(
                            verify_start
                        ),
                        4
                    )
            }
        )

        if not client_valid:

            raise ValueError(
                "Client ML-DSA-65 "
                "signature verification failed"
            )

        logger.info(
            "[HANDSHAKE] Client "
            "ML-DSA-65 signature verified"
        )

        # =====================================
        # STEP 12
        # ADD CLIENT SIGNATURE
        # =====================================

        transcript.add(
            "client",
            MSG_SIGNATURE,
            client_signature
        )

        # =====================================
        # STEP 13
        # FINAL TRANSCRIPT DIGEST
        # =====================================

        final_digest = (
            transcript.digest()
        )

        _record_metric(
            metrics,
            "FINAL_TRANSCRIPT_CREATED",
            {
                "digest_size":
                    len(final_digest)
            }
        )

        # =====================================
        # STEP 14
        # RECEIVE CLIENT KEY CONFIRMATION
        # =====================================

        (
            _,
            fields
        ) = _expect_message(
            conn,
            MSG_DONE
        )

        received_client_confirmation = (
            _extract_done_confirmation(
                fields
            )
        )

        expected_client_confirmation = (
            _derive_confirmation_tag(
                pq_shared_secret=
                    pq_shared_secret,

                auth_digest=
                    auth_digest,

                client_nonce=
                    client_nonce,

                server_nonce=
                    server_nonce,

                role=
                    "client"
            )
        )

        if not hmac.compare_digest(
            received_client_confirmation,
            expected_client_confirmation
        ):

            raise ValueError(
                "Client PQ key confirmation failed"
            )

        _record_metric(
            metrics,
            "CLIENT_DONE_RECEIVED",
            {
                "key_confirmation":
                    True
            }
        )

        # =====================================
        # STEP 15
        # SEND SERVER KEY CONFIRMATION
        # =====================================

        server_confirmation = (
            _derive_confirmation_tag(
                pq_shared_secret=
                    pq_shared_secret,

                auth_digest=
                    auth_digest,

                client_nonce=
                    client_nonce,

                server_nonce=
                    server_nonce,

                role=
                    "server"
            )
        )

        server_done_packet = (
            _build_done_confirmation(
                server_confirmation
            )
        )

        send_packet(
            conn,
            server_done_packet
        )

        _record_metric(
            metrics,
            "SERVER_DONE_SENT",
            {
                "key_confirmation":
                    True,

                "confirmation_size":
                    len(server_confirmation)
            }
        )

        logger.info(
            "[HANDSHAKE] Server DONE "
            "with PQ key confirmation sent"
        )

        # =====================================
        # COMPLETE
        # =====================================

        handshake_time_ms = (
            _elapsed_ms(
                handshake_start
            )
        )

        _record_metric(
            metrics,
            "PQ_HANDSHAKE_COMPLETE",
            {
                "authenticated":
                    True,

                "time_ms":
                    round(
                        handshake_time_ms,
                        4
                    )
            }
        )

        MiddlewareLogger.log_stage(
            logger,
            "PQ_SERVER_HANDSHAKE_COMPLETE"
        )

        return HandshakeResult(
            pq_shared_secret=
                pq_shared_secret,

            auth_transcript_digest=
                auth_digest,

            final_transcript_digest=
                final_digest,

            client_nonce=
                client_nonce,

            server_nonce=
                server_nonce,

            local_dsa_public_key=
                dsa_public_server,

            peer_dsa_public_key=
                dsa_public_client,

            authenticated=
                True,

            handshake_time_ms=
                handshake_time_ms
        )

    except Exception as exc:

        _record_metric(
            metrics,
            "PQ_SERVER_HANDSHAKE_FAILED",
            {
                "error":
                    str(exc)
            }
        )

        _send_error(
            conn,
            str(exc)
        )

        logger.error(
            "[HANDSHAKE] Server handshake "
            f"failed: {exc}"
        )

        raise