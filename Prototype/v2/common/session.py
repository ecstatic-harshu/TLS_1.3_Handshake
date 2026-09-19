import time
import threading

from common.serializer import (
    encode,
    decode,
    MSG_SECURE_MESSAGE
)

from common.transport import (
    send_packet,
    recv_packet
)


# =====================================
# CONSTANTS
# =====================================

NONCE_SIZE = 12

SEQUENCE_SIZE = 8

GCM_TAG_SIZE = 16

MAX_SEQUENCE = (
    2 ** (SEQUENCE_SIZE * 8)
) - 1


class SecureSession:
    """
    Secure application session layered over
    the authenticated hybrid secure channel.

    Security properties:

        - Direction-separated AES-256-GCM
        - Monotonic directional sequences
        - Deterministic unique GCM nonces
        - Replay protection
        - Strict ordering enforcement
        - Nonce validation
        - Sequence authentication using AAD
        - Thread-safe send path
        - Thread-safe receive path

    Expected SecureChannel API:

        encrypt(
            plaintext: bytes,
            nonce: bytes,
            aad: bytes = None
        ) -> bytes

        decrypt(
            nonce: bytes,
            ciphertext: bytes,
            aad: bytes = None
        ) -> bytes
    """


    # =====================================
    # INITIALIZATION
    # =====================================

    def __init__(
        self,
        pq_secret=None,
        tls_secret=None,
        hybrid_key=None,
        transcript_hash=None,
        secure_channel=None,
        metrics=None,
        role=None
    ):

        # =====================================
        # CRYPTOGRAPHIC SESSION MATERIAL
        # =====================================

        self.pq_secret = (
            pq_secret
        )

        self.tls_secret = (
            tls_secret
        )

        self.hybrid_key = (
            hybrid_key
        )

        self.transcript_hash = (
            transcript_hash
        )

        self.secure_channel = (
            secure_channel
        )

        self.metrics = (
            metrics
        )

        # =====================================
        # SESSION ROLE
        # =====================================

        if role not in (
            "client",
            "server"
        ):

            raise ValueError(
                "role must be "
                "'client' or 'server'"
            )

        self.role = role

        # =====================================
        # SESSION STATE
        # =====================================

        self.is_authenticated = False

        self.is_established = False

        self.socket = None

        # =====================================
        # DIRECTIONAL SEQUENCE NUMBERS
        # =====================================
        #
        # Local outbound traffic:
        #
        #     send_sequence
        #
        # Remote inbound traffic:
        #
        #     receive_sequence
        #
        # Both begin at zero.
        #
        # =====================================

        self.send_sequence = 0

        self.receive_sequence = 0

        # =====================================
        # THREAD SAFETY
        # =====================================

        self._send_lock = (
            threading.Lock()
        )

        self._receive_lock = (
            threading.Lock()
        )


    # =====================================
    # STATE MANAGEMENT
    # =====================================

    def mark_authenticated(
        self
    ):

        self.is_authenticated = True


    def mark_established(
        self
    ):

        if not self.is_authenticated:

            raise ValueError(
                "Cannot establish session "
                "before authentication"
            )

        if self.secure_channel is None:

            raise ValueError(
                "Cannot establish session "
                "without SecureChannel"
            )

        self.is_established = True


    # =====================================
    # INTERNAL SESSION VALIDATION
    # =====================================

    def _require_established(
        self
    ):

        if not self.is_authenticated:

            raise ValueError(
                "Session not authenticated"
            )

        if not self.is_established:

            raise ValueError(
                "Session not established"
            )

        if self.socket is None:

            raise ValueError(
                "Session socket not attached"
            )

        if self.secure_channel is None:

            raise ValueError(
                "SecureChannel not configured"
            )


    # =====================================
    # SEQUENCE -> BYTES
    # =====================================

    def _sequence_to_bytes(
        self,
        sequence
    ):

        if not isinstance(
            sequence,
            int
        ):

            raise TypeError(
                "sequence must be int"
            )

        if not (
            0 <= sequence <= MAX_SEQUENCE
        ):

            raise ValueError(
                "sequence out of range"
            )

        return sequence.to_bytes(
            SEQUENCE_SIZE,
            byteorder="big",
            signed=False
        )


    # =====================================
    # BYTES -> SEQUENCE
    # =====================================

    def _bytes_to_sequence(
        self,
        data
    ):

        if not isinstance(
            data,
            bytes
        ):

            raise TypeError(
                "sequence data must be bytes"
            )

        if len(data) != SEQUENCE_SIZE:

            raise ValueError(
                "Invalid sequence size"
            )

        return int.from_bytes(
            data,
            byteorder="big",
            signed=False
        )


    # =====================================
    # LOCAL OUTBOUND NONCE
    # =====================================

    def _build_nonce(
        self,
        sequence
    ):
        """
        Build deterministic 96-bit AES-GCM
        nonce for local outbound traffic.

        Format:

            4-byte direction prefix
            +
            8-byte sequence number

        Client outbound:

            b"CLNT" || sequence

        Server outbound:

            b"SRVR" || sequence

        Total:

            4 + 8 = 12 bytes
        """

        sequence_bytes = (
            self._sequence_to_bytes(
                sequence
            )
        )

        if self.role == "client":

            prefix = b"CLNT"

        else:

            prefix = b"SRVR"

        nonce = (
            prefix
            +
            sequence_bytes
        )

        if len(nonce) != NONCE_SIZE:

            raise ValueError(
                "Generated nonce must "
                "be exactly 12 bytes"
            )

        return nonce


    # =====================================
    # EXPECTED REMOTE NONCE
    # =====================================

    def _build_remote_nonce(
        self,
        sequence
    ):
        """
        Build the nonce expected from the
        remote peer.

        Local client receives:

            server nonce
            b"SRVR" || sequence

        Local server receives:

            client nonce
            b"CLNT" || sequence
        """

        sequence_bytes = (
            self._sequence_to_bytes(
                sequence
            )
        )

        if self.role == "client":

            prefix = b"SRVR"

        else:

            prefix = b"CLNT"

        nonce = (
            prefix
            +
            sequence_bytes
        )

        if len(nonce) != NONCE_SIZE:

            raise ValueError(
                "Generated remote nonce "
                "must be exactly 12 bytes"
            )

        return nonce


    # =====================================
    # BUILD AUTHENTICATED AAD
    # =====================================

    def _build_aad(
        self,
        sequence
    ):
        """
        Build AES-GCM Additional
        Authenticated Data.

        The sequence number remains visible
        on the wire but is authenticated by
        AES-GCM.

        Any sequence modification causes
        authentication failure.
        """

        sequence_bytes = (
            self._sequence_to_bytes(
                sequence
            )
        )

        return (
            b"QSCP-v1|SECURE_MESSAGE|"
            +
            sequence_bytes
        )


    # =====================================
    # METRICS HELPER
    # =====================================

    def _record_metric(
        self,
        label,
        metadata=None
    ):

        if self.metrics is None:

            return

        self.metrics.record(
            label,
            metadata or {}
        )


    # =====================================
    # SECURE SEND
    # =====================================

    def send_secure(
        self,
        plaintext: bytes
    ):

        # =====================================
        # VERIFY SESSION
        # =====================================

        self._require_established()

        # =====================================
        # VERIFY PLAINTEXT
        # =====================================

        if not isinstance(
            plaintext,
            bytes
        ):

            raise TypeError(
                "plaintext must be bytes"
            )

        # =====================================
        # SERIALIZE SEND OPERATIONS
        # =====================================

        with self._send_lock:

            # =====================================
            # CHECK SEQUENCE EXHAUSTION
            # =====================================

            if (
                self.send_sequence
                >
                MAX_SEQUENCE
            ):

                raise OverflowError(
                    "Send sequence exhausted"
                )

            sequence = (
                self.send_sequence
            )

            # =====================================
            # SERIALIZE SEQUENCE
            # =====================================

            sequence_bytes = (
                self._sequence_to_bytes(
                    sequence
                )
            )

            # =====================================
            # BUILD UNIQUE NONCE
            # =====================================

            nonce = (
                self._build_nonce(
                    sequence
                )
            )

            # =====================================
            # BUILD AAD
            # =====================================

            aad = (
                self._build_aad(
                    sequence
                )
            )

            # =====================================
            # ENCRYPT
            # =====================================

            encrypt_start = (
                time.perf_counter()
            )

            ciphertext = (
                self.secure_channel.encrypt(
                    plaintext=plaintext,
                    nonce=nonce,
                    aad=aad
                )
            )

            encryption_time_ms = (
                time.perf_counter()
                -
                encrypt_start
            ) * 1000

            # =====================================
            # VERIFY CIPHERTEXT
            # =====================================

            if not isinstance(
                ciphertext,
                bytes
            ):

                raise TypeError(
                    "SecureChannel.encrypt() "
                    "must return bytes"
                )

            if len(ciphertext) < GCM_TAG_SIZE:

                raise ValueError(
                    "Encrypted ciphertext "
                    "is too short"
                )

            # =====================================
            # APPLICATION PAYLOAD FORMAT
            # =====================================
            #
            # +-----------------------------+
            # | Sequence       8 bytes      |
            # +-----------------------------+
            # | Nonce         12 bytes      |
            # +-----------------------------+
            # | Ciphertext + GCM Tag        |
            # +-----------------------------+
            #
            # =====================================

            payload = (
                sequence_bytes
                +
                nonce
                +
                ciphertext
            )

            # =====================================
            # SERIALIZE MESSAGE
            # =====================================

            packet = (
                encode(
                    MSG_SECURE_MESSAGE,
                    payload
                )
            )

            packet_size = (
                len(packet)
            )

            # =====================================
            # SEND THROUGH TLS SOCKET
            # =====================================

            send_packet(
                self.socket,
                packet
            )

            # =====================================
            # ADVANCE ONLY AFTER SEND SUCCESS
            # =====================================

            self.send_sequence += 1

            # =====================================
            # RECORD METRICS
            # =====================================

            self._record_metric(
                "SECURE_MESSAGE_SENT",
                {
                    "role":
                        self.role,

                    "sequence":
                        sequence,

                    "packet_size":
                        packet_size,

                    "plaintext_size":
                        len(plaintext),

                    "ciphertext_size":
                        len(ciphertext),

                    "nonce_size":
                        len(nonce),

                    "aad_size":
                        len(aad),

                    "encryption_time_ms":
                        round(
                            encryption_time_ms,
                            4
                        )
                }
            )

            # =====================================
            # DISPLAY
            # =====================================

            print(
                "[SESSION] Secure message sent "
                f"(seq={sequence})"
            )


    # =====================================
    # SECURE RECEIVE
    # =====================================

    def receive_secure(
        self
    ):

        # =====================================
        # VERIFY SESSION
        # =====================================

        self._require_established()

        # =====================================
        # SERIALIZE RECEIVE OPERATIONS
        # =====================================

        with self._receive_lock:

            # =====================================
            # RECEIVE FRAMED PACKET
            # =====================================

            packet = (
                recv_packet(
                    self.socket
                )
            )

            packet_size = (
                len(packet)
            )

            # =====================================
            # DESERIALIZE MESSAGE
            # =====================================

            msg_type, payload = (
                decode(
                    packet
                )
            )

            # =====================================
            # VERIFY MESSAGE TYPE
            # =====================================

            if (
                msg_type
                !=
                MSG_SECURE_MESSAGE
            ):

                self._record_metric(
                    "INVALID_MESSAGE_TYPE",
                    {
                        "role":
                            self.role,

                        "received_type":
                            msg_type,

                        "expected_type":
                            MSG_SECURE_MESSAGE
                    }
                )

                raise ValueError(
                    "Invalid secure message type"
                )

            # =====================================
            # MINIMUM PAYLOAD SIZE
            # =====================================
            #
            # Sequence:
            #     8 bytes
            #
            # Nonce:
            #     12 bytes
            #
            # Minimum GCM tag:
            #     16 bytes
            #
            # Total minimum:
            #     36 bytes
            #
            # =====================================

            minimum_size = (
                SEQUENCE_SIZE
                +
                NONCE_SIZE
                +
                GCM_TAG_SIZE
            )

            if len(payload) < minimum_size:

                self._record_metric(
                    "INVALID_SECURE_PAYLOAD",
                    {
                        "role":
                            self.role,

                        "payload_size":
                            len(payload),

                        "minimum_size":
                            minimum_size
                    }
                )

                raise ValueError(
                    "Secure message payload "
                    "too short"
                )

            # =====================================
            # EXTRACT SEQUENCE BYTES
            # =====================================

            sequence_bytes = (
                payload[
                    :SEQUENCE_SIZE
                ]
            )

            # =====================================
            # PARSE SEQUENCE
            # =====================================

            sequence = (
                self._bytes_to_sequence(
                    sequence_bytes
                )
            )

            # =====================================
            # EXTRACT NONCE
            # =====================================

            nonce_start = (
                SEQUENCE_SIZE
            )

            nonce_end = (
                nonce_start
                +
                NONCE_SIZE
            )

            nonce = (
                payload[
                    nonce_start:
                    nonce_end
                ]
            )

            # =====================================
            # EXTRACT CIPHERTEXT
            # =====================================

            ciphertext = (
                payload[
                    nonce_end:
                ]
            )

            # =====================================
            # VERIFY CIPHERTEXT SIZE
            # =====================================

            if len(ciphertext) < GCM_TAG_SIZE:

                self._record_metric(
                    "INVALID_CIPHERTEXT",
                    {
                        "role":
                            self.role,

                        "sequence":
                            sequence,

                        "ciphertext_size":
                            len(ciphertext)
                    }
                )

                raise ValueError(
                    "Ciphertext too short"
                )

            # =====================================
            # EXPECTED SEQUENCE
            # =====================================

            expected_sequence = (
                self.receive_sequence
            )

            # =====================================
            # REPLAY DETECTION
            # =====================================

            if (
                sequence
                <
                expected_sequence
            ):

                self._record_metric(
                    "REPLAY_ATTACK_DETECTED",
                    {
                        "role":
                            self.role,

                        "received_sequence":
                            sequence,

                        "expected_sequence":
                            expected_sequence
                    }
                )

                raise ValueError(
                    "Replay attack detected: "
                    f"received sequence "
                    f"{sequence}, expected "
                    f"{expected_sequence}"
                )

            # =====================================
            # OUT-OF-ORDER DETECTION
            # =====================================

            if (
                sequence
                >
                expected_sequence
            ):

                self._record_metric(
                    "OUT_OF_ORDER_MESSAGE_DETECTED",
                    {
                        "role":
                            self.role,

                        "received_sequence":
                            sequence,

                        "expected_sequence":
                            expected_sequence
                    }
                )

                raise ValueError(
                    "Out-of-order secure message: "
                    f"received sequence "
                    f"{sequence}, expected "
                    f"{expected_sequence}"
                )

            # =====================================
            # BUILD EXPECTED REMOTE NONCE
            # =====================================

            expected_nonce = (
                self._build_remote_nonce(
                    sequence
                )
            )

            # =====================================
            # VERIFY NONCE
            # =====================================

            if nonce != expected_nonce:

                self._record_metric(
                    "INVALID_NONCE_DETECTED",
                    {
                        "role":
                            self.role,

                        "sequence":
                            sequence,

                        "nonce_size":
                            len(nonce)
                    }
                )

                raise ValueError(
                    "Invalid secure message nonce"
                )

            # =====================================
            # REBUILD IDENTICAL AAD
            # =====================================

            aad = (
                self._build_aad(
                    sequence
                )
            )

            # =====================================
            # DECRYPT
            # =====================================

            decrypt_start = (
                time.perf_counter()
            )

            try:

                plaintext = (
                    self.secure_channel.decrypt(
                        nonce=nonce,
                        ciphertext=ciphertext,
                        aad=aad
                    )
                )

            except Exception as exc:

                self._record_metric(
                    "SECURE_MESSAGE_AUTH_FAILED",
                    {
                        "role":
                            self.role,

                        "sequence":
                            sequence,

                        "ciphertext_size":
                            len(ciphertext)
                    }
                )

                raise ValueError(
                    "Secure message authentication "
                    "failed"
                ) from exc

            decryption_time_ms = (
                time.perf_counter()
                -
                decrypt_start
            ) * 1000

            # =====================================
            # VERIFY PLAINTEXT
            # =====================================

            if not isinstance(
                plaintext,
                bytes
            ):

                raise TypeError(
                    "SecureChannel.decrypt() "
                    "must return bytes"
                )

            # =====================================
            # ADVANCE ONLY AFTER SUCCESSFUL
            # AUTHENTICATED DECRYPTION
            # =====================================

            self.receive_sequence += 1

            # =====================================
            # RECORD METRICS
            # =====================================

            self._record_metric(
                "SECURE_MESSAGE_RECEIVED",
                {
                    "role":
                        self.role,

                    "sequence":
                        sequence,

                    "packet_size":
                        packet_size,

                    "plaintext_size":
                        len(plaintext),

                    "ciphertext_size":
                        len(ciphertext),

                    "nonce_size":
                        len(nonce),

                    "aad_size":
                        len(aad),

                    "decryption_time_ms":
                        round(
                            decryption_time_ms,
                            4
                        )
                }
            )

            # =====================================
            # DISPLAY
            # =====================================

            print(
                "[SESSION] Secure message received "
                f"(seq={sequence})"
            )

            return plaintext


    # =====================================
    # SESSION SUMMARY
    # =====================================

    def summary(
        self
    ):

        transcript = (
            self.transcript_hash
        )

        if isinstance(
            transcript,
            bytes
        ):

            transcript = (
                transcript.hex()
            )

        return {
            "authenticated":
                self.is_authenticated,

            "established":
                self.is_established,

            "role":
                self.role,

            "transcript_hash":
                transcript,

            "send_sequence":
                self.send_sequence,

            "receive_sequence":
                self.receive_sequence
        }