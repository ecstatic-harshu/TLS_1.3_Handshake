from cryptography.hazmat.primitives import (
    hashes
)

from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM
)

from cryptography.hazmat.primitives.kdf.hkdf import (
    HKDFExpand
)


class SecureChannel:
    """
    Direction-separated AES-256-GCM channel.

    A single handshake-bound master key
    produces:

        client -> server key
        server -> client key

    The local role determines which key
    is used for sending and receiving.
    """

    MASTER_KEY_SIZE = 32

    TRAFFIC_KEY_SIZE = 32

    NONCE_SIZE = 12

    CLIENT_TO_SERVER_LABEL = (
        b"QSCP-v1|traffic|client-to-server"
    )

    SERVER_TO_CLIENT_LABEL = (
        b"QSCP-v1|traffic|server-to-client"
    )


    # =====================================
    # INITIALIZATION
    # =====================================

    def __init__(
        self,
        master_key: bytes,
        role: str
    ):

        self._validate_key(
            master_key
        )

        self._validate_role(
            role
        )

        self.role = role

        # =====================================
        # DERIVE DIRECTIONAL KEYS
        # =====================================

        client_to_server_key = (
            self._derive_traffic_key(
                master_key,
                self.CLIENT_TO_SERVER_LABEL
            )
        )

        server_to_client_key = (
            self._derive_traffic_key(
                master_key,
                self.SERVER_TO_CLIENT_LABEL
            )
        )

        # =====================================
        # ASSIGN LOCAL SEND/RECEIVE KEYS
        # =====================================

        if role == "client":

            self.send_key = (
                client_to_server_key
            )

            self.receive_key = (
                server_to_client_key
            )

        else:

            self.send_key = (
                server_to_client_key
            )

            self.receive_key = (
                client_to_server_key
            )

        # =====================================
        # CREATE AES-GCM INSTANCES
        # =====================================

        self._send_aesgcm = AESGCM(
            self.send_key
        )

        self._receive_aesgcm = AESGCM(
            self.receive_key
        )


    # =====================================
    # VALIDATION
    # =====================================

    @classmethod
    def _validate_key(
        cls,
        key: bytes
    ) -> None:

        if not isinstance(
            key,
            bytes
        ):
            raise TypeError(
                "master_key must be bytes"
            )

        if len(key) != cls.MASTER_KEY_SIZE:
            raise ValueError(
                "master_key must be exactly "
                "32 bytes"
            )


    @staticmethod
    def _validate_role(
        role: str
    ) -> None:

        if role not in (
            "client",
            "server"
        ):
            raise ValueError(
                "role must be 'client' "
                "or 'server'"
            )


    @staticmethod
    def _validate_plaintext(
        plaintext: bytes
    ) -> None:

        if not isinstance(
            plaintext,
            bytes
        ):
            raise TypeError(
                "plaintext must be bytes"
            )


    @classmethod
    def _validate_nonce(
        cls,
        nonce: bytes
    ) -> None:

        if not isinstance(
            nonce,
            bytes
        ):
            raise TypeError(
                "nonce must be bytes"
            )

        if len(nonce) != cls.NONCE_SIZE:
            raise ValueError(
                "AES-GCM nonce must be "
                "exactly 12 bytes"
            )


    @staticmethod
    def _validate_ciphertext(
        ciphertext: bytes
    ) -> None:

        if not isinstance(
            ciphertext,
            bytes
        ):
            raise TypeError(
                "ciphertext must be bytes"
            )

        # AES-GCM ciphertext includes
        # a 16-byte authentication tag.
        if len(ciphertext) < 16:
            raise ValueError(
                "ciphertext is too short"
            )


    @staticmethod
    def _validate_aad(
        aad
    ) -> None:

        if (
            aad is not None
            and
            not isinstance(
                aad,
                bytes
            )
        ):
            raise TypeError(
                "aad must be bytes or None"
            )


    # =====================================
    # TRAFFIC KEY DERIVATION
    # =====================================

    @classmethod
    def _derive_traffic_key(
        cls,
        master_key: bytes,
        label: bytes
    ) -> bytes:
        """
        Expand the handshake-bound master
        key into one directional 256-bit
        AES traffic key.
        """

        hkdf = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=cls.TRAFFIC_KEY_SIZE,
            info=label
        )

        return hkdf.derive(
            master_key
        )


    # =====================================
    # ENCRYPT
    # =====================================

    def encrypt(
        self,
        plaintext: bytes,
        nonce: bytes,
        aad: bytes = None
    ):
        """
        Encrypt using the local send key.

        Nonce is supplied by session.py,
        which should generate it from a
        monotonic sequence number.
        """

        self._validate_plaintext(
            plaintext
        )

        self._validate_nonce(
            nonce
        )

        self._validate_aad(
            aad
        )

        try:

            ciphertext = (
                self._send_aesgcm.encrypt(
                    nonce,
                    plaintext,
                    aad
                )
            )

            return ciphertext

        except Exception as exc:

            raise ValueError(
                "AES-GCM encryption failed"
            ) from exc


    # =====================================
    # DECRYPT
    # =====================================

    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        aad: bytes = None
    ):
        """
        Decrypt using the local receive key.
        """

        self._validate_nonce(
            nonce
        )

        self._validate_ciphertext(
            ciphertext
        )

        self._validate_aad(
            aad
        )

        try:

            plaintext = (
                self._receive_aesgcm.decrypt(
                    nonce,
                    ciphertext,
                    aad
                )
            )

            return plaintext

        except Exception as exc:

            raise ValueError(
                "AES-GCM authentication failed"
            ) from exc


    # =====================================
    # METADATA
    # =====================================

    def metadata(self):

        return {
            "cipher":
                "AES-256-GCM",

            "role":
                self.role,

            "direction_separated":
                True,

            "traffic_key_size":
                self.TRAFFIC_KEY_SIZE,

            "nonce_size":
                self.NONCE_SIZE
        }