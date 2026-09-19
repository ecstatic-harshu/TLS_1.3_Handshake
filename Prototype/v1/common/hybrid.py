from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import (
    hashes
)


class HybridKeyDerivation:

    # =====================================
    # CONFIGURATION
    # =====================================

    OUTPUT_KEY_SIZE = 32

    HKDF_INFO = (
        b"QSCP_HYBRID_KEY_V1"
    )

    # =====================================
    # INTERNAL VALIDATION
    # =====================================

    @staticmethod
    def _require_bytes(
        value,
        field_name,
        minimum_size=1
    ):

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

    # =====================================
    # HYBRID KEY DERIVATION
    # =====================================

    def derive(
        self,
        pq_secret: bytes,
        tls_secret: bytes,
        transcript_digest: bytes,
        client_nonce: bytes,
        server_nonce: bytes
    ) -> bytes:
        """
        Derive the 32-byte hybrid master key.

        Inputs:

            pq_secret
                ML-KEM-768 shared secret

            tls_secret
                TLS contribution or TLS
                context-binding value

            transcript_digest
                Final authenticated handshake
                transcript digest

            client_nonce
                32-byte client nonce

            server_nonce
                32-byte server nonce

        Output:

            32-byte hybrid master key
        """

        # =====================================
        # VALIDATE INPUTS
        # =====================================

        pq_secret = self._require_bytes(
            pq_secret,
            "pq_secret",
            minimum_size=16
        )

        tls_secret = self._require_bytes(
            tls_secret,
            "tls_secret",
            minimum_size=16
        )

        transcript_digest = (
            self._require_bytes(
                transcript_digest,
                "transcript_digest",
                minimum_size=32
            )
        )

        client_nonce = self._require_bytes(
            client_nonce,
            "client_nonce",
            minimum_size=32
        )

        server_nonce = self._require_bytes(
            server_nonce,
            "server_nonce",
            minimum_size=32
        )

        # =====================================
        # REQUIRE EXACT SHA-256 DIGEST SIZE
        # =====================================

        if len(
            transcript_digest
        ) != 32:

            raise ValueError(
                "transcript_digest must be "
                "exactly 32 bytes"
            )

        # =====================================
        # REQUIRE EXACT NONCE SIZES
        # =====================================

        if len(
            client_nonce
        ) != 32:

            raise ValueError(
                "client_nonce must be "
                "exactly 32 bytes"
            )

        if len(
            server_nonce
        ) != 32:

            raise ValueError(
                "server_nonce must be "
                "exactly 32 bytes"
            )

        # =====================================
        # BUILD HKDF INPUT KEY MATERIAL
        # =====================================
        #
        # IKM:
        #
        #   domain separation
        #       ||
        #   ML-KEM shared secret
        #       ||
        #   TLS contribution
        #
        # =====================================

        input_key_material = (
            b"QSCP-HYBRID-IKM-V1"
            +
            pq_secret
            +
            tls_secret
        )

        # =====================================
        # BUILD CONTEXT
        # =====================================
        #
        # Context binds the derived key to:
        #
        #   - authenticated transcript
        #   - client freshness
        #   - server freshness
        #
        # =====================================

        context = (
            b"QSCP-HYBRID-CONTEXT-V1"
            +
            transcript_digest
            +
            client_nonce
            +
            server_nonce
        )

        # =====================================
        # DERIVE CONTEXT-BOUND SALT
        # =====================================
        #
        # The salt is deterministic but unique
        # to this authenticated handshake.
        #
        # Both peers calculate exactly the same
        # value.
        #
        # =====================================

        digest = hashes.Hash(
            hashes.SHA256()
        )

        digest.update(
            context
        )

        hkdf_salt = (
            digest.finalize()
        )

        # =====================================
        # BUILD HKDF INFO
        # =====================================

        hkdf_info = (
            self.HKDF_INFO
            +
            b"|"
            +
            transcript_digest
        )

        # =====================================
        # HKDF-SHA256
        # =====================================

        hkdf = HKDF(
            algorithm=
                hashes.SHA256(),

            length=
                self.OUTPUT_KEY_SIZE,

            salt=
                hkdf_salt,

            info=
                hkdf_info
        )

        # =====================================
        # DERIVE HYBRID MASTER KEY
        # =====================================

        hybrid_key = hkdf.derive(
            input_key_material
        )

        # =====================================
        # DEFENSIVE OUTPUT VALIDATION
        # =====================================

        if len(
            hybrid_key
        ) != self.OUTPUT_KEY_SIZE:

            raise ValueError(
                "Invalid hybrid key size"
            )

        return hybrid_key