import hashlib


class TLSSession:

    def __init__(
        self,
        tls_socket
    ):

        self.tls_socket = (
            tls_socket
        )


    def get_tls_metadata(
        self
    ):

        return {
            "version":
                self.tls_socket.version(),

            "cipher":
                self.tls_socket.cipher(),

            "session_reused":
                self.tls_socket.session_reused
        }


    def export_tls_secret(
        self
    ) -> bytes:
        """
        Prototype TLS contribution.

        IMPORTANT:
        This is not a real TLS exporter.
        It derives a deterministic contribution
        from negotiated TLS metadata.
        """

        version = (
            self.tls_socket.version()
            or
            ""
        )

        cipher = (
            self.tls_socket.cipher()
            or
            ()
        )

        session_reused = (
            self.tls_socket.session_reused
        )

        session_data = (
            str(version)
            +
            "|"
            +
            str(cipher)
            +
            "|"
            +
            str(session_reused)
        ).encode(
            "utf-8"
        )

        return hashlib.sha256(
            session_data
        ).digest()