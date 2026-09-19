import hashlib
import os
import struct
import threading


class Transcript:
    """
    Cryptographic handshake transcript.

    Every entry binds:

        - sender role
        - message type
        - payload length
        - payload bytes

    Both client and server must add the
    same logical messages in the same order.
    """

    DEFAULT_LABEL = (
        b"QSCP-PQ-HANDSHAKE-v1"
    )


    # =====================================
    # INITIALIZATION
    # =====================================

    def __init__(
        self,
        label=None
    ):

        if label is None:

            label = (
                self.DEFAULT_LABEL
            )

        elif isinstance(
            label,
            str
        ):

            label = label.encode(
                "utf-8"
            )

        if not isinstance(
            label,
            bytes
        ):

            raise TypeError(
                "Transcript label must be "
                "bytes or string"
            )

        if len(label) == 0:

            raise ValueError(
                "Transcript label cannot "
                "be empty"
            )

        self._lock = (
            threading.RLock()
        )

        self._hash = (
            hashlib.sha256()
        )

        self.entries = []

        # =====================================
        # DOMAIN SEPARATION
        # =====================================

        self._hash.update(
            struct.pack(
                ">I",
                len(label)
            )
        )

        self._hash.update(
            label
        )


    # =====================================
    # ADD TRANSCRIPT ENTRY
    # =====================================

    def add(
        self,
        role: str,
        msg_type: int,
        data: bytes
    ) -> None:
        """
        Add one logical handshake message.

        Encoding:

            role length
            role bytes
            message type
            payload length
            payload bytes
        """

        # =====================================
        # VALIDATE ROLE
        # =====================================

        if role not in (
            "client",
            "server"
        ):

            raise ValueError(
                "role must be 'client' "
                "or 'server'"
            )

        # =====================================
        # VALIDATE MESSAGE TYPE
        # =====================================

        if not isinstance(
            msg_type,
            int
        ):

            raise TypeError(
                "msg_type must be int"
            )

        if not (
            0
            <=
            msg_type
            <=
            255
        ):

            raise ValueError(
                "msg_type must fit in "
                "one byte"
            )

        # =====================================
        # VALIDATE DATA
        # =====================================

        if not isinstance(
            data,
            bytes
        ):

            raise TypeError(
                "data must be bytes"
            )

        role_bytes = (
            role.encode(
                "ascii"
            )
        )

        # =====================================
        # CANONICAL ENTRY ENCODING
        # =====================================

        encoded_entry = (
            len(role_bytes).to_bytes(
                1,
                "big"
            )
            +
            role_bytes
            +
            msg_type.to_bytes(
                1,
                "big"
            )
            +
            len(data).to_bytes(
                4,
                "big"
            )
            +
            data
        )

        # =====================================
        # UPDATE HASH
        # =====================================

        with self._lock:

            self._hash.update(
                encoded_entry
            )

            self.entries.append(
                (
                    role,
                    msg_type,
                    len(data)
                )
            )


    # =====================================
    # DIGEST
    # =====================================

    def digest(
        self
    ) -> bytes:
        """
        Return current 32-byte digest
        without finalizing transcript.
        """

        with self._lock:

            return (
                self._hash
                .copy()
                .digest()
            )


    # =====================================
    # HEX DIGEST
    # =====================================

    def hexdigest(
        self
    ) -> str:

        return (
            self.digest()
            .hex()
        )


    # =====================================
    # BACKWARD-COMPATIBLE HASH
    # =====================================

    def hash(
        self
    ) -> str:
        """
        Compatibility with the original
        Transcript.hash() API.

        Returns hexadecimal string.
        """

        return self.hexdigest()


    # =====================================
    # SUMMARY
    # =====================================

    def summary(
        self
    ) -> str:

        with self._lock:

            entries = list(
                self.entries
            )

        lines = [
            (
                "Transcript "
                f"({len(entries)} entries):"
            )
        ]

        for index, (
            role,
            msg_type,
            size
        ) in enumerate(
            entries,
            start=1
        ):

            lines.append(
                f"  [{index}] "
                f"{role:<8} "
                f"type=0x{msg_type:02X} "
                f"{size} bytes"
            )

        lines.append(
            "  digest = "
            f"{self.hexdigest()}"
        )

        return "\n".join(
            lines
        )


# =====================================
# GENERATE NONCE
# =====================================

def generate_nonce(
    size: int = 32
) -> bytes:
    """
    Generate a cryptographically secure
    random nonce.

    Default:
        32 bytes = 256 bits
    """

    if not isinstance(
        size,
        int
    ):

        raise TypeError(
            "Nonce size must be int"
        )

    if size < 16:

        raise ValueError(
            "Nonce size must be at least "
            "16 bytes"
        )

    return os.urandom(
        size
    )