import socket
import struct
import threading


# =====================================
# TRANSPORT CONFIGURATION
# =====================================

HEADER_FORMAT = "!I"

HEADER_SIZE = struct.calcsize(
    HEADER_FORMAT
)

MAX_PACKET_SIZE = (
    10_000_000
)


# =====================================
# SEND LOCK REGISTRY
# =====================================
#
# sendall() protects against partial writes,
# but multiple threads writing to the same
# socket can still interleave logical frames.
#
# SecureSession already has a send lock, but
# transport-level locking gives additional
# protection for shared socket use.
#
# =====================================

_socket_locks = {}

_socket_locks_guard = (
    threading.Lock()
)


def _get_socket_lock(
    sock
) -> threading.Lock:

    socket_id = id(
        sock
    )

    with _socket_locks_guard:

        lock = _socket_locks.get(
            socket_id
        )

        if lock is None:

            lock = (
                threading.Lock()
            )

            _socket_locks[
                socket_id
            ] = lock

        return lock


# =====================================
# SEND PACKET
# =====================================

def send_packet(
    sock,
    data: bytes
) -> None:
    """
    Send one length-prefixed packet.

    Wire format:

        4-byte big-endian payload length
        +
        payload bytes
    """

    if sock is None:

        raise ValueError(
            "Socket cannot be None"
        )

    if not isinstance(
        data,
        bytes
    ):

        raise TypeError(
            "Packet data must be bytes"
        )

    packet_length = len(
        data
    )

    if packet_length <= 0:

        raise ValueError(
            "Cannot send empty packet"
        )

    if (
        packet_length
        >
        MAX_PACKET_SIZE
    ):

        raise ValueError(
            "Packet too large"
        )

    header = struct.pack(
        HEADER_FORMAT,
        packet_length
    )

    framed_packet = (
        header
        +
        data
    )

    send_lock = (
        _get_socket_lock(
            sock
        )
    )

    try:

        with send_lock:

            sock.sendall(
                framed_packet
            )

    except (
        OSError,
        socket.error
    ) as exc:

        raise ConnectionError(
            "Failed to send packet"
        ) from exc


# =====================================
# RECEIVE EXACT BYTES
# =====================================

def recv_exact(
    sock,
    size: int
) -> bytes:
    """
    Receive exactly `size` bytes.

    Handles TCP/TLS partial reads.
    """

    if sock is None:

        raise ValueError(
            "Socket cannot be None"
        )

    if not isinstance(
        size,
        int
    ):

        raise TypeError(
            "size must be int"
        )

    if size < 0:

        raise ValueError(
            "size cannot be negative"
        )

    if size == 0:

        return b""

    buffer = bytearray()

    try:

        while (
            len(buffer)
            <
            size
        ):

            remaining = (
                size
                -
                len(buffer)
            )

            chunk = sock.recv(
                remaining
            )

            if not chunk:

                raise ConnectionError(
                    "Connection closed "
                    "unexpectedly"
                )

            buffer.extend(
                chunk
            )

    except ConnectionError:

        raise

    except (
        OSError,
        socket.error
    ) as exc:

        raise ConnectionError(
            "Failed while receiving data"
        ) from exc

    return bytes(
        buffer
    )


# =====================================
# RECEIVE PACKET
# =====================================

def recv_packet(
    sock
) -> bytes:
    """
    Receive one complete length-prefixed
    packet.
    """

    # =====================================
    # RECEIVE HEADER
    # =====================================

    header = recv_exact(
        sock,
        HEADER_SIZE
    )

    # =====================================
    # PARSE LENGTH
    # =====================================

    packet_length = struct.unpack(
        HEADER_FORMAT,
        header
    )[0]

    # =====================================
    # VALIDATE LENGTH
    # =====================================

    if packet_length <= 0:

        raise ValueError(
            "Invalid packet length"
        )

    if (
        packet_length
        >
        MAX_PACKET_SIZE
    ):

        raise ValueError(
            "Packet too large"
        )

    # =====================================
    # RECEIVE PAYLOAD
    # =====================================

    payload = recv_exact(
        sock,
        packet_length
    )

    return payload


# =====================================
# CLEANUP SOCKET LOCK
# =====================================

def release_socket_lock(
    sock
) -> None:
    """
    Remove transport lock associated with
    a closed socket.

    Call during session cleanup if desired.
    """

    if sock is None:

        return

    socket_id = id(
        sock
    )

    with _socket_locks_guard:

        _socket_locks.pop(
            socket_id,
            None
        )