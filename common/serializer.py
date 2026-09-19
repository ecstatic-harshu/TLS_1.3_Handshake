import struct


# =====================================
# MESSAGE TYPE CONSTANTS
# =====================================

MSG_HELLO = 0x01

MSG_CIPHERTEXT = 0x02

MSG_DSA_PUBKEY = 0x03

MSG_SIGNATURE = 0x04

MSG_DONE = 0x05

# Encrypted application data
MSG_SECURE_MESSAGE = 0x10

MSG_ERROR = 0xFF


# =====================================
# MESSAGE NAMES
# =====================================

MSG_NAMES = {
    MSG_HELLO:
        "HELLO",

    MSG_CIPHERTEXT:
        "CIPHERTEXT",

    MSG_DSA_PUBKEY:
        "DSA_PUBKEY",

    MSG_SIGNATURE:
        "SIGNATURE",

    MSG_DONE:
        "DONE",

    MSG_SECURE_MESSAGE:
        "SECURE_MESSAGE",

    MSG_ERROR:
        "ERROR"
}


# =====================================
# PROTOCOL HEADER
# =====================================
#
# Inner protocol format:
#
# | 1 byte message type |
# | 4 bytes payload len |
# | N bytes payload     |
#
# =====================================

HEADER_SIZE = 5


# =====================================
# VALIDATE MESSAGE TYPE
# =====================================

def _validate_message_type(
    msg_type: int
):

    if not isinstance(
        msg_type,
        int
    ):

        raise TypeError(
            "msg_type must be int"
        )

    if msg_type not in MSG_NAMES:

        raise ValueError(
            f"Unknown message type: "
            f"{msg_type:#04x}"
        )


# =====================================
# ENCODE
# =====================================

def encode(
    msg_type: int,
    payload: bytes
) -> bytes:
    """
    Encode protocol message.

    Format:

    | msg_type: 1 byte |
    | length:   4 bytes |
    | payload:  N bytes |
    """

    # =====================================
    # VALIDATE MESSAGE TYPE
    # =====================================

    _validate_message_type(
        msg_type
    )

    # =====================================
    # VALIDATE PAYLOAD
    # =====================================

    if not isinstance(
        payload,
        bytes
    ):

        raise TypeError(
            "payload must be bytes"
        )

    # =====================================
    # PREVENT uint32 OVERFLOW
    # =====================================

    if len(payload) > 0xFFFFFFFF:

        raise ValueError(
            "Payload too large"
        )

    # =====================================
    # BUILD HEADER
    # =====================================

    header = struct.pack(
        ">BI",
        msg_type,
        len(payload)
    )

    # =====================================
    # RETURN PACKET
    # =====================================

    return (
        header
        +
        payload
    )


# =====================================
# DECODE
# =====================================

def decode(
    data: bytes
) -> tuple[int, bytes]:
    """
    Decode protocol message.

    Returns:

        (
            msg_type,
            payload
        )
    """

    # =====================================
    # VALIDATE INPUT
    # =====================================

    if not isinstance(
        data,
        bytes
    ):

        raise TypeError(
            "data must be bytes"
        )

    # =====================================
    # CHECK MINIMUM LENGTH
    # =====================================

    if len(data) < HEADER_SIZE:

        raise ValueError(
            f"Packet too short: "
            f"{len(data)} bytes, "
            f"need at least "
            f"{HEADER_SIZE}"
        )

    # =====================================
    # DECODE HEADER
    # =====================================

    msg_type, payload_length = (
        struct.unpack(
            ">BI",
            data[:HEADER_SIZE]
        )
    )

    # =====================================
    # VALIDATE MESSAGE TYPE
    # =====================================

    _validate_message_type(
        msg_type
    )

    # =====================================
    # EXTRACT PAYLOAD
    # =====================================

    payload = data[
        HEADER_SIZE:
    ]

    # =====================================
    # VALIDATE LENGTH
    # =====================================

    if len(payload) != payload_length:

        raise ValueError(
            "Payload length mismatch: "
            f"header says "
            f"{payload_length}, "
            f"got {len(payload)}"
        )

    return (
        msg_type,
        payload
    )


# =====================================
# MESSAGE NAME
# =====================================

def msg_name(
    msg_type: int
) -> str:
    """
    Return human-readable
    message type name.
    """

    return MSG_NAMES.get(
        msg_type,
        (
            f"UNKNOWN("
            f"{msg_type:#04x}"
            f")"
        )
    )