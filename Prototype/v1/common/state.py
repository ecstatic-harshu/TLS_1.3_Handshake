from enum import Enum


class HandshakeState(Enum):
    """
    States for the integrated authenticated
    post-quantum handshake.
    """

    INIT = 0

    # =====================================
    # CLIENT HELLO / KEM
    # =====================================

    CLIENT_HELLO_SENT = 1

    CLIENT_HELLO_RECEIVED = 2

    KEM_CIPHERTEXT_SENT = 3

    KEM_CIPHERTEXT_RECEIVED = 4

    PQ_SHARED_SECRET_DERIVED = 5

    # =====================================
    # ML-DSA PUBLIC KEY EXCHANGE
    # =====================================

    SERVER_DSA_PUBKEY_SENT = 6

    SERVER_DSA_PUBKEY_RECEIVED = 7

    CLIENT_DSA_PUBKEY_SENT = 8

    CLIENT_DSA_PUBKEY_RECEIVED = 9

    # =====================================
    # TRANSCRIPT AUTHENTICATION
    # =====================================

    AUTH_TRANSCRIPT_READY = 10

    SERVER_SIGNATURE_SENT = 11

    SERVER_SIGNATURE_VERIFIED = 12

    CLIENT_SIGNATURE_SENT = 13

    CLIENT_SIGNATURE_VERIFIED = 14

    # =====================================
    # FINAL TRANSCRIPT
    # =====================================

    FINAL_TRANSCRIPT_READY = 15

    # =====================================
    # COMPLETION
    # =====================================

    DONE_SENT = 16

    DONE_RECEIVED = 17

    AUTHENTICATED = 18

    ESTABLISHED = 19

    FAILED = 255


# =====================================
# TERMINAL STATES
# =====================================

TERMINAL_STATES = {
    HandshakeState.ESTABLISHED,
    HandshakeState.FAILED
}


# =====================================
# HELPERS
# =====================================

def is_terminal(
    state: HandshakeState
) -> bool:

    if not isinstance(
        state,
        HandshakeState
    ):

        raise TypeError(
            "state must be HandshakeState"
        )

    return state in TERMINAL_STATES