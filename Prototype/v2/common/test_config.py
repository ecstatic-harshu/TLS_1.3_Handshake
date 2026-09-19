# =====================================
# SECURITY TEST CONFIGURATION
# =====================================
#
# IMPORTANT:
# These options are for controlled
# localhost/laboratory testing only.
#
# Keep all values False during normal
# operation.
#
# =====================================


# =====================================
# PACKET CORRUPTION
# =====================================

ENABLE_PACKET_CORRUPTION = False


# =====================================
# AES-GCM CIPHERTEXT TAMPERING
# =====================================

ENABLE_CIPHERTEXT_TAMPERING = False


# =====================================
# RANDOM CONNECTION DROP
# =====================================

ENABLE_RANDOM_DISCONNECT = False


# =====================================
# SECURE MESSAGE REPLAY
# =====================================

ENABLE_REPLAY_ATTACK = False


# =====================================
# OPTIONAL TEST PARAMETERS
# =====================================

PACKET_CORRUPTION_PROBABILITY = (
    0.10
)

CIPHERTEXT_TAMPERING_PROBABILITY = (
    0.10
)

RANDOM_DISCONNECT_PROBABILITY = (
    0.05
)


# =====================================
# VALIDATION
# =====================================

def _validate_probability(
    name: str,
    value: float
):

    if not isinstance(
        value,
        (int, float)
    ):

        raise TypeError(
            f"{name} must be numeric"
        )

    if not (
        0.0
        <=
        float(value)
        <=
        1.0
    ):

        raise ValueError(
            f"{name} must be between "
            "0.0 and 1.0"
        )


_validate_probability(
    "PACKET_CORRUPTION_PROBABILITY",
    PACKET_CORRUPTION_PROBABILITY
)

_validate_probability(
    "CIPHERTEXT_TAMPERING_PROBABILITY",
    CIPHERTEXT_TAMPERING_PROBABILITY
)

_validate_probability(
    "RANDOM_DISCONNECT_PROBABILITY",
    RANDOM_DISCONNECT_PROBABILITY
)


# =====================================
# SUMMARY
# =====================================

def summary():

    return {
        "packet_corruption":
            ENABLE_PACKET_CORRUPTION,

        "ciphertext_tampering":
            ENABLE_CIPHERTEXT_TAMPERING,

        "random_disconnect":
            ENABLE_RANDOM_DISCONNECT,

        "replay_attack":
            ENABLE_REPLAY_ATTACK
    }