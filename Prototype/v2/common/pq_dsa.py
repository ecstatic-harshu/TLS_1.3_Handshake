import oqs


# =====================================
# CONFIGURATION
# =====================================

ALGORITHM = "ML-DSA-65"


# =====================================
# INTERNAL VALIDATION
# =====================================

def _validate_bytes(
    name: str,
    value: bytes
) -> None:

    if not isinstance(value, bytes):
        raise TypeError(
            f"{name} must be bytes"
        )

    if len(value) == 0:
        raise ValueError(
            f"{name} cannot be empty"
        )


# =====================================
# ALGORITHM AVAILABILITY
# =====================================

def is_available() -> bool:
    """
    Check whether ML-DSA-65 is available
    in the installed liboqs build.
    """

    try:

        enabled = (
            oqs.get_enabled_sig_mechanisms()
        )

        return ALGORITHM in enabled

    except Exception:

        return False


def _ensure_available() -> None:

    if not is_available():

        raise RuntimeError(
            f"{ALGORITHM} is not available "
            f"in the installed liboqs build"
        )


# =====================================
# GENERATE KEYPAIR
# =====================================

def generate_keypair():
    """
    Generate an ML-DSA-65 keypair.

    Returns:
        (
            public_key: bytes,
            secret_key: bytes
        )
    """

    _ensure_available()

    try:

        with oqs.Signature(
            ALGORITHM
        ) as signature:

            public_key = (
                signature.generate_keypair()
            )

            secret_key = (
                signature.export_secret_key()
            )

        _validate_bytes(
            "public_key",
            public_key
        )

        _validate_bytes(
            "secret_key",
            secret_key
        )

        return (
            public_key,
            secret_key
        )

    except Exception as exc:

        raise RuntimeError(
            f"{ALGORITHM} key generation "
            f"failed: {exc}"
        ) from exc


# =====================================
# SIGN DATA
# =====================================

def sign_data(
    data: bytes,
    secret_key: bytes
) -> bytes:
    """
    Sign arbitrary bytes using ML-DSA-65.

    Returns:
        signature: bytes
    """

    _ensure_available()

    _validate_bytes(
        "data",
        data
    )

    _validate_bytes(
        "secret_key",
        secret_key
    )

    try:

        with oqs.Signature(
            ALGORITHM,
            secret_key
        ) as signature:

            signed_data = (
                signature.sign(data)
            )

        _validate_bytes(
            "signature",
            signed_data
        )

        return signed_data

    except Exception as exc:

        raise RuntimeError(
            f"{ALGORITHM} signing failed: "
            f"{exc}"
        ) from exc


# =====================================
# VERIFY SIGNATURE
# =====================================

def verify_signature(
    data: bytes,
    signature: bytes,
    public_key: bytes
) -> bool:
    """
    Verify an ML-DSA-65 signature.

    Returns:
        True  -> valid
        False -> invalid
    """

    _ensure_available()

    _validate_bytes(
        "data",
        data
    )

    _validate_bytes(
        "signature",
        signature
    )

    _validate_bytes(
        "public_key",
        public_key
    )

    try:

        with oqs.Signature(
            ALGORITHM
        ) as verifier:

            return bool(
                verifier.verify(
                    data,
                    signature,
                    public_key
                )
            )

    except Exception:

        # Verification failure should be
        # represented as False rather than
        # crashing the handshake.
        return False