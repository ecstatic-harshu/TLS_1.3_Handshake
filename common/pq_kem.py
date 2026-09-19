import oqs


# =====================================
# CONFIGURATION
# =====================================

ALGORITHM = "ML-KEM-768"


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
    Check whether ML-KEM-768 is available
    in the installed liboqs build.
    """

    try:

        enabled = (
            oqs.get_enabled_kem_mechanisms()
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
    Generate an ML-KEM-768 keypair.

    Returns:
        (
            public_key: bytes,
            secret_key: bytes
        )
    """

    _ensure_available()

    try:

        with oqs.KeyEncapsulation(
            ALGORITHM
        ) as kem:

            public_key = (
                kem.generate_keypair()
            )

            secret_key = (
                kem.export_secret_key()
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
# ENCAPSULATE
# =====================================

def encapsulate(
    public_key: bytes
):
    """
    Encapsulate a fresh shared secret
    using the recipient ML-KEM-768
    public key.

    Returns:
        (
            ciphertext: bytes,
            shared_secret: bytes
        )
    """

    _ensure_available()

    _validate_bytes(
        "public_key",
        public_key
    )

    try:

        with oqs.KeyEncapsulation(
            ALGORITHM
        ) as kem:

            (
                ciphertext,
                shared_secret
            ) = kem.encap_secret(
                public_key
            )

        _validate_bytes(
            "ciphertext",
            ciphertext
        )

        _validate_bytes(
            "shared_secret",
            shared_secret
        )

        return (
            ciphertext,
            shared_secret
        )

    except Exception as exc:

        raise RuntimeError(
            f"{ALGORITHM} encapsulation "
            f"failed: {exc}"
        ) from exc


# =====================================
# DECAPSULATE
# =====================================

def decapsulate(
    ciphertext: bytes,
    secret_key: bytes
) -> bytes:
    """
    Recover the ML-KEM-768 shared secret
    from ciphertext using the recipient
    secret key.
    """

    _ensure_available()

    _validate_bytes(
        "ciphertext",
        ciphertext
    )

    _validate_bytes(
        "secret_key",
        secret_key
    )

    try:

        with oqs.KeyEncapsulation(
            ALGORITHM,
            secret_key
        ) as kem:

            shared_secret = (
                kem.decap_secret(
                    ciphertext
                )
            )

        _validate_bytes(
            "shared_secret",
            shared_secret
        )

        return shared_secret

    except Exception as exc:

        raise RuntimeError(
            f"{ALGORITHM} decapsulation "
            f"failed: {exc}"
        ) from exc