import hashlib
import hmac


class PQKem:
    def __init__(self):
        self.public_key = b"mock_public_key"
        self.secret_key = b"mock_secret_key"

    def generate_keypair(self):
        return self.public_key, self.secret_key

    def encapsulate(self, public_key):
        ciphertext = b"mock_ciphertext"

        shared_secret = hashlib.sha256(
            public_key + ciphertext
        ).digest()

        return ciphertext, shared_secret

    def decapsulate(self, ciphertext):
        shared_secret = hashlib.sha256(
            self.public_key + ciphertext
        ).digest()

        return shared_secret


class PQSignature:
    def __init__(self):
        self.public_key = b"mock_dsa_public"
        self.private_key = b"mock_dsa_private"

    def generate_keypair(self):
        return self.public_key, self.private_key

    def sign(self, message: bytes):
        signature = hmac.new(
            self.private_key,
            message,
            hashlib.sha256
        ).digest()

        return signature

    def verify(self, message: bytes, signature: bytes):
        expected_signature = hmac.new(
            self.private_key,
            message,
            hashlib.sha256
        ).digest()

        return hmac.compare_digest(
            signature,
            expected_signature
        )