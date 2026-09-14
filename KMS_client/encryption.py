# encryption.py

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# Configuration
# ============================================================

ENV_KEY_NAME = "KMS_DB_ENCRYPTION_KEY_B64"

NONCE_SIZE = 12

AES_KEY_SIZE = 32

VERSION = "v1"


# ============================================================
# AES-256-GCM Encryption Service
# ============================================================

class EncryptionService:

    def __init__(self, key: bytes | None = None):

        if key is None:

            key_b64 = os.getenv(ENV_KEY_NAME)

            if not key_b64:
                raise RuntimeError(
                    f"Environment variable "
                    f"{ENV_KEY_NAME} is not set."
                )

            try:
                key = base64.b64decode(key_b64)

            except Exception as e:

                raise RuntimeError(
                    "Invalid Base64 encryption key."
                ) from e

        # ----------------------------------------------------
        # AES-256 requires exactly 32 bytes
        # ----------------------------------------------------

        if len(key) != AES_KEY_SIZE:

            raise ValueError(
                f"AES-256 key must be exactly "
                f"{AES_KEY_SIZE} bytes. "
                f"Received: {len(key)} bytes."
            )

        self.key = key

        self.aesgcm = AESGCM(self.key)

    # ========================================================
    # Encrypt Bytes
    # ========================================================

    def encrypt_bytes(
        self,
        plaintext: bytes,
        aad: bytes | None = None
    ) -> str:

        if not isinstance(plaintext, bytes):

            raise TypeError(
                "plaintext must be bytes."
            )

        # ----------------------------------------------------
        # Generate random 12-byte nonce
        # ----------------------------------------------------

        nonce = os.urandom(NONCE_SIZE)

        # ----------------------------------------------------
        # AES-GCM encryption
        #
        # AESGCM.encrypt() returns:
        #
        # ciphertext + authentication tag
        # ----------------------------------------------------

        ciphertext_with_tag = self.aesgcm.encrypt(
            nonce,
            plaintext,
            aad
        )

        # ----------------------------------------------------
        # Store:
        #
        # nonce + ciphertext + authentication tag
        # ----------------------------------------------------

        encrypted_data = (
            nonce +
            ciphertext_with_tag
        )

        encoded = base64.b64encode(
            encrypted_data
        ).decode("ascii")

        # ----------------------------------------------------
        # Versioned format
        #
        # v1:<Base64 data>
        # ----------------------------------------------------

        return f"{VERSION}:{encoded}"

    # ========================================================
    # Decrypt Bytes
    # ========================================================

    def decrypt_bytes(
        self,
        encrypted_value: str,
        aad: bytes | None = None
    ) -> bytes:

        if not isinstance(
            encrypted_value,
            str
        ):

            raise TypeError(
                "encrypted_value must be string."
            )

        # ----------------------------------------------------
        # Validate version
        # ----------------------------------------------------

        if not encrypted_value.startswith(
            f"{VERSION}:"
        ):

            raise ValueError(
                "Unsupported encryption format."
            )

        encoded = encrypted_value[
            len(VERSION) + 1:
        ]

        try:

            encrypted_data = base64.b64decode(
                encoded
            )

        except Exception as e:

            raise ValueError(
                "Invalid Base64 encrypted value."
            ) from e

        # ----------------------------------------------------
        # Minimum:
        #
        # nonce + authentication tag
        # ----------------------------------------------------

        if len(encrypted_data) < (
            NONCE_SIZE + 16
        ):

            raise ValueError(
                "Encrypted data is too short."
            )

        # ----------------------------------------------------
        # Extract nonce
        # ----------------------------------------------------

        nonce = encrypted_data[
            :NONCE_SIZE
        ]

        # ----------------------------------------------------
        # Extract ciphertext + tag
        # ----------------------------------------------------

        ciphertext_with_tag = encrypted_data[
            NONCE_SIZE:
        ]

        try:

            plaintext = self.aesgcm.decrypt(
                nonce,
                ciphertext_with_tag,
                aad
            )

        except Exception as e:

            raise ValueError(
                "Decryption failed. "
                "Data may be corrupted or authentication failed."
            ) from e

        return plaintext

    # ========================================================
    # Encrypt String
    # ========================================================

    def encrypt_string(
        self,
        plaintext: str,
        aad: str | None = None
    ) -> str:

        if not isinstance(
            plaintext,
            str
        ):

            raise TypeError(
                "plaintext must be string."
            )

        aad_bytes = (
            aad.encode("utf-8")
            if aad is not None
            else None
        )

        return self.encrypt_bytes(
            plaintext.encode("utf-8"),
            aad_bytes
        )

    # ========================================================
    # Decrypt String
    # ========================================================

    def decrypt_string(
        self,
        encrypted_value: str,
        aad: str | None = None
    ) -> str:

        aad_bytes = (
            aad.encode("utf-8")
            if aad is not None
            else None
        )

        plaintext = self.decrypt_bytes(
            encrypted_value,
            aad_bytes
        )

        return plaintext.decode("utf-8")

    # ========================================================
    # Encrypt HEX
    #
    # Example:
    #
    # KEY:
    # AABBCCDDEEFF...
    #
    # This treats the HEX as text and encrypts it.
    # ========================================================

    def encrypt_hex(
        self,
        hex_value: str,
        aad: str | None = None
    ) -> str:

        # Remove spaces
        clean_hex = (
            hex_value
            .replace(" ", "")
            .replace("\n", "")
            .strip()
        )

        # Validate HEX
        try:

            bytes.fromhex(clean_hex)

        except ValueError as e:

            raise ValueError(
                "Invalid HEX value."
            ) from e

        # Store encrypted HEX text
        return self.encrypt_string(
            clean_hex.upper(),
            aad
        )

    # ========================================================
    # Decrypt HEX
    # ========================================================

    def decrypt_hex(
        self,
        encrypted_value: str,
        aad: str | None = None
    ) -> str:

        hex_value = self.decrypt_string(
            encrypted_value,
            aad
        )

        return hex_value.upper()


# ============================================================
# Generate a New AES-256 Key
# ============================================================

def generate_key() -> str:

    key = os.urandom(
        AES_KEY_SIZE
    )

    return base64.b64encode(
        key
    ).decode("ascii")


# ============================================================
# Example / Test
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("KMS AES-256-GCM ENCRYPTION TEST")
    print("=" * 60)

    # --------------------------------------------------------
    # Generate temporary key for testing
    # --------------------------------------------------------

    key_b64 = generate_key()

    print()
    print("Generated AES-256 Key:")
    print(key_b64)

    print()
    print(
        "For testing only, set:"
    )

    print(
        f"export {ENV_KEY_NAME}='{key_b64}'"
    )

    # --------------------------------------------------------
    # Create service directly using generated key
    # --------------------------------------------------------

    key = base64.b64decode(
        key_b64
    )

    encryption = EncryptionService(
        key=key
    )

    # --------------------------------------------------------
    # Test KEY_1
    # --------------------------------------------------------

    key_1 = (
        "00112233445566778899AABBCCDDEEFF"
    )

    aad_key_1 = (
        "KMS_KEY_SETS|KEY_1|12345"
    )

    encrypted_key_1 = encryption.encrypt_hex(
        key_1,
        aad_key_1
    )

    decrypted_key_1 = encryption.decrypt_hex(
        encrypted_key_1,
        aad_key_1
    )

    print()
    print("KEY_1")
    print("-" * 60)

    print(
        f"Original  : {key_1}"
    )

    print(
        f"Encrypted : {encrypted_key_1}"
    )

    print(
        f"Decrypted : {decrypted_key_1}"
    )

    print(
        f"Match     : "
        f"{key_1.upper() == decrypted_key_1}"
    )

    # --------------------------------------------------------
    # Test KEY_2
    # --------------------------------------------------------

    key_2 = (
        "FFEEDDCCBBAA99887766554433221100"
    )

    aad_key_2 = (
        "KMS_KEY_SETS|KEY_2|12345"
    )

    encrypted_key_2 = encryption.encrypt_hex(
        key_2,
        aad_key_2
    )

    decrypted_key_2 = encryption.decrypt_hex(
        encrypted_key_2,
        aad_key_2
    )

    print()
    print("KEY_2")
    print("-" * 60)

    print(
        f"Original  : {key_2}"
    )

    print(
        f"Encrypted : {encrypted_key_2}"
    )

    print(
        f"Decrypted : {decrypted_key_2}"
    )

    print(
        f"Match     : "
        f"{key_2.upper() == decrypted_key_2}"
    )

    print()
    print("=" * 60)
    print("TEST COMPLETED")
    print("=" * 60)