# encryption.py

import os
import base64
from collections.abc import Iterable

import oracledb
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .utils.datetime_utils import decode_validity


# ============================================================
# Configuration
# ============================================================

ENV_KEY_NAME = "KMS_DB_ENCRYPTION_KEY_B64"

NONCE_SIZE = 12

AES_KEY_SIZE = 32

VERSION = "v1"

TABLE_NAME = "KMS_KEY_SETS"


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

    def encrypt_key_set(
        self,
        key_set_id: int,
        key_1: str,
        key_2: str
    ) -> tuple[str, str]:
        """Encrypt keys received from KMS using their database AAD."""
        key_1_aad = f"{TABLE_NAME}|KEY_1|{key_set_id}"
        key_2_aad = f"{TABLE_NAME}|KEY_2|{key_set_id}"

        return (
            self.encrypt_hex(key_1, aad=key_1_aad),
            self.encrypt_hex(key_2, aad=key_2_aad),
        )

    def save_key_sets(
        self,
        connection: oracledb.Connection,
        key_set_id: int,
        key_sets: Iterable[dict]
    ) -> int:
        """Encrypt parsed KMS key sets and persist them in Oracle."""
        rows = []
        for key_set in key_sets:
            encrypted_key_1, encrypted_key_2 = self.encrypt_key_set(
                key_set_id,
                key_set["key_1"],
                key_set["key_2"],
            )
            valid_from = decode_validity(
                bytes.fromhex(key_set["valid_from"])
            )
            valid_to = decode_validity(
                bytes.fromhex(key_set["valid_to"])
            )
            rows.append(
                (
                    key_set_id,
                    valid_from,
                    valid_to,
                    encrypted_key_1,
                    encrypted_key_2,
                )
            )

        with connection.cursor() as cursor:
            cursor.executemany(
                f"""
                INSERT INTO {TABLE_NAME}
                    (KEY_SET_ID, VALID_FROM, VALID_TO, KEY_1, KEY_2)
                VALUES (:1, :2, :3, :4, :5)
                """,
                rows,
            )

        connection.commit()
        return len(rows)

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

