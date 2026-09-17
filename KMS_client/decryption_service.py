import base64
import os

import oracledb
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from .database_access import require_database_access
except ImportError:  # Supports direct execution: python KMS_client/decryption_service.py
    from KMS_client.database_access import require_database_access


ENV_KEY_NAME = "KMS_DB_ENCRYPTION_KEY_B64"
NONCE_SIZE = 12
AES_KEY_SIZE = 32
VERSION = "v1"
TABLE_NAME = "KMS_KEY_SETS"


class DecryptionService:

    def __init__(self, key: bytes | None = None):
        if key is None:
            key_b64 = os.getenv(ENV_KEY_NAME)
            if not key_b64:
                raise RuntimeError(
                    f"Environment variable {ENV_KEY_NAME} is not set."
                )

            try:
                key = base64.b64decode(key_b64)
            except Exception as error:
                raise RuntimeError("Invalid Base64 encryption key.") from error

        if len(key) != AES_KEY_SIZE:
            raise ValueError(
                f"AES-256 key must be exactly {AES_KEY_SIZE} bytes. "
                f"Received: {len(key)} bytes."
            )

        self.aesgcm = AESGCM(key)

    def decrypt_bytes(
        self,
        encrypted_value: str,
        aad: bytes | None = None
    ) -> bytes:
        if not isinstance(encrypted_value, str):
            raise TypeError("encrypted_value must be string.")

        if not encrypted_value.startswith(f"{VERSION}:"):
            raise ValueError("Unsupported encryption format.")

        try:
            encrypted_data = base64.b64decode(
                encrypted_value[len(VERSION) + 1:]
            )
        except Exception as error:
            raise ValueError("Invalid Base64 encrypted value.") from error

        if len(encrypted_data) < NONCE_SIZE + 16:
            raise ValueError("Encrypted data is too short.")

        nonce = encrypted_data[:NONCE_SIZE]
        ciphertext_with_tag = encrypted_data[NONCE_SIZE:]

        try:
            return self.aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
        except Exception as error:
            raise ValueError(
                "Decryption failed. Data may be corrupted or authentication failed."
            ) from error

    def decrypt_string(
        self,
        encrypted_value: str,
        aad: str | None = None
    ) -> str:
        aad_bytes = aad.encode("utf-8") if aad is not None else None
        return self.decrypt_bytes(encrypted_value, aad_bytes).decode("utf-8")

    def decrypt_hex(
        self,
        encrypted_value: str,
        aad: str | None = None
    ) -> str:
        aad_bytes = aad.encode("utf-8") if aad is not None else None
        plaintext = self.decrypt_bytes(encrypted_value, aad_bytes)

        # Support text HEX and raw binary key material.
        try:
            hex_value = plaintext.decode("utf-8")
            bytes.fromhex(hex_value)
            return hex_value.upper()
        except (UnicodeDecodeError, ValueError):
            return plaintext.hex().upper()


def get_required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Environment variable {name} is not set")
    return value


def decrypt_key(
    service: DecryptionService,
    encrypted_value: str,
    field_name: str,
    key_set_id: object
) -> str:
    aad = f"{TABLE_NAME}|{field_name}|{key_set_id}"
    return service.decrypt_hex(encrypted_value, aad=aad)


def main() -> None:
    service = DecryptionService()
    require_database_access("read encrypted key sets for decryption")
    connection = oracledb.connect(
        user=get_required_env("ORACLE_USER"),
        password=get_required_env("ORACLE_PASSWORD"),
        dsn=get_required_env("ORACLE_DSN"),
    )

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT KEY_SET_ID, KEY_1, KEY_2
                FROM {TABLE_NAME}
                ORDER BY KEY_SET_ID
                """
            )

            total = 0
            failed = 0
            for key_set_id, encrypted_key_1, encrypted_key_2 in cursor:
                total += 1
                print(f"KEY_SET_ID={key_set_id}")

                for field_name, encrypted_value in (
                    ("KEY_1", encrypted_key_1),
                    ("KEY_2", encrypted_key_2),
                ):
                    try:
                        decrypted = decrypt_key(
                            service,
                            encrypted_value,
                            field_name,
                            key_set_id,
                        )
                        print(f"  {field_name}={decrypted}")
                    except Exception as error:
                        failed += 1
                        print(
                            f"  {field_name}=FAILED "
                            f"({type(error).__name__}: {error})"
                        )

            print(f"Processed rows: {total}; failed values: {failed}")
    finally:
        connection.close()


if __name__ == "__main__":
    main()
