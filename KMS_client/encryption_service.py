import base64
import logging
import os
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

import oracledb
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .utils.datetime_utils import decode_validity

TABLE_NAME = "KMS_KEY_SETS"
NONCE_SIZE = 12
VERSION = "v1"
MAX_KEY_SETS = 30


def _audit_logger() -> logging.Logger:
    logger = logging.getLogger("kms.key_set_changes")
    if logger.handlers:
        return logger

    log_dir = Path(__file__).resolve().parent.parent / "logs"
    log_dir.mkdir(exist_ok=True)
    handler = TimedRotatingFileHandler(
        log_dir / "key_set_changes.log",
        when="midnight",
        interval=1,
        backupCount=30,
        encoding="utf-8",
        utc=True,
    )
    handler.setFormatter(logging.Formatter("%(asctime)sZ %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


class EncryptionService:
    def __init__(self, key=None):
        if key is None:
            raw=os.getenv("KMS_DB_ENCRYPTION_KEY_B64")
            if not raw: raise RuntimeError("KMS_DB_ENCRYPTION_KEY_B64 is not set")
            try: key=base64.b64decode(raw)
            except Exception as e: raise RuntimeError("Invalid Base64 encryption key") from e
        if len(key)!=32: raise ValueError("AES-256 key must be exactly 32 bytes")
        self.aes=AESGCM(key)
    def encrypt_string(self, value, aad):
        nonce=os.urandom(NONCE_SIZE); out=self.aes.encrypt(nonce,value.encode(),aad.encode())
        return VERSION+":"+base64.b64encode(nonce+out).decode()
    def encrypt_hex(self, value, aad):
        clean = value.replace(" ", "").replace("\n", "").strip().upper()
        bytes.fromhex(clean)
        return self.encrypt_string(clean,aad)
    def save_key_sets(
        self,
        connection: oracledb.Connection,
        key_set_id: int,
        key_sets,
        packet: bytes,
    ) -> int:
        now = datetime.now()
        unique_key_sets = []
        seen = set()

        for key_set in key_sets:
            valid_from = decode_validity(bytes.fromhex(key_set["valid_from"]))
            valid_to = decode_validity(bytes.fromhex(key_set["valid_to"]))
            key_1 = key_set["key_1"].replace(" ", "").replace("\n", "").upper()
            key_2 = key_set["key_2"].replace(" ", "").replace("\n", "").upper()
            identity = (key_set_id, valid_from, valid_to, key_1, key_2)

            if valid_to <= now or identity in seen:
                continue
            seen.add(identity)
            unique_key_sets.append((valid_from, valid_to, key_1, key_2))

        if len(unique_key_sets) > MAX_KEY_SETS:
            raise ValueError(
                f"KMS response contains {len(unique_key_sets)} unique active key sets; "
                f"maximum supported is {MAX_KEY_SETS}"
            )

        packet_hex = packet.hex().upper()
        rows = []
        for valid_from, valid_to, key_1, key_2 in unique_key_sets:
            encrypted_key_1 = self.encrypt_hex(
                key_1, f"{TABLE_NAME}|KEY_1|{key_set_id}"
            )
            encrypted_key_2 = self.encrypt_hex(
                key_2, f"{TABLE_NAME}|KEY_2|{key_set_id}"
            )
            encrypted_packet = self.encrypt_hex(
                packet_hex, f"{TABLE_NAME}|PKT|{key_set_id}"
            )
            rows.append(
                (
                    key_set_id,
                    valid_from,
                    valid_to,
                    encrypted_key_1,
                    encrypted_key_2,
                    encrypted_packet,
                )
            )

        logger = _audit_logger()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT KEY_SET_ID, VALID_FROM, VALID_TO FROM KMS_KEY_SETS"
                )
                removed = cursor.fetchall()
                cursor.execute("DELETE FROM KMS_KEY_SETS")
                if rows:
                    cursor.executemany(
                        """INSERT INTO KMS_KEY_SETS
                        (KEY_SET_ID, VALID_FROM, VALID_TO, KEY_1, KEY_2, PKT)
                        VALUES (:1, :2, :3, :4, :5, :6)""",
                        rows,
                    )
            connection.commit()
        except Exception:
            connection.rollback()
            raise

        for old_key_set_id, valid_from, valid_to in removed:
            logger.info(
                "REMOVED key_set_id=%s valid_from=%s valid_to=%s",
                old_key_set_id,
                valid_from,
                valid_to,
            )
        for _, valid_from, valid_to, _, _, _ in rows:
            logger.info(
                "INSERTED key_set_id=%s valid_from=%s valid_to=%s",
                key_set_id,
                valid_from,
                valid_to,
            )

        return len(rows)
