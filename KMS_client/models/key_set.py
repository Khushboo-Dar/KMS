# models/key_set.py

from dataclasses import dataclass
from typing import Optional


@dataclass
class KeySet:

    # ========================================================
    # Key Set Information
    # ========================================================

    key_set_id: str

    # ========================================================
    # Validity
    # ========================================================

    valid_from: str

    valid_to: str

    # ========================================================
    # Authentication Keys
    # ========================================================

    key_1: str

    key_2: str

    # ========================================================
    # Optional Complete Packet
    # ========================================================

    packet: Optional[str] = None

    # ========================================================
    # Database ID
    # ========================================================

    database_id: Optional[int] = None

    # ========================================================
    # Display
    # ========================================================

    def __str__(self):

        return (
            f"KeySet("
            f"key_set_id={self.key_set_id}, "
            f"valid_from={self.valid_from}, "
            f"valid_to={self.valid_to}"
            f")"
        )

    # ========================================================
    # Convert to Dictionary
    # ========================================================

    def to_dict(self) -> dict:

        return {
            "key_set_id": self.key_set_id,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "key_1": self.key_1,
            "key_2": self.key_2,
            "packet": self.packet,
            "database_id": self.database_id,
        }