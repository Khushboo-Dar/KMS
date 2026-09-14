# models/polling_result.py

from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime

from .key_set import KeySet


@dataclass
class PollingResult:

    # ========================================================
    # Polling Status
    # ========================================================

    success: bool = False

    # ========================================================
    # KAVACH Information
    # ========================================================

    kavach_id: Optional[int] = None

    unit_type: Optional[int] = None

    # ========================================================
    # Request Information
    # ========================================================

    query_packet: Optional[str] = None

    query_time: Optional[datetime] = None

    # ========================================================
    # Response Information
    # ========================================================

    status_packet: Optional[str] = None

    status_time: Optional[datetime] = None

    # ========================================================
    # Key Set Information
    # ========================================================

    key_set_id: Optional[str] = None

    number_of_key_sets: int = 0

    key_sets: List[KeySet] = field(
        default_factory=list
    )

    # ========================================================
    # Error Information
    # ========================================================

    error: Optional[str] = None

    # ========================================================
    # Retry Information
    # ========================================================

    retry_count: int = 0

    # ========================================================
    # Convert to Dictionary
    # ========================================================

    def to_dict(self) -> dict:

        return {

            "success": self.success,

            "kavach_id": self.kavach_id,

            "unit_type": (
                f"0x{self.unit_type:02X}"
                if self.unit_type is not None
                else None
            ),

            "query_packet": self.query_packet,

            "query_time": (
                self.query_time.isoformat()
                if self.query_time
                else None
            ),

            "status_packet": self.status_packet,

            "status_time": (
                self.status_time.isoformat()
                if self.status_time
                else None
            ),

            "key_set_id": self.key_set_id,

            "number_of_key_sets":
                self.number_of_key_sets,

            "key_sets": [
                key_set.to_dict()
                for key_set in self.key_sets
            ],

            "error": self.error,

            "retry_count": self.retry_count,
        }

    # ========================================================
    # Mark Success
    # ========================================================

    def mark_success(self):

        self.success = True
        self.error = None

    # ========================================================
    # Mark Failure
    # ========================================================

    def mark_failure(
        self,
        error_message: str
    ):

        self.success = False
        self.error = error_message