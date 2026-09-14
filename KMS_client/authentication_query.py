"""
KAVACH KMS Authentication Query - 0x94

Purpose:
    KAVACH subsystem periodically sends Authentication Query
    to KMS to check whether a new authentication key set
    is available.

Packet structure:

    SOF              2 bytes
    Message Type     1 byte
    Message Length   2 bytes
    Date             3 bytes
    Time             3 bytes
    Unit Type        1 byte
    KAVACH ID        3 bytes
    CRC              4 bytes

Total = 19 bytes

CRC input:

    Message Type
    +
    Message Length
    +
    Date
    +
    Time
    +
    Unit Type
    +
    KAVACH ID
"""

from datetime import datetime

from .config import (
    SOF,
    MSG_AUTHENTICATION_QUERY,
)

from .crc import calculate_crc_bytes


# ============================================================
# CONSTANTS
# ============================================================

MESSAGE_LENGTH = 14


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def _date_bytes(timestamp: datetime) -> bytes:
    """
    KAVACH date format:

        DD MM YY
    """

    return bytes([
        timestamp.day,
        timestamp.month,
        timestamp.year % 100,
    ])


def _time_bytes(timestamp: datetime) -> bytes:
    """
    KAVACH time format:

        HH MM SS
    """

    return bytes([
        timestamp.hour,
        timestamp.minute,
        timestamp.second,
    ])


def _kavach_id_bytes(kavach_id: int) -> bytes:
    """
    Convert KAVACH ID to 3-byte big-endian value.
    """

    if not 0 <= kavach_id <= 0xFFFFFF:
        raise ValueError(
            "KAVACH ID must fit in 3 bytes"
        )

    return kavach_id.to_bytes(
        3,
        byteorder="big"
    )


# ============================================================
# BUILD 0x94
# ============================================================

def build_authentication_query(
    kavach_id: int,
    unit_type: int,
    timestamp: datetime | None = None,
) -> bytes:
    """
    Build complete 0x94 Authentication Query packet.
    """

    if timestamp is None:
        timestamp = datetime.now()

    # Message Type
    message_type = bytes([
        MSG_AUTHENTICATION_QUERY
    ])

    # Message Length
    length = MESSAGE_LENGTH.to_bytes(
        2,
        byteorder="big"
    )

    # Date
    date = _date_bytes(timestamp)

    # Time
    time = _time_bytes(timestamp)

    # Unit Type
    unit = bytes([
        unit_type
    ])

    # KAVACH ID
    kavach = _kavach_id_bytes(
        kavach_id
    )

    # --------------------------------------------------------
    # CRC INPUT
    # --------------------------------------------------------

    crc_input = (
        message_type
        + length
        + date
        + time
        + unit
        + kavach
    )

    # --------------------------------------------------------
    # CRC
    # --------------------------------------------------------

    crc = calculate_crc_bytes(
        crc_input
    )

    # --------------------------------------------------------
    # COMPLETE PACKET
    # --------------------------------------------------------

    packet = (
        SOF
        + crc_input
        + crc
    )

    # Safety check
    if len(packet) != 19:
        raise ValueError(
            f"Invalid 0x94 packet size: {len(packet)}"
        )

    return packet


def authentication_query_hex(
    kavach_id: int,
    unit_type: int,
    timestamp: datetime | None = None,
) -> str:
    """
    Build 0x94 packet and return HEX string.
    """

    packet = build_authentication_query(
        kavach_id,
        unit_type,
        timestamp,
    )

    return packet.hex(" ").upper()