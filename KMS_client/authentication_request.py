"""
KAVACH KMS Authentication Key Request - 0x92

Purpose:
    Send Authentication Key Request to KMS
    after successful OTP authentication flow.

Packet structure:

    SOF              2 bytes
    Message Type     1 byte
    Message Length   2 bytes
    Date             3 bytes
    Time             3 bytes
    Unit Type        1 byte
    KAVACH ID        3 bytes
    SIM ID           1 byte
    OTP              4 bytes
    CRC              4 bytes

Total = 24 bytes

CRC input:

    Message Type through OTP
"""

from datetime import datetime

from .config import (
    SOF,
    MSG_AUTHENTICATION_REQUEST,
    SIM_ID,
)

from .crc import calculate_crc_bytes


# ============================================================
# CONSTANTS
# ============================================================

MESSAGE_LENGTH = 19
PACKET_SIZE = 24


# ============================================================
# HELPERS
# ============================================================

def _date_bytes(timestamp: datetime) -> bytes:

    return bytes([
        timestamp.day,
        timestamp.month,
        timestamp.year % 100,
    ])


def _time_bytes(timestamp: datetime) -> bytes:

    return bytes([
        timestamp.hour,
        timestamp.minute,
        timestamp.second,
    ])


def _kavach_id_bytes(kavach_id: int) -> bytes:

    if not 0 <= kavach_id <= 0xFFFFFF:
        raise ValueError(
            "KAVACH ID must fit in 3 bytes"
        )

    return kavach_id.to_bytes(
        3,
        byteorder="big"
    )


def _otp_bytes(otp: str) -> bytes:
    """
    Convert 4-character OTP to bytes.
    """

    if not isinstance(otp, str):
        raise TypeError(
            "OTP must be a string"
        )

    if len(otp) != 4:
        raise ValueError(
            "OTP must contain exactly 4 characters"
        )

    try:
        return otp.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError(
            "OTP must contain ASCII characters only"
        )


# ============================================================
# BUILD 0x92
# ============================================================

def build_authentication_request(
    kavach_id: int,
    unit_type: int,
    otp: str,
    sim_id: int = SIM_ID,
    timestamp: datetime | None = None,
) -> bytes:
    """
    Build complete 0x92 Authentication Key Request.
    """

    if timestamp is None:
        timestamp = datetime.now()

    # Message Type
    message_type = bytes([
        MSG_AUTHENTICATION_REQUEST
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

    # SIM ID
    sim = bytes([
        sim_id
    ])

    # OTP
    otp_data = _otp_bytes(otp)

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
        + sim
        + otp_data
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

    if len(packet) != PACKET_SIZE:
        raise ValueError(
            f"Invalid 0x92 packet size: "
            f"{len(packet)}"
        )

    return packet


def authentication_request_hex(
    kavach_id: int,
    unit_type: int,
    otp: str,
    sim_id: int = SIM_ID,
    timestamp: datetime | None = None,
) -> str:
    """
    Build 0x92 packet and return HEX.
    """

    packet = build_authentication_request(
        kavach_id=kavach_id,
        unit_type=unit_type,
        otp=otp,
        sim_id=sim_id,
        timestamp=timestamp,
    )

    return packet.hex(" ").upper()