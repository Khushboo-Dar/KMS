"""
KAVACH KMS Packet Builder

Responsible for creating KMS packets.

Currently supported:
    0x94 - Authentication Query
    0x92 - Authentication Key Request

Packet structure follows the KAVACH KMS SRS.
"""

from datetime import datetime

from .config import (
    SOF,
    MSG_AUTHENTICATION_QUERY,
    MSG_AUTHENTICATION_REQUEST,
    SIM_ID,
)

from .crc import calculate_crc_bytes


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def int_to_bytes(value: int, length: int) -> bytes:
    """
    Convert integer to big-endian bytes.

    Example:
        int_to_bytes(50002, 3)
        -> b'\\x00\\xc3\\x52'
    """

    return value.to_bytes(
        length,
        byteorder="big"
    )


def date_to_kavach_bytes(dt: datetime) -> bytes:
    """
    Convert date into KAVACH date format.

    Format:
        DD MM YY

    Example:
        11 May 2026
        -> 0B 05 1A
    """

    return bytes([
        dt.day,
        dt.month,
        dt.year % 100,
    ])


def time_to_kavach_bytes(dt: datetime) -> bytes:
    """
    Convert time into KAVACH time format.

    Format:
        HH MM SS
    """

    return bytes([
        dt.hour,
        dt.minute,
        dt.second,
    ])


# ============================================================
# 0x94 AUTHENTICATION QUERY
# ============================================================

def build_authentication_query(
    kavach_id: int,
    unit_type: int,
    sim_id: int = SIM_ID,
    timestamp: datetime | None = None,
) -> bytes:
    """
    Build KAVACH Authentication Query packet (0x94).

    Packet:

        SOF             2 bytes
        Message Type    1 byte
        Message Length  2 bytes
        Date            3 bytes
        Time            3 bytes
        Unit Type       1 byte
        KAVACH ID       3 bytes
        CRC             4 bytes

    Total = 19 bytes

    CRC is calculated over:

        Message Type
        through
        KAVACH ID

    Note:
        According to the SRS, Authentication Query
        does NOT contain SIM ID.
    """

    if timestamp is None:
        timestamp = datetime.now()

    # --------------------------------------------------------
    # Message Type
    # --------------------------------------------------------

    message_type = bytes([
        MSG_AUTHENTICATION_QUERY
    ])

    # --------------------------------------------------------
    # Date
    # --------------------------------------------------------

    date_bytes = date_to_kavach_bytes(timestamp)

    # --------------------------------------------------------
    # Time
    # --------------------------------------------------------

    time_bytes = time_to_kavach_bytes(timestamp)

    # --------------------------------------------------------
    # Unit Type
    # --------------------------------------------------------

    unit_type_bytes = bytes([
        unit_type
    ])

    # --------------------------------------------------------
    # KAVACH ID
    # --------------------------------------------------------

    kavach_id_bytes = int_to_bytes(
        kavach_id,
        3
    )

    # --------------------------------------------------------
    # Message Length
    #
    # Date 3
    # Time 3
    # Unit Type 1
    # KAVACH ID 3
    # CRC 4
    #
    # Total = 14? 
    #
    # But SRS message length is calculated from
    # Date through CRC inclusive:
    #
    # 3 + 3 + 1 + 3 + 4 = 14 bytes
    # --------------------------------------------------------

    message_length = 14

    length_bytes = message_length.to_bytes(
        2,
        byteorder="big"
    )

    # --------------------------------------------------------
    # Build CRC input
    # --------------------------------------------------------

    crc_input = (
        message_type
        + length_bytes
        + date_bytes
        + time_bytes
        + unit_type_bytes
        + kavach_id_bytes
    )

    # --------------------------------------------------------
    # Calculate CRC
    # --------------------------------------------------------

    crc_bytes = calculate_crc_bytes(
        crc_input
    )

    # --------------------------------------------------------
    # Final Packet
    # --------------------------------------------------------

    packet = (
        SOF
        + crc_input
        + crc_bytes
    )

    return packet


# ============================================================
# 0x92 AUTHENTICATION KEY REQUEST
# ============================================================

def build_authentication_key_request(
    kavach_id: int,
    unit_type: int,
    otp: str,
    sim_id: int = SIM_ID,
    timestamp: datetime | None = None,
) -> bytes:
    """
    Build Authentication Key Request packet (0x92).

    Packet:

        SOF             2
        Message Type    1
        Message Length  2
        Date            3
        Time            3
        Unit Type       1
        KAVACH ID       3
        SIM ID          1
        OTP             4
        CRC             4

    Total = 24 bytes.

    CRC input:

        Message Type through OTP
    """

    if timestamp is None:
        timestamp = datetime.now()

    # Validate OTP
    if not isinstance(otp, str):
        raise TypeError(
            "OTP must be a string"
        )

    if len(otp) != 4:
        raise ValueError(
            "OTP must contain exactly 4 characters"
        )

    # --------------------------------------------------------
    # Message Type
    # --------------------------------------------------------

    message_type = bytes([
        MSG_AUTHENTICATION_REQUEST
    ])

    # --------------------------------------------------------
    # Message Length
    #
    # Date      = 3
    # Time      = 3
    # Unit Type = 1
    # KAVACH ID = 3
    # SIM ID    = 1
    # OTP       = 4
    # CRC       = 4
    #
    # Total = 19 bytes
    # --------------------------------------------------------

    message_length = 19

    length_bytes = message_length.to_bytes(
        2,
        byteorder="big"
    )

    # --------------------------------------------------------
    # Date
    # --------------------------------------------------------

    date_bytes = date_to_kavach_bytes(timestamp)

    # --------------------------------------------------------
    # Time
    # --------------------------------------------------------

    time_bytes = time_to_kavach_bytes(timestamp)

    # --------------------------------------------------------
    # Unit Type
    # --------------------------------------------------------

    unit_type_bytes = bytes([
        unit_type
    ])

    # --------------------------------------------------------
    # KAVACH ID
    # --------------------------------------------------------

    kavach_id_bytes = int_to_bytes(
        kavach_id,
        3
    )

    # --------------------------------------------------------
    # SIM ID
    # --------------------------------------------------------

    sim_id_bytes = bytes([
        sim_id
    ])

    # --------------------------------------------------------
    # OTP
    # --------------------------------------------------------

    otp_bytes = otp.encode("ascii")

    # --------------------------------------------------------
    # CRC Input
    # --------------------------------------------------------

    crc_input = (
        message_type
        + length_bytes
        + date_bytes
        + time_bytes
        + unit_type_bytes
        + kavach_id_bytes
        + sim_id_bytes
        + otp_bytes
    )

    # --------------------------------------------------------
    # CRC
    # --------------------------------------------------------

    crc_bytes = calculate_crc_bytes(
        crc_input
    )

    # --------------------------------------------------------
    # Final packet
    # --------------------------------------------------------

    packet = (
        SOF
        + crc_input
        + crc_bytes
    )

    return packet


# ============================================================
# HEX DISPLAY HELPER
# ============================================================

def packet_to_hex(packet: bytes) -> str:
    """
    Convert packet bytes to uppercase HEX string.
    """

    return packet.hex(" ").upper()


# ============================================================
# SIMPLE TEST
# ============================================================

if __name__ == "__main__":

    packet = build_authentication_query(
        kavach_id=50002,
        unit_type=0x22,
    )

    print("0x94 Authentication Query")
    print("--------------------------------")

    print("Packet Length:", len(packet))

    print("Packet HEX:")
    print(packet_to_hex(packet))