"""
KAVACH KMS Authentication Key Status - 0x95

Purpose:
    Parse Authentication Key Status information
    received from KMS.

Packet structure:

    SOF              2 bytes
    Message Type     1 byte
    Message Length   2 bytes
    Date             3 bytes
    Time             3 bytes
    Unit Type        1 byte
    KAVACH ID        3 bytes
    Key Set ID       4 bytes
    CRC              4 bytes

Total = 23 bytes
"""

from .app_config import (
    SOF,
    MSG_AUTHENTICATION_STATUS,
)

from .crc_validator import calculate_crc_bytes


# ============================================================
# CONSTANTS
# ============================================================

PACKET_SIZE = 23


# ============================================================
# PARSER
# ============================================================

def parse_authentication_status(
    packet: bytes
) -> dict:
    """
    Parse complete 0x95 packet.

    Returns dictionary containing:
        message_type
        message_length
        date
        time
        unit_type
        kavach_id
        key_set_id
        crc_valid
        raw_packet
    """

    # --------------------------------------------------------
    # Basic length
    # --------------------------------------------------------

    if len(packet) != PACKET_SIZE:
        raise ValueError(
            f"Invalid 0x95 packet size. "
            f"Expected {PACKET_SIZE}, "
            f"received {len(packet)}"
        )

    # --------------------------------------------------------
    # SOF
    # --------------------------------------------------------

    if packet[0:2] != SOF:
        raise ValueError(
            "Invalid SOF. Expected A5 C3."
        )

    # --------------------------------------------------------
    # Message Type
    # --------------------------------------------------------

    message_type = packet[2]

    if message_type != MSG_AUTHENTICATION_STATUS:
        raise ValueError(
            f"Expected 0x95, "
            f"received 0x{message_type:02X}"
        )

    # --------------------------------------------------------
    # Message Length
    # --------------------------------------------------------

    message_length = int.from_bytes(
        packet[3:5],
        byteorder="big"
    )

    if message_length != 18:
        raise ValueError(
            f"Invalid 0x95 message length: "
            f"{message_length}"
        )

    # --------------------------------------------------------
    # Date
    # --------------------------------------------------------

    date = packet[5:8]

    # --------------------------------------------------------
    # Time
    # --------------------------------------------------------

    time = packet[8:11]

    # --------------------------------------------------------
    # Unit Type
    # --------------------------------------------------------

    unit_type = packet[11]

    # --------------------------------------------------------
    # KAVACH ID
    # --------------------------------------------------------

    kavach_id = int.from_bytes(
        packet[12:15],
        byteorder="big"
    )

    # --------------------------------------------------------
    # KEY SET UNIQUE ID
    # --------------------------------------------------------

    key_set_id = int.from_bytes(
        packet[15:19],
        byteorder="big"
    )

    # --------------------------------------------------------
    # RECEIVED CRC
    # --------------------------------------------------------

    received_crc = packet[-4:]

    # --------------------------------------------------------
    # CALCULATED CRC
    # --------------------------------------------------------

    crc_input = packet[2:-4]

    calculated_crc = calculate_crc_bytes(
        crc_input
    )

    crc_valid = (
        received_crc == calculated_crc
    )

    if not crc_valid:
        raise ValueError(
            "0x95 CRC verification failed"
        )

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    return {
        "message_type": message_type,
        "message_type_hex": f"0x{message_type:02X}",

        "message_length": message_length,

        "date": date.hex(" ").upper(),
        "time": time.hex(" ").upper(),

        "unit_type": unit_type,
        "unit_type_hex": f"0x{unit_type:02X}",

        "kavach_id": kavach_id,

        "key_set_id": key_set_id,

        "received_crc": received_crc.hex().upper(),
        "calculated_crc": calculated_crc.hex().upper(),

        "crc_valid": True,

        "raw_packet": packet.hex(" ").upper(),
    }