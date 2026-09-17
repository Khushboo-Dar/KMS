"""
KAVACH KMS Packet Parser

Responsible for:
    - Packet validation
    - SOF validation
    - Message type detection
    - Message length validation
    - CRC verification
    - Parsing 0x91 and 0x95 packets
"""

from .app_config import (
    SOF,
    MSG_IDENTIFICATION_ACK,
    MSG_AUTHENTICATION_STATUS,
    MSG_AUTHENTICATION_RESPONSE,
)

from .crc_validator import calculate_crc_bytes


# ============================================================
# BASIC PACKET VALIDATION
# ============================================================

def validate_sof(packet: bytes) -> bool:
    """
    Check whether packet starts with KAVACH SOF A5 C3.
    """

    return packet.startswith(SOF)


def get_message_type(packet: bytes) -> int:
    """
    Return message type.

    Packet format:

        Byte 0-1 : SOF
        Byte 2   : Message Type
    """

    if len(packet) < 3:
        raise ValueError(
            "Packet too short to contain message type"
        )

    return packet[2]


def get_message_length(packet: bytes) -> int:
    """
    Read message length from packet.

    Length field:

        Byte 3-4
    """

    if len(packet) < 5:
        raise ValueError(
            "Packet too short to contain length"
        )

    return int.from_bytes(
        packet[3:5],
        byteorder="big"
    )


# ============================================================
# CRC VERIFICATION
# ============================================================

def verify_packet_crc(packet: bytes) -> bool:
    """
    Verify CRC of complete KAVACH packet.

    CRC calculation:

        packet[2:-4]

    because:
        packet[0:2] -> SOF
        packet[-4:]  -> received CRC
    """

    if len(packet) < 7:
        return False

    crc_input = packet[2:-4]

    received_crc = packet[-4:]

    calculated_crc = calculate_crc_bytes(
        crc_input
    )

    return received_crc == calculated_crc


# ============================================================
# COMPLETE PACKET VALIDATION
# ============================================================

def validate_packet(packet: bytes) -> None:
    """
    Validate:
        1. SOF
        2. Message length
        3. CRC
    """

    if not validate_sof(packet):
        raise ValueError(
            "Invalid SOF. Expected A5 C3."
        )

    message_length = get_message_length(
        packet
    )

    expected_total_length = (
        5 + message_length
    )

    if len(packet) != expected_total_length:
        raise ValueError(
            f"Invalid packet length. "
            f"Expected {expected_total_length}, "
            f"received {len(packet)}"
        )

    if not verify_packet_crc(packet):
        raise ValueError(
            "CRC verification failed"
        )


# ============================================================
# PARSE 0x91 IDENTIFICATION ACK
# ============================================================

def parse_identification_ack(packet: bytes) -> dict:
    """
    Parse an SRS-format Identification Acknowledgement (0x91).

    Packet layout::

        SOF(2) | Type=0x91(1) | Length=0x000F(2) |
        Date(3) | Time(3) | Unit Type(1) | KAVACH Unit ID(3) |
        Acknowledgement Status(1) | CRC(4)

    ``Message Length`` counts Date through CRC, inclusively, so it is 15
    bytes and the complete packet is 20 bytes.  CRC is calculated from the
    message type through acknowledgement status.

    Expected status:

        0x01 -> OTP sent
        0x02 -> KAVACH ID not registered
        0x03 -> Message delivery failed
    """

    validate_packet(packet)

    message_type = get_message_type(packet)

    if message_type != MSG_IDENTIFICATION_ACK:
        raise ValueError(
            f"Expected 0x91, "
            f"received 0x{message_type:02X}"
        )

    message_length = get_message_length(packet)
    expected_message_length = 15
    expected_packet_length = 20

    if (
        message_length != expected_message_length
        or len(packet) != expected_packet_length
    ):
        raise ValueError(
            "Invalid SRS 0x91 acknowledgement layout: "
            f"expected {expected_packet_length} bytes with message length "
            f"{expected_message_length}, received {len(packet)} bytes with "
            f"message length {message_length}"
        )

    date = packet[5:8]
    time = packet[8:11]
    unit_type = packet[11]
    kavach_id = int.from_bytes(packet[12:15], byteorder="big")
    status = packet[15]

    status_map = {
        0x01: "OTP_SENT",
        0x02: "KAVACH_ID_NOT_REGISTERED",
        0x03: "MESSAGE_DELIVERY_FAILED",
    }

    return {
        "message_type": message_type,
        "message_type_hex": f"0x{message_type:02X}",
        "message_length": message_length,
        "date": date.hex(" ").upper(),
        "time": time.hex(" ").upper(),
        "unit_type": unit_type,
        "unit_type_hex": f"0x{unit_type:02X}",
        "kavach_id": kavach_id,
        "status": status,
        "status_hex": f"0x{status:02X}",
        "status_name": status_map.get(
            status,
            "UNKNOWN"
        ),
        "crc_valid": True,
    }


# ============================================================
# PARSE 0x95 AUTHENTICATION KEY STATUS
# ============================================================

def parse_authentication_status(
    packet: bytes
) -> dict:
    """
    Parse Authentication Key Status (0x95).

    Structure:

        SOF             2
        Message Type    1
        Message Length  2
        Date            3
        Time            3
        Unit Type       1
        KAVACH ID       3
        Key Set ID      4
        CRC             4

    Total = 23 bytes.
    """

    validate_packet(packet)

    message_type = get_message_type(
        packet
    )

    if message_type != MSG_AUTHENTICATION_STATUS:
        raise ValueError(
            f"Expected 0x95, "
            f"received 0x{message_type:02X}"
        )

    # --------------------------------------------------------
    # Extract fields
    # --------------------------------------------------------

    message_length = get_message_length(
        packet
    )

    date_bytes = packet[5:8]

    time_bytes = packet[8:11]

    unit_type = packet[11]

    kavach_id = int.from_bytes(
        packet[12:15],
        byteorder="big"
    )

    key_set_id = int.from_bytes(
        packet[15:19],
        byteorder="big"
    )

    received_crc = packet[-4:]

    return {
        "message_type": message_type,
        "message_type_hex": f"0x{message_type:02X}",

        "message_length": message_length,

        "date": date_bytes.hex(" ").upper(),

        "time": time_bytes.hex(" ").upper(),

        "unit_type": unit_type,
        "unit_type_hex": f"0x{unit_type:02X}",

        "kavach_id": kavach_id,

        "key_set_id": key_set_id,

        "received_crc": received_crc.hex().upper(),

        "crc_valid": True,
    }


# ============================================================
# PARSE GENERIC PACKET
# ============================================================

def parse_packet(packet: bytes) -> dict:
    """
    Automatically identify and parse supported packet.
    """

    message_type = get_message_type(
        packet
    )

    if message_type == MSG_IDENTIFICATION_ACK:

        return parse_identification_ack(
            packet
        )

    elif message_type == MSG_AUTHENTICATION_STATUS:

        return parse_authentication_status(
            packet
        )

    else:

        # Validate generic packet even if
        # parser is not implemented for it.
        validate_packet(packet)

        return {
            "message_type": message_type,
            "message_type_hex": (
                f"0x{message_type:02X}"
            ),
            "message_length": (
                get_message_length(packet)
            ),
            "crc_valid": True,
            "raw_hex": packet.hex().upper(),
        }


# ============================================================
# DEBUG
# ============================================================

if __name__ == "__main__":

    print(
        "KAVACH KMS Packet Parser"
    )
