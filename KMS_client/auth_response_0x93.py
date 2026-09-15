"""
KAVACH KMS Authentication Key Response - 0x93

Purpose:
    Parse Authentication Key Response received from KMS.

Packet structure:

    SOF                  2 bytes
    Message Type         1 byte
    Message Length       2 bytes
    Date                 3 bytes
    Time                 3 bytes
    Unit Type            1 byte
    KAVACH ID            3 bytes
    Key Set Unique ID    4 bytes
    Number of Key Sets   1 byte

    For every key set:

        Validity Start   4 bytes
        Validity End     4 bytes
        Authentication Key 1  16 bytes
        Authentication Key 2  16 bytes

    CRC                  4 bytes

Each key-set block = 40 bytes.

Total packet size:

    24 + (40 * number_of_key_sets)
"""

from .app_config import (
    SOF,
    MSG_AUTHENTICATION_RESPONSE,
)

from .crc_validator import calculate_crc_bytes


# ============================================================
# CONSTANTS
# ============================================================

HEADER_BEFORE_KEY_SETS = 20
KEY_SET_SIZE = 40
CRC_SIZE = 4


# ============================================================
# BASIC HELPERS
# ============================================================

def _read_uint(
    data: bytes,
    start: int,
    size: int,
) -> int:
    """
    Read unsigned big-endian integer.
    """

    end = start + size

    return int.from_bytes(
        data[start:end],
        byteorder="big"
    )


def _hex(data: bytes) -> str:
    """
    Convert bytes to uppercase HEX.
    """

    return data.hex().upper()


# ============================================================
# PARSE 0x93
# ============================================================

def parse_authentication_response(
    packet: bytes
) -> dict:
    """
    Parse complete 0x93 Authentication Key Response.

    Returns:

        {
            message_type,
            message_length,
            date,
            time,
            unit_type,
            kavach_id,
            key_set_id,
            number_of_key_sets,
            key_sets,
            crc_valid,
            raw_packet
        }
    """

    # --------------------------------------------------------
    # Minimum packet size
    # --------------------------------------------------------

    if len(packet) < 24:
        raise ValueError(
            "0x93 packet is too short"
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

    if message_type != MSG_AUTHENTICATION_RESPONSE:
        raise ValueError(
            f"Expected 0x93, "
            f"received 0x{message_type:02X}"
        )

    # --------------------------------------------------------
    # Message Length
    # --------------------------------------------------------

    message_length = _read_uint(
        packet,
        3,
        2
    )

    # Total packet size:
    #
    # 2 SOF
    # + 3 message type/length
    # + message_length

    expected_packet_size = (
        5 + message_length
    )

    if len(packet) != expected_packet_size:
        raise ValueError(
            f"Invalid 0x93 packet size. "
            f"Expected {expected_packet_size}, "
            f"received {len(packet)}"
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

    kavach_id = _read_uint(
        packet,
        12,
        3
    )

    # --------------------------------------------------------
    # KEY SET UNIQUE ID
    # --------------------------------------------------------

    key_set_id = _read_uint(
        packet,
        15,
        4
    )

    # --------------------------------------------------------
    # NUMBER OF KEY SETS
    # --------------------------------------------------------

    number_of_key_sets = packet[19]

    # --------------------------------------------------------
    # Calculate expected size
    # --------------------------------------------------------

    expected_message_length = (
        15
        + (KEY_SET_SIZE * number_of_key_sets)
        + CRC_SIZE
    )

    if message_length != expected_message_length:
        raise ValueError(
            f"Invalid 0x93 message length. "
            f"Expected {expected_message_length}, "
            f"received {message_length}"
        )

    # --------------------------------------------------------
    # CRC
    # --------------------------------------------------------

    received_crc = packet[-4:]

    crc_input = packet[2:-4]

    calculated_crc = calculate_crc_bytes(
        crc_input
    )

    crc_valid = (
        received_crc == calculated_crc
    )

    if not crc_valid:
        raise ValueError(
            "0x93 CRC verification failed"
        )

    # --------------------------------------------------------
    # PARSE KEY SETS
    # --------------------------------------------------------

    key_sets = []

    offset = 20

    for index in range(
        number_of_key_sets
    ):

        # ----------------------------------------------------
        # Current key-set block
        # ----------------------------------------------------

        block = packet[
            offset:
            offset + KEY_SET_SIZE
        ]

        if len(block) != KEY_SET_SIZE:
            raise ValueError(
                f"Incomplete key-set block "
                f"at index {index}"
            )

        # ----------------------------------------------------
        # Validity Start
        # Format:
        # HH DD MM YY
        # ----------------------------------------------------

        valid_from = block[0:4]

        # ----------------------------------------------------
        # Validity End
        # ----------------------------------------------------

        valid_to = block[4:8]

        # ----------------------------------------------------
        # Authentication Key 1
        # ----------------------------------------------------

        key_1 = block[8:24]

        # ----------------------------------------------------
        # Authentication Key 2
        # ----------------------------------------------------

        key_2 = block[24:40]

        # ----------------------------------------------------
        # Store key set
        # ----------------------------------------------------

        key_sets.append({
            "index": index + 1,

            "key_set_id": key_set_id,

            "valid_from":
                _hex(valid_from),

            "valid_to":
                _hex(valid_to),

            "key_1":
                _hex(key_1),

            "key_2":
                _hex(key_2),

            "key_1_bytes":
                key_1,

            "key_2_bytes":
                key_2,
        })

        # Move to next block
        offset += KEY_SET_SIZE

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    return {
        "message_type":
            message_type,

        "message_type_hex":
            f"0x{message_type:02X}",

        "message_length":
            message_length,

        "date":
            _hex(date),

        "time":
            _hex(time),

        "unit_type":
            unit_type,

        "unit_type_hex":
            f"0x{unit_type:02X}",

        "kavach_id":
            kavach_id,

        "key_set_id":
            key_set_id,

        "number_of_key_sets":
            number_of_key_sets,

        "key_sets":
            key_sets,

        "received_crc":
            _hex(received_crc),

        "calculated_crc":
            _hex(calculated_crc),

        "crc_valid":
            True,

        "raw_packet":
            _hex(packet),
    }