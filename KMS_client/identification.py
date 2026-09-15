"""
KAVACH 0x90 Identification Packet

0x90 Identification Message Format:

SOF             : 2 bytes  -> A5 C3
Message Type    : 1 byte   -> 90
Message Length  : 2 bytes  -> 00 0F
Date            : 3 bytes  -> DD MM YY
Time            : 3 bytes  -> HH MM SS
Unit Type       : 1 byte
KAVACH ID       : 3 bytes
SIM ID          : 1 byte
CRC             : 4 bytes

Total Packet Size = 20 bytes

CRC is calculated over:
    Message Type through SIM ID

CRC parameters:
    Polynomial : 0x04C11DB7
    Init       : 0x00000000
    RefIn      : True
    RefOut     : True
    XorOut     : 0x00000000

Reflected polynomial:
    0xEDB88320
"""

from datetime import datetime
import struct


# ============================================================
# CONSTANTS
# ============================================================

SOF = bytes.fromhex("A5 C3")

MESSAGE_TYPE = 0x90

# Date(3) + Time(3) + UnitType(1) + KavachID(3) + SIMID(1) + CRC(4)
MESSAGE_LENGTH = 15

# 1 byte type + 2 bytes length + 15 bytes message
# + 2 bytes SOF = 20 bytes total
TOTAL_PACKET_LENGTH = 20


# ============================================================
# CRC
# ============================================================

def calculate_crc(data: bytes) -> int:
    """
    Calculate CRC-32 using the KAVACH/KMS parameters.

    Polynomial : 0x04C11DB7
    Init       : 0x00000000
    RefIn      : True
    RefOut     : True
    XorOut     : 0x00000000

    Reflected polynomial = 0xEDB88320
    """

    reflected_poly = 0xEDB88320
    crc = 0x00000000

    for byte in data:
        crc ^= byte

        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ reflected_poly
            else:
                crc >>= 1

            crc &= 0xFFFFFFFF

    return crc


# ============================================================
# DATE / TIME
# ============================================================

def encode_date(dt: datetime) -> bytes:
    """
    Encode date as:

        DD MM YY

    Example:
        05 September 2026
        -> 05 09 1A
    """

    return bytes([
        dt.day,
        dt.month,
        dt.year % 100
    ])


def encode_time(dt: datetime) -> bytes:
    """
    Encode time as:

        HH MM SS

    Example:
        14:30:25
        -> 0E 1E 19
    """

    return bytes([
        dt.hour,
        dt.minute,
        dt.second
    ])


# ============================================================
# KAVACH ID
# ============================================================

def encode_kavach_id(kavach_id: int) -> bytes:
    """
    Convert KAVACH ID into 3-byte big-endian value.

    Example:

        50002 decimal
        = 00 C3 52
    """

    if not isinstance(kavach_id, int):
        raise TypeError("KAVACH ID must be an integer")

    if kavach_id < 0 or kavach_id > 0xFFFFFF:
        raise ValueError(
            "KAVACH ID must be between 0 and 16777215"
        )

    return kavach_id.to_bytes(3, byteorder="big")


# ============================================================
# 0x90 PACKET BUILDER
# ============================================================

def build_identification_packet(
    kavach_id: int,
    unit_type: int,
    sim_id: int,
    dt: datetime | None = None
) -> bytes:
    """
    Build complete KAVACH 0x90 Identification Packet.

    Parameters
    ----------
    kavach_id : int
        3-byte KAVACH/Loco/Unit ID.

    unit_type : int
        Unit type:
            0x11 = Stationary KAVACH
            0x22 = Onboard KAVACH
            0x33 = TSRMS

    sim_id : int
        SIM ID.

    dt : datetime, optional
        Date/time to put in packet.
        If None, current local system time is used.

    Returns
    -------
    bytes
        Complete 20-byte 0x90 packet.
    """

    # --------------------------------------------------------
    # Validate inputs
    # --------------------------------------------------------

    if not 0 <= unit_type <= 0xFF:
        raise ValueError("Unit Type must be 1 byte")

    if not 0 <= sim_id <= 0xFF:
        raise ValueError("SIM ID must be 1 byte")

    # --------------------------------------------------------
    # Current date/time
    # --------------------------------------------------------

    if dt is None:
        dt = datetime.now()

    # --------------------------------------------------------
    # Encode fields
    # --------------------------------------------------------

    date_bytes = encode_date(dt)
    time_bytes = encode_time(dt)

    kavach_id_bytes = encode_kavach_id(kavach_id)

    unit_type_byte = bytes([unit_type])
    sim_id_byte = bytes([sim_id])

    # --------------------------------------------------------
    # Build CRC input
    #
    # CRC is calculated from:
    #
    # Message Type
    #       ↓
    # Message Length
    #       ↓
    # Date
    #       ↓
    # Time
    #       ↓
    # Unit Type
    #       ↓
    # KAVACH ID
    #       ↓
    # SIM ID
    #
    # SOF is NOT included.
    # CRC itself is NOT included.
    # --------------------------------------------------------

    crc_data = (
        bytes([MESSAGE_TYPE])
        + MESSAGE_LENGTH.to_bytes(2, byteorder="big")
        + date_bytes
        + time_bytes
        + unit_type_byte
        + kavach_id_bytes
        + sim_id_byte
    )

    # --------------------------------------------------------
    # Calculate CRC
    # --------------------------------------------------------

    crc_value = calculate_crc(crc_data)

    # CRC transmitted as 4 bytes, big-endian
    crc_bytes = crc_value.to_bytes(4, byteorder="big")

    # --------------------------------------------------------
    # Build complete packet
    # --------------------------------------------------------

    packet = (
        SOF
        + crc_data
        + crc_bytes
    )

    # --------------------------------------------------------
    # Final validation
    # --------------------------------------------------------

    if len(packet) != TOTAL_PACKET_LENGTH:
        raise ValueError(
            f"Invalid 0x90 packet length: "
            f"{len(packet)}, expected {TOTAL_PACKET_LENGTH}"
        )

    return packet


# ============================================================
# HEX HELPER
# ============================================================

def packet_to_hex(packet: bytes) -> str:
    """
    Convert packet bytes to uppercase HEX.
    """

    return packet.hex(" ").upper()


# ============================================================
# PACKET PRINTING / DEBUG
# ============================================================

def print_identification_packet(packet: bytes) -> None:
    """
    Print 0x90 packet in readable format.
    """

    print("\n" + "=" * 60)
    print("KAVACH 0x90 IDENTIFICATION PACKET")
    print("=" * 60)

    print(f"HEX       : {packet_to_hex(packet)}")
    print(f"Length    : {len(packet)} bytes")

    if len(packet) != 20:
        print("WARNING   : Packet length is not 20 bytes!")
        return

    print()
    print(f"SOF       : {packet[0:2].hex(' ').upper()}")
    print(f"Type      : {packet[2]:02X}")
    print(f"Length    : {packet[3:5].hex(' ').upper()}")
    print(f"Date      : {packet[5:8].hex(' ').upper()}")
    print(f"Time      : {packet[8:11].hex(' ').upper()}")
    print(f"Unit Type : {packet[11]:02X}")

    kavach_id = int.from_bytes(
        packet[12:15],
        byteorder="big"
    )

    print(
        f"KAVACH ID : "
        f"{packet[12:15].hex(' ').upper()} "
        f"({kavach_id})"
    )

    print(f"SIM ID    : {packet[15]:02X}")
    print(f"CRC       : {packet[16:20].hex(' ').upper()}")

    print("=" * 60)


# ============================================================
# CONVENIENCE FUNCTION
# ============================================================

def create_identification_packet(
    kavach_id: int,
    unit_type: int,
    sim_id: int
) -> bytes:
    """
    Convenience wrapper for creating 0x90 packet.
    """

    packet = build_identification_packet(
        kavach_id=kavach_id,
        unit_type=unit_type,
        sim_id=sim_id
    )

    return packet


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    # Example:
    # Loco ID    = 50002
    # Unit Type  = 0x22 (Onboard)
    # SIM ID     = 0x02

    KAVACH_ID = 50002
    UNIT_TYPE = 0x22
    SIM_ID = 0x02

    packet = build_identification_packet(
        kavach_id=KAVACH_ID,
        unit_type=UNIT_TYPE,
        sim_id=SIM_ID
    )

    print_identification_packet(packet)