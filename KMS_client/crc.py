"""
KAVACH KMS CRC-32 Utility

CRC configuration used for KMS packets:

    Polynomial              : 0x04C11DB7
    Reflected Polynomial    : 0xEDB88320
    Initial Value            : 0x00000000
    RefIn                    : True
    RefOut                   : True
    XOR Out                  : 0x00000000

CRC is calculated over the packet data excluding:
    - SOF
    - CRC itself
"""


from .config import (
    CRC_REFLECTED_POLYNOMIAL,
    CRC_INITIAL_VALUE,
    CRC_XOR_OUT,
)


# ============================================================
# CRC CALCULATION
# ============================================================

def calculate_crc(data: bytes) -> int:
    """
    Calculate reflected CRC-32.

    Parameters
    ----------
    data : bytes
        Data over which CRC needs to be calculated.

    Returns
    -------
    int
        32-bit CRC value.
    """

    crc = CRC_INITIAL_VALUE

    for byte in data:

        # XOR byte into CRC
        crc ^= byte

        # Process all 8 bits
        for _ in range(8):

            if crc & 0x00000001:

                crc = (
                    crc >> 1
                ) ^ CRC_REFLECTED_POLYNOMIAL

            else:

                crc >>= 1

    crc ^= CRC_XOR_OUT

    return crc & 0xFFFFFFFF


# ============================================================
# CRC AS BYTES
# ============================================================

def calculate_crc_bytes(data: bytes) -> bytes:
    """
    Calculate CRC and return it as 4 bytes.

    CRC is stored in big-endian/network-byte-order form.
    """

    crc = calculate_crc(data)

    return crc.to_bytes(
        4,
        byteorder="big"
    )


# ============================================================
# APPEND CRC
# ============================================================

def append_crc(data: bytes) -> bytes:
    """
    Append calculated CRC to data.

    Returns:
        data + 4-byte CRC
    """

    crc_bytes = calculate_crc_bytes(data)

    return data + crc_bytes


# ============================================================
# VERIFY CRC
# ============================================================

def verify_crc(packet: bytes) -> bool:
    """
    Verify CRC of a complete packet.

    The last 4 bytes are treated as received CRC.
    Everything before those 4 bytes is treated as CRC input.

    Note:
        SOF should already be excluded before calling this
        function if the protocol specifies CRC from Message
        Type onward.
    """

    if len(packet) < 5:
        return False

    data = packet[:-4]

    received_crc = packet[-4:]

    calculated_crc = calculate_crc_bytes(data)

    return calculated_crc == received_crc


# ============================================================
# CRC HEX UTILITY
# ============================================================

def crc_hex(data: bytes) -> str:
    """
    Calculate CRC and return uppercase HEX string.

    Example:
        'E28A65A4'
    """

    return calculate_crc(data).__format__("08X")


# ============================================================
# TEST / DEBUG
# ============================================================

if __name__ == "__main__":

    # Example CRC input from KMS 0x92 packet
    test_hex = (
        "90 00 0F "
        "0B 05 1A "
        "0C 38 "
        "02 "
        "11 00 C3 7E "
        "01"
    )

    test_data = bytes.fromhex(test_hex)

    crc_value = calculate_crc(test_data)

    print("CRC Input:")
    print(test_data.hex(" ").upper())

    print("\nCalculated CRC:")
    print(f"{crc_value:08X}")

    print("\nCRC Bytes:")
    print(calculate_crc_bytes(test_data).hex(" ").upper())