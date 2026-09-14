# utils/hex_utils.py


# ============================================================
# HEX -> Bytes
# ============================================================

def hex_to_bytes(
    hex_string: str
) -> bytes:

    if not isinstance(
        hex_string,
        str
    ):

        raise TypeError(
            "hex_string must be a string."
        )

    # Remove spaces
    clean_hex = (
        hex_string
        .replace(" ", "")
        .replace("\n", "")
        .replace("\t", "")
        .strip()
    )

    # HEX must have even number of characters
    if len(clean_hex) % 2 != 0:

        raise ValueError(
            "HEX string must contain an even number "
            "of characters."
        )

    try:

        return bytes.fromhex(
            clean_hex
        )

    except ValueError as e:

        raise ValueError(
            f"Invalid HEX string: {hex_string}"
        ) from e


# ============================================================
# Bytes -> HEX
# ============================================================

def bytes_to_hex(
    data: bytes,
    separator: str = ""
) -> str:

    if not isinstance(
        data,
        bytes
    ):

        raise TypeError(
            "data must be bytes."
        )

    hex_string = data.hex().upper()

    if separator:

        return separator.join(
            hex_string[i:i + 2]
            for i in range(
                0,
                len(hex_string),
                2
            )
        )

    return hex_string


# ============================================================
# Validate HEX
# ============================================================

def validate_hex(
    hex_string: str
) -> bool:

    try:

        hex_to_bytes(
            hex_string
        )

        return True

    except (
        TypeError,
        ValueError
    ):

        return False


# ============================================================
# Integer -> Bytes
# ============================================================

def int_to_bytes(
    value: int,
    length: int,
    byteorder: str = "big"
) -> bytes:

    if value < 0:

        raise ValueError(
            "Integer cannot be negative."
        )

    max_value = (
        1 << (length * 8)
    ) - 1

    if value > max_value:

        raise ValueError(
            f"Value {value} does not fit "
            f"in {length} bytes."
        )

    return value.to_bytes(
        length,
        byteorder=byteorder
    )


# ============================================================
# Bytes -> Integer
# ============================================================

def bytes_to_int(
    data: bytes,
    byteorder: str = "big"
) -> int:

    if not isinstance(
        data,
        bytes
    ):

        raise TypeError(
            "data must be bytes."
        )

    return int.from_bytes(
        data,
        byteorder=byteorder
    )


# ============================================================
# Integer -> 3-byte KAVACH ID
# ============================================================

def kavach_id_to_bytes(
    kavach_id: int
) -> bytes:

    return int_to_bytes(
        kavach_id,
        3,
        "big"
    )


# ============================================================
# 3-byte KAVACH ID -> Integer
# ============================================================

def bytes_to_kavach_id(
    data: bytes
) -> int:

    if len(data) != 3:

        raise ValueError(
            "KAVACH ID must contain exactly 3 bytes."
        )

    return bytes_to_int(
        data,
        "big"
    )


# ============================================================
# Pretty HEX dump
# ============================================================

def hex_dump(
    data: bytes,
    width: int = 16
) -> str:

    if not isinstance(
        data,
        bytes
    ):

        raise TypeError(
            "data must be bytes."
        )

    lines = []

    for offset in range(
        0,
        len(data),
        width
    ):

        chunk = data[
            offset:
            offset + width
        ]

        hex_part = " ".join(
            f"{byte:02X}"
            for byte in chunk
        )

        lines.append(
            f"{offset:04X}  {hex_part}"
        )

    return "\n".join(lines)