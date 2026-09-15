# utils/datetime_utils.py

from datetime import datetime, timezone


# ============================================================
# Encode Date
#
# KAVACH date format:
#
# DD MM YY
#
# Example:
# 03 September 2026
#
# 03 09 26
# ============================================================

def encode_date(
    dt: datetime
) -> bytes:

    return bytes([
        dt.day,
        dt.month,
        dt.year % 100
    ])


# ============================================================
# Encode Time
#
# HH MM SS
# ============================================================

def encode_time(
    dt: datetime
) -> bytes:

    return bytes([
        dt.hour,
        dt.minute,
        dt.second
    ])


# ============================================================
# Encode Date + Time
# ============================================================

def encode_datetime(
    dt: datetime
) -> bytes:

    return (
        encode_date(dt)
        +
        encode_time(dt)
    )


# ============================================================
# Decode Date + Time
#
# Input:
# DD MM YY HH MM SS
# ============================================================

def decode_datetime(
    data: bytes
) -> datetime:

    if len(data) != 6:

        raise ValueError(
            "Date/time data must contain 6 bytes."
        )

    day = data[0]
    month = data[1]
    year = 2000 + data[2]

    hour = data[3]
    minute = data[4]
    second = data[5]

    return datetime(
        year,
        month,
        day,
        hour,
        minute,
        second
    )


# ============================================================
# Current Date/Time
# ============================================================

def get_current_datetime() -> datetime:

    return datetime.now()


# ============================================================
# Convert datetime to String
# ============================================================

def datetime_to_string(
    dt: datetime
) -> str:

    return dt.strftime(
        "%Y-%m-%d %H:%M:%S"
    )


# ============================================================
# Parse String to datetime
# ============================================================

def string_to_datetime(
    value: str
) -> datetime:

    return datetime.strptime(
        value,
        "%Y-%m-%d %H:%M:%S"
    )


# ============================================================
# Convert 4-byte KAVACH Validity
#
# Format:
#
# HH DD MM YY
#
# Example:
#
# 09 03 09 26
# ============================================================

def decode_validity(
    data: bytes
) -> datetime:

    if len(data) != 4:

        raise ValueError(
            "Validity must contain exactly 4 bytes."
        )

    hour = data[0]
    day = data[1]
    month = data[2]
    year = 2000 + data[3]

    return datetime(
        year,
        month,
        day,
        hour,
        0,
        0
    )


# ============================================================
# Encode KAVACH Validity
#
# HH DD MM YY
# ============================================================

def encode_validity(
    dt: datetime
) -> bytes:

    return bytes([
        dt.hour,
        dt.day,
        dt.month,
        dt.year % 100
    ])