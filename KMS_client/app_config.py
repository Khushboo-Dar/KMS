"""
KAVACH KMS Client Configuration

Contains:
- KMS server configuration
- KAVACH unit configuration
- Packet/message type constants
- Polling configuration
- UDP configuration
"""

import os


# ============================================================
# KMS SERVER CONFIGURATION
# ============================================================

KMS_IP = os.getenv(
    "KMS_IP",
    "112.133.205.6"
)

KMS_PORT = int(
    os.getenv(
        "KMS_PORT",
        "54143"
    )
)


# ============================================================
# KAVACH UNIT CONFIGURATION
# ============================================================

# KAVACH Unit ID / Loco ID
KAVACH_ID = int(
    os.getenv(
        "KAVACH_ID",
        "50002"
    )
)

# Unit Type
#
# 0x11 -> Stationary KAVACH
# 0x22 -> Onboard KAVACH
# 0x33 -> TSRMS

UNIT_TYPE = int(
    os.getenv(
        "UNIT_TYPE",
        "0x11"
    ),
    0
)

# SIM ID
#
# 0x01 -> Secondary SIM
# 0x02 -> Primary SIM
SIM_ID = int(
    os.getenv(
        "SIM_ID",
        "0x02"
    ),
    0
)


# ============================================================
# KMS PACKET MESSAGE TYPES
# ============================================================

# Identification
MSG_IDENTIFICATION = 0x90

# Identification Acknowledgement
MSG_IDENTIFICATION_ACK = 0x91

# Authentication Key Request
MSG_AUTHENTICATION_REQUEST = 0x92

# Authentication Key Response
MSG_AUTHENTICATION_RESPONSE = 0x93

# Authentication Query / Polling
MSG_AUTHENTICATION_QUERY = 0x94

# Authentication Key Status
MSG_AUTHENTICATION_STATUS = 0x95


# ============================================================
# PACKET CONSTANTS
# ============================================================

# Start Of Frame
SOF = bytes.fromhex("A5 C3")

# Packet lengths
AUTHENTICATION_QUERY_LENGTH = 19
AUTHENTICATION_STATUS_LENGTH = 23


# ============================================================
# POLLING CONFIGURATION
# ============================================================

# KAVACH sends Authentication Query every 6 hours.
POLLING_INTERVAL_HOURS = int(
    os.getenv(
        "POLLING_INTERVAL_HOURS",
        "6"
    )
)

# Convert hours to seconds
POLLING_INTERVAL_SECONDS = (
    POLLING_INTERVAL_HOURS * 60 * 60
)


# ============================================================
# RANDOMIZED REQUEST WINDOW
# ============================================================

# SRS specifies a 2-hour randomized request window.
RANDOM_REQUEST_WINDOW_MINUTES = 120

RANDOM_REQUEST_WINDOW_SECONDS = (
    RANDOM_REQUEST_WINDOW_MINUTES * 60
)


# ============================================================
# RETRY CONFIGURATION
# ============================================================

# If the first request fails,
# retry every 5 minutes.

RETRY_INTERVAL_MINUTES = int(
    os.getenv(
        "RETRY_INTERVAL_MINUTES",
        "5"
    )
)

RETRY_INTERVAL_SECONDS = (
    RETRY_INTERVAL_MINUTES * 60
)


# ============================================================
# UDP CONFIGURATION
# ============================================================

# Maximum time to wait for KMS response.

UDP_TIMEOUT_SECONDS = int(
    os.getenv(
        "UDP_TIMEOUT_SECONDS",
        "10"
    )
)

# Maximum UDP packet size that we accept.

UDP_BUFFER_SIZE = int(
    os.getenv(
        "UDP_BUFFER_SIZE",
        "65535"
    )
)


# ============================================================
# CRC CONFIGURATION
# ============================================================

CRC_POLYNOMIAL = 0x04C11DB7

CRC_REFLECTED_POLYNOMIAL = 0xEDB88320

CRC_INITIAL_VALUE = 0x00000000

CRC_XOR_OUT = 0x00000000

CRC_REF_IN = True

CRC_REF_OUT = True

CRC_SIZE = 4


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_unit_type_name(unit_type: int) -> str:
    """
    Convert Unit Type value into readable name.
    """

    unit_types = {
        0x11: "STATIONARY_KAVACH",
        0x22: "ONBOARD_KAVACH",
        0x33: "TSRMS",
    }

    return unit_types.get(
        unit_type,
        "UNKNOWN"
    )


def get_unit_prefix(unit_type: int) -> str:
    """
    Return the prefix used in KMS SMS/OTP messages.

    S -> Stationary
    L -> Loco/Onboard
    T -> TSRMS
    """

    prefixes = {
        0x11: "S",
        0x22: "L",
        0x33: "T",
    }

    return prefixes.get(
        unit_type,
        ""
    )


def get_random_request_minute(kavach_id: int) -> int:
    """
    Calculate randomized request minute according
    to the SRS rule:

        Request time in a day minute =
        KAVACH Subsystem ID mod (2 * 60)

    Therefore the result is between 0 and 119.
    """

    return kavach_id % RANDOM_REQUEST_WINDOW_MINUTES