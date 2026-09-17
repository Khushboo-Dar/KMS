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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


# Configuration values below are read during module import.  Loading the
# repository's .env here keeps direct packet/module imports consistent with the
# application entry point while preserving explicitly supplied environment
# variables.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")


# ============================================================
# RUNTIME CLIENT CONFIGURATION
# ============================================================

# This client is bound to one stationary KAVACH unit. These protocol identity
# fields are intentionally not read from the environment or accepted at runtime.
KAVACH_ID = 50002
UNIT_TYPE = 0x11
SIM_ID = 0x01

UNIT_TYPE_NAMES = {
    0x11: "STATIONARY_KAVACH",
    0x22: "ONBOARD_KAVACH",
    0x33: "TSRMS",
}

UNIT_TYPE_ALIASES = {
    "stationary": 0x11,
    "stationary_kavach": 0x11,
    "onboard": 0x22,
    "loco": 0x22,
    "onboard_kavach": 0x22,
    "tsrms": 0x33,
}


def parse_integer(value: str | int) -> int:
    """Parse decimal (including ``02``) or ``0x``-prefixed integer input."""
    try:
        text = str(value).strip()
        base = 16 if text.lower().startswith(("0x", "+0x", "-0x")) else 10
        return int(text, base)
    except (TypeError, ValueError) as error:
        raise ValueError(f"Invalid integer value: {value!r}") from error


def parse_unit_type(value: str | int) -> int:
    """Accept SRS type values or friendly names such as ``loco``."""
    if isinstance(value, str):
        normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
        if normalized in UNIT_TYPE_ALIASES:
            return UNIT_TYPE_ALIASES[normalized]
    return parse_integer(value)


@dataclass(frozen=True, slots=True)
class KmsClientConfig:
    """Validated runtime identity and endpoint for one KAVACH client."""

    kms_ip: str
    kms_port: int
    kavach_id: int
    unit_type: int
    sim_id: int
    udp_timeout_seconds: int

    @property
    def unit_type_name(self) -> str:
        return UNIT_TYPE_NAMES[self.unit_type]


def _first_value(explicit_value: Any, environment_name: str) -> Any:
    return explicit_value if explicit_value is not None else os.getenv(environment_name)


def resolve_client_config(
    *,
    kms_ip: str | None = None,
    kms_port: str | int | None = None,
    udp_timeout_seconds: str | int | None = None,
) -> KmsClientConfig:
    """Resolve the KMS endpoint while using the fixed client identity."""
    raw_values = {
        "KMS_IP": _first_value(kms_ip, "KMS_IP"),
        "KMS_PORT": _first_value(kms_port, "KMS_PORT"),
    }
    missing = [name for name, value in raw_values.items() if value in (None, "")]
    if missing:
        raise ValueError("Missing required configuration: " + ", ".join(missing))

    config = KmsClientConfig(
        kms_ip=str(raw_values["KMS_IP"]).strip(),
        kms_port=parse_integer(raw_values["KMS_PORT"]),
        kavach_id=KAVACH_ID,
        unit_type=UNIT_TYPE,
        sim_id=SIM_ID,
        udp_timeout_seconds=parse_integer(
            _first_value(udp_timeout_seconds, "UDP_TIMEOUT_SECONDS") or "10"
        ),
    )

    if not config.kms_ip:
        raise ValueError("KMS_IP cannot be empty")
    if not 1 <= config.kms_port <= 65535:
        raise ValueError("KMS_PORT must be between 1 and 65535")
    if not 0 <= config.kavach_id <= 0xFFFFFF:
        raise ValueError("KAVACH_ID must fit in 3 bytes (0 to 16777215)")
    if config.unit_type not in UNIT_TYPE_NAMES:
        raise ValueError("UNIT_TYPE must be 0x11 (stationary), 0x22 (loco), or 0x33 (tsrms)")
    if config.sim_id not in (0x01, 0x02):
        raise ValueError("SIM_ID must be 1/0x01 (Secondary) or 2/0x02 (Primary)")
    if config.udp_timeout_seconds <= 0:
        raise ValueError("UDP_TIMEOUT_SECONDS must be greater than zero")
    return config


# KMS connectivity may be configured by environment; the unit identity above
# is fixed for this client.
KMS_IP = os.getenv("KMS_IP")
KMS_PORT = parse_integer(os.getenv("KMS_PORT")) if os.getenv("KMS_PORT") else None


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

# KAVACH sends Authentication Query every 6 hours.  Older deployments used
# POLL_INTERVAL_HOURS, so accept that name while migrating to the documented
# POLLING_INTERVAL_HOURS setting.
POLLING_INTERVAL_HOURS = int(
    os.getenv(
        "POLLING_INTERVAL_HOURS",
        os.getenv("POLL_INTERVAL_HOURS", "1"),
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
        "5",
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
        "10",
    )
)

# Maximum UDP packet size that we accept.

UDP_BUFFER_SIZE = int(
    os.getenv(
        "UDP_BUFFER_SIZE",
        "65535",
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
ORACLE_USER=os.getenv("ORACLE_USER", "")
ORACLE_PASSWORD=os.getenv("ORACLE_PASSWORD", "")
ORACLE_DSN=os.getenv("ORACLE_DSN", "")
