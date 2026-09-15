# key_service.py

from dataclasses import dataclass
from datetime import datetime
from typing import List


# ============================================================
# Constants
# ============================================================

SOF = b"\xA5\xC3"

MESSAGE_TYPE_AUTHENTICATION_RESPONSE = 0x93

CRC_SIZE = 4

KEY_SET_SIZE = 40

KEY_SIZE = 16

VALIDITY_SIZE = 4

KEY_SET_UNIQUE_ID_SIZE = 4

NUMBER_OF_KEY_SETS_SIZE = 1


# ============================================================
# Data Model
# ============================================================

@dataclass
class KeySet:

    validity_start: bytes
    validity_end: bytes

    key_1: bytes
    key_2: bytes

    # Optional decoded values
    validity_start_str: str = ""
    validity_end_str: str = ""

    # --------------------------------------------------------
    # HEX representation
    # --------------------------------------------------------

    @property
    def key_1_hex(self) -> str:

        return self.key_1.hex().upper()

    @property
    def key_2_hex(self) -> str:

        return self.key_2.hex().upper()


@dataclass
class AuthenticationKeyResponse:

    key_set_unique_id: bytes

    number_of_key_sets: int

    key_sets: List[KeySet]

    raw_packet: bytes

    # --------------------------------------------------------
    # Key Set ID as HEX
    # --------------------------------------------------------

    @property
    def key_set_unique_id_hex(self) -> str:

        return self.key_set_unique_id.hex().upper()


# ============================================================
# Key Service
# ============================================================

class KeyService:

    # --------------------------------------------------------
    # Parse 4-byte validity
    #
    # SRS format:
    #
    # HH DD MM YY
    #
    # Example:
    # 09 03 09 26
    # = 09:00, 03-Sep-2026
    # --------------------------------------------------------

    @staticmethod
    def parse_validity(
        data: bytes
    ) -> datetime:

        if len(data) != 4:

            raise ValueError(
                "Validity field must contain exactly 4 bytes"
            )

        hour = data[0]
        day = data[1]
        month = data[2]
        year = 2000 + data[3]

        try:

            return datetime(
                year,
                month,
                day,
                hour,
                0,
                0
            )

        except ValueError as e:

            raise ValueError(
                f"Invalid validity date/time: "
                f"{data.hex().upper()}"
            ) from e

    # --------------------------------------------------------
    # Parse Key Set
    # --------------------------------------------------------

    @classmethod
    def parse_key_set(
        cls,
        data: bytes
    ) -> KeySet:

        if len(data) != KEY_SET_SIZE:

            raise ValueError(
                f"Key set must be {KEY_SET_SIZE} bytes, "
                f"received {len(data)} bytes"
            )

        # ----------------------------------------------------
        # Layout
        #
        # 0  - 3   Validity Start
        # 4  - 7   Validity End
        # 8  - 23  Authentication Key 1
        # 24 - 39  Authentication Key 2
        # ----------------------------------------------------

        validity_start = data[0:4]

        validity_end = data[4:8]

        key_1 = data[8:24]

        key_2 = data[24:40]

        start_dt = cls.parse_validity(
            validity_start
        )

        end_dt = cls.parse_validity(
            validity_end
        )

        return KeySet(

            validity_start=validity_start,

            validity_end=validity_end,

            key_1=key_1,

            key_2=key_2,

            validity_start_str=start_dt.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            validity_end_str=end_dt.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

    # --------------------------------------------------------
    # Parse Complete 0x93 Packet
    # --------------------------------------------------------

    @classmethod
    def parse_93_packet(
        cls,
        packet: bytes
    ) -> AuthenticationKeyResponse:

        # ----------------------------------------------------
        # Basic Length Check
        # ----------------------------------------------------

        if len(packet) < 24:

            raise ValueError(
                f"0x93 packet too short: {len(packet)} bytes"
            )

        # ----------------------------------------------------
        # SOF
        # ----------------------------------------------------

        if packet[0:2] != SOF:

            raise ValueError(
                f"Invalid SOF: "
                f"{packet[0:2].hex().upper()}"
            )

        # ----------------------------------------------------
        # Message Type
        # ----------------------------------------------------

        message_type = packet[2]

        if message_type != MESSAGE_TYPE_AUTHENTICATION_RESPONSE:

            raise ValueError(
                f"Invalid message type: "
                f"0x{message_type:02X}"
            )

        # ----------------------------------------------------
        # Message Length
        # ----------------------------------------------------

        message_length = int.from_bytes(
            packet[3:5],
            byteorder="big"
        )

        # ----------------------------------------------------
        # Key Set Unique ID
        #
        # Offset = 12
        # ----------------------------------------------------

        key_set_unique_id = packet[12:16]

        # ----------------------------------------------------
        # Number of Key Sets
        #
        # Offset = 16
        # ----------------------------------------------------

        number_of_key_sets = packet[16]

        # ----------------------------------------------------
        # First Key Set
        #
        # Offset = 17
        # ----------------------------------------------------

        key_sets_start = 17

        expected_length = (
            5
            + 12
            + 1
            + (number_of_key_sets * KEY_SET_SIZE)
            + CRC_SIZE
        )

        if len(packet) != expected_length:

            raise ValueError(
                f"Invalid 0x93 packet size. "
                f"Expected {expected_length}, "
                f"received {len(packet)}"
            )

        # ----------------------------------------------------
        # Validate Message Length
        #
        # message length normally represents bytes after
        # header through CRC.
        # ----------------------------------------------------

        calculated_message_length = len(packet) - 5

        if message_length != calculated_message_length:

            raise ValueError(
                f"Invalid message length field. "
                f"Field={message_length}, "
                f"Expected={calculated_message_length}"
            )

        # ----------------------------------------------------
        # Parse Key Sets
        # ----------------------------------------------------

        key_sets = []

        offset = key_sets_start

        for index in range(number_of_key_sets):

            key_set_data = packet[
                offset:
                offset + KEY_SET_SIZE
            ]

            if len(key_set_data) != KEY_SET_SIZE:

                raise ValueError(
                    f"Invalid key set #{index + 1}"
                )

            key_set = cls.parse_key_set(
                key_set_data
            )

            key_sets.append(key_set)

            offset += KEY_SET_SIZE

        # ----------------------------------------------------
        # CRC
        #
        # Last 4 bytes
        # ----------------------------------------------------

        received_crc = packet[-CRC_SIZE:]

        # CRC calculation is intentionally kept separate.
        # Use crc.py for actual CRC validation.
        #
        # Example:
        #
        # from .crc import verify_crc
        #
        # verify_crc(packet)
        # ----------------------------------------------------

        return AuthenticationKeyResponse(

            key_set_unique_id=key_set_unique_id,

            number_of_key_sets=number_of_key_sets,

            key_sets=key_sets,

            raw_packet=packet
        )

    # --------------------------------------------------------
    # Convert Key Response to Database Records
    # --------------------------------------------------------

    @staticmethod
    def prepare_database_records(
        response: AuthenticationKeyResponse
    ):

        records = []

        for key_set in response.key_sets:

            record = {

                "KEY_SET_ID":
                    response.key_set_unique_id_hex,

                "VALID_FROM":
                    key_set.validity_start_str,

                "VALID_TO":
                    key_set.validity_end_str,

                "KEY_1":
                    key_set.key_1_hex,

                "KEY_2":
                    key_set.key_2_hex,

                "PKT":
                    response.raw_packet.hex().upper()
            }

            records.append(record)

        return records

    # --------------------------------------------------------
    # Print Key Information
    # --------------------------------------------------------

    @staticmethod
    def print_key_response(
        response: AuthenticationKeyResponse
    ):

        print()
        print("=" * 60)
        print("KMS 0x93 AUTHENTICATION KEY RESPONSE")
        print("=" * 60)

        print(
            f"Key Set Unique ID : "
            f"{response.key_set_unique_id_hex}"
        )

        print(
            f"Number of Key Sets: "
            f"{response.number_of_key_sets}"
        )

        print()

        for index, key_set in enumerate(
            response.key_sets,
            start=1
        ):

            print(
                f"----------- KEY SET #{index} -----------"
            )

            print(
                f"Valid From : "
                f"{key_set.validity_start_str}"
            )

            print(
                f"Valid To   : "
                f"{key_set.validity_end_str}"
            )

            print(
                f"KEY_1      : "
                f"{key_set.key_1_hex}"
            )

            print(
                f"KEY_2      : "
                f"{key_set.key_2_hex}"
            )

        print("=" * 60)


# ============================================================
# Standalone Test
# ============================================================

if __name__ == "__main__":

    # Example packet.
    #
    # Replace this with your actual 0x93 packet.
    #
    TEST_PACKET_HEX = ""

    if not TEST_PACKET_HEX:

        print(
            "Please provide a 0x93 packet HEX "
            "in TEST_PACKET_HEX."
        )

    else:

        try:

            packet = bytes.fromhex(
                TEST_PACKET_HEX
            )

            response = KeyService.parse_93_packet(
                packet
            )

            KeyService.print_key_response(
                response
            )

        except Exception as e:

            print(
                f"Failed to parse 0x93 packet: {e}"
            )