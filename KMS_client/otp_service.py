# otp_service.py

import os
import re
import oracledb


# ============================================================
# Oracle Configuration
# ============================================================

ORACLE_USER = os.getenv(
    "ORACLE_USER",
    "SURAKSHA"
)

ORACLE_PASSWORD = os.getenv(
    "ORACLE_PASSWORD",
    "Suraksha#123"
)

ORACLE_DSN = os.getenv(
    "ORACLE_DSN",
    "10.30.4.153:1521/SMMSDB"
)


# ============================================================
# Unit Type Mapping
# ============================================================

UNIT_TYPE_PREFIX = {
    0x11: "S",   # Stationary KAVACH
    0x22: "L",   # Onboard KAVACH / Loco
    0x33: "T",   # TSRMS
}


# ============================================================
# OTP Service
# ============================================================

class OtpService:

    def __init__(
        self,
        username=ORACLE_USER,
        password=ORACLE_PASSWORD,
        dsn=ORACLE_DSN
    ):
        self.username = username
        self.password = password
        self.dsn = dsn

    # --------------------------------------------------------
    # Get Oracle Connection
    # --------------------------------------------------------

    def _get_connection(self):

        return oracledb.connect(
            user=self.username,
            password=self.password,
            dsn=self.dsn
        )

    # --------------------------------------------------------
    # Get Prefix from Unit Type
    # --------------------------------------------------------

    @staticmethod
    def get_unit_prefix(unit_type: int) -> str:

        prefix = UNIT_TYPE_PREFIX.get(unit_type)

        if prefix is None:
            raise ValueError(
                f"Unsupported Unit Type: 0x{unit_type:02X}"
            )

        return prefix

    # --------------------------------------------------------
    # Create OTP Marker
    #
    # Example:
    # Unit Type = 0x22
    # Loco ID   = 50002
    #
    # Marker = L50002:
    # --------------------------------------------------------

    def create_marker(
        self,
        kavach_id: int,
        unit_type: int
    ) -> str:

        prefix = self.get_unit_prefix(unit_type)

        return f"{prefix}{kavach_id}:"

    # --------------------------------------------------------
    # Retrieve Latest OTP Message
    # --------------------------------------------------------

    def get_latest_message(
        self,
        kavach_id: int,
        unit_type: int
    ):

        marker = self.create_marker(
            kavach_id,
            unit_type
        )

        query = """
            SELECT MESSAGE
            FROM (
                SELECT MESSAGE
                FROM KMS_SMS
                WHERE INSTR(MESSAGE, :marker) > 0
                ORDER BY EVENT_TIME DESC NULLS LAST,
                         ID DESC
            )
            WHERE ROWNUM = 1
        """

        connection = None
        cursor = None

        try:

            connection = self._get_connection()

            cursor = connection.cursor()

            cursor.execute(
                query,
                marker=marker
            )

            row = cursor.fetchone()

            if row is None:
                return None

            return row[0]

        finally:

            if cursor:
                cursor.close()

            if connection:
                connection.close()

    # --------------------------------------------------------
    # Extract OTP from Message
    #
    # Example:
    #
    # MESSAGE:
    # S50002:aiDt
    #
    # OTP:
    # aiDt
    # --------------------------------------------------------

    def extract_otp(
        self,
        message: str,
        kavach_id: int,
        unit_type: int
    ) -> str:

        marker = self.create_marker(
            kavach_id,
            unit_type
        )

        pattern = re.escape(marker) + r"([A-Za-z0-9]{4})"

        match = re.search(
            pattern,
            message
        )

        if not match:

            raise ValueError(
                f"OTP not found after marker '{marker}'. "
                f"Message: {message}"
            )

        return match.group(1)

    # --------------------------------------------------------
    # Main Function
    #
    # Database -> Message -> OTP
    # --------------------------------------------------------

    def get_otp(
        self,
        kavach_id: int,
        unit_type: int
    ) -> str:

        message = self.get_latest_message(
            kavach_id,
            unit_type
        )

        if message is None:

            raise RuntimeError(
                f"No OTP message found for "
                f"KAVACH ID {kavach_id}"
            )

        otp = self.extract_otp(
            message,
            kavach_id,
            unit_type
        )

        return otp


# ============================================================
# Standalone Test
# ============================================================

if __name__ == "__main__":

    service = OtpService()

    KAVACH_ID = 50002
    UNIT_TYPE = 0x22

    try:

        otp = service.get_otp(
            KAVACH_ID,
            UNIT_TYPE
        )

        print("--------------------------------")
        print("OTP Retrieved Successfully")
        print("--------------------------------")
        print(f"KAVACH ID : {KAVACH_ID}")
        print(f"UNIT TYPE : 0x{UNIT_TYPE:02X}")
        print(f"OTP       : {otp}")
        print("--------------------------------")

    except Exception as e:

        print("--------------------------------")
        print("OTP Retrieval Failed")
        print("--------------------------------")
        print(f"Error: {e}")
        print("--------------------------------")