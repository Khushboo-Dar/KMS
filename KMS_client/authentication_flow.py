"""Initial authentication and authentication-key retrieval flows."""

import time

from .app_config import (
    MSG_AUTHENTICATION_RESPONSE,
    MSG_IDENTIFICATION_ACK,
)
from .auth_request_0x92 import build_authentication_request
from .auth_response_0x93 import parse_authentication_response
from .database_service import DatabaseService
from .encryption_service import EncryptionService
from .identification import build_identification_packet
from .otp_manager import OtpService
from .packet_parser import parse_identification_ack
from .udp_client import KmsUdpClient


class AuthenticationFlow:
    """Perform the 0x90/0x91 and 0x92/0x93 KMS authentication flows."""

    def __init__(
        self,
        kavach_id: int,
        unit_type: int,
        sim_id: int,
        udp_client: KmsUdpClient,
    ):
        """Create a flow for the supplied unit; no unit identity is implicit."""
        self.kavach_id = kavach_id
        self.unit_type = unit_type
        self.sim_id = sim_id
        self.udp = udp_client

    def _build_authentication_request(self) -> bytes:
        """Fetch the OTP and build a correctly ordered 0x92 request."""
        otp = OtpService().get_otp(self.kavach_id, self.unit_type)
        return build_authentication_request(
            kavach_id=self.kavach_id,
            unit_type=self.unit_type,
            otp=otp,
            sim_id=self.sim_id,
        )

    def _save(self, response: bytes) -> dict:
        parsed = parse_authentication_response(response)
        database = DatabaseService()
        encryption = EncryptionService()
        connection = database.connect("securely store the received key set")

        try:
            encryption.save_key_sets(
                connection,
                parsed["key_set_id"],
                parsed["key_sets"],
                response,
            )
        finally:
            connection.close()

        return parsed

    def _request_keys(self) -> dict:
        request = self._build_authentication_request()
        response = self.udp.send_and_receive(
            request,
            expected_type=MSG_AUTHENTICATION_RESPONSE,
        )

        if response is None:
            raise RuntimeError("No 0x93 Authentication Key Response received")

        return self._save(response)

    def run_initial(self) -> dict:
        """Run 0x90 -> 0x91, then OTP -> 0x92 -> 0x93."""
        identification = build_identification_packet(
            self.kavach_id,
            self.unit_type,
            self.sim_id,
        )
        acknowledgement = self.udp.send_and_receive(
            identification,
            expected_type=MSG_IDENTIFICATION_ACK,
        )

        if acknowledgement is None:
            raise RuntimeError("No 0x91 Identification ACK received")

        acknowledgement_data = parse_identification_ack(acknowledgement)
        if acknowledgement_data["status"] != 0x01:
            raise RuntimeError(
                "Identification failed. "
                f"KMS status=0x{acknowledgement_data['status']:02X}"
            )

        return self._request_keys()

    def request_keys(self) -> dict:
        """Request and store a new key set using OTP -> 0x92 -> 0x93."""
        return self._request_keys()

    def run_initial_with_retry(self, retry_seconds: int = 300) -> dict:
        """Retry transient or not-yet-delivered authentication attempts."""
        if retry_seconds < 0:
            raise ValueError("retry_seconds must be zero or greater")

        while True:
            try:
                return self.run_initial()
            except (ConnectionError, RuntimeError, TimeoutError) as exc:
                print(
                    "Initial authentication failed: "
                    f"{exc}; retrying in {retry_seconds} seconds"
                )
                time.sleep(retry_seconds)
