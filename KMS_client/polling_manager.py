"""
KAVACH KMS Polling Manager

Responsible for:

    - Periodic Authentication Query (0x94)
    - 6-hour polling cycle
    - Randomized request timing
    - UDP communication with KMS
    - Handling KMS responses
    - 5-minute retry mechanism

This module coordinates:

    scheduler.py
    authentication_query.py
    authentication_status.py
    authentication_request.py
    authentication_response.py
    udp_client.py

It does NOT contain packet-building or CRC logic.
"""


import time
from datetime import datetime

from .config import (
    KAVACH_ID,
    UNIT_TYPE,
    POLLING_INTERVAL_SECONDS,
    RETRY_INTERVAL_SECONDS,
    MSG_AUTHENTICATION_STATUS,
    MSG_AUTHENTICATION_RESPONSE,
)

from .scheduler import (
    calculate_random_request_minute,
)

from .authentication_query import (
    build_authentication_query,
)

from .authentication_status import (
    parse_authentication_status,
)

from .authentication_response import (
    parse_authentication_response,
)

from .udp_client import (
    KmsUdpClient,
)


class KmsPollingManager:
    """
    Main KMS polling manager.

    Default configuration:

        KAVACH ID = 50002
        Unit Type = 0x22
        Polling    = 6 hours
        Retry      = 5 minutes
    """

    def __init__(
        self,
        kavach_id: int = KAVACH_ID,
        unit_type: int = UNIT_TYPE,
    ):

        self.kavach_id = kavach_id

        self.unit_type = unit_type

        self.running = False

        self.poll_count = 0

        self.retry_count = 0

    # ========================================================
    # BUILD QUERY
    # ========================================================

    def create_query_packet(self) -> bytes:
        """
        Create 0x94 Authentication Query.
        """

        return build_authentication_query(
            kavach_id=self.kavach_id,
            unit_type=self.unit_type,
        )

    # ========================================================
    # SEND QUERY
    # ========================================================

    def send_query(self) -> bytes | None:
        """
        Build and send 0x94 Authentication Query.

        Returns:
            KMS response bytes
            or None if no response.
        """

        packet = self.create_query_packet()

        print()
        print("=" * 60)
        print("KMS AUTHENTICATION QUERY")
        print("=" * 60)

        print(
            f"KAVACH ID : {self.kavach_id}"
        )

        print(
            f"Unit Type : 0x{self.unit_type:02X}"
        )

        print(
            f"Packet    : "
            f"{packet.hex(' ').upper()}"
        )

        print(
            f"Length    : {len(packet)} bytes"
        )

        try:

            with KmsUdpClient() as client:

                response = (
                    client.send_and_receive(
                        packet
                    )
                )

            if response is None:

                print(
                    "No response received from KMS."
                )

                return None

            print(
                "KMS Response:"
            )

            print(
                response.hex(
                    " "
                ).upper()
            )

            return response

        except OSError as error:

            print(
                f"UDP communication error: "
                f"{error}"
            )

            return None

    # ========================================================
    # HANDLE RESPONSE
    # ========================================================

    def handle_response(
        self,
        response: bytes,
    ) -> bool:
        """
        Handle response received from KMS.

        Returns:

            True
                Response successfully processed.

            False
                Response failed / retry required.
        """

        if not response:

            print(
                "Empty response received."
            )

            return False

        message_type = response[2]

        print(
            f"Response Message Type: "
            f"0x{message_type:02X}"
        )

        # ----------------------------------------------------
        # 0x95 Authentication Status
        # ----------------------------------------------------

        if message_type == MSG_AUTHENTICATION_STATUS:

            try:

                status = (
                    parse_authentication_status(
                        response
                    )
                )

                print()
                print(
                    "Authentication Status:"
                )

                print(
                    f"KAVACH ID : "
                    f"{status['kavach_id']}"
                )

                print(
                    f"Key Set ID: "
                    f"{status['key_set_id']}"
                )

                print(
                    f"CRC Valid : "
                    f"{status['crc_valid']}"
                )

                return True

            except ValueError as error:

                print(
                    f"Invalid 0x95 response: "
                    f"{error}"
                )

                return False

        # ----------------------------------------------------
        # 0x93 Authentication Key Response
        # ----------------------------------------------------

        elif message_type == MSG_AUTHENTICATION_RESPONSE:

            try:

                result = (
                    parse_authentication_response(
                        response
                    )
                )

                print()
                print(
                    "Authentication Key Response:"
                )

                print(
                    f"KAVACH ID : "
                    f"{result['kavach_id']}"
                )

                print(
                    f"Key Set ID: "
                    f"{result['key_set_id']}"
                )

                print(
                    f"Number of Key Sets: "
                    f"{result['number_of_key_sets']}"
                )

                print(
                    f"CRC Valid : "
                    f"{result['crc_valid']}"
                )

                return True

            except ValueError as error:

                print(
                    f"Invalid 0x93 response: "
                    f"{error}"
                )

                return False

        # ----------------------------------------------------
        # Unknown Message
        # ----------------------------------------------------

        else:

            print(
                f"Unsupported KMS message: "
                f"0x{message_type:02X}"
            )

            return False

    # ========================================================
    # SINGLE POLL
    # ========================================================

    def execute_poll(self) -> bool:
        """
        Execute one complete polling cycle.

        Returns:
            True  -> successful
            False -> failed
        """

        self.poll_count += 1

        print()
        print(
            "#" * 60
        )

        print(
            f"Polling Cycle #{self.poll_count}"
        )

        print(
            f"Time: {datetime.now()}"
        )

        print(
            "#" * 60
        )

        response = self.send_query()

        if response is None:

            return False

        return self.handle_response(
            response
        )

    # ========================================================
    # RETRY
    # ========================================================

    def retry_until_success(
        self,
        max_retries: int | None = None,
    ) -> bool:
        """
        Retry failed query every 5 minutes.

        Parameters
        ----------
        max_retries:
            Number of retries.

            None = retry forever.

        Returns
        -------
        bool
            True if successful.
        """

        self.retry_count = 0

        while True:

            self.retry_count += 1

            print()
            print(
                "-" * 60
            )

            print(
                f"Retry #{self.retry_count}"
            )

            print(
                "Waiting 5 minutes before retry..."
            )

            print(
                "-" * 60
            )

            # ------------------------------------------------
            # Wait 5 minutes
            # ------------------------------------------------

            time.sleep(
                RETRY_INTERVAL_SECONDS
            )

            # ------------------------------------------------
            # Try again
            # ------------------------------------------------

            success = self.execute_poll()

            if success:

                print(
                    "KMS polling successful."
                )

                return True

            # ------------------------------------------------
            # Check max retries
            # ------------------------------------------------

            if (
                max_retries is not None
                and self.retry_count
                >= max_retries
            ):

                print(
                    "Maximum retry count reached."
                )

                return False

    # ========================================================
    # START
    # ========================================================

    def start(
        self,
        run_forever: bool = True,
    ):
        """
        Start KMS polling.

        Behaviour:

            1. Calculate randomized request minute.
            2. Wait until scheduled time.
            3. Send 0x94.
            4. If failed, retry every 5 minutes.
            5. After success, wait for next 6-hour cycle.

        Note:
            Exact interpretation of the SRS phrase
            "request time in a day minute" should be
            confirmed against the deployed KMS timing
            convention before production use.
        """

        self.running = True

        randomized_minute = (
            calculate_random_request_minute(
                self.kavach_id
            )
        )

        print()
        print(
            "=" * 60
        )

        print(
            "KAVACH KMS POLLING MANAGER"
        )

        print(
            "=" * 60
        )

        print(
            f"KAVACH ID       : "
            f"{self.kavach_id}"
        )

        print(
            f"Unit Type       : "
            f"0x{self.unit_type:02X}"
        )

        print(
            f"Randomized min  : "
            f"{randomized_minute}"
        )

        print(
            "Polling interval: "
            f"{POLLING_INTERVAL_SECONDS // 3600} hours"
        )

        print(
            "Retry interval  : "
            f"{RETRY_INTERVAL_SECONDS // 60} minutes"
        )

        # ====================================================
        # POLLING LOOP
        # ====================================================

        while self.running:

            # ------------------------------------------------
            # Execute query
            # ------------------------------------------------

            success = self.execute_poll()

            # ------------------------------------------------
            # Retry if required
            # ------------------------------------------------

            if not success:

                print(
                    "Initial polling request failed."
                )

                success = (
                    self.retry_until_success()
                )

            # ------------------------------------------------
            # Next 6-hour cycle
            # ------------------------------------------------

            if success:

                print()
                print(
                    "Polling cycle completed."
                )

            if not run_forever:

                print(
                    "Polling manager stopped "
                    "after one cycle."
                )

                break

            print()
            print(
                "Waiting 6 hours for next "
                "Authentication Query..."
            )

            time.sleep(
                POLLING_INTERVAL_SECONDS
            )

    # ========================================================
    # STOP
    # ========================================================

    def stop(self):
        """
        Stop polling manager.
        """

        self.running = False

        print(
            "KMS Polling Manager stopped."
        )


# ============================================================
# DEBUG
# ============================================================

if __name__ == "__main__":

    manager = KmsPollingManager(
        kavach_id=50002,
        unit_type=0x22,
    )

    try:

        manager.start(
            run_forever=True
        )

    except KeyboardInterrupt:

        print()
        print(
            "Stopping KMS polling..."
        )

        manager.stop()