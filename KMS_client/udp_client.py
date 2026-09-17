# """
# KAVACH KMS UDP Client

# Responsible only for:
#     - Creating UDP socket
#     - Sending packet to KMS
#     - Receiving KMS response
#     - Handling timeout
#     - Closing socket
# """

# import socket

# from .app_config import (
#     KMS_IP,
#     KMS_PORT,
#     UDP_TIMEOUT_SECONDS,
#     UDP_BUFFER_SIZE,
# )


# class KmsUdpClient:
#     """
#     UDP client for communication with KMS.
#     """

#     def __init__(
#         self,
#         server_ip: str = KMS_IP,
#         server_port: int = KMS_PORT,
#         timeout: int = UDP_TIMEOUT_SECONDS,
#     ):
#         """
#         Initialize UDP client.

#         Parameters
#         ----------
#         server_ip:
#             KMS server IP.

#         server_port:
#             KMS UDP port.

#         timeout:
#             Socket receive timeout in seconds.
#         """

#         self.server_ip = server_ip

#         self.server_port = server_port

#         self.timeout = timeout

#         self.socket = None

#     # ========================================================
#     # CREATE SOCKET
#     # ========================================================

#     def create_socket(self):
#         """
#         Create UDP socket.
#         """

#         if self.socket is None:

#             self.socket = socket.socket(
#                 socket.AF_INET,
#                 socket.SOCK_DGRAM
#             )

#             self.socket.settimeout(
#                 self.timeout
#             )

#     # ========================================================
#     # SEND
#     # ========================================================

#     def send(
#         self,
#         packet: bytes
#     ) -> int:
#         """
#         Send packet to KMS.

#         Returns:
#             Number of bytes sent.
#         """

#         if not isinstance(packet, bytes):
#             raise TypeError(
#                 "packet must be bytes"
#             )

#         self.create_socket()

#         bytes_sent = self.socket.sendto(
#             packet,
#             (
#                 self.server_ip,
#                 self.server_port
#             )
#         )

#         return bytes_sent

#     # ========================================================
#     # RECEIVE
#     # ========================================================

#     def receive(self) -> bytes | None:
#         """
#         Wait for KMS response.

#         Returns:
#             Response bytes if received.

#             None if timeout occurs.
#         """

#         self.create_socket()

#         try:

#             data, address = (
#                 self.socket.recvfrom(
#                     UDP_BUFFER_SIZE
#                 )
#             )

#             print(
#                 f"KMS response received "
#                 f"from {address[0]}:{address[1]}"
#             )

#             return data

#         except socket.timeout:

#             print(
#                 "KMS response timeout"
#             )

#             return None

#     # ========================================================
#     # SEND AND RECEIVE
#     # ========================================================

#     def send_and_receive(
#         self,
#         packet: bytes,
#         expected_type: int = None
#     ) -> bytes | None:
#         """
#         Send packet and wait for response.
#         """

#         self.send(packet)

#         return self.receive()

#     # ========================================================
#     # CLOSE
#     # ========================================================

#     def close(self):
#         """
#         Close UDP socket.
#         """

#         if self.socket is not None:

#             self.socket.close()

#             self.socket = None

#     # ========================================================
#     # CONTEXT MANAGER
#     # ========================================================

#     def __enter__(self):

#         self.create_socket()

#         return self

#     def __exit__(
#         self,
#         exc_type,
#         exc_value,
#         traceback
#     ):

#         self.close()


# # ============================================================
# # DEBUG / TEST
# # ============================================================

# if __name__ == "__main__":

#     print(
#         "KAVACH KMS UDP Client"
#     )

#     print(
#         f"KMS Server: "
#         f"{KMS_IP}:{KMS_PORT}"
#     )

#     client = KmsUdpClient()

#     try:

#         # Test data only
#         test_packet = b"TEST"

#         print(
#             f"Sending: "
#             f"{test_packet.hex().upper()}"
#         )

#         sent = client.send(
#             test_packet
#         )

#         print(
#             f"Bytes sent: {sent}"
#         )

#     finally:

#         client.close()
"""
KMS UDP Client

Handles UDP communication between KAVACH subsystem and KMS.

Supported flows:
    0x90 -> 0x91   Identification
    0x92 -> 0x93   Authentication Key Request/Response
    0x94 -> 0x95   Authentication Query/Status

Features:
    - Configurable UDP timeout
    - Expected response type validation
    - Ignores unexpected UDP packets
    - Proper socket cleanup
    - Hex logging
    - Backward compatible send_and_receive(packet)
"""

import socket
from typing import Optional, Tuple

from .kms_server_access import require_kms_server_access


class KmsUdpClient:
    """
    UDP client used to communicate with KMS.
    """

    def __init__(
        self,
        host: str,
        port: int,
        timeout: float = 10.0,
        recv_buffer_size: int = 4096,
    ):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self.recv_buffer_size = int(recv_buffer_size)

    # ---------------------------------------------------------
    # Utility
    # ---------------------------------------------------------

    @staticmethod
    def _hex(data: bytes) -> str:
        """Convert bytes to uppercase HEX string."""
        return data.hex(" ").upper()

    @staticmethod
    def _message_type(data: bytes) -> Optional[int]:
        """
        KMS packet structure:

            Byte 0-1 : SOF
            Byte 2   : Message Type

        Returns message type if available.
        """
        if len(data) < 3:
            return None

        return data[2]

    # ---------------------------------------------------------
    # Socket
    # ---------------------------------------------------------

    def _create_socket(self) -> socket.socket:
        """
        Create and configure UDP socket.
        """
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        sock.settimeout(self.timeout)

        return sock

    # ---------------------------------------------------------
    # Send
    # ---------------------------------------------------------

    def send(self, packet: bytes) -> int:
        """
        Send UDP packet to KMS.

        Returns:
            Number of bytes sent.
        """

        if not isinstance(packet, (bytes, bytearray)):
            raise TypeError(
                "packet must be bytes or bytearray"
            )

        if len(packet) == 0:
            raise ValueError(
                "Cannot send an empty packet"
            )

        packet = bytes(packet)
        require_kms_server_access(
            self.host,
            self.port,
            "send a UDP packet to KMS",
        )

        print()
        print("=" * 60)
        print("KMS UDP SEND")
        print("=" * 60)

        print(
            f"Destination : {self.host}:{self.port}"
        )

        print(
            f"Length      : {len(packet)} bytes"
        )

        print(
            f"HEX         : {self._hex(packet)}"
        )

        sock = self._create_socket()

        try:

            bytes_sent = sock.sendto(
                packet,
                (self.host, self.port)
            )

            print(
                f"Sent        : {bytes_sent} bytes"
            )

            return bytes_sent

        finally:

            sock.close()

    # ---------------------------------------------------------
    # Receive
    # ---------------------------------------------------------

    def receive(
        self,
        expected_type: Optional[int] = None,
    ) -> Tuple[bytes, Tuple[str, int]]:
        """
        Receive UDP response.

        Parameters:
            expected_type:
                Expected KMS message type.

                Examples:
                    0x91
                    0x93
                    0x95

                If None, first received packet is returned.

        Returns:
            (response_bytes, sender_address)

        Raises:
            TimeoutError
            ConnectionError
            ValueError
        """

        require_kms_server_access(
            self.host,
            self.port,
            "receive a UDP response from KMS",
        )
        sock = self._create_socket()

        try:

            while True:

                try:

                    response, sender = sock.recvfrom(
                        self.recv_buffer_size
                    )

                except socket.timeout:

                    raise TimeoutError(
                        f"KMS UDP response timeout after "
                        f"{self.timeout} seconds "
                        f"from {self.host}:{self.port}"
                    )

                except OSError as exc:

                    raise ConnectionError(
                        f"UDP receive failed: {exc}"
                    ) from exc

                # ---------------------------------------------
                # Basic validation
                # ---------------------------------------------

                if not response:

                    print(
                        "Received empty UDP packet. "
                        "Ignoring..."
                    )

                    continue

                actual_type = self._message_type(
                    response
                )

                print()
                print("=" * 60)
                print("KMS UDP RECEIVE")
                print("=" * 60)

                print(
                    f"Source      : {sender[0]}:{sender[1]}"
                )

                print(
                    f"Length      : {len(response)} bytes"
                )

                print(
                    f"HEX         : {self._hex(response)}"
                )

                if actual_type is not None:

                    print(
                        f"Message Type: 0x{actual_type:02X}"
                    )

                # ---------------------------------------------
                # Expected message type
                # ---------------------------------------------

                if expected_type is not None:

                    expected_type = int(
                        expected_type
                    ) & 0xFF

                    if actual_type != expected_type:

                        actual_text = (
                            "UNKNOWN"
                            if actual_type is None
                            else f"0x{actual_type:02X}"
                        )

                        print(
                            f"Unexpected packet type "
                            f"{actual_text}; "
                            f"expected "
                            f"0x{expected_type:02X}. "
                            f"Ignoring packet..."
                        )

                        # Continue waiting for correct response.
                        continue

                    print(
                        f"Expected response "
                        f"0x{expected_type:02X} received."
                    )

                return response, sender

        finally:

            sock.close()

    # ---------------------------------------------------------
    # Send + Receive
    # ---------------------------------------------------------

    def send_and_receive(
        self,
        packet: bytes,
        expected_type: Optional[int] = None,
    ) -> bytes:
        """
        Send a packet and wait for its response.

        This is the main method used by the KMS flow.

        Examples:

            0x90 -> 0x91

                response = client.send_and_receive(
                    packet,
                    expected_type=0x91
                )

            0x92 -> 0x93

                response = client.send_and_receive(
                    packet,
                    expected_type=0x93
                )

            0x94 -> 0x95

                response = client.send_and_receive(
                    packet,
                    expected_type=0x95
                )

        Backward compatible:

            response = client.send_and_receive(packet)

        In that case the first received packet is returned.
        """

        if not isinstance(packet, (bytes, bytearray)):
            raise TypeError(
                "packet must be bytes or bytearray"
            )

        if len(packet) == 0:
            raise ValueError(
                "Cannot send an empty packet"
            )

        packet = bytes(packet)
        require_kms_server_access(
            self.host,
            self.port,
            "send a request to and receive a response from KMS",
        )

        print()
        print("=" * 60)
        print("KMS UDP TRANSACTION")
        print("=" * 60)

        print(
            f"Destination : {self.host}:{self.port}"
        )

        print(
            f"Request Len : {len(packet)} bytes"
        )

        print(
            f"Request HEX : {self._hex(packet)}"
        )

        if expected_type is not None:

            print(
                f"Expected    : "
                f"0x{int(expected_type) & 0xFF:02X}"
            )

        sock = self._create_socket()

        try:

            # -------------------------------------------------
            # SEND
            # -------------------------------------------------

            try:

                bytes_sent = sock.sendto(
                    packet,
                    (self.host, self.port)
                )

            except OSError as exc:

                raise ConnectionError(
                    f"Failed to send UDP packet to "
                    f"{self.host}:{self.port}: {exc}"
                ) from exc

            print()
            print(
                f"UDP packet sent successfully "
                f"({bytes_sent} bytes)"
            )

            # -------------------------------------------------
            # RECEIVE
            # -------------------------------------------------

            while True:

                try:

                    response, sender = sock.recvfrom(
                        self.recv_buffer_size
                    )

                except socket.timeout:

                    raise TimeoutError(
                        f"No expected response received "
                        f"from KMS {self.host}:{self.port} "
                        f"within {self.timeout} seconds"
                    )

                except OSError as exc:

                    raise ConnectionError(
                        f"Failed while receiving UDP response: "
                        f"{exc}"
                    ) from exc

                # -------------------------------------------------
                # Empty response
                # -------------------------------------------------

                if not response:

                    print(
                        "Received empty UDP packet. "
                        "Ignoring..."
                    )

                    continue

                # -------------------------------------------------
                # Message Type
                # -------------------------------------------------

                actual_type = self._message_type(
                    response
                )

                print()
                print("=" * 60)
                print("KMS UDP RESPONSE")
                print("=" * 60)

                print(
                    f"Source      : {sender[0]}:{sender[1]}"
                )

                print(
                    f"Length      : {len(response)} bytes"
                )

                print(
                    f"HEX         : {self._hex(response)}"
                )

                if actual_type is not None:

                    print(
                        f"Message Type: 0x{actual_type:02X}"
                    )

                # -------------------------------------------------
                # Expected Type Check
                # -------------------------------------------------

                if expected_type is not None:

                    expected = (
                        int(expected_type) & 0xFF
                    )

                    if actual_type != expected:

                        actual_text = (
                            "UNKNOWN"
                            if actual_type is None
                            else f"0x{actual_type:02X}"
                        )

                        print(
                            f"Ignoring unexpected "
                            f"response {actual_text}; "
                            f"waiting for "
                            f"0x{expected:02X}..."
                        )

                        continue

                print()
                print(
                    "Correct KMS response received."
                )

                return response

        finally:

            sock.close()

    # ---------------------------------------------------------
    # Context Manager
    # ---------------------------------------------------------

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback
    ):
        return False


# =============================================================
# Simple Manual Test
# =============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("KMS UDP CLIENT TEST")
    print("=" * 60)

    KMS_IP = "112.133.205.6"
    KMS_PORT = 54143

    client = KmsUdpClient(
        host=KMS_IP,
        port=KMS_PORT,
        timeout=10
    )

    print()
    print(
        f"KMS Server: {KMS_IP}:{KMS_PORT}"
    )

    print()
    print(
        "udp_client.py loaded successfully."
    )
