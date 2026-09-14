"""
KAVACH KMS UDP Client

Responsible only for:
    - Creating UDP socket
    - Sending packet to KMS
    - Receiving KMS response
    - Handling timeout
    - Closing socket
"""

import socket

from .config import (
    KMS_IP,
    KMS_PORT,
    UDP_TIMEOUT_SECONDS,
    UDP_BUFFER_SIZE,
)


class KmsUdpClient:
    """
    UDP client for communication with KMS.
    """

    def __init__(
        self,
        server_ip: str = KMS_IP,
        server_port: int = KMS_PORT,
        timeout: int = UDP_TIMEOUT_SECONDS,
    ):
        """
        Initialize UDP client.

        Parameters
        ----------
        server_ip:
            KMS server IP.

        server_port:
            KMS UDP port.

        timeout:
            Socket receive timeout in seconds.
        """

        self.server_ip = server_ip

        self.server_port = server_port

        self.timeout = timeout

        self.socket = None

    # ========================================================
    # CREATE SOCKET
    # ========================================================

    def create_socket(self):
        """
        Create UDP socket.
        """

        if self.socket is None:

            self.socket = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            )

            self.socket.settimeout(
                self.timeout
            )

    # ========================================================
    # SEND
    # ========================================================

    def send(
        self,
        packet: bytes
    ) -> int:
        """
        Send packet to KMS.

        Returns:
            Number of bytes sent.
        """

        if not isinstance(packet, bytes):
            raise TypeError(
                "packet must be bytes"
            )

        self.create_socket()

        bytes_sent = self.socket.sendto(
            packet,
            (
                self.server_ip,
                self.server_port
            )
        )

        return bytes_sent

    # ========================================================
    # RECEIVE
    # ========================================================

    def receive(self) -> bytes | None:
        """
        Wait for KMS response.

        Returns:
            Response bytes if received.

            None if timeout occurs.
        """

        self.create_socket()

        try:

            data, address = (
                self.socket.recvfrom(
                    UDP_BUFFER_SIZE
                )
            )

            print(
                f"KMS response received "
                f"from {address[0]}:{address[1]}"
            )

            return data

        except socket.timeout:

            print(
                "KMS response timeout"
            )

            return None

    # ========================================================
    # SEND AND RECEIVE
    # ========================================================

    def send_and_receive(
        self,
        packet: bytes
    ) -> bytes | None:
        """
        Send packet and wait for response.
        """

        self.send(packet)

        return self.receive()

    # ========================================================
    # CLOSE
    # ========================================================

    def close(self):
        """
        Close UDP socket.
        """

        if self.socket is not None:

            self.socket.close()

            self.socket = None

    # ========================================================
    # CONTEXT MANAGER
    # ========================================================

    def __enter__(self):

        self.create_socket()

        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback
    ):

        self.close()


# ============================================================
# DEBUG / TEST
# ============================================================

if __name__ == "__main__":

    print(
        "KAVACH KMS UDP Client"
    )

    print(
        f"KMS Server: "
        f"{KMS_IP}:{KMS_PORT}"
    )

    client = KmsUdpClient()

    try:

        # Test data only
        test_packet = b"TEST"

        print(
            f"Sending: "
            f"{test_packet.hex().upper()}"
        )

        sent = client.send(
            test_packet
        )

        print(
            f"Bytes sent: {sent}"
        )

    finally:

        client.close()