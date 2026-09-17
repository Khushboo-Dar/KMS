"""Tests for KMS server access confirmation behavior."""

import unittest
from unittest.mock import patch

from KMS_client.kms_server_access import KmsServerAccessDenied
from KMS_client.udp_client import KmsUdpClient


class KmsServerAccessConfirmationTests(unittest.TestCase):
    def setUp(self):
        self.client = KmsUdpClient(host="127.0.0.1", port=54143)

    @patch("builtins.input", return_value="yes")
    @patch("KMS_client.udp_client.socket.socket")
    def test_send_opens_socket_after_yes(self, socket_factory, _input):
        socket_factory.return_value.sendto.return_value = 1

        self.assertEqual(self.client.send(b"\x90"), 1)
        socket_factory.assert_called_once()

    @patch("builtins.input", return_value="no")
    @patch("KMS_client.udp_client.socket.socket")
    def test_send_does_not_open_socket_after_no(self, socket_factory, _input):
        with self.assertRaises(KmsServerAccessDenied):
            self.client.send(b"\x90")

        socket_factory.assert_not_called()

    @patch("builtins.input", return_value="no")
    @patch("KMS_client.udp_client.socket.socket")
    def test_receive_does_not_open_socket_after_no(self, socket_factory, _input):
        with self.assertRaises(KmsServerAccessDenied):
            self.client.receive()

        socket_factory.assert_not_called()

    @patch("builtins.input", return_value="no")
    @patch("KMS_client.udp_client.socket.socket")
    def test_transaction_does_not_open_socket_after_no(
        self, socket_factory, _input
    ):
        with self.assertRaises(KmsServerAccessDenied):
            self.client.send_and_receive(b"\x90")

        socket_factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
