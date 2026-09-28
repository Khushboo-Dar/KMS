#!/usr/bin/env python3
"""Calculate and compare the MAC from the MAC TEST vector.

The two reference documents are not identical in their key-selection text.
This script follows the concrete MAC TEST instruction requested for this
vector:

    key_index = (kavach_id + loco_id) % 2

The selected authentication key is used directly.  No session-key
derivation is performed.

MAC calculation follows the CBC-MAC description in Annexure-G:

* append zero octets until the input is a multiple of 16 bytes;
* start CBC with a zero 16-byte chaining value;
* AES-128-encrypt each XORed block;
* use the first four bytes of the final chaining value as MAC_CODE.

Run with no arguments to reproduce the values in ``MAC TEST.docx``.  The
hex input, keys, IDs, and expected MAC can also be overridden on the command
line for another test vector.
"""

from __future__ import annotations

import argparse
import binascii
import hmac
import re
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Defaults copied from MAC TEST.docx.
DEFAULT_KAVACH_ID = 50002
DEFAULT_LOCO_ID = 65551
DEFAULT_INPUT_HEX = (
    "18 00 23 05 47 01 00 0F 61 78 01 18 09 1A "
    "0F 05 08 03 00 10 6A 00 10 68 00 10 6C"
)
DEFAULT_KEY_0_HEX = "E7 16 07 4C 91 66 52 6F 33 07 E6 C0 71 C1 18 EF"
DEFAULT_KEY_1_HEX = "7A D4 63 7D 0C B9 80 DC 70 BC 7A A5 D4 3C 2B 41"
DEFAULT_EXPECTED_MAC_HEX = "BB 01 BD 09"

AES_BLOCK_SIZE = 16
MAC_SIZE = 4


def parse_hex(value: str, label: str) -> bytes:
    """Parse hex with optional spaces, commas, and ``0x`` prefixes."""
    cleaned = re.sub(r"0x", "", value, flags=re.IGNORECASE)
    cleaned = re.sub(r"[\s,;:_-]+", "", cleaned)
    if not cleaned:
        raise ValueError(f"{label} must contain hexadecimal bytes")
    if len(cleaned) % 2:
        raise ValueError(f"{label} has an odd number of hexadecimal digits")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"{label} is not valid hexadecimal: {value!r}") from exc


def aes128_encrypt(key: bytes, block: bytes) -> bytes:
    """Encrypt one 16-byte block with AES-128."""
    if len(key) != AES_BLOCK_SIZE:
        raise ValueError(f"AES-128 key must be 16 bytes, got {len(key)}")
    if len(block) != AES_BLOCK_SIZE:
        raise ValueError(f"AES block must be 16 bytes, got {len(block)}")
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def cbc_mac(key: bytes, message: bytes) -> tuple[bytes, bytes, int]:
    """Return ``(full_mac_block, padded_message, loop_count)``.

    This is written as the CBC-MAC iteration instead of relying on a CBC
    helper so the zero-IV and two-block loop are explicit and inspectable.
    An already block-aligned message receives no extra block, matching the
    Annexure-G wording that only the zero octets needed are appended.
    """
    if not message:
        raise ValueError("MAC input must not be empty")

    pad_len = (-len(message)) % AES_BLOCK_SIZE
    padded = message + (b"\x00" * pad_len)
    state = b"\x00" * AES_BLOCK_SIZE

    for offset in range(0, len(padded), AES_BLOCK_SIZE):
        block = padded[offset : offset + AES_BLOCK_SIZE]
        state = aes128_encrypt(
            key,
            bytes(left ^ right for left, right in zip(state, block)),
        )

    return state, padded, len(padded) // AES_BLOCK_SIZE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Calculate and compare the MAC TEST CBC-MAC vector."
    )
    parser.add_argument(
        "--input",
        dest="message_hex",
        default=DEFAULT_INPUT_HEX,
        help="MAC input bytes in hex (default: MAC TEST vector)",
    )
    parser.add_argument(
        "--kavach-id",
        "--server-id",
        dest="kavach_id",
        type=int,
        default=DEFAULT_KAVACH_ID,
        help=f"Kavach/Server ID used for key selection (default: {DEFAULT_KAVACH_ID})",
    )
    parser.add_argument(
        "--loco-id",
        type=int,
        default=DEFAULT_LOCO_ID,
        help=f"Loco ID used for key selection (default: {DEFAULT_LOCO_ID})",
    )
    parser.add_argument(
        "--key0",
        default=DEFAULT_KEY_0_HEX,
        help="CurKey[0] in hex (default: MAC TEST vector)",
    )
    parser.add_argument(
        "--key1",
        default=DEFAULT_KEY_1_HEX,
        help="CurKey[1] in hex (default: MAC TEST vector)",
    )
    parser.add_argument(
        "--expected",
        default=DEFAULT_EXPECTED_MAC_HEX,
        help="Expected/written MAC_CODE in hex (default: BB 01 BD 09)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="return exit status 1 when the calculated MAC differs",
    )
    return parser


def format_hex(value: bytes) -> str:
    return " ".join(f"{byte:02X}" for byte in value)


def run(args: argparse.Namespace) -> bool:
    message = parse_hex(args.message_hex, "MAC input")
    key0 = parse_hex(args.key0, "CurKey[0]")
    key1 = parse_hex(args.key1, "CurKey[1]")
    expected = parse_hex(args.expected, "expected MAC")

    if len(key0) != AES_BLOCK_SIZE or len(key1) != AES_BLOCK_SIZE:
        raise ValueError("CurKey[0] and CurKey[1] must each be 16 bytes")
    if len(expected) != MAC_SIZE:
        raise ValueError("expected MAC must be exactly 4 bytes")
    if args.kavach_id < 0 or args.loco_id < 0:
        raise ValueError("Kavach ID and Loco ID must be non-negative")

    key_index = (args.kavach_id + args.loco_id) % 2
    selected_key = (key0, key1)[key_index]
    full_mac, padded_message, loop_count = cbc_mac(selected_key, message)
    calculated = full_mac[:MAC_SIZE]
    matches = hmac.compare_digest(calculated, expected)

    print("=" * 72)
    print("KAVACH CBC-MAC calculation")
    print("=" * 72)
    print(f"MAC input         : {format_hex(message)}")
    print(f"Input length      : {len(message)} bytes")
    print(f"Padded input      : {format_hex(padded_message)}")
    print(f"Padding           : {len(padded_message) - len(message)} zero byte(s)")
    print(f"Kavach/Server ID  : {args.kavach_id}")
    print(f"Loco ID           : {args.loco_id}")
    print(
        f"Key index         : ({args.kavach_id} + {args.loco_id}) % 2 "
        f"= {key_index}"
    )
    print(f"Selected key      : CurKey[{key_index}] = {format_hex(selected_key)}")
    print("Session key       : not used")
    print("CBC IV            : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
    print(f"MAC loop count    : {loop_count}")
    print(f"Final MAC block   : {format_hex(full_mac)}")
    print(f"Calculated MAC    : {format_hex(calculated)}")
    print(f"Documented MAC    : {format_hex(expected)}")
    print("Comparison        : " + ("MATCH" if matches else "MISMATCH"))
    print("=" * 72)

    if not matches:
        print(
            "The supplied input, authentication keys, key-selection rule, "
            "and Annexure-G CBC-MAC procedure do not reproduce the written MAC."
        )
    return matches


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        matches = run(args)
    except (ValueError, binascii.Error) as exc:
        parser.error(str(exc))
    return 1 if args.strict and not matches else 0


if __name__ == "__main__":
    sys.exit(main())
