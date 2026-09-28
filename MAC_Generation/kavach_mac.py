#!/usr/bin/env python3

import base64
import os
import sys
import datetime
from pathlib import Path

import oracledb
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES


def _load_dotenv(env_path: Path) -> None:
    if not env_path.is_file():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in ("'", '"')
        ):
            value = value[1:-1]

        os.environ.setdefault(key, value)


def _require_env(name: str) -> str:
    value = os.environ.get(name)

    if not value:
        sys.exit(
            f"Missing required environment variable: {name}\n"
            f"Add it to the .env file next to this script."
        )

    return value


def _require_env_int(name: str) -> int:
    raw = _require_env(name)

    try:
        return int(raw, 0)
    except ValueError:
        sys.exit(
            f"Environment variable {name} must be an integer, got: {raw!r}"
        )


_load_dotenv(Path(__file__).resolve().parent / ".env")


ORACLE_USER = _require_env("ORACLE_USER")
ORACLE_PASSWORD = _require_env("ORACLE_PASSWORD")
ORACLE_DSN = _require_env("ORACLE_DSN")
DB_KEY_B64 = _require_env("KMS_DB_ENCRYPTION_KEY_B64")
KAVACH_ID = _require_env_int("KAVACH_ID")

TABLE = "KMS_KEY_SETS"

GPRS_TYPES = (0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x20)

NAMES = {
    0x18: "Onboard KAVACH Health",
    0x19: "KAVACH Fault",
    0x1A: "Onboard KAVACH Radio (GPRS)",
    0x1B: "Onboard KAVACH Tag Data (GPRS)",
    0x1C: "Onboard KAVACH DMI Events (GPRS)",
    0x20: "Loco KAVACH RSSI",
}

SOF = b"\xBB\xBB"
MAC_LEN = 4
CRC_LEN = 4
AES_BLOCK = 16
ZERO_IV = b"\x00" * AES_BLOCK


def _decrypt_key(blob: str, aad: str, gcm: AESGCM) -> bytes:
    if not blob.startswith("v1:"):
        raise ValueError(f"bad blob prefix: {blob[:12]!r}")

    b64 = blob[3:] + "=" * (-len(blob[3:]) % 4)
    raw = base64.b64decode(b64)

    plaintext = gcm.decrypt(
        raw[:12],
        raw[12:],
        aad.encode("utf-8"),
    )

    try:
        value = plaintext.decode("utf-8")
        bytes.fromhex(value)
        return bytes.fromhex(value)
    except (UnicodeDecodeError, ValueError):
        return plaintext


def load_key_pair_for(packet_date: datetime.datetime):
    gcm = AESGCM(base64.b64decode(DB_KEY_B64))

    sql = f"""
        SELECT KEY_SET_ID, KEY_1, KEY_2
        FROM {TABLE}
        WHERE VALID_FROM <= :d
          AND VALID_TO >= :d
        ORDER BY VALID_FROM
        FETCH FIRST 1 ROWS ONLY
    """

    with oracledb.connect(
        user=ORACLE_USER,
        password=ORACLE_PASSWORD,
        dsn=ORACLE_DSN,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql, d=packet_date)
            row = cursor.fetchone()

    if not row:
        raise LookupError(
            f"No key set covers {packet_date:%Y-%m-%d}"
        )

    key_set_id, key1_encrypted, key2_encrypted = row

    key1 = _decrypt_key(
        key1_encrypted,
        f"{TABLE}|KEY_1|{key_set_id}",
        gcm,
    )

    key2 = _decrypt_key(
        key2_encrypted,
        f"{TABLE}|KEY_2|{key_set_id}",
        gcm,
    )

    return key1, key2


def select_key(k1: bytes, k2: bytes, loco_id: int):
    index = (KAVACH_ID + loco_id) % 2
    key = k1 if index == 0 else k2

    print(
        f"Key selection : "
        f"(KAVACH_ID {KAVACH_ID} + Loco_ID {loco_id}) % 2 "
        f"= {index}  -> Key {index + 1}"
    )

    return key


def cbc_mac_code(key: bytes, mac_input: bytes) -> bytes:
    if len(key) != AES_BLOCK:
        raise ValueError(
            f"AES key must be {AES_BLOCK} bytes, got {len(key)}"
        )

    padding_length = (-len(mac_input)) % AES_BLOCK
    padded_input = mac_input + b"\x00" * padding_length

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=ZERO_IV,
    )

    encrypted = cipher.encrypt(padded_input)

    return encrypted[-AES_BLOCK:][:MAC_LEN]


def _clean_hex(value: str) -> str:
    value = (
        value.strip()
        .replace(" ", "")
        .replace("\n", "")
        .replace("\r", "")
    )

    if value.lower().startswith("0x"):
        value = value[2:]

    return value


def _parse_header(pkt: bytes, *, need_mac: bool):
    min_len = 16 + (MAC_LEN + CRC_LEN if need_mac else 0)

    if len(pkt) < min_len:
        print("Packet too short - MAC code not present in packet")
        sys.exit(0)

    if pkt[:2] != SOF:
        print(
            f"Warning: SOF is {pkt[:2].hex().upper()}, "
            f"expected BBBB"
        )

    msg_type = pkt[2]

    if msg_type not in GPRS_TYPES:
        print(
            f"Packet type 0x{msg_type:02X} is not MAC-protected"
        )
        print("MAC code not present in packet")
        sys.exit(0)

    msg_len = int.from_bytes(pkt[3:5], "big")
    loco_id = int.from_bytes(pkt[7:10], "big")
    nms_id_field = int.from_bytes(pkt[10:12], "big")

    dd = pkt[13]
    mm = pkt[14]
    yy = pkt[15]

    try:
        packet_date = datetime.datetime(
            2000 + yy,
            mm,
            dd,
        )
    except ValueError:
        print(
            f"Bad date in packet: "
            f"{dd:02d}/{mm:02d}/20{yy:02d}"
        )
        sys.exit(0)

    return (
        msg_type,
        loco_id,
        nms_id_field,
        packet_date,
        msg_len,
    )


def _print_header(
    msg_type,
    loco_id,
    nms_id_field,
    packet_date,
    packet_length,
    mac_input_length=None,
):
    print("-" * 60)
    print(
        f"Packet type          : "
        f"0x{msg_type:02X}  ({NAMES[msg_type]})"
    )
    print(f"Loco ID (pkt)        : {loco_id}")
    print(
        f"NMS_System_ID (pkt)  : "
        f"{nms_id_field}   (display only)"
    )
    print(
        f"This unit's KAVACH_ID: "
        f"{KAVACH_ID}   (fixed, from .env)"
    )
    print(f"Packet date          : {packet_date:%d-%b-%Y}")
    print(f"Packet length        : {packet_length} bytes")

    if mac_input_length is not None:
        print(f"MAC input length     : {mac_input_length} bytes")


def generate_mode():
    raw = _clean_hex(input("Packet hex > "))
    pkt = bytes.fromhex(raw)

    (
        msg_type,
        loco_id,
        nms_id_field,
        packet_date,
        msg_len,
    ) = _parse_header(pkt, need_mac=False)

    expected_total = 2 + msg_len

    if len(pkt) == expected_total:
        mac_input = pkt[2:-8]
        head = pkt[:-8]
        crc_tail = pkt[-4:]
        mode_note = f"complete packet ({len(pkt)} bytes)"

    elif len(pkt) == expected_total - 8:
        mac_input = pkt[2:]
        head = pkt
        crc_tail = b"\x00\x00\x00\x00"
        mode_note = (
            f"payload only ({len(pkt)} bytes); "
            f"appending MAC + zero CRC"
        )

    else:
        mac_input = pkt[2:-8]
        head = pkt[:-8]
        crc_tail = pkt[-4:]
        mode_note = (
            f"header says {expected_total} bytes, "
            f"got {len(pkt)}; "
            f"assuming last 8 bytes are MAC + CRC"
        )

    print(f"Mode: {mode_note}")

    _print_header(
        msg_type,
        loco_id,
        nms_id_field,
        packet_date,
        len(pkt),
        len(mac_input),
    )

    try:
        k1, k2 = load_key_pair_for(packet_date)
    except Exception as error:
        print(f"[KMS] {type(error).__name__}: {error}")
        return

    key = select_key(k1, k2, loco_id)
    mac = cbc_mac_code(key, mac_input)

    full_packet = head + mac + crc_tail

    print("-" * 60)
    print(
        f"Calculated MAC_CODE        : "
        f"{mac.hex().upper()}"
    )
    print(
        f"Reconstructed packet (hex) : "
        f"{full_packet.hex().upper()}"
    )

    if crc_tail == b"\x00\x00\x00\x00":
        print(
            "NOTE: CRC field is a zero placeholder. "
            "This script does not compute CRC."
        )
        print(
            "Run your CRC generator on the reconstructed packet."
        )

    print("=" * 60)


def verify_mode():
    raw = _clean_hex(input("Packet hex > "))
    pkt = bytes.fromhex(raw)

    (
        msg_type,
        loco_id,
        nms_id_field,
        packet_date,
        msg_len,
    ) = _parse_header(pkt, need_mac=True)

    if len(pkt) != 2 + msg_len:
        print(
            f"Warning: header says {2 + msg_len} bytes total, "
            f"got {len(pkt)}"
        )

    mac_input = pkt[2:-8]
    received_mac = pkt[-8:-4]
    received_crc = pkt[-4:]

    _print_header(
        msg_type,
        loco_id,
        nms_id_field,
        packet_date,
        len(pkt),
        len(mac_input),
    )

    if received_mac == b"\x00\x00\x00\x00":
        print("MAC code not present in packet")
        return

    try:
        k1, k2 = load_key_pair_for(packet_date)
    except Exception as error:
        print(f"[KMS] {type(error).__name__}: {error}")
        return

    key = select_key(k1, k2, loco_id)
    computed_mac = cbc_mac_code(key, mac_input)

    print("-" * 60)
    print(f"Received MAC : {received_mac.hex().upper()}")
    print(f"Computed MAC : {computed_mac.hex().upper()}")
    print(f"CRC in packet: {received_crc.hex().upper()}")
    print("-" * 60)

    if computed_mac == received_mac:
        print("MAC is VALID")
    else:
        print("MAC is INVALID")

    print("=" * 60)


def main():
    print("=" * 60)
    print(" KAVACH MAC tool - generate / verify")
    print(f" This unit's KAVACH_ID: {KAVACH_ID}")
    print("=" * 60)
    print("  1) Generate MAC_CODE")
    print("  2) Verify MAC_CODE")

    choice = input("Choose [1/2] > ").strip()

    if choice == "1":
        generate_mode()
    elif choice == "2":
        verify_mode()
    else:
        print("Invalid choice - enter 1 or 2.")


if __name__ == "__main__":
    main()