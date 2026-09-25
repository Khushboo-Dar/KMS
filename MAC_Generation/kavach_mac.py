#!/usr/bin/env python3
"""
KAVACH GPRS/LTE MAC tool — combined generator + verifier
========================================================
Packet types handled: 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x20

Key selection : Key Index = (KAVACH_ID + Loco_ID) % 2
                    0 -> Authentication Key 1
                    1 -> Authentication Key 2
                (Annexure-G clause G.3.4)

                IMPORTANT — KAVACH_ID here is THIS UNIT'S OWN FIXED
                provisioning identity (the same ID used to poll KMS,
                e.g. 50002) — it is a constant for this deployment,
                NOT the NMS_System_ID field read out of each packet.
                Earlier versions of this tool used the packet's own
                NMS_System_ID field in the formula; that was corrected
                per clarification from the firmware/standards owner.
                The packet's NMS_System_ID field is still read and
                displayed for reference, but no longer feeds the key
                selection formula.

Key set lookup: the row in KMS_KEY_SETS whose VALID_FROM..VALID_TO
                covers the packet's own Date field (bytes 13..15).

Credentials  : loaded automatically from a `.env` file placed next
               to this script. Required keys:
                   ORACLE_USER
                   ORACLE_PASSWORD
                   ORACLE_DSN
                   KMS_DB_ENCRYPTION_KEY_B64
                   KAVACH_ID              (this unit's fixed ID, e.g. 50002)
               No hardcoded fallback is used for any of these.

Usage:
    python kavach_mac.py
    -> choose 1 (generate) or 2 (verify)
    -> paste the packet in hex
"""
import base64
import os
import sys
import datetime
from pathlib import Path

import oracledb
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES


# =====================================================================
# 1. Load .env from the script's own folder
# =====================================================================
def _load_dotenv(env_path: Path) -> None:
    """
    Tiny .env loader that preserves '#' inside values (needed for
    passwords like 'Suraksha#1234').  Existing environment variables
    are NOT overwritten.
    """
    if not env_path.is_file():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key   = key.strip()
        value = value.strip()
        # Strip surrounding single or double quotes only
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        os.environ.setdefault(key, value)


_load_dotenv(Path(__file__).resolve().parent / ".env")


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
        return int(raw, 0)  # base 0 -> accepts "50002" or "0xC352" etc.
    except ValueError:
        sys.exit(f"Environment variable {name} must be an integer, got: {raw!r}")


ORACLE_USER     = _require_env("ORACLE_USER")
ORACLE_PASSWORD = _require_env("ORACLE_PASSWORD")
ORACLE_DSN      = _require_env("ORACLE_DSN")
DB_KEY_B64      = _require_env("KMS_DB_ENCRYPTION_KEY_B64")

# This unit's own fixed provisioning identity — used in the key
# selection formula. NOT read from the packet.
KAVACH_ID       = _require_env_int("KAVACH_ID")

TABLE = "KMS_KEY_SETS"


# =====================================================================
# 2. Constants
# =====================================================================
GPRS_TYPES = (0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x20)
NAMES = {
    0x18: "Onboard KAVACH Health",
    0x19: "KAVACH Fault",
    0x1A: "Onboard KAVACH Radio (GPRS)",
    0x1B: "Onboard KAVACH Tag Data (GPRS)",
    0x1C: "Onboard KAVACH DMI Events (GPRS)",
    0x20: "Loco KAVACH RSSI",
}
SOF       = b"\xBB\xBB"
MAC_LEN   = 4
CRC_LEN   = 4
AES_BLOCK = 16
ZERO_IV   = b"\x00" * AES_BLOCK


# =====================================================================
# 3. KMS helpers
# =====================================================================
def _decrypt_key(blob: str, aad: str, gcm: AESGCM) -> bytes:
    if not blob.startswith("v1:"):
        raise ValueError(f"bad blob prefix: {blob[:12]!r}")
    b64 = blob[3:] + "=" * (-len(blob[3:]) % 4)
    raw = base64.b64decode(b64)
    pt  = gcm.decrypt(raw[:12], raw[12:], aad.encode("utf-8"))
    try:
        s = pt.decode("utf-8")
        bytes.fromhex(s)
        return bytes.fromhex(s)
    except (UnicodeDecodeError, ValueError):
        return pt


def load_key_pair_for(packet_date: datetime.datetime):
    gcm = AESGCM(base64.b64decode(DB_KEY_B64))
    sql = f"""
        SELECT KEY_SET_ID, KEY_1, KEY_2
          FROM {TABLE}
         WHERE VALID_FROM <= :d AND VALID_TO >= :d
         ORDER BY VALID_FROM
         FETCH FIRST 1 ROWS ONLY
    """
    with oracledb.connect(user=ORACLE_USER, password=ORACLE_PASSWORD, dsn=ORACLE_DSN) as c:
        with c.cursor() as cur:
            cur.execute(sql, d=packet_date)
            row = cur.fetchone()
    if not row:
        raise LookupError(f"No key set covers {packet_date:%Y-%m-%d}")
    kid, k1e, k2e = row
    return (
        _decrypt_key(k1e, f"{TABLE}|KEY_1|{kid}", gcm),
        _decrypt_key(k2e, f"{TABLE}|KEY_2|{kid}", gcm),
    )


def select_key(k1: bytes, k2: bytes, loco_id: int):
    """
    Key Index = (KAVACH_ID + Loco_ID) % 2
    KAVACH_ID is this unit's own fixed ID (from .env), NOT the
    packet's NMS_System_ID field.
    """
    idx = (KAVACH_ID + loco_id) % 2
    key = k1 if idx == 0 else k2
    print(f"Key selection : (KAVACH_ID {KAVACH_ID} + Loco_ID {loco_id}) % 2 "
          f"= {idx}  -> Key {idx + 1}")
    return key


# =====================================================================
# 4. CBC-MAC
# =====================================================================
def cbc_mac_code(key: bytes, mac_input: bytes) -> bytes:
    if len(key) != AES_BLOCK:
        raise ValueError(f"AES key must be {AES_BLOCK} bytes, got {len(key)}")
    pad = (-len(mac_input)) % AES_BLOCK
    padded = mac_input + b"\x00" * pad
    return AES.new(key, AES.MODE_CBC, iv=ZERO_IV).encrypt(padded)[-AES_BLOCK:][:MAC_LEN]


# =====================================================================
# 5. Common packet parsing
# =====================================================================
def _clean_hex(s: str) -> str:
    s = s.strip().replace(" ", "").replace("\n", "").replace("\r", "")
    if s.lower().startswith("0x"):
        s = s[2:]
    return s


def _parse_header(pkt: bytes, *, need_mac: bool):
    """
    Returns (msg_type, loco_id, nms_id_field, pkt_date, msg_len).

    nms_id_field is the packet's own NMS_System_ID field (bytes 10:12) —
    read and returned for DISPLAY ONLY. It is not used in key selection;
    see select_key() / KAVACH_ID.

    Exits with a friendly message on any structural error.
    """
    min_len = 16 + (MAC_LEN + CRC_LEN if need_mac else 0)
    if len(pkt) < min_len:
        print("Packet too short — MAC code not present in packet")
        sys.exit(0)
    if pkt[:2] != SOF:
        print(f"Warning: SOF is {pkt[:2].hex().upper()}, expected BBBB")

    msg_type = pkt[2]
    if msg_type not in GPRS_TYPES:
        print(f"Packet type 0x{msg_type:02X} is not MAC-protected")
        print("MAC code not present in packet")
        sys.exit(0)

    msg_len = int.from_bytes(pkt[3:5], "big")
    loco_id = int.from_bytes(pkt[7:10],  "big")
    nms_id_field = int.from_bytes(pkt[10:12], "big")
    dd, mm, yy = pkt[13], pkt[14], pkt[15]
    try:
        pkt_date = datetime.datetime(2000 + yy, mm, dd)
    except ValueError:
        print(f"Bad date in packet: {dd:02d}/{mm:02d}/20{yy:02d}")
        sys.exit(0)

    return msg_type, loco_id, nms_id_field, pkt_date, msg_len


def _print_header(msg_type, loco_id, nms_id_field, pkt_date, pkt_len, mac_input_len=None):
    print("-" * 60)
    print(f"Packet type          : 0x{msg_type:02X}  ({NAMES[msg_type]})")
    print(f"Loco ID (pkt)        : {loco_id}")
    print(f"NMS_System_ID (pkt)  : {nms_id_field}   (display only — not used in key selection)")
    print(f"This unit's KAVACH_ID: {KAVACH_ID}   (fixed, from .env — used in key selection)")
    print(f"Packet date          : {pkt_date:%d-%b-%Y}")
    print(f"Packet length        : {pkt_len} bytes")
    if mac_input_len is not None:
        print(f"MAC input length     : {mac_input_len} bytes")


# =====================================================================
# 6. Generate mode
# =====================================================================
def generate_mode():
    raw = _clean_hex(input("Packet hex > "))
    pkt = bytes.fromhex(raw)

    msg_type, loco_id, nms_id_field, pkt_date, msg_len = _parse_header(pkt, need_mac=False)

    expected_total = 2 + msg_len

    if len(pkt) == expected_total:                    # complete packet
        mac_input = pkt[2:-8]
        head      = pkt[:-8]
        crc_tail  = pkt[-4:]
        mode_note = f"complete packet ({len(pkt)} bytes)"
    elif len(pkt) == expected_total - 8:              # payload only
        mac_input = pkt[2:]
        head      = pkt
        crc_tail  = b"\x00\x00\x00\x00"
        mode_note = f"payload only ({len(pkt)} bytes); appending MAC + zero CRC"
    else:
        mac_input = pkt[2:-8]
        head      = pkt[:-8]
        crc_tail  = pkt[-4:]
        mode_note = (f"header says {expected_total} bytes, got {len(pkt)}; "
                     f"assuming last 8 bytes are MAC + CRC")

    print(f"Mode: {mode_note}")
    _print_header(msg_type, loco_id, nms_id_field, pkt_date, len(pkt), len(mac_input))

    try:
        k1, k2 = load_key_pair_for(pkt_date)
    except Exception as e:
        print(f"[KMS] {type(e).__name__}: {e}")
        return

    key = select_key(k1, k2, loco_id)

    mac = cbc_mac_code(key, mac_input)
    full_packet = head + mac + crc_tail

    print("-" * 60)
    print(f"Calculated MAC_CODE        : {mac.hex().upper()}")
    print(f"Reconstructed packet (hex) : {full_packet.hex().upper()}")
    if crc_tail == b"\x00\x00\x00\x00":
        print("NOTE: CRC field is a zero placeholder — this script does not")
        print("compute CRC. Run your CRC generator on the reconstructed packet.")
    print("=" * 60)


# =====================================================================
# 7. Verify mode
# =====================================================================
def verify_mode():
    raw = _clean_hex(input("Packet hex > "))
    pkt = bytes.fromhex(raw)

    msg_type, loco_id, nms_id_field, pkt_date, msg_len = _parse_header(pkt, need_mac=True)

    if len(pkt) != 2 + msg_len:
        print(f"Warning: header says {2 + msg_len} bytes total, got {len(pkt)}")

    mac_input    = pkt[2:-8]
    received_mac = pkt[-8:-4]
    received_crc = pkt[-4:]

    _print_header(msg_type, loco_id, nms_id_field, pkt_date, len(pkt), len(mac_input))

    if received_mac == b"\x00\x00\x00\x00":
        print("MAC code not present in packet")
        return

    try:
        k1, k2 = load_key_pair_for(pkt_date)
    except Exception as e:
        print(f"[KMS] {type(e).__name__}: {e}")
        return

    key = select_key(k1, k2, loco_id)

    computed_mac = cbc_mac_code(key, mac_input)

    print("-" * 60)
    print(f"Received MAC : {received_mac.hex().upper()}")
    print(f"Computed MAC : {computed_mac.hex().upper()}")
    print(f"CRC in packet: {received_crc.hex().upper()}")
    print("-" * 60)
    if computed_mac == received_mac:
        print("✅ MAC is VALID")
    else:
        print("❌ MAC is INVALID")
    print("=" * 60)


# =====================================================================
# 8. Entry point
# =====================================================================
def main():
    print("=" * 60)
    print(" KAVACH MAC tool  —  generate / verify")
    print(f" This unit's KAVACH_ID: {KAVACH_ID}")
    print("=" * 60)
    print("  1) Generate MAC_CODE")
    print("  2) Verify   MAC_CODE")
    choice = input("Choose [1/2] > ").strip()

    if choice == "1":
        generate_mode()
    elif choice == "2":
        verify_mode()
    else:
        print("Invalid choice — enter 1 or 2.")


if __name__ == "__main__":
    main()