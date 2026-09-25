#!/usr/bin/env python3
"""
Verifies the MAC_CODE of a KAVACH GPRS/LTE packet
(0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x20).

Just run:  python verify_mac.py
Paste the packet in hex when asked.

Key selection: (NMS_ID + Loco_ID) % 2  (Annexure-G G.3.4).
Key set lookup: the row in KMS_KEY_SETS whose VALID_FROM..VALID_TO
                covers the packet's own date field.

CREDENTIALS: read ONLY from environment variables — there is no fallback
default. Populate these in your .env / secrets manager before running:
    ORACLE_USER
    ORACLE_PASSWORD
    ORACLE_DSN
    KMS_DB_ENCRYPTION_KEY_B64
If any is missing, this script refuses to run rather than silently
falling back to a hardcoded value.
"""
import base64
import os
import datetime
import oracledb
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES

# --------------- config -------------------------------------------------
def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable: {name}. "
            "Set it in your .env / secrets manager — this script does not "
            "fall back to a hardcoded default for credentials."
        )
    return value

ORACLE_USER     = _require_env("ORACLE_USER")
ORACLE_PASSWORD = _require_env("ORACLE_PASSWORD")
ORACLE_DSN      = _require_env("ORACLE_DSN")
DB_KEY_B64      = _require_env("KMS_DB_ENCRYPTION_KEY_B64")
TABLE = "KMS_KEY_SETS"

GPRS_TYPES = (0x18, 0x19, 0x20, 0x1A, 0x1B, 0x1C)
SOF        = b"\xBB\xBB"
MAC_LEN    = 4
CRC_LEN    = 4
AES_BLOCK  = 16
ZERO_IV    = b"\x00" * AES_BLOCK
NAMES = {
    0x18: "Onboard KAVACH Health",
    0x19: "KAVACH Fault",
    0x1A: "Onboard KAVACH Radio (GPRS)",
    0x1B: "Onboard KAVACH Tag Data (GPRS)",
    0x1C: "Onboard KAVACH DMI Events (GPRS)",
    0x20: "Loco KAVACH RSSI",
}

# --------------- KMS ----------------------------------------------------
def _decrypt_key(blob: str, aad: str, gcm: AESGCM) -> bytes:
    if not blob.startswith("v1:"):
        raise ValueError(f"bad blob prefix: {blob[:12]!r}")
    b64 = blob[3:] + "=" * (-len(blob[3:]) % 4)
    raw = base64.b64decode(b64)
    pt  = gcm.decrypt(raw[:12], raw[12:], aad.encode("utf-8"))
    try:
        s = pt.decode("utf-8"); bytes.fromhex(s); return bytes.fromhex(s)
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

# --------------- CBC-MAC -------------------------------------------------
def cbc_mac_code(key: bytes, mac_input: bytes) -> bytes:
    if len(key) != AES_BLOCK:
        raise ValueError(f"AES key must be {AES_BLOCK} bytes, got {len(key)}")
    pad = (-len(mac_input)) % AES_BLOCK
    padded = mac_input + b"\x00" * pad
    return AES.new(key, AES.MODE_CBC, iv=ZERO_IV).encrypt(padded)[-AES_BLOCK:][:MAC_LEN]

# --------------- main ----------------------------------------------------
def main():
    print("=" * 60)
    print(" KAVACH MAC_CODE verifier")
    print("=" * 60)
    raw = input("Packet hex > ").strip().replace(" ", "").replace("\n", "")
    if raw.lower().startswith("0x"):
        raw = raw[2:]
    pkt = bytes.fromhex(raw)

    # Minimum length to safely read through the Date field (offset 13-15)
    # plus MAC(4) + CRC(4) at the tail.
    if len(pkt) < 16 + MAC_LEN + CRC_LEN:
        print("Packet too short — MAC code not present in packet"); return
    if pkt[:2] != SOF:
        print(f"Warning: SOF is {pkt[:2].hex().upper()}, expected BBBB")

    msg_type = pkt[2]
    if msg_type not in GPRS_TYPES:
        print(f"Packet type 0x{msg_type:02X} is not MAC-protected")
        print("MAC code not present in packet"); return

    msg_len = int.from_bytes(pkt[3:5], "big")
    if len(pkt) != 2 + msg_len:
        print(f"Warning: header says {2 + msg_len} bytes total, got {len(pkt)}")

    loco_id = int.from_bytes(pkt[7:10],  "big")
    nms_id  = int.from_bytes(pkt[10:12], "big")
    dd, mm, yy = pkt[13], pkt[14], pkt[15]
    pkt_date = datetime.datetime(2000 + yy, mm, dd)

    mac_input    = pkt[2:-8]
    received_mac = pkt[-8:-4]
    received_crc = pkt[-4:]

    print("-" * 60)
    print(f"Packet type   : 0x{msg_type:02X}  ({NAMES[msg_type]})")
    print(f"NMS System ID : {nms_id}")
    print(f"Loco ID       : {loco_id}")
    print(f"Packet date   : {pkt_date:%d-%b-%Y}")
    print(f"Packet length : {len(pkt)} bytes")
    print(f"MAC input len : {len(mac_input)} bytes")

    if received_mac == b"\x00\x00\x00\x00":
        print("MAC code not present in packet"); return

    try:
        k1, k2 = load_key_pair_for(pkt_date)
    except Exception as e:
        print(f"[KMS] {type(e).__name__}: {e}"); return

    idx = (nms_id + loco_id) % 2
    k_nos = k1 if idx == 0 else k2
    print(f"Key selection : ({nms_id} + {loco_id}) % 2 = {idx}  -> Key {idx + 1}")

    computed_mac = cbc_mac_code(k_nos, mac_input)

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


if __name__ == "__main__":
    main()