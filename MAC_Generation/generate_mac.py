#!/usr/bin/env python3
"""
Generates the MAC_CODE for a KAVACH GPRS/LTE packet
(0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x20).

Just run:  python generate_mac.py
Paste the packet in hex when asked.

The script accepts two input forms:
  * Complete packet (MAC + CRC slots present at the end) -> MAC is replaced in place.
  * Payload-only packet (no MAC + CRC at the end)         -> MAC + zero-CRC appended.

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
    print(" KAVACH MAC_CODE generator")
    print("=" * 60)
    raw = input("Packet hex > ").strip().replace(" ", "").replace("\n", "")
    if raw.lower().startswith("0x"):
        raw = raw[2:]
    pkt = bytes.fromhex(raw)

    # Minimum length to safely read through the Date field (offset 13-15)
    # before we even attempt MAC/CRC slicing.
    if len(pkt) < 16 or pkt[:2] != SOF:
        print("Error: packet too short or does not start with 0xBBBB"); return

    msg_type = pkt[2]
    if msg_type not in GPRS_TYPES:
        print(f"Error: 0x{msg_type:02X} is not a GPRS MAC-protected type"); return

    msg_len = int.from_bytes(pkt[3:5], "big")
    expected_total = 2 + msg_len

    # ---- figure out where the MAC slot is ----
    if len(pkt) == expected_total:                    # complete packet
        mac_input = pkt[2:-8]
        head      = pkt[:-8]
        crc_tail  = pkt[-4:]
        print(f"Mode: complete packet ({len(pkt)} bytes)")
    elif len(pkt) == expected_total - 8:              # no MAC/CRC yet
        mac_input = pkt[2:]
        head      = pkt
        crc_tail  = b"\x00\x00\x00\x00"
        print(f"Mode: payload only ({len(pkt)} bytes); appending MAC + zero CRC")
    else:
        print(f"Warning: header says {expected_total} bytes, got {len(pkt)}")
        print("Assuming last 8 bytes are MAC + CRC.")
        mac_input = pkt[2:-8]
        head      = pkt[:-8]
        crc_tail  = pkt[-4:]

    # ---- extract IDs and packet date ----
    loco_id = int.from_bytes(pkt[7:10],  "big")
    nms_id  = int.from_bytes(pkt[10:12], "big")
    dd, mm, yy = pkt[13], pkt[14], pkt[15]
    pkt_date = datetime.datetime(2000 + yy, mm, dd)

    print(f"Packet type   : 0x{msg_type:02X}")
    print(f"NMS System ID : {nms_id}")
    print(f"Loco ID       : {loco_id}")
    print(f"Packet date   : {pkt_date:%d-%b-%Y}")

    # ---- key set + mod-2 selection ----
    try:
        k1, k2 = load_key_pair_for(pkt_date)
    except Exception as e:
        print(f"[KMS] {type(e).__name__}: {e}"); return

    idx = (nms_id + loco_id) % 2
    k_nos = k1 if idx == 0 else k2
    print(f"Key selection : ({nms_id} + {loco_id}) % 2 = {idx}  -> Key {idx + 1}")

    mac = cbc_mac_code(k_nos, mac_input)
    full_packet = head + mac + crc_tail

    print("-" * 60)
    print(f"Calculated MAC_CODE          : {mac.hex().upper()}")
    print(f"Reconstructed packet (hex)   : {full_packet.hex().upper()}")
    if crc_tail == b"\x00\x00\x00\x00":
        print("NOTE: CRC field is a zero placeholder — this script does not")
        print("compute CRC. Run your crc_validator.py / CRC generator on the")
        print("reconstructed packet before treating it as final.")
    print("=" * 60)


if __name__ == "__main__":
    main()