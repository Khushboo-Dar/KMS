#!/usr/bin/env python3
"""
KAVACH GPRS/LTE MAC tool — combined generator + verifier
========================================================
Packet types handled: 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x20

ALGORITHM:
    1. Key Index = (Server_ID + Loco_ID) % 2
       Server_ID is THIS UNIT'S OWN FIXED ID (from .env as KAVACH_ID).
       Loco_ID is read from the packet, bytes 7-9.
    2. Key Index 0 -> Authentication Key 1. Key Index 1 -> Authentication Key 2.
    3. The selected Authentication Key (KA) is the initial Working Key.
    4. MAC input = bytes from Message Type through the last payload byte.
    5. Zero-pad the MAC input to a multiple of 16 bytes.
    6. For each 16-byte block, in order:
           Cipher Block = AES-128-CBC (Working Key, Zero IV, block)
           Working Key  = Cipher Block
    7. After the last block, the Working Key holds the final 16-byte block.
    8. Compute CRC-32/XFER over that final 16-byte block.
    9. The resulting 32-bit value, written MSB-first (big-endian), is MAC_CODE.
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
# 1. Load .env
# =====================================================================
def _load_dotenv(env_path: Path) -> None:
    if not env_path.is_file():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        os.environ.setdefault(key, value)

_load_dotenv(Path(__file__).resolve().parent / ".env")

def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        sys.exit(f"Missing required environment variable: {name}")
    return value

def _require_env_int(name: str) -> int:
    raw = _require_env(name)
    try:
        return int(raw, 0)
    except ValueError:
        sys.exit(f"Environment variable {name} must be an integer, got: {raw!r}")

ORACLE_USER     = _require_env("ORACLE_USER")
ORACLE_PASSWORD = _require_env("ORACLE_PASSWORD")
ORACLE_DSN      = _require_env("ORACLE_DSN")
DB_KEY_B64      = _require_env("KMS_DB_ENCRYPTION_KEY_B64")
KAVACH_ID       = _require_env_int("KAVACH_ID")
TABLE           = "KMS_KEY_SETS"

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
SOF_E1    = bytes.fromhex("AAAA")
SECURITY_TRAILER_LEN = MAC_LEN + CRC_LEN
ZERO_IV   = b"\x00" * AES_BLOCK

ALLOWED_SOFS = {
    0x18: (SOF,),
    0x19: (SOF_E1, SOF),
    0x1A: (SOF,),
    0x1B: (SOF,),
    0x1C: (SOF,),
    0x20: (SOF,),
}

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
    return (kid, k1e, k2e,
            _decrypt_key(k1e, f"{TABLE}|KEY_1|{kid}", gcm),
            _decrypt_key(k2e, f"{TABLE}|KEY_2|{kid}", gcm))

def select_key(k1: bytes, k2: bytes, loco_id: int):
    idx = (KAVACH_ID + loco_id) % 2
    key = k1 if idx == 0 else k2
    return idx, key

# =====================================================================
# 4. MAC computation
# =====================================================================
def crc32_xfer(data: bytes) -> int:
    poly = 0xEDB88320
    crc  = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (poly if (crc & 1) else 0)
    return crc & 0xFFFFFFFF

def packet_crc(data: bytes) -> bytes:
    return crc32_xfer(data).to_bytes(CRC_LEN, "big")

def oem_mac_code(ka: bytes, mac_input: bytes) -> bytes:
    if len(ka) != AES_BLOCK:
        raise ValueError(f"KA must be {AES_BLOCK} bytes, got {len(ka)}")
    pad = (-len(mac_input)) % AES_BLOCK
    padded = mac_input + b"\x00" * pad
    working = ka
    for i in range(0, len(padded), AES_BLOCK):
        block = padded[i:i + AES_BLOCK]
        # Using CBC mode with Zero IV per block, exactly as the spec states.
        working = AES.new(working, AES.MODE_CBC, iv=ZERO_IV).encrypt(block)
    return crc32_xfer(working).to_bytes(4, "big")

# =====================================================================
# 5. Self-test
# =====================================================================
def self_test(verbose: bool = True) -> bool:
    server_id     = 50002
    loco_id       = 65551
    ka_hex        = "7AD4637D0CB980DC70BC7AA5D43C2B41"
    mac_input_hex = "180023054701000F61780118091A0F05080300106A00106800106C"
    expected_hex  = "BB01BD09"
    annex_crc_input_hex    = "B32AB7F0210409D490411A80CC16082B4A04C0A3CCFE"
    annex_crc_expected_hex = "B93EE60A"

    ka       = bytes.fromhex(ka_hex)
    mac_in   = bytes.fromhex(mac_input_hex)
    expected = bytes.fromhex(expected_hex)
    annex_crc          = packet_crc(bytes.fromhex(annex_crc_input_hex))
    annex_crc_expected = bytes.fromhex(annex_crc_expected_hex)

    idx = (server_id + loco_id) % 2
    computed = oem_mac_code(ka, mac_in)
    mac_ok = computed == expected
    crc_ok = annex_crc == annex_crc_expected
    ok = mac_ok and crc_ok

    if verbose:
        print("=" * 62)
        print(" Self-test — OEM reference vector")
        print("=" * 62)
        print(f" Computed MAC           : {computed.hex().upper()}")
        print(f" Expected MAC           : {expected.hex().upper()}")
        print(f" Result                 : {'PASS' if ok else 'FAIL'}")
        print("=" * 62)

    return ok

# =====================================================================
# 6. Packet parsing
# =====================================================================
def _clean_hex(s: str) -> str:
    s = s.strip().replace(" ", "").replace("\n", "").replace("\r", "")
    if s.lower().startswith("0x"):
        s = s[2:]
    return s

def _parse_header(pkt: bytes, *, need_mac: bool):
    min_len = 19 + (SECURITY_TRAILER_LEN if need_mac else 0)
    if len(pkt) < min_len:
        print("Packet too short — MAC code not present in packet")
        sys.exit(0)

    msg_type = pkt[2]
    if msg_type not in GPRS_TYPES:
        print(f"Packet type 0x{msg_type:02X} is not MAC-protected")
        sys.exit(0)

    allowed_sofs = ALLOWED_SOFS[msg_type]
    if pkt[:2] not in allowed_sofs:
        print(f"Invalid SOF {pkt[:2].hex().upper()} for packet type 0x{msg_type:02X}")
        sys.exit(0)

    msg_len = int.from_bytes(pkt[3:5], "big")
    loco_id = int.from_bytes(pkt[7:10], "big")
    dd, mm, yy = pkt[13], pkt[14], pkt[15]
    hh, minute, second = pkt[16], pkt[17], pkt[18]
    try:
        pkt_date = datetime.datetime(2000 + yy, mm, dd, hh, minute, second)
    except ValueError:
        print(f"Bad date/time in packet: {dd:02d}/{mm:02d}/20{yy:02d}")
        sys.exit(0)

    return msg_type, loco_id, pkt_date, msg_len

# =====================================================================
# 7. Generate mode
# =====================================================================
def generate_mode():
    raw = _clean_hex(input("Packet hex > "))
    pkt = bytes.fromhex(raw)

    msg_type, loco_id, pkt_date, msg_len = _parse_header(pkt, need_mac=False)
    expected_total = 2 + msg_len

    if len(pkt) == expected_total:
        mac_input = pkt[2:-SECURITY_TRAILER_LEN]
        head = pkt[:-SECURITY_TRAILER_LEN]
    elif len(pkt) == expected_total - SECURITY_TRAILER_LEN:
        mac_input = pkt[2:]
        head = pkt
    else:
        print(f"Invalid packet length. Expected {expected_total} or {expected_total - SECURITY_TRAILER_LEN}")
        return

    print("=" * 62)
    print(" GENERATE — MAC_CODE computation")
    print("=" * 62)
    print(f" Packet Type            : 0x{msg_type:02X}  ({NAMES[msg_type]})")
    print(f" Loco ID                : {loco_id}")
    print(f" Packet Timestamp       : {pkt_date:%d-%b-%Y %H:%M:%S} IST")
    print(f" MAC Input              : {mac_input.hex().upper()}")

    try:
        kid, enc_k1, enc_k2, k1, k2 = load_key_pair_for(pkt_date)
    except Exception as e:
        print(f"[KMS] {type(e).__name__}: {e}")
        return

    idx, key = select_key(k1, k2, loco_id)
    enc_blob = enc_k1 if idx == 0 else enc_k2

    print("-" * 62)
    print(f" Key Set ID             : {kid}")
    print(f" Key Index              : ({KAVACH_ID} + {loco_id}) % 2 = {idx}  -> Key {idx + 1}")
    print(f" Selected Key (hex)     : {key.hex().upper()}")

    mac = oem_mac_code(key, mac_input)
    crc = packet_crc(mac_input + mac)
    full_packet = head + mac + crc

    print("-" * 62)
    print(f" Calculated MAC_CODE    : {mac.hex().upper()}")
    print(f" Reconstructed packet   : {full_packet.hex().upper()}")
    print(f" Packet CRC             : VALID")
    print("=" * 62)

# =====================================================================
# 8. Verify mode
# =====================================================================
def verify_mode():
    raw = _clean_hex(input("Packet hex > "))
    pkt = bytes.fromhex(raw)

    msg_type, loco_id, pkt_date, msg_len = _parse_header(pkt, need_mac=True)
    expected_total = 2 + msg_len
    if len(pkt) != expected_total:
        print(f"Invalid packet length: expected {expected_total}, got {len(pkt)}")
        return

    mac_input    = pkt[2:-SECURITY_TRAILER_LEN]
    received_mac = pkt[-SECURITY_TRAILER_LEN:-CRC_LEN]
    received_crc = pkt[-CRC_LEN:]

    print("=" * 62)
    print(" VERIFY — MAC_CODE check")
    print("=" * 62)
    print(f" Packet Type            : 0x{msg_type:02X}  ({NAMES[msg_type]})")
    print(f" Loco ID                : {loco_id}")
    print(f" Packet Timestamp       : {pkt_date:%d-%b-%Y %H:%M:%S} IST")
    print(f" MAC Input              : {mac_input.hex().upper()}")

    if received_mac == b"\x00\x00\x00\x00":
        print("MAC code not present in packet")
        return

    try:
        kid, enc_k1, enc_k2, k1, k2 = load_key_pair_for(pkt_date)
    except Exception as e:
        print(f"[KMS] {type(e).__name__}: {e}")
        return

    idx, key = select_key(k1, k2, loco_id)
    alternate_idx = 1 - idx
    alternate_key = k2 if idx == 0 else k1

    computed_mac  = oem_mac_code(key, mac_input)
    alternate_mac = oem_mac_code(alternate_key, mac_input)
    crc_ok        = packet_crc(mac_input + received_mac) == received_crc

    print("-" * 62)
    print(f" Key Set ID             : {kid}")
    print(f" Key Index              : ({KAVACH_ID} + {loco_id}) % 2 = {idx}  -> Key {idx + 1}")
    print(f" Selected Key (hex)     : {key.hex().upper()}")
    print(f" Received MAC           : {received_mac.hex().upper()}")
    print(f" Computed MAC           : {computed_mac.hex().upper()}")
    print("-" * 62)
    
    if computed_mac == received_mac:
        print(" Result                 : ✅ MAC is VALID")
    else:
        print(" Result                 : ❌ MAC is INVALID for selected key")
    print("=" * 62)

    if computed_mac != received_mac:
        print()
        print("=" * 62)
        print(" ALTERNATE KEY TEST")
        print("=" * 62)
        print(f" Alternate Key Index    : {alternate_idx}  -> Key {alternate_idx + 1}")
        print(f" Alternate Key (hex)    : {alternate_key.hex().upper()}")
        print(f" Alternate MAC          : {alternate_mac.hex().upper()}")
        print("-" * 62)
        if alternate_mac == received_mac:
            print(f" Result                 : ✅ MATCH (packet signed with Key {alternate_idx + 1})")
        else:
            print(" Result                 : ❌ NO MATCH with either key")
        print("=" * 62)

    print(f" Packet CRC is {'VALID' if crc_ok else 'INVALID'}")

# =====================================================================
# 9. Entry point
# =====================================================================
def main():
    print("=" * 62)
    print(" KAVACH MAC tool  —  generate / verify")
    print("=" * 62)
    print("  1) Generate MAC_CODE")
    print("  2) Verify   MAC_CODE")
    print("  3) Self-test against OEM reference vector")
    choice = input("Choose [1/2/3] > ").strip()

    if choice == "1":
        generate_mode()
    elif choice == "2":
        verify_mode()
    elif choice == "3":
        self_test()
    else:
        print("Invalid choice — enter 1, 2, or 3.")

if __name__ == "__main__":
    main()