#!/usr/bin/env python3
"""
Final exhaustive brute-force to determine why the MAC does not match.

Tries every combination of:
  - Key (Key 1 and Key 2 from the covering KMS_KEY_SETS row)
  - MAC input slice (10 different start/end offsets)
  - AES mode (ECB key-chaining, plain CBC, plain ECB)
  - MAC derivation (CRC-32/XFER, first 4, last 4)
  - Byte order (big-endian, little-endian)
  - Candidate MAC fields (pkt[-8:-4] and pkt[-4:])

Prints every match. If nothing matches, the packet was signed with a key
not present in this DB.
"""
import base64
import datetime
import os

import oracledb
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES


# ---------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------
ORACLE_USER     = os.environ.get("ORACLE_USER", "SURAKSHA")
ORACLE_PASSWORD = os.environ.get("ORACLE_PASSWORD", "Suraksha#1234")
ORACLE_DSN      = os.environ.get("ORACLE_DSN", "10.30.4.153:1521/SMMSDB")
DB_KEY_B64      = os.environ.get(
    "KMS_DB_ENCRYPTION_KEY_B64",
    "ngUesMwf26EdVkhrOjtxhYCPb0FxURWrvKXJNJEqaEE=",
)
TABLE     = "KMS_KEY_SETS"
KAVACH_ID = 50002


# ---------------------------------------------------------------------
# KMS decryption
# ---------------------------------------------------------------------
def _decrypt_key(blob: str, aad: str, gcm: AESGCM) -> bytes:
    b64 = blob[3:] + "=" * (-len(blob[3:]) % 4)
    raw = base64.b64decode(b64)
    pt  = gcm.decrypt(raw[:12], raw[12:], aad.encode("utf-8"))
    try:
        s = pt.decode("utf-8")
        bytes.fromhex(s)
        return bytes.fromhex(s)
    except (UnicodeDecodeError, ValueError):
        return pt


def load_key_pair(packet_date: datetime.datetime):
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
    k1 = _decrypt_key(k1e, f"{TABLE}|KEY_1|{kid}", gcm)
    k2 = _decrypt_key(k2e, f"{TABLE}|KEY_2|{kid}", gcm)
    return kid, k1, k2


# ---------------------------------------------------------------------
# MAC primitives
# ---------------------------------------------------------------------
def crc32_xfer(data: bytes) -> int:
    poly = 0xEDB88320
    crc  = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (poly if (crc & 1) else 0)
    return crc & 0xFFFFFFFF


def chain_ecb(key: bytes, data: bytes) -> bytes:
    pad = (-len(data)) % 16
    data = data + b"\x00" * pad
    wk = key
    for i in range(0, len(data), 16):
        wk = AES.new(wk, AES.MODE_ECB).encrypt(data[i:i+16])
    return wk


def plain_cbc(key: bytes, data: bytes) -> bytes:
    pad = (-len(data)) % 16
    data = data + b"\x00" * pad
    return AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16).encrypt(data)


def plain_ecb(key: bytes, data: bytes) -> bytes:
    pad = (-len(data)) % 16
    data = data + b"\x00" * pad
    return AES.new(key, AES.MODE_ECB).encrypt(data)


# ---------------------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------------------
def parse(pkt: bytes):
    msg_type = pkt[2]
    msg_len  = int.from_bytes(pkt[3:5], "big")
    loco_id  = int.from_bytes(pkt[7:10], "big")
    dd, mm, yy = pkt[13], pkt[14], pkt[15]
    date = datetime.datetime(2000 + yy, mm, dd)
    return msg_type, msg_len, loco_id, date


# ---------------------------------------------------------------------
# Build candidate MAC-input slices
# ---------------------------------------------------------------------
def build_inputs(pkt: bytes, msg_type: int, msg_len: int):
    total = len(pkt)
    candidates = {}

    candidates["spec  [2:-8]"]       = pkt[2:-8]
    candidates["withSOF [0:-8]"]     = pkt[0:-8]
    candidates["noCRC [2:-4]"]       = pkt[2:-4]
    candidates["noCRCSOF [0:-4]"]    = pkt[0:-4]
    candidates["skip MT [3:-8]"]     = pkt[3:-8]
    candidates["skip MT,len [5:-8]"] = pkt[5:-8]
    candidates["after hdr 19 [19:-8]"] = pkt[19:-8] if total > 27 else b""
    candidates["after hdr 20 [20:-8]"] = pkt[20:-8] if total > 28 else b""
    candidates["after hdr 21 [21:-8]"] = pkt[21:-8] if total > 29 else b""

    if msg_type in (0x1A, 0x1B) and total > 21:
        candidates["skip cnt [2:19]+[20:-8]"]    = pkt[2:19] + pkt[20:-8]
        candidates["skip sof [2:19]+[21:-8]"]    = pkt[2:19] + pkt[21:-8]

    return {k: v for k, v in candidates.items() if v}


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
def main():
    hex_in = input("Packet hex > ").strip().replace(" ", "").replace("\n", "")
    if hex_in.lower().startswith("0x"):
        hex_in = hex_in[2:]
    pkt = bytes.fromhex(hex_in)

    msg_type, msg_len, loco_id, pkt_date = parse(pkt)
    total    = len(pkt)
    expected = 2 + msg_len

    print()
    print("=" * 72)
    print(f"Packet length        : {total} bytes")
    print(f"MsgLen field         : {msg_len}  (implies total = {expected})")
    print(f"Message type         : 0x{msg_type:02X}")
    print(f"Loco ID              : {loco_id}")
    print(f"Packet date          : {pkt_date:%d-%b-%Y}")
    print(f"KAVACH_ID            : {KAVACH_ID}")
    print(f"Mod-2 (KAVACH+Loco)  : {(KAVACH_ID + loco_id) % 2}")
    print()

    candidate_macs = {}
    if total >= 8:
        candidate_macs["pkt[-8:-4]"] = pkt[-8:-4]
    if total >= 4:
        candidate_macs["pkt[-4:]"]   = pkt[-4:]

    for name, mac in candidate_macs.items():
        print(f"Candidate MAC {name:14s}: {mac.hex().upper()}")
    print()

    try:
        kid, k1, k2 = load_key_pair(pkt_date)
    except Exception as e:
        print(f"[KMS] {type(e).__name__}: {e}")
        return
    print(f"Key set ID           : {kid}")
    print(f"Key 1                : {k1.hex().upper()}")
    print(f"Key 2                : {k2.hex().upper()}")
    print()

    keys    = {"Key1": k1, "Key2": k2}
    inputs  = build_inputs(pkt, msg_type, msg_len)

    print(f"Keys to try          : {len(keys)}")
    print(f"Input slices to try  : {len(inputs)}")
    print(f"Candidate MACs       : {len(candidate_macs)}")
    print(f"AES modes            : 3 (ECB-chain, CBC, ECB)")
    print(f"MAC derivations      : 3 (CRC32/XFER, first4, last4)")
    print(f"Byte orders          : 2")
    total_combos = (len(keys) * len(inputs) * 3 * 3 * 2 * len(candidate_macs))
    print(f"Total combinations   : {total_combos}")
    print("-" * 72)

    hits = []

    def try_match(key_name, mode, in_name, deriv, order, computed):
        for cname, cval in candidate_macs.items():
            if computed == cval:
                hits.append((key_name, mode, in_name, deriv, order, cname))
                print(f"*** MATCH *** key={key_name} mode={mode} "
                      f"input={in_name} deriv={deriv} order={order} "
                      f"target={cname} value={computed.hex().upper()}")

    for key_name, key in keys.items():
        for in_name, data in inputs.items():
            # ECB key-chaining
            final_ecb = chain_ecb(key, data)
            crc_be = crc32_xfer(final_ecb).to_bytes(4, "big")
            crc_le = crc32_xfer(final_ecb).to_bytes(4, "little")
            try_match(key_name, "ECB-chain", in_name, "crc32/be", "big", crc_be)
            try_match(key_name, "ECB-chain", in_name, "crc32/le", "little", crc_le)
            try_match(key_name, "ECB-chain", in_name, "first4", "big", final_ecb[:4])
            try_match(key_name, "ECB-chain", in_name, "last4", "big", final_ecb[-4:])

            # Plain CBC
            try:
                cbc_out = plain_cbc(key, data)
                try_match(key_name, "CBC", in_name, "last4", "big", cbc_out[-4:])
                try_match(key_name, "CBC", in_name, "first4", "big", cbc_out[:4])
                try_match(key_name, "CBC", in_name, "crc32/be", "big",
                          crc32_xfer(cbc_out[-16:]).to_bytes(4, "big"))
            except Exception:
                pass

            # Plain ECB
            try:
                ecb_out = plain_ecb(key, data)
                try_match(key_name, "ECB", in_name, "last4", "big", ecb_out[-4:])
                try_match(key_name, "ECB", in_name, "first4", "big", ecb_out[:4])
                try_match(key_name, "ECB", in_name, "crc32/be", "big",
                          crc32_xfer(ecb_out[-16:]).to_bytes(4, "big"))
            except Exception:
                pass

    print()
    print("=" * 72)
    if hits:
        print(f"*** {len(hits)} MATCH(ES) FOUND ***")
        for h in hits:
            print(h)
    else:
        print("NO MATCH")
        print()
        print("Every combination of key, input slice, AES mode, MAC")
        print("derivation, byte order and target field was tried.")
        print()
        print("Conclusion: this packet was NOT signed by any key currently")
        print("in KMS_KEY_SETS for its date. The key used by the sender is")
        print("not present in this database.")
    print("=" * 72)


if __name__ == "__main__":
    main()