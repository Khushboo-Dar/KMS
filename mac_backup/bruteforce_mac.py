#!/usr/bin/env python3
"""
Comprehensive MAC diagnostic. Tries EVERY key in KMS_KEY_SETS,
plus the doc's default keys, across multiple ranges + truncations.
Prints every match found.
"""
import base64
import oracledb
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

ORACLE_USER     = "SURAKSHA"
ORACLE_PASSWORD = "Suraksha#1234"
ORACLE_DSN      = "10.30.4.153:1521/SMMSDB"
DB_KEY_B64      = "ngUesMwf26EdVkhrOjtxhYCPb0FxURWrvKXJNJEqaEE="
TABLE           = "KMS_KEY_SETS"

def decrypt_key(blob, aad, gcm):
    b64 = blob[3:] + "=" * (-len(blob[3:]) % 4)
    raw = base64.b64decode(b64)
    pt  = gcm.decrypt(raw[:12], raw[12:], aad.encode())
    try:
        s = pt.decode("utf-8"); bytes.fromhex(s); return bytes.fromhex(s)
    except (UnicodeDecodeError, ValueError):
        return pt

def cbc_mac(key, data, trunc):
    if len(data) % 16:
        data += b"\x00" * (16 - len(data) % 16)
    blk = AES.new(key, AES.MODE_CBC, iv=b"\x00"*16).encrypt(data)[-16:]
    return blk[:4] if trunc == "first" else blk[-4:]


def aes_cmac(key: bytes, data: bytes) -> bytes:
    c = cmac.CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()  # 16 bytes, full CMAC — no manual padding needed, RFC4493 handles it

def main():
    hex_in = input("Packet hex > ").strip().replace(" ","").replace("\n","")
    pkt = bytes.fromhex(hex_in)
    print(f"Packet length: {len(pkt)} bytes\n")

    # ---- Load every key from the DB ----
    gcm = AESGCM(base64.b64decode(DB_KEY_B64))
    keys = {}
    with oracledb.connect(user=ORACLE_USER, password=ORACLE_PASSWORD, dsn=ORACLE_DSN) as c:
        with c.cursor() as cur:
            cur.execute(f"SELECT KEY_SET_ID, VALID_FROM, KEY_1, KEY_2 FROM {TABLE} ORDER BY VALID_FROM")
            for kid, vf, k1e, k2e in cur:
                try:
                    keys[f"{vf.date()} K1"] = decrypt_key(k1e, f"{TABLE}|KEY_1|{kid}", gcm)
                    keys[f"{vf.date()} K2"] = decrypt_key(k2e, f"{TABLE}|KEY_2|{kid}", gcm)
                except Exception as e:
                    print(f"  {vf.date()}: decrypt fail {e}")

    # Doc example defaults
    keys["DOC K1"] = bytes.fromhex("1234567890ABCDEF1234567890ABCDEF")
    keys["DOC K2"] = bytes.fromhex("567890ABCDEF123456781234CDEF1234")

    # ---- Ranges to try ----
    ranges = {
        "[2:-8]  (current)":  pkt[2:-8],
        "[2:-4]  (no CRC)":   pkt[2:-4],
        "[0:-8]  (with SOF)": pkt[0:-8],
        "[3:-8]  (skip MT)":  pkt[3:-8],
        "[2:-12] (extra 4)":  pkt[2:-12],
    }

    received_mac = pkt[-8:-4]
    received_last4 = pkt[-4:]
    print(f"Received MAC (last-8..last-4) : {received_mac.hex().upper()}")
    print(f"Received bytes (last 4)       : {received_last4.hex().upper()}\n")

    matches = []
    for kn, k in keys.items():
        for rn, r in ranges.items():
            for tr in ("first", "last"):
                mac = cbc_mac(k, r, tr)
                if mac == received_mac:
                    matches.append((kn, rn, tr, "last8..last4"))
                if mac == received_last4:
                    matches.append((kn, rn, tr, "last4"))

    if matches:
        print("*** MATCHES ***")
        for kn, rn, tr, cmp in matches:
            print(f"  key={kn:20s}  range={rn:20s}  trunc={tr:5s}  cmp={cmp}")
    else:
        print("No match with any key in the DB.")
        print("=> The KMS does NOT contain the key that signed this packet.\n")
        print("Sample computed MACs (first key x all ranges):")
        first_key_name, first_key = next(iter(keys.items()))
        for rn, r in ranges.items():
            m = cbc_mac(first_key, r, "first")
            print(f"  {first_key_name:20s} {rn:20s} first4={m.hex().upper()}")

if __name__ == "__main__":
    main()