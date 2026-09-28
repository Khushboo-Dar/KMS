#!/usr/bin/env python3
"""
CBC-MAC calculator + comparator
-------------------------------
Uses the algorithm from "Addition of packet in Annexure-G through GPRS":
  1. Take MAC input = Message Type → last payload byte (excludes SOF, MAC_CODE, CRC)
  2. Zero-pad to a multiple of 16 bytes
  3. AES-128 in CBC mode, IV = 16 zero bytes
  4. Take the final 16-byte cipher block
  5. MAC_CODE = first 4 bytes

Compares the computed MAC_CODE with the OEM MAC_CODE.
"""
from Crypto.Cipher import AES


# ------------------------------------------------------------------
# 1. Inputs  (edit these if you want to test another vector)
# ------------------------------------------------------------------
KEY_HEX         = "7AD4637D0CB980DC70BC7AA5D43C2B41"
MAC_INPUT_HEX   = "180023054701000F61780118091A0F05080300106A00106800106C"
OEM_MAC_HEX     = "BB01BD09"      # MAC reported by the OEM for this input


# ------------------------------------------------------------------
# 2. CBC-MAC per the specification
# ------------------------------------------------------------------
def cbc_mac_code(key: bytes, mac_input: bytes) -> bytes:
    """AES-128 CBC-MAC, zero pad, IV=0, return the first 4 bytes."""
    pad = (-len(mac_input)) % 16
    padded = mac_input + b"\x00" * pad
    ct = AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16).encrypt(padded)
    return ct[-16:][:4]


# ------------------------------------------------------------------
# 3. Run
# ------------------------------------------------------------------
def main():
    key       = bytes.fromhex(KEY_HEX)
    mac_input = bytes.fromhex(MAC_INPUT_HEX)
    oem_mac   = bytes.fromhex(OEM_MAC_HEX)

    print("=" * 60)
    print(" CBC-MAC computation")
    print("=" * 60)
    print(f" Key            : {KEY_HEX}")
    print(f" MAC input      : {MAC_INPUT_HEX}")
    print(f" Input length   : {len(mac_input)} bytes")
    padded_len = len(mac_input) + ((-len(mac_input)) % 16)
    print(f" Padded length  : {padded_len} bytes "
          f"({padded_len - len(mac_input)} zero bytes added)")
    print(f" IV             : 16 zero bytes")
    print(f" Algorithm      : AES-128 CBC-MAC, take first 4 bytes")
    print("-" * 60)

    # Full 16-byte CBC-MAC for reference
    pad = (-len(mac_input)) % 16
    padded = mac_input + b"\x00" * pad
    full_mac = AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16).encrypt(padded)[-16:]
    computed_mac = full_mac[:4]

    print(f" Full 16-byte MAC : {full_mac.hex().upper()}")
    print(f" Computed MAC_CODE: {computed_mac.hex().upper()}")
    print(f" OEM      MAC_CODE: {oem_mac.hex().upper()}")
    print("-" * 60)

    # -------------------------------------------------------------
    # Compare
    # -------------------------------------------------------------
    if computed_mac == oem_mac:
        print("✅ MATCH — computed MAC_CODE equals OEM MAC_CODE.")
    else:
        print("❌ MISMATCH — computed MAC_CODE does not equal OEM MAC_CODE.")
        # Also report where the OEM MAC appears in the full 16 bytes,
        # if at all, so we can see if it is a different 4-byte slice.
        found = False
        for off in range(13):
            if full_mac[off:off + 4] == oem_mac:
                print(f"   (OEM MAC found at offset {off} of the 16-byte block)")
                found = True
        if not found:
            print("   (OEM MAC does not appear anywhere in the 16-byte block)")
    print("=" * 60)


if __name__ == "__main__":
    main()