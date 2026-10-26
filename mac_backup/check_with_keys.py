#!/usr/bin/env python3
"""
KAVACH GPRS/LTE MAC_CODE — generator + verifier
================================================
Packet types: 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x20

Confirmed OEM MAC algorithm:
    1. Key Index = (Server_ID + Loco_ID) % 2
         0 -> Authentication Key 1
         1 -> Authentication Key 2
    2. MAC input = Message Type -> last payload byte
         (excludes SOF, MAC_CODE, CRC)
    3. Zero-pad MAC input to a multiple of 16 bytes
    4. Working Key = selected Authentication Key
       For each 16-byte block:
           Cipher Block = AES-128-CBC(Working Key, Zero IV, block)
           Working Key  = Cipher Block
    5. After last block, Working Key = final 16-byte cipher block
    6. MAC_CODE = CRC-32/XFER(final cipher block), MSB first

Key set lookup: the row whose validity window (from .. to) covers
the packet's own date and time. The 30 key sets below are hardcoded
from the KMS 0x93 response (KAVACH unit 50002, 29-09-2026).
"""
import re
from Crypto.Cipher import AES


# =====================================================================
# 30 key sets (from KMS 0x93 response)
# Each row: (valid_from, valid_to, key1_hex, key2_hex)
# Times are IST, format: DD-MM-YY HH:MM
# =====================================================================
KEY_SETS = [
    ("01-09-26 19:00", "05-09-26 19:00", "1DA4BFAF4CF07102D66390EE83432877", "47ED349383D913B7732484703E81CF48"),
    ("05-09-26 19:00", "09-09-26 19:00", "090F83420ECBA7658302B97F5F963316", "D7304E22ADE8554390083B286C00C454"),
    ("09-09-26 19:00", "13-09-26 19:00", "9347E474C0E5697B45CF0F80209458DD", "F06E980D33AC9B21BA3FB206907EF883"),
    ("13-09-26 19:00", "17-09-26 19:00", "3D64EB17B1BF56F1C7D3DDDDD8D422FC", "B05E38FE67B721E7ACC2BA803362EBC7"),
    ("17-09-26 19:00", "21-09-26 19:00", "D68C43BCA9402B3017A64560CEBD48E5", "1CB6563146FA1B8642036BEE04D5BE65"),
    ("21-09-26 19:00", "25-09-26 19:00", "E716074C9166526F3307E6C071C118EF", "7AD4637D0CB980DC70BC7AA5D43C2B41"),
    ("25-09-26 19:00", "29-09-26 19:00", "E8E078B8B5FC54B663E6FE3E135A1580", "EA7B742F7240582E952ADCD4EBAD9BF7"),
    ("29-09-26 19:00", "03-10-26 19:00", "DBA5D891495F397E80AD1A26BB42C815", "A7F9BA59C7FBCFA78849238B1F7FCBB5"),
    ("03-10-26 19:00", "07-10-26 19:00", "4B06636E8283378B42F6AFC526317252", "61C72DF2F2412FDFD53008FF3BAE5E01"),
    ("07-10-26 19:00", "11-10-26 19:00", "E164DBB4DE5A9223C22F17D04C0A8156", "D7D0295851D8C309D68399527B374F93"),
    ("11-10-26 19:00", "15-10-26 19:00", "98ADE3C155BD7307340A30C22A5F92CA", "AEB1286A8505AF09A1D2DD5BC13FA88A"),
    ("15-10-26 19:00", "19-10-26 19:00", "E083389F27BF01195D222447A800DE77", "F0CEA3C90FE40E92FDD92083DF1845F4"),
    ("19-10-26 19:00", "23-10-26 19:00", "61A6E1A726F3A3EEB00E0D62E16860A0", "F3656AF39BDF7AFC75A6A14D9F7D3944"),
    ("23-10-26 19:00", "27-10-26 19:00", "DC2FE6021E3751FD2BB51800D6ABB095", "78808F79AE5258822BE5327F52554F33"),
    ("27-10-26 19:00", "31-10-26 19:00", "D4C986B2815E81BC146DC7E6C77A26C9", "F60BD41FEDC0968AD663D73905D2ABD6"),
    ("31-10-26 19:00", "04-11-26 19:00", "65E42C0C25FD131AFFD365408A71BBB1", "BE6888468030451432FBDB1E8747B641"),
    ("04-11-26 19:00", "08-11-26 19:00", "C2F180E24D19A3F9F7BA201A5A550064", "A8267A9C496455359F17DA2A22F593B7"),
    ("08-11-26 19:00", "12-11-26 19:00", "1C237E98F1D963A5C48F4EC6102BB9DD", "FB767560CC1AF85D9C4B43363F79D702"),
    ("12-11-26 19:00", "16-11-26 19:00", "2668FD37D66773CFC2D5D7B9158F2573", "5EFC2EAB7F32EA022B21FCA6962D654B"),
    ("16-11-26 19:00", "20-11-26 19:00", "B84C9FA72E82069403A69EF6423E470C", "25CFD7424B2B82F47DFA0CB56ACD3995"),
    ("20-11-26 19:00", "24-11-26 19:00", "708C01C9F07D45DCF59AA8D994F3C0EC", "D9F080C65522FF8CC9AB293375512935"),
    ("24-11-26 19:00", "28-11-26 19:00", "6D0886B53D7E1BA789FB4DB183A95F89", "3A1FDC7A4C72404D8C74FF44541266A4"),
    ("28-11-26 19:00", "02-12-26 19:00", "71726C8C6D0BAE5AD4D93D59D54E0920", "4B9FF85575AEE9FAC73928C97ED75377"),
    ("02-12-26 19:00", "06-12-26 19:00", "95A83F113DD31C2F7181A67335E7773E", "6ADFF9B41A102FC28971C433E2E5DCFD"),
    ("06-12-26 19:00", "10-12-26 19:00", "85C5C42C0EF7E37883C9E4F30775C5E0", "C1EA5E9FDD9F5D84797D88CC0EE94C8B"),
    ("10-12-26 19:00", "14-12-26 19:00", "A5A9ED6F234A2F72FC8030502C3BBA13", "ABE471F8863C1FE5683FB3916F176A99"),
    ("14-12-26 19:00", "18-12-26 19:00", "7C584E5E8755BD76BAEBA35D6E0C583E", "C2752029775305688A0806E3979E03E5"),
    ("18-12-26 19:00", "22-12-26 19:00", "1597D4D3EC5C8B5527FA3E9A99C1775C", "E774CEFAF640212853E6D47F4FD9DE1C"),
    ("22-12-26 19:00", "26-12-26 19:00", "E8BE47D737845266E9CA027D156ACEC8", "90AAFB23CF09EED475AC8005870B064D"),
    ("26-12-26 19:00", "30-12-26 19:00", "1B21B2DB79A024622268102B3EA412E8", "170CEFA4DEBB4DDFCF72618B044CDEDD"),
]

KAVACH_ID = 50002
SOF       = b"\xBB\xBB"
AES_BLOCK = 16
ZERO_IV   = b"\x00" * AES_BLOCK


# =====================================================================
# MAC primitives
# =====================================================================
def crc32_xfer(data: bytes) -> int:
    """CRC-32/XFER: reflected poly 0xEDB88320, init=0, xorout=0."""
    poly = 0xEDB88320
    crc  = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (poly if (crc & 1) else 0)
    return crc & 0xFFFFFFFF


def oem_mac_code(key: bytes, mac_input: bytes) -> bytes:
    """AES-128-CBC key-chaining over 16-byte blocks, then CRC-32/XFER."""
    if len(key) != AES_BLOCK:
        raise ValueError(f"Key must be {AES_BLOCK} bytes, got {len(key)}")
    pad = (-len(mac_input)) % AES_BLOCK
    padded = mac_input + b"\x00" * pad
    working = key
    for i in range(0, len(padded), AES_BLOCK):
        working = AES.new(working, AES.MODE_CBC, iv=ZERO_IV).encrypt(padded[i:i+AES_BLOCK])
    return crc32_xfer(working).to_bytes(4, "big")


# =====================================================================
# Packet parsing
# =====================================================================
def parse_packet(pkt: bytes) -> dict:
    return {
        "msg_type": pkt[2],
        "msg_len":  int.from_bytes(pkt[3:5], "big"),
        "seq":      int.from_bytes(pkt[5:7], "big"),
        "loco_id":  int.from_bytes(pkt[7:10], "big"),
        "nms_id":   int.from_bytes(pkt[10:12], "big"),
        "version":  pkt[12],
        "date":     (pkt[15], pkt[14], pkt[13]),   # (yy, mm, dd)
        "time":     (pkt[16], pkt[17], pkt[18]),   # (hh, mi, ss)
    }


def _to_stamp(ddmmyy_hhmm: str):
    """
    Parse "29-09-26 19:00" into a comparable tuple (yy, mm, dd, hh, mi).
    Handles '-' , ':' and whitespace as separators.
    """
    d, m, y, hh, mi = re.split(r"[-:\s]+", ddmmyy_hhmm.strip())
    return (int(y), int(m), int(d), int(hh), int(mi))


def select_key_set(pkt_dd: int, pkt_mm: int, pkt_yy: int,
                   pkt_hh: int, pkt_mi: int):
    """
    Return the row whose validity window contains the packet's
    timestamp. Compares (yy, mm, dd, hh, mi) tuples.
    """
    pkt_stamp = (pkt_yy, pkt_mm, pkt_dd, pkt_hh, pkt_mi)
    for row in KEY_SETS:
        frm, to = row[0], row[1]
        if _to_stamp(frm) <= pkt_stamp < _to_stamp(to):
            return row
    return None


# =====================================================================
# Main
# =====================================================================
def main():
    raw = input("Packet hex > ").strip().replace(" ", "").replace("\n", "")
    if raw.lower().startswith("0x"):
        raw = raw[2:]
    pkt = bytes.fromhex(raw)

    meta = parse_packet(pkt)
    yy, mm, dd = meta["date"]
    hh, mi, ss = meta["time"]

    print()
    print("=" * 66)
    print(" PACKET")
    print("=" * 66)
    print(f" Length          : {len(pkt)} bytes")
    print(f" Message type    : 0x{meta['msg_type']:02X}")
    print(f" MsgLen          : {meta['msg_len']}  (total = {2 + meta['msg_len']})")
    print(f" Sequence        : {meta['seq']}")
    print(f" Loco ID         : {meta['loco_id']}  (hex {meta['loco_id']:06X})")
    print(f" NMS ID          : {meta['nms_id']}")
    print(f" Timestamp       : {dd:02d}-{mm:02d}-20{yy:02d} {hh:02d}:{mi:02d}:{ss:02d} IST")
    print(f" KAVACH_ID       : {KAVACH_ID}")

    # --- Key selection ---
    idx = (KAVACH_ID + meta["loco_id"]) % 2
    print()
    print("=" * 66)
    print(" KEY SELECTION")
    print("=" * 66)
    print(f" Formula         : (KAVACH_ID + Loco_ID) % 2")
    print(f"                 : ({KAVACH_ID} + {meta['loco_id']}) % 2 = {idx}")
    print(f" Chosen slot     : Authentication Key {idx + 1}")

    row = select_key_set(dd, mm, yy, hh, mi)
    if not row:
        print(" No key set covers this timestamp.")
        return
    frm, to, k1_hex, k2_hex = row
    key_hex   = k1_hex if idx == 0 else k2_hex
    key_label = "Key 1" if idx == 0 else "Key 2"

    print(f" Covering set    : {frm}  ..  {to}")
    print(f" {key_label:<15} : {key_hex}")

    # --- MAC computation ---
    mac_input    = pkt[2:-8]
    received_mac = pkt[-8:-4]
    received_crc = pkt[-4:]

    print()
    print("=" * 66)
    print(" MAC COMPUTATION")
    print("=" * 66)
    print(f" MAC input length: {len(mac_input)} bytes")
    print(f" MAC input       : {mac_input.hex().upper()}")

    computed_mac = oem_mac_code(bytes.fromhex(key_hex), mac_input)
    computed_crc = crc32_xfer(mac_input + computed_mac).to_bytes(4, "big")

    print()
    print(f" Received MAC    : {received_mac.hex().upper()}")
    print(f" Computed MAC    : {computed_mac.hex().upper()}")
    print(f" Received CRC    : {received_crc.hex().upper()}")
    print(f" Computed CRC    : {computed_crc.hex().upper()}")

    print()
    print("=" * 66)
    print(f" MAC result      : {'✅ MATCH' if computed_mac == received_mac else '❌ MISMATCH'}")
    print(f" CRC result      : {'✅ VALID' if computed_crc == received_crc else '❌ INVALID'}")
    print("=" * 66)


if __name__ == "__main__":
    main()