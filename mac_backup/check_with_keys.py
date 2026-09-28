#!/usr/bin/env python3
"""
Last-resort MAC checker.
Tries: 50 DB keys + 2 doc-example keys + 4 dummy keys
     × 7 input ranges
     × 2 truncations
     × 2 IVs (zeros, ones)
= 728 combinations. If none matches, the packet was not signed by any
key derived from this KMS.
"""
from Crypto.Cipher import AES

DB_KEYS = [
    # (K1, K2) from your decryption_service.py output — 25 pairs
    ("E716074C9166526F3307E6C071C118EF", "7AD4637D0CB980DC70BC7AA5D43C2B41"),
    ("1B21B2DB79A024622268102B3EA412E8", "170CEFA4DEBB4DDFCF72618B044CDEDD"),
    ("DBA5D891495F397E80AD1A26BB42C815", "A7F9BA59C7FBCFA78849238B1F7FCBB5"),
    ("4B06636E8283378B42F6AFC526317252", "61C72DF2F2412FDFD53008FF3BAE5E01"),
    ("E164DBB4DE5A9223C22F17D04C0A8156", "D7D0295851D8C309D68399527B374F93"),
    ("98ADE3C155BD7307340A30C22A5F92CA", "AEB1286A8505AF09A1D2DD5BC13FA88A"),
    ("E083389F27BF01195D222447A800DE77", "F0CEA3C90FE40E92FDD92083DF1845F4"),
    ("61A6E1A726F3A3EEB00E0D62E16860A0", "F3656AF39BDF7AFC75A6A14D9F7D3944"),
    ("DC2FE6021E3751FD2BB51800D6ABB095", "78808F79AE5258822BE5327F52554F33"),
    ("D4C986B2815E81BC146DC7E6C77A26C9", "F60BD41FEDC0968AD663D73905D2ABD6"),
    ("65E42C0C25FD131AFFD365408A71BBB1", "BE6888468030451432FBDB1E8747B641"),
    ("C2F180E24D19A3F9F7BA201A5A550064", "A8267A9C496455359F17DA2A22F593B7"),
    ("1C237E98F1D963A5C48F4EC6102BB9DD", "FB767560CC1AF85D9C4B43363F79D702"),
    ("2668FD37D66773CFC2D5D7B9158F2573", "5EFC2EAB7F32EA022B21FCA6962D654B"),
    ("B84C9FA72E82069403A69EF6423E470C", "25CFD7424B2B82F47DFA0CB56ACD3995"),
    ("708C01C9F07D45DCF59AA8D994F3C0EC", "D9F080C65522FF8CC9AB293375512935"),
    ("6D0886B53D7E1BA789FB4DB183A95F89", "3A1FDC7A4C72404D8C74FF44541266A4"),
    ("71726C8C6D0BAE5AD4D93D59D54E0920", "4B9FF85575AEE9FAC73928C97ED75377"),
    ("95A83F113DD31C2F7181A67335E7773E", "6ADFF9B41A102FC28971C433E2E5DCFD"),
    ("85C5C42C0EF7E37883C9E4F30775C5E0", "C1EA5E9FDD9F5D84797D88CC0EE94C8B"),
    ("A5A9ED6F234A2F72FC8030502C3BBA13", "ABE471F8863C1FE5683FB3916F176A99"),
    ("7C584E5E8755BD76BAEBA35D6E0C583E", "C2752029775305688A0806E3979E03E5"),
    ("1597D4D3EC5C8B5527FA3E9A99C1775C", "E774CEFAF640212853E6D47F4FD9DE1C"),
    ("E8BE47D737845266E9CA027D156ACEC8", "90AAFB23CF09EED475AC8005870B064D"),
    ("E8E078B8B5FC54B663E6FE3E135A1580", "EA7B742F7240582E952ADCD4EBAD9BF7"),
]

OTHER_KEYS = {
    "DOC_KEY_1 (Annexure-G example)": "1234567890ABCDEF1234567890ABCDEF",
    "DOC_KEY_2 (Annexure-G example)": "567890ABCDEF123456781234CDEF1234",
    "ALL_ZEROS":                      "00000000000000000000000000000000",
    "ALL_ONES":                       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
}

IV_ZEROS = b"\x00" * 16
IV_ONES  = b"\xff" * 16


def cbc_mac(key: bytes, data: bytes, iv: bytes, trunc: str) -> bytes:
    pad = (-len(data)) % 16
    data = data + b"\x00" * pad
    blk = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(data)[-16:]
    return blk[:4] if trunc == "first" else blk[-4:]


def build_key_list():
    out = []  # list of (label, keybytes)
    for i, (k1h, k2h) in enumerate(DB_KEYS, 1):
        out.append((f"DB pair {i} K1", bytes.fromhex(k1h)))
        out.append((f"DB pair {i} K2", bytes.fromhex(k2h)))
    for label, kh in OTHER_KEYS.items():
        out.append((label, bytes.fromhex(kh)))
    return out


def main():
    raw = input("Packet hex > ").strip().replace(" ", "").replace("\n", "")
    if raw.lower().startswith("0x"):
        raw = raw[2:]
    pkt = bytes.fromhex(raw)
    n = len(pkt)

    # NOTE: bytes 13-15 are DD MM YY (per Annexure-G example 27/04/18 -> 1B 04 12)
    dd, mm, yy = pkt[13], pkt[14], pkt[15]
    print(f"Packet length : {n} bytes")
    print(f"Packet date   : {dd:02d}/{mm:02d}/20{yy:02d}  (DD/MM/YY)")

    # The 4-byte MAC slot is the last 4 bytes before the final 4-byte CRC
    # for a complete packet. For a truncated packet it's just the last 4 bytes.
    received_mac_complete = pkt[-8:-4]
    received_mac_trunc    = pkt[-4:]

    ranges = {
        "spec  [2:-8]":      pkt[2:-8],
        "withSOF [0:-8]":    pkt[0:-8],
        "noCRC  [2:-4]":     pkt[2:-4],
        "noCRCSOF [0:-4]":   pkt[0:-4],
        "skipMT [3:-8]":     pkt[3:-8],
        "skipCnt[19:-8]":    pkt[19:-8],   # event count + data only
        "skipHdr[20:-8]":    pkt[20:-8],   # event data only
    }

    keys = build_key_list()
    print(f"Total keys     : {len(keys)}")
    print(f"Total ranges   : {len(ranges)}")
    print(f"Total IVs      : 2")
    print(f"Total trunc    : 2")
    print(f"Total combos   : {len(keys) * len(ranges) * 2 * 2}")
    print()

    hit = None
    # Try complete-packet MAC slot first
    for label, k in keys:
        for rname, r in ranges.items():
            for ivname, iv in (("IV=0", IV_ZEROS), ("IV=F", IV_ONES)):
                for tr in ("first", "last"):
                    if cbc_mac(k, r, iv, tr) == received_mac_complete:
                        hit = (label, rname, ivname, tr, "complete[-8:-4]")
                        break
                if hit: break
            if hit: break
        if hit: break

    if hit is None:
        # Try truncated-packet MAC slot (last 4 bytes)
        for label, k in keys:
            for rname, r in ranges.items():
                for ivname, iv in (("IV=0", IV_ZEROS), ("IV=F", IV_ONES)):
                    for tr in ("first", "last"):
                        if cbc_mac(k, r, iv, tr) == received_mac_trunc:
                            hit = (label, rname, ivname, tr, "truncated[-4:]")
                            break
                    if hit: break
                if hit: break
            if hit: break

    print("=" * 60)
    if hit:
        print(f"*** MATCH FOUND ***")
        print(f"  key       : {hit[0]}")
        print(f"  range     : {hit[1]}")
        print(f"  IV        : {hit[2]}")
        print(f"  truncation: {hit[3]}")
        print(f"  MAC slot  : {hit[4]}")
    else:
        print("NO MATCH")
        print()
        print(f"Packet MAC (complete slot) : {received_mac_complete.hex().upper()}")
        print(f"Packet MAC (truncated slot): {received_mac_trunc.hex().upper()}")
        print()
        print("Verdict: this packet was NOT signed with any key from your KMS")
        print("         (nor with the doc-example keys, zeros, or ones).")
    print("=" * 60)


if __name__ == "__main__":
    main()