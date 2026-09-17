import os, base64, oracledb
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .utils.datetime_utils import decode_validity

TABLE_NAME="KMS_KEY_SETS"; NONCE_SIZE=12; VERSION="v1"
class EncryptionService:
    def __init__(self, key=None):
        if key is None:
            raw=os.getenv("KMS_DB_ENCRYPTION_KEY_B64")
            if not raw: raise RuntimeError("KMS_DB_ENCRYPTION_KEY_B64 is not set")
            try: key=base64.b64decode(raw)
            except Exception as e: raise RuntimeError("Invalid Base64 encryption key") from e
        if len(key)!=32: raise ValueError("AES-256 key must be exactly 32 bytes")
        self.aes=AESGCM(key)
    def encrypt_string(self, value, aad):
        nonce=os.urandom(NONCE_SIZE); out=self.aes.encrypt(nonce,value.encode(),aad.encode())
        return VERSION+":"+base64.b64encode(nonce+out).decode()
    def encrypt_hex(self, value, aad):
        clean = value.replace(" ", "").replace("\n", "").strip().upper()
        bytes.fromhex(clean)
        return self.encrypt_string(clean,aad)
    def save_key_sets(self, connection:oracledb.Connection, key_set_id:int, key_sets, packet:bytes):
        rows=[]
        pkt_hex=packet.hex().upper()
        for ks in key_sets:
            vf=decode_validity(bytes.fromhex(ks["valid_from"]))
            vt=decode_validity(bytes.fromhex(ks["valid_to"]))
            k1=self.encrypt_hex(ks["key_1"],f"{TABLE_NAME}|KEY_1|{key_set_id}")
            k2=self.encrypt_hex(ks["key_2"],f"{TABLE_NAME}|KEY_2|{key_set_id}")
            pkt=self.encrypt_hex(pkt_hex,f"{TABLE_NAME}|PKT|{key_set_id}")
            rows.append((key_set_id,vf,vt,k1,k2,pkt))
        with connection.cursor() as cur:
            cur.executemany("""INSERT INTO KMS_KEY_SETS (KEY_SET_ID,VALID_FROM,VALID_TO,KEY_1,KEY_2,PKT) VALUES (:1,:2,:3,:4,:5,:6)""",rows)
        connection.commit(); return len(rows)
