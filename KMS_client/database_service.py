import oracledb
from datetime import datetime

from .app_config import ORACLE_USER, ORACLE_PASSWORD, ORACLE_DSN
from .database_access import require_database_access
from .encryption_service import _audit_logger

class DatabaseService:
    def __init__(self, username=ORACLE_USER, password=ORACLE_PASSWORD, dsn=ORACLE_DSN):
        if not username or not password or not dsn:
            raise RuntimeError("Oracle configuration is incomplete. Set ORACLE_USER, ORACLE_PASSWORD and ORACLE_DSN.")
        self.username, self.password, self.dsn = username, password, dsn
    def connect(self, purpose: str = "access KMS data"):
        require_database_access(purpose)
        return oracledb.connect(user=self.username, password=self.password, dsn=self.dsn)
    def latest_key_set_id(self):
        conn=self.connect("check the latest stored key set")
        try:
            with conn.cursor() as cur:
                now = datetime.now()
                cur.execute(
                    "SELECT KEY_SET_ID, VALID_FROM, VALID_TO "
                    "FROM KMS_KEY_SETS WHERE VALID_TO <= :1",
                    (now,),
                )
                expired = cur.fetchall()
                if expired:
                    cur.execute(
                        "DELETE FROM KMS_KEY_SETS WHERE VALID_TO <= :1",
                        (now,),
                    )
                    conn.commit()
                    logger = _audit_logger()
                    for key_set_id, valid_from, valid_to in expired:
                        logger.info(
                            "REMOVED expired key_set_id=%s valid_from=%s valid_to=%s",
                            key_set_id,
                            valid_from,
                            valid_to,
                        )

                cur.execute(
                    "SELECT MAX(KEY_SET_ID) FROM KMS_KEY_SETS "
                    "WHERE VALID_TO > :1",
                    (now,),
                )
                row=cur.fetchone()
                return int(row[0]) if row and row[0] is not None else None
        finally: conn.close()
