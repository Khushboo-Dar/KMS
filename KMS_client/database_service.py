import oracledb
from .app_config import ORACLE_USER, ORACLE_PASSWORD, ORACLE_DSN
from .database_access import require_database_access

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
                cur.execute("SELECT MAX(KEY_SET_ID) FROM KMS_KEY_SETS")
                row=cur.fetchone()
                return int(row[0]) if row and row[0] is not None else None
        finally: conn.close()
