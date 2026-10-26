import oracledb
from datetime import datetime

from .app_config import ORACLE_DSN, ORACLE_PASSWORD, ORACLE_USER
from .database_access import require_database_access
from .encryption_service import EXPIRED_KEY_SET_THRESHOLD, MAX_KEY_SETS


class DatabaseService:
    def __init__(
        self,
        username=ORACLE_USER,
        password=ORACLE_PASSWORD,
        dsn=ORACLE_DSN,
    ):
        if not username or not password or not dsn:
            raise RuntimeError(
                "Oracle configuration is incomplete. Set ORACLE_USER, "
                "ORACLE_PASSWORD and ORACLE_DSN."
            )
        self.username, self.password, self.dsn = username, password, dsn

    def connect(self, purpose: str = "access KMS data"):
        require_database_access(purpose)
        return oracledb.connect(
            user=self.username,
            password=self.password,
            dsn=self.dsn,
        )

    def key_set_inventory(self):
        """Return the local buffer state without removing expired key sets."""
        conn = self.connect("inspect the stored key-set buffer")
        try:
            with conn.cursor() as cur:
                now = datetime.now()
                cur.execute(
                    "SELECT COUNT(*), "
                    "SUM(CASE WHEN VALID_TO <= :1 THEN 1 ELSE 0 END), "
                    "MAX(KEY_SET_ID) "
                    "FROM KMS_KEY_SETS",
                    (now,),
                )
                total, expired, latest_key_set_id = cur.fetchone()
                return {
                    "total": int(total or 0),
                    "expired": int(expired or 0),
                    "latest_key_set_id": (
                        int(latest_key_set_id)
                        if latest_key_set_id is not None
                        else None
                    ),
                    "refresh_threshold": EXPIRED_KEY_SET_THRESHOLD,
                    "capacity": MAX_KEY_SETS,
                }
        finally:
            conn.close()

    def latest_key_set_id(self):
        return self.key_set_inventory()["latest_key_set_id"]
