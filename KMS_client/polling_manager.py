import time

from .app_config import (
    MSG_AUTHENTICATION_STATUS,
    POLLING_INTERVAL_SECONDS,
    RETRY_INTERVAL_SECONDS,
)
from .auth_query_0x94 import build_authentication_query
from .auth_status_0x95 import parse_authentication_status
from .authentication_flow import AuthenticationFlow
from .database_service import DatabaseService
from .udp_client import KmsUdpClient


class KmsPollingManager:
    def __init__(
        self,
        kavach_id: int,
        unit_type: int,
        sim_id: int,
        udp_client: KmsUdpClient,
        auth_flow: AuthenticationFlow | None = None,
        *,
        authentication_flow: AuthenticationFlow | None = None,
    ):
        """Create a polling manager using one UDP client and auth flow.

        ``authentication_flow`` is retained as a keyword-only alias for
        compatibility with callers that used the descriptive original name.
        """
        if auth_flow is not None and authentication_flow is not None:
            raise ValueError("Pass either auth_flow or authentication_flow, not both")

        self.kavach_id = kavach_id
        self.unit_type = unit_type
        self.sim_id = sim_id
        self.udp = udp_client
        self.flow = auth_flow or authentication_flow or AuthenticationFlow(
            kavach_id=kavach_id,
            unit_type=unit_type,
            sim_id=sim_id,
            udp_client=self.udp,
        )
        self.running = False

    def _window_delay(self):
        # SRS: request minute in the 120-minute window = KAVACH ID mod 120.
        return (self.kavach_id % 120) * 60

    def poll_once(self):
        packet=build_authentication_query(self.kavach_id,self.unit_type)
        try:
            response=self.udp.send_and_receive(packet,expected_type=MSG_AUTHENTICATION_STATUS)
        except (ConnectionError, TimeoutError, OSError) as exc:
            print(f"0x94 polling failed: {exc}")
            return False
        if response is None:
            return False
        status=parse_authentication_status(response)
        remote=status["key_set_id"]
        local=DatabaseService().latest_key_set_id()
        print(f"0x95 received: remote Key Set ID={remote}, local Key Set ID={local}")
        if local is not None and remote == local:
            print("No new key set. Next query after 6 hours."); return True
        print("New key set available. Requesting keys using 0x92.")
        time.sleep(self._window_delay())
        while self.running:
            try:
                self.flow.request_keys(); print("New key set received and stored securely."); return True
            except (ConnectionError, RuntimeError, TimeoutError, OSError) as e:
                print(f"0x92/0x93 failed: {e}; retrying in 5 minutes"); time.sleep(RETRY_INTERVAL_SECONDS)
        return False

    def start(self,run_forever=True):
        self.running=True
        try:
            while self.running:
                ok=self.poll_once()
                if not ok:
                    print("0x94 polling failed; retrying in 5 minutes")
                    while self.running and not self.poll_once(): time.sleep(RETRY_INTERVAL_SECONDS)
                if not run_forever: break
                print("Waiting 6 hours for next 0x94 Authentication Query..."); time.sleep(POLLING_INTERVAL_SECONDS)
        finally:
            self.running=False

    def stop(self):
        self.running=False

PollingManager=KmsPollingManager
