"""Command-line entry point for the fixed-identity KAVACH KMS client."""

import argparse
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Support both ``python -m KMS_client.main`` and ``python KMS_client/main.py``.
if __package__ in (None, ""):
    sys.path.insert(0, str(PROJECT_ROOT))
    from KMS_client.app_config import resolve_client_config
    from KMS_client.authentication_flow import AuthenticationFlow
    from KMS_client.polling_manager import PollingManager
    from KMS_client.udp_client import KmsUdpClient
else:
    from .app_config import resolve_client_config
    from .authentication_flow import AuthenticationFlow
    from .polling_manager import PollingManager
    from .udp_client import KmsUdpClient


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Authenticate the configured stationary KAVACH unit with KMS. "
            "Its protocol identity is fixed in the application."
        )
    )
    parser.add_argument("--kms-ip", help="KMS server hostname or IP address")
    parser.add_argument("--kms-port", help="KMS UDP port")
    parser.add_argument("--udp-timeout-seconds", help="UDP receive timeout in seconds")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run the first poll only, then exit (useful for verification).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    try:
        config = resolve_client_config(
            kms_ip=args.kms_ip,
            kms_port=args.kms_port,
            udp_timeout_seconds=args.udp_timeout_seconds,
        )
    except ValueError as error:
        parser.error(str(error))

    print("=" * 60)
    print("KAVACH KMS CLIENT")
    print("=" * 60)
    print(f"KAVACH ID : {config.kavach_id}")
    print(f"Unit Type : 0x{config.unit_type:02X} ({config.unit_type_name})")
    print(f"SIM ID    : 0x{config.sim_id:02X}")
    print(f"KMS       : {config.kms_ip}:{config.kms_port}")
    print()

    udp = KmsUdpClient(
        host=config.kms_ip,
        port=config.kms_port,
        timeout=config.udp_timeout_seconds,
    )

    try:
        print("=" * 60)
        print("[1] INITIAL AUTHENTICATION")
        print("=" * 60)
        authentication = AuthenticationFlow(
            udp_client=udp,
            kavach_id=config.kavach_id,
            unit_type=config.unit_type,
            sim_id=config.sim_id,
        )
        authentication.run_initial_with_retry()
        print("\nInitial authentication completed successfully.")

        print("\n" + "=" * 60)
        print("[2] START KMS POLLING")
        print("=" * 60)
        polling = PollingManager(
            udp_client=udp,
            auth_flow=authentication,
            kavach_id=config.kavach_id,
            unit_type=config.unit_type,
            sim_id=config.sim_id,
        )
        polling.start(run_forever=not args.once)
        return 0
    except KeyboardInterrupt:
        print("\nKMS client stopped by user.")
        return 130
    except Exception as error:
        print("\n" + "=" * 60)
        print("KMS CLIENT ERROR")
        print("=" * 60)
        print(f"{type(error).__name__}: {error}")
        return 1
    finally:
        print("\nKMS client terminated.")


if __name__ == "__main__":
    raise SystemExit(main())
