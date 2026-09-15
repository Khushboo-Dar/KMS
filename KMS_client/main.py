# main.py

import logging
import signal
import sys

from .app_config import (
    KMS_IP,
    KMS_PORT,
    KAVACH_ID,
    UNIT_TYPE,
    SIM_ID,
)

from .udp_client import KmsUdpClient
from .polling_manager import PollingManager


# ============================================================
# Logging Configuration
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s | "
        "%(levelname)s | "
        "%(name)s | "
        "%(message)s"
    ),
)

logger = logging.getLogger("KMS_MAIN")


# ============================================================
# Global Polling Manager
# ============================================================

polling_manager = None


# ============================================================
# Signal Handler
# ============================================================

def shutdown_handler(
    signum,
    frame
):

    logger.info(
        "Shutdown signal received."
    )

    global polling_manager

    if polling_manager is not None:

        try:
            polling_manager.stop()

        except Exception as e:

            logger.error(
                f"Error while stopping polling manager: {e}"
            )

    logger.info(
        "KMS Client stopped."
    )

    sys.exit(0)


# ============================================================
# Display Configuration
# ============================================================

def print_configuration():

    print()
    print("=" * 60)
    print("KAVACH KMS CLIENT")
    print("=" * 60)

    print(
        f"KMS IP       : {KMS_IP}"
    )

    print(
        f"KMS Port     : {KMS_PORT}"
    )

    print(
        f"KAVACH ID    : {KAVACH_ID}"
    )

    print(
        f"Unit Type    : 0x{UNIT_TYPE:02X}"
    )

    print(
        f"SIM ID       : 0x{SIM_ID:02X}"
    )

    print("=" * 60)
    print()


# ============================================================
# Create KMS Client
# ============================================================

def create_kms_client():

    logger.info(
        "Creating KMS UDP client..."
    )

    client = KmsUdpClient(
        server_ip=KMS_IP,
        server_port=KMS_PORT,
    )

    return client


# ============================================================
# Create Polling Manager
# ============================================================

def create_polling_manager(
    udp_client
):

    logger.info(
        "Creating polling manager..."
    )

    manager = PollingManager(
        udp_client=udp_client,
        kavach_id=KAVACH_ID,
        unit_type=UNIT_TYPE,
        sim_id=SIM_ID,
    )

    return manager


# ============================================================
# Main Application
# ============================================================

def main():

    global polling_manager

    print_configuration()

    logger.info(
        "Starting KAVACH KMS Client..."
    )

    udp_client = None

    try:

        # ----------------------------------------------------
        # Create UDP Client
        # ----------------------------------------------------

        udp_client = create_kms_client()

        # ----------------------------------------------------
        # Create Polling Manager
        # ----------------------------------------------------

        polling_manager = create_polling_manager(
            udp_client
        )

        # ----------------------------------------------------
        # Start Polling
        # ----------------------------------------------------

        logger.info(
            "Starting KMS polling..."
        )

        polling_manager.start()

    except KeyboardInterrupt:

        logger.info(
            "Keyboard interrupt received."
        )

    except Exception as e:

        logger.exception(
            f"KMS Client failed: {e}"
        )

        return 1

    finally:

        # ----------------------------------------------------
        # Stop Polling
        # ----------------------------------------------------

        if polling_manager is not None:

            try:

                polling_manager.stop()

            except Exception as e:

                logger.error(
                    f"Failed to stop polling manager: {e}"
                )

        # ----------------------------------------------------
        # Close UDP Client
        # ----------------------------------------------------

        if udp_client is not None:

            try:

                udp_client.close()

            except Exception as e:

                logger.error(
                    f"Failed to close UDP client: {e}"
                )

    logger.info(
        "KMS Client exited successfully."
    )

    return 0


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":

    # --------------------------------------------------------
    # Register shutdown handlers
    # --------------------------------------------------------

    signal.signal(
        signal.SIGINT,
        shutdown_handler
    )

    signal.signal(
        signal.SIGTERM,
        shutdown_handler
    )

    # --------------------------------------------------------
    # Start application
    # --------------------------------------------------------

    sys.exit(
        main()
    )