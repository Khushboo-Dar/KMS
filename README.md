# KAVACH KMS Client

Python client for a KAVACH unit to authenticate with the KMS over UDP,
retrieve authentication key sets, encrypt them with AES-256-GCM, and store
them in Oracle Database.

## Specifications

- Python 3.10+; dependencies: `oracledb`, `cryptography`, `python-dotenv`
- KMS UDP flows: identification `0x90/0x91`, key request `0x92/0x93`, and
  status polling `0x94/0x95`
- Fixed unit identity: KAVACH ID `50002`, unit type `0x11` (stationary), and
  SIM ID `0x01`
- KMS endpoint configuration is read from `.env`; its CLI options take priority.

## Run

1. Create and activate a virtual environment, then install dependencies:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Create `.env` in the project root:

   ```env
   KMS_IP=your-kms-host
   KMS_PORT=your-kms-port
   UDP_TIMEOUT_SECONDS=10

   ORACLE_USER=your-oracle-user
   ORACLE_PASSWORD=your-oracle-password
   ORACLE_DSN=host:1521/service_name
   KMS_DB_ENCRYPTION_KEY_B64=your-base64-32-byte-aes-key
   ```

3. Run one authentication/polling cycle:

   ```bash
   python -m KMS_client.main --once
   ```

   Omit `--once` to keep polling. The KAVACH ID, unit type, and SIM ID are
   deliberately fixed in the application and cannot be overridden.

## Access confirmation

The client asks for `Yes`/`No` before every Oracle database connection and
every KMS UDP request. Choosing `No` prevents that operation from starting.
